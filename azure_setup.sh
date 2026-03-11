#!/bin/bash
#
# azure_setup.sh — Run outside Iran to reserve an Azure IP in a whitelisted range,
# create a VM, and SSH in for MoaV proxy setup.
#

set -euo pipefail

# Defaults
TARGET_RANGES=""
RANGES_FILE=""
LOCATION=""
RG="iran-proxy-rg"
VM_NAME="proxy-vm"
VM_SIZE="Standard_B1s"
SSH_KEY="${HOME}/.ssh/id_rsa.pub"
MAX_ATTEMPTS=500
SERVICE_TAGS_FILE=""

VERBOSE=false
TEMP_IP_NAMES=()
FOUND_IP=""
FOUND_IP_NAME=""

log() { [[ "$VERBOSE" == "true" ]] && echo "[DEBUG] $*" >&2 || true; }

usage() {
    cat <<'EOF'
Usage: azure_setup.sh [OPTIONS]

Reserve an Azure public IP in a whitelisted range, create a VM, and SSH in.

Options:
  --ranges <cidrs>      Comma-separated target CIDRs (e.g. "102.37.128.0/17,20.45.0.0/16")
  --ranges-file <path>  File with target CIDRs (iran_scanner.sh output)
  --region <region>     Azure region (auto-detected if omitted)
  --rg <name>           Resource group name (default: iran-proxy-rg)
  --vm-name <name>      VM name (default: proxy-vm)
  --vm-size <size>      VM size (default: Standard_B1s)
  --ssh-key <path>      SSH public key path (default: ~/.ssh/id_rsa.pub)
  --max-attempts <N>    Max IP allocation attempts (default: 500)
  --tags-file <path>    Local ServiceTags JSON for region detection
  -v, --verbose         Show detailed logs (full az CLI output)
  -h, --help            Show this help

Examples:
  # Use a specific range and region
  azure_setup.sh --ranges "102.37.128.0/17" --region southafricanorth

  # Use iran_scanner output (auto-detect region)
  azure_setup.sh --ranges-file accessible_ranges.txt --tags-file ServiceTags_Public.json
EOF
    exit 0
}

# --- Argument parsing ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ranges)       TARGET_RANGES="$2"; shift 2 ;;
        --ranges-file)  RANGES_FILE="$2"; shift 2 ;;
        --region)       LOCATION="$2"; shift 2 ;;
        --rg)           RG="$2"; shift 2 ;;
        --vm-name)      VM_NAME="$2"; shift 2 ;;
        --vm-size)      VM_SIZE="$2"; shift 2 ;;
        --ssh-key)      SSH_KEY="$2"; shift 2 ;;
        --max-attempts) MAX_ATTEMPTS="$2"; shift 2 ;;
        --tags-file)    SERVICE_TAGS_FILE="$2"; shift 2 ;;
        -v|--verbose)   VERBOSE=true; shift ;;
        -h|--help)      usage ;;
        *)              echo "Unknown option: $1"; usage ;;
    esac
done

# --- Build target CIDR array ---
TARGET_CIDRS=()

if [[ -n "$TARGET_RANGES" ]]; then
    IFS=',' read -ra TARGET_CIDRS <<< "$TARGET_RANGES"
elif [[ -n "$RANGES_FILE" ]]; then
    while IFS=$'\t' read -r cidr _rest; do
        [[ "$cidr" =~ ^#.*$ ]] && continue
        [[ -z "$cidr" ]] && continue
        TARGET_CIDRS+=("$cidr")
    done < "$RANGES_FILE"
fi

if [[ ${#TARGET_CIDRS[@]} -eq 0 ]]; then
    echo "ERROR: No target ranges specified. Use --ranges or --ranges-file"
    exit 1
fi

echo "Target ranges: ${TARGET_CIDRS[*]}"
log "Total target CIDRs: ${#TARGET_CIDRS[@]}"
for _cidr in "${TARGET_CIDRS[@]}"; do log "  Target: $_cidr"; done

# --- CIDR matching (pure bash) ---
ip_to_int() {
    local ip="$1"
    IFS='.' read -r a b c d <<< "$ip"
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

ip_in_cidr() {
    local ip="$1" cidr="$2"
    local net="${cidr%/*}" mask="${cidr#*/}"
    local ip_n net_n hostmask netmask
    ip_n=$(ip_to_int "$ip")
    net_n=$(ip_to_int "$net")
    hostmask=$(( (1 << (32 - mask)) - 1 ))
    netmask=$(( ~hostmask & 0xFFFFFFFF ))
    [[ $(( ip_n & netmask )) -eq $(( net_n & netmask )) ]]
}

ip_matches_any() {
    local ip="$1"
    for cidr in "${TARGET_CIDRS[@]}"; do
        if ip_in_cidr "$ip" "$cidr"; then
            return 0
        fi
    done
    return 1
}

# --- Region auto-detection ---
detect_region() {
    if [[ -z "$SERVICE_TAGS_FILE" ]] || ! command -v jq &>/dev/null; then
        return
    fi
    local cidr="${TARGET_CIDRS[0]}"
    local region
    region=$(jq -r --arg cidr "$cidr" \
        '.values[] | select(.name | startswith("AzureCloud.")) |
         select(.properties.addressPrefixes[] == $cidr) |
         .name | sub("AzureCloud.";"")' "$SERVICE_TAGS_FILE" 2>/dev/null | head -1)
    if [[ -n "$region" ]]; then
        echo "$region"
    fi
}

if [[ -z "$LOCATION" ]]; then
    detected=$(detect_region)
    if [[ -n "$detected" ]]; then
        LOCATION="$detected"
        echo "Auto-detected region: $LOCATION"
    else
        echo "ERROR: Could not auto-detect region. Use --region <azure_region>"
        exit 1
    fi
fi

# --- Validate SSH key ---
if [[ ! -f "$SSH_KEY" ]]; then
    echo "ERROR: SSH public key not found: $SSH_KEY"
    echo "Generate one: ssh-keygen -t ed25519"
    exit 1
fi

# Derive private key path
SSH_KEY_PRIVATE="${SSH_KEY%.pub}"

# --- Cleanup trap ---
cleanup() {
    echo ""
    echo "Cleaning up temporary IPs..."
    for name in "${TEMP_IP_NAMES[@]}"; do
        if [[ "$name" != "$FOUND_IP_NAME" ]]; then
            az network public-ip delete --resource-group "$RG" --name "$name" --no-wait 2>/dev/null || true
        fi
    done
}
trap cleanup INT TERM EXIT

# --- Ensure resource group ---
echo "Ensuring resource group '$RG' in '$LOCATION'..."
if ! az group show --name "$RG" &>/dev/null; then
    az group create --name "$RG" --location "$LOCATION" --output none
    echo "Created resource group '$RG'"
else
    echo "Resource group '$RG' exists"
fi

# --- IP allocation loop ---
echo ""
echo "Hunting for an IP in target range(s)..."
echo "This may take a while (up to $MAX_ATTEMPTS attempts)."
echo ""

attempt=0

while [[ $attempt -lt $MAX_ATTEMPTS ]] && [[ -z "$FOUND_IP" ]]; do
    attempt=$((attempt + 1))
    ip_name="scan-${attempt}-$$"

    echo -n "Attempt $attempt: "

    log "Creating public IP: $ip_name in $LOCATION"
    output=$(az network public-ip create \
        --resource-group "$RG" \
        --name "$ip_name" \
        --location "$LOCATION" \
        --sku Standard \
        --allocation-method Static 2>&1)

    if [[ $? -ne 0 ]]; then
        log "az create failed. Full output:\n$output"
        if echo "$output" | grep -q "PublicIPCountLimitReached"; then
            echo "hit IP limit, waiting 15s..."
            sleep 15
            attempt=$((attempt - 1))
        else
            echo "create failed: $(echo "$output" | head -1)"
        fi
        continue
    fi

    log "IP resource created: $ip_name"
    [[ "$VERBOSE" == "true" ]] && echo "$output" | head -5 >&2
    TEMP_IP_NAMES+=("$ip_name")

    addr=$(az network public-ip show \
        --resource-group "$RG" \
        --name "$ip_name" \
        --query "ipAddress" -o tsv 2>/dev/null)

    if [[ -z "$addr" ]]; then
        echo "could not read IP"
        log "az show returned empty for $ip_name"
        continue
    fi

    log "Got IP address: $addr — checking against ${#TARGET_CIDRS[@]} target range(s)"
    if ip_matches_any "$addr"; then
        FOUND_IP="$addr"
        FOUND_IP_NAME="$ip_name"
        echo -e "\n  [MATCH] $addr — keeping as $ip_name"
    else
        echo "$addr — not in range, deleting..."
        log "Deleting non-matching IP: $ip_name ($addr)"
        az network public-ip delete --resource-group "$RG" --name "$ip_name" 2>/dev/null
        # Remove from temp list since we waited for delete
        TEMP_IP_NAMES=("${TEMP_IP_NAMES[@]/$ip_name/}")
    fi
done

if [[ -z "$FOUND_IP" ]]; then
    echo ""
    echo "ERROR: No matching IP found after $MAX_ATTEMPTS attempts."
    echo "Try a different region or broader target range."
    exit 1
fi

# --- Create VM ---
echo ""
echo "Creating VM '$VM_NAME' with IP $FOUND_IP..."

log "Starting VM creation pipeline for $VM_NAME"
echo "  Creating NSG..."
log "az network nsg create --name ${VM_NAME}-nsg --location $LOCATION"
az network nsg create \
    --resource-group "$RG" \
    --name "${VM_NAME}-nsg" \
    --location "$LOCATION" \
    --output none

# Open ports for MoaV
MOAV_PORTS=(22 80 443 8443 4443 51820 8080 51821 53 993 9443)
priority=100
for port in "${MOAV_PORTS[@]}"; do
    az network nsg rule create \
        --resource-group "$RG" \
        --nsg-name "${VM_NAME}-nsg" \
        --name "allow-${port}" \
        --priority $priority \
        --destination-port-ranges "$port" \
        --access Allow \
        --protocol '*' \
        --direction Inbound \
        --output none 2>/dev/null || true
    priority=$((priority + 10))
done
log "NSG rules created for ports: ${MOAV_PORTS[*]}"
echo "  NSG created with ports: ${MOAV_PORTS[*]}"

echo "  Creating VNET..."
az network vnet create \
    --resource-group "$RG" \
    --name "${VM_NAME}-vnet" \
    --address-prefix "10.0.0.0/16" \
    --subnet-name "default" \
    --subnet-prefix "10.0.0.0/24" \
    --location "$LOCATION" \
    --output none

echo "  Creating NIC..."
az network nic create \
    --resource-group "$RG" \
    --name "${VM_NAME}-nic" \
    --vnet-name "${VM_NAME}-vnet" \
    --subnet "default" \
    --public-ip-address "$FOUND_IP_NAME" \
    --network-security-group "${VM_NAME}-nsg" \
    --location "$LOCATION" \
    --output none

echo "  Creating VM (this may take a few minutes)..."
log "az vm create --name $VM_NAME --size $VM_SIZE --image ubuntu-24.04 --nics ${VM_NAME}-nic"
az vm create \
    --resource-group "$RG" \
    --name "$VM_NAME" \
    --location "$LOCATION" \
    --nics "${VM_NAME}-nic" \
    --image "Canonical:ubuntu-24_04-lts:server:latest" \
    --size "$VM_SIZE" \
    --admin-username "azureuser" \
    --ssh-key-values "$SSH_KEY" \
    --output none

echo "  Waiting for VM to be ready..."
az vm wait --resource-group "$RG" --name "$VM_NAME" --created --timeout 300 2>/dev/null || true

# --- Wait for SSH ---
echo ""
echo "Waiting for SSH to become available..."
for i in $(seq 1 30); do
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
           -i "$SSH_KEY_PRIVATE" "azureuser@${FOUND_IP}" "echo ok" &>/dev/null; then
        echo "SSH is ready!"
        break
    fi
    log "SSH attempt $i failed, retrying in 10s..."
    echo "  Attempt $i/30 — waiting 10s..."
    sleep 10
done

# --- Output ---
echo ""
echo "========================================"
echo "  VM Ready"
echo "========================================"
echo "  IP Address:    $FOUND_IP"
echo "  SSH:           ssh -i $SSH_KEY_PRIVATE azureuser@$FOUND_IP"
echo "  Region:        $LOCATION"
echo "  Resource Group: $RG"
echo "  VM Name:       $VM_NAME"
echo "========================================"
echo ""
echo "To set up MoaV, run inside the VM:"
echo "  curl -fsSL moav.sh/install.sh | sudo bash"
echo "  sudo moav domainless"
echo ""
echo "Opening SSH session..."
echo ""

# Open interactive SSH
exec ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PRIVATE" "azureuser@${FOUND_IP}"
