#!/bin/bash
#
# cloud_setup.sh — Extended external scanner & VPS provisioner
# Supports: Azure, Oracle Cloud (free tier), GCP, AWS, Hetzner, DigitalOcean
# Finds an IP in a whitelisted range, creates a VM, and SSHs in for MoaV setup.
#

set -euo pipefail

# --- Defaults ---
PROVIDER="azure"
TARGET_RANGES=""
RANGES_FILE=""
LOCATION=""
RG="iran-proxy-rg"
VM_NAME="proxy-vm"
VM_SIZE=""
SSH_KEY="${HOME}/.ssh/id_rsa.pub"
MAX_ATTEMPTS=500
AUTO_DETECT_RANGES=false
VERBOSE=false

log() { [[ "$VERBOSE" == "true" ]] && echo "[DEBUG] $*" >&2 || true; }

usage() {
    cat <<'EOF'
Usage: cloud_setup.sh --provider <provider> [OPTIONS]

Provision a VPS on a whitelisted IP range across multiple cloud providers.

Providers:
  azure          Microsoft Azure (default)
  oracle         Oracle Cloud Infrastructure (free tier available!)
  gcp            Google Cloud Platform
  aws            Amazon Web Services
  digitalocean   DigitalOcean
  hetzner        Hetzner Cloud
  vultr          Vultr

Options:
  --provider <name>     Cloud provider (default: azure)
  --ranges <cidrs>      Comma-separated target CIDRs
  --ranges-file <path>  File with target CIDRs (from iran_scanner.sh or open_ranges.txt)
  --region <region>     Cloud region
  --rg <name>           Resource group / project name (default: iran-proxy-rg)
  --vm-name <name>      VM name (default: proxy-vm)
  --vm-size <size>      VM size (provider-specific, uses cheapest if omitted)
  --ssh-key <path>      SSH public key path (default: ~/.ssh/id_rsa.pub)
  --max-attempts <N>    Max IP allocation attempts (default: 500)
  --scan-only           Only scan for IPs, don't create VM
  --list-regions        List available regions for the provider
  -v, --verbose         Show detailed logs (full CLI output, CIDR matching, etc.)
  -h, --help            Show this help

Examples:
  # Azure: scan South Africa range
  cloud_setup.sh --provider azure --ranges "102.37.128.0/17" --region southafricanorth

  # Oracle Cloud: use free tier in any accessible range
  cloud_setup.sh --provider oracle --ranges-file open_ranges.txt --region me-jeddah-1

  # GCP: target Google service ranges (likely whitelisted)
  cloud_setup.sh --provider gcp --ranges "34.64.0.0/11" --region me-central1-a

  # Just scan for matching IPs without creating a VM
  cloud_setup.sh --provider azure --ranges "102.37.0.0/16" --region southafricanorth --scan-only

  # Use the pre-populated open_ranges.txt filtered by provider
  cloud_setup.sh --provider oracle --ranges-file open_ranges.txt
EOF
    exit 0
}

SCAN_ONLY=false
LIST_REGIONS=false

# --- Argument parsing ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --provider)     PROVIDER="$2"; shift 2 ;;
        --ranges)       TARGET_RANGES="$2"; shift 2 ;;
        --ranges-file)  RANGES_FILE="$2"; shift 2 ;;
        --region)       LOCATION="$2"; shift 2 ;;
        --rg)           RG="$2"; shift 2 ;;
        --vm-name)      VM_NAME="$2"; shift 2 ;;
        --vm-size)      VM_SIZE="$2"; shift 2 ;;
        --ssh-key)      SSH_KEY="$2"; shift 2 ;;
        --max-attempts) MAX_ATTEMPTS="$2"; shift 2 ;;
        --scan-only)    SCAN_ONLY=true; shift ;;
        --list-regions) LIST_REGIONS=true; shift ;;
        -v|--verbose)   VERBOSE=true; shift ;;
        -h|--help)      usage ;;
        *)              echo "Unknown option: $1"; usage ;;
    esac
done

# --- SSH key validation ---
if [[ ! -f "$SSH_KEY" ]]; then
    echo "ERROR: SSH public key not found: $SSH_KEY"
    echo "Generate one: ssh-keygen -t ed25519"
    exit 1
fi
SSH_KEY_PRIVATE="${SSH_KEY%.pub}"

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

# --- Parse ranges file (supports open_ranges.txt format) ---
parse_ranges_file() {
    local file="$1"
    local provider_filter="$2"
    local cidrs=()

    while IFS=$'\t' read -r cidr category notes; do
        [[ "$cidr" =~ ^#.*$ || -z "$cidr" ]] && continue
        # If provider filter set, match category
        if [[ -n "$provider_filter" ]]; then
            case "$provider_filter" in
                azure)   [[ "$category" == azure-* ]] || continue ;;
                oracle)  [[ "$category" == oracle-* ]] || continue ;;
                gcp)     [[ "$category" == google-* ]] || continue ;;
                aws)     [[ "$category" == aws-* ]] || continue ;;
                cloudflare) [[ "$category" == cloudflare* ]] || continue ;;
                *)       ;; # no filter
            esac
        fi
        cidrs+=("$cidr")
    done < "$file"

    echo "${cidrs[@]}"
}

# --- Build target CIDR array ---
TARGET_CIDRS=()

if [[ -n "$TARGET_RANGES" ]]; then
    IFS=',' read -ra TARGET_CIDRS <<< "$TARGET_RANGES"
elif [[ -n "$RANGES_FILE" ]]; then
    read -ra TARGET_CIDRS <<< "$(parse_ranges_file "$RANGES_FILE" "$PROVIDER")"
fi

if [[ ${#TARGET_CIDRS[@]} -eq 0 ]] && [[ "$LIST_REGIONS" != "true" ]]; then
    echo "ERROR: No target ranges specified. Use --ranges, --ranges-file, or check open_ranges.txt"
    exit 1
fi

# ============================================================
# PROVIDER: AZURE
# ============================================================
azure_list_regions() {
    az account list-locations --query "[].name" -o tsv 2>/dev/null | sort
}

azure_check_cli() {
    if ! command -v az &>/dev/null; then
        echo "ERROR: Azure CLI (az) not installed. Install: https://aka.ms/installazurecli"
        exit 1
    fi
    if ! az account show &>/dev/null; then
        echo "ERROR: Not logged in. Run: az login"
        exit 1
    fi
}

AZURE_TEMP_IPS=()
AZURE_FOUND_IP=""
AZURE_FOUND_IP_NAME=""

azure_cleanup() {
    echo "Cleaning up Azure temp IPs..."
    for name in "${AZURE_TEMP_IPS[@]}"; do
        [[ "$name" == "$AZURE_FOUND_IP_NAME" ]] && continue
        az network public-ip delete --resource-group "$RG" --name "$name" --no-wait 2>/dev/null || true
    done
}

azure_scan_ip() {
    local location="$1"

    echo "Ensuring resource group '$RG' in '$location'..."
    if ! az group show --name "$RG" &>/dev/null; then
        az group create --name "$RG" --location "$location" --output none
    fi

    trap azure_cleanup INT TERM EXIT

    local attempt=0
    while [[ $attempt -lt $MAX_ATTEMPTS ]] && [[ -z "$AZURE_FOUND_IP" ]]; do
        attempt=$((attempt + 1))
        local ip_name="scan-${attempt}-$$"
        echo -n "Attempt $attempt: "

        log "Creating public IP: $ip_name in $location"
        local output
        output=$(az network public-ip create \
            --resource-group "$RG" \
            --name "$ip_name" \
            --location "$location" \
            --sku Standard \
            --allocation-method Static 2>&1)

        if [[ $? -ne 0 ]]; then
            log "az create failed. Full output:\n$output"
            if echo "$output" | grep -q "PublicIPCountLimitReached"; then
                echo "hit IP limit, waiting 15s..."
                sleep 15
                attempt=$((attempt - 1))
            else
                echo "failed: $(echo "$output" | head -1)"
            fi
            continue
        fi

        log "IP resource created: $ip_name"
        [[ "$VERBOSE" == "true" ]] && echo "$output" | head -5 >&2
        AZURE_TEMP_IPS+=("$ip_name")

        local addr
        addr=$(az network public-ip show \
            --resource-group "$RG" --name "$ip_name" \
            --query "ipAddress" -o tsv 2>/dev/null)

        if [[ -z "$addr" ]]; then
            echo "could not read IP"
            log "az show returned empty for $ip_name"
            continue
        fi

        log "Got IP: $addr — checking against ${#TARGET_CIDRS[@]} range(s)"
        if ip_matches_any "$addr"; then
            AZURE_FOUND_IP="$addr"
            AZURE_FOUND_IP_NAME="$ip_name"
            echo -e "\n  [MATCH] $addr"
        else
            echo "$addr — not in range, deleting..."
            log "Deleting non-matching IP: $ip_name ($addr)"
            az network public-ip delete --resource-group "$RG" --name "$ip_name" 2>/dev/null
            AZURE_TEMP_IPS=("${AZURE_TEMP_IPS[@]/$ip_name/}")
        fi
    done

    echo "$AZURE_FOUND_IP"
}

azure_create_vm() {
    local ip_name="$1" location="$2" found_ip="$3"
    local size="${VM_SIZE:-Standard_B1s}"

    echo "Creating Azure VM '$VM_NAME'..."

    echo "  Creating NSG..."
    az network nsg create --resource-group "$RG" --name "${VM_NAME}-nsg" \
        --location "$location" --output none

    local ports=(22 80 443 8443 4443 51820 8080 51821 53 993 9443)
    local priority=100
    for port in "${ports[@]}"; do
        az network nsg rule create --resource-group "$RG" --nsg-name "${VM_NAME}-nsg" \
            --name "allow-${port}" --priority $priority \
            --destination-port-ranges "$port" --access Allow --protocol '*' \
            --direction Inbound --output none 2>/dev/null || true
        priority=$((priority + 10))
    done

    echo "  Creating VNET..."
    az network vnet create --resource-group "$RG" --name "${VM_NAME}-vnet" \
        --address-prefix "10.0.0.0/16" --subnet-name "default" \
        --subnet-prefix "10.0.0.0/24" --location "$location" --output none

    echo "  Creating NIC..."
    az network nic create --resource-group "$RG" --name "${VM_NAME}-nic" \
        --vnet-name "${VM_NAME}-vnet" --subnet "default" \
        --public-ip-address "$ip_name" --network-security-group "${VM_NAME}-nsg" \
        --location "$location" --output none

    echo "  Creating VM..."
    az vm create --resource-group "$RG" --name "$VM_NAME" --location "$location" \
        --nics "${VM_NAME}-nic" --image "Canonical:ubuntu-24_04-lts:server:latest" \
        --size "$size" --admin-username "azureuser" \
        --ssh-key-values "$SSH_KEY" --output none

    az vm wait --resource-group "$RG" --name "$VM_NAME" --created --timeout 300 2>/dev/null || true
    echo "  VM created."
    echo "azureuser"
}

# ============================================================
# PROVIDER: ORACLE CLOUD (OCI) — FREE TIER
# ============================================================
oci_list_regions() {
    if command -v oci &>/dev/null; then
        oci iam region list --query "data[].name" --raw-output 2>/dev/null | jq -r '.[]' | sort
    else
        echo "ap-mumbai-1 ap-seoul-1 ap-tokyo-1 eu-amsterdam-1 eu-frankfurt-1 me-jeddah-1 uk-london-1 us-ashburn-1 us-phoenix-1"
    fi
}

oci_check_cli() {
    if ! command -v oci &>/dev/null; then
        echo "ERROR: OCI CLI not installed. Install: https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm"
        exit 1
    fi
}

oci_scan_ip() {
    local region="$1"
    echo ""
    echo "Oracle Cloud IP scanning works differently:"
    echo "  OCI assigns IPs from the regional pool. You can:"
    echo "  1. Create an instance and check the assigned IP"
    echo "  2. Reserve ephemeral public IPs and check"
    echo ""
    echo "Since OCI has free tier (ARM A1 instances), this is cost-free."
    echo ""

    local attempt=0
    local found_ip=""

    # Get compartment ID
    local compartment_id
    compartment_id=$(oci iam compartment list --compartment-id-in-subtree true \
        --query "data[0].\"compartment-id\"" --raw-output 2>/dev/null)

    if [[ -z "$compartment_id" ]]; then
        compartment_id=$(oci iam compartment list \
            --query "data[0].id" --raw-output 2>/dev/null)
    fi

    while [[ $attempt -lt $MAX_ATTEMPTS ]] && [[ -z "$found_ip" ]]; do
        attempt=$((attempt + 1))
        echo -n "Attempt $attempt: "

        # Reserve a public IP
        log "OCI: reserving public IP scan-${attempt}-$$ in $region"
        local result
        result=$(oci network public-ip create \
            --compartment-id "$compartment_id" \
            --lifetime RESERVED \
            --display-name "scan-${attempt}-$$" \
            --region "$region" 2>&1)

        if [[ $? -ne 0 ]]; then
            log "OCI create failed:\n$result"
            echo "failed: $(echo "$result" | head -1)"
            sleep 2
            continue
        fi

        local ip_id addr
        ip_id=$(echo "$result" | jq -r '.data.id')
        addr=$(echo "$result" | jq -r '.data."ip-address"')

        if ip_matches_any "$addr"; then
            found_ip="$addr"
            echo -e "\n  [MATCH] $addr (OCID: $ip_id)"
        else
            echo "$addr — not in range, deleting..."
            oci network public-ip delete --public-ip-id "$ip_id" --force --region "$region" 2>/dev/null
        fi
    done

    echo "$found_ip"
}

oci_create_vm() {
    local region="$1" found_ip="$2"
    local shape="${VM_SIZE:-VM.Standard.A1.Flex}"

    echo ""
    echo "OCI VM creation is complex (VCN, subnet, security list, instance)."
    echo "Recommended: use the OCI Console or Terraform for VM creation."
    echo ""
    echo "Quick manual steps:"
    echo "  1. Create VCN: oci network vcn create ..."
    echo "  2. Create subnet with internet gateway"
    echo "  3. Create instance: oci compute instance launch --shape $shape ..."
    echo "  4. Assign the reserved IP to the instance VNIC"
    echo ""
    echo "For free tier, use shape: VM.Standard.A1.Flex (4 OCPU, 24GB RAM)"
    echo ""
    echo "Reserved IP: $found_ip"
    echo ""

    # We won't auto-create OCI VM since it requires too many IDs
    # Instead return info for manual setup
    echo "opc"  # default OCI user
}

# ============================================================
# PROVIDER: GCP
# ============================================================
gcp_list_regions() {
    if command -v gcloud &>/dev/null; then
        gcloud compute zones list --format="value(name)" 2>/dev/null | sort
    else
        echo "me-central1-a me-central1-b me-central1-c me-west1-a me-west1-b europe-west1-b us-central1-a"
    fi
}

gcp_check_cli() {
    if ! command -v gcloud &>/dev/null; then
        echo "ERROR: gcloud CLI not installed. Install: https://cloud.google.com/sdk/docs/install"
        exit 1
    fi
}

gcp_scan_ip() {
    local zone="$1"
    local region="${zone%-*}"  # e.g. me-central1-a -> me-central1
    local found_ip=""
    local attempt=0

    while [[ $attempt -lt $MAX_ATTEMPTS ]] && [[ -z "$found_ip" ]]; do
        attempt=$((attempt + 1))
        local ip_name="scan-${attempt}-$$"
        echo -n "Attempt $attempt: "

        log "GCP: reserving address $ip_name in $region"
        local output
        output=$(gcloud compute addresses create "$ip_name" \
            --region "$region" --network-tier PREMIUM 2>&1)

        if [[ $? -ne 0 ]]; then
            log "GCP create failed:\n$output"
            echo "failed: $(echo "$output" | head -1)"
            continue
        fi

        local addr
        addr=$(gcloud compute addresses describe "$ip_name" \
            --region "$region" --format="value(address)" 2>/dev/null)

        if ip_matches_any "$addr"; then
            found_ip="$addr"
            echo -e "\n  [MATCH] $addr"
        else
            echo "$addr — not in range, deleting..."
            gcloud compute addresses delete "$ip_name" --region "$region" --quiet 2>/dev/null
        fi
    done

    echo "$found_ip"
}

gcp_create_vm() {
    local zone="$1" found_ip="$2"
    local machine="${VM_SIZE:-e2-micro}"
    local region="${zone%-*}"
    local ip_name
    # Find the address name for the matched IP
    ip_name=$(gcloud compute addresses list --region "$region" \
        --filter="address=$found_ip" --format="value(name)" 2>/dev/null | head -1)

    echo "Creating GCP VM..."
    gcloud compute instances create "$VM_NAME" \
        --zone "$zone" \
        --machine-type "$machine" \
        --image-family ubuntu-2404-lts-amd64 \
        --image-project ubuntu-os-cloud \
        --address "$ip_name" \
        --tags "moav-proxy" \
        --metadata "ssh-keys=ubuntu:$(cat "$SSH_KEY")"

    # Firewall rules
    gcloud compute firewall-rules create "allow-moav" \
        --allow tcp:22,tcp:80,tcp:443,tcp:8443,tcp:4443,tcp:8080,tcp:9443,udp:51820,tcp:993,tcp:53,udp:53 \
        --target-tags "moav-proxy" \
        --quiet 2>/dev/null || true

    echo "ubuntu"
}

# ============================================================
# PROVIDER: DIGITALOCEAN
# ============================================================
do_list_regions() {
    if command -v doctl &>/dev/null; then
        doctl compute region list --format Slug --no-header 2>/dev/null | sort
    else
        echo "ams3 blr1 fra1 lon1 nyc1 nyc3 sfo3 sgp1 tor1"
    fi
}

do_check_cli() {
    if ! command -v doctl &>/dev/null; then
        echo "ERROR: doctl not installed. Install: https://docs.digitalocean.com/reference/doctl/how-to/install/"
        exit 1
    fi
}

do_scan_ip() {
    local region="$1"
    local found_ip=""
    local attempt=0

    while [[ $attempt -lt $MAX_ATTEMPTS ]] && [[ -z "$found_ip" ]]; do
        attempt=$((attempt + 1))
        echo -n "Attempt $attempt: "

        log "DO: reserving IP in $region"
        local result
        result=$(doctl compute reserved-ip create --region "$region" --output json 2>&1)

        if [[ $? -ne 0 ]]; then
            log "DO create failed:\n$result"
            echo "failed: $(echo "$result" | head -1)"
            continue
        fi

        local addr
        addr=$(echo "$result" | jq -r '.[0].ip')

        if ip_matches_any "$addr"; then
            found_ip="$addr"
            echo -e "\n  [MATCH] $addr"
        else
            echo "$addr — not in range, deleting..."
            doctl compute reserved-ip delete "$addr" --force 2>/dev/null
        fi
    done

    echo "$found_ip"
}

do_create_vm() {
    local region="$1" found_ip="$2"
    local size="${VM_SIZE:-s-1vcpu-1gb}"

    echo "Creating DigitalOcean droplet..."

    # Import SSH key if needed
    local key_fingerprint
    key_fingerprint=$(ssh-keygen -lf "$SSH_KEY" -E md5 2>/dev/null | awk '{print $2}' | sed 's/MD5://')

    local key_id
    key_id=$(doctl compute ssh-key list --format ID,FingerPrint --no-header 2>/dev/null \
        | grep "$key_fingerprint" | awk '{print $1}')

    if [[ -z "$key_id" ]]; then
        key_id=$(doctl compute ssh-key import "moav-key" --public-key-file "$SSH_KEY" \
            --format ID --no-header 2>/dev/null)
    fi

    local droplet_id
    droplet_id=$(doctl compute droplet create "$VM_NAME" \
        --region "$region" \
        --size "$size" \
        --image ubuntu-24-04-x64 \
        --ssh-keys "$key_id" \
        --format ID --no-header --wait 2>/dev/null)

    # Assign reserved IP
    doctl compute reserved-ip-action assign "$found_ip" "$droplet_id" 2>/dev/null

    echo "root"
}

# ============================================================
# PROVIDER: HETZNER
# ============================================================
hetzner_list_regions() {
    if command -v hcloud &>/dev/null; then
        hcloud datacenter list -o columns=name 2>/dev/null
    else
        echo "fsn1-dc14 nbg1-dc3 hel1-dc2 ash-dc1 hil-dc1"
    fi
}

hetzner_check_cli() {
    if ! command -v hcloud &>/dev/null; then
        echo "ERROR: hcloud CLI not installed. Install: https://github.com/hetznercloud/cli"
        exit 1
    fi
}

hetzner_scan_ip() {
    local location="$1"
    local found_ip=""
    local attempt=0

    # Hetzner doesn't support reserving IPs without a server easily
    # But we can create floating IPs
    while [[ $attempt -lt $MAX_ATTEMPTS ]] && [[ -z "$found_ip" ]]; do
        attempt=$((attempt + 1))
        echo -n "Attempt $attempt: "

        log "Hetzner: creating floating IP in $location"
        local result
        result=$(hcloud floating-ip create --type ipv4 \
            --home-location "$location" --description "scan-${attempt}-$$" -o json 2>&1)

        if [[ $? -ne 0 ]]; then
            log "Hetzner create failed:\n$result"
            echo "failed: $(echo "$result" | head -1)"
            continue
        fi

        local addr fip_id
        addr=$(echo "$result" | jq -r '.floating_ip.ip')
        fip_id=$(echo "$result" | jq -r '.floating_ip.id')

        if ip_matches_any "$addr"; then
            found_ip="$addr"
            echo -e "\n  [MATCH] $addr (ID: $fip_id)"
        else
            echo "$addr — not in range, deleting..."
            hcloud floating-ip delete "$fip_id" 2>/dev/null
        fi
    done

    echo "$found_ip"
}

hetzner_create_vm() {
    local location="$1" found_ip="$2"
    local type="${VM_SIZE:-cx22}"

    echo "Creating Hetzner server..."
    hcloud server create \
        --name "$VM_NAME" \
        --type "$type" \
        --image ubuntu-24.04 \
        --location "$location" \
        --ssh-key "$(cat "$SSH_KEY")" 2>/dev/null

    # Assign floating IP (find ID by IP)
    local fip_id
    fip_id=$(hcloud floating-ip list -o json 2>/dev/null | jq -r ".[] | select(.ip == \"$found_ip\") | .id")
    if [[ -n "$fip_id" ]]; then
        local server_id
        server_id=$(hcloud server list -o json 2>/dev/null | jq -r ".[] | select(.name == \"$VM_NAME\") | .id")
        hcloud floating-ip assign "$fip_id" "$server_id" 2>/dev/null
    fi

    echo "root"
}

# ============================================================
# PROVIDER: VULTR
# ============================================================
vultr_list_regions() {
    if command -v vultr-cli &>/dev/null; then
        vultr-cli regions list 2>/dev/null
    else
        echo "ams ewr fra lhr nrt ord sgp syd"
    fi
}

vultr_check_cli() {
    if ! command -v vultr-cli &>/dev/null; then
        echo "ERROR: vultr-cli not installed. Install: https://github.com/vultr/vultr-cli"
        exit 1
    fi
}

vultr_scan_ip() {
    local region="$1"
    local found_ip=""
    local attempt=0

    while [[ $attempt -lt $MAX_ATTEMPTS ]] && [[ -z "$found_ip" ]]; do
        attempt=$((attempt + 1))
        echo -n "Attempt $attempt: "

        log "Vultr: reserving IP in $region"
        local result
        result=$(vultr-cli reserved-ip create --region "$region" --ip-type v4 --label "scan-${attempt}-$$" -o json 2>&1)

        if [[ $? -ne 0 ]]; then
            log "Vultr create failed:\n$result"
            echo "failed: $(echo "$result" | head -1)"
            continue
        fi

        local addr ip_id
        addr=$(echo "$result" | jq -r '.reserved_ip.subnet')
        ip_id=$(echo "$result" | jq -r '.reserved_ip.id')

        if ip_matches_any "$addr"; then
            found_ip="$addr"
            echo -e "\n  [MATCH] $addr"
        else
            echo "$addr — not in range, deleting..."
            vultr-cli reserved-ip delete "$ip_id" 2>/dev/null
        fi
    done

    echo "$found_ip"
}

vultr_create_vm() {
    local region="$1" found_ip="$2"
    echo "Vultr VM creation — use the Vultr console or vultr-cli to create and attach."
    echo "Reserved IP: $found_ip"
    echo "root"
}

# ============================================================
# MAIN ORCHESTRATION
# ============================================================

# List regions if requested
if [[ "$LIST_REGIONS" == "true" ]]; then
    echo "Available regions for $PROVIDER:"
    case "$PROVIDER" in
        azure)        azure_list_regions ;;
        oracle)       oci_list_regions ;;
        gcp)          gcp_list_regions ;;
        digitalocean) do_list_regions ;;
        hetzner)      hetzner_list_regions ;;
        vultr)        vultr_list_regions ;;
        *)            echo "Unknown provider: $PROVIDER" ;;
    esac
    exit 0
fi

# Validate region
if [[ -z "$LOCATION" ]]; then
    echo "ERROR: --region is required"
    exit 1
fi

echo "========================================"
echo "  Cloud VPS Setup"
echo "========================================"
echo "  Provider:  $PROVIDER"
echo "  Region:    $LOCATION"
echo "  Targets:   ${#TARGET_CIDRS[@]} CIDR range(s)"
echo "  Max tries: $MAX_ATTEMPTS"
echo "  Verbose:   $VERBOSE"
echo "========================================"
echo ""

log "Target CIDRs:"
for _cidr in "${TARGET_CIDRS[@]}"; do log "  $_cidr"; done
log "SSH key: $SSH_KEY"
log "VM name: $VM_NAME, size: ${VM_SIZE:-default}"

# Check CLI
case "$PROVIDER" in
    azure)        azure_check_cli ;;
    oracle)       oci_check_cli ;;
    gcp)          gcp_check_cli ;;
    digitalocean) do_check_cli ;;
    hetzner)      hetzner_check_cli ;;
    vultr)        vultr_check_cli ;;
    *)            echo "ERROR: Unknown provider: $PROVIDER"; exit 1 ;;
esac

# Scan for IP
echo "Scanning for IP in target range(s)..."
FOUND_IP=""

case "$PROVIDER" in
    azure)        FOUND_IP=$(azure_scan_ip "$LOCATION") ;;
    oracle)       FOUND_IP=$(oci_scan_ip "$LOCATION") ;;
    gcp)          FOUND_IP=$(gcp_scan_ip "$LOCATION") ;;
    digitalocean) FOUND_IP=$(do_scan_ip "$LOCATION") ;;
    hetzner)      FOUND_IP=$(hetzner_scan_ip "$LOCATION") ;;
    vultr)        FOUND_IP=$(vultr_scan_ip "$LOCATION") ;;
esac

# Get last non-empty line (the actual IP)
FOUND_IP=$(echo "$FOUND_IP" | tail -1 | tr -d '[:space:]')

if [[ -z "$FOUND_IP" ]]; then
    echo ""
    echo "ERROR: No matching IP found after scanning."
    exit 1
fi

echo ""
echo "Found IP: $FOUND_IP"

if [[ "$SCAN_ONLY" == "true" ]]; then
    echo ""
    echo "Scan complete (--scan-only). IP reserved: $FOUND_IP"
    exit 0
fi

# Create VM
echo ""
SSH_USER=""
case "$PROVIDER" in
    azure)        SSH_USER=$(azure_create_vm "$AZURE_FOUND_IP_NAME" "$LOCATION" "$FOUND_IP") ;;
    oracle)       SSH_USER=$(oci_create_vm "$LOCATION" "$FOUND_IP") ;;
    gcp)          SSH_USER=$(gcp_create_vm "$LOCATION" "$FOUND_IP") ;;
    digitalocean) SSH_USER=$(do_create_vm "$LOCATION" "$FOUND_IP") ;;
    hetzner)      SSH_USER=$(hetzner_create_vm "$LOCATION" "$FOUND_IP") ;;
    vultr)        SSH_USER=$(vultr_create_vm "$LOCATION" "$FOUND_IP") ;;
esac

# Get last line as username
SSH_USER=$(echo "$SSH_USER" | tail -1 | tr -d '[:space:]')

# Wait for SSH
echo ""
echo "Waiting for SSH..."
for i in $(seq 1 30); do
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
           -i "$SSH_KEY_PRIVATE" "${SSH_USER}@${FOUND_IP}" "echo ok" &>/dev/null; then
        break
    fi
    log "SSH attempt $i failed for ${SSH_USER}@${FOUND_IP}"
    echo "  Attempt $i/30..."
    sleep 10
done

# Final output
echo ""
echo "========================================"
echo "  VPS Ready"
echo "========================================"
echo "  Provider:  $PROVIDER"
echo "  IP:        $FOUND_IP"
echo "  SSH:       ssh -i $SSH_KEY_PRIVATE ${SSH_USER}@${FOUND_IP}"
echo "  Region:    $LOCATION"
echo "========================================"
echo ""
echo "To set up MoaV proxy, run inside the VM:"
echo "  curl -fsSL moav.sh/install.sh | sudo bash"
echo "  sudo moav domainless"
echo ""
echo "Opening SSH session..."
echo ""

exec ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PRIVATE" "${SSH_USER}@${FOUND_IP}"
