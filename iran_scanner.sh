#!/bin/bash
#
# iran_scanner.sh — Run inside Iran to find which Azure IP ranges are accessible
# during internet shutdowns. Tests ICMP, TCP, and HTTPS probes.
#

set -euo pipefail

# Defaults
JSON_FILE=""
REGION_FILTER=""
MAX_PARALLEL=50
PORTS="443,80,22"
OUTPUT_FILE="accessible_ranges_$(date +%Y%m%d_%H%M%S).txt"
MIN_PREFIX=28

usage() {
    cat <<'EOF'
Usage: iran_scanner.sh [OPTIONS]

Discover which Azure IP ranges are accessible from inside Iran.

Options:
  --file <path>       Use a local ServiceTags JSON file instead of downloading
  --region <pattern>  Only scan regions matching pattern (e.g. "southafrica|europe")
  --parallel <N>      Max concurrent probes (default: 50)
  --ports <list>      Comma-separated ports to test (default: 443,80,22)
  --output <path>     Output file path
  --min-prefix <N>    Skip CIDRs smaller than /N (default: 28)
  -h, --help          Show this help
EOF
    exit 0
}

# --- Argument parsing ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --file)      JSON_FILE="$2"; shift 2 ;;
        --region)    REGION_FILTER="$2"; shift 2 ;;
        --parallel)  MAX_PARALLEL="$2"; shift 2 ;;
        --ports)     PORTS="$2"; shift 2 ;;
        --output)    OUTPUT_FILE="$2"; shift 2 ;;
        --min-prefix) MIN_PREFIX="$2"; shift 2 ;;
        -h|--help)   usage ;;
        *)           echo "Unknown option: $1"; usage ;;
    esac
done

# --- Download ServiceTags JSON ---
get_service_tags_url() {
    # Try scraping the Microsoft download page
    local url
    url=$(curl -sL "https://www.microsoft.com/en-us/download/details.aspx?id=56519" 2>/dev/null \
        | grep -oE 'https://download\.microsoft\.com/download/[^"]+ServiceTags_Public_[0-9]+\.json' \
        | head -1)
    if [[ -n "$url" ]]; then
        echo "$url"
        return
    fi

    # Fallback: try last 7 days (published weekly, usually Monday)
    for i in $(seq 0 6); do
        local d
        # macOS date vs GNU date
        if date -v-${i}d +%Y%m%d &>/dev/null; then
            d=$(date -v-${i}d +%Y%m%d)
        else
            d=$(date -d "-${i} days" +%Y%m%d)
        fi
        local test_url="https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_${d}.json"
        if curl -sI "$test_url" 2>/dev/null | grep -q "200"; then
            echo "$test_url"
            return
        fi
    done

    echo ""
}

download_service_tags() {
    local tmpfile
    tmpfile=$(mktemp /tmp/servicetags_XXXXXX.json)

    echo "Fetching Azure ServiceTags download URL..."
    local url
    url=$(get_service_tags_url)

    if [[ -z "$url" ]]; then
        echo "ERROR: Could not find ServiceTags download URL."
        echo "Download manually from: https://www.microsoft.com/en-us/download/details.aspx?id=56519"
        echo "Then run: $0 --file <path_to_json>"
        exit 1
    fi

    echo "Downloading: $url"
    if ! curl -sL "$url" -o "$tmpfile"; then
        echo "ERROR: Download failed. Try --file with a pre-downloaded JSON."
        exit 1
    fi

    echo "$tmpfile"
}

# --- CIDR helpers (pure bash, no dependencies) ---
ip_to_int() {
    local ip="$1"
    IFS='.' read -r a b c d <<< "$ip"
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

int_to_ip() {
    local n="$1"
    echo "$(( (n >> 24) & 255 )).$(( (n >> 16) & 255 )).$(( (n >> 8) & 255 )).$(( n & 255 ))"
}

cidr_sample_ip() {
    local cidr="$1"
    local ip="${cidr%/*}"
    local n
    n=$(ip_to_int "$ip")
    int_to_ip $(( n + 1 ))
}

cidr_to_24() {
    # Round a CIDR to its containing /24
    local cidr="$1"
    local ip="${cidr%/*}"
    IFS='.' read -r a b c _ <<< "$ip"
    echo "${a}.${b}.${c}.0/24"
}

# --- Extract CIDRs from JSON ---
extract_cidrs() {
    local json_file="$1"

    if command -v jq &>/dev/null; then
        if [[ -n "$REGION_FILTER" ]]; then
            jq -r --arg pat "$REGION_FILTER" \
                '.values[] | select(.name | test("AzureCloud\\.")) |
                 select(.name | test($pat; "i")) |
                 .properties.addressPrefixes[]' "$json_file"
        else
            jq -r '.values[] | select(.name | test("AzureCloud\\.")) |
                    .properties.addressPrefixes[]' "$json_file"
        fi
    else
        # Fallback: grep for CIDR patterns
        echo "WARNING: jq not found, using grep fallback (less accurate)" >&2
        grep -oE '"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+"' "$json_file" | tr -d '"'
    fi
}

# --- Probe function ---
probe_ip() {
    local ip="$1"
    local cidr="$2"
    local results=""

    # ICMP ping
    if ping -c1 -W2 "$ip" &>/dev/null; then
        results="${results}icmp,"
    fi

    # TCP port probes
    IFS=',' read -ra port_list <<< "$PORTS"
    for port in "${port_list[@]}"; do
        if (echo >/dev/tcp/"$ip"/"$port") 2>/dev/null; then
            results="${results}tcp${port},"
        elif command -v nc &>/dev/null && nc -z -w3 "$ip" "$port" 2>/dev/null; then
            results="${results}tcp${port},"
        fi
    done

    # HTTPS probe (only if 443 is in the port list)
    if [[ "$PORTS" == *"443"* ]]; then
        if curl -sk --connect-timeout 3 --max-time 5 "https://$ip/" -o /dev/null 2>/dev/null; then
            results="${results}https,"
        fi
    fi

    # Remove trailing comma
    results="${results%,}"

    if [[ -n "$results" ]]; then
        echo -e "${cidr}\t${ip}\t${results}"
    fi
}

export -f probe_ip ip_to_int int_to_ip cidr_sample_ip
export PORTS

# --- Main ---
main() {
    # Get JSON file
    local json_file="$JSON_FILE"
    local tmp_downloaded=""
    if [[ -z "$json_file" ]]; then
        json_file=$(download_service_tags)
        tmp_downloaded="$json_file"
    fi

    if [[ ! -f "$json_file" ]]; then
        echo "ERROR: JSON file not found: $json_file"
        exit 1
    fi

    echo "Extracting Azure IP ranges..."
    local cidr_list
    cidr_list=$(mktemp /tmp/cidrs_XXXXXX.txt)

    # Extract IPv4 CIDRs, filter by prefix size, deduplicate to /24
    extract_cidrs "$json_file" \
        | grep -v ':' \
        | while read -r cidr; do
            local mask="${cidr#*/}"
            if [[ "$mask" -le "$MIN_PREFIX" ]]; then
                if [[ "$mask" -le 24 ]]; then
                    echo "$cidr"
                else
                    cidr_to_24 "$cidr"
                fi
            fi
        done \
        | sort -u > "$cidr_list"

    local total
    total=$(wc -l < "$cidr_list" | tr -d ' ')
    echo "Found $total unique IP blocks to scan"
    echo "Scanning with $MAX_PARALLEL parallel probes..."
    echo ""

    # Header
    echo -e "# Accessible Azure IP Ranges — $(date)" > "$OUTPUT_FILE"
    echo -e "# CIDR\tSampleIP\tMethods" >> "$OUTPUT_FILE"

    # Run probes in parallel
    local scanned=0
    local found=0

    while read -r cidr; do
        local sample_ip
        sample_ip=$(cidr_sample_ip "$cidr")

        (
            result=$(probe_ip "$sample_ip" "$cidr")
            if [[ -n "$result" ]]; then
                echo "$result"
                echo "$result" >> "$OUTPUT_FILE"
            fi
        ) &

        scanned=$((scanned + 1))

        # Throttle parallelism
        while [[ $(jobs -rp | wc -l) -ge $MAX_PARALLEL ]]; do
            sleep 0.1
        done

        # Progress every 100 blocks
        if (( scanned % 100 == 0 )); then
            echo "Progress: $scanned / $total blocks scanned..."
        fi
    done < "$cidr_list"

    # Wait for remaining jobs
    wait

    found=$(grep -c -v '^#' "$OUTPUT_FILE" 2>/dev/null || echo 0)

    echo ""
    echo "========================================"
    echo "  Scan Complete"
    echo "========================================"
    echo "  Blocks scanned: $total"
    echo "  Accessible:     $found"
    echo "  Results saved:  $OUTPUT_FILE"
    echo "========================================"

    # Cleanup
    rm -f "$cidr_list"
    [[ -n "$tmp_downloaded" ]] && rm -f "$tmp_downloaded"
}

main
