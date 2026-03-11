#!/bin/bash
#
# iran_scanner.sh — Run inside Iran to find which cloud IP ranges are accessible
# during internet shutdowns. Tests ICMP, TCP, and HTTPS probes.
#
# Supports: Azure, AWS, GCP, Oracle Cloud, Cloudflare, Fastly, or plain CIDR lists.
#

set -eo pipefail

# Defaults
TEMP_FILES=()
INPUT_FILE=""
FORMAT=""
REGION_FILTER=""
MAX_PARALLEL=50
PORTS="443,80,22"
OUTPUT_DIR="scans"
OUTPUT_FILE=""
MIN_PREFIX=28
VERBOSE=false
PROVIDER=""
PROBES="icmp,tcp,https"

log() { [[ "$VERBOSE" == "true" ]] && echo "[DEBUG] $*" >&2 || true; }

usage() {
    cat <<'EOF'
Usage: iran_scanner.sh [OPTIONS]

Discover which cloud IP ranges are accessible from inside Iran.

Input (one of):
  --file <path>       Local file: JSON (Azure/AWS/GCP/OCI/Fastly) or plain CIDR list
  --provider <name>   Download IP ranges from: azure, aws, gcp, oracle, cloudflare, fastly

Options:
  --format <fmt>      Force format: azure, aws, gcp, oracle, cloudflare, fastly, cidrs
                      (auto-detected from file content if omitted)
  --region <pattern>  Only scan regions matching pattern (e.g. "southafrica|us-east")
  --parallel <N>      Max concurrent probes (default: 50)
  --ports <list>      Comma-separated ports to test (default: 443,80,22)
  --output <path>     Output CSV file path (default: scans/scan_TIMESTAMP.csv)
  --output-dir <dir>  Output directory (default: scans/)
  --probes <list>     Comma-separated probe types (default: icmp,tcp,https)
                      e.g. --probes icmp (ping only), --probes icmp,tcp
  --min-prefix <N>    Skip CIDRs smaller than /N (default: 28)
  -v, --verbose       Show detailed probe logs for each IP
  -h, --help          Show this help

Supported formats:
  azure       Azure ServiceTags_Public JSON (.values[].properties.addressPrefixes)
  aws         AWS ip-ranges.json (.prefixes[].ip_prefix)
  gcp         GCP cloud.json (.prefixes[].ipv4Prefix)
  oracle      OCI public_ip_ranges.json (.regions[].cidrs[].cidr)
  cloudflare  Plain text CIDR list (one per line)
  fastly      Fastly JSON (.addresses[])
  cidrs       Plain text CIDR list (one per line, like all_azure_ips.txt)

Examples:
  iran_scanner.sh --provider azure
  iran_scanner.sh --file samples/ServiceTags_Public_20260309.json --region "southafrica"
  iran_scanner.sh --file samples/all_azure_ips.txt
  iran_scanner.sh --provider aws --region "us-east|eu-west"
  iran_scanner.sh --file samples/all_cidrs.txt --format cidrs
  iran_scanner.sh --file samples/all_cidrs.txt --probes icmp          # ping only
  iran_scanner.sh --file samples/aws_ip_ranges.json --probes icmp,tcp # no HTTPS
EOF
    exit 0
}

# --- Argument parsing ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --file)       INPUT_FILE="$2"; shift 2 ;;
        --provider)   PROVIDER="$2"; shift 2 ;;
        --format)     FORMAT="$2"; shift 2 ;;
        --region)     REGION_FILTER="$2"; shift 2 ;;
        --parallel)   MAX_PARALLEL="$2"; shift 2 ;;
        --ports)      PORTS="$2"; shift 2 ;;
        --output)     OUTPUT_FILE="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --min-prefix) MIN_PREFIX="$2"; shift 2 ;;
        --probes)     PROBES="$2"; shift 2 ;;
        -v|--verbose) VERBOSE=true; shift ;;
        -h|--help)    usage ;;
        *)            echo "Unknown option: $1"; usage ;;
    esac
done

# Set output file
mkdir -p "$OUTPUT_DIR"
if [[ -z "$OUTPUT_FILE" ]]; then
    OUTPUT_FILE="${OUTPUT_DIR}/scan_$(date +%Y%m%d_%H%M%S).csv"
fi

# --- Cleanup: kill ALL descendants recursively ---
kill_tree() {
    local pid="$1"
    local children
    children=$(pgrep -P "$pid" 2>/dev/null) || true
    for child in $children; do
        kill_tree "$child"
    done
    kill "$pid" 2>/dev/null || true
}

register_temp() { TEMP_FILES+=("$1"); }

cleanup() {
    trap - INT TERM EXIT

    # Show shutdown message before suppressing stderr
    printf "\n  Shutting down... " >&2

    # Suppress job control noise
    exec 2>/dev/null

    # Kill entire process tree recursively
    local children
    children=$(jobs -rp 2>/dev/null) || true
    for pid in $children; do
        kill_tree "$pid"
    done

    # Fallback: kill by parent
    pkill -P $$ 2>/dev/null || true
    sleep 0.2
    pkill -9 -P $$ 2>/dev/null || true

    # Wait silently to reap zombies
    wait 2>/dev/null || true

    # Restore stderr for final message
    exec 2>/dev/tty 2>/dev/null || exec 2>&1

    # Clean temp files
    for f in "${TEMP_FILES[@]}"; do
        if [[ -d "$f" ]]; then
            rm -rf "$f" 2>/dev/null
        else
            rm -f "$f" 2>/dev/null
        fi
    done

    echo "done." >&2
    exit 0
}
trap cleanup INT TERM

# Normal exit: just clean temp files (no process killing needed)
cleanup_files() {
    for f in "${TEMP_FILES[@]}"; do
        if [[ -d "$f" ]]; then
            rm -rf "$f" 2>/dev/null
        else
            rm -f "$f" 2>/dev/null
        fi
    done
}
trap cleanup_files EXIT

# --- Provider download URLs ---
download_provider() {
    local provider="$1"
    local tmpfile
    tmpfile=$(mktemp /tmp/iran_scanner_dl.XXXXXXXXXX)

    case "$provider" in
        azure)
            echo "Downloading Azure ServiceTags..."
            local url
            url=$(get_azure_url)
            if [[ -z "$url" ]]; then
                echo "ERROR: Could not find Azure ServiceTags URL. Use --file instead."
                exit 1
            fi
            log "Azure URL: $url"
            curl -sL "$url" -o "$tmpfile"
            ;;
        aws)
            echo "Downloading AWS ip-ranges.json..."
            curl -sL "https://ip-ranges.amazonaws.com/ip-ranges.json" -o "$tmpfile"
            ;;
        gcp)
            echo "Downloading GCP cloud.json..."
            curl -sL "https://www.gstatic.com/ipranges/cloud.json" -o "$tmpfile"
            ;;
        oracle)
            echo "Downloading Oracle Cloud IP ranges..."
            curl -sL "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json" -o "$tmpfile"
            ;;
        cloudflare)
            echo "Downloading Cloudflare IP ranges..."
            curl -sL "https://www.cloudflare.com/ips-v4" -o "$tmpfile"
            ;;
        fastly)
            echo "Downloading Fastly IP ranges..."
            curl -sL "https://api.fastly.com/public-ip-list" -o "$tmpfile"
            ;;
        *)
            echo "ERROR: Unknown provider '$provider'. Use: azure, aws, gcp, oracle, cloudflare, fastly"
            exit 1
            ;;
    esac

    if [[ ! -s "$tmpfile" ]]; then
        echo "ERROR: Download failed or empty file."
        exit 1
    fi

    echo "$tmpfile"
}

get_azure_url() {
    log "Scraping Microsoft download page for ServiceTags URL..."
    local url
    url=$(curl -sL "https://www.microsoft.com/en-us/download/details.aspx?id=56519" 2>/dev/null \
        | grep -oE 'https://download\.microsoft\.com/download/[^"]+ServiceTags_Public_[0-9]+\.json' \
        | head -1)
    if [[ -n "$url" ]]; then echo "$url"; return; fi

    log "Scraping failed, trying date-based URL fallback..."
    for i in $(seq 0 6); do
        local d
        if date -v-${i}d +%Y%m%d &>/dev/null; then
            d=$(date -v-${i}d +%Y%m%d)
        else
            d=$(date -d "-${i} days" +%Y%m%d)
        fi
        local test_url="https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_${d}.json"
        log "Trying date $d"
        if curl -sI "$test_url" 2>/dev/null | grep -q "200"; then
            echo "$test_url"; return
        fi
    done
    echo ""
}

# --- Format auto-detection ---
detect_format() {
    local file="$1"
    local head_content
    head_content=$(head -5 "$file" 2>/dev/null)

    if echo "$head_content" | grep -q '"changeNumber"'; then echo "azure"
    elif echo "$head_content" | grep -q '"syncToken"'; then
        if grep -q '"ip_prefix"' "$file" 2>/dev/null; then echo "aws"
        elif grep -q '"ipv4Prefix"' "$file" 2>/dev/null; then echo "gcp"
        else echo "cidrs"; fi
    elif echo "$head_content" | grep -q '"regions"'; then echo "oracle"
    elif echo "$head_content" | grep -q '"addresses"'; then echo "fastly"
    else echo "cidrs"; fi
}

# --- Extract CIDRs per format ---
extract_cidrs() {
    local file="$1" fmt="$2"
    log "Extracting CIDRs with format: $fmt"

    case "$fmt" in
        azure)
            if command -v jq &>/dev/null; then
                if [[ -n "$REGION_FILTER" ]]; then
                    jq -r --arg pat "$REGION_FILTER" '.values[] | select(.name | test("AzureCloud\\.")) | select(.name | test($pat; "i")) | .properties.addressPrefixes[]' "$file"
                else
                    jq -r '.values[] | select(.name | test("AzureCloud\\.")) | .properties.addressPrefixes[]' "$file"
                fi
            else
                echo "WARNING: jq not found, using grep fallback" >&2
                grep -oE '"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+"' "$file" | tr -d '"'
            fi ;;
        aws)
            if command -v jq &>/dev/null; then
                if [[ -n "$REGION_FILTER" ]]; then
                    jq -r --arg pat "$REGION_FILTER" '.prefixes[] | select(.region | test($pat; "i")) | .ip_prefix' "$file"
                else
                    jq -r '.prefixes[].ip_prefix' "$file"
                fi
            else
                grep -oE '"ip_prefix"\s*:\s*"[^"]+"' "$file" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+'
            fi ;;
        gcp)
            if command -v jq &>/dev/null; then
                if [[ -n "$REGION_FILTER" ]]; then
                    jq -r --arg pat "$REGION_FILTER" '.prefixes[] | select(.ipv4Prefix) | select(.scope | test($pat; "i")) | .ipv4Prefix' "$file"
                else
                    jq -r '.prefixes[] | select(.ipv4Prefix) | .ipv4Prefix' "$file"
                fi
            else
                grep -oE '"ipv4Prefix"\s*:\s*"[^"]+"' "$file" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+'
            fi ;;
        oracle)
            if command -v jq &>/dev/null; then
                if [[ -n "$REGION_FILTER" ]]; then
                    jq -r --arg pat "$REGION_FILTER" '.regions[] | select(.region | test($pat; "i")) | .cidrs[].cidr' "$file"
                else
                    jq -r '.regions[].cidrs[].cidr' "$file"
                fi
            else
                grep -oE '"cidr"\s*:\s*"[^"]+"' "$file" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+'
            fi ;;
        fastly)
            if command -v jq &>/dev/null; then jq -r '.addresses[]' "$file"
            else grep -oE '"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+"' "$file" | tr -d '"'; fi ;;
        cloudflare|cidrs)
            grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' "$file" ;;
        *) echo "ERROR: Unknown format: $fmt" >&2; exit 1 ;;
    esac
}

# --- CIDR helpers (pure bash) ---
ip_to_int() {
    local ip="$1"; IFS='.' read -r a b c d <<< "$ip"
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}
int_to_ip() {
    local n="$1"
    echo "$(( (n >> 24) & 255 )).$(( (n >> 16) & 255 )).$(( (n >> 8) & 255 )).$(( n & 255 ))"
}
cidr_sample_ip() {
    local ip="${1%/*}"; local n; n=$(ip_to_int "$ip"); int_to_ip $(( n + 1 ))
}
cidr_to_24() {
    local ip="${1%/*}"; IFS='.' read -r a b c _ <<< "$ip"; echo "${a}.${b}.${c}.0/24"
}

# --- Probe function ---
probe_ip() {
    local ip="$1" cidr="$2" results=""

    [[ "$VERBOSE" == "true" ]] && echo "[DEBUG] Probing $ip ($cidr)..." >&2

    # ICMP ping (only if enabled)
    if [[ ",$PROBES," == *",icmp,"* ]]; then
        if ping -c1 -W2 "$ip" &>/dev/null; then
            results="${results}icmp,"
            [[ "$VERBOSE" == "true" ]] && echo "[DEBUG]   $ip: ICMP OK" >&2
        else
            echo 1 >> "$STATS_DIR/fail_icmp"
            [[ "$VERBOSE" == "true" ]] && echo "[DEBUG]   $ip: ICMP failed" >&2
        fi
    fi

    # TCP port probes (only if enabled)
    if [[ ",$PROBES," == *",tcp,"* ]]; then
        IFS=',' read -ra port_list <<< "$PORTS"
        for port in "${port_list[@]}"; do
            if (echo >/dev/tcp/"$ip"/"$port") 2>/dev/null; then
                results="${results}tcp${port},"
                [[ "$VERBOSE" == "true" ]] && echo "[DEBUG]   $ip: TCP/$port OK" >&2
            elif command -v nc &>/dev/null && nc -z -w3 "$ip" "$port" 2>/dev/null; then
                results="${results}tcp${port},"
                [[ "$VERBOSE" == "true" ]] && echo "[DEBUG]   $ip: TCP/$port OK (nc)" >&2
            else
                echo 1 >> "$STATS_DIR/fail_tcp_${port}"
                [[ "$VERBOSE" == "true" ]] && echo "[DEBUG]   $ip: TCP/$port failed" >&2
            fi
        done
    fi

    # HTTPS probe (only if enabled and port 443 in list)
    if [[ ",$PROBES," == *",https,"* ]] && [[ "$PORTS" == *"443"* ]]; then
        if curl -sk --connect-timeout 3 --max-time 5 "https://$ip/" -o /dev/null 2>/dev/null; then
            results="${results}https,"
            [[ "$VERBOSE" == "true" ]] && echo "[DEBUG]   $ip: HTTPS OK" >&2
        else
            echo 1 >> "$STATS_DIR/fail_https"
            [[ "$VERBOSE" == "true" ]] && echo "[DEBUG]   $ip: HTTPS failed" >&2
        fi
    fi

    results="${results%,}"

    if [[ -n "$results" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "[DEBUG]   $ip: ACCESSIBLE ($results)" >&2
        echo "${cidr},${ip},${results}"
    fi
}

export -f probe_ip ip_to_int int_to_ip cidr_sample_ip log
export PORTS VERBOSE PROBES

# --- Main ---
main() {
    local input_file="$INPUT_FILE"
    local tmp_downloaded=""
    local fmt="$FORMAT"

    # Download if --provider given and no --file
    if [[ -z "$input_file" ]] && [[ -n "$PROVIDER" ]]; then
        input_file=$(download_provider "$PROVIDER")
        tmp_downloaded="$input_file"
        register_temp "$tmp_downloaded"
        [[ -z "$fmt" ]] && fmt="$PROVIDER"
    elif [[ -z "$input_file" ]]; then
        echo "No --file or --provider given. Downloading Azure ServiceTags..."
        input_file=$(download_provider "azure")
        tmp_downloaded="$input_file"
        register_temp "$tmp_downloaded"
        [[ -z "$fmt" ]] && fmt="azure"
    fi

    if [[ ! -f "$input_file" ]]; then
        echo "ERROR: File not found: $input_file"; exit 1
    fi

    if [[ -z "$fmt" ]]; then
        fmt=$(detect_format "$input_file")
        echo "Auto-detected format: $fmt"
    fi

    log "Input file: $input_file"
    log "Format: $fmt"
    log "Region filter: ${REGION_FILTER:-none}"
    log "Min prefix: /$MIN_PREFIX"
    log "Parallel probes: $MAX_PARALLEL"
    log "Ports: $PORTS"
    log "Probes: $PROBES"

    local provider_label
    case "$fmt" in
        azure) provider_label="Azure" ;; aws) provider_label="AWS" ;;
        gcp) provider_label="GCP" ;; oracle) provider_label="Oracle Cloud" ;;
        cloudflare) provider_label="Cloudflare" ;; fastly) provider_label="Fastly" ;;
        cidrs) provider_label="CIDR list" ;; *) provider_label="$fmt" ;;
    esac

    echo "Extracting $provider_label IP ranges..."

    # Use mktemp with enough randomness (10 X chars avoids collisions)
    local cidr_list
    cidr_list=$(mktemp /tmp/iran_scanner.XXXXXXXXXX)
    register_temp "$cidr_list"

    extract_cidrs "$input_file" "$fmt" \
        | grep -v ':' \
        | while read -r cidr; do
            local mask="${cidr#*/}"
            if [[ "$mask" -le "$MIN_PREFIX" ]]; then
                if [[ "$mask" -le 24 ]]; then echo "$cidr"
                else cidr_to_24 "$cidr"; fi
            fi
        done \
        | sort -u > "$cidr_list"

    local total
    total=$(wc -l < "$cidr_list" | tr -d ' ')

    if [[ "$total" -eq 0 ]]; then
        echo "ERROR: No CIDRs extracted. Check your file/format/region filter."; exit 1
    fi

    echo "Found $total unique IP blocks to scan"
    echo "Scanning with $MAX_PARALLEL parallel probes..."
    echo "Output: $OUTPUT_FILE"
    echo ""

    # Stats directory
    local stats_dir
    stats_dir=$(mktemp -d /tmp/iran_scanner_stats.XXXXXXXXXX)
    register_temp "$stats_dir"

    # Initialize counters
    echo 0 > "$stats_dir/found"
    echo 0 > "$stats_dir/icmp"
    echo 0 > "$stats_dir/https"
    echo 0 > "$stats_dir/scanned"
    echo 0 > "$stats_dir/launched"
    IFS=',' read -ra _ports <<< "$PORTS"
    for p in "${_ports[@]}"; do echo 0 > "$stats_dir/tcp_${p}"; done
    export STATS_DIR="$stats_dir"

    # CSV header
    echo "cidr,ip,methods" > "$OUTPUT_FILE"

    # --- Scan loop ---
    local launched=0
    local last_progress_time
    last_progress_time=$(date +%s)

    while read -r cidr; do
        local sample_ip
        sample_ip=$(cidr_sample_ip "$cidr")

        # Launch probe in background
        (
            result=$(probe_ip "$sample_ip" "$cidr")
            if [[ -n "$result" ]]; then
                echo "$result" >> "$OUTPUT_FILE"

                # Update counters
                local methods="${result##*,}"
                echo $(( $(cat "$STATS_DIR/found" 2>/dev/null || echo 0) + 1 )) > "$STATS_DIR/found" 2>/dev/null
                [[ "$methods" == *icmp* ]] && echo $(( $(cat "$STATS_DIR/icmp" 2>/dev/null || echo 0) + 1 )) > "$STATS_DIR/icmp" 2>/dev/null
                [[ "$methods" == *https* ]] && echo $(( $(cat "$STATS_DIR/https" 2>/dev/null || echo 0) + 1 )) > "$STATS_DIR/https" 2>/dev/null
                IFS=',' read -ra _sp <<< "$PORTS"
                for p in "${_sp[@]}"; do
                    [[ "$methods" == *"tcp${p}"* ]] && echo $(( $(cat "$STATS_DIR/tcp_${p}" 2>/dev/null || echo 0) + 1 )) > "$STATS_DIR/tcp_${p}" 2>/dev/null
                done
            fi
            # Increment scanned counter
            echo $(( $(cat "$STATS_DIR/scanned" 2>/dev/null || echo 0) + 1 )) > "$STATS_DIR/scanned" 2>/dev/null
        ) &

        launched=$((launched + 1))
        echo "$launched" > "$stats_dir/launched" 2>/dev/null

        # Throttle: wait if too many parallel jobs
        while [[ $(jobs -rp | wc -l) -ge $MAX_PARALLEL ]]; do
            # Print progress while waiting (time-based, every 2 seconds)
            local now
            now=$(date +%s)
            if (( now - last_progress_time >= 2 )); then
                _print_progress "$total" "$stats_dir"
                last_progress_time=$now
            fi
            sleep 0.2
        done

        # Also print progress every N launches
        local now
        now=$(date +%s)
        if (( now - last_progress_time >= 2 )); then
            _print_progress "$total" "$stats_dir"
            last_progress_time=$now
        fi

    done < "$cidr_list"

    # Wait for all remaining jobs
    echo "" >&2
    echo "Waiting for remaining probes to finish..." >&2
    wait 2>/dev/null

    # Final stats
    _print_progress "$total" "$stats_dir"
    echo "" >&2

    local found icmp https_count
    found=$(cat "$stats_dir/found" 2>/dev/null || echo 0)
    icmp=$(cat "$stats_dir/icmp" 2>/dev/null || echo 0)
    https_count=$(cat "$stats_dir/https" 2>/dev/null || echo 0)

    echo ""
    echo "========================================"
    echo "  Scan Complete"
    echo "========================================"
    echo "  Provider:       $provider_label"
    echo "  Probes:         $PROBES"
    echo "  Blocks scanned: $total"
    echo "  Accessible:     $found"
    printf "  Breakdown:      "
    local first=true
    if [[ ",$PROBES," == *",icmp,"* ]]; then
        local fail_icmp=0
        [[ -f "$stats_dir/fail_icmp" ]] && fail_icmp=$(_count_lines "$stats_dir/fail_icmp")
        $first || printf " "
        printf "icmp:%d/%d" "$icmp" "$(( icmp + fail_icmp ))"
        first=false
    fi
    if [[ ",$PROBES," == *",tcp,"* ]]; then
        for p in "${_ports[@]}"; do
            local tcp_ok tcp_fail=0
            tcp_ok=$(cat "$stats_dir/tcp_${p}" 2>/dev/null || echo 0)
            [[ -f "$stats_dir/fail_tcp_${p}" ]] && tcp_fail=$(_count_lines "$stats_dir/fail_tcp_${p}")
            $first || printf " "
            printf "tcp/%s:%d/%d" "$p" "$tcp_ok" "$(( tcp_ok + tcp_fail ))"
            first=false
        done
    fi
    if [[ ",$PROBES," == *",https,"* ]]; then
        local fail_https=0
        [[ -f "$stats_dir/fail_https" ]] && fail_https=$(_count_lines "$stats_dir/fail_https")
        $first || printf " "
        printf "https:%d/%d" "$https_count" "$(( https_count + fail_https ))"
        first=false
    fi
    echo ""
    echo "  Results:        $OUTPUT_FILE"
    echo "========================================"
}

_count_lines() {
    # Count lines in a file (used for fail counters that append one line per failure)
    wc -l < "$1" 2>/dev/null | tr -d ' '
}

_print_progress() {
    local total="$1" stats_dir="$2"
    local scanned found icmp https_count

    scanned=$(cat "$stats_dir/scanned" 2>/dev/null || echo 0)
    found=$(cat "$stats_dir/found" 2>/dev/null || echo 0)
    icmp=$(cat "$stats_dir/icmp" 2>/dev/null || echo 0)
    https_count=$(cat "$stats_dir/https" 2>/dev/null || echo 0)

    local launched
    launched=$(cat "$stats_dir/launched" 2>/dev/null || echo 0)

    # 2-decimal percentage
    local pct
    if (( total > 0 )); then
        pct=$(awk "BEGIN { printf \"%.2f\", ($scanned / $total) * 100 }")
    else
        pct="0.00"
    fi

    # Build compact probe breakdown: proto:ok/total
    local breakdown=""
    if [[ ",$PROBES," == *",icmp,"* ]]; then
        local fail_icmp=0
        [[ -f "$stats_dir/fail_icmp" ]] && fail_icmp=$(_count_lines "$stats_dir/fail_icmp")
        breakdown="${breakdown}icmp:${icmp}/$(( icmp + fail_icmp )) "
    fi

    if [[ ",$PROBES," == *",tcp,"* ]]; then
        IFS=',' read -ra _tp <<< "$PORTS"
        for p in "${_tp[@]}"; do
            local count=0 fail_count=0
            [[ -f "$stats_dir/tcp_${p}" ]] && count=$(cat "$stats_dir/tcp_${p}" 2>/dev/null || echo 0)
            [[ -f "$stats_dir/fail_tcp_${p}" ]] && fail_count=$(_count_lines "$stats_dir/fail_tcp_${p}")
            breakdown="${breakdown}t${p}:${count}/$(( count + fail_count )) "
        done
    fi

    if [[ ",$PROBES," == *",https,"* ]]; then
        local fail_https=0
        [[ -f "$stats_dir/fail_https" ]] && fail_https=$(_count_lines "$stats_dir/fail_https")
        breakdown="${breakdown}https:${https_count}/$(( https_count + fail_https )) "
    fi

    # \033[K clears to end of line, preventing stale chars from longer previous lines
    printf "\r  [%s%%] %d/%d ok:%d | %s\033[K" \
        "$pct" "$scanned" "$total" "$found" "$breakdown" >&2
}

main
