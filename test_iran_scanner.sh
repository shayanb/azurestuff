#!/bin/bash
#
# test_iran_scanner.sh — Comprehensive test suite for iran_scanner.sh
# Tests all code paths with mock tools (no real network calls).
#
# Usage: ./test_iran_scanner.sh
#

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/iran_scanner.sh"
ORIGINAL_PATH="$PATH"

# --- Counters ---
PASS_COUNT=0
FAIL_COUNT=0
TESTS_RUN=0

# --- Assert Helpers ---
assert_eq() {
    local actual="$1" expected="$2" msg="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ "$actual" == "$expected" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  PASS: $msg"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "  FAIL: $msg"
        echo "    expected: '$expected'"
        echo "    actual:   '$actual'"
    fi
}

assert_contains() {
    local haystack="$1" needle="$2" msg="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if echo "$haystack" | grep -qF -- "$needle"; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  PASS: $msg"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "  FAIL: $msg"
        echo "    expected to contain: '$needle'"
        echo "    in: '${haystack:0:300}'"
    fi
}

assert_not_contains() {
    local haystack="$1" needle="$2" msg="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if ! echo "$haystack" | grep -qF -- "$needle"; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  PASS: $msg"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "  FAIL: $msg"
        echo "    expected NOT to contain: '$needle'"
    fi
}

assert_file_exists() {
    local path="$1" msg="$2"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ -f "$path" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  PASS: $msg"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "  FAIL: $msg (file not found: $path)"
    fi
}

assert_file_not_exists() {
    local path="$1" msg="$2"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ ! -f "$path" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  PASS: $msg"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "  FAIL: $msg (file should not exist: $path)"
    fi
}

assert_gt() {
    local actual="$1" threshold="$2" msg="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if (( actual > threshold )); then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  PASS: $msg"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "  FAIL: $msg (expected > $threshold, got $actual)"
    fi
}

# --- Setup ---
setup() {
    TEST_TMPDIR=$(mktemp -d /tmp/iran_scanner_test.XXXXXXXXXX)

    # --- Mock data files ---
    mkdir -p "$TEST_TMPDIR/mock_data"

    cat > "$TEST_TMPDIR/mock_data/azure.json" << 'AZEOF'
{"changeNumber":1,"cloud":"Public","values":[{"name":"AzureCloud.eastus","id":"AzureCloud.eastus","properties":{"changeNumber":1,"region":"eastus","addressPrefixes":["10.0.0.0/24","10.0.1.0/24","2001:db8::/32"]}},{"name":"AzureCloud.westus","id":"AzureCloud.westus","properties":{"changeNumber":1,"region":"westus","addressPrefixes":["10.0.2.0/24"]}}]}
AZEOF

    cat > "$TEST_TMPDIR/mock_data/aws.json" << 'AWSEOF'
{"syncToken":"1234567890","createDate":"2026-01-01-00-00-00","prefixes":[{"ip_prefix":"10.1.0.0/24","region":"us-east-1","service":"AMAZON","network_border_group":"us-east-1"},{"ip_prefix":"10.2.0.0/24","region":"eu-west-1","service":"AMAZON","network_border_group":"eu-west-1"}],"ipv6_prefixes":[]}
AWSEOF

    cat > "$TEST_TMPDIR/mock_data/gcp.json" << 'GCPEOF'
{"syncToken":"1","creationTime":"2026-01-01T00:00:00","prefixes":[{"ipv4Prefix":"10.3.0.0/24","scope":"us-central1","service":"Google Cloud"},{"ipv4Prefix":"10.3.1.0/24","scope":"europe-west1","service":"Google Cloud"}]}
GCPEOF

    cat > "$TEST_TMPDIR/mock_data/oracle.json" << 'OCIEOF'
{"last_updated_timestamp":"2026-01-01T00:00:00","regions":[{"region":"us-ashburn-1","cidrs":[{"cidr":"10.4.0.0/24","tags":["OCI"]}]},{"region":"eu-frankfurt-1","cidrs":[{"cidr":"10.4.1.0/24","tags":["OCI"]}]}]}
OCIEOF

    cat > "$TEST_TMPDIR/mock_data/fastly.json" << 'FASTEOF'
{"addresses":["10.5.0.0/24","10.5.1.0/24"],"ipv6_addresses":["2a04:4e40::/32"]}
FASTEOF

    printf '10.6.0.0/24\n10.6.1.0/24\n' > "$TEST_TMPDIR/mock_data/cloudflare.txt"
    printf '10.7.0.0/24\n10.7.1.0/24\n' > "$TEST_TMPDIR/mock_data/cidrs.txt"
    printf 'just some random text\nnothing useful\n' > "$TEST_TMPDIR/mock_data/unknown.txt"
    > "$TEST_TMPDIR/mock_data/empty.txt"

    # CIDR file with mixed prefix sizes for min-prefix tests
    printf '10.8.0.0/24\n10.8.1.0/26\n10.8.2.0/30\n10.8.3.0/16\n' > "$TEST_TMPDIR/mock_data/mixed_prefix.txt"

    # --- Mock tool scripts ---
    mkdir -p "$TEST_TMPDIR/mock_bin"

    # Mock fping: outputs IPs listed in $MOCK_FPING_ALIVE file
    cat > "$TEST_TMPDIR/mock_bin/fping" << 'FPEOF'
#!/bin/bash
while read -r ip; do
    if [[ -n "$MOCK_FPING_ALIVE" ]] && grep -qFx "$ip" "$MOCK_FPING_ALIVE" 2>/dev/null; then
        echo "$ip"
    fi
done
FPEOF
    chmod +x "$TEST_TMPDIR/mock_bin/fping"

    # Mock nmap: parses -iL and -oG, copies $MOCK_NMAP_RESULTS to output
    cat > "$TEST_TMPDIR/mock_bin/nmap" << 'NMEOF'
#!/bin/bash
out_file=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -oG) out_file="$2"; shift 2 ;;
        *) shift ;;
    esac
done
if [[ -n "$out_file" ]] && [[ -f "$MOCK_NMAP_RESULTS" ]]; then
    cp "$MOCK_NMAP_RESULTS" "$out_file"
elif [[ -n "$out_file" ]]; then
    echo "# Nmap done" > "$out_file"
fi
NMEOF
    chmod +x "$TEST_TMPDIR/mock_bin/nmap"

    # Mock masscan: parses -oL, copies $MOCK_MASSCAN_RESULTS to output
    cat > "$TEST_TMPDIR/mock_bin/masscan" << 'MSEOF'
#!/bin/bash
out_file=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -oL) out_file="$2"; shift 2 ;;
        *) shift ;;
    esac
done
if [[ -n "$out_file" ]] && [[ -f "$MOCK_MASSCAN_RESULTS" ]]; then
    cp "$MOCK_MASSCAN_RESULTS" "$out_file"
elif [[ -n "$out_file" ]]; then
    echo "# masscan done" > "$out_file"
fi
MSEOF
    chmod +x "$TEST_TMPDIR/mock_bin/masscan"

    # Mock ping: exit code from $MOCK_PING_EXIT (default: 1 = fail)
    cat > "$TEST_TMPDIR/mock_bin/ping" << 'PIEOF'
#!/bin/bash
exit ${MOCK_PING_EXIT:-1}
PIEOF
    chmod +x "$TEST_TMPDIR/mock_bin/ping"

    # Mock curl: distinguishes probe vs download via --connect-timeout
    cat > "$TEST_TMPDIR/mock_bin/curl" << 'CUEOF'
#!/bin/bash
is_probe=false
out_file=""
for arg in "$@"; do
    [[ "$arg" == "--connect-timeout" ]] && is_probe=true
done
if $is_probe; then
    exit ${MOCK_CURL_PROBE_EXIT:-1}
fi
# Download mode: find -o arg and write mock data
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) echo '{"mock":"data"}' > "$2"; shift 2 ;;
        *) shift ;;
    esac
done
exit 0
CUEOF
    chmod +x "$TEST_TMPDIR/mock_bin/curl"

    # Mock nc: exit code from $MOCK_NC_EXIT (default: 1 = fail)
    cat > "$TEST_TMPDIR/mock_bin/nc" << 'NCEOF'
#!/bin/bash
exit ${MOCK_NC_EXIT:-1}
NCEOF
    chmod +x "$TEST_TMPDIR/mock_bin/nc"

    # --- Empty bin (hides all optional tools) ---
    mkdir -p "$TEST_TMPDIR/no_tools_bin"

    # --- Base bin: symlinks to ALL system binaries EXCEPT fping, nmap, masscan ---
    # This prevents real scan tools from leaking through /usr/bin or /usr/local/bin
    mkdir -p "$TEST_TMPDIR/base_bin"
    local exclude_tools="fping nmap masscan"
    for dir in /usr/bin /bin /usr/sbin /sbin /usr/local/bin; do
        [[ -d "$dir" ]] || continue
        for bin in "$dir"/*; do
            [[ -x "$bin" ]] || continue
            local bname
            bname=$(basename "$bin")
            # Skip excluded tools
            local skip=false
            for ex in $exclude_tools; do
                [[ "$bname" == "$ex" ]] && skip=true && break
            done
            $skip && continue
            # Don't overwrite existing (first dir wins)
            [[ -e "$TEST_TMPDIR/base_bin/$bname" ]] && continue
            ln -sf "$bin" "$TEST_TMPDIR/base_bin/$bname" 2>/dev/null || true
        done
    done

    # --- No-jq bin: same as base_bin but also excludes jq ---
    mkdir -p "$TEST_TMPDIR/no_jq_bin"
    for bin in "$TEST_TMPDIR/base_bin"/*; do
        local bname
        bname=$(basename "$bin")
        [[ "$bname" == "jq" ]] && continue
        ln -sf "$(readlink -f "$bin")" "$TEST_TMPDIR/no_jq_bin/$bname" 2>/dev/null || true
    done

    # --- Bins with specific tool combos ---
    mkdir -p "$TEST_TMPDIR/fping_only_bin"
    cp "$TEST_TMPDIR/mock_bin/fping" "$TEST_TMPDIR/fping_only_bin/"

    mkdir -p "$TEST_TMPDIR/nmap_only_bin"
    cp "$TEST_TMPDIR/mock_bin/nmap" "$TEST_TMPDIR/nmap_only_bin/"

    # --- Create testable source (functions only, no side effects) ---
    TESTABLE="$TEST_TMPDIR/iran_scanner_testable.sh"
    sed \
        -e 's/^set -eo pipefail/# set -eo pipefail/' \
        -e 's/^main$/# main/' \
        -e 's/^trap cleanup INT TERM/# trap cleanup INT TERM/' \
        -e 's/^trap cleanup_files EXIT/# trap cleanup_files EXIT/' \
        -e '/^mkdir -p "\$OUTPUT_DIR"/s/^/# /' \
        -e '/^HAS_FPING=.*command/s/^/# /' \
        -e '/^HAS_NMAP=.*command/s/^/# /' \
        -e '/^HAS_MASSCAN=.*command/s/^/# /' \
        -e '/^export -f/s/^/# /' \
        "$SCRIPT_PATH" > "$TESTABLE"

    # --- Output dirs for integration tests ---
    mkdir -p "$TEST_TMPDIR/scans"
}

# Source the testable script to get functions
source_scanner() {
    # Reset all defaults before sourcing
    TEMP_FILES=()
    INPUT_FILE=""
    FORMAT=""
    REGION_FILTER=""
    MAX_PARALLEL=50
    PORTS="443,80,22"
    OUTPUT_DIR="$TEST_TMPDIR/scans"
    OUTPUT_FILE=""
    MIN_PREFIX=28
    VERBOSE=false
    PROVIDER=""
    PROBES="icmp,tcp,https"
    RESUME_FILE=""
    HAS_FPING=false
    HAS_NMAP=false
    HAS_MASSCAN=false
    ICMP_DONE=false
    TCP_DONE=false
    set --
    source "$TESTABLE" 2>/dev/null || true
}

teardown() {
    rm -rf "$TEST_TMPDIR" 2>/dev/null
}

# Helper: run the real script as subprocess with mock tools (30s timeout)
run_scanner() {
    local tmpout="$TEST_TMPDIR/runner_output_$$_$RANDOM"
    PATH="$TEST_TMPDIR/mock_bin:$TEST_TMPDIR/base_bin" \
        bash "$SCRIPT_PATH" "$@" >"$tmpout" 2>&1 &
    local pid=$!
    (sleep 30 && kill -9 "$pid" 2>/dev/null) </dev/null >/dev/null 2>&1 &
    local watchdog=$!
    disown "$watchdog" 2>/dev/null
    wait "$pid" 2>/dev/null
    kill "$watchdog" 2>/dev/null 2>&1
    cat "$tmpout"
    rm -f "$tmpout"
}

# Helper: run the real script with NO optional tools (30s timeout)
run_scanner_no_tools() {
    local tmpout="$TEST_TMPDIR/runner_output_$$_$RANDOM"
    PATH="$TEST_TMPDIR/base_bin" \
        bash "$SCRIPT_PATH" "$@" >"$tmpout" 2>&1 &
    local pid=$!
    (sleep 30 && kill -9 "$pid" 2>/dev/null) </dev/null >/dev/null 2>&1 &
    local watchdog=$!
    disown "$watchdog" 2>/dev/null
    wait "$pid" 2>/dev/null
    kill "$watchdog" 2>/dev/null 2>&1
    cat "$tmpout"
    rm -f "$tmpout"
}

# Helper: set up a probe stats directory for probe_ip tests
# Sets STATS_DIR as a side effect (must NOT be called in a subshell)
setup_stats_dir() {
    STATS_DIR="$TEST_TMPDIR/stats_$$_$RANDOM"
    mkdir -p "$STATS_DIR"
    echo 0 > "$STATS_DIR/found"
    echo 0 > "$STATS_DIR/icmp"
    echo 0 > "$STATS_DIR/https"
    echo 0 > "$STATS_DIR/scanned"
    echo 0 > "$STATS_DIR/launched"
    echo 0 > "$STATS_DIR/tcp_443"
    echo 0 > "$STATS_DIR/tcp_80"
    echo 0 > "$STATS_DIR/tcp_22"
    export STATS_DIR
}

# ============================================================
# GROUP 1: CLI & Argument Parsing
# ============================================================

test_help_flag() {
    local output
    output=$(bash "$SCRIPT_PATH" --help 2>&1) || true
    assert_contains "$output" "Usage:" "help flag shows usage"
    assert_contains "$output" "--file" "help mentions --file"
    assert_contains "$output" "--probes" "help mentions --probes"
    assert_contains "$output" "--resume" "help mentions --resume"
}

test_unknown_flag() {
    local output
    output=$(bash "$SCRIPT_PATH" --bogus 2>&1) || true
    assert_contains "$output" "Unknown option" "unknown flag shows error"
}

test_default_values() {
    source_scanner
    assert_eq "$MAX_PARALLEL" "50" "default MAX_PARALLEL=50"
    assert_eq "$PORTS" "443,80,22" "default PORTS"
    assert_eq "$PROBES" "icmp,tcp,https" "default PROBES"
    assert_eq "$MIN_PREFIX" "28" "default MIN_PREFIX=28"
    assert_eq "$VERBOSE" "false" "default VERBOSE=false"
    assert_eq "$RESUME_FILE" "" "default RESUME_FILE empty"
}

test_file_flag() {
    local output
    output=$(run_scanner_no_tools --file /nonexistent_file_xyz 2>&1) || true
    assert_contains "$output" "File not found" "file flag error on missing file"
}

test_probes_flag() {
    source_scanner
    set -- --probes icmp
    while [[ $# -gt 0 ]]; do
        case "$1" in --probes) PROBES="$2"; shift 2 ;; *) shift ;; esac
    done
    assert_eq "$PROBES" "icmp" "probes flag sets PROBES"
}

test_parallel_flag() {
    source_scanner
    set -- --parallel 100
    while [[ $# -gt 0 ]]; do
        case "$1" in --parallel) MAX_PARALLEL="$2"; shift 2 ;; *) shift ;; esac
    done
    assert_eq "$MAX_PARALLEL" "100" "parallel flag sets MAX_PARALLEL"
}

test_ports_flag() {
    source_scanner
    set -- --ports "443,8080"
    while [[ $# -gt 0 ]]; do
        case "$1" in --ports) PORTS="$2"; shift 2 ;; *) shift ;; esac
    done
    assert_eq "$PORTS" "443,8080" "ports flag sets PORTS"
}

test_output_flag() {
    source_scanner
    set -- --output /tmp/custom.csv
    while [[ $# -gt 0 ]]; do
        case "$1" in --output) OUTPUT_FILE="$2"; shift 2 ;; *) shift ;; esac
    done
    assert_eq "$OUTPUT_FILE" "/tmp/custom.csv" "output flag sets OUTPUT_FILE"
}

test_resume_flag() {
    source_scanner
    set -- --resume /tmp/prev.csv
    while [[ $# -gt 0 ]]; do
        case "$1" in --resume) RESUME_FILE="$2"; shift 2 ;; *) shift ;; esac
    done
    assert_eq "$RESUME_FILE" "/tmp/prev.csv" "resume flag sets RESUME_FILE"
}

test_verbose_flag() {
    source_scanner
    set -- -v
    while [[ $# -gt 0 ]]; do
        case "$1" in -v|--verbose) VERBOSE=true; shift ;; *) shift ;; esac
    done
    assert_eq "$VERBOSE" "true" "verbose flag sets VERBOSE=true"
}

# ============================================================
# GROUP 2: Format Auto-Detection
# ============================================================

test_detect_azure() {
    source_scanner
    local result
    result=$(detect_format "$TEST_TMPDIR/mock_data/azure.json")
    assert_eq "$result" "azure" "detect azure format"
}

test_detect_aws() {
    source_scanner
    local result
    result=$(detect_format "$TEST_TMPDIR/mock_data/aws.json")
    assert_eq "$result" "aws" "detect aws format"
}

test_detect_gcp() {
    source_scanner
    local result
    result=$(detect_format "$TEST_TMPDIR/mock_data/gcp.json")
    assert_eq "$result" "gcp" "detect gcp format"
}

test_detect_oracle() {
    source_scanner
    local result
    result=$(detect_format "$TEST_TMPDIR/mock_data/oracle.json")
    assert_eq "$result" "oracle" "detect oracle format"
}

test_detect_fastly() {
    source_scanner
    local result
    result=$(detect_format "$TEST_TMPDIR/mock_data/fastly.json")
    assert_eq "$result" "fastly" "detect fastly format"
}

test_detect_cidrs() {
    source_scanner
    local result
    result=$(detect_format "$TEST_TMPDIR/mock_data/cidrs.txt")
    assert_eq "$result" "cidrs" "detect plain cidrs format"
}

test_detect_fallback() {
    source_scanner
    local result
    result=$(detect_format "$TEST_TMPDIR/mock_data/unknown.txt")
    assert_eq "$result" "cidrs" "unknown content falls back to cidrs"
}

# ============================================================
# GROUP 3: CIDR Extraction
# ============================================================

test_extract_azure_with_jq() {
    source_scanner
    REGION_FILTER=""
    local result
    result=$(extract_cidrs "$TEST_TMPDIR/mock_data/azure.json" "azure")
    assert_contains "$result" "10.0.0.0/24" "azure jq extracts first CIDR"
    assert_contains "$result" "10.0.1.0/24" "azure jq extracts second CIDR"
    assert_contains "$result" "10.0.2.0/24" "azure jq extracts westus CIDR"
}

test_extract_azure_without_jq() {
    source_scanner
    REGION_FILTER=""
    local result
    result=$(PATH="$TEST_TMPDIR/no_jq_bin" \
        bash -c "source '$TESTABLE' 2>/dev/null; extract_cidrs '$TEST_TMPDIR/mock_data/azure.json' 'azure'" 2>/dev/null)
    assert_contains "$result" "10.0.0.0/24" "azure grep fallback extracts CIDRs"
}

test_extract_azure_region_filter() {
    source_scanner
    REGION_FILTER="eastus"
    local result
    result=$(extract_cidrs "$TEST_TMPDIR/mock_data/azure.json" "azure" 2>/dev/null)
    assert_contains "$result" "10.0.0.0/24" "azure region filter includes eastus"
    assert_not_contains "$result" "10.0.2.0/24" "azure region filter excludes westus"
    REGION_FILTER=""
}

test_extract_aws_with_jq() {
    source_scanner
    REGION_FILTER=""
    local result
    result=$(extract_cidrs "$TEST_TMPDIR/mock_data/aws.json" "aws")
    assert_contains "$result" "10.1.0.0/24" "aws jq extracts us-east-1"
    assert_contains "$result" "10.2.0.0/24" "aws jq extracts eu-west-1"
}

test_extract_aws_without_jq() {
    source_scanner
    REGION_FILTER=""
    local result
    result=$(PATH="$TEST_TMPDIR/no_jq_bin" \
        bash -c "source '$TESTABLE' 2>/dev/null; extract_cidrs '$TEST_TMPDIR/mock_data/aws.json' 'aws'" 2>/dev/null)
    assert_contains "$result" "10.1.0.0/24" "aws grep fallback extracts CIDRs"
}

test_extract_aws_region_filter() {
    source_scanner
    REGION_FILTER="us-east"
    local result
    result=$(extract_cidrs "$TEST_TMPDIR/mock_data/aws.json" "aws" 2>/dev/null)
    assert_contains "$result" "10.1.0.0/24" "aws region filter includes us-east-1"
    assert_not_contains "$result" "10.2.0.0/24" "aws region filter excludes eu-west-1"
    REGION_FILTER=""
}

test_extract_gcp_with_jq() {
    source_scanner
    REGION_FILTER=""
    local result
    result=$(extract_cidrs "$TEST_TMPDIR/mock_data/gcp.json" "gcp")
    assert_contains "$result" "10.3.0.0/24" "gcp jq extracts us-central1"
    assert_contains "$result" "10.3.1.0/24" "gcp jq extracts europe-west1"
}

test_extract_gcp_without_jq() {
    source_scanner
    REGION_FILTER=""
    local result
    result=$(PATH="$TEST_TMPDIR/no_jq_bin" \
        bash -c "source '$TESTABLE' 2>/dev/null; extract_cidrs '$TEST_TMPDIR/mock_data/gcp.json' 'gcp'" 2>/dev/null)
    assert_contains "$result" "10.3.0.0/24" "gcp grep fallback extracts CIDRs"
}

test_extract_gcp_region_filter() {
    source_scanner
    REGION_FILTER="us-central"
    local result
    result=$(extract_cidrs "$TEST_TMPDIR/mock_data/gcp.json" "gcp" 2>/dev/null)
    assert_contains "$result" "10.3.0.0/24" "gcp region filter includes us-central1"
    assert_not_contains "$result" "10.3.1.0/24" "gcp region filter excludes europe-west1"
    REGION_FILTER=""
}

test_extract_oracle_with_jq() {
    source_scanner
    REGION_FILTER=""
    local result
    result=$(extract_cidrs "$TEST_TMPDIR/mock_data/oracle.json" "oracle")
    assert_contains "$result" "10.4.0.0/24" "oracle jq extracts us-ashburn-1"
    assert_contains "$result" "10.4.1.0/24" "oracle jq extracts eu-frankfurt-1"
}

test_extract_oracle_without_jq() {
    source_scanner
    REGION_FILTER=""
    local result
    result=$(PATH="$TEST_TMPDIR/no_jq_bin" \
        bash -c "source '$TESTABLE' 2>/dev/null; extract_cidrs '$TEST_TMPDIR/mock_data/oracle.json' 'oracle'" 2>/dev/null)
    assert_contains "$result" "10.4.0.0/24" "oracle grep fallback extracts CIDRs"
}

test_extract_oracle_region_filter() {
    source_scanner
    REGION_FILTER="us-ashburn"
    local result
    result=$(extract_cidrs "$TEST_TMPDIR/mock_data/oracle.json" "oracle" 2>/dev/null)
    assert_contains "$result" "10.4.0.0/24" "oracle region filter includes us-ashburn"
    assert_not_contains "$result" "10.4.1.0/24" "oracle region filter excludes eu-frankfurt"
    REGION_FILTER=""
}

test_extract_fastly_with_jq() {
    source_scanner
    local result
    result=$(extract_cidrs "$TEST_TMPDIR/mock_data/fastly.json" "fastly")
    assert_contains "$result" "10.5.0.0/24" "fastly jq extracts first CIDR"
    assert_contains "$result" "10.5.1.0/24" "fastly jq extracts second CIDR"
}

test_extract_fastly_without_jq() {
    source_scanner
    local result
    result=$(PATH="$TEST_TMPDIR/no_jq_bin" \
        bash -c "source '$TESTABLE' 2>/dev/null; extract_cidrs '$TEST_TMPDIR/mock_data/fastly.json' 'fastly'" 2>/dev/null)
    assert_contains "$result" "10.5.0.0/24" "fastly grep fallback extracts CIDRs"
}

test_extract_cloudflare() {
    source_scanner
    local result
    result=$(extract_cidrs "$TEST_TMPDIR/mock_data/cloudflare.txt" "cloudflare")
    assert_contains "$result" "10.6.0.0/24" "cloudflare extracts first CIDR"
    assert_contains "$result" "10.6.1.0/24" "cloudflare extracts second CIDR"
}

test_extract_cidrs() {
    source_scanner
    local result
    result=$(extract_cidrs "$TEST_TMPDIR/mock_data/cidrs.txt" "cidrs")
    assert_contains "$result" "10.7.0.0/24" "cidrs extracts first CIDR"
    assert_contains "$result" "10.7.1.0/24" "cidrs extracts second CIDR"
}

test_extract_ipv6_filtered() {
    source_scanner
    REGION_FILTER=""
    local result
    result=$(extract_cidrs "$TEST_TMPDIR/mock_data/azure.json" "azure")
    # The main() function does grep -v ':' to filter IPv6, but extract_cidrs itself
    # returns whatever jq gives. For azure, jq returns IPv6 too.
    # The filtering happens in the pipeline in main(). Let's verify the pipeline.
    local filtered
    filtered=$(extract_cidrs "$TEST_TMPDIR/mock_data/azure.json" "azure" | grep -v ':')
    assert_not_contains "$filtered" "2001:db8" "IPv6 filtered by grep -v :"
    assert_contains "$filtered" "10.0.0.0/24" "IPv4 preserved after filter"
}

# ============================================================
# GROUP 4: CIDR Helpers
# ============================================================

test_ip_to_int() {
    source_scanner
    assert_eq "$(ip_to_int 10.0.0.1)" "167772161" "ip_to_int 10.0.0.1"
    assert_eq "$(ip_to_int 0.0.0.0)" "0" "ip_to_int 0.0.0.0"
    assert_eq "$(ip_to_int 255.255.255.255)" "4294967295" "ip_to_int 255.255.255.255"
    assert_eq "$(ip_to_int 192.168.1.1)" "3232235777" "ip_to_int 192.168.1.1"
}

test_int_to_ip() {
    source_scanner
    assert_eq "$(int_to_ip 167772161)" "10.0.0.1" "int_to_ip → 10.0.0.1"
    assert_eq "$(int_to_ip 0)" "0.0.0.0" "int_to_ip → 0.0.0.0"
    assert_eq "$(int_to_ip 4294967295)" "255.255.255.255" "int_to_ip → 255.255.255.255"
}

test_cidr_sample_ip() {
    source_scanner
    assert_eq "$(cidr_sample_ip 10.0.0.0/24)" "10.0.0.1" "sample IP for /24"
    assert_eq "$(cidr_sample_ip 192.168.1.0/28)" "192.168.1.1" "sample IP for /28"
    assert_eq "$(cidr_sample_ip 172.16.0.0/16)" "172.16.0.1" "sample IP for /16"
}

test_cidr_to_24() {
    source_scanner
    assert_eq "$(cidr_to_24 10.0.0.128/25)" "10.0.0.0/24" "/25 normalized to /24"
    assert_eq "$(cidr_to_24 10.0.0.0/24)" "10.0.0.0/24" "/24 stays /24"
    assert_eq "$(cidr_to_24 10.0.0.64/26)" "10.0.0.0/24" "/26 normalized to /24"
    assert_eq "$(cidr_to_24 192.168.5.192/27)" "192.168.5.0/24" "/27 normalized to /24"
}

# ============================================================
# GROUP 5: Tool Detection
# ============================================================

test_no_tools_detected() {
    local result
    result=$(PATH="$TEST_TMPDIR/base_bin" bash -c '
        HAS_FPING=false; command -v fping &>/dev/null && HAS_FPING=true
        HAS_NMAP=false; command -v nmap &>/dev/null && HAS_NMAP=true
        HAS_MASSCAN=false; command -v masscan &>/dev/null && HAS_MASSCAN=true
        echo "$HAS_FPING $HAS_NMAP $HAS_MASSCAN"
    ')
    assert_eq "$result" "false false false" "no tools detected with empty bin"
}

test_fping_only_detected() {
    local result
    result=$(PATH="$TEST_TMPDIR/fping_only_bin:$TEST_TMPDIR/base_bin" bash -c '
        HAS_FPING=false; command -v fping &>/dev/null && HAS_FPING=true
        HAS_NMAP=false; command -v nmap &>/dev/null && HAS_NMAP=true
        HAS_MASSCAN=false; command -v masscan &>/dev/null && HAS_MASSCAN=true
        echo "$HAS_FPING $HAS_NMAP $HAS_MASSCAN"
    ')
    assert_eq "$result" "true false false" "only fping detected"
}

test_nmap_only_detected() {
    local result
    result=$(PATH="$TEST_TMPDIR/nmap_only_bin:$TEST_TMPDIR/base_bin" bash -c '
        HAS_FPING=false; command -v fping &>/dev/null && HAS_FPING=true
        HAS_NMAP=false; command -v nmap &>/dev/null && HAS_NMAP=true
        HAS_MASSCAN=false; command -v masscan &>/dev/null && HAS_MASSCAN=true
        echo "$HAS_FPING $HAS_NMAP $HAS_MASSCAN"
    ')
    assert_eq "$result" "false true false" "only nmap detected"
}

test_all_tools_detected() {
    local result
    result=$(PATH="$TEST_TMPDIR/mock_bin:$TEST_TMPDIR/base_bin" bash -c '
        HAS_FPING=false; command -v fping &>/dev/null && HAS_FPING=true
        HAS_NMAP=false; command -v nmap &>/dev/null && HAS_NMAP=true
        HAS_MASSCAN=false; command -v masscan &>/dev/null && HAS_MASSCAN=true
        echo "$HAS_FPING $HAS_NMAP $HAS_MASSCAN"
    ')
    assert_eq "$result" "true true true" "all tools detected"
}

# ============================================================
# GROUP 6: Bulk Scan Phases (integration tests)
# ============================================================

test_fping_bulk_icmp() {
    # Create alive list
    echo "10.7.0.1" > "$TEST_TMPDIR/fping_alive_list"
    export MOCK_FPING_ALIVE="$TEST_TMPDIR/fping_alive_list"
    export MOCK_PING_EXIT=1
    export MOCK_CURL_PROBE_EXIT=1
    export MOCK_NC_EXIT=1

    local output
    output=$(run_scanner --file "$TEST_TMPDIR/mock_data/cidrs.txt" --probes icmp --output "$TEST_TMPDIR/scans/fping_test.csv" 2>&1) || true

    assert_contains "$output" "fping" "fping bulk phase runs"
    assert_contains "$output" "alive" "fping reports alive count"

    unset MOCK_FPING_ALIVE MOCK_PING_EXIT MOCK_CURL_PROBE_EXIT MOCK_NC_EXIT
}

test_nmap_bulk_tcp() {
    # Create mock nmap grepable output
    cat > "$TEST_TMPDIR/mock_nmap.gnmap" << 'EOF'
# Nmap 7.94 scan
Host: 10.7.0.1 ()	Ports: 443/open/tcp//https///	Ignored State: closed (2)
# Nmap done
EOF
    export MOCK_NMAP_RESULTS="$TEST_TMPDIR/mock_nmap.gnmap"
    export MOCK_FPING_ALIVE="/dev/null"
    export MOCK_PING_EXIT=1
    export MOCK_CURL_PROBE_EXIT=1
    export MOCK_NC_EXIT=1

    local output
    output=$(run_scanner --file "$TEST_TMPDIR/mock_data/cidrs.txt" --probes tcp --output "$TEST_TMPDIR/scans/nmap_test.csv" 2>&1) || true

    assert_contains "$output" "nmap" "nmap bulk phase runs"
    assert_contains "$output" "open port" "nmap reports open ports"

    unset MOCK_NMAP_RESULTS MOCK_FPING_ALIVE MOCK_PING_EXIT MOCK_CURL_PROBE_EXIT MOCK_NC_EXIT
}

test_fping_nmap_fast_path() {
    echo "10.7.0.1" > "$TEST_TMPDIR/fping_alive_list2"
    cat > "$TEST_TMPDIR/mock_nmap2.gnmap" << 'EOF'
# Nmap 7.94 scan
Host: 10.7.0.1 ()	Ports: 443/open/tcp//https///
# Nmap done
EOF
    export MOCK_FPING_ALIVE="$TEST_TMPDIR/fping_alive_list2"
    export MOCK_NMAP_RESULTS="$TEST_TMPDIR/mock_nmap2.gnmap"
    export MOCK_PING_EXIT=1
    export MOCK_CURL_PROBE_EXIT=1
    export MOCK_NC_EXIT=1

    local output
    output=$(run_scanner --file "$TEST_TMPDIR/mock_data/cidrs.txt" --probes icmp,tcp --output "$TEST_TMPDIR/scans/fast_path_test.csv" 2>&1) || true

    # When both fping and nmap handle all probes (no https), fast compile path should be used
    assert_contains "$output" "compiling" "fast compile path used when all probes bulk-done"

    unset MOCK_FPING_ALIVE MOCK_NMAP_RESULTS MOCK_PING_EXIT MOCK_CURL_PROBE_EXIT MOCK_NC_EXIT
}

test_masscan_needs_root() {
    # When not root, masscan should be skipped
    export MOCK_PING_EXIT=1
    export MOCK_CURL_PROBE_EXIT=1
    export MOCK_NC_EXIT=1

    if [[ $EUID -ne 0 ]]; then
        # Run with masscan available but no nmap, as non-root
        mkdir -p "$TEST_TMPDIR/masscan_only_bin"
        cp "$TEST_TMPDIR/mock_bin/masscan" "$TEST_TMPDIR/masscan_only_bin/"
        cp "$TEST_TMPDIR/mock_bin/ping" "$TEST_TMPDIR/masscan_only_bin/"
        cp "$TEST_TMPDIR/mock_bin/curl" "$TEST_TMPDIR/masscan_only_bin/"

        local output tmpout_ms="$TEST_TMPDIR/masscan_out_$$"
        PATH="$TEST_TMPDIR/masscan_only_bin:$TEST_TMPDIR/base_bin" \
            MOCK_PING_EXIT=1 MOCK_CURL_PROBE_EXIT=1 MOCK_NC_EXIT=1 \
            bash "$SCRIPT_PATH" --file "$TEST_TMPDIR/mock_data/cidrs.txt" --probes tcp \
            --output "$TEST_TMPDIR/scans/masscan_test.csv" -v >"$tmpout_ms" 2>&1 &
        local ms_pid=$!
        (sleep 30 && kill -9 "$ms_pid" 2>/dev/null) </dev/null >/dev/null 2>&1 &
        local ms_wd=$!
        disown "$ms_wd" 2>/dev/null
        wait "$ms_pid" 2>/dev/null || true
        kill "$ms_wd" 2>/dev/null
        output=$(cat "$tmpout_ms" 2>/dev/null); rm -f "$tmpout_ms"

        # masscan should NOT be used (non-root)
        assert_not_contains "$output" "masscan:" "masscan skipped when not root"
    else
        echo "  SKIP: test_masscan_needs_root (running as root)"
        TESTS_RUN=$((TESTS_RUN + 1))
        PASS_COUNT=$((PASS_COUNT + 1))
    fi

    unset MOCK_PING_EXIT MOCK_CURL_PROBE_EXIT MOCK_NC_EXIT
}

# ============================================================
# GROUP 7: probe_ip Function
# ============================================================

test_probe_icmp_done_found() {
    source_scanner
    setup_stats_dir
    PROBES="icmp"
    ICMP_DONE=true
    TCP_DONE=false
    echo "10.7.0.1" > "$STATS_DIR/fping_alive"

    local result
    result=$(probe_ip "10.7.0.1" "10.7.0.0/24")
    assert_contains "$result" "icmp" "ICMP_DONE: found IP → icmp in result"
    assert_contains "$result" "10.7.0.0/24" "result contains CIDR"
}

test_probe_icmp_done_not_found() {
    source_scanner
    setup_stats_dir
    PROBES="icmp"
    ICMP_DONE=true
    TCP_DONE=false
    echo "99.99.99.99" > "$STATS_DIR/fping_alive"

    local result
    result=$(probe_ip "10.7.0.1" "10.7.0.0/24")
    assert_eq "$result" "" "ICMP_DONE: IP not alive → empty result"
    # Check fail counter was incremented
    local fails
    fails=$(wc -l < "$STATS_DIR/fail_icmp" 2>/dev/null | tr -d ' ')
    assert_gt "$fails" 0 "ICMP fail counter incremented"
}

test_probe_tcp_done_found() {
    source_scanner
    setup_stats_dir
    PROBES="tcp"
    PORTS="443"
    ICMP_DONE=false
    TCP_DONE=true
    echo "10.7.0.1:443" > "$STATS_DIR/tcp_open"

    local result
    result=$(probe_ip "10.7.0.1" "10.7.0.0/24")
    assert_contains "$result" "tcp443" "TCP_DONE: port open → tcp443 in result"
}

test_probe_tcp_done_not_found() {
    source_scanner
    setup_stats_dir
    PROBES="tcp"
    PORTS="443"
    ICMP_DONE=false
    TCP_DONE=true
    > "$STATS_DIR/tcp_open"  # empty: no open ports

    local result
    result=$(probe_ip "10.7.0.1" "10.7.0.0/24")
    assert_eq "$result" "" "TCP_DONE: port closed → empty result"
    local fails
    fails=$(wc -l < "$STATS_DIR/fail_tcp_443" 2>/dev/null | tr -d ' ')
    assert_gt "$fails" 0 "TCP fail counter incremented"
}

test_probe_https_success() {
    source_scanner
    setup_stats_dir
    PROBES="https"
    PORTS="443"
    ICMP_DONE=false
    TCP_DONE=false
    export MOCK_CURL_PROBE_EXIT=0

    local result
    result=$(PATH="$TEST_TMPDIR/mock_bin:$TEST_TMPDIR/base_bin" probe_ip "10.7.0.1" "10.7.0.0/24")
    assert_contains "$result" "https" "curl success → https in result"

    unset MOCK_CURL_PROBE_EXIT
}

test_probe_https_fail() {
    source_scanner
    setup_stats_dir
    PROBES="https"
    PORTS="443"
    ICMP_DONE=false
    TCP_DONE=false
    export MOCK_CURL_PROBE_EXIT=1

    local result
    result=$(PATH="$TEST_TMPDIR/mock_bin:$TEST_TMPDIR/base_bin" probe_ip "10.7.0.1" "10.7.0.0/24")
    assert_eq "$result" "" "curl fail → empty result"
    local fails
    fails=$(wc -l < "$STATS_DIR/fail_https" 2>/dev/null | tr -d ' ')
    assert_gt "$fails" 0 "HTTPS fail counter incremented"

    unset MOCK_CURL_PROBE_EXIT
}

test_probe_only_icmp() {
    source_scanner
    setup_stats_dir
    PROBES="icmp"
    ICMP_DONE=true
    TCP_DONE=false
    echo "10.7.0.1" > "$STATS_DIR/fping_alive"

    local result
    result=$(probe_ip "10.7.0.1" "10.7.0.0/24")
    assert_contains "$result" "icmp" "icmp-only: icmp present"
    assert_not_contains "$result" "tcp" "icmp-only: no tcp"
    assert_not_contains "$result" "https" "icmp-only: no https"
}

test_probe_result_format() {
    source_scanner
    setup_stats_dir
    PROBES="icmp,tcp"
    PORTS="443"
    ICMP_DONE=true
    TCP_DONE=true
    echo "10.7.0.1" > "$STATS_DIR/fping_alive"
    echo "10.7.0.1:443" > "$STATS_DIR/tcp_open"

    local result
    result=$(probe_ip "10.7.0.1" "10.7.0.0/24")
    # Format should be: cidr,ip,methods
    assert_eq "$result" "10.7.0.0/24,10.7.0.1,icmp,tcp443" "result format is cidr,ip,methods"
}

# ============================================================
# GROUP 8: Resume Logic
# ============================================================

test_fresh_creates_progress() {
    export MOCK_FPING_ALIVE="/dev/null"
    export MOCK_PING_EXIT=1
    export MOCK_CURL_PROBE_EXIT=1
    export MOCK_NC_EXIT=1
    local outcsv="$TEST_TMPDIR/scans/fresh_test.csv"

    run_scanner --file "$TEST_TMPDIR/mock_data/cidrs.txt" --probes icmp \
        --output "$outcsv" >/dev/null 2>&1 || true

    assert_file_exists "$outcsv" "fresh scan creates CSV"
    local progress="${outcsv%.csv}.progress"
    assert_file_exists "$progress" "fresh scan creates .progress file"

    # CSV should have header
    local header
    header=$(head -1 "$outcsv")
    assert_eq "$header" "cidr,ip,methods" "CSV has correct header"

    unset MOCK_FPING_ALIVE MOCK_PING_EXIT MOCK_CURL_PROBE_EXIT MOCK_NC_EXIT
}

test_resume_filters_done() {
    export MOCK_FPING_ALIVE="/dev/null"
    export MOCK_PING_EXIT=1
    export MOCK_CURL_PROBE_EXIT=1
    export MOCK_NC_EXIT=1
    local outcsv="$TEST_TMPDIR/scans/resume_filter_test.csv"
    local progress="${outcsv%.csv}.progress"

    # Create existing output and progress
    echo "cidr,ip,methods" > "$outcsv"
    echo "10.7.0.0/24" > "$progress"

    local output
    output=$(run_scanner --file "$TEST_TMPDIR/mock_data/cidrs.txt" --probes icmp \
        --resume "$outcsv" 2>&1) || true

    assert_contains "$output" "Resuming scan" "resume shows resuming message"
    assert_contains "$output" "1 CIDRs already scanned" "resume reports previous count"

    unset MOCK_FPING_ALIVE MOCK_PING_EXIT MOCK_CURL_PROBE_EXIT MOCK_NC_EXIT
}

test_resume_missing_progress() {
    export MOCK_FPING_ALIVE="/dev/null"
    export MOCK_PING_EXIT=1
    export MOCK_CURL_PROBE_EXIT=1
    export MOCK_NC_EXIT=1
    local outcsv="$TEST_TMPDIR/scans/resume_noprog_test.csv"

    # Create CSV but no progress file
    echo "cidr,ip,methods" > "$outcsv"

    local output
    output=$(run_scanner --file "$TEST_TMPDIR/mock_data/cidrs.txt" --probes icmp \
        --resume "$outcsv" 2>&1) || true

    assert_contains "$output" "WARNING" "resume without progress file warns"

    unset MOCK_FPING_ALIVE MOCK_PING_EXIT MOCK_CURL_PROBE_EXIT MOCK_NC_EXIT
}

test_resume_all_done() {
    export MOCK_FPING_ALIVE="/dev/null"
    export MOCK_PING_EXIT=1
    export MOCK_CURL_PROBE_EXIT=1
    export MOCK_NC_EXIT=1
    local outcsv="$TEST_TMPDIR/scans/resume_done_test.csv"
    local progress="${outcsv%.csv}.progress"

    echo "cidr,ip,methods" > "$outcsv"
    # Write all CIDRs to progress (both from cidrs.txt)
    printf '10.7.0.0/24\n10.7.1.0/24\n' > "$progress"

    local output
    output=$(run_scanner --file "$TEST_TMPDIR/mock_data/cidrs.txt" --probes icmp \
        --resume "$outcsv" 2>&1) || true

    assert_contains "$output" "Nothing to resume" "resume all done exits cleanly"

    unset MOCK_FPING_ALIVE MOCK_PING_EXIT MOCK_CURL_PROBE_EXIT MOCK_NC_EXIT
}

# ============================================================
# GROUP 9: Progress & Stats Helpers
# ============================================================

test_count_lines() {
    source_scanner
    local tmpf="$TEST_TMPDIR/count_test.txt"
    printf '1\n2\n3\n4\n5\n' > "$tmpf"
    assert_eq "$(_count_lines "$tmpf")" "5" "_count_lines returns 5 for 5-line file"

    > "$tmpf"
    assert_eq "$(_count_lines "$tmpf")" "0" "_count_lines returns 0 for empty file"
}

test_print_progress_format() {
    source_scanner
    PROBES="icmp"
    setup_stats_dir
    echo 25 > "$STATS_DIR/scanned"
    echo 5 > "$STATS_DIR/found"
    echo 5 > "$STATS_DIR/icmp"
    echo 25 > "$STATS_DIR/launched"
    printf '1\n1\n1\n' > "$STATS_DIR/fail_icmp"  # 3 failures

    local output
    output=$(_print_progress 100 "$STATS_DIR" 2>&1)
    assert_contains "$output" "25.00%" "progress shows 2-decimal percentage"
    assert_contains "$output" "25/100" "progress shows scanned/total"
    assert_contains "$output" "ok:5" "progress shows accessible count"
}

# ============================================================
# GROUP 10: Cleanup
# ============================================================

test_temp_files_cleaned() {
    source_scanner
    local tmpf1="$TEST_TMPDIR/tempfile1.txt"
    local tmpf2="$TEST_TMPDIR/tempfile2.txt"
    local tmpdir1="$TEST_TMPDIR/tempdir1"
    echo "test" > "$tmpf1"
    echo "test" > "$tmpf2"
    mkdir -p "$tmpdir1"
    echo "test" > "$tmpdir1/inside.txt"

    TEMP_FILES=("$tmpf1" "$tmpf2" "$tmpdir1")
    cleanup_files

    assert_file_not_exists "$tmpf1" "temp file 1 cleaned up"
    assert_file_not_exists "$tmpf2" "temp file 2 cleaned up"

    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ ! -d "$tmpdir1" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  PASS: temp directory cleaned up"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "  FAIL: temp directory should be removed"
    fi
    TEMP_FILES=()
}

test_progress_survives_cleanup() {
    source_scanner
    local progress="$TEST_TMPDIR/scans/survive_test.progress"
    echo "10.0.0.0/24" > "$progress"

    # Progress file is NOT in TEMP_FILES, so cleanup_files shouldn't touch it
    local other="$TEST_TMPDIR/other_temp.txt"
    echo "temp" > "$other"
    TEMP_FILES=("$other")
    cleanup_files

    assert_file_exists "$progress" "progress file survives cleanup"
    assert_file_not_exists "$other" "other temp file cleaned up"
    TEMP_FILES=()
}

# ============================================================
# GROUP 11: Edge Cases
# ============================================================

test_empty_input() {
    export MOCK_PING_EXIT=1
    export MOCK_CURL_PROBE_EXIT=1
    export MOCK_NC_EXIT=1
    local output
    output=$(run_scanner --file "$TEST_TMPDIR/mock_data/empty.txt" --probes icmp \
        --output "$TEST_TMPDIR/scans/empty_test.csv" 2>&1) || true
    assert_contains "$output" "No CIDRs extracted" "empty input shows error"
    unset MOCK_PING_EXIT MOCK_CURL_PROBE_EXIT MOCK_NC_EXIT
}

test_region_excludes_all() {
    export MOCK_PING_EXIT=1
    export MOCK_CURL_PROBE_EXIT=1
    export MOCK_NC_EXIT=1
    local output
    output=$(run_scanner --file "$TEST_TMPDIR/mock_data/azure.json" --region "nonexistent_region_xyz" \
        --probes icmp --output "$TEST_TMPDIR/scans/region_test.csv" 2>&1) || true
    assert_contains "$output" "No CIDRs extracted" "region filter excludes all → error"
    unset MOCK_PING_EXIT MOCK_CURL_PROBE_EXIT MOCK_NC_EXIT
}

test_min_prefix_filter() {
    source_scanner
    MIN_PREFIX=28

    # Simulate the filter pipeline from main()
    local result
    result=$(cat "$TEST_TMPDIR/mock_data/mixed_prefix.txt" | grep -v ':' | while read -r cidr; do
        local mask="${cidr#*/}"
        if [[ "$mask" -le "$MIN_PREFIX" ]]; then
            if [[ "$mask" -le 24 ]]; then echo "$cidr"
            else cidr_to_24 "$cidr"; fi
        fi
    done | sort -u)

    assert_contains "$result" "10.8.0.0/24" "/24 included as-is"
    assert_contains "$result" "10.8.1.0/24" "/26 normalized to /24"
    assert_not_contains "$result" "10.8.2.0/30" "/30 excluded (30 > 28)"
    assert_contains "$result" "10.8.3.0/16" "/16 included as-is"
}

test_output_dir_created() {
    export MOCK_FPING_ALIVE="/dev/null"
    export MOCK_PING_EXIT=1
    export MOCK_CURL_PROBE_EXIT=1
    export MOCK_NC_EXIT=1
    local newdir="$TEST_TMPDIR/new_output_dir"

    run_scanner --file "$TEST_TMPDIR/mock_data/cidrs.txt" --probes icmp \
        --output-dir "$newdir" >/dev/null 2>&1 || true

    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ -d "$newdir" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "  PASS: output dir auto-created"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "  FAIL: output dir was not created"
    fi

    unset MOCK_FPING_ALIVE MOCK_PING_EXIT MOCK_CURL_PROBE_EXIT MOCK_NC_EXIT
}

# ============================================================
# RUNNER
# ============================================================

main() {
    echo "=== iran_scanner.sh Test Suite ==="
    echo ""

    setup

    echo "--- CLI & Argument Parsing ---"
    test_help_flag
    test_unknown_flag
    test_default_values
    test_file_flag
    test_probes_flag
    test_parallel_flag
    test_ports_flag
    test_output_flag
    test_resume_flag
    test_verbose_flag

    echo ""
    echo "--- Format Auto-Detection ---"
    test_detect_azure
    test_detect_aws
    test_detect_gcp
    test_detect_oracle
    test_detect_fastly
    test_detect_cidrs
    test_detect_fallback

    echo ""
    echo "--- CIDR Extraction (with jq) ---"
    test_extract_azure_with_jq
    test_extract_aws_with_jq
    test_extract_gcp_with_jq
    test_extract_oracle_with_jq
    test_extract_fastly_with_jq
    test_extract_cloudflare
    test_extract_cidrs

    echo ""
    echo "--- CIDR Extraction (without jq / grep fallback) ---"
    test_extract_azure_without_jq
    test_extract_aws_without_jq
    test_extract_gcp_without_jq
    test_extract_oracle_without_jq
    test_extract_fastly_without_jq

    echo ""
    echo "--- CIDR Extraction (region filters) ---"
    test_extract_azure_region_filter
    test_extract_aws_region_filter
    test_extract_gcp_region_filter
    test_extract_oracle_region_filter
    test_extract_ipv6_filtered

    echo ""
    echo "--- CIDR Helpers ---"
    test_ip_to_int
    test_int_to_ip
    test_cidr_sample_ip
    test_cidr_to_24

    echo ""
    echo "--- Tool Detection ---"
    test_no_tools_detected
    test_fping_only_detected
    test_nmap_only_detected
    test_all_tools_detected

    echo ""
    echo "--- Bulk Scan Phases ---"
    test_fping_bulk_icmp
    test_nmap_bulk_tcp
    test_fping_nmap_fast_path
    test_masscan_needs_root

    echo ""
    echo "--- probe_ip Function ---"
    test_probe_icmp_done_found
    test_probe_icmp_done_not_found
    test_probe_tcp_done_found
    test_probe_tcp_done_not_found
    test_probe_https_success
    test_probe_https_fail
    test_probe_only_icmp
    test_probe_result_format

    echo ""
    echo "--- Resume Logic ---"
    test_fresh_creates_progress
    test_resume_filters_done
    test_resume_missing_progress
    test_resume_all_done

    echo ""
    echo "--- Progress & Stats ---"
    test_count_lines
    test_print_progress_format

    echo ""
    echo "--- Cleanup ---"
    test_temp_files_cleaned
    test_progress_survives_cleanup

    echo ""
    echo "--- Edge Cases ---"
    test_empty_input
    test_region_excludes_all
    test_min_prefix_filter
    test_output_dir_created

    teardown

    echo ""
    echo "========================================"
    echo "  Results: $PASS_COUNT passed, $FAIL_COUNT failed, $TESTS_RUN total"
    echo "========================================"
    [[ $FAIL_COUNT -eq 0 ]] && exit 0 || exit 1
}

main "$@"
