#!/bin/bash
#
# download_ranges.sh — Download IP ranges from all major cloud providers.
# Run this outside Iran and share the output files with someone inside.
#

set -euo pipefail

OUTPUT_DIR="${1:-samples}"
mkdir -p "$OUTPUT_DIR"

echo "Downloading cloud provider IP ranges to $OUTPUT_DIR/"
echo ""

# --- Azure ---
echo -n "Azure ServiceTags... "
AZURE_URL=$(curl -sL "https://www.microsoft.com/en-us/download/details.aspx?id=56519" 2>/dev/null \
    | grep -oE 'https://download\.microsoft\.com/download/[^"]+ServiceTags_Public_[0-9]+\.json' \
    | head -1)
if [[ -n "$AZURE_URL" ]]; then
    curl -sL "$AZURE_URL" -o "$OUTPUT_DIR/azure_servicetags.json"
    echo "OK ($(wc -c < "$OUTPUT_DIR/azure_servicetags.json" | tr -d ' ') bytes)"
else
    # Fallback: try last 7 days
    for i in $(seq 0 6); do
        if date -v-${i}d +%Y%m%d &>/dev/null; then
            d=$(date -v-${i}d +%Y%m%d)
        else
            d=$(date -d "-${i} days" +%Y%m%d)
        fi
        URL="https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_${d}.json"
        if curl -sI "$URL" 2>/dev/null | grep -q "200"; then
            curl -sL "$URL" -o "$OUTPUT_DIR/azure_servicetags.json"
            echo "OK (fallback date $d)"
            break
        fi
    done
fi

# --- AWS ---
echo -n "AWS ip-ranges... "
curl -sL "https://ip-ranges.amazonaws.com/ip-ranges.json" -o "$OUTPUT_DIR/aws_ip_ranges.json"
echo "OK ($(wc -c < "$OUTPUT_DIR/aws_ip_ranges.json" | tr -d ' ') bytes)"

# --- GCP ---
echo -n "GCP cloud.json... "
curl -sL "https://www.gstatic.com/ipranges/cloud.json" -o "$OUTPUT_DIR/gcp_cloud.json"
echo "OK ($(wc -c < "$OUTPUT_DIR/gcp_cloud.json" | tr -d ' ') bytes)"

# --- Oracle Cloud ---
echo -n "Oracle Cloud... "
curl -sL "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json" -o "$OUTPUT_DIR/oracle_ip_ranges.json"
echo "OK ($(wc -c < "$OUTPUT_DIR/oracle_ip_ranges.json" | tr -d ' ') bytes)"

# --- Cloudflare ---
echo -n "Cloudflare... "
curl -sL "https://www.cloudflare.com/ips-v4" -o "$OUTPUT_DIR/cloudflare_ips.txt"
echo "OK ($(wc -l < "$OUTPUT_DIR/cloudflare_ips.txt" | tr -d ' ') ranges)"

# --- Fastly ---
echo -n "Fastly... "
curl -sL "https://api.fastly.com/public-ip-list" -o "$OUTPUT_DIR/fastly_ips.json"
echo "OK ($(wc -c < "$OUTPUT_DIR/fastly_ips.json" | tr -d ' ') bytes)"

# --- Generate combined plain CIDR list ---
echo ""
echo -n "Generating combined all_cidrs.txt... "
COMBINED="$OUTPUT_DIR/all_cidrs.txt"
> "$COMBINED"

if command -v jq &>/dev/null; then
    # Azure
    jq -r '.values[].properties.addressPrefixes[]' "$OUTPUT_DIR/azure_servicetags.json" 2>/dev/null \
        | grep -v ':' >> "$COMBINED"
    # AWS
    jq -r '.prefixes[].ip_prefix' "$OUTPUT_DIR/aws_ip_ranges.json" 2>/dev/null >> "$COMBINED"
    # GCP
    jq -r '.prefixes[] | select(.ipv4Prefix) | .ipv4Prefix' "$OUTPUT_DIR/gcp_cloud.json" 2>/dev/null >> "$COMBINED"
    # Oracle
    jq -r '.regions[].cidrs[].cidr' "$OUTPUT_DIR/oracle_ip_ranges.json" 2>/dev/null >> "$COMBINED"
    # Fastly
    jq -r '.addresses[]' "$OUTPUT_DIR/fastly_ips.json" 2>/dev/null >> "$COMBINED"
else
    echo "(jq not available, using grep fallback)" >&2
    for f in "$OUTPUT_DIR"/*.json; do
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' "$f" 2>/dev/null >> "$COMBINED"
    done
fi

# Cloudflare (plain text)
cat "$OUTPUT_DIR/cloudflare_ips.txt" >> "$COMBINED"

# Deduplicate
sort -u -o "$COMBINED" "$COMBINED"
TOTAL=$(wc -l < "$COMBINED" | tr -d ' ')
echo "OK ($TOTAL unique CIDRs)"

echo ""
echo "========================================"
echo "  Downloads Complete"
echo "========================================"
echo "  Directory:  $OUTPUT_DIR/"
echo "  Files:"
for f in "$OUTPUT_DIR"/*; do
    echo "    $(basename "$f")  ($(wc -c < "$f" | tr -d ' ') bytes)"
done
echo ""
echo "  Combined:   all_cidrs.txt ($TOTAL CIDRs)"
echo "========================================"
echo ""
echo "Usage with iran_scanner.sh:"
echo "  # Scan a specific provider"
echo "  ./iran_scanner.sh --file $OUTPUT_DIR/aws_ip_ranges.json"
echo ""
echo "  # Scan all providers at once"
echo "  ./iran_scanner.sh --file $OUTPUT_DIR/all_cidrs.txt"
echo ""
echo "  # Scan with region filter"
echo "  ./iran_scanner.sh --file $OUTPUT_DIR/azure_servicetags.json --region 'southafrica'"
