# Cloud IP Scanner & VPS Setup for Internet Freedom

Tools for finding accessible cloud IP ranges during internet shutdowns and provisioning proxy servers on those IPs.

## How It Works

1. **Download ranges** (`download_ranges.sh`) — run outside Iran to fetch IP ranges from all major cloud providers
2. **Iran scanner** (`iran_scanner.sh`) — run inside Iran to discover which cloud IP ranges are accessible during a shutdown
3. **Cloud setup** (`cloud_setup.sh`) — run outside Iran to reserve a public IP in an accessible range, create a VM, and SSH in for proxy setup via [MoaV](https://moav.sh)

## Quick Start

```bash
# 1. Outside Iran — download all provider IP ranges
./download_ranges.sh samples/

# 2. Send the samples/ folder to someone inside Iran (USB, Bluetooth, etc.)

# 3. Inside Iran — find which ranges are open
./iran_scanner.sh --file samples/azure_servicetags.json --output open_ranges_scan.txt
./iran_scanner.sh --file samples/aws_ip_ranges.json --output open_ranges_scan.txt
./iran_scanner.sh --file samples/all_cidrs.txt --output open_ranges_scan.txt  # scan everything

# 4. Outside Iran — provision a VM on an accessible IP
./cloud_setup.sh --provider azure --ranges "102.37.128.0/17" --region southafricanorth

# 5. Inside the SSH session that opens:
curl -fsSL moav.sh/install.sh | sudo bash
sudo moav domainless
```

## Scripts

### `download_ranges.sh`

Downloads IP ranges from all supported cloud providers into a directory. Run this **outside Iran** where internet is unrestricted.

```bash
./download_ranges.sh [output_dir]   # default: samples/
```

Downloads from:

| Provider | File | Source URL |
|---|---|---|
| Azure | `azure_servicetags.json` | [ServiceTags_Public](https://www.microsoft.com/en-us/download/details.aspx?id=56519) |
| AWS | `aws_ip_ranges.json` | https://ip-ranges.amazonaws.com/ip-ranges.json |
| GCP | `gcp_cloud.json` | https://www.gstatic.com/ipranges/cloud.json |
| Oracle Cloud | `oracle_ip_ranges.json` | https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json |
| Cloudflare | `cloudflare_ips.txt` | https://www.cloudflare.com/ips-v4 |
| Fastly | `fastly_ips.json` | https://api.fastly.com/public-ip-list |

Also generates `all_cidrs.txt` — a deduplicated plain CIDR list combining all providers.

### `iran_scanner.sh`

Discovers which cloud IP ranges are reachable from inside Iran. Supports multiple input formats.

```
Usage: iran_scanner.sh [OPTIONS]

Input (one of):
  --file <path>       Local file: JSON (Azure/AWS/GCP/OCI/Fastly) or plain CIDR list
  --provider <name>   Download from: azure, aws, gcp, oracle, cloudflare, fastly

Options:
  --format <fmt>      Force format (auto-detected if omitted):
                        azure, aws, gcp, oracle, cloudflare, fastly, cidrs
  --region <pattern>  Only scan regions matching pattern (e.g. "southafrica|us-east")
  --parallel <N>      Max concurrent probes (default: 50)
  --ports <list>      Comma-separated ports to test (default: 443,80,22)
  --probes <list>     Probe types to run: icmp,tcp,https (default: all three)
  --output <path>     Output CSV file path (default: scans/scan_TIMESTAMP.csv)
  --output-dir <dir>  Output directory (default: scans/)
  --min-prefix <N>    Skip CIDRs smaller than /N (default: 28)
  -v, --verbose       Show detailed probe logs for each IP
```

**Supported input formats** (auto-detected from file content):

| Format | JSON Structure | Region filtering |
|---|---|---|
| `azure` | `.values[].properties.addressPrefixes[]` | By service tag name |
| `aws` | `.prefixes[].ip_prefix` | By `.region` field |
| `gcp` | `.prefixes[].ipv4Prefix` | By `.scope` field |
| `oracle` | `.regions[].cidrs[].cidr` | By `.region` field |
| `fastly` | `.addresses[]` | None |
| `cloudflare` | Plain text, one CIDR per line | None |
| `cidrs` | Plain text, one CIDR per line | None |

**Examples**:
```bash
# Auto-download and scan Azure ranges
./iran_scanner.sh --provider azure

# Use pre-downloaded Azure JSON, filter to South Africa
./iran_scanner.sh --file samples/azure_servicetags.json --region "southafrica"

# Use pre-downloaded AWS JSON, filter to US East
./iran_scanner.sh --file samples/aws_ip_ranges.json --region "us-east"

# Use pre-downloaded GCP JSON
./iran_scanner.sh --file samples/gcp_cloud.json --region "me-central"

# Use pre-extracted plain CIDR list (like all_azure_ips.txt or all_cidrs.txt)
./iran_scanner.sh --file samples/all_azure_ips.txt

# Scan all providers at once using the combined file
./iran_scanner.sh --file samples/all_cidrs.txt --parallel 100

# Verbose mode — see every probe result
./iran_scanner.sh --file samples/aws_ip_ranges.json -v

# Ping only (fastest scan)
./iran_scanner.sh --file samples/all_cidrs.txt --probes icmp

# Ping + TCP only (skip HTTPS)
./iran_scanner.sh --file samples/aws_ip_ranges.json --probes icmp,tcp
```

> **Tip: Two-pass scanning** — The fastest strategy for large range files (e.g. all Azure or `all_cidrs.txt`) is two passes:
> 1. **Fast ping sweep** to find reachable ranges:
>    ```bash
>    ./iran_scanner.sh --file samples/azure_servicetags.json --probes icmp --parallel 200
>    ```
> 2. **Deep scan** only the reachable CIDRs with TCP + HTTPS:
>    ```bash
>    ./iran_scanner.sh --file scans/scan_YYYYMMDD.csv --probes tcp,https --parallel 100
>    ```
>
> Ping probes complete in ~2s each vs ~8-10s for full TCP+HTTPS, so pass 1 finishes much faster. Pass 2 then only tests the ranges that responded — typically a small fraction of the total.

**Minimal dependencies**: `bash`, `curl`, `ping`. Uses `jq` if available, falls back to `grep`.

**Offline mode**: Have someone outside Iran run `download_ranges.sh` and send the files, then:
```bash
./iran_scanner.sh --file samples/all_cidrs.txt
```

**Output format** (CSV in `scans/` directory):
```csv
cidr,ip,methods
102.37.128.0/17,102.37.128.1,"tcp443,tcp22,https"
34.64.0.0/11,34.64.0.1,"tcp443,https"
```

### `cloud_setup.sh`

Multi-provider VPS provisioner. Brute-force reserves public IPs until one lands in a target range, then creates a VM and opens an SSH session.

```
Usage: cloud_setup.sh --provider <provider> [OPTIONS]

Providers:
  azure          Microsoft Azure
  oracle         Oracle Cloud (free tier available)
  gcp            Google Cloud Platform
  digitalocean   DigitalOcean
  hetzner        Hetzner Cloud
  vultr          Vultr

Options:
  --provider <name>     Cloud provider (default: azure)
  --ranges <cidrs>      Comma-separated target CIDRs
  --ranges-file <path>  File with target CIDRs (iran_scanner output or open_ranges.txt)
  --region <region>     Cloud region
  --rg <name>           Resource group name (default: iran-proxy-rg)
  --vm-name <name>      VM name (default: proxy-vm)
  --vm-size <size>      VM size (uses cheapest if omitted)
  --ssh-key <path>      SSH public key (default: ~/.ssh/id_rsa.pub)
  --max-attempts <N>    Max IP allocation attempts (default: 500)
  --scan-only           Only find/reserve an IP, don't create a VM
  --list-regions        List available regions for the provider
  -v, --verbose         Show detailed logs (full CLI output, CIDR matching, errors)
```

**Examples**:
```bash
# Azure — South Africa range
./cloud_setup.sh --provider azure --ranges "102.37.128.0/17" --region southafricanorth

# Oracle Cloud — free tier, Middle East region
./cloud_setup.sh --provider oracle --ranges-file open_ranges.txt --region me-jeddah-1

# GCP — Google service ranges (likely whitelisted since Google services were accessible)
./cloud_setup.sh --provider gcp --ranges "34.64.0.0/11" --region me-central1-a

# Hetzner — cheap EU option
./cloud_setup.sh --provider hetzner --ranges-file open_ranges.txt --region hel1

# Just scan, don't create VM
./cloud_setup.sh --provider azure --ranges "102.37.0.0/16" --region southafricanorth --scan-only

# List available regions
./cloud_setup.sh --provider azure --list-regions
```

### `azure_setup.sh`

Simpler Azure-only version of `cloud_setup.sh`. Same IP scanning logic but only supports Azure. Use this if you only need Azure.

### `open_ranges.txt`

Pre-populated list of cloud IP ranges likely to be accessible during Iranian shutdowns, based on services confirmed working during the January 2026 shutdown.

| Category | Ranges | Why likely accessible |
|---|---|---|
| Azure South Africa | `102.37.0.0/16`, `102.133.0.0/16` | Original target |
| Azure UAE/Qatar | `20.37.64.0/18`, `20.21.0.0/18`, etc. | Middle East regions |
| Azure M365 | `52.96.0.0/14`, `13.107.128.0/22`, etc. | Outlook was accessible |
| Azure GitHub | `140.82.112.0/20`, `192.30.252.0/22` | GitHub was accessible |
| Azure OpenAI | `13.65.0.0/16`, `40.78.0.0/17` | ChatGPT was accessible |
| Google Services | `142.250.0.0/15`, `172.217.0.0/16`, etc. | Gmail, Meet, Search, Maps, Play all working |
| Cloudflare CDN | `104.16.0.0/13`, `172.64.0.0/13`, etc. | Custom domains route; Iranian banks use Cloudflare |
| Apple | `17.0.0.0/8` | App Store was accessible |
| Oracle Cloud | `129.146.0.0/16`, `152.67.0.0/16`, etc. | Free tier VMs available |
| Fastly/Akamai | `151.101.0.0/16`, `23.32.0.0/11` | CDN ranges |

The file is tab-separated with columns: `CIDR`, `Category`, `Notes`. It's automatically filtered by provider when used with `cloud_setup.sh --ranges-file`.

### `samples/`

Pre-downloaded IP range files. Use `download_ranges.sh` to populate, or add files manually.

| File | Description |
|---|---|
| `ServiceTags_Public_20260309.json` | Azure ServiceTags JSON (use with `--file` + `--format azure`) |
| `all_azure_ips.txt` | Pre-extracted Azure CIDRs (use with `--file`, auto-detects as `cidrs`) |
| `azure_servicetags.json` | Downloaded by `download_ranges.sh` |
| `aws_ip_ranges.json` | Downloaded by `download_ranges.sh` |
| `gcp_cloud.json` | Downloaded by `download_ranges.sh` |
| `oracle_ip_ranges.json` | Downloaded by `download_ranges.sh` |
| `cloudflare_ips.txt` | Downloaded by `download_ranges.sh` |
| `fastly_ips.json` | Downloaded by `download_ranges.sh` |
| `all_cidrs.txt` | Combined deduplicated CIDRs from all providers |

## IP Range Source URLs

For manual download or reference:

| Provider | URL | Updated |
|---|---|---|
| Azure | [ServiceTags_Public JSON](https://www.microsoft.com/en-us/download/details.aspx?id=56519) | Weekly |
| AWS | https://ip-ranges.amazonaws.com/ip-ranges.json | As needed |
| GCP | https://www.gstatic.com/ipranges/cloud.json | As needed |
| Oracle | https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json | Weekly |
| Cloudflare | https://www.cloudflare.com/ips-v4 | As needed |
| Fastly | https://api.fastly.com/public-ip-list | As needed |
| DigitalOcean | Not officially published | — |
| Hetzner | Not officially published | — |

## Provider Comparison (for VPS provisioning)

| Provider | CLI Tool | Free Tier | IP Method | Default VM Size |
|---|---|---|---|---|
| Azure | `az` | No | Static public IP | Standard_B1s |
| Oracle Cloud | `oci` | Yes (A1 ARM, 4 OCPU/24GB) | Reserved public IP | VM.Standard.A1.Flex |
| GCP | `gcloud` | $300 credit | Static address | e2-micro |
| DigitalOcean | `doctl` | No | Reserved IP | s-1vcpu-1gb |
| Hetzner | `hcloud` | No | Floating IP | cx22 |
| Vultr | `vultr-cli` | No | Reserved IP | — |

## Prerequisites

- **bash** 4.0+
- **curl**
- **jq** (recommended, not required for iran_scanner.sh)
- Cloud provider CLI installed and authenticated for the provider you choose
- SSH key pair (`ssh-keygen -t ed25519` if you don't have one)

## How the IP Scanning Works

Cloud providers assign public IPs from regional pools but don't let you choose a specific IP. The scripts brute-force it:

1. Request a new public IP in the target region
2. Check if the assigned IP falls within a target CIDR range
3. If yes, keep it. If no, delete it and try again
4. Once a matching IP is found, create a VM and attach it

The probability of hitting a target range depends on the pool size. Smaller regional pools (South Africa, Middle East) have better odds. Expect anywhere from 1 to 100+ attempts.

**Azure-specific**: Azure has a 3 public IP limit per subscription per region on free/trial accounts. The script handles this by waiting for deletes to propagate before retrying.

## MoaV Proxy Setup

After the VM is created and you're SSH'd in:

```bash
# Install MoaV (installs Docker + proxy stack)
curl -fsSL moav.sh/install.sh | sudo bash

# Set up domain-less mode (no domain/DNS needed)
sudo moav domainless
```

MoaV supports multiple protocols: VLESS/Reality, WireGuard, Hysteria2, Telegram MTProxy, and more. Domain-less mode uses protocols that don't require a domain name or TLS certificate — ideal when DNS may be unreliable.

Share the server IP with users inside Iran. They connect using compatible clients (v2rayNG, Nekoray, etc.).

## Background: Iran Internet Shutdowns

During shutdowns, Iran switches to a "block-by-default" model where only explicitly whitelisted services are accessible. Whitelisted services historically include:

- **Microsoft**: Outlook, Bing (→ Azure/M365 IP ranges routable)
- **Google**: Gmail, Meet, Search, Maps, Play Store (→ Google IP ranges routable)
- **GitHub**: Accessible (→ Microsoft/GitHub IP ranges routable)
- **ChatGPT**: Accessible (→ Azure/OpenAI IP ranges routable)
- **Apple**: App Store (→ Apple IP ranges routable)
- **Cloudflare**: Custom domains work, workers.dev blocked (→ CF CDN IPs routable)
- **Domestic**: Banking, government sites, Bale messenger

If a cloud VPS has an IP within one of these routable ranges, traffic to it passes through the firewall — enabling proxy access.

## Files

```
├── iran_scanner.sh      # Inside Iran: discover accessible IP ranges (multi-provider)
├── cloud_setup.sh       # Outside Iran: multi-provider VPS provisioner
├── azure_setup.sh       # Outside Iran: Azure-only (simpler)
├── download_ranges.sh   # Download IP ranges from all providers
├── open_ranges.txt      # Pre-populated whitelisted ranges
├── scanner.sh           # Original Azure IP scanner (v1)
├── scanner_v2.sh        # Azure IP scanner (v2, sequential)
├── scans/               # Scan results (gitignored)
│   └── scan_20260311_013645.csv
├── samples/             # Downloaded IP range files
│   ├── azure_servicetags.json
│   ├── aws_ip_ranges.json
│   ├── gcp_cloud.json
│   ├── oracle_ip_ranges.json
│   ├── cloudflare_ips.txt
│   ├── fastly_ips.json
│   └── all_cidrs.txt
├── .gitignore           # Ignores scans/
└── README.md
```
