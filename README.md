<div align="center">

```
   _____                          ______                     __
  / ___/_________  ____  ___     / ____/_  ______ __________/ /
  \__ \/ ___/ __ \/ __ \/ _ \   / / __/ / / / __ `/ ___/ __  /
 ___/ / /__/ /_/ / /_/ /  __/  / /_/ / /_/ / /_/ / /  / /_/ /
/____/\___/\____/ .___/\___/   \____/\__,_/\__,_/_/   \__,_/
		/_/

```

**Authorized Web + Network Security Assessment Framework**

![Shell](https://img.shields.io/badge/shell-bash-green?logo=gnu-bash)
![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20WSL-informational)

</div>

---

> ⚠️ **AUTHORIZED USE ONLY.** ScopeGuard must only be run against systems you own or have explicit written permission to assess. Unauthorized scanning is illegal in most jurisdictions.

---

## What is ScopeGuard?

ScopeGuard is a single-file, dependency-light Bash framework that orchestrates a structured security triage workflow for both **web targets** (URLs/domains) and **network targets** (IPs/CIDRs). It produces a clean, structured report — a Markdown summary, a findings CSV, and preserved raw tool output — suitable for authorized security projects, CTF documentation, and resume-ready security portfolios.

It is built around three principles:

- **Authorization-first** — it will not run a single scan without `--authorized`
- **Graceful degradation** — optional tools (`nuclei`, `testssl.sh`, `dig`, `jq`) are used when available; the assessment continues and notes gaps when they are not
- **Auditable output** — every raw tool output is preserved, every finding is timestamped, and the summary report cites evidence paths

---

## Features

### 🌐 Web Mode
- DNS snapshot (A, AAAA, MX, NS records)
- HTTP metadata collection (status, content type, remote IP, response time, page title)
- Security header triage (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Low-noise common path probing (`/.env`, `/.git/HEAD`, `/phpinfo.php`, `/backup.zip`, etc.)
- TLS/SSL assessment via `testssl.sh`
- Template-based vulnerability triage via `nuclei` (rate-limited, severity-summarized)

### 🔍 Network Mode
- Host discovery with Nmap ping sweep
- TCP service enumeration with banner / `http-title` / `ssl-cert` / `ssh-hostkey` NSE scripts
- Optional full TCP sweep (`--full-tcp`)
- Optional common UDP port spot check (`--udp`)
- Structured `open_ports.csv` extracted from gnmap output
- OS detection when running as root

### 📋 Structured Reporting
- `summary.md` — human-readable Markdown report per run
- `findings.csv` — triage worksheet with category, status, detail, evidence
- `open_ports.csv` — structured service table (network mode)
- `raw/` — all raw tool outputs preserved for independent verification
- Full `scopeguard.log` with timestamped entries

---

## Requirements

| Tool | Required | Purpose |
|---|---|---|
| `bash` ≥ 4.2 | ✅ Always | Runtime |
| `curl` | ✅ Web mode | HTTP requests |
| `nmap` | ✅ Network mode | Port scanning + service detection |
| `dig` | Optional | DNS record collection |
| `jq` | Optional | Nuclei severity parsing |
| `testssl.sh` | Optional | TLS/SSL analysis |
| `nuclei` | Optional | Template-based vulnerability triage |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/scopeguard.git
cd scopeguard

# Make the script executable
bash install.sh

# Optional: install system-wide (requires sudo)
sudo bash install.sh --global
```

---

## Quick Start

### Web mode
```bash
# Basic web triage
bash scopeguard.sh web -u https://example.com --authorized

# Deep assessment — skip nothing
bash scopeguard.sh web -u example.com --authorized --profile deep

# Skip TLS and Nuclei for a fast run
bash scopeguard.sh web -u https://example.com --authorized --profile quick --skip-tls --skip-nuclei
```

### Network mode
```bash
# Subnet discovery + service scan
bash scopeguard.sh net -t 192.168.1.0/24 --authorized

# Single host — full TCP + UDP, skip host discovery
bash scopeguard.sh net -t 10.10.10.15 --authorized --full-tcp --udp --pn

# Deep profile with custom output directory
bash scopeguard.sh net -t 10.0.0.0/16 --authorized --profile deep -o /tmp/my-reports
```

---

## Scan Profiles

| Profile | TCP Ports | Version Intensity | Typical Use |
|---|---|---|---|
| `quick` | Top 100 | Standard | Fast triage |
| `standard` *(default)* | Top 1000 | Standard | Typical authorized assessment |
| `deep` | Top 2000 | High | Thorough recon |
| *(+ `--full-tcp`)* | All 65535 | Standard/High | Full coverage |

---

## Output Structure

```
reports/
└── <mode>_<target>_<timestamp>/
    ├── summary.md           ← Human-readable Markdown report
    ├── findings.csv         ← Triage worksheet
    ├── open_ports.csv       ← Structured service table (net mode)
    ├── scopeguard.log       ← Full timestamped run log
    └── raw/                 ← All raw tool outputs
        ├── dns_snapshot.txt
        ├── http_headers_final.txt
        ├── http_meta.txt
        ├── path_probe_results.tsv
        ├── tls_report.txt
        ├── nuclei_findings.jsonl
        ├── nmap_services.{nmap,xml,gnmap}
        └── ...
```

---

## Example Output

See the [`examples/`](examples/) directory for sample reports:

- [`example_web_summary.md`](examples/example_web_summary.md) — sample web assessment report
- [`example_net_summary.md`](examples/example_net_summary.md) — sample network assessment report

For a full flag reference, see [`docs/usage.md`](docs/usage.md).

---

## All Options

```
Usage:
  ./scopeguard.sh web -u <url-or-domain> --authorized [options]
  ./scopeguard.sh net -t <ip-host-or-cidr> --authorized [options]

Required:
  --authorized          Confirms you have explicit permission to assess the target.

Common:
  --profile quick|standard|deep    Scan depth profile. Default: standard
  -o, --output <dir>               Report root directory. Default: reports
  -h, --help                       Show help.

Web options:
  -u, --url <url>       Target URL or domain (https:// assumed if no scheme)
  --skip-nuclei         Skip Nuclei template triage
  --skip-tls            Skip testssl.sh TLS assessment

Network options:
  -t, --target <ip>     Target IP, hostname, or CIDR
  --full-tcp            Scan all 65535 TCP ports
  --udp                 Run common UDP port spot check
  --pn                  Skip host discovery (-Pn)
```

---

## Security & Ethics

- This tool is designed exclusively for **authorized** security assessments.
- Nmap default NSE scripts (`-sC`) are deliberately excluded to avoid intrusive behavior.
- Nuclei is rate-limited to **25 requests/second** by default.
- The `--authorized` flag is not a legal shield — you are responsible for obtaining proper written authorization before running any scan.

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting issues or pull requests.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

---

## License

[MIT](LICENSE) © ScopeGuard Contributors
