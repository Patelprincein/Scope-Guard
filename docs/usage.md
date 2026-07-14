# ScopeGuard — Detailed Usage Reference

> **IMPORTANT**: Use ScopeGuard only on systems you own or are explicitly authorized to assess. Running unauthorized scans is illegal.

---

## Table of Contents

1. [Invocation Syntax](#invocation-syntax)
2. [Modes](#modes)
3. [Global Flags](#global-flags)
4. [Web Mode Flags](#web-mode-flags)
5. [Network Mode Flags](#network-mode-flags)
6. [Profile Comparison](#profile-comparison)
7. [Output Structure](#output-structure)
8. [Dependency Matrix](#dependency-matrix)
9. [Example Workflows](#example-workflows)

---

## Invocation Syntax

```bash
bash scopeguard.sh <mode> <target-flag> <value> --authorized [options]
```

The `--authorized` flag is **required** on every invocation. It is your explicit acknowledgment that you hold permission to assess the target.

---

## Modes

| Mode | Flag | Description |
|---|---|---|
| `web` | `-u / --url` | Web security triage for a URL or domain |
| `net` | `-t / --target` | Network discovery and service enumeration |

---

## Global Flags

| Flag | Default | Description |
|---|---|---|
| `--authorized` | *(required)* | Confirms authorized access — script will not run without it |
| `--profile quick\|standard\|deep` | `standard` | Controls scan depth (port range, version intensity) |
| `-o / --output <dir>` | `reports` | Root directory where assessment reports are written |
| `-h / --help` | — | Print usage and exit |

---

## Web Mode Flags

| Flag | Description |
|---|---|
| `-u / --url <url-or-domain>` | Web target. If no scheme is provided, `https://` is assumed |
| `--skip-nuclei` | Skip the Nuclei template-based vulnerability triage step |
| `--skip-tls` | Skip the `testssl.sh` TLS assessment step |

### What web mode runs

1. **DNS Snapshot** — A-record, AAAA, MX, NS records via `dig` / `getent`
2. **HTTP Metadata** — effective URL, status code, content type, remote IP, response time, page title
3. **Security Header Triage** — checks for CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
4. **Common Path Triage** — low-noise probes of `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, `/.git/HEAD`, `/.env`, `/phpinfo.php`, `/server-status`, `/backup.zip`
5. **TLS Assessment** — full TLS/SSL analysis via `testssl.sh` (skipped if not installed)
6. **Nuclei Template Triage** — template-based vulnerability triage rate-limited to 25 req/s (skipped if not installed)

---

## Network Mode Flags

| Flag | Description |
|---|---|
| `-t / --target <ip-or-cidr>` | Network target — single IP, hostname, or CIDR range |
| `--full-tcp` | Scan **all 65535 TCP ports** instead of the profile's top-ports range |
| `--udp` | Run a common-port UDP service spot check (top 20 UDP ports) |
| `--pn` | Skip Nmap host discovery (`-Pn`) and scan the target directly |

### What network mode runs

1. **Host Discovery** — `nmap -sn` ping sweep to find live hosts (skipped with `--pn`)
2. **Service Enumeration** — TCP version scan with banner, `http-title`, `ssl-cert`, `ssh-hostkey` NSE scripts
3. **UDP Spot Check** — top-20 UDP ports with version detection (only with `--udp`)
4. **Open Ports CSV** — extracted structured table from gnmap output

> OS detection (`-O`) is added automatically when running as root.

---

## Profile Comparison

| Profile | TCP Ports | Version Intensity | Best For |
|---|---|---|---|
| `quick` | Top 100 | 5 | Fast triage, CI pipelines |
| `standard` *(default)* | Top 1000 | 5 | Typical authorized assessment |
| `deep` | Top 2000 | 7 | Thorough pre-pentest recon |
| *(+ `--full-tcp`)* | All 65535 | 5 or 7 | Full port coverage |

---

## Output Structure

```
reports/
└── <mode>_<target>_<timestamp>/
    ├── summary.md           ← Human-readable Markdown report
    ├── findings.csv         ← Triage worksheet (category, status, detail, evidence)
    ├── open_ports.csv       ← Structured service table (network mode only)
    ├── scopeguard.log       ← Full run log with timestamped entries
    └── raw/
        ├── dns_snapshot.txt
        ├── http_headers_chain.txt
        ├── http_headers_final.txt
        ├── http_meta.txt
        ├── landing_page_body.html
        ├── path_probe_results.tsv
        ├── tls_report.txt
        ├── nuclei_findings.jsonl
        ├── nuclei_findings.txt
        ├── nmap_host_discovery.{nmap,xml,gnmap}
        ├── nmap_services.{nmap,xml,gnmap}
        ├── nmap_udp_common.{nmap,xml,gnmap}
        └── live_hosts.txt
```

All raw files are preserved intact so findings can be verified independently.

---

## Dependency Matrix

| Tool | Required For | Install |
|---|---|---|
| `bash` ≥ 4.2 | Everything | Pre-installed on most Linux/macOS |
| `curl` | Web mode | `apt install curl` / `brew install curl` |
| `nmap` | Network mode | `apt install nmap` / `brew install nmap` |
| `dig` | Web DNS snapshot | `apt install dnsutils` |
| `jq` | Nuclei severity parsing | `apt install jq` / `brew install jq` |
| `testssl.sh` | TLS assessment | [testssl.sh/testssl.sh](https://github.com/drwetter/testssl.sh) |
| `nuclei` | Template triage | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |

`dig`, `jq`, `testssl.sh`, and `nuclei` are **optional** — the tool degrades gracefully when they are absent and notes the gap in the report.

---

## Example Workflows

### Quick web triage
```bash
bash scopeguard.sh web -u https://example.com --authorized --profile quick
```

### Deep web assessment with all tools
```bash
bash scopeguard.sh web -u https://example.com --authorized --profile deep
```

### Network scan of a subnet (standard)
```bash
bash scopeguard.sh net -t 192.168.1.0/24 --authorized
```

### Single host with full TCP + UDP
```bash
bash scopeguard.sh net -t 10.10.10.15 --authorized --full-tcp --udp --pn
```

### Custom output directory
```bash
bash scopeguard.sh web -u example.com --authorized -o /tmp/client-reports
```
