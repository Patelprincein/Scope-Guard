# ScopeGuard Security Assessment Report

- **Tool:** ScopeGuard v1.0.0
- **Mode:** net
- **Target:** `192.168.1.0/24`
- **Profile:** standard
- **Started (UTC):** 2026-07-14T09:05:00Z
- **Authorized flag supplied:** yes

> This report is a triage artifact. Findings should be manually validated before being treated as confirmed vulnerabilities.

## Dependency Status

| Tool | Status |
|---|---|
| `curl` | available |
| `nmap` | available |
| `nuclei` | not detected |
| `jq` | available |
| `dig` | available |
| `testssl.sh` | not detected |
| `testssl` | not detected |

## Network Assessment Scope

- **Target:** `192.168.1.0/24`
- **Full TCP requested:** false
- **UDP spot check requested:** true
- **Skip host discovery (-Pn):** false

## Host Discovery

- **Live hosts observed:** 5
- Raw discovery output: `raw/nmap_host_discovery.nmap`, `raw/nmap_host_discovery.xml`, `raw/nmap_host_discovery.gnmap`

## Service Enumeration

Nmap service outputs were saved to:

- `raw/nmap_services.nmap`
- `raw/nmap_services.xml`
- `raw/nmap_services.gnmap`

## UDP Spot Check

A small common-port UDP scan was saved to `raw/nmap_udp_common.*`.

## Open Service Summary

- **Open service entries captured:** 12
- Structured service output: `open_ports.csv`

| Host | Port | Protocol | Service |
|---|---:|---|---|
| `192.168.1.1` | `22` | `tcp` | `ssh` |
| `192.168.1.1` | `80` | `tcp` | `http` |
| `192.168.1.1` | `443` | `tcp` | `https` |
| `192.168.1.10` | `22` | `tcp` | `ssh` |
| `192.168.1.10` | `3306` | `tcp` | `mysql` |
| `192.168.1.20` | `22` | `tcp` | `ssh` |
| `192.168.1.20` | `8080` | `tcp` | `http-proxy` |
| `192.168.1.30` | `21` | `tcp` | `ftp` |
| `192.168.1.30` | `22` | `tcp` | `ssh` |
| `192.168.1.30` | `25` | `tcp` | `smtp` |
| `192.168.1.40` | `3389` | `tcp` | `ms-wbt-server` |
| `192.168.1.1` | `53` | `udp` | `domain` |

## Report Notes

- Files under `raw/` preserve tool output for verification.
- `findings.csv` is a triage worksheet, not a final vulnerability report.
- Manual validation is required before making security claims.
- Ended (UTC): 2026-07-14T09:12:44Z
