# ScopeGuard Security Assessment Report

- **Tool:** ScopeGuard v1.0.0
- **Mode:** web
- **Target:** `https://example.com`
- **Profile:** standard
- **Started (UTC):** 2026-07-14T09:00:00Z
- **Authorized flag supplied:** yes

> This report is a triage artifact. Findings should be manually validated before being treated as confirmed vulnerabilities.

## Dependency Status

| Tool | Status |
|---|---|
| `curl` | available |
| `nmap` | available |
| `nuclei` | available |
| `jq` | available |
| `dig` | available |
| `testssl.sh` | available |
| `testssl` | not detected |

## Web Assessment Scope

- **Host:** `example.com`
- **Authority:** `example.com`

## DNS Snapshot

DNS details were saved to `raw/dns_snapshot.txt`.

## HTTP Snapshot

| Field | Value |
|---|---|
| Effective URL | `https://example.com/` |
| HTTP status | `200` |
| Content type | `text/html; charset=UTF-8` |
| Remote IP | `93.184.216.34` |
| Response time | `0.432s` |
| Download size | `1256 bytes` |
| Page title | Example Domain |

## Security Header Triage

| Header | Status |
|---|---|
| `Content-Security-Policy` | **missing** |
| `Strict-Transport-Security` | present |
| `X-Frame-Options` | **missing** |
| `X-Content-Type-Options` | **missing** |
| `Referrer-Policy` | **missing** |
| `Permissions-Policy` | **missing** |

Missing headers are **hardening review items**, not automatically confirmed vulnerabilities.

## Common Path Triage

A low-noise review of a few common discovery/exposure paths was saved to `raw/path_probe_results.tsv`.

| Label | Path | Result |
|---|---|---|
| `robots.txt` | `/robots.txt` | `code=200	content_type=text/plain	size=28` |
| `sitemap.xml` | `/sitemap.xml` | `code=404	content_type=text/html	size=315` |
| `security.txt` | `/.well-known/security.txt` | `code=404	content_type=text/html	size=315` |
| `.git/HEAD` | `/.git/HEAD` | `code=404	content_type=text/html	size=315` |
| `.env` | `/.env` | `code=404	content_type=text/html	size=315` |
| `phpinfo.php` | `/phpinfo.php` | `code=404	content_type=text/html	size=315` |
| `server-status` | `/server-status` | `code=403	content_type=text/html	size=199` |
| `backup.zip` | `/backup.zip` | `code=404	content_type=text/html	size=315` |

## TLS Assessment

TLS results were saved to `raw/tls_report.txt`.

## Nuclei Template Triage

| Severity | Count |
|---|---:|
| info | 3 |
| low | 1 |
| medium | 0 |
| high | 0 |
| critical | 0 |
| unknown | 0 |

Nuclei output is a **triage signal** and should be manually validated before reporting.

## Report Notes

- Files under `raw/` preserve tool output for verification.
- `findings.csv` is a triage worksheet, not a final vulnerability report.
- Manual validation is required before making security claims.
- Ended (UTC): 2026-07-14T09:02:17Z
