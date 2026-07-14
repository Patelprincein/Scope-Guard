# Changelog

All notable changes to **ScopeGuard** will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026-07-14

### Added
- **Web mode** (`web`): Full HTTP/S triage pipeline including DNS snapshot, HTTP metadata collection, security header analysis, low-noise common path probing, TLS assessment via `testssl.sh`, and template-based vulnerability triage via `nuclei`.
- **Network mode** (`net`): Network discovery and service enumeration pipeline using `nmap` with optional OS detection, full TCP port sweep (`--full-tcp`), UDP spot check (`--udp`), and host discovery bypass (`--pn`).
- Three scan **profiles**: `quick`, `standard`, `deep` controlling port range and version intensity.
- Structured **report output** per assessment run:
  - `summary.md` — human-readable Markdown report
  - `findings.csv` — triage worksheet for further analysis
  - `open_ports.csv` — structured open service table (network mode)
  - `raw/` — all raw tool outputs preserved for verification
- Dependency detection and graceful degradation — scan continues if optional tools (`nuclei`, `testssl.sh`, `dig`, `jq`) are absent.
- Colored, timestamped console logging with full log file mirroring.
- Strict authorization gate (`--authorized` flag required to run any scan).
- Safe filename sanitization for all report paths.
- Signal trapping for clean interrupt handling.
- `install.sh` convenience script for making the tool executable.

### Security Notes
- Designed exclusively for **authorized** assessments. The `--authorized` flag is mandatory.
- Avoids Nmap default NSE scripts to prevent unintentional intrusive behavior.
- Nuclei rate-limited to 25 req/s by default.
