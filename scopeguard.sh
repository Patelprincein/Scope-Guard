#!/usr/bin/env bash
#
# ScopeGuard
# Bash-based authorized web + network security assessment framework.
#
# Purpose:
#   - Web security triage for URLs/domains
#   - Network discovery and service enumeration for IPs/CIDRs
#   - Structured report generation for resume-ready security projects
#
# IMPORTANT:
#   Use this tool only on systems you own or are explicitly authorized to assess.
#

set -Eeuo pipefail
IFS=$'\n\t'

VERSION="1.0.0"
TOOL_NAME="ScopeGuard"

MODE=""
TARGET=""
PROFILE="standard"
AUTHORIZED="true"
OUTPUT_ROOT="reports"

FULL_TCP="true"
UDP_SCAN="true"
FORCE_PN="true"
SKIP_NUCLEI="false"
SKIP_TLS="false"

USER_AGENT="ScopeGuard/1.0 Authorized-Security-Assessment"
TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"

REPORT_DIR=""
RAW_DIR=""
LOG_FILE=""
SUMMARY_MD=""
FINDINGS_CSV=""
OPEN_PORTS_CSV=""

NUCLEI_RATE_LIMIT=25

# -----------------------------
# Terminal colors
# -----------------------------
if [[ -t 1 ]]; then
  RED=$'\033[0;31m'
  GREEN=$'\033[0;32m'
  YELLOW=$'\033[1;33m'
  BLUE=$'\033[0;34m'
  BOLD=$'\033[1m'
  RESET=$'\033[0m'
else
  RED=""
  GREEN=""
  YELLOW=""
  BLUE=""
  BOLD=""
  RESET=""
fi

# -----------------------------
# Logging helpers
# -----------------------------
timestamp() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

print_banner() {
  cat <<EOF
${BOLD}${BLUE}
   _____                          ______                     __
  / ___/_________  ____  ___     / ____/_  ______ __________/ /
  \__ \/ ___/ __ \/ __ \/ _ \   / / __/ / / / __ \`/ ___/ __  /
 ___/ / /__/ /_/ / /_/ /  __/  / /_/ / /_/ / /_/ / /  / /_/ /
/____/\___/\____/ .___/\___/   \____/\__,_/\__,_/_/   \__,_/
               /_/
${RESET}
${BOLD}${TOOL_NAME} v${VERSION}${RESET}
Authorized Web + Network Security Assessment Framework
EOF
}

log_line() {
  local level="$1"
  shift
  local message="$*"
  local line
  line="[$(timestamp)] [$level] $message"

  case "$level" in
    INFO) printf "%s%s%s\n" "$BLUE" "$line" "$RESET" ;;
    OK)   printf "%s%s%s\n" "$GREEN" "$line" "$RESET" ;;
    WARN) printf "%s%s%s\n" "$YELLOW" "$line" "$RESET" ;;
    ERROR) printf "%s%s%s\n" "$RED" "$line" "$RESET" ;;
    *) printf "%s\n" "$line" ;;
  esac

  if [[ -n "${LOG_FILE:-}" ]]; then
    printf "%s\n" "$line" >> "$LOG_FILE"
  fi
}

info() { log_line "INFO" "$*"; }
ok() { log_line "OK" "$*"; }
warn() { log_line "WARN" "$*"; }
error() { log_line "ERROR" "$*"; }

die() {
  error "$*"
  exit 1
}

on_interrupt() {
  warn "Interrupted by user. Partial artifacts remain in: ${REPORT_DIR:-not-created}"
  exit 130
}

on_error() {
  local exit_code=$?
  error "Unexpected error near line ${BASH_LINENO[0]:-unknown}. Exit code: $exit_code"
  exit "$exit_code"
}

trap on_interrupt INT TERM
trap on_error ERR

# -----------------------------
# Usage
# -----------------------------
usage() {
  cat <<'EOF'
Usage:
  ./scopeguard.sh web -u <url-or-domain> --authorized [options]
  ./scopeguard.sh net -t <ip-host-or-cidr> --authorized [options]

Modes:
  web     Web security triage for a URL or domain
  net     Network discovery and service enumeration

Required authorization:
  --authorized
      Confirms you have permission to assess the target.

Common options:
  --profile quick|standard|deep
      Scan depth profile. Default: standard

  -o, --output <directory>
      Root report directory. Default: reports

  -h, --help
      Show this help.

Web options:
  -u, --url <url-or-domain>
      Web target. If no scheme is supplied, https:// is assumed.

  --skip-nuclei
      Skip Nuclei template-based vulnerability triage.

  --skip-tls
      Skip testssl.sh TLS assessment.

Network options:
  -t, --target <ip-host-or-cidr>
      Network target.

  --full-tcp
      Scan all TCP ports instead of top ports. Use carefully.

  --udp
      Run a small UDP service check against common UDP ports.

  --pn
      Skip host discovery and scan specified target(s) directly with Nmap -Pn.

Examples:
  ./scopeguard.sh web -u https://example.com --authorized
  ./scopeguard.sh web -u example.com --authorized --profile deep
  ./scopeguard.sh net -t 192.168.1.0/24 --authorized --profile standard
  ./scopeguard.sh net -t 10.10.10.15 --authorized --full-tcp --udp

Output:
  reports/<mode>_<target>_<timestamp>/
    summary.md
    findings.csv
    open_ports.csv        (network mode)
    raw/
      tool-specific outputs and logs
EOF
}

# -----------------------------
# CLI parsing
# -----------------------------
parse_args() {
  if [[ $# -lt 1 ]]; then
    usage
    exit 1
  fi

  MODE="$1"
  shift

  case "$MODE" in
    web|net) ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown mode: $MODE"
      ;;
  esac

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -u|--url)
        [[ $# -ge 2 ]] || die "Missing value for $1"
        TARGET="$2"
        shift 2
        ;;
      -t|--target)
        [[ $# -ge 2 ]] || die "Missing value for $1"
        TARGET="$2"
        shift 2
        ;;
      --authorized)
        AUTHORIZED="true"
        shift
        ;;
      --profile)
        [[ $# -ge 2 ]] || die "Missing value for --profile"
        PROFILE="$2"
        shift 2
        ;;
      -o|--output)
        [[ $# -ge 2 ]] || die "Missing value for $1"
        OUTPUT_ROOT="$2"
        shift 2
        ;;
      --full-tcp)
        FULL_TCP="true"
        shift
        ;;
      --udp)
        UDP_SCAN="true"
        shift
        ;;
      --pn)
        FORCE_PN="true"
        shift
        ;;
      --skip-nuclei)
        SKIP_NUCLEI="true"
        shift
        ;;
      --skip-tls)
        SKIP_TLS="true"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown option: $1"
        ;;
    esac
  done
}

validate_args() {
  [[ "$AUTHORIZED" == "true" ]] || die "Refusing to run without --authorized. Use only on systems you own or are explicitly permitted to assess."
  [[ -n "$TARGET" ]] || die "No target provided."

  case "$PROFILE" in
    quick|standard|deep) ;;
    *) die "Invalid profile: $PROFILE. Use quick, standard, or deep." ;;
  esac

  if [[ "$MODE" == "web" ]]; then
    if [[ "$TARGET" != http://* && "$TARGET" != https://* ]]; then
      TARGET="https://${TARGET}"
    fi
  fi
}

# -----------------------------
# Generic helpers
# -----------------------------
sanitize_filename() {
  printf "%s" "$1" | sed -E 's#^https?://##; s#[/:?&=]+#_#g; s#[^A-Za-z0-9._-]#_#g; s#_+#_#g; s#^_##; s#_$##'
}

init_report_dir() {
  local safe_target
  safe_target="$(sanitize_filename "$TARGET")"
  [[ -n "$safe_target" ]] || safe_target="target"

  REPORT_DIR="${OUTPUT_ROOT}/${MODE}_${safe_target}_${TIMESTAMP}"
  RAW_DIR="${REPORT_DIR}/raw"
  LOG_FILE="${REPORT_DIR}/scopeguard.log"
  SUMMARY_MD="${REPORT_DIR}/summary.md"
  FINDINGS_CSV="${REPORT_DIR}/findings.csv"
  OPEN_PORTS_CSV="${REPORT_DIR}/open_ports.csv"

  mkdir -p "$RAW_DIR"
  : > "$LOG_FILE"
  printf 'category,status,detail,evidence\n' > "$FINDINGS_CSV"

  cat > "$SUMMARY_MD" <<EOF
# ScopeGuard Security Assessment Report

- **Tool:** ${TOOL_NAME} v${VERSION}
- **Mode:** ${MODE}
- **Target:** \`${TARGET}\`
- **Profile:** ${PROFILE}
- **Started (UTC):** $(timestamp)
- **Authorized flag supplied:** yes

> This report is a triage artifact. Findings should be manually validated before being treated as confirmed vulnerabilities.

EOF

  ok "Report directory created: $REPORT_DIR"
}

md() {
  printf "%s\n" "$*" >> "$SUMMARY_MD"
}

csv_escape() {
  local value="${1:-}"
  value="${value//\"/\"\"}"
  printf '"%s"' "$value"
}

add_finding() {
  local category="$1"
  local status="$2"
  local detail="$3"
  local evidence="$4"

  {
    csv_escape "$category"
    printf ","
    csv_escape "$status"
    printf ","
    csv_escape "$detail"
    printf ","
    csv_escape "$evidence"
    printf "\n"
  } >> "$FINDINGS_CSV"
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

first_available_command() {
  local candidate
  for candidate in "$@"; do
    if command_exists "$candidate"; then
      command -v "$candidate"
      return 0
    fi
  done
  return 1
}

record_dependency_status() {
  md "## Dependency Status"
  md ""
  md "| Tool | Status |"
  md "|---|---|"

  local tool
  for tool in curl nmap nuclei jq dig testssl.sh testssl; do
    if command_exists "$tool"; then
      md "| \`${tool}\` | available |"
    else
      md "| \`${tool}\` | not detected |"
    fi
  done

  md ""
}

require_core_dependencies() {
  command_exists awk || die "Missing dependency: awk"
  command_exists sed || die "Missing dependency: sed"
  command_exists grep || die "Missing dependency: grep"
  command_exists date || die "Missing dependency: date"

  if [[ "$MODE" == "web" ]]; then
    command_exists curl || die "Missing dependency for web mode: curl"
  fi

  if [[ "$MODE" == "net" ]]; then
    command_exists nmap || die "Missing dependency for network mode: nmap"
  fi
}

extract_url_authority() {
  printf "%s" "$1" | sed -E 's#^[a-zA-Z]+://##; s#/.*$##'
}

extract_url_host() {
  printf "%s" "$1" | sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s#^([^@]+@)##; s#:[0-9]+$##'
}

meta_value() {
  local key="$1"
  local file="$2"
  grep -E "^${key}=" "$file" | tail -n 1 | cut -d'=' -f2- || true
}

is_https_url() {
  [[ "$1" == https://* ]]
}

# -----------------------------
# Web mode
# -----------------------------
web_dns_snapshot() {
  local host="$1"
  local out="${RAW_DIR}/dns_snapshot.txt"

  info "Collecting DNS snapshot for ${host}"

  {
    echo "# DNS snapshot for ${host}"
    echo
    echo "## getent hosts"
    getent hosts "$host" 2>/dev/null || true
    echo

    if command_exists dig; then
      echo "## A records"
      dig +short A "$host" 2>/dev/null || true
      echo
      echo "## AAAA records"
      dig +short AAAA "$host" 2>/dev/null || true
      echo
      echo "## MX records"
      dig +short MX "$host" 2>/dev/null || true
      echo
      echo "## NS records"
      dig +short NS "$host" 2>/dev/null || true
    else
      echo "dig not available; only getent output captured."
    fi
  } > "$out"

  md "## DNS Snapshot"
  md ""
  md "DNS details were saved to \`raw/dns_snapshot.txt\`."
  md ""
}

web_http_snapshot() {
  local url="$1"
  local headers="${RAW_DIR}/http_headers_chain.txt"
  local final_headers="${RAW_DIR}/http_headers_final.txt"
  local body="${RAW_DIR}/landing_page_body.html"
  local meta="${RAW_DIR}/http_meta.txt"

  info "Collecting HTTP metadata for ${url}"

  curl -ksSL \
    --max-time 25 \
    -A "$USER_AGENT" \
    -D "$headers" \
    -o "$body" \
    -w 'effective_url=%{url_effective}\nhttp_code=%{http_code}\ncontent_type=%{content_type}\nremote_ip=%{remote_ip}\ntime_total=%{time_total}\nsize_download=%{size_download}\n' \
    "$url" > "$meta" || warn "HTTP metadata request returned a non-zero exit status."

  awk '
    /^HTTP\// { block = $0 ORS; next }
    { block = block $0 ORS }
    END { printf "%s", block }
  ' "$headers" > "$final_headers" 2>/dev/null || true

  local effective_url http_code content_type remote_ip time_total size_download title
  effective_url="$(meta_value "effective_url" "$meta")"
  http_code="$(meta_value "http_code" "$meta")"
  content_type="$(meta_value "content_type" "$meta")"
  remote_ip="$(meta_value "remote_ip" "$meta")"
  time_total="$(meta_value "time_total" "$meta")"
  size_download="$(meta_value "size_download" "$meta")"
  title="$(grep -ioE '<title[^>]*>[^<]+' "$body" 2>/dev/null | head -n 1 | sed -E 's/<title[^>]*>//I' || true)"

  md "## HTTP Snapshot"
  md ""
  md "| Field | Value |"
  md "|---|---|"
  md "| Effective URL | \`${effective_url:-unknown}\` |"
  md "| HTTP status | \`${http_code:-unknown}\` |"
  md "| Content type | \`${content_type:-unknown}\` |"
  md "| Remote IP | \`${remote_ip:-unknown}\` |"
  md "| Response time | \`${time_total:-unknown}s\` |"
  md "| Download size | \`${size_download:-unknown} bytes\` |"
  md "| Page title | ${title:-not detected} |"
  md ""

  add_finding "HTTP Metadata" "Observed" "Status ${http_code:-unknown}; content type ${content_type:-unknown}" "raw/http_meta.txt"

  if [[ -n "${http_code:-}" && "$http_code" =~ ^[45] ]]; then
    add_finding "HTTP Reachability" "Review" "Target returned HTTP ${http_code}" "raw/http_meta.txt"
  fi
}

header_present() {
  local header_name="$1"
  local file="$2"
  grep -qiE "^${header_name}:" "$file"
}

web_security_headers() {
  local final_headers="${RAW_DIR}/http_headers_final.txt"

  info "Checking common web security headers"

  md "## Security Header Triage"
  md ""
  md "| Header | Status |"
  md "|---|---|"

  local header status
  local -a headers=(
    "Content-Security-Policy"
    "Strict-Transport-Security"
    "X-Frame-Options"
    "X-Content-Type-Options"
    "Referrer-Policy"
    "Permissions-Policy"
  )

  for header in "${headers[@]}"; do
    if header_present "$header" "$final_headers"; then
      status="present"
      md "| \`${header}\` | present |"
      add_finding "Security Header" "Present" "$header detected" "raw/http_headers_final.txt"
    else
      status="missing"
      md "| \`${header}\` | **missing** |"
      add_finding "Security Header" "Review" "$header not observed in final response headers" "raw/http_headers_final.txt"
    fi
  done

  md ""
  md "Missing headers are **hardening review items**, not automatically confirmed vulnerabilities."
  md ""
}

web_path_probe() {
  local base_url="$1"
  local path="$2"
  local label="$3"
  local output_file="${RAW_DIR}/path_probe_results.tsv"

  local result
  result="$(curl -ksSL \
    --max-time 15 \
    -A "$USER_AGENT" \
    -o /dev/null \
    -w "code=%{http_code}\tcontent_type=%{content_type}\tsize=%{size_download}" \
    "${base_url%/}${path}" 2>/dev/null || true)"

  printf "%s\t%s\t%s\n" "$label" "$path" "$result" >> "$output_file"

  local code
  code="$(printf "%s" "$result" | sed -nE 's/.*code=([0-9]{3}).*/\1/p')"

  case "$label" in
    "robots.txt"|"sitemap.xml"|"security.txt")
      if [[ "$code" == "200" || "$code" == "206" ]]; then
        add_finding "Discovery Artifact" "Observed" "${label} available" "${path} returned ${code}"
      fi
      ;;
    *)
      if [[ "$code" == "200" || "$code" == "206" ]]; then
        add_finding "Exposure Candidate" "Review" "${label} returned ${code}; manually validate whether sensitive data is exposed" "${path}"
      elif [[ "$code" == "401" || "$code" == "403" ]]; then
        add_finding "Exposure Candidate" "Guarded/Review" "${label} appears restricted with HTTP ${code}" "${path}"
      fi
      ;;
  esac
}

web_common_path_triage() {
  local base_url="$1"
  local output_file="${RAW_DIR}/path_probe_results.tsv"

  info "Running low-noise common path triage"

  printf "label\tpath\tresult\n" > "$output_file"

  web_path_probe "$base_url" "/robots.txt" "robots.txt"
  web_path_probe "$base_url" "/sitemap.xml" "sitemap.xml"
  web_path_probe "$base_url" "/.well-known/security.txt" "security.txt"
  web_path_probe "$base_url" "/.git/HEAD" ".git/HEAD"
  web_path_probe "$base_url" "/.env" ".env"
  web_path_probe "$base_url" "/phpinfo.php" "phpinfo.php"
  web_path_probe "$base_url" "/server-status" "server-status"
  web_path_probe "$base_url" "/backup.zip" "backup.zip"

  md "## Common Path Triage"
  md ""
  md "A low-noise review of a few common discovery/exposure paths was saved to \`raw/path_probe_results.tsv\`."
  md ""
  md "| Label | Path | Result |"
  md "|---|---|---|"

  tail -n +2 "$output_file" | while IFS=$'\t' read -r label path result; do
    md "| \`${label}\` | \`${path}\` | \`${result}\` |"
  done

  md ""
}

web_tls_scan() {
  local url="$1"

  if [[ "$SKIP_TLS" == "true" ]]; then
    warn "TLS scan skipped by user."
    md "## TLS Assessment"
    md ""
    md "Skipped with \`--skip-tls\`."
    md ""
    return
  fi

  if ! is_https_url "$url"; then
    warn "TLS scan skipped because effective URL is not HTTPS."
    md "## TLS Assessment"
    md ""
    md "Skipped because the target URL is not HTTPS."
    md ""
    return
  fi

  local tls_tool
  if ! tls_tool="$(first_available_command testssl.sh testssl)"; then
    warn "testssl.sh/testssl not detected. TLS scan skipped."
    md "## TLS Assessment"
    md ""
    md "Skipped because \`testssl.sh\` was not detected in PATH."
    md ""
    add_finding "TLS Assessment" "Skipped" "testssl.sh not detected" "Install testssl.sh to enable TLS analysis."
    return
  fi

  info "Running TLS assessment with ${tls_tool}"
  local tls_out="${RAW_DIR}/tls_report.txt"

  "$tls_tool" --quiet "$url" > "$tls_out" 2>>"$LOG_FILE" || warn "TLS assessment exited non-zero; review raw output."

  md "## TLS Assessment"
  md ""
  md "TLS results were saved to \`raw/tls_report.txt\`."
  md ""
  add_finding "TLS Assessment" "Completed" "TLS output captured with testssl.sh/testssl" "raw/tls_report.txt"
}

summarize_nuclei_findings() {
  local jsonl="$1"

  md "## Nuclei Template Triage"
  md ""

  if [[ ! -s "$jsonl" ]]; then
    md "No Nuclei findings were written to the JSONL result file."
    md ""
    add_finding "Nuclei" "No Output" "No JSONL findings recorded" "raw/nuclei_findings.jsonl"
    return
  fi

  local info_count=0 low_count=0 medium_count=0 high_count=0 critical_count=0 unknown_count=0

  if command_exists jq; then
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      local severity
      severity="$(printf "%s" "$line" | jq -r '.info.severity // .severity // "unknown"' 2>/dev/null || printf "unknown")"
      case "$severity" in
        info) ((info_count++)) || true ;;
        low) ((low_count++)) || true ;;
        medium) ((medium_count++)) || true ;;
        high) ((high_count++)) || true ;;
        critical) ((critical_count++)) || true ;;
        *) ((unknown_count++)) || true ;;
      esac
    done < "$jsonl"
  else
    info_count="$(grep -ciE '"severity"[[:space:]]*:[[:space:]]*"info"' "$jsonl" || true)"
    low_count="$(grep -ciE '"severity"[[:space:]]*:[[:space:]]*"low"' "$jsonl" || true)"
    medium_count="$(grep -ciE '"severity"[[:space:]]*:[[:space:]]*"medium"' "$jsonl" || true)"
    high_count="$(grep -ciE '"severity"[[:space:]]*:[[:space:]]*"high"' "$jsonl" || true)"
    critical_count="$(grep -ciE '"severity"[[:space:]]*:[[:space:]]*"critical"' "$jsonl" || true)"
    unknown_count=0
  fi

  md "| Severity | Count |"
  md "|---|---:|"
  md "| info | ${info_count} |"
  md "| low | ${low_count} |"
  md "| medium | ${medium_count} |"
  md "| high | ${high_count} |"
  md "| critical | ${critical_count} |"
  md "| unknown | ${unknown_count} |"
  md ""
  md "Nuclei output is a **triage signal** and should be manually validated before reporting."
  md ""

  add_finding "Nuclei Summary" "Completed" "info=${info_count}, low=${low_count}, medium=${medium_count}, high=${high_count}, critical=${critical_count}, unknown=${unknown_count}" "raw/nuclei_findings.jsonl"
}

web_nuclei_scan() {
  local url="$1"

  if [[ "$SKIP_NUCLEI" == "true" ]]; then
    warn "Nuclei scan skipped by user."
    md "## Nuclei Template Triage"
    md ""
    md "Skipped with \`--skip-nuclei\`."
    md ""
    return
  fi

  if ! command_exists nuclei; then
    warn "nuclei not detected. Template triage skipped."
    md "## Nuclei Template Triage"
    md ""
    md "Skipped because \`nuclei\` was not detected in PATH."
    md ""
    add_finding "Nuclei" "Skipped" "nuclei not detected" "Install Nuclei to enable template-based triage."
    return
  fi

  local jsonl="${RAW_DIR}/nuclei_findings.jsonl"
  local plain="${RAW_DIR}/nuclei_findings.txt"

  info "Running Nuclei with conservative rate limiting"
  nuclei \
    -u "$url" \
    -severity info,low,medium,high,critical \
    -rl "$NUCLEI_RATE_LIMIT" \
    -timeout 10 \
    -retries 1 \
    -nc \
    -o "$plain" \
    -jle "$jsonl" >> "$LOG_FILE" 2>&1 || warn "Nuclei exited non-zero; review raw output."

  summarize_nuclei_findings "$jsonl"
}

run_web_mode() {
  local host authority effective_url
  host="$(extract_url_host "$TARGET")"
  authority="$(extract_url_authority "$TARGET")"

  [[ -n "$host" ]] || die "Unable to extract host from URL: $TARGET"

  md "## Web Assessment Scope"
  md ""
  md "- **Host:** \`${host}\`"
  md "- **Authority:** \`${authority}\`"
  md ""

  web_dns_snapshot "$host"
  web_http_snapshot "$TARGET"

  effective_url="$(meta_value "effective_url" "${RAW_DIR}/http_meta.txt")"
  [[ -n "$effective_url" ]] || effective_url="$TARGET"

  web_security_headers
  web_common_path_triage "$effective_url"
  web_tls_scan "$effective_url"
  web_nuclei_scan "$effective_url"
}

# -----------------------------
# Network mode
# -----------------------------
count_lines() {
  local file="$1"
  if [[ -f "$file" ]]; then
    wc -l < "$file" | tr -d ' '
  else
    printf "0"
  fi
}

network_host_discovery() {
  local target="$1"
  local discovery_base="${RAW_DIR}/nmap_host_discovery"
  local live_hosts="${RAW_DIR}/live_hosts.txt"

  if [[ "$FORCE_PN" == "true" ]]; then
    warn "Skipping host discovery due to --pn."
    printf "%s\n" "$target" > "$live_hosts"
    md "## Host Discovery"
    md ""
    md "Skipped with \`--pn\`. The specified target is passed directly to service scanning."
    md ""
    return
  fi

  info "Running Nmap host discovery"

  nmap -sn "$target" -oA "$discovery_base" >> "$LOG_FILE" 2>&1 || warn "Host discovery returned non-zero; review Nmap outputs."

  grep -h "Status: Up" "${discovery_base}.gnmap" 2>/dev/null | awk '{print $2}' | sort -u > "$live_hosts" || true

  local live_count
  live_count="$(count_lines "$live_hosts")"

  md "## Host Discovery"
  md ""
  md "- **Live hosts observed:** ${live_count}"
  md "- Raw discovery output: \`raw/nmap_host_discovery.nmap\`, \`raw/nmap_host_discovery.xml\`, \`raw/nmap_host_discovery.gnmap\`"
  md ""

  add_finding "Host Discovery" "Completed" "${live_count} live host(s) observed" "raw/live_hosts.txt"
}

nmap_port_args() {
  if [[ "$FULL_TCP" == "true" ]]; then
    printf "%s\n" "-p-"
    return
  fi

  case "$PROFILE" in
    quick) printf "%s\n" "--top-ports" "100" ;;
    standard) printf "%s\n" "--top-ports" "1000" ;;
    deep) printf "%s\n" "--top-ports" "2000" ;;
  esac
}

network_service_scan() {
  local live_hosts="${RAW_DIR}/live_hosts.txt"
  local service_base="${RAW_DIR}/nmap_services"

  if [[ ! -s "$live_hosts" ]]; then
    warn "No live hosts available for service scan. Use --pn if host discovery is blocked and you are authorized to continue."
    md "## Service Enumeration"
    md ""
    md "Skipped because no live hosts were discovered."
    md ""
    add_finding "Service Enumeration" "Skipped" "No live hosts discovered" "raw/live_hosts.txt"
    return
  fi

  local -a port_args service_args script_args os_args target_args
  mapfile -t port_args < <(nmap_port_args)

  if [[ "$PROFILE" == "deep" ]]; then
    service_args=(-sV --version-intensity 7 --open --reason)
  else
    service_args=(-sV --version-intensity 5 --open --reason)
  fi

  # Deliberately avoid -sC/default NSE because default scripts can include intrusive behavior.
  script_args=(--script banner,http-title,ssl-cert,ssh-hostkey)

  os_args=()
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    os_args=(-O)
  else
    warn "Not running as root; OS detection (-O) will not be added."
  fi

  if [[ "$FORCE_PN" == "true" ]]; then
    target_args=(-Pn "$TARGET")
  else
    target_args=(-iL "$live_hosts")
  fi

  info "Running Nmap service enumeration"

  nmap \
    -T3 \
    "${port_args[@]}" \
    "${service_args[@]}" \
    "${script_args[@]}" \
    "${os_args[@]}" \
    -oA "$service_base" \
    "${target_args[@]}" >> "$LOG_FILE" 2>&1 || warn "Service enumeration returned non-zero; review Nmap outputs."

  md "## Service Enumeration"
  md ""
  md "Nmap service outputs were saved to:"
  md ""
  md "- \`raw/nmap_services.nmap\`"
  md "- \`raw/nmap_services.xml\`"
  md "- \`raw/nmap_services.gnmap\`"
  md ""

  add_finding "Service Enumeration" "Completed" "Nmap service scan completed" "raw/nmap_services.nmap"
}

network_udp_scan() {
  if [[ "$UDP_SCAN" != "true" ]]; then
    return
  fi

  local live_hosts="${RAW_DIR}/live_hosts.txt"
  local udp_base="${RAW_DIR}/nmap_udp_common"

  if [[ ! -s "$live_hosts" && "$FORCE_PN" != "true" ]]; then
    warn "UDP scan skipped because no live hosts were discovered."
    add_finding "UDP Enumeration" "Skipped" "No live hosts discovered" "raw/live_hosts.txt"
    return
  fi

  local -a target_args
  if [[ "$FORCE_PN" == "true" ]]; then
    target_args=(-Pn "$TARGET")
  else
    target_args=(-iL "$live_hosts")
  fi

  info "Running small UDP service check against common UDP ports"

  nmap \
    -sU \
    --top-ports 20 \
    --open \
    -sV \
    -T3 \
    --reason \
    -oA "$udp_base" \
    "${target_args[@]}" >> "$LOG_FILE" 2>&1 || warn "UDP scan returned non-zero; review Nmap outputs."

  md "## UDP Spot Check"
  md ""
  md "A small common-port UDP scan was saved to \`raw/nmap_udp_common.*\`."
  md ""

  add_finding "UDP Enumeration" "Completed" "Common UDP service check completed" "raw/nmap_udp_common.nmap"
}

generate_open_ports_csv() {
  local gnmap="${RAW_DIR}/nmap_services.gnmap"

  printf 'host,port,protocol,service\n' > "$OPEN_PORTS_CSV"

  if [[ ! -f "$gnmap" ]]; then
    return
  fi

  while IFS= read -r line; do
    local host ports_blob
    host="$(printf "%s" "$line" | awk '{print $2}')"
    ports_blob="$(printf "%s" "$line" | sed -nE 's/.*Ports: (.*)/\1/p')"

    [[ -n "$ports_blob" ]] || continue

    IFS=',' read -r -a port_entries <<< "$ports_blob"
    local entry
    for entry in "${port_entries[@]}"; do
      entry="$(printf "%s" "$entry" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"

      local port state proto service
      port="$(printf "%s" "$entry" | cut -d'/' -f1)"
      state="$(printf "%s" "$entry" | cut -d'/' -f2)"
      proto="$(printf "%s" "$entry" | cut -d'/' -f3)"
      service="$(printf "%s" "$entry" | cut -d'/' -f5)"

      if [[ "$state" == "open" ]]; then
        {
          csv_escape "$host"; printf ","
          csv_escape "$port"; printf ","
          csv_escape "$proto"; printf ","
          csv_escape "$service"; printf "\n"
        } >> "$OPEN_PORTS_CSV"

        add_finding "Open Service" "Observed" "${host}:${port}/${proto} ${service}" "raw/nmap_services.gnmap"
      fi
    done
  done < <(grep -h "Ports:" "$gnmap" 2>/dev/null || true)
}

network_summary_table() {
  generate_open_ports_csv

  local open_count
  open_count="$(( $(count_lines "$OPEN_PORTS_CSV") > 0 ? $(count_lines "$OPEN_PORTS_CSV") - 1 : 0 ))"

  md "## Open Service Summary"
  md ""
  md "- **Open service entries captured:** ${open_count}"
  md "- Structured service output: \`open_ports.csv\`"
  md ""

  if [[ "$open_count" -gt 0 ]]; then
    md "| Host | Port | Protocol | Service |"
    md "|---|---:|---|---|"

    tail -n +2 "$OPEN_PORTS_CSV" | head -n 50 | while IFS=',' read -r host port proto service; do
      host="${host%\"}"; host="${host#\"}"
      port="${port%\"}"; port="${port#\"}"
      proto="${proto%\"}"; proto="${proto#\"}"
      service="${service%\"}"; service="${service#\"}"
      md "| \`${host}\` | \`${port}\` | \`${proto}\` | \`${service}\` |"
    done

    md ""
    if [[ "$open_count" -gt 50 ]]; then
      md "Only the first 50 open service entries are shown here. Review \`open_ports.csv\` for the full list."
      md ""
    fi
  fi
}

run_network_mode() {
  md "## Network Assessment Scope"
  md ""
  md "- **Target:** \`${TARGET}\`"
  md "- **Full TCP requested:** ${FULL_TCP}"
  md "- **UDP spot check requested:** ${UDP_SCAN}"
  md "- **Skip host discovery (-Pn):** ${FORCE_PN}"
  md ""

  network_host_discovery "$TARGET"
  network_service_scan
  network_udp_scan
  network_summary_table
}

# -----------------------------
# Final report footer
# -----------------------------
finalize_report() {
  md "## Report Notes"
  md ""
  md "- Files under \`raw/\` preserve tool output for verification."
  md "- \`findings.csv\` is a triage worksheet, not a final vulnerability report."
  md "- Manual validation is required before making security claims."
  md "- Ended (UTC): $(timestamp)"
  md ""

  ok "Assessment complete."
  ok "Summary report: ${SUMMARY_MD}"
  ok "Findings CSV: ${FINDINGS_CSV}"
}

main() {
  print_banner
  parse_args "$@"
  validate_args
  init_report_dir
  require_core_dependencies
  record_dependency_status

  case "$MODE" in
    web) run_web_mode ;;
    net) run_network_mode ;;
  esac

  finalize_report
}

main "$@"
