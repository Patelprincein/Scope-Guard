#!/usr/bin/env bash
# install.sh — ScopeGuard convenience installer
# Usage:
#   bash install.sh             — makes scopeguard.sh executable in the current directory
#   bash install.sh --global    — also symlinks to /usr/local/bin/scopeguard (requires sudo)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/scopeguard.sh"
GLOBAL_LINK="/usr/local/bin/scopeguard"

if [[ ! -f "$TARGET" ]]; then
  printf "ERROR: scopeguard.sh not found at %s\n" "$TARGET" >&2
  exit 1
fi

chmod +x "$TARGET"
printf "✔ Made %s executable.\n" "$TARGET"

if [[ "${1:-}" == "--global" ]]; then
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    printf "ERROR: --global install requires root. Re-run with sudo.\n" >&2
    exit 1
  fi
  ln -sf "$TARGET" "$GLOBAL_LINK"
  printf "✔ Symlinked to %s. You can now run 'scopeguard' from anywhere.\n" "$GLOBAL_LINK"
else
  printf "Tip: run 'bash install.sh --global' (with sudo) to install system-wide.\n"
fi
