#!/usr/bin/env bash
#
# setup.sh - one-shot installer for dnshub.
#
#   bash setup.sh           full install: prereq check -> install -> start -> summary
#   bash setup.sh --check   only verify this box can host dnshub
#   bash setup.sh --clean   remove caches/scratch, keep your config and lists
#
# Requirements: Debian/Ubuntu, systemd, python3 (>= 3.9), openssl, sudo.
# Everything else dnshub needs lives in src/ - no packages to install for the
# core. If your box is NOT on 192.168.1.x, set DNSHUB_LAN_IP so the internal
# names and the CA follow your real subnet. For unattended/remote installs
# (ssh session, CI) export DNSHUB_SUDO_PW so setup.sh can sudo without a tty.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/src"
DN="$SRC/dnshub"

say() { printf '\n\033[1;34m::\033[0m %s\n' "$*"; }
ok()  { printf '  \033[1;32mok\033[0m   %s\n' "$*"; }
warn(){ printf '  \033[1;33m!!\033[0m   %s\n' "$*"; }
bad() { printf '  \033[1;31mXX\033[0m   %s\n' "$*"; }

LAN_IP="${DNSHUB_LAN_IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}"

# sudo wrapper: on a normal terminal it prompts; with DNSHUB_SUDO_PW set it is
# fully non-interactive (ssh sessions, CI, Ansible-style runs).
run_sudo() {
  if [ -n "${DNSHUB_SUDO_PW:-}" ]; then
    echo "$DNSHUB_SUDO_PW" | sudo -S -p '' "$@" 2>/dev/null
  else
    sudo "$@"
  fi
}

check() {
  local fails=0
  say "checking this box can host dnshub"
  [ -x "$DN" ] || { bad "missing $DN - keep the whole folder together"; fails=1; }
  [ -f "$SRC/dns-server.py" ] || { bad "missing $SRC/dns-server.py"; fails=1; }
  for c in python3 openssl curl; do
    command -v "$c" >/dev/null 2>&1 || { bad "$c not found"; fails=1; }
  done
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
    || { bad "python3 is too old (need >= 3.9)"; fails=1; }
  if command -v systemctl >/dev/null 2>&1; then
    [ "$(ps -p 1 -o comm= 2>/dev/null)" = "systemd" ] || warn "PID 1 is not systemd - units will not work"
  else
    bad "systemd not found (systemctl)"; fails=1
  fi
  command -v dig >/dev/null 2>&1 || warn "dig missing (apt install dnsutils) - 'dnshub dns' needs it"
  if [ "$(id -u)" -eq 0 ]; then
    ok "running as root"
  else
    command -v sudo >/dev/null 2>&1 || { bad "sudo not found"; fails=1; }
    if sudo -n true 2>/dev/null; then ok "passwordless sudo"; else warn "you will be asked for your sudo password"; fi
  fi
  if [ -n "$LAN_IP" ]; then ok "LAN IP detected: $LAN_IP"; else warn "no LAN IP yet - configure networking first"; fi
  if command -v docker >/dev/null 2>&1; then
    warn "docker found: dnshub-unbound is optional; the core runs without docker"
  fi
  if [ "$fails" -ne 0 ]; then bad "fix the problems above, then re-run."; fi
  return "$fails"
}

cmd_clean() {
  say "cleaning caches and scratch (your config, CA, lists and logs stay)"
  find "$HERE" \( -name '__pycache__' -o -name '*.pyc' \) -prune -exec rm -rf {} + 2>/dev/null || true
  rm -f /tmp/dnshub-*.service /tmp/dnshub.sudoers \
        /tmp/dnshub-server.csr /tmp/dnshub-san.cnf 2>/dev/null || true
  ok "scratch removed"
}

cmd_install() {
  check || { bad "aborting"; return 1; }
  say "installing dnshub (units, control token, your private CA, sudoers allowlist)"
  run_sudo env DNSHUB_LAN_IP="$LAN_IP" "$DN" install
  say "starting the whole hub"
  run_sudo env DNSHUB_LAN_IP="$LAN_IP" "$DN" on
  if run_sudo "$DN" version >/dev/null 2>&1; then
    run_sudo "$DN" version
  fi

  say "your dnshub is up. Summary:"
  echo "  control panel : http://$LAN_IP:8081"
  echo "  resolver UI   : http://$LAN_IP:8080"
  echo "  file hub      : http://$LAN_IP:8082"
  echo "  encrypted DNS : DoT dns.home:853  /  DoH https://$LAN_IP/dns-query"
  echo "  your CA       : https://$LAN_IP/ca.pem   (install once on every device)"
  echo "  panel token   : $(run_sudo "$DN" token 2>/dev/null)"
  echo
  echo "  To point a device at dnshub: set its DNS server to $LAN_IP"
  echo "  (or hostname dns.home via 'Private DNS' for encrypted DNS)."
  echo "  Full guide: docs/INSTALL.md"
  cmd_clean
}

case "${1:-install}" in
  --check|-c) check || exit 1 ;;
  --clean)    cmd_clean ;;
  --help|-h)  sed -n '1,12p' "$0" | sed 's/^# \{0,1\}//' ;;
  install|*)  cmd_install ;;
esac