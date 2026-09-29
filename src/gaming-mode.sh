#!/usr/bin/env bash
# =============================================================================
# gaming-mode.sh - Dynamic gaming traffic management
#
#   IMPORTANT / HONEST SCOPE NOTE
#   This host is a laptop on WiFi (wlp5s0, 192.168.1.12) sitting BEHIND a
#   consumer router at 192.168.1.1. Bufferbloat is created in the queue of
#   whatever device owns the bottleneck link - here, the router/ISP uplink.
#   Traffic control on THIS host can only shape THIS host's own transmit queue.
#   Gaming traffic is predominantly INGRESS (server -> client), which a local
#   root qdisc does not shape at all.
#
#   => Local SQM will NOT remove ISP-side bufferbloat. That requires running
#      SQM/CAKE on the router itself. This script is honest about that.
#
#   What it DOES genuinely deliver:
#     1. CAKE (preferred) or fq_codel on the local interface. CAKE does
#        per-flow fair queueing with diffserv awareness, so a Steam download
#        on this host cannot starve a game session on it.
#     2. DSCP marking so any DSCP-aware device downstream can prioritise
#        interactive traffic over bulk downloads.
#     3. Deferral of this host's real background update jobs.
# =============================================================================
set -u
# Privilege escalation uses a root-owned NOPASSWD sudoers drop-in rather than an
# embedded password. A password in this file is a plaintext credential sitting
# in the project directory, and it previously leaked into /etc/cron.d when a
# `sudo -S ... <<< "$PW"` helper clobbered a heredoc body.
#
#   /etc/sudoers.d/dnshub-gaming:
#     mostfa ALL=(root) NOPASSWD: /usr/sbin/tc, /usr/sbin/nft, /usr/sbin/modprobe, \
#       /usr/bin/systemctl, /usr/sbin/ip, /usr/bin/systemctl
IFACE="${DNSHUB_IFACE:-wlp5s0}"
# Measured tx bitrate on wlp5s0 is 135 Mbit/s. Shape slightly below it so
# CAKE actually has a queue to manage.
SHAPE_RATE="${DNSHUB_SHAPE_RATE:-100mbit}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE="${DNSHUB_DEV_DIR:-$HERE}/gaming_mode.state"
NFT_TABLE="inet dnshub_gaming"
MODE="${1:-status}"

log() { echo "[gaming-mode] $*"; }

# Run a privileged command, keep sudo's real exit status, and drop the
# password prompt from stdout. (A naive `sudo ... | grep` returns grep's
# status, which silently reports success for failing commands.)
root() {
  local out rc
  # No stdin redirect: a `<<<` here would swallow any heredoc body in the
  # caller. That collision previously wrote this file's password into
  # unrelated system config files.
  out=$(sudo -n "$@" 2>&1); rc=$?
  printf '%s\n' "$out" | grep -viE '^\[sudo\]|password for' >&2
  return $rc
}

# ---- what actually exists to be deferred on THIS host ----------------------
# NOTE: "Windows Update / Play Store / App Store" do not exist on Ubuntu. The
# real background consumers present here are apt-daily and unattended-upgrades.
DEFER_SERVICES=(unattended-upgrades.service apt-daily.service apt-daily-upgrade.service)
DEFER_TIMERS=(apt-daily.timer apt-daily-upgrade.timer)

apply_sqm() {
  # CAKE first: per-flow fairness + diffserv3 gives markedly better latency
  # under load than fq_codel on a single host.
  log "applying CAKE (rate $SHAPE_RATE, diffserv3) on $IFACE"
  if root tc qdisc replace dev "$IFACE" root cake \
        bandwidth "$SHAPE_RATE" diffserv3 triple-isolate nonat nowash; then
    log "CAKE active on $IFACE"
    return 0
  fi
  log "CAKE unavailable, falling back to fq_codel"
  # NOTE: this kernel's fq_codel rejects an explicit `limit` parameter
  # (verified: 'Illegal limit'), so it is left at the built-in 10240p.
  if root tc qdisc replace dev "$IFACE" root fq_codel \
        flows 1024 target 5ms interval 100ms memory_limit 8Mb ecn; then
    log "fq_codel active on $IFACE"
    return 0
  fi
  log "WARNING: could not attach any qdisc to $IFACE"
  return 1
}

remove_sqm() {
  log "restoring default qdisc on $IFACE"
  # Detach whatever root qdisc is installed. `tc qdisc del ... root` errors with
  # "Cannot delete qdisc with handle of zero" when the root is the wireless
  # default noqueue - that is expected, so its stderr is discarded.
  root tc qdisc del dev "$IFACE" root 2>/dev/null || true
  local cur
  cur=$(tc qdisc show dev "$IFACE" 2>/dev/null | head -1)
  if echo "$cur" | grep -qE 'cake|fq_codel|htb|sfq";'; then
    log "WARNING: a shaper qdisc is still attached: $cur"
  else
    log "default qdisc in place: ${cur:-none}"
  fi
}

apply_dscp() {
  log "applying DSCP priority rules"
  if root nft -f "$HERE/dnshub-gaming.nft"; then
    log "DSCP rules loaded"
    return 0
  fi
  log "WARNING: DSCP rules failed to load"
  return 1
}

remove_dscp() {
  if root nft list table "$NFT_TABLE" >/dev/null 2>&1; then
    log "removing DSCP rules"
    root nft delete table "$NFT_TABLE" || true
  else
    log "no DSCP table present"
  fi
}

defer_updates() {
  log "deferring background updates"
  # Stop the TIMERS first: stopping the service while its trigger is still
  # active makes systemd refuse ("but its triggering units are still active").
  for t in "${DEFER_TIMERS[@]}"; do
    root systemctl stop "$t" 2>/dev/null || true
  done
  for s in "${DEFER_SERVICES[@]}"; do
    root systemctl stop "$s" 2>/dev/null || true
  done
  log "apt timers + unattended-upgrades paused (the real update jobs here)"
}

resume_updates() {
  log "resuming background updates"
  for t in "${DEFER_TIMERS[@]}"; do
    root systemctl start "$t" 2>/dev/null || true
  done
  for s in "${DEFER_SERVICES[@]}"; do
    root systemctl start "$s" 2>/dev/null || true
  done
}

set_state() {
  printf '{"enabled":%s,"changed":%s}\n' \
    "$([ "$1" = true ] && echo true || echo false)" "$(date +%s)" > "$STATE"
}

case "$MODE" in
  on|enable)
    set_state true
    apply_sqm
    apply_dscp
    defer_updates
    log "GAMING MODE ON"
    ;;
  off|disable)
    set_state false
    remove_dscp
    remove_sqm
    resume_updates
    log "GAMING MODE OFF"
    ;;
  status)
    S="off"
    if [ -f "$STATE" ]; then
      S=$(grep -o '"enabled":[a-z]*' "$STATE" | cut -d: -f2)
    fi
    echo "gaming mode:   $S"
    echo "interface:     $IFACE ($(ip -br a show "$IFACE" 2>/dev/null | awk '{print $3}'))"
    echo "qdisc:         $(tc qdisc show dev "$IFACE" 2>/dev/null | head -1)"
    # `root` is REQUIRED here. Reading an nft table needs CAP_NET_ADMIN, so an
    # unprivileged `nft list table` always fails and this branch reported
    # "absent" even while the table was loaded and actively counting packets.
    # tc qdisc show and ip are safe without it; nft is not.
    if root nft list table "$NFT_TABLE" >/dev/null 2>&1; then
      echo "DSCP table:    active"
    else
      echo "DSCP table:    absent"
    fi
    echo "updates:       $(systemctl is-active unattended-upgrades 2>/dev/null) / timers $(systemctl is-active apt-daily.timer 2>/dev/null)"
    echo "gateway:       $(ip r | awk '/^default/{print $3; exit}')  <- queue NOT controllable from this host"
    # tx bitrate line looks like: "tx bitrate: 135.0 MBit/s MCS 6 40MHz short GI"
    echo "shape rate:    $SHAPE_RATE (wifi tx link: $(iw dev "$IFACE" link 2>/dev/null | awk '/tx bitrate/{print $3" "$4}'))"
    ;;
  *)
    echo "usage: $0 {on|off|status}" >&2
    exit 2
    ;;
esac
