# Changelog

All notable changes to **dnshub** are tracked here. The format is inspired by
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[semantic versioning](https://semver.org/).

## [2.0.0] — 2026-09-29

### Added
- **Public release shape**: README, banner, MIT license, SECURITY model, this changelog, `tests/`.
- **Branding everywhere**: web UIs carry the `dnshub · by Mostfa` wordmark + version.
- **`dnshub version`** command.
- **Guard ships with `install`**: `dnshub-wg-guard` + its unit are now part of
  `src/` and get installed/enabled by `dnshub install` (previously a manual step).
- **Internal `.home` zone** (`dns.home`, `panel.home`, `files.home`, `wg.home`,
  `router.home`, `mtt-server` + PTRs) — served before the blocklist, NXDOMAIN
  for unknown `.home`, never forwarded upstream.
- **Gaming fast lane**: game-platform domains pinned as sticky RAM entries with
  honest clamped TTLs, surviving cold starts via SQLite warm-load tags.
- **Local private DNS**: DoT :853 + DoH :443 front forwarding only to
  127.0.0.1:53, with a self-generated CA.
- **DoH on :443** serving `/dns-query` (GET/POST) and `/ca.pem`.
- **Per-service control panel** :8081 with logs, blocklist stats, resolver
  metrics, trends and doctor.

### Changed
- `dnshub on` now **restarts** active units instead of bare `enable --now`
  (avoids silently running stale code after an update).
- **`dnshub` on your PATH**: `install` ships the master to
  `/usr/local/lib/dnshub/dnshub` plus a `/usr/local/bin/dnshub` launcher that
  pins `DNSHUB_DEV_DIR` to the installed tree. Every command escalates to root
  itself — the operator gets a NOPASSWD sudo entry for that one launcher, so
  plain `dnshub on|off|status|…` works from any directory with **zero** password
  or polkit prompts (before the first install, one normal `sudo` still applies).
- Blocklist compiled format DHB2 updated (mmap-ready blob + sorted index).
- `dnshub on` and `setup.sh --clean` sweep stale blocklist compile
  intermediates (`blocklist.compiled.*.tmp*`) left by an interrupted build.

### Fixed
- Resolver now serves internal zone + NXDOMAIN correctly (6-field rrs tuples).
- Gaming sticky survives restart (warm-load applies sticky tags).
- Stale `build_binary` import in `tests/test_blocklist.py` corrected.
- `dnshub install` now writes the `dnshub-resolver.service` unit — previously
  it only existed on boxes that carried it over from an older manual setup, so
  a truly fresh install had no resolver at all.
- Fresh installs pre-create `/var/log/dnshub/abuse.log` (fail2ban refuses to
  start while a jail's log file is missing).
- Optional recursive `unbound` sidecar config published at
  `src/unbound/unbound.conf` (container recipe in the file header).

## [1.0.0] — 2026-09

Initial private deployment: master switch, ad-block resolver (3M+ domains),
dual-tier cache, resolver dashboard :8080, file hub :8082, WireGuard split
tunnel with LAN-safety guard, fail2ban abuse handling, chrony clock sanity.