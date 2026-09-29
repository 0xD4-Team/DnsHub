# Security

dnshub is engineered as a **private, LAN-only** system. This file describes
the threat model and the controls that matter — read it before exposing
anything beyond your network.

## Threat model

- **Assumed adversary**: your ISP / anyone on the path to the Internet, plus
  casual access to your LAN (guest WiFi, a compromised device).
- **Out of scope**: a nation-state wanting in; someone with physical access
  to the box.
- **Design rule**: *nothing plaintext leaves the box; no cloud, no domain,
  no telemetry, no accounts.*

## Controls

| Area | Control |
|---|---|
| **Panel & file hub auth** | 256-bit random bearer token stored at `/etc/dnshub/control.token` (root:dnshub, 0640). Compared with `hmac.compare_digest` (constant-time). **8 failed attempts → 300 s lockout** per client IP. |
| **Least privilege** | The panel service runs as the operator user. It may only call `dnshub-ctl` (root-owned, in the sudoers allowlist), a helper that refuses any unit/action outside its allowlist table. |
| **Private DNS certs** | The CA and server keys are generated **on the box** and never leave it. The CA is published to your devices via `GET /ca.pem`; the server key is group-readable only by the `dnshub` group. |
| **No plaintext egress** | The resolver only uses DoT/DoH upstreams. The DoT/DoH front (`dnshub-privacy`) forwards **only** to `127.0.0.1:53` — it has no other upstream, by construction. |
| **Abuse** | The resolver tracks abusive query patterns and feeds fail2ban, which drops the offender at nftables level. |
| **File hub** | Realpath-containment enforced (no `..` escape), token-only, 4 GiB file cap. |
| **WireGuard** | Split tunnel with per-peer `/32` + LAN `/24` routes. The always-on guard tears down and disables `wg0` *only* if the LAN ever routes into the tunnel. |
| **Wrongly-trusted CAs** | The provided `ca.crt` is the *only* certificate your devices must trust. Do not share it outside your devices. |

## Reporting

dnshub has no public bug-tracker gate: open a draft issue, or contact Mostfa
directly. Security-relevant fixes are free of charge and land fast. Please
include:

- what you exposed (ports, auth mode),
- the exact request/query that triggered it,
- your LAN layout (deployment) so the fix can be reproduced.

## Rotation

- **Token**: `sudo rm /etc/dnshub/control.token && sudo ./dnshub install`
  (or just regenerate via `./dnshub token --regen` if present).
- **Certs / CA**: delete `/etc/dnshub/certs` and re-run `sudo ./dnshub install`,
  then reinstall the CA on every device.
- **WireGuard keys**: regenerate the peer keys with the `add_wireguard` tooling.