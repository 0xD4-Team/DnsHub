# Installing dnshub — the full guide

This walks through everything, from "I have a spare Linux box" to "every device
on my LAN is protected". The short version is in [README.md](../README.md);
this is the long, careful version.

---

## 1. What you need

| Thing | Requirement |
|---|---|
| **A box** | Debian/Ubuntu, **systemd**, at least **2 cores / 1.5 GiB RAM**, a static LAN IP |
| **Python** | `python3` ≥ 3.9 (stdlib only for the core; `dnspython` is used by the resolver) |
| **Tools** | `openssl`, `curl`/`wget`, `sudo`. `dig` (dnsutils) for the `dnshub dns` command |
| **Optional** | `docker` (only for the optional recursive `unbound` sidecar), `wg` (WireGuard), `fail2ban`, `chrony` |

dnshub installs itself; you do **not** need to install a web server, a proxy,
node, or a DNS daemon yourself.

> **Tip — static IP**: give the box a reserved DHCP lease or a static address
> *before* installing. The private CA is generated with the box's IP in the
> certificate; changing the IP later means regenerating the CA and re-trusting
> it on every device.

---

## 2. Get the code

```sh
git clone <your-repo-url> dnshub
cd dnshub
```

(No git? Download the zip of the repo and unpack — `setup.sh` works from the
unpacked folder too. Keep `src/`, `setup.sh` and the docs together in one
folder.)

---

## 3. Install — one command

```sh
bash setup.sh            # checks, installs, starts, prints a summary
```

If your subnet is not `192.168.1.0/24`:

```sh
DNSHUB_LAN_IP=10.0.0.5 bash setup.sh
```

You can run just the pre-flight check first:

```sh
bash setup.sh --check
```

Installing over **ssh / CI without a terminal**? Export your sudo password and
setup.sh runs fully unattended:

```sh
DNSHUB_SUDO_PW=your-sudo-password bash setup.sh
```

What happens under the hood (see `src/dnshub install` for the authoritative
list):

1. Installs the four Python services, the sudo-allowlisted helper
   `dnshub-ctl`, the blocklist service and the **WireGuard safety guard**.
2. Writes the control token to `/etc/dnshub/control.token` (root:dnshub, 0640).
3. Generates **your own CA + server certificate** locally — it never leaves the
   box.
4. Installs and validates the sudoers drop-in (`visudo -c` before trusting it).
5. Starts everything and prints your panel URL + token.

---

## 4. Ports & services after install

| Port | Service | Purpose | Auth |
|---|---|---|---|
| 53 UDP/TCP | `dnshub-resolver` | DNS for your LAN, ad-blocking | — |
| 853 | `dnshub-privacy` | DNS-over-TLS (Android *Private DNS*) | your CA |
| 443 | `dnshub-privacy` | DNS-over-HTTPS `/dns-query`, CA at `/ca.pem` | your CA |
| 8080 | resolver | live dashboard | — |
| 8081 | `dnshub-control` | panel: service switches, logs, blocklist, trends, doctor | bearer token |
| 8082 | `dnshub-files` | file hub | bearer token |
| 51820 | `wg-quick@wg0` | WireGuard (optional part) | keys |

```sh
sudo ./src/dnshub status    # one screen for everything
sudo ./src/dnshub token     # panel token
```

---

## 5. Point your devices at it

**Plain DNS (fastest to try):** set the device's DNS server to the box IP.

**Encrypted DNS — the recommended setup** (works everywhere, invisible to the
ISP):

1. Install your CA **once** on each device: open
   `https://<box-ip>/ca.pem`, trust it as a *root certificate*.
2. Then:

| OS | How |
|---|---|
| **Android** | Settings → Network → Private DNS → *dns.home* (hostname) |
| **Windows 11** | Settings → Network → adapters → DNS → **DoH**: `https://<box-ip>/dns-query`, CA imported into *Trusted Root* |
| **iOS / macOS** | Install the CA profile, then a DNS-over-TLS profile with hostname `dns.home` |
| **Linux** | `kdig @dns.home -d example.com`, or configure systemd-resolved with `DoT=dns.home` |

Your box's own names (`dns.home`, `panel.home`, `files.home`, `wg.home`,
`router.home`) resolve from every device on the LAN, and even over the VPN —
no public DNS, zero data cost.

---

## 6. WireGuard (optional)

`wg-quick@wg0` is part of the master switch, but peer setup is yours to do
once. The always-on **guard** (`dnshub-wg-guard.service`) runs regardless —
it only acts if the LAN ever routes into the tunnel:

```sh
sudo systemctl status dnshub-wg-guard.service   # landed on with install
tail /var/log/dnshub/wg-guard.log               # its decision log
```

---

## 7. Updating

```sh
git pull
bash setup.sh            # idempotent: reinstalls units, keeps CA + token
```

Updating never touches your blocklist config, your CA, or your token.

---

## 8. Uninstall

dnshub is 100% systemd — remove the units and stop:

```sh
sudo systemctl disable --now dnshub-control dnshub-files dnshub-privacy \
  dnshub-blocklist dnshub-resolver dnshub-wg-guard dnshub-unbound 2>/dev/null
sudo rm -f /etc/systemd/system/dnshub-*.service /etc/systemd/system/dnshub-*.timer
sudo rm -f /usr/local/sbin/dnshub-ctl /usr/local/sbin/dnshub-wg-guard
sudo rm -rf /usr/local/lib/dnshub /etc/dnshub /etc/sudoers.d/dnshub
sudo systemctl daemon-reload
```

(Then remove the folder. Your `/home/.../files`, logs and lists go with it —
back up anything you want to keep.)

---

## 9. Troubleshooting

| Symptom | What to do |
|---|---|
| `dig @<box> google.com` fails | `sudo ./src/dnshub status` → is `dnshub-resolver` active? `sudo systemctl status dnshub-resolver` |
| "This server can't be reached" in a browser UI | the panel needs the token first — `sudo ./src/dnshub token` |
| DoT/DoH "not trusted" on a device | you skipped the CA step, or the box IP changed after CA generation |
| Everything off after a power cut | that is by design: run `sudo ./src/dnshub on` once it is back, or enable autostart with `systemctl enable` per unit |
| Blocklist looks empty | `sudo ./src/dnshub blocklist refresh`, then `sudo ./src/dnshub dns doubleclick.net` |
| sudoers error visible in logs | re-run `sudo ./src/dnshub install` after updates |

The panel's **Doctor** tab and `sudo ./src/dnshub doctor` check most of these
for you and propose a fix.

---

## 10. Tuning knobs (env vars)

| Variable | What it changes |
|---|---|
| `DNSHUB_LAN_IP` | the LAN IP baked into the CA + internal zone |
| `DNSHUB_DEV_DIR` | where dnshub expects its files (defaults to `src/`'s own dir) |
| `DNSHUB_FILES_ROOT` | file-hub root (default `~/dnshub-files`) |
| `DNSHUB_PROFILE` | blocklist profile: `daily` (default), `weekly`, … |
| `DNSHUB_CERT_DIR` | where the private CA lives (default `/etc/dnshub/certs`) |

---

*Questions? Open an issue in the repo — dnshub was written to be understood,
and the author answers directly.*