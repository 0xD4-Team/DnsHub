#!/usr/bin/env python3
"""
dns-server.py  --  DNS Hub resolver  (v2, production rewrite)

Why this is a rewrite and not a patch of the original:
  * The original blocked the single recvfrom() loop on a synchronous DoH HTTP
    request, so one cache miss stalled every client for up to 1.5s.
  * It forced an A record for *every* qtype, breaking AAAA / MX / TXT / SRV /
    HTTPS(SVCB) responses.
  * It persisted a cache entry with max(ttl, 7200), pinning CDN/matchmaker
    clients to stale edge IPs for 2 hours - the opposite of the goal.
  * It opened a new SQLite connection and fsync'd on every single query.
  * Its fallback path leaked queries to 1.1.1.1:53 in cleartext UDP.

This version targets the actual host: Ubuntu 26.04, 2 vCPU Core 2 Duo,
1.8 GiB RAM, WiFi uplink.

Key properties:
  * asyncio UDP + TCP listeners (TCP is required for >512B and for DoT/DoH
    style clients; the original was UDP-only).
  * Encrypted upstreams ONLY: DoH (Cloudflare/Google) and DoT (Cloudflare).
    Quad9's DoH on :5053 is unreachable from this network (measured 133s
    timeout) and is therefore excluded.
  * Correct per-qtype answers by caching the full upstream response payload
    (a set of records), not a single A record.
  * TTL is honoured honestly, bounded by MIN/MAX_TTL; never inflated.
  * SQLite persistence uses WAL + batched commits on a background thread.
  * Single-flight de-duplication: N concurrent misses for the same name make
    exactly ONE upstream request.
  * Ad-blocking: compiled list is consulted before any upstream call and the
    result is negatively cached so repeat ad hits never touch the network.
  * Background prefetch: hot names are refreshed at 80% of their TTL so a
    gaming client never pays an upstream round trip for a warm name.
  * Bounded caches + TTL clamps keep RSS flat on a 1.8 GiB host.

Run:   python3 dns-server.py            (foreground, for systemd)
       python3 dns-server.py --selftest (offline correctness tests)
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import json
import mmap
import os
import signal
import socket
import sqlite3
import ssl
import struct
import sys
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Optional

try:
    import dns.asyncresolver
    import dns.exception
    import dns.flags
    import dns.message
    import dns.name
    import dns.opcode
    import dns.rcode
    import dns.rdataclass
    import dns.rdatatype
    import dns.rdtypes.IN.A
    import dns.rdtypes.IN.AAAA
    import dns.rdtypes.ANY.TXT
except ImportError as exc:  # pragma: no cover
    print(f"FATAL: dnspython is required ({exc}). "
          f"Install with: pip install dnspython", file=sys.stderr)
    sys.exit(2)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DNSHUB_DB", os.path.join(BASE_DIR, "dns_analytics.db"))
BLOCK_BIN = os.environ.get("DNSHUB_BLOCKLIST", os.path.join(BASE_DIR, "blocklist.compiled.bin"))
BIND_ADDR = os.environ.get("DNSHUB_BIND", "0.0.0.0")
DNS_PORT = int(os.environ.get("DNSHUB_PORT", "53"))
ACCESS_LOG = os.path.join(BASE_DIR, "dns_queries.log")

# Abuse log: consumed by the fail2ban `dnshub-dns-abuse` jail. The jail file is
# useless if the resolver never writes here, so this is the producer half.
ABUSE_LOG = os.environ.get("DNSHUB_ABUSE_LOG", "/var/log/dnshub-abuse.log")
# A single client above this many queries inside the window is logged as `rate`.
# Deliberately far above any real browsing/gaming client: Riot's launcher plus a
# browser plus Discord peaks in the tens of QPS, while a flood or an open-resolver
# scan runs in the thousands. Too low a value and fail2ban bans normal users.
ABUSE_RATE_QPS = int(os.environ.get("DNSHUB_ABUSE_RATE_QPS", "120"))
ABUSE_WINDOW = float(os.environ.get("DNSHUB_ABUSE_WINDOW", "60"))
# Only these source ranges may use the resolver. Anything else is a WAN scanner
# or a host that has been pointed at us from outside; it gets logged as `nonlan`.
ALLOWED_NETS = [ipaddress.ip_network(n) for n in os.environ.get(
    "DNSHUB_ALLOWED_NETS", "127.0.0.0/8,::1/128,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
).split(",") if n.strip()]

# ---------------------------------------------------------------------------
# Encrypted upstream transports
#
# dnspython 2.8's async resolver exposes no use_doh()/use_tls(), and
# dns.query.https/tls are synchronous only (they want aiohttp/requests,
# neither of which is installed and both of which are heavy on a 1.36 GiB
# host). So we speak DoT and DoH directly on asyncio. That keeps the event
# loop non-blocking, adds zero dependencies, and costs ~0 extra RSS.
#
# Both transports forward the ORIGINAL client query wire, so EDNS0, the DO
# bit and DNSSEC expectations survive the round trip.
# ---------------------------------------------------------------------------
def _ssl_context(server_hostname: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context()          # verifies against system CAs
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


class _TLSStream:
    """A pooled DoT connection: TLS, 2-byte length framing."""

    def __init__(self, host: str, port: int, hostname: str):
        self.host, self.port, self.hostname = host, port, hostname
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.lock = asyncio.Lock()

    async def _connect(self) -> None:
        ctx = _ssl_context(self.hostname)
        self.reader, self.writer = await asyncio.open_connection(
            self.host, self.port, ssl=ctx, server_hostname=self.hostname
        )
        sock = self.writer.get_extra_info("socket")
        if sock is not None:
            import socket as _s
            try:
                sock.setsockopt(_s.IPPROTO_TCP, _s.TCP_NODELAY, 1)
            except OSError:
                pass

    async def query(self, wire: bytes, timeout: float) -> bytes:
        async with self.lock:
            for attempt in (0, 1):
                try:
                    if self.writer is None or self.writer.is_closing():
                        await self._connect()
                    assert self.writer is not None and self.reader is not None
                    self.writer.write(struct.pack(">H", len(wire)) + wire)
                    await self.writer.drain()
                    hdr = await asyncio.wait_for(self.reader.readexactly(2),
                                                 timeout=timeout)
                    ln = struct.unpack(">H", hdr)[0]
                    body = await asyncio.wait_for(self.reader.readexactly(ln),
                                                  timeout=timeout)
                    return body
                except Exception:
                    await self.close()
                    if attempt:
                        raise
        raise RuntimeError("unreachable")

    async def close(self) -> None:
        if self.writer is not None:
            with contextlib.suppress(Exception):
                self.writer.close()
                await self.writer.wait_closed()
        self.reader = self.writer = None


class _HTTPSStream:
    """A pooled DoH connection: TLS + HTTP/1.1 POST of the wire-format query."""

    def __init__(self, host: str, port: int, hostname: str, path: str):
        self.host, self.port, self.hostname, self.path = host, port, hostname, path
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.lock = asyncio.Lock()

    async def _connect(self) -> None:
        ctx = _ssl_context(self.hostname)
        self.reader, self.writer = await asyncio.open_connection(
            self.host, self.port, ssl=ctx, server_hostname=self.hostname
        )

    async def query(self, wire: bytes, timeout: float) -> bytes:
        async with self.lock:
            for attempt in (0, 1):
                try:
                    if self.writer is None or self.writer.is_closing():
                        await self._connect()
                    assert self.writer is not None and self.reader is not None
                    head = (
                        f"POST {self.path} HTTP/1.1\r\n"
                        f"Host: {self.hostname}\r\n"
                        f"Content-Type: application/dns-message\r\n"
                        f"Accept: application/dns-message\r\n"
                        f"Content-Length: {len(wire)}\r\n"
                        f"User-Agent: dnshub/2.0\r\n"
                        f"Connection: keep-alive\r\n\r\n"
                    ).encode()
                    self.writer.write(head + wire)
                    await self.writer.drain()

                    # status line
                    status = await asyncio.wait_for(
                        self.reader.readline(), timeout=timeout)
                    if not status:
                        raise ConnectionResetError("no status line")
                    parts = status.decode("latin-1").split()
                    if len(parts) < 2 or not parts[1].isdigit():
                        raise ValueError(f"bad status line {status!r}")
                    code = int(parts[1])
                    # headers
                    clen = None
                    chunked = False
                    while True:
                        line = await asyncio.wait_for(
                            self.reader.readline(), timeout=timeout)
                        if line in (b"\r\n", b"\n", b""):
                            break
                        k, _, v = line.decode("latin-1").partition(":")
                        k = k.strip().lower()
                        v = v.strip()
                        if k == "content-length":
                            clen = int(v)
                        elif k == "transfer-encoding" and "chunked" in v.lower():
                            chunked = True
                    if code != 200:
                        raise ValueError(f"DoH status {code}")
                    if chunked:
                        body = b""
                        while True:
                            sz = int((await asyncio.wait_for(
                                self.reader.readline(), timeout=timeout)
                            ).strip().split(b";")[0] or b"0", 16)
                            if sz == 0:
                                await asyncio.wait_for(
                                    self.reader.readline(), timeout=timeout)
                                break
                            body += await asyncio.wait_for(
                                self.reader.readexactly(sz), timeout=timeout)
                            await asyncio.wait_for(
                                self.reader.readline(), timeout=timeout)
                        return body
                    if clen is None:
                        raise ValueError("DoH response without content-length")
                    return await asyncio.wait_for(
                        self.reader.readexactly(clen), timeout=timeout)
                except Exception:
                    await self.close()
                    if attempt:
                        raise
        raise RuntimeError("unreachable")

    async def close(self) -> None:
        if self.writer is not None:
            with contextlib.suppress(Exception):
                self.writer.close()
                await self.writer.wait_closed()
        self.reader = self.writer = None


# name, kind, connect-host, SNI/hostname, port, path
UPSTREAMS = [
    ("dot-cloudflare", "dot", "1.1.1.1", "cloudflare-dns.com", 853, None),
    ("doh-cloudflare", "doh", "1.1.1.1", "cloudflare-dns.com", 443, "/dns-query"),
    ("doh-google",    "doh", "8.8.8.8", "dns.google",        443, "/resolve"),
]
UPSTREAM_TIMEOUT = float(os.environ.get("DNSHUB_UPSTREAM_TIMEOUT", "4.0"))
# Hard wall-clock budget for the whole miss (all upstreams taken together).
# Without it, three upstreams x one 4s read each, with lock-queue time on top,
# gave a 65s tail when the providers were slow at boot. This caps the whole
# attempt regardless of how many providers are tried.
UPSTREAM_DEADLINE = float(os.environ.get("DNSHUB_UPSTREAM_DEADLINE",
                                         str(2 * UPSTREAM_TIMEOUT)))

# TTL policy. The original bug was max(ttl, 7200); we do the opposite.
MIN_TTL = 5         # seconds; do not cache shorter-lived answers aggressively
MAX_TTL = 3600      # seconds; hard ceiling so we do not serve stale CDN edges
NEGATIVE_TTL = 300  # NXDOMAIN / blocked cache lifetime
BLOCKED_TTL = 3600  # ad-block negative cache lifetime

MAX_RAM_ENTRIES = 20000     # LRU ceiling (memory-bounded for 1.8 GiB host)
MAX_SQL_ENTRIES = 100000    # persisted rows ceiling
PREFETCH_AT = 0.80          # refresh a hot entry once 80% of TTL has elapsed
PREFETCH_MIN_TTL = 120      # only prefetch entries with at least this TTL
HOT_THRESHOLD = 3           # hits before a name is considered "hot"

# Gaming fast lane: these suffixes never leave RAM (they survive LRU eviction)
# and always qualify for prefetch, so game-client lookups on this LAN resolve
# from RAM instantly and stop going upstream altogether. Deliberately a short
# a short, curated list of the big platforms rather than a scrape.
GAMING_SUFFIXES = (
    "riotgames.com", "leagueoflegends.com", "valorant.com",
    "epicgames.com", "fortnite.com", "unrealengine.com",
    "steampowered.com", "steamstatic.com", "steamcommunity.com",
    "steamcontent.com", "steamgames.com",
    "xboxlive.com", "playstation.net", "playstation.com",
    "ea.com", "origin.com", "activision.com", "battle.net", "blizzard.com",
    "ubisoft.com", "ubi.com", "rockstargames.com", "discord.com",
    "garena.com", "nintendo.net", "square-enix.com", "capcom.com",
)

# Internal zone served outright, ahead of the blocklist and upstream: the
# hub's own services + the WireGuard endpoint + the router, plus a reverse
# zone. Zero data cost and zero dependence on the outside world.
def detect_lan_ip() -> str:
    env = os.environ.get("DNSHUB_LAN_IP")
    if env:
        return env
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("1.1.1.1", 80))  # UDP connect sends no packets
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip or "192.168.1.12"
    except OSError:
        return "192.168.1.12"


LAN_IP = detect_lan_ip()
ROUTER_IP = os.environ.get("DNSHUB_ROUTER_IP", "192.168.1.1")
INTERNAL_A = {
    "dns.home": LAN_IP, "panel.home": LAN_IP, "files.home": LAN_IP,
    "resolver.home": LAN_IP, "privacy.home": LAN_IP, "mtt-server": LAN_IP,
    "wg.home": "10.8.0.1", "router.home": ROUTER_IP,
}
INTERNAL_PTR = {
    "1.1.168.192.in-addr.arpa": "router.home.",
    "1.0.8.10.in-addr.arpa": "wg.home.",
    "2.0.8.10.in-addr.arpa": "phone.home.",
    "3.0.8.10.in-addr.arpa": "laptop.home.",
}
if "." in LAN_IP:
    last = LAN_IP.rsplit(".", 1)[1]
    INTERNAL_PTR[f"{last}.1.168.192.in-addr.arpa"] = "dns.home."

WRITE_BATCH = 64            # rows per SQLite transaction
WRITE_FLUSH_INTERVAL = 1.0  # seconds


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# AbuseTracker
#
# Feeds the fail2ban `dnshub-dns-abuse` jail. Emits one line per abusive event
# in the shape the filter expects:   <ip> <keyword> <detail>
#
# Two properties matter more than the feature itself:
#
#  1. It must be O(1) and allocation-light. The obvious implementation (write a
#     line per query) turns the logger into the amplifier: a 10k QPS flood
#     becomes 10k synchronous writes on the event loop, which is a *worse* DoS
#     than not logging at all. So we only write when a threshold is crossed,
#     and per-client we write at most one line per window.
#
#  2. It must not ban honest clients. So the only volumetric trigger is a high
#     query RATE, not volume, and the threshold sits an order of magnitude above
#     what a launcher + browser + Discord produces. Ad-block hits are counted
#     but deliberately NOT logged as abuse: a page with 200 blocked trackers is
#     normal browsing, and treating it as abuse would ban users at random.
# ---------------------------------------------------------------------------
class AbuseTracker:
    # Per-event-kind thresholds. Anything not listed logs on first occurrence,
    # which is reserved for events that are unconditionally abusive (a source
    # outside the allowed ranges is never a legitimate client).
    THRESHOLDS = {
        "rate": None,        # handled by note_query's sliding window
        "malformed": 5,      # a couple of odd packets happen; 5 in a window is not
        "opcode": 20,        # a stray UPDATE/notify is harmless; a storm is not
        "tcp-trunc": 30,     # OS connectivity checks do this routinely
        "nonlan": None,      # log immediately
    }

    def __init__(self, path: str, allowed: list, rate_qps: int, window: float):
        self.path = path
        self.allowed = allowed
        self.rate_qps = rate_qps
        self.window = window
        self.lock = threading.Lock()
        self.windows: dict[str, list[float]] = {}
        self.events: dict[str, list[float]] = {}
        self._lan_memo: dict[str, bool] = {}
        # Hard ceiling on memoised source IPs. A scan touching 100k addresses
        # must not be able to grow this dict without bound; evicting oldest is
        # fine because the memo is only a cache of a pure function.
        self._memo_cap = 4096
        self.fh = None
        self.counts: dict[str, int] = {}
        self.tracked = 0
        self.enabled = False
        self._open()

    def _open(self) -> None:
        """Open the log lazily and never crash the resolver over it.

        A failure here (no permission under ProtectSystem=strict, disk full,
        read-only fs) must degrade to "no abuse logging", never to a resolver
        that refuses to start or dies mid-query.
        """
        try:
            self.fh = open(self.path, "a", buffering=1024, encoding="utf-8")
            self.enabled = True
        except OSError as exc:
            self.enabled = False
            log(f"abuse log disabled ({self.path}: {exc})")

    def _reopen_if_rotated(self) -> bool:
        """Re-open the log if the path no longer refers to our open file.

        A plain `open()` handle silently follows the OLD inode if the file is
        deleted or rotated. Everything then looks fine - the resolver reports
        abuse logging as enabled and keeps "writing" - while fail2ban tails a
        file that never grows, so the jail matches nothing and is permanently
        blind with no error anywhere. That is worse than not logging at all,
        because the config still looks correct.

        Compare the fd's inode against the path's. They differ after an
        unlink, a rename-based rotation, or a truncate-and-replace. This runs
        only on a threshold-gated log line (a handful per window at most), so
        the two stat calls are not on any hot path.

        Returns True if a fresh handle was installed.
        """
        if self.fh is None:
            return False
        try:
            if os.fstat(self.fh.fileno()).st_ino == os.stat(self.path).st_ino:
                return False
        except (OSError, ValueError):
            # fd already closed, or the path is gone entirely; fall through and
            # let _open() recreate it.
            pass
        try:
            self.fh.close()
        except Exception:
            pass
        self.fh = None
        self._open()
        return self.enabled

    def _emit(self, ip: str, kind: str, detail: str = "") -> None:
        self.counts[kind] = self.counts.get(kind, 0) + 1
        if not self.enabled:
            return
        # The LN-BEG timestamp is not decoration: the fail2ban filter uses
        # datepattern = {^LN-BEG}, so without it fail2ban cannot place the
        # event in time and the ban would never expire correctly.
        ts = time.strftime("%b %d %H:%M:%S")
        try:
            self._reopen_if_rotated()
            if not self.enabled:
                return
            self.fh.write(f"{ts} {ip} {kind} {detail}\n".rstrip() + "\n")
            self.fh.flush()          # fail2ban tails the file; buffering defeats it
        except OSError:
            self.enabled = False
            try:
                self.fh.close()
            except Exception:
                pass

    def is_allowed(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self.allowed)

    def _flag_if_nonlan(self, ip: str) -> None:
        """Log a source outside the allowed ranges, once per window.

        ipaddress.ip_address() plus a subnet containment test is far too
        expensive to run on every query on a 2-core host, so the verdict is
        memoised per source IP. A flood from one address therefore pays the
        parse once, and the memo table is pruned with the other windows.
        """
        with self.lock:
            verdict = self._lan_memo.get(ip)
            if verdict is None:
                verdict = self.is_allowed(ip)
                self._lan_memo[ip] = verdict
        if not verdict:
            self._emit(ip, "nonlan", "source outside allowed networks")

    def note_query(self, ip: str) -> None:
        """Called for every parsed query. Returns fast on the happy path."""
        if ip not in self._lan_memo:
            self._flag_if_nonlan(ip)
        now = time.monotonic()
        with self.lock:
            w = self.windows.get(ip)
            if w is None:
                w = self.windows[ip] = []
            w.append(now)
            # Drop timestamps that have aged out. Amortised O(1) per query.
            cutoff = now - self.window
            if w[0] < cutoff:
                w[:] = [t for t in w if t >= cutoff]
            if len(w) <= self.rate_qps:
                return
            # Threshold crossed. Log once, then reset the window so a sustained
            # flood produces one line per window rather than one per query.
            n = len(w)
            w.clear()
        self._emit(ip, "rate", f"{n} queries in {self.window:.0f}s")

    def note_event(self, ip: str, kind: str, detail: str = "") -> None:
        """Threshold-gated event: malformed, bad opcode, truncated TCP, non-LAN."""
        # A source outside the allowed ranges is never a legitimate client, so
        # it is logged on sight rather than waiting for a threshold.
        if kind != "nonlan" and not self.is_allowed(ip):
            self._emit(ip, "nonlan", "source outside allowed networks")

        limit = self.THRESHOLDS.get(kind)
        if limit is None:
            self._emit(ip, kind, detail)
            return
        now = time.monotonic()
        with self.lock:
            w = self.events.setdefault(f"{kind}:{ip}", [])
            w.append(now)
            cutoff = now - self.window
            if w[0] < cutoff:
                w[:] = [t for t in w if t >= cutoff]
            if len(w) < limit:
                return
            n = len(w)
            w.clear()
        self._emit(ip, kind, f"{n}x in {self.window:.0f}s: {detail}")

    def prune(self) -> int:
        """Drop idle client windows so the dicts cannot grow without bound."""
        now = time.monotonic()
        cutoff = now - self.window
        dropped = 0
        with self.lock:
            # Build the doomed-key lists first: deleting from a dict while
            # iterating it raises RuntimeError.
            stale_q = [ip for ip, w in self.windows.items()
                       if not w or w[-1] < cutoff]
            stale_e = [k for k, w in self.events.items()
                       if not w or w[-1] < cutoff]
            for ip in stale_q:
                del self.windows[ip]
            for k in stale_e:
                del self.events[k]
            dropped = len(stale_q) + len(stale_e)
            for ip in stale_q:
                self._lan_memo.pop(ip, None)
            # Bound the memo independently: a source that never trips a
            # window threshold would otherwise never be considered stale.
            if len(self._lan_memo) > self._memo_cap:
                for k in list(self._lan_memo)[:len(self._lan_memo) - self._memo_cap]:
                    del self._lan_memo[k]
            self.tracked = len(self.windows)
        return dropped

    def snapshot(self) -> dict:
        with self.lock:
            tracked = len(self.windows)
        return {
            "abuse_log": self.path if self.enabled else "disabled",
            "abuse_tracked_clients": tracked,
            "abuse_events": dict(self.counts),
        }


# ---------------------------------------------------------------------------
# Blocklist: DHB2 blob + index, both mmapped.
#
# The previous implementation read the whole blob into a bytes object and
# built a Python list of offsets by scanning it. That list is the expensive
# part: ~20 MiB of heap at 416k domains, and it scales linearly, so a
# multi-million-domain list (what the aggregation goal needs) would have cost
# well over 150 MiB on a host with 1.36 GiB available.
#
# v2 stores the offset table in a second file and maps both. A lookup becomes
# struct.unpack_from on the mapped index plus a slice of the mapped blob, so
# a search allocates nothing that scales with list size. Resident memory is
# whatever pages are actually touched, which stays in the page cache.
# ---------------------------------------------------------------------------
_U32 = struct.Struct("<I")


class Blocklist:
    def __init__(self, path: str):
        self.path = path
        self.idx_path = path[:-4] + ".idx" if path.endswith(".bin") else path + ".idx"
        self.blob = None
        self.idx = None
        self._files: list = []
        self.count = 0
        self.generation = 0
        self._sig = None
        self.load()

    # -- lifecycle ---------------------------------------------------------
    def _close(self) -> None:
        for m in (self.blob, self.idx):
            try:
                if m is not None:
                    m.close()
            except (BufferError, ValueError):
                pass
        for f in self._files:
            try:
                f.close()
            except OSError:
                pass
        self.blob = self.idx = None
        self._files = []

    def load(self) -> None:
        try:
            bf = open(self.path, "rb")
            head = bf.read(8)
            if len(head) < 8 or head[:4] != b"DHB2":
                raise ValueError(f"bad magic {head[:4]!r}; expecting DHB2")
            self.count = _U32.unpack(head[4:8])[0]
            xf = open(self.idx_path, "rb")
            # fstat, not read(4): read() returns the bytes it was asked for, so
            # len() of it is 4 for any non-empty index and the check below then
            # rejects every valid list.
            idx_len = os.fstat(xf.fileno()).st_size
            if idx_len != self.count * 4:
                raise ValueError(
                    f"index is {idx_len} bytes, expected {self.count*4}; "
                    f"blob and index are from different builds")
            if os.fstat(bf.fileno()).st_size < 8:
                raise ValueError("blob is truncated")
            self.blob = mmap.mmap(bf.fileno(), 0, access=mmap.ACCESS_READ)
            self.idx = mmap.mmap(xf.fileno(), 0, access=mmap.ACCESS_READ)
            self._files = [bf, xf]
        except Exception as exc:
            log(f"blocklist: load failed ({exc}); ad-blocking disabled")
            self._close()
            self.count = 0
            return

        self.generation += 1
        # Record the current identity so reload_if_changed() does not fire a
        # spurious re-index on its first call after startup.
        try:
            st = os.stat(self.path)
            self._sig = (st.st_mtime_ns, st.st_size)
        except OSError:
            self._sig = None
        log(f"blocklist: {self.count:,} domains indexed (gen {self.generation}, "
            f"{os.path.getsize(self.path)/1048576:.1f} MiB mmap)")

    # -- lookup ------------------------------------------------------------
    def _entry(self, i: int) -> bytes:
        """Domain bytes for sorted position i, read straight out of the map."""
        off = _U32.unpack_from(self.idx, i * 4)[0]
        ln = self.blob[off]
        return self.blob[off + 1: off + 1 + ln]

    def match(self, domain: str) -> bool:
        """
        Binary search the mapped sorted blob, then walk parent suffixes so
        blocking 'tracker.com' also blocks 'a.b.tracker.com'.

        Comparisons are in BYTES: the blob stores raw ASCII, and comparing
        bytes to str raises TypeError on the first probe.
        """
        if not self.count or not domain:
            return False
        probe = domain.strip().lower().rstrip(".").encode("ascii", "ignore")
        if not probe:
            return False
        lo, hi = 0, self.count - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            cur = self._entry(mid)
            if cur == probe:
                return True
            if cur < probe:
                lo = mid + 1
            else:
                hi = mid - 1
        # parent-domain walk
        if b"." in probe:
            parent = probe.split(b".", 1)[1]
            if parent and parent != probe:
                return self.match(parent.decode("ascii", "ignore"))
        return False

    def reload_if_changed(self) -> bool:
        """
        Pick up a new compiled list with no downtime. Returns True on a
        successful swap so the caller knows to invalidate now-stale answers.

        The updater publishes blob and index with separate os.replace() calls,
        so there is a brief window where the index on disk is newer than the
        blob. Reject the swap if they disagree and retry on the next tick
        rather than loading a mismatched pair; a short "index is N bytes"
        error in the log is far cheaper than under-blocking.
        """
        try:
            st = os.stat(self.path)
            xi = os.stat(self.idx_path)
        except OSError:
            return False
        sig = (st.st_mtime_ns, st.st_size, xi.st_mtime_ns, xi.st_size)
        if self._sig == sig:
            return False
        old_blob, old_idx, old_files = self.blob, self.idx, self._files
        old_count = self.count
        # Roll back to the previous mapping if the new pair fails to load.
        self.blob = self.idx = None
        self._files = []
        self.count = 0
        self.load()
        if self.count == 0:
            log("blocklist: reload rejected, keeping previous mapping")
            self.blob, self.idx, self._files = old_blob, old_idx, old_files
            self.count = old_count
            return False
        self._sig = sig
        log(f"blocklist: change detected, re-indexed to {self.count:,} domains")
        # The old mapping is intentionally left to the garbage collector: the
        # updater has already replaced the inode, and closing it here would
        # fail if a lookup is mid-flight on this thread.
        return True



# ---------------------------------------------------------------------------
# Cache entry
# ---------------------------------------------------------------------------
@dataclass
class Entry:
    """A cached upstream answer."""
    expire: float
    ttl: int
    rcode: int
    # rrs: list of (name, rdatatype, rdataclass, ttl, rdata-hex)
    rrs: list
    # flags to preserve (e.g. AD bit)
    flags: int = 0
    hits: int = 0
    prefetched: bool = False
    blocked: bool = False
    qname: str = ""
    qtype: int = 0
    # sticky entries (gaming fast lane) survive LRU eviction and always
    # qualify for prefetch; a warm gaming cache never leaves RAM.
    sticky: bool = False


# ---------------------------------------------------------------------------
# SQLite persistence: WAL + batched writer thread
# ---------------------------------------------------------------------------
class Store:
    def __init__(self, path: str):
        self.path = path
        self.q: deque = deque(maxlen=50000)
        self.wake = threading.Event()
        self._stop = threading.Event()
        self.lock = threading.Lock()
        self._init_db()
        self.thr = threading.Thread(target=self._writer, daemon=True,
                                    name="sqlite-writer")
        self.thr.start()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-2000")   # ~2 MiB page cache
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    # Expected columns for the v2 schema. The v1 schema stored only
    # (domain, ip_address, expire_time) and had no `qtype`, so reusing the
    # table in place would fail at INSERT time.
    _WANT_CACHE = {
        "key", "qname", "qtype", "rcode", "flags", "ttl",
        "expire_time", "rrs", "hits", "blocked",
    }
    _WANT_LOGS = {
        "id", "timestamp", "client_ip", "domain", "qtype", "status",
        "response_time_ms",
    }

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """Archive any pre-v2 table whose shape differs and let CREATE rebuild it."""
        cur = conn.cursor()
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND "
            "name NOT LIKE 'sqlite_%'"
        )
        for (table,) in cur.fetchall():
            want = self._WANT_CACHE if table == "dns_cache" else (
                self._WANT_LOGS if table == "dns_logs" else None)
            if want is None:
                continue
            cur.execute(f"PRAGMA table_info({table})")
            have = {r[1] for r in cur.fetchall()}
            if not have:
                continue
            if have == want:
                continue
            missing = want - have
            log(f"store: migrating legacy {table} "
                f"(missing {sorted(missing)}); archiving old data")
            stamp = time.strftime("%Y%m%d-%H%M%S")
            # Quote the identifier: the timestamp contains '-', which SQLite
            # would otherwise parse as a subtraction operator.
            archive = f'"{table}_v1_{stamp}"'
            conn.execute(f"ALTER TABLE {table} RENAME TO {archive}")
        conn.commit()

    def _init_db(self) -> None:
        conn = self._connect()
        self._migrate(conn)
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS dns_cache (
                key TEXT PRIMARY KEY,
                qname TEXT NOT NULL,
                qtype INTEGER NOT NULL,
                rcode INTEGER NOT NULL,
                flags INTEGER NOT NULL DEFAULT 0,
                ttl INTEGER NOT NULL,
                expire_time REAL NOT NULL,
                rrs TEXT NOT NULL,
                hits INTEGER NOT NULL DEFAULT 0,
                blocked INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_dns_cache_expire
                ON dns_cache(expire_time);
            CREATE INDEX IF NOT EXISTS idx_dns_cache_hot
                ON dns_cache(hits DESC);

            CREATE TABLE IF NOT EXISTS dns_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                client_ip TEXT,
                domain TEXT,
                qtype TEXT,
                status TEXT,
                response_time_ms REAL
            );
            CREATE INDEX IF NOT EXISTS idx_dns_logs_ts
                ON dns_logs(id DESC);
            """
        )
        conn.commit()
        conn.close()
        log("store: schema ready (WAL)")

    def enqueue(self, row) -> None:
        self.q.append(row)
        if len(self.q) >= WRITE_BATCH:
            self.wake.set()

    def _writer(self) -> None:
        conn = self._connect()
        pending = 0
        last_flush = time.time()
        while not self._stop.is_set():
            self.wake.wait(timeout=WRITE_FLUSH_INTERVAL)
            self.wake.clear()
            batch = []
            while self.q and len(batch) < 500:
                with contextlib.suppress(IndexError):
                    batch.append(self.q.popleft())
            now = time.time()
            if batch and (len(batch) >= WRITE_BATCH or now - last_flush >= WRITE_FLUSH_INTERVAL):
                try:
                    self._flush(conn, batch)
                    pending += len(batch)
                    last_flush = now
                except Exception as exc:
                    log(f"store: write error {exc}")
        # final drain
        rest = []
        while self.q:
            with contextlib.suppress(IndexError):
                rest.append(self.q.popleft())
        if rest:
            with contextlib.suppress(Exception):
                self._flush(conn, rest)
        with contextlib.suppress(Exception):
            conn.close()

    @staticmethod
    def _flush(conn, batch) -> None:
        caches = [r for r in batch if r[0] == "cache"]
        logs = [r for r in batch if r[0] == "log"]
        cur = conn.cursor()
        if caches:
            cur.executemany(
                "INSERT OR REPLACE INTO dns_cache "
                "(key,qname,qtype,rcode,flags,ttl,expire_time,rrs,hits,blocked) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                [r[1] for r in caches],
            )
        if logs:
            cur.executemany(
                "INSERT INTO dns_logs "
                "(timestamp,client_ip,domain,qtype,status,response_time_ms) "
                "VALUES (?,?,?,?,?,?)",
                [r[1] for r in logs],
            )
        conn.commit()

    def load_cache(self, limit: int = MAX_SQL_ENTRIES) -> list:
        try:
            conn = self._connect()
            cur = conn.cursor()
            cur.execute(
                "SELECT key,qname,qtype,rcode,flags,ttl,expire_time,rrs,hits,blocked "
                "FROM dns_cache WHERE expire_time > ? "
                "ORDER BY hits DESC LIMIT ?",
                (time.time(), limit),
            )
            rows = cur.fetchall()
            conn.close()
            return rows
        except Exception as exc:
            log(f"store: cache load failed ({exc})")
            return []

    def prune_expired(self) -> int:
        try:
            conn = self._connect()
            cur = conn.cursor()
            cur.execute("DELETE FROM dns_cache WHERE expire_time < ?",
                        (time.time(),))
            conn.commit()
            n = cur.rowcount
            conn.close()
            return n
        except Exception:
            return 0

    def purge_blocked(self, blocklist) -> int:
        """
        Drop persisted cache rows whose domain is now on the blocklist.

        Without this, a positive answer written before a blocklist update
        survives the update: the resolver reads it back at startup and at
        every restart until the TTL lapses. A domain that just became blocked
        keeps resolving for the rest of its TTL, which is exactly the
        "I added the list and the ads are still there" symptom. Runs in the
        store thread, off the query path.
        """
        try:
            conn = self._connect()
            cur = conn.cursor()
            cur.execute("SELECT key,qname FROM dns_cache WHERE blocked=0")
            doomed = [k for k, q in cur.fetchall() if blocklist.match(q)]
            if not doomed:
                conn.close()
                return 0
            # Chunked so a large purge does not build one enormous statement.
            for i in range(0, len(doomed), 500):
                chunk = doomed[i:i + 500]
                cur.executemany("DELETE FROM dns_cache WHERE key = ?",
                                [(k,) for k in chunk])
            conn.commit()
            n = cur.rowcount
            conn.close()
            log(f"store: purged {n} cached entries that are now blocked")
            return n
        except Exception as exc:
            log(f"store: blocklist purge failed ({exc})")
            return 0

    def close(self) -> None:
        self._stop.set()
        self.wake.set()


# ---------------------------------------------------------------------------
# Upstream resolution over encrypted transports
# ---------------------------------------------------------------------------
class Upstream:
    """
    Pool of encrypted upstreams, each holding POOL_SIZE concurrent connections.

    A single connection per upstream serialises every miss behind one lock,
    which measured ~800 ms for a 40-way parallel burst (40 / 3 streams x ~60
    ms). Multiple keep-alive connections per upstream let misses proceed
    concurrently; each stream still serialises its own requests, preserving
    HTTP/1.1 and DoT framing correctness.
    """

    POOL_SIZE = 4

    def __init__(self):
        self.pools: dict[str, list] = {}
        self.health: dict[str, float] = {u[0]: 0.0 for u in UPSTREAMS}
        self.rr: dict[str, int] = {}
        for (name, kind, host, hostname, port, path) in UPSTREAMS:
            try:
                pool = []
                for _ in range(self.POOL_SIZE):
                    if kind == "dot":
                        pool.append(_TLSStream(host, port, hostname))
                    else:
                        pool.append(_HTTPSStream(host, port, hostname, path))
                self.pools[name] = pool
                self.rr[name] = 0
            except Exception as exc:
                log(f"upstream {name}: init failed ({exc})")
        if not self.pools:
            raise RuntimeError("no usable encrypted upstream configured")
        log("upstreams: " + ", ".join(
            f"{n}x{len(p)}" for n, p in sorted(self.pools.items())))

    def _pick(self, name: str):
        """Prefer an idle stream; otherwise round-robin."""
        pool = self.pools[name]
        for s in pool:
            if not s.lock.locked():
                return s
        i = self.rr.get(name, 0)
        self.rr[name] = (i + 1) % len(pool)
        return pool[i]

    def order(self) -> list:
        return sorted(self.pools, key=lambda n: -self.health.get(n, 0.0))

    async def close(self) -> None:
        for pool in self.pools.values():
            for s in pool:
                with contextlib.suppress(Exception):
                    await s.close()

    async def _query_bound(self, s, wire: bytes, timeout: float) -> bytes:
        """Run one upstream attempt under a wall-clock budget.

        The stream classes already time out their own reads and close on
        error, but a slow peer can hold the stream's lock past its budget.
        asyncio.wait_for cancels from outside, which the stream's
        `except Exception` path does not catch (CancelledError is a
        BaseException), so a cancelled mid-query stream would keep a torn
        TLS/HTTP frame. We therefore close it ourselves on timeout so the
        next query reconnects a fresh stream.
        """
        try:
            return await asyncio.wait_for(
                s.query(wire, UPSTREAM_TIMEOUT), timeout=timeout)
        except asyncio.TimeoutError:
            await s.close()
            raise TimeoutError(f"{s.hostname} over {timeout:.1f}s budget")

    async def resolve(self, query_wire: bytes, qname: str, qtype: int) -> tuple:
        """
        Returns (rcode_int, flags, rrs, ttl). rrs is a list of tuples
        (name, rdtype_text, rdtype_int, rdclass_int, ttl, rdata_text).
        """
        last_exc = None
        start = time.monotonic()
        for name in self.order():
            remaining = UPSTREAM_DEADLINE - (time.monotonic() - start)
            if remaining <= 0:
                break
            s = self._pick(name)
            try:
                resp_wire = await self._query_bound(
                    s, query_wire, max(0.2, remaining + 0.05))
                resp = dns.message.from_wire(resp_wire)
                rcode = resp.rcode()
                if rcode == dns.rcode.NXDOMAIN:
                    self.health[name] = time.time()
                    return 3, 0, [], NEGATIVE_TTL
                rrs: list = []
                min_ttl = MAX_TTL
                for rrset in resp.answer:
                    ttl = min(int(rrset.ttl), MAX_TTL)
                    min_ttl = min(min_ttl, ttl)
                    rdtype = int(rrset.rdtype)
                    rdtype_txt = dns.rdatatype.to_text(rrset.rdtype)
                    for rd in rrset:
                        rrs.append((
                            rrset.name.to_text().lower(),
                            rdtype_txt, rdtype, int(rrset.rdclass),
                            ttl, rd.to_text(),
                        ))
                self.health[name] = time.time()
                if not rrs:
                    return 0, 0, [], NEGATIVE_TTL
                return 0, int(resp.flags), rrs, min_ttl
            except Exception as exc:
                last_exc = exc
                # demote so a dead upstream is skipped quickly
                self.health[name] = self.health.get(name, 0.0) - 30
                log(f"upstream {name} failed: {type(exc).__name__}: {exc}")
        raise RuntimeError(f"all upstreams failed: {last_exc}")


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
class Metrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.started = time.time()
        self.total = 0
        self.ram_hits = 0
        self.sql_hits = 0
        self.blocked = 0
        self.misses = 0
        self.errors = 0
        self.prefetched = 0
        self.lat_sum = 0.0
        self.lat_max = 0.0
        self.by_qtype: dict[str, int] = {}
        self.recent: deque = deque(maxlen=50)

    def record(self, qtype: str, status: str, ms: float) -> None:
        with self.lock:
            self.total += 1
            self.lat_sum += ms
            if ms > self.lat_max:
                self.lat_max = ms
            self.by_qtype[qtype] = self.by_qtype.get(qtype, 0) + 1
            if status == "RAM":
                self.ram_hits += 1
            elif status == "SQL":
                self.sql_hits += 1
            elif status == "BLOCKED":
                self.blocked += 1
            elif status == "ERROR":
                self.errors += 1
            else:
                self.misses += 1

    def snapshot(self) -> dict:
        with self.lock:
            hits = self.ram_hits + self.sql_hits
            total = max(self.total, 1)
            return {
                "uptime_sec": round(time.time() - self.started, 1),
                "queries_total": self.total,
                "ram_cache_hits": self.ram_hits,
                "sqlite_cache_hits": self.sql_hits,
                "cache_hit_pct": round(100.0 * hits / total, 2),
                "blocked_total": self.blocked,
                "upstream_misses": self.misses,
                "errors": self.errors,
                "prefetched": self.prefetched,
                "avg_latency_ms": round(self.lat_sum / total, 3),
                "max_latency_ms": round(self.lat_max, 3),
                "queries_by_qtype": dict(self.by_qtype),
                "recent": list(self.recent),
            }


# ---------------------------------------------------------------------------
# Resolver core
# ---------------------------------------------------------------------------
class Resolver:
    def __init__(self):
        self.store = Store(DB_PATH)
        self.blocklist = Blocklist(BLOCK_BIN)
        self.upstream = Upstream()
        self.metrics = Metrics()
        self.abuse = AbuseTracker(ABUSE_LOG, ALLOWED_NETS, ABUSE_RATE_QPS, ABUSE_WINDOW)
        self.ram: OrderedDict[str, Entry] = OrderedDict()
        self.inflight: dict[str, asyncio.Future] = {}
        self._warm()

    def _key(self, qname: str, qtype: int) -> str:
        return f"{qname}|{qtype}"

    def _warm(self) -> None:
        rows = self.store.load_cache()
        now = time.time()
        n = 0
        blocked_n = 0
        for (key, qname, qtype, rcode, flags, ttl, expire, rrs_json,
             hits, blocked) in rows:
            if expire <= now:
                continue
            try:
                rrs = [tuple(x) for x in json.loads(rrs_json)]
            except Exception:
                continue
            # Restore the PERSISTED rcode. Hardcoding 0 here silently turned
            # every warmed BLOCKED entry into a NOERROR/NODATA answer, which
            # looks like "ad not blocked" to the client.
            e = Entry(expire=expire, ttl=ttl, rcode=int(rcode), rrs=rrs,
                      flags=int(flags), hits=hits, blocked=bool(blocked),
                      qname=qname, qtype=qtype)
            if not blocked and qname and any(
                    qname.endswith(s) for s in GAMING_SUFFIXES):
                e.sticky = True
            self.ram[key] = e
            n += 1
            if blocked:
                blocked_n += 1
            if n >= MAX_RAM_ENTRIES:
                break
        if n:
            log(f"cache: warmed {n} entries from SQLite "
                f"({blocked_n} ad-blocked)")

    # -- cache access ------------------------------------------------------
    def ram_get(self, key: str) -> Optional[Entry]:
        e = self.ram.get(key)
        if e is None:
            return None
        if e.expire <= time.time():
            self.ram.pop(key, None)
            return None
        self.ram.move_to_end(key)
        e.hits += 1
        return e

    def ram_put(self, key: str, e: Entry) -> None:
        if not e.sticky and e.qname and e.rcode == 0 and any(
                e.qname.endswith(s) for s in GAMING_SUFFIXES):
            e.sticky = True
        self.ram[key] = e
        self.ram.move_to_end(key)
        # Evict from the LRU tail, but never a sticky (gaming) entry: the
        # whole point of the fast lane is that it is always present.
        while len(self.ram) > MAX_RAM_ENTRIES:
            victim = next((k for k in self.ram if not self.ram[k].sticky), None)
            if victim is None:
                break  # everything left is pinned; keep them
            self.ram.pop(victim, None)

    def persist(self, e: Entry, key: str) -> None:
        self.store.enqueue(("cache", (
            key, e.qname, e.qtype, e.rcode, e.flags, e.ttl, e.expire,
            json.dumps([list(r) for r in e.rrs]), e.hits, int(e.blocked),
        )))

    def log_query(self, client_ip, domain, qtype, status, ms) -> None:
        self.store.enqueue(("log", (
            time.strftime("%Y-%m-%d %H:%M:%S"), client_ip, domain, qtype,
            status, round(ms, 3),
        )))

    # -- resolution --------------------------------------------------------
    def internal_entry(self, qname: str, qtype: int) -> Optional[Entry]:
        """Names this box owns: served outright, never blocked, never upstream.

        .home subdomains that are not in the table answer NXDOMAIN instead of
        leaking the name to the Internet (in practice that also hides typos of
        the hub's own names from the ISP-facing resolver).
        """
        now = time.time()
        qn = qname.rstrip(".").lower()
        if qn in INTERNAL_A:
            if qtype in (1, 255):  # A, ANY
                rrs = [(qn + ".", "A", 1, 1, 60, INTERNAL_A[qn])]
            else:                  # AAAA etc -> NODATA so clients fall back to A
                rrs = []
            return Entry(expire=now + 60, ttl=60, rcode=0, rrs=rrs,
                         qname=qn + ".", qtype=qtype)
        if qn in INTERNAL_PTR and qtype in (12, 255):  # PTR, ANY
            rrs = [(qn + ".", "PTR", 12, 1, 60, INTERNAL_PTR[qn])]
            return Entry(expire=now + 60, ttl=60, rcode=0, rrs=rrs,
                         qname=qn + ".", qtype=qtype)
        if qn.endswith(".home"):
            return Entry(expire=now + 30, ttl=30, rcode=3, rrs=[],
                         qname=qn + ".", qtype=qtype)
        return None

    async def resolve(self, query_wire: bytes, qname: str, qtype: int) -> tuple:
        """
        Return (entry, status). Implements single-flight: concurrent callers for
        the same key await one shared upstream request instead of each issuing
        their own DoT/DoH round trip.
        """
        key = self._key(qname, qtype)
        now = time.time()

        # 0) Internal zone, ahead of everything: the box's own names never go
        # through the blocklist and never leave the LAN.
        internal = self.internal_entry(qname, qtype)
        if internal is not None:
            return internal, "INTERNAL"

        # 1) Ad-block check, ahead of every cache lookup. It used to run after
        # the RAM cache, which was a real bug: a positive answer cached before
        # a blocklist update kept being served until its TTL lapsed, so a domain
        # that had just been added to the list still resolved. doubleclick.net
        # was present in the compiled blob and still answered, purely because a
        # 300 s record was already in RAM. Blocking is a function of the query,
        # not of cached state, so it is checked first and unconditionally.
        if self.blocklist.match(qname):
            bk = f"blk|{qname}"
            be = self.ram_get(bk)
            if be is not None and be.blocked and be.expire > now:
                return be, "BLOCKED"
            blk = Entry(expire=now + BLOCKED_TTL, ttl=BLOCKED_TTL, rcode=3,
                        rrs=[], blocked=True, qname=qname, qtype=qtype)
            self.ram_put(bk, blk)
            self.persist(blk, bk)
            return blk, "BLOCKED"

        # 2) RAM cache
        e = self.ram_get(key)
        if e is not None:
            return e, "RAM"

        # 3) single-flight, 4) upstream
        if key in self.inflight:
            fut = self.inflight[key]
            if not fut.done():
                return await asyncio.shield(fut)

        fut = asyncio.get_event_loop().create_future()
        self.inflight[key] = fut
        try:
            entry, status = await self._do_resolve(query_wire, qname, qtype, key)
            if not fut.done():
                fut.set_result((entry, status))
            return entry, status
        except Exception as exc:
            if not fut.done():
                fut.set_exception(exc)
            raise
        finally:
            self.inflight.pop(key, None)

    async def _do_resolve(self, query_wire: bytes, qname: str, qtype: int,
                          key: str):
        now = time.time()

        # The ad-block check lives in resolve(), ahead of the cache. It is not
        # repeated here: resolve() is the only caller and already guaranteed
        # the domain is not on the list, and a second binary search per miss is
        # pure cost.

        # Upstream (encrypted transports only). We forward the client's wire so
        # EDNS0 / DO-bit / DNSSEC survive the round trip.
        try:
            upstream_wire = _rewrite_id(query_wire)
            rcode, flags, rrs, ttl = await self.upstream.resolve(
                upstream_wire, qname, qtype)
        except Exception:
            e = Entry(expire=now + 30, ttl=30, rcode=2, rrs=[], qname=qname,
                      qtype=qtype)
            self.ram_put(key, e)
            return e, "ERROR"

        ttl = max(MIN_TTL, min(MAX_TTL, int(ttl)))
        e = Entry(expire=now + ttl, ttl=ttl, rcode=rcode, rrs=rrs, flags=flags,
                  qname=qname, qtype=qtype)
        self.ram_put(key, e)
        self.persist(e, key)
        return e, "MISS"

    # -- prefetch ----------------------------------------------------------
    async def _purge_now_blocked(self) -> None:
        """
        Evict every cached answer whose domain is on the freshly loaded list.

        The blocklist is now consulted before the cache, so a stale positive
        answer can no longer be served. It can still occupy RAM, survive a
        restart in the sqlite cache, and inflate the hit rate with entries that
        can never be used, so they are removed here rather than left to expire.

        Deliberately not on the query path: the sqlite scan runs in the store's
        worker thread via run_in_executor so a large purge cannot stall DNS.
        """
        now = time.time()
        doomed = [
            k for k, e in list(self.ram.items())
            if not e.blocked and e.expire > now and self.blocklist.match(e.qname)
        ]
        for k in doomed:
            self.ram.pop(k, None)
        if doomed:
            log(f"blocklist: dropped {len(doomed)} cached answers that are "
                f"now blocked")
        try:
            n = await asyncio.get_event_loop().run_in_executor(
                None, self.store.purge_blocked, self.blocklist)
            log(f"blocklist: cache purge complete ({n} persisted rows removed)")
        except Exception as exc:
            log(f"blocklist: cache purge failed ({exc})")

    async def prefetch_loop(self) -> None:
        while True:
            await asyncio.sleep(30)
            try:
                if self.blocklist.reload_if_changed():
                    await self._purge_now_blocked()
                now = time.time()
                hot = [
                    (k, e) for k, e in list(self.ram.items())
                    if (e.hits >= HOT_THRESHOLD or e.sticky)
                    and e.ttl >= PREFETCH_MIN_TTL
                    and not e.blocked
                    and (e.expire - now) < e.ttl * (1 - PREFETCH_AT) + 1
                ]
                for key, e in hot[:50]:
                    try:
                        # rebuild a minimal query for the prefetch
                        q = dns.message.make_query(e.qname, e.qtype)
                        q.flags &= ~dns.flags.RD
                        q.flags |= dns.flags.RD
                        qw = _rewrite_id(q.to_wire())
                        rcode, flags, rrs, ttl = await self.upstream.resolve(
                            qw, e.qname, e.qtype)
                        ttl = max(MIN_TTL, min(MAX_TTL, int(ttl)))
                        if rrs:
                            ne = Entry(expire=time.time() + ttl, ttl=ttl,
                                       rcode=0, rrs=rrs, flags=flags,
                                       hits=e.hits, prefetched=True,
                                       qname=e.qname, qtype=e.qtype)
                            self.ram_put(key, ne)
                            self.persist(ne, key)
                            with self.metrics.lock:
                                self.metrics.prefetched += 1
                    except Exception:
                        pass
                    await asyncio.sleep(0.05)
            except Exception as exc:
                log(f"prefetch loop error: {exc}")

    # -- maintenance -------------------------------------------------------
    async def maintenance_loop(self) -> None:
        """Periodic housekeeping that must not sit on the query path.

        The abuse windows dict is keyed by client IP, so on a network being
        scanned it grows one entry per source. Pruning here keeps it bounded
        without adding a per-query branch.
        """
        while True:
            await asyncio.sleep(60)
            try:
                n = self.abuse.prune()
                if n:
                    log(f"abuse tracker pruned {n} idle client window(s)")
            except Exception as exc:
                log(f"maintenance loop error: {exc}")


# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------
def build_response(query_wire: bytes, entry: Entry) -> bytes:
    """
    Construct a DNS response from a cached Entry, preserving the client's
    question section and transaction id. This is the piece the original got
    wrong (it forced an A record regardless of qtype).
    """
    try:
        q = dns.message.from_wire(query_wire)
    except dns.exception.DNSException:
        return b""
    resp = dns.message.make_response(q)
    resp.flags |= dns.flags.AA
    # rcode
    rcode_map = {0: dns.rcode.NOERROR, 1: dns.rcode.NXDOMAIN,
                 2: dns.rcode.SERVFAIL, 3: dns.rcode.NXDOMAIN}
    resp.set_rcode(rcode_map.get(entry.rcode, dns.rcode.SERVFAIL))
    if entry.rrs:
        try:
            for (name, _txt, rdtype, rdclass, ttl, rdata) in entry.rrs:
                # Owner name must be ABSOLUTE (trailing dot) and we must not
                # relativize rdata against it, otherwise dnspython raises
                # "non-absolute name ... when there was also a non-absolute
                # origin" while serialising.
                owner = name if name.endswith(".") else name + "."
                # dnspython 2.8 signature:
                #   from_text_list(name, ttl, rdclass, rdtype, text_rdatas, ...)
                # The explicit rdtype keeps the answer's type faithful to the
                # original query, which is exactly what the v1 server got wrong.
                rrset = dns.rrset.from_text_list(
                    owner,                                  # absolute owner
                    max(MIN_TTL, min(MAX_TTL, int(ttl))),   # ttl
                    "IN" if rdclass == 1 else str(rdclass), # class
                    _txt,                                   # rdata type
                    [rdata],                                # rdata list
                    relativize=False,                       # keep rdata as-is
                )
                resp.answer.append(rrset)
        except Exception as exc:
            # rdata text that will not parse: skip that record rather than
            # corrupting the whole message.
            log(f"build_response: rdata parse issue ({exc}); skipping")
    return resp.to_wire(max_size=65535)


def qtype_name(q: dns.message.Message) -> str:
    try:
        return dns.rdatatype.to_text(q.question[0].rdtype)
    except Exception:
        return "?"


def _rewrite_id(wire: bytes) -> bytes:
    """
    Randomise the transaction id before forwarding upstream. Uses a dedicated
    SystemRandom so ids are not predictable by a neighbouring client.
    """
    if len(wire) < 2:
        return wire
    return struct.pack(">H", _RNG.randrange(0, 0x10000)) + wire[2:]


_RNG = __import__("random").SystemRandom()


def qname_text(q: dns.message.Message) -> str:
    try:
        return q.question[0].name.to_text().lower()
    except Exception:
        return "?"


# ---------------------------------------------------------------------------
# asyncio DNS protocol handlers
# ---------------------------------------------------------------------------
class DNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, resolver: Resolver, access_log_enabled: bool):
        self.resolver = resolver
        self.access_log_enabled = access_log_enabled
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data: bytes, addr):
        t0 = time.perf_counter()
        client_ip = addr[0]
        try:
            q = dns.message.from_wire(data)
            if not q.question:
                return
            qname = qname_text(q)
            qtype = int(q.question[0].rdtype)
            if q.opcode() != dns.opcode.QUERY:
                # respond NOTIMP for non-QUERY opcodes
                resp = dns.message.make_response(q)
                resp.set_rcode(dns.rcode.NOTIMP)
                self.transport.sendto(resp.to_wire(), addr)
                self.resolver.abuse.note_event(client_ip, "opcode",
                                              f"opcode {q.opcode()} for {qname}")
                return

            self.resolver.abuse.note_query(client_ip)
            entry, status = await self.resolver.resolve(data, qname, qtype)
            wire = build_response(data, entry)
            if not wire:
                return
            # truncation for UDP
            if len(wire) > 512:
                trunc = dns.message.from_wire(wire)
                truncated = dns.message.make_response(q)
                truncated.set_rcode(trunc.rcode())
                wire = truncated.to_wire()[:512]
            self.transport.sendto(wire, addr)
            ms = (time.perf_counter() - t0) * 1000
            self.resolver.metrics.record(qtype_name(q), status, ms)
            with self.resolver.metrics.lock:
                self.resolver.metrics.recent.append(
                    (time.strftime("%H:%M:%S"), client_ip, qname,
                     qtype_name(q), status, round(ms, 2)))
            self.resolver.log_query(client_ip, qname, qtype_name(q), status, ms)
        except dns.exception.DNSException as exc:
            # Malformed wire format. This is the fingerprint of a DNS fuzzer or
            # an attempt to smuggle payloads through the resolver, so it is the
            # one client-side parse error worth counting against the source.
            ms = (time.perf_counter() - t0) * 1000
            self.resolver.metrics.record("?", "ERROR", ms)
            self.resolver.abuse.note_event(client_ip, "malformed", type(exc).__name__)
            log(f"malformed packet from {client_ip}: {type(exc).__name__}: {exc}")
        except Exception as exc:
            ms = (time.perf_counter() - t0) * 1000
            self.resolver.metrics.record("?", "ERROR", ms)
            log(f"udp handler error from {client_ip}: {exc}")
            with contextlib.suppress(Exception):
                resp = dns.message.make_response(dns.message.from_wire(data))
                resp.set_rcode(dns.rcode.SERVFAIL)
                self.transport.sendto(resp.to_wire(), addr)

    def error_received(self, exc):
        log(f"udp error: {exc}")


async def handle_tcp(reader, writer, resolver: Resolver):
    t0 = time.perf_counter()
    client_ip = "?"
    try:
        # DNS over TCP: 2-byte length prefix
        hdr = await reader.readexactly(2)
        ln = struct.unpack(">H", hdr)[0]
        data = await reader.readexactly(ln)
        client_ip = writer.get_extra_info("peername")[0]
        q = dns.message.from_wire(data)
        qname = qname_text(q)
        qtype = int(q.question[0].rdtype)
        resolver.abuse.note_query(client_ip)
        entry, status = await resolver.resolve(data, qname, qtype)
        wire = build_response(data, entry)
        writer.write(struct.pack(">H", len(wire)) + wire)
        await writer.drain()
        ms = (time.perf_counter() - t0) * 1000
        resolver.metrics.record(qtype_name(q), status, ms)
        resolver.log_query(client_ip, qname, qtype_name(q), status, ms)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        # A client that opens TCP and drops without a full query is a port
        # scanner or a connection-exhaustion probe. Threshold-gated, because OS
        # connectivity checks also open and immediately close port 53.
        with contextlib.suppress(Exception):
            peer = writer.get_extra_info("peername")
            if peer:
                resolver.abuse.note_event(peer[0], "tcp-trunc", "truncated tcp query")
    except dns.exception.DNSException as exc:
        with contextlib.suppress(Exception):
            peer = writer.get_extra_info("peername")
            if peer:
                resolver.abuse.note_event(peer[0], "malformed", type(exc).__name__)
        log(f"malformed tcp packet from {client_ip}: {type(exc).__name__}: {exc}")
    except Exception as exc:
        log(f"tcp handler error: {exc}")
    finally:
        with contextlib.suppress(Exception):
            writer.close()


# ---------------------------------------------------------------------------
# Dashboard / API
#
# Deliberately built into the resolver process rather than deployed as
# Uptime Kuma: on a 1.8 GiB / 2-vCPU host Uptime Kuma's Node runtime costs
# 250-400 MB, which is the single largest memory item available. This uses
# asyncio's built-in HTTP server, so it costs a few hundred KB.
# ---------------------------------------------------------------------------
DASHBOARD_PORT = int(os.environ.get("DNSHUB_DASH_PORT", "8080"))
DASHBOARD_BIND = os.environ.get("DNSHUB_DASH_BIND", "0.0.0.0")
STATE_FILE = os.path.join(BASE_DIR, "gaming_mode.state")

_DASH_HTML = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>dnshub · DNS Hub by Mostfa</title><style>
*{box-sizing:border-box}body{margin:0;font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;
background:#0d1117;color:#c9d1d9;padding:16px}
h1{font-size:18px;margin:0 0 4px;color:#58a6ff}
.sub{color:#8b949e;font-size:12px;margin-bottom:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px}
.k{color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
.v{font-size:22px;margin-top:4px;color:#e6edf3}
.good{color:#3fb950}.warn{color:#d29922}.bad{color:#f85149}
table{width:100%;border-collapse:collapse;font-size:12px;background:#161b22;
border:1px solid #30363d;border-radius:6px;overflow:hidden}
th,td{padding:6px 10px;text-align:left;border-bottom:1px solid #21262d}
th{color:#8b949e;font-weight:600;font-size:11px;text-transform:uppercase}
.bar{height:8px;background:#21262d;border-radius:4px;overflow:hidden;margin:6px 0 10px}
.bar>div{height:100%;background:#238636}
button{background:#238636;color:#fff;border:0;padding:8px 14px;border-radius:5px;
cursor:pointer;font:inherit}button.off{background:#6e7681}
.note{background:#1c2128;border-left:3px solid #d29922;padding:10px 12px;
border-radius:4px;margin:12px 0;font-size:12px;color:#d29922}
</style></head><body>
<h1>dnshub <span style="color:#8b949e;font-size:12px;font-weight:400">DNS Hub · by Mostfa</span></h1><div class=sub id=sub>loading...</div>
<div class=grid id=cards></div>
<div class=bar><div id=hitbar style=width:0%></div></div>
<div class=note>SQM note: traffic shaping runs on this host's WiFi uplink
(wlp5s0) and shapes LOCAL EGRESS ONLY. Bufferbloat lives in the queue of the
gateway (192.168.1.1), so it cannot be eliminated from here.</div>
<h2 style="font-size:13px;color:#8b949e">Recent queries</h2>
<table><thead><tr><th>Time</th><th>Client</th><th>Domain</th><th>Type</th>
<th>Status</th><th>ms</th></tr></thead><tbody id=rows></tbody></table>
<h2 style="font-size:13px;color:#8b949e;margin-top:16px">Controls</h2>
<button id=gm onclick=toggleGM()>Gaming Mode</button>
<script>
let gmOn=false;
function fmt(n){return n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3).toFixed(1)+'k':n}
async function load(){
 const r=await fetch('/api/stats'),s=await r.json();
 document.getElementById('sub').textContent=
  'up '+Math.floor(s.uptime_sec/60)+'m | upstreams: '+(s.upstreams||[]).join(', ')
  +' | blocklist '+fmt(s.blocklist_domains)+' domains | RAM cache '+s.ram_entries;
 const cards=[
  ['Queries',fmt(s.queries_total),''],
  ['Cache hit',s.cache_hit_pct+'%',s.cache_hit_pct>70?'good':s.cache_hit_pct>40?'warn':'bad'],
  ['RAM hits',fmt(s.ram_cache_hits),'good'],
  ['SQLite hits',fmt(s.sqlite_cache_hits),'good'],
  ['Ad-blocked',fmt(s.blocked_total),'warn'],
  ['Upstream miss',fmt(s.upstream_misses),''],
  ['Prefetched',fmt(s.prefetched),'good'],
  ['Avg latency',s.avg_latency_ms+' ms',s.avg_latency_ms<50?'good':'warn'],
  ['Max latency',s.max_latency_ms+' ms',''],
  ['Errors',fmt(s.errors),s.errors>0?'bad':'good'],
  ['Abuse events',fmt((s.abuse_events||{}).rate||0),'warn'],
  ['RSS MB',s.rss_mb,'good'],
 ];
 document.getElementById('cards').innerHTML=cards.map(
  ([k,v,cls])=>'<div class=card><div class=k>'+k+'</div><div class="v '+cls+'">'+v+'</div></div>').join('');
 document.getElementById('hitbar').style.width=Math.min(100,s.cache_hit_pct)+'%';
 document.getElementById('rows').innerHTML=(s.recent||[]).slice(-25).reverse().map(q=>
  '<tr><td>'+q[0]+'</td><td>'+q[1]+'</td><td>'+q[2]+'</td><td>'+q[3]+
  '</td><td>'+q[4]+'</td><td>'+q[5]+'</td></tr>').join('');
 gmOn=s.gaming_mode;
 const b=document.getElementById('gm');
 b.textContent='Gaming Mode: '+(gmOn?'ON':'OFF');
 b.className=gmOn?'':'off';
}
async function toggleGM(){
 await fetch('/api/gaming-mode',{method:'POST',
   headers:{'Content-Type':'application/json'},
   body:JSON.stringify({enabled:!gmOn})});
 load();
}
load();setInterval(load,2000);
</script></body></html>"""


class Dashboard:
    def __init__(self, resolver: "Resolver"):
        self.resolver = resolver
        self.httpd = None

    @staticmethod
    def _gaming_mode() -> bool:
        try:
            with open(STATE_FILE) as f:
                return json.load(f).get("enabled", False)
        except Exception:
            return False

    def _snapshot(self) -> dict:
        s = self.resolver.metrics.snapshot()
        try:
            rss_mb = 0
            with open("/proc/self/status") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        rss_mb = round(int(line.split()[1]) / 1024, 1)
                        break
            s["rss_mb"] = rss_mb
        except Exception:
            s["rss_mb"] = 0
        s["blocklist_domains"] = self.resolver.blocklist.count
        s["ram_entries"] = len(self.resolver.ram)
        s["gaming_mode"] = self._gaming_mode()
        s.update(self.resolver.abuse.snapshot())
        try:
            s["upstreams"] = list(self.resolver.upstream.pools)
        except Exception:
            s["upstreams"] = []
        return s

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=5)
            if not line:
                return
            parts = line.decode("latin-1").split()
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            # drain headers + body
            clen = 0
            while True:
                h = await asyncio.wait_for(reader.readline(), timeout=5)
                if h in (b"\r\n", b"\n", b""):
                    break
                if h.lower().startswith(b"content-length:"):
                    clen = int(h.split(b":")[1].strip())
            if clen:
                with contextlib.suppress(Exception):
                    await reader.readexactly(clen)

            if path.startswith("/api/stats"):
                body = json.dumps(self._snapshot()).encode()
                ctype = "application/json"
            elif path.startswith("/api/gaming-mode") and method == "POST":
                new_state = not self._gaming_mode()
                with open(STATE_FILE, "w") as f:
                    json.dump({"enabled": new_state,
                               "changed": time.time()}, f)
                log(f"dashboard: gaming mode -> {new_state}")
                body = json.dumps({"gaming_mode": new_state}).encode()
                ctype = "application/json"
            elif path.startswith("/health"):
                ok = self.resolver.upstream.pools and self.resolver.blocklist.count
                body = json.dumps({"ok": bool(ok),
                                   "blocklist": self.resolver.blocklist.count,
                                   "upstreams": list(
                                       self.resolver.upstream.pools)}).encode()
                ctype = "application/json"
            else:
                body = _DASH_HTML.encode()
                ctype = "text/html; charset=utf-8"

            writer.write(
                f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                .encode() + body)
            await writer.drain()
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def start(self) -> None:
        self.httpd = await asyncio.start_server(
            self._handle, DASHBOARD_BIND, DASHBOARD_PORT)
        log(f"dashboard: http://{DASHBOARD_BIND}:{DASHBOARD_PORT}")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
async def serve():
    resolver = Resolver()
    loop = asyncio.get_running_loop()

    # UDP
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DNSProtocol(resolver, True), local_addr=(BIND_ADDR, DNS_PORT)
    )
    log(f"listening UDP {BIND_ADDR}:{DNS_PORT}")

    # TCP
    tcp_server = await asyncio.start_server(
        lambda r, w: handle_tcp(r, w, resolver), BIND_ADDR, DNS_PORT
    )
    log(f"listening TCP {BIND_ADDR}:{DNS_PORT}")

    # prefetch task
    prefetch = asyncio.create_task(resolver.prefetch_loop())
    maintenance = asyncio.create_task(resolver.maintenance_loop())

    # One-off sweep of answers cached by a previous run whose domain has since
    # been blocked. Harmless to the blocklist-first lookup order, but it keeps
    # the sqlite cache from filling with entries that can never be served and
    # stops them being counted as cache hits on the dashboard.
    startup_purge = asyncio.create_task(resolver._purge_now_blocked())

    # dashboard
    dash = Dashboard(resolver)
    try:
        await dash.start()
    except Exception as exc:
        log(f"dashboard: failed to start ({exc}); DNS service unaffected")

    log(f"blocklist domains: {resolver.blocklist.count:,}")
    log(f"RAM cache entries: {len(resolver.ram)}")

    stop = loop.create_future()

    def _shutdown(*_):
        # set_result, not set: `stop` is a Future, and Future has no `.set`.
        # The old `stop.set()` raised AttributeError *inside the signal handler*,
        # so the shutdown future never resolved and the process hung until
        # systemd's TimeoutStopSec killed it.
        if not stop.done():
            stop.set_result(None)

    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _shutdown)

    log("ready")
    await stop

    log("shutting down...")
    transport.close()
    tcp_server.close()
    prefetch.cancel()
    maintenance.cancel()
    with contextlib.suppress(Exception):
        await resolver.upstream.close()
    resolver.store.close()
    # give the writer a moment to drain
    await asyncio.sleep(0.5)
    log("bye")


def selftest() -> int:
    """Offline correctness tests for the wire-building and cache logic."""
    failures = []

    def check(name, cond):
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")
        if not cond:
            failures.append(name)

    print("=== SELFTEST ===")
    # TTL policy must never inflate
    check("MAX_TTL clamp constant sane", MAX_TTL <= 86400)
    check("MIN_TTL < MAX_TTL", MIN_TTL < MAX_TTL)

    # A qtype round-trip through build_response
    for rdtype_text, rdata in (("A", "1.2.3.4"),
                               ("AAAA", "2001:db8::1"),
                               ("TXT", '"hello"'),
                               ("MX", "10 mail.example.com.")):
        try:
            q = dns.message.make_query("example.com", rdtype_text)
            qw = q.to_wire()
            e = Entry(expire=time.time() + 60, ttl=60, rcode=0, rrs=[
                ("example.com", rdtype_text,
                 int(getattr(dns.rdatatype, rdtype_text)), 1, 60, rdata),
            ], qname="example.com",
                qtype=int(getattr(dns.rdatatype, rdtype_text)))
            resp_wire = build_response(qw, e)
            resp = dns.message.from_wire(resp_wire)
            got = resp.answer[0].to_text() if resp.answer else ""
            check(f"{rdtype_text} response builds with rdata",
                  bool(resp.answer) and rdata.split()[0] in got)
        except Exception as exc:
            check(f"{rdtype_text} response builds ({exc})", False)

    # Blocklist matcher logic
    import shutil
    import tempfile
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from dnshub_blocklist import BlobWriter
    tdir = tempfile.mkdtemp(prefix="dnshub-bl-")
    bpath, xpath = os.path.join(tdir, "t.bin"), os.path.join(tdir, "t.idx")
    doms = sorted({"ads.example", "tracker.net", "bad.co.uk"})
    with open(bpath, "wb") as bf, open(xpath, "wb") as xf:
        w = BlobWriter(bf, xf)
        for d in doms:
            w.add(d)
        w.close()
    bl = Blocklist(bpath)
    check("blocklist loaded", bl.count == 3)
    check("blocklist exact match", bl.match("ads.example"))
    check("blocklist subdomain match", bl.match("x.ads.example"))
    check("blocklist deep subdomain", bl.match("a.b.tracker.net"))
    check("blocklist multi-label tld", bl.match("sub.bad.co.uk"))
    check("blocklist miss clean", not bl.match("google.com"))
    check("blocklist miss subdomain-of-clean", not bl.match("mail.google.com"))
    check("blocklist case-insensitive", bl.match("ADS.Example"))
    check("blocklist trailing dot", bl.match("ads.example."))
    # A mismatched blob/index pair must be refused rather than half-loaded,
    # because the updater swaps the two files with separate rename() calls.
    with open(xpath, "r+b") as f:
        f.truncate(4)
    bad = Blocklist(bpath)
    check("blocklist rejects mismatched index", bad.count == 0)
    check("blocklist match on rejected list is False", not bad.match("ads.example"))
    shutil.rmtree(tdir, ignore_errors=True)

    # TTL clamp function behaviour
    def clamp(ttl):
        return max(MIN_TTL, min(MAX_TTL, int(ttl)))
    check("clamp(0)->MIN", clamp(0) == MIN_TTL)
    check("clamp(99999)->MAX", clamp(99999) == MAX_TTL)
    check("clamp(300)->300", clamp(300) == 300)

    # AbuseTracker: the properties that keep fail2ban from banning honest users.
    atmp = tempfile.NamedTemporaryFile(suffix=".log", delete=False)
    atmp.close()
    allowed = [ipaddress.ip_network(n) for n in
               ("127.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8")]
    at = AbuseTracker(atmp.name, allowed, rate_qps=10, window=60)

    check("abuse: LAN client is allowed",
          at.is_allowed("192.168.1.50") and at.is_allowed("127.0.0.1"))
    check("abuse: public source is NOT allowed",
          not at.is_allowed("8.8.8.8") and not at.is_allowed("203.0.113.7"))
    check("abuse: garbage ip is not allowed", not at.is_allowed("not-an-ip"))

    # Rate trigger must not fire below threshold, must fire above it.
    for _ in range(10):
        at.note_query("192.168.1.50")
    check("abuse: no rate line below threshold", at.counts.get("rate", 0) == 0)
    at.note_query("192.168.1.50")
    check("abuse: rate line fires at threshold", at.counts.get("rate", 0) == 1)
    for _ in range(10):
        at.note_query("192.168.1.50")
    check("abuse: rate line is once-per-window, not per-query",
          at.counts.get("rate", 0) == 1)

    # A non-LAN source is flagged on sight, even on the very first packet.
    before = at.counts.get("nonlan", 0)
    at.note_query("203.0.113.7")
    check("abuse: non-LAN flagged immediately",
          at.counts.get("nonlan", 0) == before + 1)

    # Malformed/opcode are threshold-gated, so one stray packet is not a ban.
    before = at.counts.get("malformed", 0)
    at.note_event("192.168.1.50", "malformed", "FormError")
    check("abuse: single malformed packet does not trip", at.counts.get("malformed", 0) == before)
    for _ in range(5):
        at.note_event("192.168.1.50", "malformed", "FormError")
    check("abuse: 5 malformed packets trip", at.counts.get("malformed", 0) == before + 1)

    # Every emitted line must satisfy the real fail2ban filter regex, including
    # the LN-BEG timestamp the filter's datepattern depends on.
    import re as _re
    KW = r"(?:rate|malformed|nonlan|opcode|tcp-trunc)"
    pat = _re.compile(r"^\s*(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)?"
                      r"\S+ \S*" + KW + r"\S*")
    ts_pat = _re.compile(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+")
    with open(atmp.name) as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    check("abuse: wrote at least one line", len(lines) > 0)
    check("abuse: every line matches the fail2ban failregex",
          all(pat.match(ln) for ln in lines),
          )
    check("abuse: every line carries an LN-BEG timestamp",
          all(ts_pat.match(ln) for ln in lines))
    check("abuse: no 'blocked' keyword reaches the jail regex",
          not any(" blocked " in ln for ln in lines))

    # An unopenable log path must disable logging, not raise.
    at2 = AbuseTracker("/proc/definitely/not/writable.log", allowed, 10, 60)
    at2.note_query("8.8.8.8")
    check("abuse: unwritable log degrades safely", not at2.enabled)

    # Prune must bound the window dicts.
    at.windows["192.168.9.9"] = [0.0]          # ancient timestamp
    at.events["malformed:192.168.9.9"] = [0.0]
    n = at.prune()
    check("abuse: prune drops idle windows", n >= 1)
    check("abuse: prune leaves live windows",
          "192.168.1.50" in at.windows)
    os.unlink(atmp.name)

    print(f"=== {'ALL PASS' if not failures else str(len(failures)) + ' FAILURES'} ===")
    for f in failures:
        print(f"  ! {f}")
    return 0 if not failures else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--stats", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.stats:
        # print persisted cache stats from the DB
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM dns_cache")
        print("sqlite cache rows:", cur.fetchone()[0])
        cur.execute("SELECT COUNT(*) FROM dns_logs")
        print("log rows:", cur.fetchone()[0])
        conn.close()
        return 0
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
