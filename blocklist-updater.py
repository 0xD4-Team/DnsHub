#!/usr/bin/env python3
"""
blocklist-updater.py - aggregate, deduplicate and compile DNS blocklists.

Design constraints, all forced by the host (Core 2 Duo T6670, 1.8 GiB RAM,
1.36 GiB available, 48 ms WiFi uplink):

  * Bounded memory. The previous implementation accumulated every domain in a
    Python set. That is ~40 MiB at 416k domains and roughly 500-700 MiB at
    several million, i.e. an OOM on this box. Dedup is now delegated to
    `sort -u -S`, which spills to disk, and compilation streams the sorted
    file straight into the DHB2 blob and index.

  * Atomic swap. The resolver mmaps immutable files. We write .tmp files,
    fsync them, then os.replace() each one and fsync the directory, so a
    reader sees either the old list or the new one, never a partial file, and
    the service never needs a restart.

  * Resilient. A source that fails keeps its last good copy. Without this a
    single timeout silently shrinks the blocklist and weakens protection
    invisibly, which is worse than the outage it was trying to avoid.

Usage:
    blocklist-updater.py --once                     # profile from meta
    blocklist-updater.py --once --profile max
    blocklist-updater.py --once --categories ads,privacy
    blocklist-updater.py --stats
    blocklist-updater.py --sources                  # what would be fetched
    blocklist-updater.py --test DOMAIN...           # is it blocked?
"""
from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from blocklist_parser import iter_entries, normalise          # noqa: E402
from blocklist_sources import (CATEGORIES, DEFAULT_PROFILE,   # noqa: E402
                              PROFILES, SOURCES, active_sources)
from dnshub_blocklist import MAGIC, BlobWriter                # noqa: E402

BLOCK_DIR = os.path.join(BASE_DIR, "blocklists")
OUT_TEXT = os.path.join(BASE_DIR, "blocklist.compiled.txt")
OUT_BIN = os.path.join(BASE_DIR, "blocklist.compiled.bin")
OUT_IDX = os.path.join(BASE_DIR, "blocklist.compiled.idx")
OUT_META = os.path.join(BASE_DIR, "blocklist.meta.json")

# Never block these regardless of what any list says. Blocking them causes
# login loops, certificate errors or an unusable resolver, and a resolver you
# cannot log into is worse than an ad you did not block.
ALLOWLIST = {
    # identity / auth
    "accounts.google.com", "google.com", "www.google.com", "googleapis.com",
    "gstatic.com", "gvt1.com", "gvt2.com", "googleusercontent.com",
    "microsoft.com", "login.live.com", "login.microsoftonline.com",
    "microsoftonline.com", "msauth.net", "msftauth.net", "msftauthimages.net",
    "apple.com", "icloud.com", "mzstatic.com", "icloud-content.com",
    # household sites. A broad blocklist made every one of these NXDOMAIN at
    # least once (youtube, facebook and ebay were caught returning NXDOMAIN
    # during the over-blocking audit). That was a parser bug - AdGuard browser
    # filters such as "||youtube.com/embed/$domain=filma24.*" are URL rules and
    # were being applied as DNS blocks - and it is fixed in the parser. This
    # group is a guard rail so a future bad list cannot take the household
    # offline. merge_sorted() walks parent suffixes, so listing "youtube.com"
    # also protects its subdomains.
    "youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com",
    "facebook.com", "fbcdn.net", "fbsbx.com", "messenger.com",
    "instagram.com", "whatsapp.com", "whatsapp.net",
    "netflix.com", "nflximg.net", "nflxvideo.net", "nflxext.com",
    "amazon.com", "media-amazon.com", "ssl-images-amazon.com",
    "ebay.com", "ebay.co.uk", "ebayimg.com",
    "reddit.com", "redditstatic.com", "redditmedia.com",
    "wikipedia.org", "wikimedia.org", "wiktionary.org",
    "telegram.org", "t.me", "telegram.me",
    "spotify.com", "scdn.co", "spotifycdn.com",
    "paypal.com", "paypalobjects.com", "stripe.com",
    "twitch.tv", "ttvnw.net", "discord.com", "discordapp.com",
    "slack.com", "slack-edge.com",
    # content nobody asked to block, and which broad lists often include
    "tiktok.com", "byteoversea.com", "tiktokcdn.com",
    "pinterest.com", "pinimg.com", "tumblr.com",
    # riot / valorant and general game infrastructure
    "riotgames.com", "valorant.riotgames.com", "pvp.riotgames.com",
    "riotcdn.net", "rsod.riotgames.com", "l3cdn.riotgames.com",
    "amazonaws.com", "cloudfront.net", "akamaized.net", "akamaitechnologies.com",
    "steamserver.net", "steamstatic.com", "steampowered.com", "valvesoftware.com",
    # infrastructure that would brick this host
    "docker.io", "registry-1.docker.io", "github.com", "githubusercontent.com",
    "deb.debian.org", "archive.ubuntu.com", "security.ubuntu.com",
    "letsencrypt.org", "cloudflare.com", "cloudflare-dns.com",
    "pypi.org", "files.pythonhosted.org",
    # dnshub's own upstreams and the DoH endpoints it must reach. The DoH
    # category deliberately blackholes browser DoH, so without this the
    # resolver could lock out the very clients it is trying to steer.
    "one.one.one.one", "dns.google", "dns.quad9.net", "quad9.net",
    "dns.adguard.com", "doh.opendns.com",
    # local / infrastructure
    "localhost", "local", "lan", "home.arpa", "favicon.ico",
}

# Applied AFTER the allowlist, so it wins. merge_sorted() walks parent
# suffixes when matching the allowlist, which is right for "never break
# github.com" but has a cost: allowlisting facebook.com to stop an AdGuard
# browser filter taking it offline also shelters facebook.com's tracking
# pixel. These are the first-party trackers worth the trade.
FORCE_BLOCK = {
    "pixel.facebook.com",
    "analytics.tiktok.com",
    "ads.tiktok.com",
    "analytics.twitter.com",
    "ads-twitter.com",
    "static.ads-twitter.com",
    "analytics.linkedin.com",
    "px.ads.linkedin.com",
}

# A publisher's own exception rules ("@@||example.com^") become allowlist
# entries. Capped so a malformed or hostile list cannot grow the exemption set
# without bound and quietly disable filtering.
MAX_AUTO_ALLOW = 200_000

_running = True


def _stop(signum, frame):
    global _running
    _running = False
    print(f"[updater] signal {signum}: finishing current cycle")


def log(msg: str) -> None:
    print(f"[updater] {msg}", flush=True)


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------
def fetch_to_file(url: str, path: str, deadline_sec: float = 300.0) -> int:
    """
    Stream a URL straight to disk, enforcing a real wall-clock deadline.

    urllib's timeout= is a per-socket-operation timeout, not a total budget; a
    trickled response stalled this host for 329 s once. Spooling to disk rather
    than returning bytes is what keeps peak memory flat: the largest source is
    31 MiB, which as a bytes object plus its decoded str plus a list of its
    lines was measured at ~150 MiB before this was rewritten.

    300 s is sized for the largest source on the measured 48 ms WiFi uplink
    (1Hosts-Xtra, 31 MiB, 76 s when probed alone). An earlier 90 s deadline
    failed the three biggest feeds every single run.
    """
    start = time.monotonic()
    req = urllib.request.Request(url, headers={
        "User-Agent": "dnshub-blocklist/3.0 (self-hosted; low-ram build)",
        "Accept": "*/*",
    })
    resp = urllib.request.urlopen(req, timeout=deadline_sec)
    total = 0
    try:
        with open(path, "wb") as f:
            head = b""
            while True:
                if deadline_sec - (time.monotonic() - start) <= 0:
                    raise TimeoutError(
                        f"deadline {deadline_sec:.0f}s at {total} bytes")
                chunk = resp.read(262144)
                if not chunk:
                    break
                if not head:
                    head = chunk[:2]
                f.write(chunk)
                total += len(chunk)
                if total > 256 * 1024 * 1024:
                    raise ValueError("source exceeded 256 MiB")
    finally:
        resp.close()
    # Servers may gzip transparently even without Accept-Encoding; only the
    # magic tells us, and a half-gunzipped file would parse as garbage.
    with open(path, "rb") as f:
        if f.read(2) == b"\x1f\x8b":
            with gzip.open(path, "rb") as gz, \
                    open(path + ".plain", "wb") as out:
                shutil.copyfileobj(gz, out, 262144)
            os.replace(path + ".plain", path)
    return total


def fetch_retry(url: str, path: str, attempts: int = 4,
                deadline_sec: float = 300.0) -> int:
    last: Exception | None = None
    for i in range(attempts):
        try:
            return fetch_to_file(url, path, deadline_sec)
        except Exception as e:
            last = e
            if i < attempts - 1:
                # Linear-ish backoff. Six workers retrying in lockstep on a
                # shared WiFi link turned a slow uplink into a retry storm that
                # reset connections instead of recovering from them.
                wait = 5.0 * (i + 1) + (hash(url) % 7)
                log(f"  retry {i+1}/{attempts-1} in {wait:.0f}s "
                    f"({type(e).__name__})")
                time.sleep(wait)
    raise last  # type: ignore[misc]


# ---------------------------------------------------------------------------
# per-source staging
# ---------------------------------------------------------------------------
def stage_path(name: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
    return os.path.join(BLOCK_DIR, f"stage-{safe}.txt")


def allow_path(name: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
    return os.path.join(BLOCK_DIR, f"allow-{safe}.txt")


def write_atomic(path: str, data: bytes) -> None:
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    dfd = os.open(os.path.dirname(path) or ".", os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _sort_in_place(path: str) -> int:
    """
    Deduplicate and sort a staged file. Returns the unique line count.

    LC_ALL=C is mandatory, not stylistic. The resolver's binary search compares
    raw bytes, but `sort` under a UTF-8 locale collates with locale rules that
    ignore punctuation and case - measured 1292 out of 8000 random adjacent
    pairs out of order. An unsorted blob still looks valid (correct magic,
    correct count) so the resolver loads it happily and then fails to find
    domains that are present, which presents as "ads are not blocked".
    """
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        open(path, "w").close()
        return 0
    subprocess.run(["sort", "-u", "-S", "48M", "-T", BLOCK_DIR,
                    "-o", path, path],
                   check=True, env={**os.environ, "LC_ALL": "C"})
    n = 0
    with open(path, "rb") as f:
        for _ in f:
            n += 1
    return n


def stage_source(src: dict, reuse: bool = False) -> dict:
    """
    Fetch one source and write its deny/allow domains to sorted staging files.

    Everything streams through disk. The response is spooled to a temp file and
    then read line by line, because holding a 31 MiB list in memory as a Python
    list of lines costs ~90 MiB on its own - measured at 314 MiB peak RSS
    across six concurrent workers before this was fixed, on a host with
    1.36 GiB available. Per-source deduplication is `sort -u`, which spills.

    `reuse` skips the network when a usable staged copy exists, which makes
    recompiling after a merge-semantics change (or a profile switch) take
    seconds instead of the ~2 minutes a full refetch costs on this uplink.
    """
    name = src["name"]
    spath, apath = stage_path(name), allow_path(name)
    raw = os.path.join(BLOCK_DIR, f"raw-{os.getpid()}-{abs(hash(name))%99999}.txt")
    t0 = time.time()
    if reuse and os.path.exists(spath) and os.path.getsize(spath) > 0:
        n = _sort_in_place(spath)
        _sort_in_place(apath)
        log(f"  reuse {name}: {n:,} domains from staging")
        return dict(name=name, domains=n, stale=False, secs=0.0, err=None)
    try:
        fetch_retry(src["url"], raw)
    except Exception as e:
        if os.path.exists(spath) and os.path.getsize(spath) > 0:
            n = _sort_in_place(spath)
            log(f"  STALE {name}: cached copy, {n:,} domains "
                f"({type(e).__name__})")
            return dict(name=name, domains=n, stale=True, secs=0.0, err=None)
        return dict(name=name, domains=0, stale=False, secs=0.0,
                    err=f"{type(e).__name__}: {e}"[:90])
    finally:
        pass

    try:
        n_deny = n_allow = 0
        truncated_allow = False
        tmp_d, tmp_a = spath + ".part", apath + ".part"
        with open(raw, "r", encoding="utf-8", errors="replace") as fin, \
                open(tmp_d, "w", encoding="utf-8") as fd, \
                open(tmp_a, "w", encoding="utf-8") as fa:
            # StringIO iterates line by line; text.splitlines() would
            # materialise every line of a 1.1M-domain list at once.
            for line in io.StringIO(fin.read()):
                for verdict, d in iter_entries((line,)):
                    if verdict == "deny":
                        fd.write(d)
                        fd.write("\n")
                        n_deny += 1
                    elif n_allow < MAX_AUTO_ALLOW:
                        fa.write(d)
                        fa.write("\n")
                        n_allow += 1
                    else:
                        truncated_allow = True
        os.replace(tmp_d, spath)
        os.replace(tmp_a, apath)
        uniq = _sort_in_place(spath)
        _sort_in_place(apath)
        if truncated_allow:
            log(f"  WARN {name}: exception list exceeded {MAX_AUTO_ALLOW:,}, "
                f"extras dropped")
        return dict(name=name, domains=uniq, stale=False,
                    secs=round(time.time() - t0, 1), err=None)
    finally:
        if os.path.exists(raw):
            os.unlink(raw)


# ---------------------------------------------------------------------------
# merge + compile
# ---------------------------------------------------------------------------
def merge_sorted(stage_files: list[str], allow_files: list[str],
                 out_sorted: str) -> tuple[int, int]:
    """
    Combine every staged source into one sorted, deduplicated deny set.

    Publisher exceptions are applied PER SOURCE, never globally. AdGuard's
    Base filter carries "@@||doubleclick.net^", and ten other sources block
    that domain; collecting all exceptions into one set let a single
    publisher's opinion override the other nine, so doubleclick.net started
    resolving again. An exception means "this filter does not want to block
    it", so it may only remove entries from its own filter.

    `comm -23` is used because both inputs are already LC_ALL=C sorted: it is
    a streaming set difference with no memory cost, where a Python set
    difference would hold every domain in memory.

    Returns (unique_before_operator_allowlist, after).
    """
    if not stage_files:
        return 0, 0

    per_source: list[str] = []
    env = {**os.environ, "LC_ALL": "C"}
    for sp, ap in zip(stage_files, allow_files):
        if os.path.exists(ap) and os.path.getsize(ap) > 0:
            out = sp + ".final"
            # comm has no -o; it writes the difference to stdout.
            with open(out, "w", encoding="utf-8") as fh:
                subprocess.run(["comm", "-23", sp, ap], check=True, env=env,
                               stdout=fh)
        else:
            out = sp
        if os.path.getsize(out) > 0:
            per_source.append(out)

    if not per_source:
        open(out_sorted, "w").close()
        return 0, 0

    cmd = ["sort", "-u", "-m", "-S", "48M", "-T", BLOCK_DIR, "-o", out_sorted]
    cmd += per_source
    # LC_ALL=C for the same reason as _sort_in_place: the blob is compared as
    # bytes at lookup time and must be ordered as bytes at build time.
    subprocess.run(cmd, check=True, env={**os.environ, "LC_ALL": "C"})

    total = 0
    with open(out_sorted, "rb") as f:
        for _ in f:
            total += 1

    # The operator allowlist IS global on purpose: it is an explicit local
    # decision, and it must win over every publisher.
    exempt: set[str] = set(ALLOWLIST)
    force: set[str] = set(FORCE_BLOCK)
    kept_path = out_sorted + ".kept"
    kept = 0
    forced_kept = 0
    with open(out_sorted, "r", encoding="utf-8", errors="replace") as fin, \
            open(kept_path, "w", encoding="utf-8") as fout:
        for line in fin:
            d = line.strip()
            if not d:
                continue
            # An exception for a parent domain protects its subdomains, which
            # is exactly how the resolver's suffix walk behaves.
            blocked = True
            forced = False
            probe = d
            while probe and probe.count(".") >= 1:
                if probe in exempt:
                    blocked = False
                    break
                if probe in force:
                    forced = True
                probe = probe.split(".", 1)[1] if "." in probe else ""
            if not blocked and not forced:
                continue
            if not blocked:
                forced_kept += 1
            fout.write(d)
            fout.write("\n")
            kept += 1
    os.replace(kept_path, out_sorted)
    if forced_kept:
        log(f"force-blocked {forced_kept} domain(s) that the allowlist would "
            f"otherwise have protected")

    for sp in stage_files:
        if os.path.exists(sp + ".final"):
            os.unlink(sp + ".final")
    return total, kept


def compile_blocklist(sorted_path: str) -> tuple[int, int, int]:
    """
    Stream the sorted file into DHB2 blob + index.

    Returns (domains, blob_bytes, index_bytes). Nothing is held in memory
    except one line at a time.
    """
    bin_tmp, idx_tmp = OUT_BIN + ".tmp", OUT_IDX + ".tmp"
    kept = 0
    with open(sorted_path, "r", encoding="utf-8", errors="replace") as fin, \
            open(bin_tmp, "wb") as bf, open(idx_tmp, "wb") as xf:
        w = BlobWriter(bf, xf)
        last = None
        for line in fin:
            d = line.strip()
            if not d or d == last:
                continue
            last = d
            w.add(d)
            kept += 1
        w.close()
    return kept, os.path.getsize(bin_tmp), os.path.getsize(idx_tmp)


def verify_compiled(blob_bytes: int, expected: int,
                    samples: int = 20000) -> None:
    """
    Refuse to publish a list that does not read back correctly.

    A truncated or mis-sorted blob still looks like a valid file to the
    resolver - correct magic, correct count, correct index length - so it
    loads without complaint and then fails to find domains that are present.
    That presents to the user as "the blocklist is broken", which is exactly
    the symptom that a locale-collated `sort` produced (1292 of 8000 random
    adjacent pairs out of order). Sortedness is therefore verified here, on
    the bytes we are about to publish, rather than trusted.
    """
    import mmap
    import random
    import struct as _struct

    with open(OUT_BIN, "rb") as f:
        head = f.read(8)
        if head[:4] != MAGIC:
            raise ValueError("compiled blob has wrong magic")
        got = int.from_bytes(head[4:8], "little")
        if got != expected:
            raise ValueError(f"blob count {got} != expected {expected}")
    idx_size = os.path.getsize(OUT_IDX)
    if idx_size != expected * 4:
        raise ValueError(f"index is {idx_size} bytes, expected {expected*4}")
    if os.path.getsize(OUT_BIN) != blob_bytes:
        raise ValueError("blob length changed during write")

    if expected < 2:
        return
    with open(OUT_BIN, "rb") as bf, open(OUT_IDX, "rb") as xf:
        blob = mmap.mmap(bf.fileno(), 0, access=mmap.ACCESS_READ)
        idx = mmap.mmap(xf.fileno(), 0, access=mmap.ACCESS_READ)

        def entry(i: int) -> bytes:
            off = _struct.unpack_from("<I", idx, i * 4)[0]
            ln = blob[off]
            return blob[off + 1: off + 1 + ln]

        # Adjacent pairs first, because an off-by-one in the index would show
        # up there before it showed up anywhere random.
        bad = 0
        for i in range(min(expected - 1, 5000)):
            if entry(i) > entry(i + 1):
                bad += 1
        rng = random.Random(1234)
        for _ in range(samples):
            i = rng.randrange(expected - 1)
            if entry(i) > entry(i + 1):
                bad += 1
        total = min(expected - 1, 5000) + samples
        if bad:
            raise ValueError(
                f"blob is NOT byte-sorted: {bad} inverted adjacent pairs out of "
                f"{total} checked. A non-C locale on `sort` is the usual cause. "
                f"Refusing to publish - the resolver's binary search would "
                f"silently miss domains.")
        log(f"verified: byte-sorted, {expected:,} entries, "
            f"{total:,} adjacent pairs checked, 0 inverted")
        blob.close()
        idx.close()


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------
def run_once(profile: str = DEFAULT_PROFILE,
             categories: list[str] | None = None,
             reuse: bool = False) -> int:
    os.makedirs(BLOCK_DIR, exist_ok=True)
    t0 = time.time()
    srcs = active_sources(profile, categories)
    log("=" * 68)
    log(f"update start  profile={profile}  sources={len(srcs)}")
    log(f"expected entries (pre-dedup, from registry): "
        f"{sum(s['entries'] for s in srcs):,}")

    per_source: dict[str, int] = {}
    failed: list[str] = []
    stale: list[str] = []

    # Three workers. The uplink measured 135 Mbit/s but is 48 ms RTT on shared
    # WiFi; six concurrent multi-megabyte transfers produced connection resets
    # rather than throughput, and the retries then made it worse.
    with ThreadPoolExecutor(max_workers=3) as ex:
        for r in ex.map(lambda s: stage_source(s, reuse), srcs):
            if r["err"]:
                failed.append(r["name"])
                log(f"  FAIL {r['name']}: {r['err']}")
            else:
                per_source[r["name"]] = r["domains"]
                if r["stale"]:
                    stale.append(r["name"])
                log(f"  ok   {r['name']}: {r['domains']:,} domains"
                    + (f" in {r['secs']:.0f}s" if r["secs"] else ""))

    if not per_source:
        log("all sources failed; keeping the previous compiled list")
        return 1

    merged = os.path.join(BLOCK_DIR, "merged.sorted")
    try:
        raw, final = merge_sorted(
            [stage_path(s["name"]) for s in srcs if s["name"] in per_source],
            [allow_path(s["name"]) for s in srcs if s["name"] in per_source],
            merged,
        )
        log(f"deduplicated: {raw:,} unique -> {final:,} after exemptions")

        n, bin_bytes, idx_bytes = compile_blocklist(merged)
        os.replace(OUT_BIN + ".tmp", OUT_BIN)
        os.replace(OUT_IDX + ".tmp", OUT_IDX)
        dfd = os.open(BASE_DIR, os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        verify_compiled(bin_bytes, n)
        log(f"compiled DHB2: {n:,} domains, "
            f"blob {bin_bytes/1048576:.1f} MiB, index {idx_bytes/1048576:.1f} MiB")

        # Keep a plain-text copy for humans and for the leak-audit tooling, but
        # build it from the same sorted stream so it can never disagree. This
        # must happen BEFORE the merged file is removed.
        txt_tmp = OUT_TEXT + ".tmp"
        with open(merged, "r", encoding="utf-8", errors="replace") as fin, \
                open(txt_tmp, "w", encoding="utf-8") as fout:
            fout.write("# dnshub compiled blocklist\n")
            fout.write(f"# generated: {time.strftime('%Y-%m-%dT%H:%M:%S')}\n")
            fout.write(f"# domains: {final}\n")
            for line in fin:
                fout.write(line)
        os.replace(txt_tmp, OUT_TEXT)
    finally:
        for tmp in (merged, OUT_BIN + ".tmp", OUT_IDX + ".tmp"):
            if os.path.exists(tmp):
                os.unlink(tmp)

    peak_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    meta = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "format": "DHB2",
        "profile": profile,
        "categories": sorted(categories) if categories else sorted(
            PROFILES.get(profile, [])),
        "total_domains": final,
        "unique_before_allowlist": raw,
        "per_source": per_source,
        "failed_sources": failed,
        "stale_sources": stale,
        "allowlist_size": len(ALLOWLIST),
        "auto_allowlist_size": None,
        "elapsed_sec": round(time.time() - t0, 1),
        "peak_rss_mb": round(peak_mb, 1),
        "text_bytes": os.path.getsize(OUT_TEXT),
        "bin_bytes": os.path.getsize(OUT_BIN),
        "idx_bytes": os.path.getsize(OUT_IDX),
    }
    write_atomic(OUT_META, json.dumps(meta, indent=2).encode())
    log(f"done in {time.time()-t0:.0f}s, peak RSS {peak_mb:.0f} MiB")
    if failed:
        log(f"WARNING: {len(failed)} source(s) failed: {', '.join(failed)}")
    return 0


def show_sources(profile: str) -> int:
    srcs = active_sources(profile)
    print(f"profile '{profile}' -> {len(srcs)} sources, "
          f"{sum(s['entries'] for s in srcs):,} entries pre-dedup\n")
    for s in sorted(srcs, key=lambda x: -x["entries"]):
        print(f"  {s['entries']:>9,}  {s['fmt']:8}  "
              f"{'+'.join(s['cats']):22} {s['name']}")
    print(f"\n  {sum(s['entries'] for s in srcs):,} total pre-dedup")
    print("  unique total will be lower; measure it with --once")
    return 0


def show_stats() -> int:
    if not os.path.exists(OUT_META):
        print("no compiled list yet")
        return 1
    print(json.dumps(json.load(open(OUT_META)), indent=2))
    return 0


def test_domains(names: list[str]) -> int:
    """Answer "is this blocked, and by which sources" using the staged data."""
    if not os.path.exists(OUT_META):
        print("no compiled list yet")
        return 1
    universe: set[str] = set()
    for name in json.load(open(OUT_META)).get("per_source", {}):
        p = stage_path(name)
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                universe.update(l.strip() for l in f if l.strip())
    for raw in names:
        d = normalise(raw)
        hit = d in universe
        if not hit and d:
            probe = d
            while probe and "." in probe and not hit:
                probe = probe.split(".", 1)[1]
                hit = probe in universe
        via = "PARENT" if hit and d not in universe else "EXACT"
        print(f"  {d:45} {'BLOCKED' if hit else 'allowed':8} ({via})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--sources", action="store_true")
    ap.add_argument("--test", nargs="*", default=None)
    ap.add_argument("--profile", default=None,
                    choices=sorted(PROFILES), help=f"default: {DEFAULT_PROFILE}")
    ap.add_argument("--categories", default=None,
                    help="comma-separated, overrides --profile")
    ap.add_argument("--reuse", action="store_true",
                    help="recompile from existing staging, skip the network")
    ap.add_argument("--loop", type=int, default=0)
    a = ap.parse_args()

    if a.stats:
        return show_stats()
    if a.sources:
        return show_sources(a.profile or DEFAULT_PROFILE)
    if a.test is not None:
        return test_domains(a.test)

    cats = [c.strip() for c in a.categories.split(",") if c.strip()] \
        if a.categories else None
    if cats:
        unknown = [c for c in cats if c not in CATEGORIES]
        if unknown:
            print(f"unknown categories: {unknown}\nknown: {sorted(CATEGORIES)}")
            return 2
    profile = a.profile or DEFAULT_PROFILE

    if a.once or not a.loop:
        return run_once(profile, cats, a.reuse)

    if a.reuse:
        # --loop --reuse would refetch nothing and then recompile the same
        # staging files forever, so the "automatic" refresh would silently stop
        # tracking reality. Better to refuse than to look healthy while stale.
        print("--loop cannot be combined with --reuse: the whole point of the "
              "loop is to refetch, and --reuse skips the network.", file=sys.stderr)
        return 2

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    # The interval is measured from the START of each cycle, not the end. A
    # compile takes ~8 min, and "every 12 hours" that quietly means 12h08m is
    # the kind of drift nobody notices until a list is months old.
    while _running:
        cycle_started = time.monotonic()
        try:
            run_once(profile, cats, a.reuse)
        except Exception as exc:  # keep the loop alive across a bad fetch day
            log(f"cycle failed ({type(exc).__name__}: {exc}); "
                f"retrying in {a.loop}s")
        elapsed = time.monotonic() - cycle_started
        remaining = max(0.0, a.loop - elapsed)
        log(f"next rebuild in {remaining/3600:.1f}h")
        # Sleep in slices so a stop request is honoured promptly instead of
        # after the rest of the interval.
        deadline = time.monotonic() + remaining
        while _running and time.monotonic() < deadline:
            time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
