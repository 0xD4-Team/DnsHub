#!/usr/bin/env python3
"""
dnshub-control - the control plane web UI.

Everything the household needs to see and change lives here: service cards with
on/off switches, live logs, the blocklist registry, and a doctor that explains
what is wrong in plain language.

Design constraints, all of them forced by the host:

  * 1.8 GiB of RAM and 2 vCPU, already running the resolver. So this is
    stdlib asyncio, not Flask/FastAPI/uvicorn, and it holds no persistent
    state in memory.
  * No pip install. `dns` is the only third-party module on the box.
  * It cannot be root: a web server with root on a LAN is the worst thing you
    can put on a home network. Every privileged action is a call out to
    dnshub-ctl, which is the only binary in the sudoers drop-in.
  * The panel is LAN-only and intentionally open: the product is a home-lab DNS
    box, and a client that can reach the panel already has LAN access to every
    other service on the box. If the box is ever exposed to a WAN, put the
    panel behind a proxy that adds auth - out of the box it trusts the LAN the
    way the WiFi itself does.
"""
from __future__ import annotations

import asyncio
import contextlib
import html
import json
import os
import shlex
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import unquote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PORT = int(os.environ.get("DNSHUB_CTL_PORT", "8081"))
BIND = os.environ.get("DNSHUB_CTL_BIND", "0.0.0.0")
CTL = os.environ.get("DNSHUB_CTL_BIN", "/usr/local/sbin/dnshub-ctl")
DEV_DIR = os.environ.get("DNSHUB_DEV_DIR",
                          os.path.dirname(os.path.abspath(__file__)))
REQUEST_TIMEOUT = 25
MAX_BODY = 64 * 1024

# Mirrors dnshub-ctl's UNITS keys. dnshub-ctl is the authority and refuses
# anything not in its own table; this copy exists only so the page can render
# every card in one pass instead of eight sequential round trips. A stale entry
# here shows up as a card with no data rather than as silent wrongness.
CTL_UNITS = ("resolver", "blocklist", "control", "files", "privacy", "fail2ban",
             "chrony", "unbound", "wireguard", "netdata")


def log(msg: str) -> None:
    sys.stdout.write(f"[{time.strftime('%H:%M:%S')}] ctl: {msg}\n")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# privileged actions
# ---------------------------------------------------------------------------
async def run_ctl(*args: str) -> tuple[int, str, str]:
    """Invoke the sudoers-whitelisted helper. Never a shell, always a list, so
    nothing in `args` can be reinterpreted as syntax."""
    argv = ["sudo", "-n", CTL, *args]
    try:
        p = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL)
        try:
            out, err = await asyncio.wait_for(p.communicate(), REQUEST_TIMEOUT)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                p.kill()
            return 124, "", f"{' '.join(args)}: timed out after {REQUEST_TIMEOUT}s"
    except FileNotFoundError as e:
        return 127, "", f"cannot run the helper: {e}"
    return (p.returncode,
            out.decode("utf-8", "replace"),
            err.decode("utf-8", "replace").strip())


# ---------------------------------------------------------------------------
# system facts, read from /proc because psutil is not installed
# ---------------------------------------------------------------------------
def read_mem() -> dict:
    info: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, _, v = line.partition(":")
            parts = v.split()
            if parts and parts[0].isdigit():
                info[k] = int(parts[0])
        return {
            "total_mb": info.get("MemTotal", 0) // 1024,
            "avail_mb": info.get("MemAvailable", 0) // 1024,
            "used_mb": (info.get("MemTotal", 0) - info.get("MemAvailable", 0)) // 1024,
        }
    except OSError:
        return {"total_mb": 0, "avail_mb": 0, "used_mb": 0}


def read_load() -> list[float]:
    try:
        return [round(x, 2) for x in os.getloadavg()]
    except OSError:
        return [0.0, 0.0, 0.0]


async def unit_states() -> list[dict]:
    """Ask the helper for every unit in one pass. It has to be one pass: seven
    units times a two-fork systemctl each is a visibly slow page load."""
    keys = list(CTL_UNITS)
    results = await asyncio.gather(*(run_ctl("status", k) for k in keys))
    units = []
    for key, (rc, out, err) in zip(keys, results):
        try:
            data = json.loads(out.strip() or "{}")
        except json.JSONDecodeError:
            data = {}
        if not data:
            data = {"exists": False, "active": "unknown",
                    "error": err or f"helper returned {rc}"}
        data["key"] = key
        data.setdefault("label", key)
        data.setdefault("desc", "")
        units.append(data)
    return units


def blocklist_info() -> dict:
    base = Path(DEV_DIR)
    info: dict = {"meta": None, "sources": [], "counts": {}}
    try:
        info["meta"] = json.loads((base / "blocklist.meta.json").read_text())
    except (OSError, json.JSONDecodeError):
        pass
    for name, path in (("blob", "blocklist.compiled.bin"),
                       ("index", "blocklist.compiled.idx")):
        try:
            info["counts"][name] = (base / path).stat().st_size
        except OSError:
            info["counts"][name] = 0
    try:
        sys.path.insert(0, str(base))
        import blocklist_sources as bs  # noqa: PLC0415
        # SOURCES is a list of plain dicts, and CATEGORIES maps a category name
        # to its human description. An earlier version read them as dataclass
        # attributes and a category list, so the blocklist tab rendered "0
        # registered sources" next to a real AttributeError in the corner.
        info["categories"] = bs.CATEGORIES
        info["profiles"] = {k: sorted(v) for k, v in bs.PROFILES.items()}
        info["default_profile"] = bs.DEFAULT_PROFILE
        rows = []
        for s in bs.SOURCES:
            if not isinstance(s, dict):
                # Tolerate a future dataclass rather than crashing the tab.
                s = {k: getattr(s, k, None) for k in
                     ("name", "url", "cats", "entries", "fmt")}
            rows.append({
                "name": s.get("name", "?"),
                "url": s.get("url", ""),
                "categories": s.get("cats", s.get("category", [])),
                "entries": s.get("entries", 0),
                "format": s.get("fmt", ""),
                "superseded_by": s.get("superseded_by"),
                "doh": bool(s.get("doh_blocklist")),
            })
        info["sources"] = rows
    except Exception as e:  # the registry is a nice-to-have, never fatal
        info["sources_error"] = f"{type(e).__name__}: {e}"
    return info


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
STATUS_TEXT = {200: "OK", 400: "Bad Request", 401: "Unauthorized",
               403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
               413: "Payload Too Large", 429: "Too Many Requests",
               500: "Internal Server Error", 502: "Bad Gateway",
               504: "Gateway Timeout"}


class Request:
    __slots__ = ("method", "path", "query", "headers", "body", "peer")

    def __init__(self, method, path, query, headers, body, peer):
        self.method, self.path, self.query = method, path, query
        self.headers, self.body, self.peer = headers, body, peer

    def json(self) -> dict:
        if not self.body:
            return {}
        try:
            v = json.loads(self.body)
            return v if isinstance(v, dict) else {}
        except json.JSONDecodeError:
            return {}


async def handle(reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter) -> None:
    peer = "-"
    try:
        peer = writer.get_extra_info("peername")
        peer = peer[0] if peer else "-"
    except Exception:
        pass
    try:
        req = await read_request(reader, peer)
        if req is None:
            return
        code, ctype, body = await route(req)
        await respond(writer, code, ctype, body)
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    except Exception as exc:
        log(f"unhandled from {peer}: {type(exc).__name__}: {exc}")
        with contextlib.suppress(Exception):
            await respond(writer, 500, "application/json",
                          json.dumps({"error": "internal"}).encode())
    finally:
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()


async def read_request(reader: asyncio.StreamReader,
                       peer: str) -> Request | None:
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=10)
    except asyncio.TimeoutError:
        return None
    if not line:
        return None
    try:
        parts = line.decode("latin-1").rstrip("\r\n").split()
        if len(parts) < 2:
            return None
        method, raw = parts[0].upper(), parts[1]
    except UnicodeDecodeError:
        return None
    path, _, qs = raw.partition("?")
    query = {}
    for pair in qs.split("&"):
        if "=" in pair:
            k, _, v = pair.partition("=")
            query[unquote(k)] = unquote(v)
    headers: dict[str, str] = {}
    while True:
        h = await asyncio.wait_for(reader.readline(), timeout=10)
        if h in (b"\r\n", b"\n", b""):
            break
        name, _, value = h.decode("latin-1").partition(":")
        headers[name.strip().lower()] = value.strip()
    clen = int(headers.get("content-length", "0") or 0)
    if clen > MAX_BODY:
        raise ValueError("body too large")
    body = await reader.readexactly(clen) if clen else b""
    return Request(method, path, query, headers, body, peer)


async def respond(writer: asyncio.StreamWriter, code: int, ctype: str,
                  body: bytes, extra: dict | None = None) -> None:
    head = [f"HTTP/1.1 {code} {STATUS_TEXT.get(code, 'OK')}",
            f"Content-Type: {ctype}",
            f"Content-Length: {len(body)}",
            "Cache-Control: no-store",
            "X-Content-Type-Options: nosniff",
            "Referrer-Policy: no-referrer",
            "Connection: close"]
    for k, v in (extra or {}).items():
        head.append(f"{k}: {v}")
    writer.write(("\r\n".join(head) + "\r\n\r\n").encode() + body)
    await writer.drain()


def trends_info() -> dict:
    """Read-only aggregates over the resolver's analytics DB (dns_logs /
    dns_cache). Pure stdlib sqlite3; the resolver owns the file and this
    only reads it, so not even the panel can second-guess the records."""
    db = Path(DEV_DIR) / "dns_analytics.db"
    if not db.exists():
        return {"error": "no analytics db yet - run the resolver for a bit"}
    try:
        conn = sqlite3.connect(str(db), timeout=3)
        conn.execute("PRAGMA query_only=ON")
        cur = conn.cursor()

        def one(q, p=()):
            cur.execute(q, p)
            return cur.fetchone()

        def all_rows(q, p=()):
            cur.execute(q, p)
            return cur.fetchall()

        total, = one("SELECT count(*) FROM dns_logs")
        clients, = one("SELECT count(DISTINCT client_ip) FROM dns_logs")
        d_queries, d_blocked = one(
            "SELECT count(*), coalesce(sum(status='BLOCKED'),0) FROM dns_logs "
            "WHERE timestamp >= datetime('now','-1 day')")
        status = all_rows(
            "SELECT status, count(*) FROM dns_logs "
            "WHERE timestamp >= datetime('now','-1 day') "
            "GROUP BY status ORDER BY 2 DESC")
        hourly = all_rows(
            "SELECT substr(timestamp,1,13) h, count(*), "
            "coalesce(sum(status='BLOCKED'),0) FROM dns_logs "
            "WHERE timestamp >= datetime('now','-1 day') "
            "GROUP BY h ORDER BY h")
        top_domains = all_rows(
            "SELECT domain, count(*), coalesce(sum(status='BLOCKED'),0) "
            "FROM dns_logs GROUP BY domain ORDER BY count(*) DESC LIMIT 15")
        top_blocked = all_rows(
            "SELECT domain, count(*) FROM dns_logs WHERE status='BLOCKED' "
            "GROUP BY domain ORDER BY count(*) DESC LIMIT 15")
        top_clients = all_rows(
            "SELECT client_ip, count(*) FROM dns_logs "
            "GROUP BY client_ip ORDER BY count(*) DESC LIMIT 10")
        lat = [r[0] for r in all_rows(
            "SELECT response_time_ms FROM dns_logs "
            "ORDER BY id DESC LIMIT 3000") if r[0] is not None]
        cache_entries, cache_blocked, cache_hits, cache_avg_ttl = one(
            "SELECT count(*), coalesce(sum(blocked),0), coalesce(sum(hits),0), "
            "round(avg(ttl),0) FROM dns_cache")
        conn.close()
    except Exception as exc:
        return {"error": str(exc)}

    def pct(v):
        if not lat:
            return 0.0
        s = sorted(lat)
        return round(s[min(len(s) - 1, int(len(s) * v))], 1)

    return {
        "total": total,
        "clients": clients,
        "queries_24h": d_queries or 0,
        "blocked_24h": d_blocked or 0,
        "status": [[s, n] for s, n in status],
        "hourly": [[h, q, b] for h, q, b in hourly],
        "top_domains": [[d, q, b] for d, q, b in top_domains],
        "top_blocked": top_blocked,
        "top_clients": top_clients,
        "latency": {
            "avg": round(sum(lat) / len(lat), 1) if lat else 0.0,
            "p50": pct(0.50),
            "p95": pct(0.95),
            "max": round(max(lat), 1) if lat else 0.0,
            "n": len(lat),
        },
        "cache": {"entries": cache_entries or 0, "blocked": cache_blocked or 0,
                  "hits": cache_hits or 0, "avg_ttl": cache_avg_ttl or 0},
        "window": "last 24h",
    }


async def route(req: Request) -> tuple[int, str, bytes]:
    path = req.path
    js = ("application/json",)

    if path == "/healthz":
        return 200, js[0], json.dumps({"ok": True, "ts": time.time()}).encode()

    if path in ("/", "/index.html") and req.method == "GET":
        return 200, "text/html; charset=utf-8", PAGE_MAIN.encode()

    if path == "/api/state" and req.method == "GET":
        units = await unit_states()
        mem = read_mem()
        up = 0
        try:
            import urllib.request
            with urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=4) as f:
                up = json.loads(f.read().decode()).get("blocklist", 0)
        except Exception:
            up = 0
        return 200, js[0], json.dumps({
            "units": units, "mem": mem, "load": read_load(),
            "uptime": round(time.time() - BOOT, 1),
            "resolver_domains": up,
        }).encode()

    if path == "/api/action" and req.method == "POST":
        body = req.json()
        action = str(body.get("action", ""))
        key = str(body.get("unit", ""))
        if action not in {"start", "stop", "restart", "enable", "disable", "status"}:
            return 400, js[0], json.dumps(
                {"error": f"action {action!r} not allowed"}).encode()
        rc, out, err = await run_ctl(action, key)
        log(f"{req.peer} -> {action} {key} (rc={rc})")
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            data = {"raw": out}
        # 200 even when the action failed. A refused or ineffective toggle is a
        # successful API call that reports an outcome; returning 502 made the
        # browser treat it as a transport error and show "failed: undefined"
        # instead of the helper's explanation of what actually happened.
        return 200, js[0], json.dumps({
            "rc": rc, "result": data, "error": err, "ok": rc == 0}).encode()

    if path == "/api/logs" and req.method == "GET":
        rc, out, err = await run_ctl("logs", req.query.get("unit", "resolver"),
                                     req.query.get("stream", "service"))
        body = out or (err or "(no output)")
        # The log view renders with textContent, not innerHTML, so this is
        # defence in depth rather than the primary control.
        return 200, "text/plain; charset=utf-8", body.encode("utf-8", "replace")

    if path == "/api/doctor" and req.method == "GET":
        rc, out, err = await run_ctl("doctor")
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            data = {"checks": [], "error": err or out[:2000]}
        data["ok"] = rc == 0
        return 200, js[0], json.dumps(data).encode()

    if path == "/api/blocklist" and req.method == "GET":
        return 200, js[0], json.dumps(blocklist_info()).encode()

    if path == "/api/blocklist/refresh" and req.method == "POST":
        # This is the one action that is not a systemctl call: it starts the
        # updater as the operator user in the background, because a compile
        # takes minutes and an HTTP request cannot be held open that long.
        lock = Path(DEV_DIR) / ".blocklist.lock"
        if lock.exists():
            # flock holds this while a run is in flight; a stale file from a
            # crashed run is possible, so only trust it if the process is alive.
            r = subprocess.run(["flock", "-n", str(lock), "-c", "true"],
                               capture_output=True, timeout=5)
            if r.returncode != 0:
                return 200, js[0], json.dumps({
                    "ok": False,
                    "message": "a blocklist compile is already running; "
                               "watch it on the Blocklist Updater log"}).encode()
        logfile = open(Path(DEV_DIR) / "blocklist-refresh.log", "ab")
        subprocess.Popen(
            ["flock", str(lock), "-c",
             f"cd {shlex.quote(DEV_DIR)} && python3 ./blocklist-updater.py "
             "--once --profile daily"],
            stdout=logfile, stderr=logfile, stdin=subprocess.DEVNULL,
            start_new_session=True)
        log(f"{req.peer} started a blocklist refresh")
        return 200, js[0], json.dumps({
            "ok": True,
            "message": "compile started; the resolver hot-reloads in about 30s "
                       "when it lands. Watch the Blocklist Updater logs."}).encode()

    if path == "/api/resolver" and req.method == "GET":
        try:
            import urllib.request
            with urllib.request.urlopen("http://127.0.0.1:8080/api/stats",
                                        timeout=6) as f:
                return 200, js[0], f.read()
        except Exception as e:
            return 502, js[0], json.dumps({"error": str(e)}).encode()

    if path == "/api/querylog" and req.method == "GET":
        # The full DNS history straight from the resolver's sqlite db: who
        # asked for what, when, and what happened. Filters are optional.
        db = Path(DEV_DIR) / "dns_analytics.db"
        if not db.exists():
            return 200, js[0], json.dumps(
                {"total": 0, "rows": [], "clients": [], "error":
                 "no analytics db yet - run the resolver for a bit"}).encode()
        q = req.query
        client = (q.get("client") or "").strip()
        status = (q.get("status") or "").strip()
        try:
            limit = min(int(q.get("limit", "100")), 500)
            offset = max(int(q.get("offset", "0")), 0)
        except ValueError:
            limit, offset = 100, 0
        try:
            conn = sqlite3.connect(str(db), timeout=3)
            conn.execute("PRAGMA query_only=ON")
            cur = conn.cursor()
            where, args = [], []
            if client:
                where.append("client_ip = ?")
                args.append(client)
            if status:
                where.append("status = ?")
                args.append(status)
            wsql = (" WHERE " + " AND ".join(where)) if where else ""
            cur.execute(f"SELECT count(*) FROM dns_logs{wsql}", args)
            total, = cur.fetchone()
            cur.execute(
                f"SELECT coalesce(sum(status='BLOCKED'),0) FROM dns_logs{wsql}",
                args)
            blocked, = cur.fetchone()
            clients = [r[0] for r in cur.execute(
                "SELECT DISTINCT client_ip FROM dns_logs "
                "ORDER BY client_ip").fetchall()]
            rows = cur.execute(
                f"SELECT timestamp, client_ip, domain, qtype, status, "
                f"response_time_ms FROM dns_logs{wsql} "
                f"ORDER BY id DESC LIMIT ? OFFSET ?",
                args + [limit, offset]).fetchall()
            conn.close()
            return 200, js[0], json.dumps({
                "total": total, "blocked": blocked,
                "offset": offset, "limit": limit,
                "clients": clients, "rows": rows,
            }).encode()
        except sqlite3.Error as e:
            return 500, js[0], json.dumps({"error": str(e)}).encode()

    if path == "/api/sources.txt" and req.method == "GET":
        try:
            return 200, "text/plain; charset=utf-8", \
                (Path(DEV_DIR) / "blocklist_sources.py").read_bytes()
        except OSError as e:
            return 404, js[0], json.dumps({"error": str(e)}).encode()

    if path == "/api/trends" and req.method == "GET":
        return 200, js[0], json.dumps(trends_info()).encode()

    return 404, js[0], json.dumps({"error": "no such route"}).encode()


BOOT = time.time()


# ---------------------------------------------------------------------------
# pages
# ---------------------------------------------------------------------------
_CSS = """
*{box-sizing:border-box}
body{margin:0;background:#0d1117;color:#c9d1d9;
 font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
header{position:sticky;top:0;z-index:20;background:#161b22ee;backdrop-filter:blur(8px);
 border-bottom:1px solid #30363d;padding:10px 18px;display:flex;gap:14px;align-items:center;
 flex-wrap:wrap}
h1{font-size:16px;margin:0;color:#58a6ff;letter-spacing:.4px}
.tabs{display:flex;gap:4px;margin-left:auto;flex-wrap:wrap}
.tab{background:none;border:1px solid transparent;color:#8b949e;padding:6px 12px;
 border-radius:6px;cursor:pointer;font:inherit;font-size:13px}
.tab:hover{color:#c9d1d9;background:#21262d}
.tab.on{color:#e6edf3;background:#21262d;border-color:#30363d}
main{padding:18px;max-width:1400px;margin:0 auto}
.bar{height:6px;background:#21262d;border-radius:3px;overflow:hidden;margin:10px 0 18px}
.bar>i{display:block;height:100%;background:linear-gradient(90deg,#238636,#2ea043)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:12px}
.card{background:#161b22;border:1px solid #30363d;border-radius:9px;padding:14px;
 display:flex;flex-direction:column;gap:8px}
.card.down{border-color:#6e3030}
.card h3{margin:0;font-size:14px;color:#e6edf3;display:flex;align-items:center;gap:8px}
.dot{width:9px;height:9px;border-radius:50%;flex:0 0 auto}
.dot.on{background:#3fb950;box-shadow:0 0 8px #3fb95088}
.dot.off{background:#6e7681}
.dot.err{background:#f85149;box-shadow:0 0 8px #f8514988}
.desc{color:#8b949e;font-size:12px;flex:1}
.meta{color:#6e7681;font-size:11px;font-family:ui-monospace,monospace}
.row{display:flex;gap:6px;flex-wrap:wrap}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;padding:6px 11px;
 border-radius:6px;cursor:pointer;font:inherit;font-size:12px}
button:hover:not(:disabled){background:#30363d;border-color:#484f58}
button:disabled{opacity:.4;cursor:not-allowed}
button.pri{background:#238636;border-color:#2ea043;color:#fff}
button.pri:hover:not(:disabled){background:#2ea043}
button.dan{background:#3d1d1d;border-color:#6e3030;color:#ff9492}
button.dan:hover:not(:disabled){background:#542424}
table{width:100%;border-collapse:collapse;font-size:12.5px;
 background:#161b22;border:1px solid #30363d;border-radius:9px;overflow:hidden}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #21262d}
th{color:#8b949e;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:#1c2128}
pre{background:#0d1117;border:1px solid #30363d;border-radius:9px;padding:14px;
 overflow:auto;max-height:70vh;font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;
 color:#c9d1d9;white-space:pre-wrap;word-break:break-word}
.hide{display:none}
.good{color:#3fb950}.warn{color:#d29922}.bad{color:#f85149}
.kpi{background:#161b22;border:1px solid #30363d;border-radius:9px;padding:12px 14px}
.kpi .k{color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
.kpi .v{font-size:20px;margin-top:3px;color:#e6edf3;
 font-family:ui-monospace,Menlo,Consolas,monospace}
.twocol{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:16px}
@media(max-width:800px){.twocol{grid-template-columns:1fr}}
.ttl{font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;
 margin:0 0 8px}
.spark{display:flex;align-items:flex-end;gap:3px;height:110px;
 padding:14px 4px 6px;background:#161b22;border:1px solid #30363d;
 border-radius:9px}
.spark .bar{flex:1;height:100%;position:relative;display:flex;
 align-items:flex-end}
.spark .qbar{width:100%;background:#1f6feb;border-radius:2px;min-height:2px}
.spark .blk{position:absolute;left:0;right:0;bottom:0;background:#f85149;
 border-radius:2px;opacity:.95}
.note{background:#1c2128;border-left:3px solid #d29922;padding:10px 13px;border-radius:5px;
 margin:12px 0;font-size:12.5px;color:#d29922}
.note.info{border-left-color:#58a6ff;color:#8b949e}
.toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);
 background:#161b22;border:1px solid #30363d;border-radius:8px;padding:11px 18px;
 font-size:13px;z-index:60;box-shadow:0 6px 24px #0009;max-width:88vw}
.toast.ok{border-color:#2ea043;color:#7ee787}
.toast.bad{border-color:#6e3030;color:#ff9492}
.login{max-width:400px;margin:14vh auto;background:#161b22;border:1px solid #30363d;
 border-radius:11px;padding:26px}
input,select{width:100%;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;
 padding:9px 11px;border-radius:6px;font:inherit;font-size:13px;margin:8px 0 14px}
"""

PAGE_MAIN = ("""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>dnshub control · by Mostfa</title><style>""" + _CSS + """</style></head><body>
<header>
<h1>dnshub control <span class=meta>by Mostfa</span></h1>
<div id=hstat class=meta></div>
<div class=tabs>
 <button class="tab on" data-t=services>Services</button>
 <button class="tab" data-t=logs>Logs</button>
 <button class="tab" data-t=blocklist>Blocklist</button>
 <button class="tab" data-t=resolver>Resolver</button>
 <button class="tab" data-t=queries>Queries</button>
 <button class="tab" data-t=trends>Trends</button>
 <button class="tab" data-t=doctor>Doctor</button>
</div>
</header>
<main>
<div class=bar><i id=mem></i></div>

<section id=services>
 <div class=grid id=cards></div>
 <div class=note info">Every switch below is a real systemd action and takes
 effect immediately. Turning the resolver off stops DNS for the whole house,
 including this page's own name resolution.</div>
</section>

<section id=logs class=hide>
 <div class=row style="margin-bottom:12px">
  <select id=lu style="max-width:220px;margin:0"></select>
  <select id=ls style="max-width:200px;margin:0">
    <option value=service>service journal</option>
    <option value=kernel>kernel ring buffer</option>
    <option value=abuse>abuse log (ban decisions)</option>
    <option value=blocklist>blocklist updater log</option>
  </select>
  <button id=lr>Refresh</button>
  <label class=meta style="margin-left:auto"><input type=checkbox id=auto
   style="width:auto;margin:0 6px 0 0"checked> auto every 5s</label>
 </div>
 <pre id=lout>loading...</pre>
</section>

<section id=blocklist class=hide>
 <div class=grid id=bkpis style="margin-bottom:16px"></div>
 <div class=row style="margin-bottom:12px">
  <button class=pri id=refresh>Rebuild the list now</button>
  <span id=bmsg class=meta></span>
 </div>
 <div class=note info">A rebuild fetches about 200 MiB from the publishers and
 takes roughly 8 minutes on this uplink. The resolver picks up the result by
 itself, with no restart and no dropped queries.</div>
 <table><thead><tr><th>Source</th><th>Categories</th><th>Entries</th>
 <th>Format / notes</th></tr></thead><tbody id=bsrc></tbody></table>
</section>

<section id=resolver class=hide>
 <div class=grid id=rkpis style="margin-bottom:16px"></div>
 <table><thead><tr><th>Time</th><th>Client</th><th>Domain</th><th>Type</th>
 <th>Status</th><th>ms</th></tr></thead><tbody id=rrows></tbody></table>
</section>

<section id=queries class=hide>
 <div class=row style="margin-bottom:12px">
  <select id=qc style="max-width:220px;margin:0"><option value="">all clients</option></select>
  <select id=qs style="max-width:170px;margin:0">
   <option value="">all statuses</option>
   <option>INTERNAL</option><option>RAM</option><option>SQL</option>
   <option>MISS</option><option>BLOCKED</option><option>ERROR</option>
  </select>
  <button id=qr>Refresh</button>
  <label class=meta style="margin-left:auto"><input type=checkbox id=qa
   style="width:auto;margin:0 6px 0 0"checked> auto every 5s</label>
 </div>
 <div class=grid id=qkpis style="margin-bottom:16px"></div>
 <div class=note info>Every query the resolver sees is logged here - client IP,
  domain, type, result - and the full history stays until the analytics db is
  cleared. RAM/SQL are cache hits, MISS was answered by an upstream,
  INTERNAL is the built-in .home zone, BLOCKED means the blocklist refused it.</div>
 <table><thead><tr><th>Time</th><th>Client</th><th>Domain</th><th>Type</th>
 <th>Status</th><th>ms</th></tr></thead><tbody id=qrows></tbody></table>
 <div class=row style="margin-top:12px"><button id=qmore>Show older</button>
  <span id=qinfo class=meta></span></div>
</section>

<section id=trends class=hide>
 <div class=grid id=tkpis style="margin-bottom:16px"></div>
 <div class=note info>Aggregated straight from the resolver's sqlite logs -
 no extra service, no library. Blue bars below are queries per hour over the
 last 24h, red is the blocked share of that hour. Totals are <b>last 24h</b>
 except the cache KPIs, which are the live in-memory cache.</div>
 <div class=spark id=tspark>loading...</div>
 <div class=twocol>
  <div><h3 class=ttl>Top domains</h3>
   <table><thead><tr><th>Domain</th><th>Queries</th><th>Blocked</th>
   </tr></thead><tbody id=tdom></tbody></table></div>
  <div><h3 class=ttl>Most blocked</h3>
   <table><thead><tr><th>Domain</th><th>Times</th>
   </tr></thead><tbody id=tblk></tbody></table></div>
 </div>
 <div class=twocol>
  <div><h3 class=ttl>Clients</h3>
   <table><thead><tr><th>Client</th><th>Queries</th>
   </tr></thead><tbody id=tcl></tbody></table></div>
  <div><h3 class=ttl>Status breakdown</h3>
   <table><thead><tr><th>Status</th><th>Count</th>
   </tr></thead><tbody id=tst></tbody></table></div>
 </div>
</section>

<section id=doctor class=hide>
 <div class=row style="margin-bottom:12px">
  <button id=dr>Run the check again</button>
 </div>
 <table><thead><tr><th>Check</th><th>Result</th><th>Detail</th><th>What to do</th>
 </tr></thead><tbody id=drows></tbody></table>
</section>
</main>
<div id=toast class="toast hide"></div>
<script>
const $=i=>document.getElementById(i);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;',
 '>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(p,o){
 o=o||{};
 const r=await fetch(p,o);
 const j=await r.json().catch(()=>({error:'bad response'}));
 if(!r.ok)throw new Error(j.error||('http '+r.status));
 return j;
}
document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>{
 document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('on',x===t));
 ['services','logs','blocklist','resolver','queries','trends','doctor'].forEach(s=>
  $(s).classList.toggle('hide',s!==t.dataset.t));
 if(t.dataset.t=='logs')loadLogs();
 if(t.dataset.t=='blocklist')loadBlock();
 if(t.dataset.t=='resolver')loadRes();
 if(t.dataset.t=='queries')loadQueries(1);
 if(t.dataset.t=='trends')loadTrends();
 if(t.dataset.t=='doctor')loadDoctor();
});

let busy={},lastMsg='';
function say(t,cls){$('toast').textContent=t;$('toast').className=cls||'toast';
 setTimeout(()=>{$('toast').className='toast hide'},4200);}
function act(unit,action,btn){
 if(busy[unit+action])return;
 busy[unit+action]=1;btn.disabled=true;const t=btn.textContent;btn.textContent='...';
 api('/api/action',{method:'POST',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({unit,action})})
  // The helper explains the outcome in result.message; surface that rather than
  // a generic failure, because "the unit did not come back up" and "that unit
  // is not whitelisted" need very different reactions.
  .then(r=>{const m=(r.result&&r.result.message)||'';
   say(m+(r.error?'  ('+r.error+')':''),r.ok?'toast ok':'toast bad');})
  .catch(e=>say('failed: '+e.message,'toast bad'))
  .finally(()=>{delete busy[unit+action];btn.disabled=false;btn.textContent=t;
   load();if(!$('logs').classList.contains('hide'))loadLogs();});
}
async function load(){
 let s;try{s=await api('/api/state')}catch(e){
  $('hstat').innerHTML='<span class=bad>'+esc(e.message)+
   ' &middot; panel API unreachable</span>';return}
 const mem=s.mem, pct=Math.round(100*mem.used_mb/Math.max(1,mem.total_mb));
 $('mem').style.width=pct+'%';
 $('hstat').innerHTML='mem '+mem.used_mb+'/'+mem.total_mb+' MB &middot; load '+
  s.load[0]+' &middot; up '+Math.floor(s.uptime/60)+'m &middot; '+
  s.resolver_domains.toLocaleString()+' domains';
 $('cards').innerHTML=s.units.map(u=>{
  const on=u.active==='active', known=u.exists!==false;
  const st=known?(on?'on':(u.active==='failed'?'err':'off')):'err';
  const since=u.since?u.since.replace(/ .*/,''):'';
  const kind=u.kind==='container'?'container':'';
  const health=u.health&&u.health!=='healthy'?u.health:'';
  return '<div class="card'+(on?'':' down')+'">'+
   '<h3><span class="dot '+st+'"></span>'+esc(u.label||u.key)+'</h3>'+
   '<div class=desc>'+esc(u.desc||'')+'</div>'+
   '<div class=meta>'+esc(u.unit)+(kind?' ('+kind+')':'')+'<br>'+
    (known?(on?'running':esc(u.active||'stopped'))+
      (health?' &middot; health='+esc(health):'')+
      ' &middot; enabled='+esc(u.enabled)+
      (since?' &middot; since '+esc(since):'')
     :'not installed &middot; run: dnshub install')+'</div>'+
   '<div class=row>'+
    '<button class="'+(on?'dan':'pri')+'" onclick="act(\\''+u.key+'\\','+
     (on?'stop':'start')+',this)">'+(on?'Stop':'Start')+'</button>'+
    '<button onclick="act(\\''+u.key+'\\','+(on?'disable':'enable')+
     ',this)">'+(on?'Disable':'Enable')+'</button>'+
    '<button onclick="act(\\''+u.key+'\\',restart,this)">Restart</button>'+
    '<button onclick="showLogs(\\''+u.key+'\\')">Logs</button>'+
   '</div></div>'}).join('');
 if(!$('lu').options.length){
  $('lu').innerHTML=s.units.map(u=>
   '<option value='+u.key+'>'+esc(u.label||u.key)+'</option>').join('');}
}
function showLogs(k){
 document.querySelector('.tab[data-t=logs]').click();
 $('lu').value=k;loadLogs();
}
async function loadLogs(){
 const u=$('lu').value,s=$('ls').value;
 $('lout').textContent='loading...';
 try{
  const r=await fetch('/api/logs?unit='+encodeURIComponent(u)+'&stream='+s);
  $('lout').textContent=await r.text();
 }catch(e){$('lout').textContent='error: '+e.message}
}
$('lr').onclick=loadLogs;$('lu').onchange=loadLogs;$('ls').onchange=loadLogs;
setInterval(()=>{if($('auto').checked&&!$('logs').classList.contains('hide'))
 loadLogs()},5000);

async function loadBlock(){
 let b;try{b=await api('/api/blocklist')}catch(e){$('bkpis').innerHTML=
  '<div class=bad">'+esc(e.message)+'</div>';return}
 const m=b.meta||{};
 $('bkpis').innerHTML=[
  ['Domains blocked',(m.total_domains||0).toLocaleString(),''],
  ['Before exemptions',(m.unique_before_allowlist||0).toLocaleString(),''],
  ['Allowlist size',m.allowlist_size||0,''],
  ['Blob',((b.counts.blob||0)/1048576).toFixed(1)+' MiB',''],
  ['Index',((b.counts.index||0)/1048576).toFixed(1)+' MiB',''],
  ['Sources',(b.sources||[]).length,''],
  ['Failed sources',m.failed_sources??'-',m.failed_sources?'bad':'good'],
  ['Profile',m.profile||b.default_profile||'daily',''],
  ['Last build',m.elapsed_sec?Math.round(m.elapsed_sec)+'s, peak '+
   Math.round(m.peak_rss_mb||0)+' MiB':'-',''],
 ].map(([k,v,c])=>'<div class=kpi><div class=k>'+k+'</div><div class="v '+
  c+'">'+esc(v)+'</div></div>').join('');
 if(b.sources_error)$('bsrc').innerHTML='<tr><td colspan=4 class=bad>'+
  esc(b.sources_error)+'</td></tr>';
 else $('bsrc').innerHTML=(b.sources||[]).map(s=>
  '<tr><td>'+esc(s.name)+'</td><td>'+
  esc(Array.isArray(s.categories)?s.categories.join(', '):s.categories)+
  '</td><td>'+(s.entries||0).toLocaleString()+'</td><td class=meta>'+
  esc(s.format||'')+
  (s.superseded_by?' &middot; superseded by '+esc(s.superseded_by):'')+
  (s.doh?' &middot; blocks browser DoH':'')+'</td></tr>').join('');
}
$('refresh').onclick=async()=>{
 $('bmsg').textContent='starting...';
 try{const r=await api('/api/blocklist/refresh',{method:'POST'});
  $('bmsg').textContent=r.message;loadBlock();}
 catch(e){$('bmsg').textContent='failed: '+e.message}};

async function loadRes(){
 let s;try{s=await api('/api/resolver')}catch(e){
  $('rkpis').innerHTML='<div class=bad">'+esc(e.message)+'</div>';return}
 const f=n=>n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3).toFixed(1)+'k':n;
 $('rkpis').innerHTML=[
  ['Queries',f(s.queries_total),''],['Cache hit',s.cache_hit_pct+'%',
   s.cache_hit_pct>70?'good':'warn'],['Blocked',f(s.blocked_total),'warn'],
  ['Upstreams',(s.upstreams||[]).length,''],['RAM entries',s.ram_entries,''],
  ['Avg latency',s.avg_latency_ms+' ms',''],['Errors',s.errors,
   s.errors?'bad':'good'],['RSS',s.rss_mb+' MB',''],
 ].map(([k,v,c])=>'<div class=kpi><div class=k>'+k+'</div><div class="v '+
  c+'">'+esc(v)+'</div></div>').join('');
 $('rrows').innerHTML=(s.recent||[]).slice(-40).reverse().map(q=>
  '<tr>'+q.map(c=>'<td>'+esc(c)+'</td>').join('')+'</tr>').join('');
}

let qoff=0;
async function loadQueries(reset){
 if(reset)qoff=0;
 const c=$('qc').value,s=$('qs').value;
 let d;try{d=await api('/api/querylog?client='+encodeURIComponent(c)+
  '&status='+encodeURIComponent(s)+'&limit=100&offset='+qoff)}
 catch(e){$('qrows').innerHTML='<tr><td colspan=6 class=bad>'+esc(e.message)+
  '</td></tr>';return}
 if(d.error){$('qrows').innerHTML='<tr><td colspan=6 class=meta>'+
  esc(d.error)+'</td></tr>';return}
 const f=n=>n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3).toFixed(1)+'k':n;
 $('qkpis').innerHTML=[
  ['Total queries',f(d.total),''],
  ['Blocked',f(d.blocked),d.blocked?'warn':'good'],
  ['Block rate',d.total?Math.round(100*d.blocked/d.total)+'%':'-',
   d.total&&100*d.blocked/d.total>20?'warn':'good'],
  ['Clients',(d.clients||[]).length,''],
 ].map(([k,v,c])=>'<div class=kpi><div class=k>'+k+'</div><div class="v '+
  c+'">'+esc(v)+'</div></div>').join('');
 const sel=$('qc'),have=new Set([...sel.options].map(o=>o.value));
 (d.clients||[]).forEach(c=>{if(!have.has(c)){
  const o=document.createElement('option');o.value=c;o.textContent=c;
  sel.appendChild(o);}});
 $('qrows').innerHTML=(d.rows||[]).map(r=>{
  const st=String(r[4]||'').toLowerCase();
  const cls=st=='blocked'?'bad':st=='error'?'warn':
   (st=='ram'||st=='sql'||st=='internal')?'good':'';
  return '<tr><td>'+esc(r[0])+'</td><td>'+esc(r[1])+'</td><td>'+esc(r[2])+
   '</td><td>'+esc(r[3])+'</td><td class="'+cls+'">'+esc(r[4])+'</td><td>'+
   (r[5]==null?'-':r[5]+' ms')+'</td></tr>';
 }).join('')||'<tr><td colspan=6 class=meta>no queries match these filters</td></tr>';
 $('qinfo').textContent=(d.offset>0||(qoff+d.rows.length)<d.total)?
  ('rows '+(qoff+1)+'-'+(qoff+d.rows.length)+' of '+d.total.toLocaleString()):
  (d.total?d.total.toLocaleString()+' queries in the log':'no queries yet');
 $('qmore').style.display=(qoff+d.rows.length)<d.total?'':'none';
}
$('qc').onchange=()=>loadQueries(1);$('qs').onchange=()=>loadQueries(1);
$('qr').onclick=()=>loadQueries(0);
$('qmore').onclick=()=>{qoff+=100;loadQueries(0)};
setInterval(()=>{if($('qa').checked&&!$('queries').classList.contains('hide'))
 loadQueries(0)},5000);

async function loadTrends(){
 let t;try{t=await api('/api/trends')}catch(e){
  $('tkpis').innerHTML='<div class="bad">'+esc(e.message)+'</div>';return}
 if(t.error){$('tkpis').innerHTML='<div class="bad">'+esc(t.error)+
  '</div>';return}
 const q=t.queries_24h||0,b=t.blocked_24h||0;
 $('tkpis').innerHTML=[
  ['Queries (24h)',q.toLocaleString(),''],
  ['Blocked (24h)',b.toLocaleString(),'warn'],
  ['Block rate',q?(Math.round(100*b/q)+'%'):'-',
   q&&100*b/q>20?'warn':'good'],
  ['Clients',t.clients.toLocaleString(),''],
  ['All-time rows',t.total.toLocaleString(),''],
  ['Latency p50 / p95',t.latency.p50+' / '+t.latency.p95+' ms',
   t.latency.p95>300?'warn':'good'],
  ['Cache entries',t.cache.entries.toLocaleString(),''],
  ['Cache: blocked',t.cache.blocked.toLocaleString(),'warn'],
 ].map(([k,v,c])=>'<div class=kpi><div class=k>'+k+'</div><div class="v '+
  c+'">'+esc(v)+'</div></div>').join('');
 const h=t.hourly||[];
 const mq=Math.max(1,...h.map(x=>x[1]));
 $('tspark').innerHTML=h.length?h.map(x=>{
  const hp=Math.max(2,x[1]/mq*100),hb=x[2]>0?Math.max(2,x[2]/mq*100):0;
  return '<div class=bar title="'+esc(x[0])+' &middot; '+x[1]+' queries, '+
   x[2]+' blocked"><div class=qbar style="height:'+hp+'%"></div>'+
   (hb?'<div class=blk style="height:'+hb+'%"></div>':'')+'</div>';
 }).join(''):'<div class=meta style="margin:auto">no queries in the last '
  '24h yet - the resolver logs every query by default</div>';
 $('tdom').innerHTML=(t.top_domains||[]).map(r=>
  '<tr><td>'+esc(r[0])+'</td><td>'+r[1].toLocaleString()+'</td><td'+
  (r[2]>0?' class=warn':'')+'>'+r[2]+'</td></tr>').join('')||
  '<tr><td colspan=3 class=meta>no data</td></tr>';
 $('tblk').innerHTML=(t.top_blocked||[]).map(r=>
  '<tr><td>'+esc(r[0])+'</td><td>'+r[1].toLocaleString()+'</td></tr>').join('')||
  '<tr><td colspan=2 class=meta>nothing blocked yet</td></tr>';
 $('tcl').innerHTML=(t.top_clients||[]).map(r=>
  '<tr><td>'+esc(r[0])+'</td><td>'+r[1].toLocaleString()+'</td></tr>').join('')||
  '<tr><td colspan=2 class=meta>no clients yet</td></tr>';
 $('tst').innerHTML=(t.status||[]).map(r=>
  '<tr><td>'+esc(r[0])+'</td><td>'+r[1].toLocaleString()+'</td></tr>').join('')||
  '<tr><td colspan=2 class=meta>no data</td></tr>';
}

async function loadDoctor(){
 $('drows').innerHTML='<tr><td colspan=4>checking...</td></tr>';
 let d;try{d=await api('/api/doctor')}catch(e){
  $('drows').innerHTML='<tr><td colspan=4 class=bad>'+esc(e.message)+
   '</td></tr>';return}
 $('drows').innerHTML=(d.checks||[]).map(c=>
  '<tr><td>'+esc(c.name)+'</td><td class="'+(c.ok===true?'good':
   c.ok===false?'bad':'warn')+'">'+(c.ok===true?'OK':c.ok===false?'PROBLEM':
   'UNKNOWN')+'</td><td>'+esc(c.detail)+'</td><td class=meta>'+
   esc(c.fix||'')+'</td></tr>').join('')||
  '<tr><td colspan=4>no checks ran</td></tr>';
}
$('dr').onclick=loadDoctor;
load();setInterval(load,5000);
</script></body></html>""")


# ---------------------------------------------------------------------------
async def main() -> int:
    server = await asyncio.start_server(handle, BIND, PORT)
    log(f"http://{BIND}:{PORT} (LAN-only, open panel)")
    async with server:
        await server.serve_forever()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(130)
