#!/usr/bin/env python3
"""
dnshub-files - the "comprehensive files" service for the hub.

One stdlib asyncio HTTP server that turns the box's files directory into a
shared drive: browse, upload, download, delete, mkdir, from any LAN device or
from anywhere over the WireGuard tunnel. Path traversal is locked to the root
directory.

Deliberate limits (a 2-core / 1.8 GiB box):
  * LAN-only and intentionally open, like the control panel: a client that can
    reach the hub already has LAN access, so there is no additional gate. If
    the box is ever exposed to a WAN, front this with a proxy that adds auth —
    out of the box a file server on the internet is a readable dropper.
  * Downloads stream in 256 KiB chunks; no file is slurped into RAM.
  * The root defaults to ~/dnshub-files (created by `dnshub install`; override
    with DNSHUB_FILES_ROOT).
"""
from __future__ import annotations

import asyncio
import contextlib
import html
import json
import mimetypes
import os
import shutil
import sys
import time
import urllib.parse
from pathlib import Path

PORT = int(os.environ.get("DNSHUB_FILES_PORT", "8082"))
BIND = os.environ.get("DNSHUB_FILES_BIND", "0.0.0.0")
ROOT = Path(os.environ.get("DNSHUB_FILES_ROOT",
                           os.path.expanduser("~/dnshub-files")))
CHUNK = 256 * 1024
MAX_BODY = int(os.environ.get("DNSHUB_FILES_MAX",
                              str(4 * 1024 * 1024 * 1024)))  # 4 GiB cap


def log(msg: str) -> None:
    sys.stdout.write(f"[{time.strftime('%H:%M:%S')}] files: {msg}\n")
    sys.stdout.flush()


def safe_path(requested: str, mk: bool = False) -> Path | None:
    """Resolve a user-supplied path strictly inside ROOT."""
    try:
        p = urllib.parse.unquote(requested or "")
        base = ROOT.resolve()
        if p in ("", "/", "."):
            return base
        tgt = (base / p.lstrip("/")).resolve()
        if mk:  # mkdir may point at a not-yet-existing child
            par = tgt.parent.resolve()
            try:
                tgt.relative_to(base)
                par.relative_to(base)
            except ValueError:
                return None
            return tgt
        tgt.relative_to(base)
        return tgt
    except (ValueError, OSError):
        return None


def human(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} TiB"


async def send_file(writer, p: Path, req_id: int) -> None:
    st = p.stat()
    header = (f"HTTP/1.1 200 OK\r\n"
              f"Content-Length: {st.st_size}\r\n"
              f"Content-Type: {mimetypes.guess_type(p.name)[0] or 'application/octet-stream'}\r\n"
              f"Content-Disposition: attachment; filename*=UTF-8''"
              f"{urllib.parse.quote(p.name)}\r\n"
              f"Cache-Control: private, max-age=60\r\n\r\n")
    writer.write(header.encode())
    await writer.drain()
    with open(p, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    with contextlib.suppress(Exception):
        await writer.drain()


def listing(p: Path) -> dict:
    rows = []
    for f in sorted(p.iterdir(), key=lambda x: (x.is_file(), x.name.lower())):
        try:
            st = f.stat()
        except OSError:
            continue
        rows.append({
            "name": f.name,
            "dir": f.is_dir(),
            "size": st.st_size if f.is_file() else 0,
            "size_h": human(st.st_size) if f.is_file() else "-",
            "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
        })
    return {"path": str(p), "rel": str(p.relative_to(ROOT.resolve())) if p != ROOT.resolve() else "",
            "entries": rows}


async def handle(reader, writer) -> None:
    peer = writer.get_extra_info("peername")
    peer = peer[0] if peer else "?"
    buf = b""
    try:
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            chunk = await reader.read(4096)
            if not chunk:
                break
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        try:
            head_txt = head.decode("ascii", "replace")
            request_line, *hlines = head_txt.split("\r\n")
            method, target, _ = request_line.split(" ", 2)
        except ValueError:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return

        headers: dict[str, str] = {}
        for h in hlines:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        parsed = urllib.parse.urlsplit(target)
        path = parsed.path
        q = urllib.parse.parse_qs(parsed.query)

        # The file hub is LAN-only and open (same trust model as the control
        # panel): a client that can reach it already has LAN access. Path
        # traversal below is still strictly contained in ROOT.
        if method == "GET" and path in ("/", "/index.html"):
            body = PAGE.encode()
            writer.write((f"HTTP/1.1 200 OK\r\nContent-Type: text/html; "
                          f"charset=utf-8\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body)
            await writer.drain()
            writer.close()
            return

        # OPTIONS for CORS-free same-origin fetches is unnecessary; reject everything else.
        if method == "GET" and path == "/browse":
            p = safe_path((q.get("path") or [""])[0])
            if not p or not p.is_dir():
                writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            else:
                body = json.dumps(listing(p)).encode()
                writer.write((f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                              f"Content-Length: {len(body)}\r\n\r\n").encode() + body)
        elif method == "GET" and path == "/download":
            p = safe_path((q.get("path") or [""])[0])
            if not p or not p.is_file():
                writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            else:
                await send_file(writer, p, req_id=1)
        elif method == "DELETE" and path == "/file":
            p = safe_path((q.get("path") or [""])[0])
            if not p:
                r = 400, "bad path"
            elif p in (ROOT.resolve(),) :
                r = 403, "cannot delete the root"
            elif p.is_dir():
                shutil.rmtree(p)
                log(f"{peer} deleted dir {p.relative_to(ROOT.resolve())}")
                r = 200, "deleted dir"
            elif p.exists():
                p.unlink()
                log(f"{peer} deleted {p.relative_to(ROOT.resolve())}")
                r = 200, "deleted"
            else:
                r = 404, "not found"
            body = json.dumps({"ok": r[0] == 200, "message": r[1]}).encode()
            writer.write((f"HTTP/1.1 {r[0]}\r\nContent-Type: application/json\r\n"
                          f"Content-Length: {len(body)}\r\n\r\n").encode() + body)
        elif method == "PUT" and path == "/upload":
            p = safe_path((q.get("path") or [""])[0], mk=True)
            name = (q.get("name") or [""])[0]
            size = int(headers.get("content-length", "0") or 0)
            if not p or not name or "/" in name or "\\" in name or name in (".", ".."):
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            elif size > MAX_BODY:
                writer.write(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n")
            else:
                p.mkdir(parents=True, exist_ok=True)
                tgt = (p / name).resolve()
                try:
                    tgt.relative_to(ROOT.resolve())
                except ValueError:
                    writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                    return
                got = len(rest)
                with open(tgt, "wb") as fh:
                    if rest:
                        fh.write(rest)
                    while got < size:
                        more = await reader.read(min(CHUNK, size - got))
                        if not more:
                            break
                        fh.write(more)
                        got += len(more)
                log(f"{peer} uploaded {name} ({human(got)})")
                body = json.dumps({"ok": True, "size": got}).encode()
                writer.write((f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                              f"Content-Length: {len(body)}\r\n\r\n").encode() + body)
        elif method == "POST" and path == "/mkdir":
            p = safe_path((q.get("path") or [""])[0], mk=True)
            name = (q.get("name") or [""])[0]
            if not p or not name or "/" in name or "\\" in name or name in (".", "..", ""):
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            else:
                tgt = (p / name).resolve()
                tgt.mkdir(parents=True, exist_ok=True)
                body = json.dumps({"ok": True, "name": name}).encode()
                writer.write((f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                              f"Content-Length: {len(body)}\r\n\r\n").encode() + body)
        else:
            writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
    except asyncio.CancelledError:
        pass
    except Exception as exc:
        log(f"{peer}: {type(exc).__name__}: {exc}")
        with contextlib.suppress(Exception):
            writer.write(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
    finally:
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()


PAGE = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>dnshub files · by Mostfa</title><style>
*{box-sizing:border-box}body{margin:0;background:#0d1117;color:#c9d1d9;
 font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
header{position:sticky;top:0;background:#161b22ee;border-bottom:1px solid #30363d;
 padding:10px 18px;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
h1{font-size:16px;margin:0;color:#58a6ff}main{padding:18px;max-width:1100px;margin:0 auto}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;padding:7px 12px;
 border-radius:6px;cursor:pointer;font:inherit;font-size:12.5px}
button:hover:not(:disabled){background:#30363d}
button.pri{background:#238636;border-color:#2ea043;color:#fff}
button.dan{background:#3d1d1d;border-color:#6e3030;color:#ff9492}
table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;
 border-radius:9px;overflow:hidden;font-size:13px}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #21262d}
th{color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
tr:hover{background:#1c2128}.meta{color:#6e7681;font-size:11px}
.crumb{color:#58a6ff;cursor:pointer}.hide{display:none}
#toast{position:fixed;bottom:16px;left:50%;transform:translateX(-50%);background:#161b22;
 border:1px solid #30363d;padding:10px 16px;border-radius:8px;font-size:13px;z-index:50}
</style></head><body><header>
<h1>dnshub files <span class=meta>by Mostfa</span></h1><div class=meta id=hstat></div>
<div class=row style=margin-left:auto>
 <span class=meta>path:</span><span id=crumb>~</span></div>
</header><main>
<div class=row style="margin:14px 0">
 <input type=file id=up multiple style="color:#c9d1d9;font-size:13px">
 <button class=pri id=bu>Upload here</button>
 <input id=nf placeholder="new folder name" style="width:170px;margin:0 6px;
  background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:7px 10px;border-radius:6px">
 <button id=bd>Make folder</button></div>
<table><thead><tr><th>Name</th><th>Size</th><th>Modified</th><th></th></tr></thead>
<tbody id=rows></tbody></table></main><div id=toast class=hide></div>
<script>
const $=i=>document.getElementById(i),esc=s=>String(s==null?'':s).replace(/[&<>"']/g,
 c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let path='';
function say(t,cls){const e=$('toast');e.textContent=t;e.className=cls||'';
 setTimeout(()=>e.classList.add('hide'),4200)}
async function api(p,o){o=o||{};
 const r=await fetch(p,o);
 if(!r.ok){let m='http '+r.status;try{m=(await r.json()).message||m}catch(e){}
  throw new Error(m)}return r}
function heading(){$('crumb').textContent=path||'~';
 $('crumb').onclick=()=>{path='';load()};
 refresh(path)}
async function load(){heading();
 try{const j=await (await api('/browse'+qpath())).json();
  $('hstat').textContent=j.entries.length+' entries';
  $('rows').innerHTML=j.entries.map(f=>
   '<tr><td>'+(f.dir?'<span class=crumb onclick="openDir(\''+esc(f.name).replace(/'/g,"\\'")+'\')">'
    +'['+esc(f.name)+']</span>':esc(f.name))+'</td><td>'+esc(f.size_h)+'</td><td class=meta>'
   +esc(f.mtime)+'</td><td class=row style=justify-content:flex-end>'+
   (f.dir?'':'<button onclick="dl(\''+esc(f.name).replace(/'/g,"\\'")+'\')">Download</button>')+
   '<button class=dan onclick="rm(\''+esc(f.name).replace(/'/g,"\\'")+'\')">Delete</button>'
   +'</td></tr>').join('')||'<tr><td colspan=4 class=meta>empty folder</td></tr>';
 }catch(e){say('load: '+e.message,'toast')}}
const qpath=()=>path?('?path='+encodeURIComponent(path)):'';
const qp=p=>'?path='+encodeURIComponent(p);
const qp2=(p,n)=>'?path='+encodeURIComponent(p||'')+'&name='+encodeURIComponent(n);
function openDir(n){path=path?path+'/'+n:n;load()}
$('bu').onclick=async()=>{const fs=$('up').files;if(!fs.length)return;
 $('bu').disabled=true;$('bu').textContent='uploading...';
 try{for(const f of fs){
  const r=await api('/upload'+qp2(path,f.name),
   {method:'PUT',body:f});
  say('uploaded '+f.name,'')}}
 catch(e){say(e.message)}finally{$('bu').disabled=false;$('bu').textContent='Upload here';load()}};
$('bd').onclick=async()=>{const n=$('nf').value.trim();if(!n)return;
 try{await api('/mkdir'+qp2(path,n),
  {method:'POST'});$('nf').value='';load()}
 catch(e){say(e.message)}};
async function dl(n){try{const r=await api('/download'+qp(path?path+'/'+n:n));
 const url=URL.createObjectURL(await r.blob());
 const a=document.createElement('a');a.href=url;a.download=n;
 document.body.appendChild(a);a.click();a.remove();
 URL.revokeObjectURL(url)}catch(e){say(e.message)}}
async function rm(n){if(!confirm('delete '+n+'?'))return;
 try{await api('/file'+qp(path?path+'/'+n:n),{method:'DELETE'});load()}
 catch(e){say(e.message)}}
load();
</script></body></html>"""


async def main() -> int:
    ROOT.mkdir(parents=True, exist_ok=True)
    server = await asyncio.start_server(handle, BIND, PORT)
    log(f"http://{BIND}:{PORT} root={ROOT}")
    async with server:
        await server.serve_forever()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(130)