#!/usr/bin/env python3
"""Isolate the DHB2 Blocklist behaviour that the resolver selftest exercises."""
import importlib.util
import os
import shutil
import struct
import sys
import tempfile

# sys.path[0] is this script's own directory, and a stale /tmp/dnshub_blocklist.py
# from an earlier session was shadowing the real module with a v1 copy that has
# no BlobWriter. Put the project directory first, unconditionally.
DEV = os.environ.get("DNSHUB_DEV") or os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
sys.path.insert(0, DEV)
for _stale in ("/tmp/dnshub_blocklist.py", "/tmp/dnshub_blocklist.pyc"):
    if os.path.exists(_stale):
        os.unlink(_stale)

sys.argv = ["x"]
# spec_from_file_location picks a loader by file extension and returns None for
# anything that is not .py/.pyc, so stage the candidate under a real name.
import shutil as _sh
_cand = os.path.join(DEV, "dns-server.new")
if not os.path.exists(_cand):
    _cand = os.path.join(DEV, "dns-server.py")
_sh.copy(_cand, "/tmp/ds_candidate.py")
spec = importlib.util.spec_from_file_location(
    "ds", "/tmp/ds_candidate.py")
ds = importlib.util.module_from_spec(spec)
# dataclasses resolves annotations through sys.modules[cls.__module__], so the
# module must be registered before exec_module or @dataclass raises.
sys.modules["ds"] = ds
spec.loader.exec_module(ds)

from dnshub_blocklist import BlobWriter  # noqa: E402

tdir = tempfile.mkdtemp(prefix="bltest-")
bpath, xpath = os.path.join(tdir, "t.bin"), os.path.join(tdir, "t.idx")
doms = sorted({"ads.example", "tracker.net", "bad.co.uk"})
print(f"  compiling {doms} with LC_ALL=C byte order")
with open(bpath, "wb") as bf, open(xpath, "wb") as xf:
    w = BlobWriter(bf, xf)
    for d in doms:
        w.add(d)
    n = w.close()
print(f"  BlobWriter wrote {n} entries, blob={os.path.getsize(bpath)}B "
      f"idx={os.path.getsize(xpath)}B")

with open(bpath, "rb") as f:
    raw = f.read()
print(f"  header: magic={raw[:4]!r} count={struct.unpack('<I', raw[4:8])[0]}")
print(f"  raw blob bytes: {raw!r}")

bl = ds.Blocklist(bpath)
print(f"  Blocklist loaded count={bl.count} blob={bl.blob is not None} "
      f"idx={bl.idx is not None} idx_path={bl.idx_path}")
if bl.count:
    off = struct.unpack_from("<I", bl.idx, 0)[0]
    ln = bl.blob[off]
    print(f"  entry(0): off={off} len={ln} bytes={bl.blob[off+1:off+1+ln]!r}")

for t, want in [("ads.example", True), ("x.ads.example", True),
                ("a.b.tracker.net", True), ("sub.bad.co.uk", True),
                ("google.com", False), ("mail.google.com", False),
                ("ADS.Example", True), ("ads.example.", True)]:
    got = bl.match(t)
    print(f"  {'ok ' if got == want else 'BAD'} match({t!r:24}) = {got} "
          f"(want {want})")

# mismatched index must be refused
with open(xpath, "r+b") as f:
    f.truncate(4)
bad = ds.Blocklist(bpath)
print(f"  mismatched index -> count={bad.count} (want 0), "
      f"match returns {bad.match('ads.example')} (want False)")
shutil.rmtree(tdir, ignore_errors=True)
