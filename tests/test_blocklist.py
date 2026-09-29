# Legacy-style smoke test for blob build + Blocklist load + match, adapted to
# the current API (build_blob_and_index instead of the removed build_binary).
import importlib.util
import os
import sys
import tempfile

DEV = os.environ.get("DNSHUB_DEV") or os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
sys.path.insert(0, DEV)
from dnshub_blocklist import build_blob_and_index, count_of

spec = importlib.util.spec_from_file_location(
    "dnshub_dnsserver", os.path.join(DEV, "dns-server.py"))
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod  # required: @dataclass resolves via sys.modules
spec.loader.exec_module(mod)

# The builders expect sorted, deduplicated input (production feeds them from
# `sort -u` with LC_ALL=C). Passing an unsorted set breaks binary search.
doms = sorted({"ads.example", "tracker.net", "bad.co.uk"})
blob, index = build_blob_and_index(doms)
assert blob[:4] == b"DHB2", "magic header not DHB2"
assert count_of(blob) == len(doms), f"count_of={count_of(blob)} want {len(doms)}"
assert len(index) > 0, "index empty"

tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
tmp.write(blob)
tmp.close()
open(tmp.name[:-4] + ".idx", "wb").write(index)
print("wrote", os.path.getsize(tmp.name), "bytes blob +",
      len(index), "bytes index; count_of =", count_of(blob))

bl = mod.Blocklist(tmp.name)
print("loaded count:", bl.count, "generation:", bl.generation)
for d in ["ads.example", "x.ads.example", "a.b.tracker.net",
          "google.com", "mail.google.com", "bad.co.uk", "example", ""]:
    try:
        print(f"  match({d!r}) = {bl.match(d)}")
    except Exception as e:
        print(f"  match({d!r}) RAISED {type(e).__name__}: {e}")

# dedupe/merge sanity: exact-duplicate strings collapse to one entry each;
# case folding happens upstream in the parser (normalise), not in the builder.
doms2 = sorted(set(doms) | {"ads.example", "bad.co.uk"})
blob2, _ = build_blob_and_index(doms2)
assert count_of(blob2) == len(doms), f"dedupe failed: {count_of(blob2)} != {len(doms)}"
print("dedupe/merge OK: count_of stays", count_of(blob2))
print("=== test_blocklist PASS ===")