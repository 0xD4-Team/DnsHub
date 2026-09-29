#!/usr/bin/env python3
"""
dnshub_blocklist.py - on-disk compiled blocklist format (v2, "DHB2").

Why v2 exists
-------------
v1 stored the blob plus an implicit offset sequence, and the resolver had to
scan the blob once at load time to build a Python list of offsets. At 416k
domains that list costs ~20 MiB of heap. Scaling to several million domains
(what the aggregation goal requires) would push it past 150 MiB and, together
with the blob held as a Python bytes object, risk an OOM on a host with
1.36 GiB available - taking the resolver down with it.

v2 moves the offset table into its own file so both the blob and the index can
be mmap'd. A binary search then costs zero Python objects: the index is read
straight out of the mapped page and the candidate domain is sliced out of the
mapped blob. Resident memory becomes a function of pages actually touched, not
of list size, so the same code path serves 400k or 4,000,000 domains.

Layout
------
  blob file  (blocklist.compiled.bin)
      0  magic   4 bytes  b"DHB2"
      4  count   4 bytes  uint32 little-endian
      8  records repeated, in ascending byte order:
             len_u8, then len_u8 bytes of ASCII domain

  index file (blocklist.compiled.idx)
      count records of uint32 little-endian, each the byte offset of the
      corresponding record in the blob file (i.e. offset 8 for entry 0).

Two files rather than one interleaved table so the index can be mmap'd on its
own and read with struct.unpack_from / int.from_bytes without slicing bytes
objects.
"""
from __future__ import annotations

import struct

MAGIC = b"DHB2"
HEADER = struct.Struct("<4sI")
INDEX_ENTRY = struct.Struct("<I")


def build_blob_and_index(domains) -> tuple[bytes, bytearray]:
    """
    Compile a domain iterable into (blob, index).

    `domains` must already be deduplicated and sorted; the caller is expected
    to have done that with `sort -u` so peak memory stays flat. Duplicate
    entries are tolerated here (the index still lines up) but would waste
    space, so the sort is not optional.

    Returns the blob as bytes and the index as a bytearray, letting the caller
    stream the blob to disk instead of holding both plus the source set.
    """
    blob = bytearray()
    blob += HEADER.pack(MAGIC, 0)          # count patched in below
    index = bytearray()
    n = 0
    for d in domains:
        b = (d.encode("idna") if any(ord(c) > 127 for c in d)
             else d.encode("ascii", "ignore"))
        if not b or len(b) > 255 or len(b) > 253:
            continue
        index += INDEX_ENTRY.pack(len(blob))
        blob.append(len(b))
        blob += b
        n += 1
    # Patch the count now that it is known.
    blob[4:8] = struct.pack("<I", n)
    return bytes(blob), index


def count_of(blob: bytes) -> int:
    if len(blob) < 8 or blob[:4] != MAGIC:
        raise ValueError("not a DHB2 blob")
    return struct.unpack("<I", blob[4:8])[0]


class BlobWriter:
    """
    Streaming compiler. Writes straight to two file handles so neither the
    blob nor the index is ever fully resident.

    `build_blob_and_index` is convenient for tests and small lists but builds
    the whole blob in memory first; at several million domains that is a
    ~110 MiB spike for a 55 MiB result, which is exactly the kind of peak that
    an OOM killer punishes on a 1.36 GiB host.
    """

    def __init__(self, blob_fh, index_fh):
        self.blob = blob_fh
        self.index = index_fh
        self.count = 0
        # Header is reserved up front and rewritten with the real count at
        # close(), so a reader never sees count=0 on a half-written file.
        self.blob.write(HEADER.pack(MAGIC, 0))

    def add(self, domain: str) -> None:
        b = (domain.encode("idna") if any(ord(c) > 127 for c in domain)
             else domain.encode("ascii", "ignore"))
        if not b or len(b) > 253:
            return
        self.index.write(INDEX_ENTRY.pack(self.blob.tell()))
        self.blob.write(bytes((len(b),)))
        self.blob.write(b)
        self.count += 1

    def close(self) -> int:
        self.blob.flush()
        end = self.blob.tell()
        self.blob.seek(4)
        self.blob.write(struct.pack("<I", self.count))
        self.blob.flush()
        self.blob.seek(end)
        self.blob.truncate()
        self.index.flush()
        return self.count
