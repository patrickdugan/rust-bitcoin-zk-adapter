#!/usr/bin/env python3
"""Fetch mainnet headers 30240 and 32240..32300 (around the first difficulty
change at 32256) from the mempool.space Esplora API into data/retarget.txt.

Each header is rebuilt from the block JSON and its double SHA-256 is checked
against the block id, so the API cannot hand back a mismatched header.
"""
import hashlib
import json
import struct
import sys
import time
import urllib.request

API = "https://mempool.space/api"
WANT = [30240] + list(range(32240, 32301))


def get(path):
    with urllib.request.urlopen(API + path, timeout=30) as r:
        return json.loads(r.read())


def header(b):
    raw = (struct.pack("<i", b["version"]) + bytes.fromhex(b["previousblockhash"])[::-1]
           + bytes.fromhex(b["merkle_root"])[::-1]
           + struct.pack("<III", b["timestamp"], b["bits"], b["nonce"]))
    assert hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex() == b["id"], b["height"]
    return raw


def main(out):
    got = {}
    for h in sorted(set(WANT)):
        if h in got:
            continue
        for b in get(f"/blocks/{h + 9}"):  # ten blocks, descending from h+9
            got[b["height"]] = header(b)
        time.sleep(0.5)
    with open(out, "w") as f:
        for h in WANT:
            f.write(f"{h} {got[h].hex()}\n")
    print(f"wrote {len(WANT)} headers to {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "data/retarget.txt")
