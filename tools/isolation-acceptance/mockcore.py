#!/usr/bin/env python3
"""SYNTHETIC Bitcoin Core JSON-RPC stand-in for isolation/crash tests.

It is not a Bitcoin node: block hashes are sha256("rbzk-synthetic-<h>"),
and an override file can remap a height to simulate an active-chain change
("simulated reorg"). Nothing it returns is mainnet evidence.
"""
import base64
import hashlib
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("MOCKCORE_PORT", "18332"))
COOKIE = os.environ["MOCKCORE_COOKIE"]          # "user:password"
OVERRIDES = os.environ.get("MOCKCORE_OVERRIDES", "/var/lib/rbzk-mockcore/overrides.json")
TIP = 950000


def block_hash(height: int) -> str:
    try:
        with open(OVERRIDES, encoding="utf8") as f:
            remap = json.load(f)
    except (OSError, ValueError):
        remap = {}
    if str(height) in remap:
        return remap[str(height)]
    return hashlib.sha256(f"rbzk-synthetic-{height}".encode()).hexdigest()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        expected = "Basic " + base64.b64encode(COOKIE.encode()).decode()
        if self.headers.get("Authorization") != expected:
            self.send_response(401)
            self.end_headers()
            return
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        method, params = body.get("method"), body.get("params") or []
        error, result = None, None
        if method == "getblockhash":
            height = params[0]
            if not isinstance(height, int) or not 0 <= height <= TIP:
                error = {"code": -8, "message": "Block height out of range"}
            else:
                result = block_hash(height)
        elif method == "getblockchaininfo":
            result = {"chain": "main", "blocks": TIP, "headers": TIP,
                      "bestblockhash": block_hash(TIP), "initialblockdownload": False,
                      "verificationprogress": 1.0, "pruned": False}
        elif method == "getindexinfo":
            result = {}
        else:
            error = {"code": -32601, "message": "Method not found (synthetic core)"}
        payload = json.dumps({"result": result, "error": error, "id": body.get("id")}).encode()
        self.send_response(200 if error is None else 500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    print(f"synthetic core on 127.0.0.1:{PORT}", file=sys.stderr, flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
