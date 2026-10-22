#!/usr/bin/env python3
"""Export one historical Litecoin testnet transaction from Litecoin Core JSON-RPC.

The exporter anchors chain identity by getblockhash(0), obtains the block hash
from getblockhash(height), and independently constructs an ordinary transaction
Merkle branch from the node's ordered txids. The Rust verifier checks the
resulting evidence again. Litecoin Core remains the chain-validity authority.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)

LITECOIN_TESTNET_GENESIS = (
    "4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0"
)
MAX_RPC_RESPONSE_BYTES = 24_000_000
MAX_BLOCK_TXIDS = 100_000


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def parse_hash(text: str) -> bytes:
    if not isinstance(text, str) or len(text) != 64:
        raise ValueError("expected 64-character hash")
    try:
        return bytes.fromhex(text)[::-1]
    except ValueError as error:
        raise ValueError("invalid hash hex") from error


def merkle_branch(txids: list[str], index: int) -> tuple[list[str], str]:
    if not 0 < len(txids) <= MAX_BLOCK_TXIDS:
        raise ValueError("empty or excessively large block transaction list")
    if not 0 <= index < len(txids):
        raise ValueError("transaction index out of range")
    leaves = [parse_hash(txid) for txid in txids]
    path = []
    current_index = index
    while len(leaves) > 1:
        adjacent = current_index ^ 1
        if adjacent >= len(leaves):
            adjacent = current_index
        path.append(leaves[adjacent][::-1].hex())
        if len(leaves) % 2:
            leaves.append(leaves[-1])
        leaves = [
            double_sha256(leaves[i] + leaves[i + 1])
            for i in range(0, len(leaves), 2)
        ]
        current_index //= 2
    return path, leaves[0][::-1].hex()


class RefuseRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("refusing RPC redirect to protect credentials")


class RpcClient:
    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        allow_remote: bool = False,
    ):
        parsed = urlsplit(url)
        loopback = parsed.hostname in ("127.0.0.1", "localhost", "::1")
        if parsed.scheme not in ("http", "https"):
            raise ValueError("RPC URL must be HTTP(S)")
        if not loopback and not allow_remote:
            raise ValueError("remote RPC requires explicit --allow-remote-rpc")
        if not loopback and parsed.scheme != "https":
            raise ValueError("remote RPC must use TLS")
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError("place RPC credentials in environment or cookie")
        if not username or not password:
            raise ValueError("RPC credentials missing")
        self.url = url
        self.auth = base64.b64encode(
            (username + ":" + password).encode("utf-8")
        ).decode("ascii")
        self.opener = build_opener(RefuseRedirect)

    def __call__(self, method: str, params: list):
        payload = json.dumps(
            {"jsonrpc": "1.0", "id": "zk-adapter-export", "method": method, "params": params}
        ).encode("utf-8")
        request = Request(
            self.url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Basic " + self.auth,
            },
            method="POST",
        )
        with self.opener.open(request, timeout=30) as response:
            body = response.read(MAX_RPC_RESPONSE_BYTES + 1)
        if len(body) > MAX_RPC_RESPONSE_BYTES:
            raise ValueError("RPC response exceeds configured byte limit")
        message = json.loads(body)
        if message.get("error") is not None:
            raise RuntimeError("%s: %s" % (method, message["error"]))
        return message["result"]


def build_claim(rpc, txid: str, height: int) -> dict:
    target = parse_hash(txid)[::-1].hex()
    if height < 1:
        raise ValueError("provide a positive historical block height")
    chain_info = rpc("getblockchaininfo", [])
    if chain_info.get("chain") not in ("test", "testnet", "testnet3", "testnet4"):
        raise ValueError("RPC node reports a non-testnet chain")
    if height > chain_info.get("blocks", -1):
        raise ValueError("height exceeds the node's active testnet tip")

    genesis = rpc("getblockhash", [0]).lower()
    if genesis != LITECOIN_TESTNET_GENESIS:
        raise ValueError("Litecoin testnet genesis does not match pinned anchor")

    block_hash = rpc("getblockhash", [height]).lower()
    parse_hash(block_hash)
    block = rpc("getblock", [block_hash, 1])
    if block.get("hash", "").lower() != block_hash:
        raise ValueError("block response hash differs from active-chain lookup")
    if block.get("height") != height:
        raise ValueError("block response height mismatch")
    if block.get("confirmations", 0) <= 0:
        raise ValueError("block is not confirmed on the queried node")
    txids = block.get("tx", [])
    if len(txids) != len(set(txids)):
        raise ValueError("duplicate transaction IDs in block response")
    if target not in txids:
        raise ValueError("txid absent from block at supplied height")
    index = txids.index(target)

    header_hex = rpc("getblockheader", [block_hash, False]).lower()
    header = bytes.fromhex(header_hex)
    if len(header) != 80:
        raise ValueError("Litecoin header must be 80 bytes")
    if double_sha256(header)[::-1].hex() != block_hash:
        raise ValueError("header hash does not match Litecoin Core block hash")

    siblings, root = merkle_branch(txids, index)
    if header[36:68][::-1].hex() != root:
        raise ValueError("block txids do not match header Merkle root")

    tx_hex = rpc("getrawtransaction", [target, False, block_hash]).lower()
    if not isinstance(tx_hex, str) or len(tx_hex) > 8_000_000:
        raise ValueError("raw transaction hex missing or oversized")
    bytes.fromhex(tx_hex)

    return {
        "schema_version": 1,
        "chain": "litecoin",
        "network": "testnet",
        "genesis_hash": genesis,
        "block_height": height,
        "block_hash": block_hash,
        "block_header_hex": header_hex,
        "txid": target,
        "raw_transaction_hex": tx_hex,
        "tx_index": index,
        "transaction_count": len(txids),
        "merkle_siblings": siblings,
    }


def credentials(args):
    if args.cookie_file:
        userpass = Path(args.cookie_file).read_text(encoding="utf-8").strip()
        if ":" not in userpass:
            raise ValueError("RPC cookie missing colon separator")
        return userpass.split(":", 1)
    return (
        os.environ.get("LITECOIN_RPC_USER", ""),
        os.environ.get("LITECOIN_RPC_PASSWORD", ""),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--txid", required=True)
    parser.add_argument("--height", type=int, required=True)
    parser.add_argument("--rpc-url", default="http://127.0.0.1:19332")
    parser.add_argument("--cookie-file", help="Litecoin Core RPC .cookie path")
    parser.add_argument("--allow-remote-rpc", action="store_true")
    parser.add_argument("--out", default="-", help="Output JSON file, or - for stdout")
    args = parser.parse_args()

    try:
        username, password = credentials(args)
        client = RpcClient(
            args.rpc_url, username, password, allow_remote=args.allow_remote_rpc
        )
        claim = build_claim(client, args.txid, args.height)
        output = json.dumps(claim, sort_keys=True, indent=2) + "\n"
        if args.out == "-":
            sys.stdout.write(output)
        else:
            Path(args.out).write_text(output, encoding="utf-8")
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        parser.exit(1, "Evidence export failed: %s\n" % error)


if __name__ == "__main__":
    main()
