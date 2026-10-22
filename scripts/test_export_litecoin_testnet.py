"""Offline regression checks for the Litecoin Core evidence exporter."""

import hashlib
import struct
import unittest

from export_litecoin_testnet import (
    LITECOIN_TESTNET_GENESIS,
    build_claim,
    double_sha256,
    merkle_branch,
    parse_hash,
    RpcClient,
)


class MerkleBranchTests(unittest.TestCase):
    def test_two_leaves(self):
        txids = ["01" * 32, "02" * 32]
        siblings, root = merkle_branch(txids, 1)
        expected = double_sha256(parse_hash(txids[0]) + parse_hash(txids[1]))
        self.assertEqual(siblings, [txids[0]])
        self.assertEqual(root, expected[::-1].hex())

    def test_three_leaf_odd_duplication(self):
        txids = ["01" * 32, "02" * 32, "03" * 32]
        siblings, root = merkle_branch(txids, 2)
        self.assertEqual(siblings[0], txids[2])
        ab = double_sha256(parse_hash(txids[0]) + parse_hash(txids[1]))
        cc = double_sha256(parse_hash(txids[2]) * 2)
        self.assertEqual(siblings[1], ab[::-1].hex())
        self.assertEqual(root, double_sha256(ab + cc)[::-1].hex())

    def test_rejects_incorrect_indices(self):
        with self.assertRaises(ValueError):
            merkle_branch([], 0)
        with self.assertRaises(ValueError):
            merkle_branch(["01" * 32], 1)
        with self.assertRaises(ValueError):
            parse_hash("xyz")


class ExportClaimTests(unittest.TestCase):
    def fake_node(self, genesis=LITECOIN_TESTNET_GENESIS, chain="test"):
        txids = ["01" * 32, "02" * 32]
        _, root = merkle_branch(txids, 1)
        header = (
            struct.pack("<I", 1)
            + bytes(32)
            + parse_hash(root)
            + struct.pack("<III", 1486949366, 0x1e0ffff0, 293345)
        )
        block_hash = double_sha256(header)[::-1].hex()
        answers = {
            ("getblockchaininfo", ()): {"chain": chain, "blocks": 1000},
            ("getblockhash", (0,)): genesis,
            ("getblockhash", (100,)): block_hash,
            ("getblock", (block_hash, 1)): {
                "hash": block_hash, "height": 100,
                "confirmations": 3, "tx": txids,
            },
            ("getblockheader", (block_hash, False)): header.hex(),
            ("getrawtransaction", (txids[1], False, block_hash)): "01000000",
        }

        def mock(method, params):
            return answers[method, tuple(params)]

        return mock, txids[1]

    def test_exported_claim_shape(self):
        rpc, txid = self.fake_node()
        claim = build_claim(rpc, txid, 100)
        self.assertEqual(claim["network"], "testnet")
        self.assertEqual(claim["chain"], "litecoin")
        self.assertEqual(claim["merkle_siblings"], ["01" * 32])
        self.assertEqual(claim["transaction_count"], 2)
        self.assertEqual(claim["genesis_hash"], LITECOIN_TESTNET_GENESIS)

    def test_rejects_wrong_genesis_and_chain(self):
        rpc, txid = self.fake_node(genesis="00" * 32)
        with self.assertRaises(ValueError):
            build_claim(rpc, txid, 100)
        rpc, txid = self.fake_node(chain="main")
        with self.assertRaises(ValueError):
            build_claim(rpc, txid, 100)

    def test_rpc_credentials_stay_on_loopback_by_default(self):
        with self.assertRaises(ValueError):
            RpcClient("http://example.com", "alice", "secret")
        with self.assertRaises(ValueError):
            RpcClient("http://example.com", "alice", "secret", allow_remote=True)
        client = RpcClient("http://127.0.0.1:19332", "alice", "secret")
        self.assertTrue(client.url.startswith("http://127.0.0.1"))


if __name__ == "__main__":
    unittest.main()
