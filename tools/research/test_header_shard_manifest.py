"""Independent synthetic fixtures for R0 mock-only shard-boundary validation.

These are arbitrary claimed states, NOT actual mainnet headers or proofs.
"""
import copy
import hashlib
import json
import unittest

from header_shard_manifest import ManifestError, check_mock_manifest


def digest(label):
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def claimed_state(height, work=None):
    # Hand-made fixture construction. These fields are NOT derived by a
    # Bitcoin consensus validator or any proof system.
    first = ((height - 1) // 2016) * 2016
    return {
        "next_height": height,
        "tip_hash": digest(f"mock-last-header-{height - 1}"),
        "cumulative_work_hex": f"{work if work is not None else height * 1000:064x}",
        "last_nbits_hex": "1d00ffff",
        "retarget_first_height": first,
        "retarget_first_timestamp": 1231006505 + first * 600,
        "last_11_timestamps": list(
            range(1231006505 + max(height - 11, 0),
                  1231006505 + height)
        ),
        "header_history_commitment": digest(f"mock-history-to-{height}"),
    }


def claimed_shard(start, end):
    return {
        "schema": "bitcoin_header_shard_mock_v0",
        "network": "bitcoin-mainnet",
        "ruleset": "bitcoin-mainnet-header-experimental-v0",
        "anchor_id": "aa" * 32,
        "start_height": start,
        "end_height_exclusive": end,
        "starting_state": claimed_state(start),
        "ending_state": claimed_state(end),
        "claimed_segment_digest": digest(f"mock-segment-{start}-{end}"),
    }


def fixture():
    return {
        "schema": "bitcoin_header_shard_mock_v0",
        "anchor": {
            "mode": "declared_checkpoint",
            "id": "aa" * 32,
            "provenance": "UNAUTHENTICATED",
        },
        "shards": [
            claimed_shard(100, 132),
            claimed_shard(132, 164),
            claimed_shard(164, 196),
            claimed_shard(196, 228),
        ],
    }


def encoded(value):
    return json.dumps(value, separators=(",", ":"), allow_nan=False).encode()


class ShardStructureTests(unittest.TestCase):
    def assert_rejected(self, obj, reason=None):
        with self.assertRaises(ManifestError) as ctx:
            check_mock_manifest(encoded(obj))
        if reason:
            self.assertIn(reason, str(ctx.exception))

    def test_four_32_header_shards_are_only_structurally_consistent(self):
        outcome = check_mock_manifest(encoded(fixture()))
        self.assertEqual(outcome["status"], "UNVERIFIED")
        self.assertEqual(outcome["acceptance"], "NOT_CHECKED")
        self.assertEqual(outcome["shard_claims"], 4)
        self.assertEqual(outcome["boundary_links_compared"], 3)
        self.assertFalse(outcome["checkpoint_authenticated"])
        self.assertEqual(outcome["headers_cryptographically_validated"], 0)
        self.assertEqual(outcome["proofs_verified"], 0)
        self.assertEqual(len(outcome["manifest_sha256"]), 64)

    def test_detects_gap_overlap_and_out_of_order(self):
        for start, end in ((133, 164), (131, 164), (164, 196)):
            with self.subTest(start=start, end=end):
                data = fixture()
                data["shards"][1] = claimed_shard(start, end)
                self.assert_rejected(data, "gap, overlap or reordered")
        data = fixture()
        data["shards"].reverse()
        self.assert_rejected(data, "gap, overlap or reordered")

    def test_rejects_every_changed_boundary_context(self):
        fields = (
            "tip_hash", "cumulative_work_hex", "last_nbits_hex",
            "retarget_first_timestamp", "last_11_timestamps",
            "header_history_commitment",
        )
        for field in fields:
            with self.subTest(field=field):
                data = fixture()
                state = data["shards"][1]["starting_state"]
                if field == "last_11_timestamps":
                    state[field][0] += 1
                elif field == "retarget_first_timestamp":
                    state[field] += 1
                elif field == "last_nbits_hex":
                    state[field] = "1d00fffe"
                else:
                    state[field] = "bb" * 32
                self.assert_rejected(data, "changed shard boundary context")

    def test_checkpoint_and_network_ruleset_cannot_change_mid_graph(self):
        for path, value in (
            (("anchor", "provenance"), "VERIFIED"),
            (("anchor", "mode"), "claimed_genesis"),
            (("shards", 2, "anchor_id"), "bb" * 32),
            (("shards", 2, "network"), "litecoin-mainnet"),
            (("shards", 2, "ruleset"), "other-consensus"),
        ):
            with self.subTest(path=path):
                data = fixture()
                node = data
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = value
                self.assert_rejected(data)

    def test_invalid_hex_or_unchecked_work_is_not_promoted(self):
        for name, invalid in (
            ("tip_hash", "f" * 63),
            ("tip_hash", "F" * 64),
            ("cumulative_work_hex", "z" * 64),
            ("last_nbits_hex", "1d0ffff"),
            ("header_history_commitment", ""),
        ):
            with self.subTest(field=name):
                data = fixture()
                data["shards"][0]["starting_state"][name] = invalid
                self.assert_rejected(data)
        data = fixture()
        data["shards"][0]["ending_state"]["cumulative_work_hex"] = (
            data["shards"][0]["starting_state"]["cumulative_work_hex"]
        )
        self.assert_rejected(data, "non-increasing")
        # Deliberately lie about ALL work in a mutually consistent way.
        # This cannot become a real work proof merely because it is ordered.
        data = fixture()
        for idx, shard in enumerate(data["shards"]):
            shard["starting_state"]["cumulative_work_hex"] = f"{2**230 + idx:064x}"
            shard["ending_state"]["cumulative_work_hex"] = f"{2**230 + idx + 1:064x}"
        report = check_mock_manifest(encoded(data))
        self.assertEqual(report["status"], "UNVERIFIED")
        self.assertEqual(report["proofs_verified"], 0)

    def test_malformed_json_unknown_duplicate_fields_and_numbers(self):
        for raw in (b"", b"{", b"\xff", b'{"schema": "x", "schema": "y"}'):
            with self.subTest(raw=raw[:30]):
                with self.assertRaises(ManifestError):
                    check_mock_manifest(raw)
        data = fixture()
        data["not_in_contract"] = True
        self.assert_rejected(data, "missing or unknown")
        data = fixture()
        data["shards"][0]["proof_verified"] = True
        self.assert_rejected(data, "missing or unknown")
        data = fixture()
        del data["shards"][1]["starting_state"]["last_11_timestamps"]
        self.assert_rejected(data, "missing or unknown")
        raw = encoded(fixture()).replace(b"1231006505", b"NaN", 1)
        with self.assertRaises(ManifestError):
            check_mock_manifest(raw)

    def test_rejects_bool_height_bad_mtp_and_epoch_context(self):
        for location, invalid in (
            ("start_height", True),
            ("end_height_exclusive", 0),
            ("end_height_exclusive", 645),
        ):
            with self.subTest(field=location):
                data = fixture()
                data["shards"][0][location] = invalid
                self.assert_rejected(data)
        for field, invalid in (
            ("next_height", True),
            ("retarget_first_height", 2016),
            ("retarget_first_timestamp", -1),
            ("last_11_timestamps", [123]),
            ("last_11_timestamps", [True] * 11),
        ):
            with self.subTest(field=field):
                data = fixture()
                data["shards"][0]["starting_state"][field] = invalid
                self.assert_rejected(data)

    def test_retarget_boundary_has_to_preserve_entire_boundary_state(self):
        # A shape-only retarget boundary: no nBits recomputation is done.
        data = fixture()
        data["shards"] = [claimed_shard(2000, 2016),
                          claimed_shard(2016, 2032)]
        report = check_mock_manifest(encoded(data))
        self.assertEqual(report["status"], "UNVERIFIED")
        data["shards"][1]["starting_state"]["retarget_first_height"] = 2016
        self.assert_rejected(data, "retarget-epoch")

    def test_bounds_and_untrusted_checkpoint_enforced(self):
        data = fixture()
        data["shards"] = data["shards"] * 65
        self.assert_rejected(data, "excessive shard")
        data = fixture()
        data["shards"] = []
        self.assert_rejected(data, "missing or excessive")
        with self.assertRaises(ManifestError):
            check_mock_manifest(b"x" * (128 * 1024 + 1))
        data = fixture()
        data["shards"][0] = claimed_shard(100, 613)
        self.assert_rejected(data, "excessive header range")
        data = fixture()
        data["anchor"]["id"] = "cc" * 32
        self.assert_rejected(data, "changed checkpoint")

    def test_manifest_id_is_stable_but_does_not_certify_claims(self):
        baseline = fixture()
        shuffled = copy.deepcopy(baseline)
        shuffled["anchor"] = dict(reversed(list(shuffled["anchor"].items())))
        left = check_mock_manifest(encoded(baseline))
        right = check_mock_manifest(encoded(shuffled))
        self.assertEqual(left["manifest_sha256"], right["manifest_sha256"])
        changed = copy.deepcopy(baseline)
        changed["shards"][0]["claimed_segment_digest"] = "fe" * 32
        different = check_mock_manifest(encoded(changed))
        self.assertNotEqual(left["manifest_sha256"], different["manifest_sha256"])
        self.assertEqual(different["status"], "UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
