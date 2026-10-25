"""Unit checks for bounded Supernode benchmark helpers."""
import contextlib
import copy
import hashlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from tools.benchmark_supernode import (
    cgroup_io_delta, main, loopback_url, percentiles, proof_retrieve,
    require_hash, run_job, select_cgroups, snapshot_cgroup, parse_cgroup_counter,
    read_cgroup_counter_file, validate_raito_receipt, RAITO_STATEMENT,
    RAITO_VERIFIER, MAX_RAITO_HEIGHT, MAX_CGROUP_IO_STAT_BYTES,
    MAX_CGROUP_METRIC_BYTES, MAX_VERIFIED_PROOF_BYTES,
    PROOF_CHUNK_BYTES, MAX_PROOF_DOWNLOAD_SECONDS,
)


class BenchmarkHelpersTest(unittest.TestCase):
    def test_percentiles_for_sparse_sample(self):
        self.assertEqual(percentiles([]), {})
        data = percentiles([1, 2, 3])
        self.assertEqual(data["n"], 3)
        self.assertEqual(data["p50_ms"], 2)
        self.assertAlmostEqual(data["p95_ms"], 2.9)

    def test_strict_hash(self):
        self.assertEqual(require_hash("AB" * 32), "ab" * 32)
        with self.assertRaises(ValueError):
            require_hash("0xff")

    def test_loopback_credentials_rejected(self):
        self.assertEqual(loopback_url("http://127.0.0.1:8332"), "http://127.0.0.1:8332")
        for url in ["https://example.com", "http://example.com",
                    "http://name:password@localhost:8332", "http://192.168.1.20:8332"]:
            with self.assertRaises(ValueError):
                loopback_url(url)



class FakeControl:
    def call(self, method, params):
        assert method == "zk.proof.submit"
        return {"job": {"id": "fixture-job"}}


class MutatingControl(FakeControl):
    def __init__(self, on_submit):
        self.on_submit = on_submit

    def call(self, method, params):
        self.on_submit()
        return super().call(method, params)


class FakeRead:
    def call(self, method, params):
        assert method == "zk.proof.status"
        return {"job": {
            "status": "completed_unverified",
            "error": "fixture only",
            "result_sha256": None,
        }}


def synthetic_receipt(proof_sha: str, *,
                      txid: str = "bb" * 32,
                      block_hash: str = "cc" * 32,
                      block_height: int = 42,
                      policy_sha: str = "aa" * 32) -> dict:
    """Gateway-shaped synthetic receipt. Never evidence of a real STARK."""
    return {
        "job_id": "fixture-job",
        "proof_verified": True,
        "active_chain_at_lookup": True,
        "output_retained": True,
        "result_sha256": proof_sha,
        "verified_statement": {
            "statement": RAITO_STATEMENT,
            "verifier": RAITO_VERIFIER,
            "txid": txid,
            "block_hash": block_hash,
            "block_height": block_height,
            "proven_tip_height": block_height + 1,
            "tx_index": 0,
            "proof_sha256": proof_sha,
            "policy_sha256": policy_sha,
        },
    }


class RaitoReceiptBindingTest(unittest.TestCase):
    @staticmethod
    def checked(reply: dict) -> dict:
        return validate_raito_receipt(
            reply, "fixture-job", "bb" * 32, "cc" * 32, 42,
            "aa" * 32, "11" * 32
        )

    def test_synthetic_fully_bound_receipt_is_accepted_as_schema_only(self):
        expected = synthetic_receipt("11" * 32)
        self.assertEqual(self.checked(expected), expected["verified_statement"])

    def test_receipt_must_bind_pinned_statement_and_block_policy_proof(self):
        baseline = synthetic_receipt("11" * 32)
        mutations = {
            "statement": "other_statement",
            "verifier": "untrusted-verifier",
            "txid": "ee" * 32,
            "block_hash": "ee" * 32,
            "block_height": 43,
            "proven_tip_height": 41,
            "tx_index": True,
            "proof_sha256": "ee" * 32,
            "policy_sha256": "ee" * 32,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(baseline)
                changed["verified_statement"][field] = replacement
                with self.assertRaises(ValueError):
                    self.checked(changed)

    def test_gateway_receipt_origin_chain_and_output_claims_required(self):
        baseline = synthetic_receipt("11" * 32)
        for key, value in (
            ("job_id", "other-job"),
            ("proof_verified", False),
            ("active_chain_at_lookup", False),
            ("output_retained", False),
            ("result_sha256", "ee" * 32),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(baseline)
                changed[key] = value
                with self.assertRaises(ValueError):
                    self.checked(changed)

    def test_unknown_or_missing_typed_fields_rejected(self):
        baseline = synthetic_receipt("11" * 32)
        for field in ("statement", "verifier", "txid", "block_hash",
                      "block_height", "proven_tip_height", "tx_index",
                      "proof_sha256", "policy_sha256"):
            with self.subTest(field=field):
                changed = copy.deepcopy(baseline)
                del changed["verified_statement"][field]
                with self.assertRaises(ValueError):
                    self.checked(changed)
        changed = copy.deepcopy(baseline)
        changed["verified_statement"]["extra_claim"] = "injected"
        with self.assertRaises(ValueError):
            self.checked(changed)

    def test_noninteger_and_out_of_range_tip_height_and_index_rejected(self):
        baseline = synthetic_receipt("11" * 32)
        for field, value in (
            ("block_height", True),
            ("proven_tip_height", True),
            ("proven_tip_height", MAX_RAITO_HEIGHT + 1),
            ("tx_index", -1),
            ("tx_index", MAX_RAITO_HEIGHT + 1),
        ):
            with self.subTest(field=field, value=value):
                changed = copy.deepcopy(baseline)
                changed["verified_statement"][field] = value
                with self.assertRaises(ValueError):
                    self.checked(changed)

    def test_missing_explicit_block_context_fails_closed(self):
        baseline = synthetic_receipt("11" * 32)
        for block_hash, height in ((None, 42), ("cc" * 32, None),
                                   ("cc" * 32, True),
                                   ("cc" * 32, MAX_RAITO_HEIGHT + 1)):
            with self.subTest(block_hash=block_hash, height=height):
                with self.assertRaises(ValueError):
                    validate_raito_receipt(
                        baseline, "fixture-job", "bb" * 32,
                        block_hash, height, "aa" * 32, "11" * 32
                    )


class SyntheticChunkGateway:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def call(self, method, params):
        assert method == "zk.proof.get"
        self.calls.append(params)
        return next(self.responses)


class ProofRetrievalTest(unittest.TestCase):
    @staticmethod
    def chunks_for(payload: bytes, job: str = "fixture-job") -> list[dict]:
        digest = hashlib.sha256(payload).hexdigest()
        return [
            {
                "job_id": job,
                "result_sha256": digest,
                "proof_verified": True,
                "verified_statement": synthetic_receipt(digest)["verified_statement"],
                "total_bytes": len(payload),
                "offset": offset,
                "next_offset": min(offset + PROOF_CHUNK_BYTES, len(payload)),
                "data_hex": payload[offset:offset + PROOF_CHUNK_BYTES].hex(),
                "complete": offset + PROOF_CHUNK_BYTES >= len(payload),
            }
            for offset in range(0, len(payload), PROOF_CHUNK_BYTES)
        ]

    @staticmethod
    def retrieve(gateway, job_id, digest, expected_bytes=None):
        return proof_retrieve(
            gateway, job_id, digest, expected_bytes,
            expected_statement=synthetic_receipt(digest)["verified_statement"]
        )

    def test_chunk_without_typed_receipt_is_rejected(self):
        payload = b"synthetic proof"
        digest = hashlib.sha256(payload).hexdigest()
        for bad in (None, [], False):
            with self.subTest(bad=bad):
                chunk = self.chunks_for(payload)[0]
                chunk["verified_statement"] = bad
                gateway = SyntheticChunkGateway([chunk])
                with self.assertRaisesRegex(
                        RuntimeError, "verified statement differs from receipt"):
                    self.retrieve(gateway, "fixture-job", digest)
                self.assertEqual(len(gateway.calls), 1)

    def test_every_chunk_must_agree_with_original_typed_receipt(self):
        payload = b"x" * PROOF_CHUNK_BYTES + b"yz"
        digest = hashlib.sha256(payload).hexdigest()
        for changed_chunk in (0, 1):
            for mutation in ("txid", "policy", "bool_index", "missing_field", "extra_field"):
                with self.subTest(chunk=changed_chunk, mutation=mutation):
                    responses = self.chunks_for(payload)
                    statement = responses[changed_chunk]["verified_statement"].copy()
                    if mutation == "txid":
                        statement["txid"] = "dd" * 32
                    elif mutation == "policy":
                        statement["policy_sha256"] = "ee" * 32
                    elif mutation == "bool_index":
                        # Python would normally consider 0 == False.
                        statement["tx_index"] = False
                    elif mutation == "missing_field":
                        del statement["verifier"]
                    elif mutation == "extra_field":
                        statement["untrusted"] = True
                    responses[changed_chunk]["verified_statement"] = statement
                    gateway = SyntheticChunkGateway(responses)
                    with self.assertRaisesRegex(
                            RuntimeError, "verified statement differs from receipt"):
                        self.retrieve(gateway, "fixture-job", digest, len(payload))
                    self.assertEqual(len(gateway.calls), changed_chunk + 1)

    def test_missing_expected_statement_rejected_before_rpc(self):
        gateway = SyntheticChunkGateway([])
        with self.assertRaisesRegex(ValueError, "validated Raito receipt statement"):
            proof_retrieve(
                gateway, "fixture-job", "11" * 32,
                expected_statement=None
            )
        self.assertEqual(gateway.calls, [])

    def test_two_chunk_proof_has_consistent_length_hash_and_offsets(self):
        payload = bytes(range(256)) * 256 + b"z"
        digest = hashlib.sha256(payload).hexdigest()
        server = SyntheticChunkGateway(self.chunks_for(payload))
        report = self.retrieve(server, "fixture-job", digest, len(payload))
        self.assertEqual(report["proof_bytes"], len(payload))
        self.assertEqual(report["chunks"], 2)
        self.assertEqual(report["proof_sha256"], digest)
        self.assertTrue(report["digest_matches_job"])
        self.assertEqual(
            server.calls,
            [["fixture-job", 0, PROOF_CHUNK_BYTES],
             ["fixture-job", PROOF_CHUNK_BYTES, PROOF_CHUNK_BYTES]],
        )

    def test_declared_size_outside_verifier_limit_is_rejected_at_first_chunk(self):
        payload = b"example"
        digest = hashlib.sha256(payload).hexdigest()
        for total in (0, -1, True, "7", MAX_VERIFIED_PROOF_BYTES + 1):
            with self.subTest(total=total):
                response = self.chunks_for(payload)[0]
                response["total_bytes"] = total
                gateway = SyntheticChunkGateway([response])
                with self.assertRaisesRegex(RuntimeError, "16 MiB"):
                    self.retrieve(gateway, "fixture-job", digest)
                self.assertEqual(len(gateway.calls), 1)

    def test_status_record_size_must_match_transferred_size(self):
        payload = b"synthetic proof"
        digest = hashlib.sha256(payload).hexdigest()
        for expected_bytes in (0, -1, True, MAX_VERIFIED_PROOF_BYTES + 1):
            with self.subTest(expected_bytes=expected_bytes):
                with self.assertRaises(ValueError):
                    self.retrieve(SyntheticChunkGateway([]),
                                   "fixture-job", digest, expected_bytes)
        gateway = SyntheticChunkGateway(self.chunks_for(payload))
        with self.assertRaisesRegex(RuntimeError, "differs from job record"):
            self.retrieve(gateway, "fixture-job", digest, len(payload) + 1)
        self.assertEqual(len(gateway.calls), 1)

    def test_conflicting_chunk_claims_fail_closed(self):
        payload = b"synthetic proof"
        digest = hashlib.sha256(payload).hexdigest()
        tamper = [
            ("job_id", "other", "different proof job"),
            ("result_sha256", "ee" * 32, "differs from job record"),
            ("proof_verified", False, "verified statement"),
            ("offset", 1, "offset"),
            ("offset", True, "offset"),
            ("next_offset", 0, "offset"),
            ("next_offset", True, "offset"),
            ("complete", False, "completion marker"),
            ("complete", 1, "completion marker"),
            ("data_hex", "a", "malformed"),
            ("data_hex", "gg", "malformed"),
            ("data_hex", "", "malformed"),
            ("data_hex", "a" * (PROOF_CHUNK_BYTES * 2 + 2), "malformed"),
        ]
        for key, value, message in tamper:
            with self.subTest(field=key, value=str(value)[:40]):
                response = self.chunks_for(payload)[0]
                response[key] = value
                gateway = SyntheticChunkGateway([response])
                with self.assertRaisesRegex(RuntimeError, message):
                    self.retrieve(gateway, "fixture-job", digest)
                self.assertEqual(len(gateway.calls), 1)

    def test_multi_chunk_total_change_or_short_chunk_is_rejected(self):
        payload = b"x" * PROOF_CHUNK_BYTES + b"yz"
        digest = hashlib.sha256(payload).hexdigest()
        baseline = self.chunks_for(payload)
        for change, reason in (
            ({"total_bytes": len(payload) + 1}, "changed between chunks"),
            ({"data_hex": "00"}, "size or offset"),
            ({"complete": False}, "completion marker"),
        ):
            with self.subTest(change=change):
                response = [dict(x) for x in baseline]
                response[1].update(change)
                gateway = SyntheticChunkGateway(response)
                with self.assertRaisesRegex(RuntimeError, reason):
                    self.retrieve(gateway, "fixture-job", digest)
                self.assertEqual(len(gateway.calls), 2)

    def test_hash_mismatch_rejects_well_framed_but_changed_bytes(self):
        payload = b"synthetic proof"
        original = self.chunks_for(payload)[0]
        original["data_hex"] = b"synthetic pr00f".hex()
        server = SyntheticChunkGateway([original])
        with self.assertRaisesRegex(RuntimeError, "reassembled proof SHA-256 mismatch"):
            self.retrieve(server, "fixture-job", hashlib.sha256(payload).hexdigest())

    def test_retrieval_deadline_stops_before_extra_rpc(self):
        payload = b"a"
        gateway = SyntheticChunkGateway(self.chunks_for(payload))
        with patch("tools.benchmark_supernode.time.monotonic",
                   side_effect=[0, MAX_PROOF_DOWNLOAD_SECONDS + 1]):
            with self.assertRaisesRegex(RuntimeError, "deadline"):
                self.retrieve(gateway, "fixture-job", hashlib.sha256(payload).hexdigest())
        self.assertEqual(gateway.calls, [])


class CgroupReportingTest(unittest.TestCase):
    @staticmethod
    def fixture(path, current=100, peak=200, swap=0,
                io_stat="8:0 rbytes=30 wbytes=40 rios=1 wios=1\n"):
        path.mkdir(parents=True, exist_ok=True)
        for filename, value in (
            ("memory.current", current), ("memory.peak", peak),
            ("memory.swap.peak", swap), ("io.stat", io_stat),
        ):
            if value is not None:
                (path / filename).write_text(str(value), encoding="ascii")
        return path

    @staticmethod
    def job(cgroups, on_submit=None):
        # The fake RPC returns completed_unverified; no node, proof or tokens.
        control = MutatingControl(on_submit) if on_submit else FakeControl()
        return run_job(FakeRead(), control, "fixture-artifact",
                       "aa" * 32, "bb" * 32, 1, 1, cgroups)

    def assert_rejected_before_submit(self, cgroups, role):
        # The mock ensures a stale selected scope cannot admit expensive
        # proving, even when the chosen path still contains valid counters.
        control = Mock()
        with self.assertRaisesRegex(
                RuntimeError, role + " cgroup changed or became unavailable"):
            run_job(FakeRead(), control, "fixture-artifact",
                    "aa" * 32, "bb" * 32, 1, 1, cgroups)
        control.call.assert_not_called()

    def test_status_rpc_error_keeps_cgroup_evidence_without_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(
                Path(tmp) / "worker", io_stat="8:0 rbytes=5 wbytes=9\n")

            def status_fails(method, params):
                self.assertEqual(method, "zk.proof.status")
                (root / "io.stat").write_text(
                    "8:0 rbytes=13 wbytes=10\n", encoding="ascii")
                raise RuntimeError("SECRET_TOKEN_IN_REMOTE_EXCEPTION")

            read = Mock()
            read.call.side_effect = status_fails
            report = run_job(
                read, FakeControl(), "synthetic-artifact",
                "aa" * 32, "bb" * 32, 1, 1,
                select_cgroups(root, None, None),
            )
            self.assertFalse(report["observation_complete"])
            self.assertFalse(report["proof_verified"])
            self.assertIsNone(report["status"])
            self.assertEqual(report["job_id"], "fixture-job")
            self.assertEqual(report["cgroup_io_delta"]["io_read_delta_bytes"], 8)
            self.assertEqual(report["cgroup_io_delta"]["io_write_delta_bytes"], 1)
            self.assertIn("status RPC unavailable: RuntimeError", report["monitor_error"])
            self.assertNotIn("SECRET_TOKEN", str(report))
            self.assertNotIn("receipt", report)

    def test_monitor_timeout_retains_last_known_running_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            producer = self.fixture(
                Path(tmp) / "producer", io_stat="8:0 rbytes=9 wbytes=2\n")
            verifier = self.fixture(
                Path(tmp) / "verifier", io_stat="8:0 rbytes=1 wbytes=1\n")
            read = Mock()
            read.call.return_value = {"job": {"status": "running",
                                               "error": None,
                                               "result_sha256": None}}
            # An already-expired deadline exercises timeout without sleeping.
            report = run_job(
                read, FakeControl(), "synthetic-artifact",
                "aa" * 32, "bb" * 32, 1, -1,
                select_cgroups(None, producer, verifier),
            )
            self.assertEqual(report["status"], "running")
            self.assertEqual(report["monitor_error"],
                             "benchmark monitoring deadline exceeded")
            self.assertFalse(report["observation_complete"])
            self.assertFalse(report["proof_verified"])
            self.assertIn("running", report["observed_status_transitions_seconds"])
            self.assertEqual(report["cgroups_io_delta"]["producer"]["io_read_delta_bytes"], 0)
            self.assertEqual(report["cgroups_io_delta"]["verifier"]["io_write_delta_bytes"], 0)

    def test_unknown_or_invalid_job_status_keeps_unverified_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            cgroups = select_cgroups(self.fixture(Path(tmp) / "worker"), None, None)
            for invalid, expected in (
                ("unknown_future_state", "unrecognized proof job state"),
                (["verified_raito"], "invalid job status field"),
            ):
                with self.subTest(value=invalid):
                    read = Mock()
                    read.call.return_value = {
                        "job": {"status": invalid, "result_sha256": None}
                    }
                    result = run_job(read, FakeControl(), "synthetic-artifact",
                                     "aa" * 32, "bb" * 32, 1, 1, cgroups)
                    self.assertEqual(result["monitor_error"], expected)
                    self.assertFalse(result["observation_complete"])
                    self.assertFalse(result["proof_verified"])
                    self.assertIn("cgroup_before", result)

    def test_forged_verified_receipt_preserves_observation_as_unverified(self):
        with tempfile.TemporaryDirectory() as tmp:
            cgroups = select_cgroups(self.fixture(Path(tmp) / "worker"), None, None)
            read = Mock()

            def response(method, params):
                if method == "zk.proof.status":
                    return {"job": {"status": "verified_raito",
                                    "result_sha256": "11" * 32, "error": None}}
                if method == "zk.proof.receipt":
                    return synthetic_receipt("11" * 32, txid="dd" * 32)
                self.fail("proof retrieval started after mismatched receipt")

            read.call.side_effect = response
            result = run_job(read, FakeControl(), "synthetic-artifact",
                             "aa" * 32, "bb" * 32, 1, 1, cgroups,
                             block_hash="cc" * 32, block_height=42)
            self.assertEqual(result["status"], "verified_raito")
            self.assertTrue(result["observation_complete"])
            self.assertFalse(result["proof_verified"])
            self.assertIn("ValueError", result["verification_error"])
            self.assertIn("cgroup_after", result)
            self.assertNotIn("receipt", result)

    def test_bad_proof_chunk_cannot_promote_gateway_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            cgroups = select_cgroups(self.fixture(Path(tmp) / "worker"), None, None)
            read = Mock()

            def response(method, params):
                if method == "zk.proof.status":
                    return {"job": {"status": "verified_raito",
                                    "result_sha256": "11" * 32, "error": None}}
                if method == "zk.proof.receipt":
                    return synthetic_receipt("11" * 32)
                if method == "zk.proof.get":
                    return {"proof_verified": False, "data_hex": "abcd"}
                self.fail("unexpected synthetic RPC method")

            read.call.side_effect = response
            result = run_job(read, FakeControl(), "synthetic-artifact",
                             "aa" * 32, "bb" * 32, 1, 1, cgroups,
                             block_hash="cc" * 32, block_height=42)
            self.assertEqual(result["status"], "verified_raito")
            self.assertFalse(result["proof_verified"])
            self.assertIn("RuntimeError", result["verification_error"])
            self.assertIn("cgroup_io_delta", result)
            self.assertNotIn("receipt", result)

    def test_synthetic_receipt_and_reassembled_digest_finish_successfully(self):
        with tempfile.TemporaryDirectory() as tmp:
            cgroups = select_cgroups(self.fixture(Path(tmp) / "worker"), None, None)
            payload = b"synthetic bytes, NOT a STARK proof"
            digest = hashlib.sha256(payload).hexdigest()
            read = Mock()

            def response(method, params):
                if method == "zk.proof.status":
                    return {"job": {"status": "verified_raito",
                                    "result_sha256": digest,
                                    "result_bytes": len(payload), "error": None}}
                if method == "zk.proof.receipt":
                    return synthetic_receipt(digest)
                if method == "zk.proof.get":
                    return {
                        "job_id": "fixture-job",
                        "result_sha256": digest,
                        "proof_verified": True,
                        "verified_statement": synthetic_receipt(digest)["verified_statement"],
                        "data_hex": payload.hex(),
                        "offset": 0, "next_offset": len(payload),
                        "complete": True, "total_bytes": len(payload),
                    }
                self.fail("unexpected synthetic RPC method")

            read.call.side_effect = response
            result = run_job(read, FakeControl(), "synthetic-artifact",
                             "aa" * 32, "bb" * 32, 1, 1, cgroups,
                             block_hash="cc" * 32, block_height=42)
            self.assertTrue(result["observation_complete"])
            self.assertIsNone(result["verification_error"])
            self.assertTrue(result["proof_verified"])
            self.assertTrue(result["digest_matches_job"])
            self.assertEqual(result["proof_sha256"], digest)

    def test_chunk_statement_mismatch_cannot_promote_verified_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            selected = select_cgroups(self.fixture(Path(tmp) / "worker"), None, None)
            payload = b"synthetic bytes, NOT a STARK proof"
            digest = hashlib.sha256(payload).hexdigest()
            read = Mock()

            def response(method, params):
                if method == "zk.proof.status":
                    return {"job": {"status": "verified_raito",
                                    "result_sha256": digest,
                                    "result_bytes": len(payload), "error": None}}
                if method == "zk.proof.receipt":
                    return synthetic_receipt(digest)
                if method == "zk.proof.get":
                    altered = synthetic_receipt(digest)["verified_statement"]
                    altered = dict(altered, proven_tip_height=43, txid="dd" * 32)
                    return {
                        "job_id": "fixture-job",
                        "result_sha256": digest,
                        "proof_verified": True,
                        "verified_statement": altered,
                        "data_hex": payload.hex(),
                        "offset": 0, "next_offset": len(payload),
                        "complete": True, "total_bytes": len(payload),
                    }
                self.fail("unexpected synthetic RPC method")

            read.call.side_effect = response
            result = run_job(read, FakeControl(), "fixture-artifact",
                             "aa" * 32, "bb" * 32, 1, 1, selected,
                             block_hash="cc" * 32, block_height=42)
            self.assertEqual(result["status"], "verified_raito")
            self.assertTrue(result["observation_complete"])
            self.assertFalse(result["proof_verified"])
            self.assertIn("RuntimeError", result["verification_error"])
            self.assertIn("cgroup_io_delta", result)
            self.assertNotIn("receipt", result)

    def test_missing_optional_counter_does_not_block_a_valid_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp) / "worker", io_stat=None)
            job = self.job(select_cgroups(root, None, None))
            self.assertEqual(job["status"], "completed_unverified")
            self.assertIsNone(job["cgroup_before"]["io_read_bytes"])
            self.assertIn("unavailable",
                          job["cgroup_before"]["errors"]["io_read_bytes"])
            self.assertIsNone(job["cgroup_io_delta"]["io_write_delta_bytes"])

    def test_separate_roles_and_two_device_totals(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            producer = self.fixture(
                base / "producer", current=111, peak=222, swap=0,
                io_stat="8:0 rbytes=5 wbytes=7\n8:16 rbytes=11 wbytes=13\n")
            verifier = self.fixture(
                base / "verifier", current=333, peak=444, swap=1,
                io_stat="8:0 rbytes=23 wbytes=29\n")
            roles = select_cgroups(None, producer, verifier)
            job = self.job(roles)
            self.assertNotIn("cgroup_before", job)
            self.assertNotIn("cgroup_after", job)
            before = job["cgroups_before"]
            self.assertEqual(set(before), {"producer", "verifier"})
            self.assertEqual(before["producer"]["memory_current_bytes"], 111)
            self.assertEqual(before["verifier"]["memory_current_bytes"], 333)
            self.assertEqual(before["producer"]["io_read_bytes"], 16)
            self.assertEqual(before["producer"]["io_write_bytes"], 20)
            self.assertEqual(before["verifier"]["io_read_bytes"], 23)
            self.assertEqual(before["verifier"]["io_write_bytes"], 29)
            self.assertEqual(before["producer"]["swap_peak_bytes"], 0)
            self.assertEqual(before["producer"]["errors"], {})
            self.assertEqual(job["cgroups_after"]["verifier"]["memory_peak_bytes"], 444)

    def test_interval_io_deltas_keep_producer_and_verifier_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            producer = self.fixture(base / "producer", io_stat=(
                "8:0 rbytes=3 wbytes=5\n8:16 rbytes=7 wbytes=11\n"))
            verifier = self.fixture(base / "verifier", io_stat=(
                "8:0 rbytes=20 wbytes=22\n"))

            def advance():
                (producer / "io.stat").write_text(
                    "8:0 rbytes=10 wbytes=9\n8:16 rbytes=13 wbytes=11\n",
                    encoding="ascii")
                (verifier / "io.stat").write_text(
                    "8:0 rbytes=20 wbytes=42\n", encoding="ascii")

            job = self.job(select_cgroups(None, producer, verifier), advance)
            prod = job["cgroups_io_delta"]["producer"]
            ver = job["cgroups_io_delta"]["verifier"]
            self.assertEqual(prod["io_read_delta_bytes"], 13)
            self.assertEqual(prod["io_write_delta_bytes"], 4)
            self.assertEqual(ver["io_read_delta_bytes"], 0)
            self.assertEqual(ver["io_write_delta_bytes"], 20)
            self.assertEqual(prod["errors"], {})
            self.assertEqual(ver["errors"], {})
            self.assertEqual(job["cgroups_before"]["producer"]["io_read_bytes"], 10)
            self.assertEqual(job["cgroups_after"]["producer"]["io_read_bytes"], 23)

    def test_io_delta_rejects_per_device_reset_despite_increasing_total(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp), io_stat=(
                "8:0 rbytes=100 wbytes=10\n8:16 rbytes=1 wbytes=0\n"))
            before = snapshot_cgroup(root)
            (root / "io.stat").write_text(
                "8:0 rbytes=90 wbytes=16\n8:16 rbytes=500 wbytes=8\n",
                encoding="ascii")
            delta = cgroup_io_delta(before, snapshot_cgroup(root))
            self.assertIsNone(delta["io_read_delta_bytes"])
            self.assertIn("decreased on 8:0", delta["errors"]["io_read_delta_bytes"])
            self.assertEqual(delta["io_write_delta_bytes"], 14)

    def test_role_scope_replaced_before_first_sample_is_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            producer = self.fixture(base / "producer", current=11,
                                    io_stat="8:0 rbytes=5 wbytes=7\n")
            verifier = self.fixture(base / "verifier", current=31,
                                    io_stat="8:0 rbytes=9 wbytes=13\n")
            selected = select_cgroups(None, producer, verifier)
            original = selected.expected_identities["producer"]
            producer.rename(base / "retired-producer")
            self.fixture(producer, current=99,
                         io_stat="8:0 rbytes=500 wbytes=700\n")
            self.assertNotEqual(original, {
                "device": producer.stat().st_dev, "inode": producer.stat().st_ino})
            self.assert_rejected_before_submit(selected, "producer")
            replaced = snapshot_cgroup(producer,
                                       selected.expected_identities["producer"])
            self.assertIsNone(replaced["cgroup_fs_identity"])
            self.assertIsNone(replaced["memory_current_bytes"])
            self.assertIsNone(replaced["io_read_bytes"])
            self.assertIn("changed since selection",
                          replaced["errors"]["memory_current_bytes"])
            valid = snapshot_cgroup(verifier,
                                    selected.expected_identities["verifier"])
            self.assertEqual(valid["memory_current_bytes"], 31)

    def test_roles_swapped_after_selection_are_both_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            producer = self.fixture(base / "producer", current=10)
            verifier = self.fixture(base / "verifier", current=20)
            selected = select_cgroups(None, producer, verifier)
            producer.rename(base / "spare")
            verifier.rename(producer)
            (base / "spare").rename(verifier)
            self.assert_rejected_before_submit(selected, "producer")
            for role in ("producer", "verifier"):
                sample = snapshot_cgroup(selected[role],
                                         selected.expected_identities[role])
                self.assertIsNone(sample["memory_current_bytes"])
                self.assertIn("changed since selection",
                              sample["errors"]["memory_current_bytes"])

    def test_legacy_scope_replaced_after_selection_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            worker = self.fixture(base / "worker", current=5)
            selected = select_cgroups(worker, None, None)
            worker.rename(base / "old-worker")
            self.fixture(worker, current=700)
            self.assert_rejected_before_submit(selected, "worker")
            snap = snapshot_cgroup(worker, selected.expected_identities["worker"])
            self.assertIsNone(snap["memory_current_bytes"])
            self.assertIn("changed since selection",
                          snap["errors"]["memory_peak_bytes"])

    def test_recreated_producer_cgroup_invalidates_only_its_interval(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            producer = self.fixture(base / "producer", io_stat="8:0 rbytes=5 wbytes=7\n")
            verifier = self.fixture(base / "verifier", io_stat="8:0 rbytes=10 wbytes=20\n")

            def rotate_producer():
                producer.rename(base / "old-producer")
                self.fixture(producer, io_stat="8:0 rbytes=15 wbytes=17\n")
                (verifier / "io.stat").write_text(
                    "8:0 rbytes=13 wbytes=29\n", encoding="ascii")

            job = self.job(select_cgroups(None, producer, verifier), rotate_producer)
            before = job["cgroups_before"]
            after = job["cgroups_after"]
            self.assertNotEqual(before["producer"]["cgroup_fs_identity"],
                                after["producer"]["cgroup_fs_identity"])
            self.assertEqual(before["producer"]["io_devices"]["8:0"]["rbytes"], 5)
            self.assertIsNone(after["producer"]["io_devices"])
            self.assertIn("changed since selection",
                          after["producer"]["errors"]["io_read_bytes"])
            producer_delta = job["cgroups_io_delta"]["producer"]
            self.assertIsNone(producer_delta["io_read_delta_bytes"])
            self.assertIsNone(producer_delta["io_write_delta_bytes"])
            self.assertIn("filesystem identity unavailable",
                          producer_delta["errors"]["io_read_delta_bytes"])
            verifier_delta = job["cgroups_io_delta"]["verifier"]
            self.assertEqual(verifier_delta["io_read_delta_bytes"], 3)
            self.assertEqual(verifier_delta["io_write_delta_bytes"], 9)

    def test_pinned_fd_prevents_mixed_counters_during_transient_path_swap(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self.fixture(
                base / "producer", current=111, peak=222, swap=3,
                io_stat="8:0 rbytes=5 wbytes=7\n")
            original_reader = read_cgroup_counter_file
            moved = base / "renamed-original"
            replaced = base / "temporary-replacement"
            swapped = False

            def transient_swap(path, filename, cap, *, dir_fd=None):
                nonlocal swapped
                if filename == "memory.peak" and not swapped:
                    swapped = True
                    root.rename(moved)
                    self.fixture(root, current=900, peak=999, swap=999,
                                 io_stat="8:0 rbytes=900 wbytes=900\n")
                    try:
                        return original_reader(
                            path, filename, cap, dir_fd=dir_fd)
                    finally:
                        root.rename(replaced)
                        moved.rename(root)
                return original_reader(path, filename, cap, dir_fd=dir_fd)

            with patch("tools.benchmark_supernode.read_cgroup_counter_file",
                       side_effect=transient_swap):
                snap = snapshot_cgroup(root)
            self.assertTrue(swapped)
            self.assertEqual(snap["memory_current_bytes"], 111)
            self.assertEqual(snap["memory_peak_bytes"], 222)
            self.assertEqual(snap["swap_peak_bytes"], 3)
            self.assertEqual(snap["io_read_bytes"], 5)
            self.assertEqual(snap["io_write_bytes"], 7)
            self.assertEqual(snap["errors"], {})

    def test_missing_directory_yields_explicit_unavailable_counters(self):
        with tempfile.TemporaryDirectory() as tmp:
            snap = snapshot_cgroup(Path(tmp) / "missing")
            self.assertIsNone(snap["cgroup_fs_identity"])
            self.assertIsNone(snap["io_devices"])
            for key in ("memory_current_bytes", "memory_peak_bytes",
                        "swap_peak_bytes", "io_read_bytes", "io_write_bytes"):
                self.assertIsNone(snap[key])
                self.assertIn("directory unavailable", snap["errors"][key])

    def test_snapshot_rejects_symlink_directory_even_when_target_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            actual = self.fixture(base / "actual")
            alias = base / "symlink"
            alias.symlink_to(actual, target_is_directory=True)
            snap = snapshot_cgroup(alias)
            self.assertIsNone(snap["cgroup_fs_identity"])
            self.assertIsNone(snap["memory_current_bytes"])
            self.assertIn("directory unavailable",
                          snap["errors"]["memory_current_bytes"])

    def test_torn_snapshot_refuses_values_when_directory_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp), io_stat="8:0 rbytes=5 wbytes=9\n")
            first = {"device": 1, "inode": 10}
            second = {"device": 1, "inode": 11}
            with patch("tools.benchmark_supernode.cgroup_fs_identity",
                       side_effect=[first, second]):
                snap = snapshot_cgroup(root)
            self.assertIsNone(snap["cgroup_fs_identity"])
            self.assertIsNone(snap["io_devices"])
            for key in ("memory_current_bytes", "memory_peak_bytes",
                        "swap_peak_bytes", "io_read_bytes", "io_write_bytes"):
                self.assertIsNone(snap[key])
                self.assertIn("changed during snapshot", snap["errors"][key])

    def test_legacy_scope_recreation_invalidates_delta(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            worker = self.fixture(base / "worker", io_stat="8:0 rbytes=9 wbytes=6\n")

            def restart_scope():
                worker.rename(base / "retired-worker")
                self.fixture(worker, io_stat="8:0 rbytes=11 wbytes=10\n")

            job = self.job(select_cgroups(worker, None, None), restart_scope)
            self.assertIn("cgroup_before", job)
            self.assertIn("cgroup_after", job)
            self.assertIsNone(job["cgroup_io_delta"]["io_read_delta_bytes"])
            self.assertIn("filesystem identity unavailable",
                          job["cgroup_io_delta"]["errors"]["io_write_delta_bytes"])

    def test_io_delta_refuses_device_set_churn(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp), io_stat="8:0 rbytes=5 wbytes=6\n")
            before = snapshot_cgroup(root)
            (root / "io.stat").write_text(
                "8:0 rbytes=7 wbytes=8\n8:16 rbytes=11 wbytes=12\n",
                encoding="ascii")
            delta = cgroup_io_delta(before, snapshot_cgroup(root))
            self.assertIsNone(delta["io_read_delta_bytes"])
            self.assertIsNone(delta["io_write_delta_bytes"])
            self.assertIn("device set changed", delta["errors"]["io_read_delta_bytes"])

    def test_io_delta_keeps_unavailable_or_malformed_directions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp), io_stat=None)
            unavailable = snapshot_cgroup(root)
            (root / "io.stat").write_text(
                "8:0 rbytes=10 wbytes=4\n", encoding="ascii")
            delta = cgroup_io_delta(unavailable, snapshot_cgroup(root))
            self.assertIsNone(delta["io_read_delta_bytes"])
            self.assertIsNone(delta["io_write_delta_bytes"])
            self.assertIn("unavailable", delta["errors"]["io_read_delta_bytes"])
            (root / "io.stat").write_text(
                "8:0 rbytes=invalid wbytes=4\n", encoding="ascii")
            bad_before = snapshot_cgroup(root)
            (root / "io.stat").write_text(
                "8:0 rbytes=15 wbytes=14\n", encoding="ascii")
            delta = cgroup_io_delta(bad_before, snapshot_cgroup(root))
            self.assertIsNone(delta["io_read_delta_bytes"])
            self.assertIn("before sample", delta["errors"]["io_read_delta_bytes"])
            self.assertEqual(delta["io_write_delta_bytes"], 10)

    def test_legacy_io_delta_retains_existing_snapshots(self):
        with tempfile.TemporaryDirectory() as tmp:
            worker = self.fixture(Path(tmp) / "worker", io_stat=(
                "8:0 rbytes=5 wbytes=7\n"))

            def advance():
                (worker / "io.stat").write_text(
                    "8:0 rbytes=8 wbytes=7\n", encoding="ascii")

            job = self.job(select_cgroups(worker, None, None), advance)
            self.assertIn("cgroup_before", job)
            self.assertIn("cgroup_after", job)
            self.assertEqual(job["cgroup_io_delta"]["io_read_delta_bytes"], 3)
            self.assertEqual(job["cgroup_io_delta"]["io_write_delta_bytes"], 0)
            self.assertNotIn("cgroups_io_delta", job)
            no_scope = self.job(select_cgroups(None, None, None))
            self.assertNotIn("cgroup_io_delta", no_scope)

    def test_swapped_fixture_paths_remain_operator_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            producer = self.fixture(base / "producer", current=12)
            verifier = self.fixture(base / "verifier", current=89)
            swapped = select_cgroups(None, verifier, producer)
            before = self.job(swapped)["cgroups_before"]
            self.assertEqual(before["producer"]["memory_current_bytes"], 89)
            self.assertEqual(before["verifier"]["memory_current_bytes"], 12)
            # The counter values carry no evidence of service identity.

    def test_oversized_files_are_bounded_and_keep_valid_counters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp), current=0, peak=200, swap=0)
            (root / "memory.current").write_bytes(
                b"9" * (MAX_CGROUP_METRIC_BYTES + 1))
            (root / "io.stat").write_bytes(
                b"8:0 rbytes=0 wbytes=0\n" + b" " * MAX_CGROUP_IO_STAT_BYTES)
            snap = snapshot_cgroup(root)
            self.assertIsNone(snap["memory_current_bytes"])
            self.assertIn("exceeds", snap["errors"]["memory_current_bytes"])
            self.assertIsNone(snap["io_devices"])
            for field in ("io_read_bytes", "io_write_bytes"):
                self.assertIsNone(snap[field])
                self.assertIn("exceeds", snap["errors"][field])
            self.assertEqual(snap["memory_peak_bytes"], 200)
            self.assertEqual(snap["swap_peak_bytes"], 0)

    def test_counter_limit_boundary_allows_exactly_cap_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "io.stat").write_bytes(b" " * MAX_CGROUP_IO_STAT_BYTES)
            value = read_cgroup_counter_file(
                root, "io.stat", MAX_CGROUP_IO_STAT_BYTES)
            self.assertEqual(len(value), MAX_CGROUP_IO_STAT_BYTES)

    def test_non_ascii_counters_are_malformed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp))
            (root / "memory.current").write_bytes(b"\xff")
            (root / "io.stat").write_bytes(b"\xff")
            snap = snapshot_cgroup(root)
            self.assertIsNone(snap["memory_current_bytes"])
            self.assertIn("not ASCII", snap["errors"]["memory_current_bytes"])
            self.assertIsNone(snap["io_devices"])
            self.assertIsNone(snap["io_read_bytes"])
            self.assertIn("not ASCII", snap["errors"]["io_read_bytes"])

    def test_symlinked_counter_files_cannot_be_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self.fixture(base / "cgroup")
            other = base / "unrelated-counter"
            other.write_text("123", encoding="ascii")
            for filename in ("memory.current", "io.stat"):
                (root / filename).unlink()
                (root / filename).symlink_to(other)
            snap = snapshot_cgroup(root)
            self.assertIsNone(snap["memory_current_bytes"])
            self.assertIn("unavailable", snap["errors"]["memory_current_bytes"])
            for key in ("io_read_bytes", "io_write_bytes"):
                self.assertIsNone(snap[key])
                self.assertIn("unavailable", snap["errors"][key])
            self.assertEqual(snap["memory_peak_bytes"], 200)

    def test_nonregular_fifo_counter_files_are_rejected(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("requires Unix FIFO fixture support")
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp))
            for filename in ("memory.peak", "io.stat"):
                (root / filename).unlink()
                os.mkfifo(root / filename)
            # O_NONBLOCK avoids waiting for a writer before fstat validation.
            snap = snapshot_cgroup(root)
            self.assertIsNone(snap["memory_peak_bytes"])
            self.assertIn("not a regular", snap["errors"]["memory_peak_bytes"])
            self.assertIsNone(snap["io_read_bytes"])
            self.assertIn("not a regular", snap["errors"]["io_read_bytes"])
            self.assertEqual(snap["memory_current_bytes"], 100)

    def test_missing_counters_are_unavailable_not_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snap = snapshot_cgroup(root)
            for key in ("memory_current_bytes", "memory_peak_bytes",
                        "swap_peak_bytes", "io_read_bytes", "io_write_bytes"):
                self.assertIsNone(snap[key])
                self.assertIn(key, snap["errors"])
            self.assertEqual(snapshot_cgroup(None), {})

    def test_malformed_memory_and_io_preserve_field_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(
                Path(tmp), current="max", peak="-1", swap="garbage",
                io_stat="8:0 rbytes=invalid wbytes=32\n")
            snap = snapshot_cgroup(root)
            for key in ("memory_current_bytes", "memory_peak_bytes",
                        "swap_peak_bytes", "io_read_bytes"):
                self.assertIsNone(snap[key])
                self.assertIn(key, snap["errors"])
            self.assertEqual(snap["io_write_bytes"], 32)
            self.assertNotIn("io_write_bytes", snap["errors"])

    def test_unsigned_counter_bounds_and_malformed_decimal_input(self):
        self.assertEqual(parse_cgroup_counter("0"), 0)
        self.assertEqual(parse_cgroup_counter(str((1 << 64) - 1)), (1 << 64) - 1)
        for value in (None, "", "-1", "+1", "1.0", "0xff",
                      str(1 << 64), "9" * 5000):
            with self.subTest(value=(value or "")[:32]):
                self.assertIsNone(parse_cgroup_counter(value))
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(
                Path(tmp), current="9" * 5000, peak=str(1 << 64),
                swap="0", io_stat="8:0 rbytes=" + "9" * 5000 + " wbytes=0\n")
            snap = snapshot_cgroup(root)
            for field in ("memory_current_bytes", "memory_peak_bytes",
                          "io_read_bytes"):
                self.assertIsNone(snap[field])
                self.assertIn(field, snap["errors"])
            self.assertEqual(snap["swap_peak_bytes"], 0)
            self.assertEqual(snap["io_write_bytes"], 0)

    def test_selected_cgroup_path_resists_symlink_retargeting(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            producer = self.fixture(base / "producer", current=17)
            verifier = self.fixture(base / "verifier", current=51)
            alias = base / "producer-alias"
            alias.symlink_to(producer, target_is_directory=True)
            selected = select_cgroups(None, alias, verifier)
            self.assertEqual(selected["producer"], producer.resolve())
            self.assertEqual(selected["verifier"], verifier.resolve())
            alias.unlink()
            alias.symlink_to(verifier, target_is_directory=True)
            job = self.job(selected)
            self.assertEqual(job["cgroups_before"]["producer"]["memory_current_bytes"], 17)
            self.assertEqual(job["cgroups_before"]["verifier"]["memory_current_bytes"], 51)

    def test_repeated_cgroup_flags_rejected_before_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            producer = self.fixture(base / "producer")
            verifier = self.fixture(base / "verifier")
            common = ["benchmark_supernode.py",
                      "--core-cookie", str(base / "nonexistent.cookie"),
                      "--height", "1", "--blockhash", "aa" * 32,
                      "--txid", "bb" * 32, "--policy-sha256", "cc" * 32]
            for role, other in (
                ("--worker-cgroup", []),
                ("--producer-cgroup", ["--verifier-cgroup", str(verifier)]),
                ("--verifier-cgroup", ["--producer-cgroup", str(producer)]),
            ):
                for second in (str(verifier), str(producer)):
                    argv = common + [role, str(producer), f"{role}={second}"] + other
                    with self.subTest(role=role, second=second):
                        stderr = io.StringIO()
                        with patch.object(sys, "argv", argv), contextlib.redirect_stderr(stderr):
                            with self.assertRaises(SystemExit) as exit_status:
                                main()
                        self.assertEqual(exit_status.exception.code, 2)
                        self.assertIn("supplied more than once", stderr.getvalue())

    def test_missing_device_field_and_repeated_devices_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(
                Path(tmp), io_stat="8:0 rbytes=5 wbytes=6\n8:16 rbytes=7\n")
            snap = snapshot_cgroup(root)
            self.assertEqual(snap["io_read_bytes"], 12)
            self.assertIsNone(snap["io_write_bytes"])
            self.assertIn("io_write_bytes", snap["errors"])
            (root / "io.stat").write_text(
                "8:0 rbytes=5 wbytes=6\n8:0 rbytes=7 wbytes=8\n", encoding="ascii")
            snap = snapshot_cgroup(root)
            self.assertIsNone(snap["io_read_bytes"])
            self.assertIsNone(snap["io_write_bytes"])
            self.assertIn("io_read_bytes", snap["errors"])

    def test_legacy_worker_and_unconfigured_report_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            worker = self.fixture(Path(tmp) / "worker", current=50)
            selected = select_cgroups(worker, None, None)
            self.assertEqual(selected, {"worker": worker})
            job = self.job(selected)
            self.assertEqual(job["cgroup_before"]["memory_current_bytes"], 50)
            self.assertEqual(job["cgroup_after"]["memory_current_bytes"], 50)
            self.assertNotIn("cgroups_before", job)
            self.assertNotIn("cgroups_after", job)
            empty = self.job(select_cgroups(None, None, None))
            self.assertEqual(empty["cgroup_before"], {})
            self.assertEqual(empty["cgroup_after"], {})

    def test_conflicts_missing_roles_and_overlapping_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            prod = self.fixture(base / "producer")
            ver = self.fixture(base / "verifier")
            child = self.fixture(prod / "child")
            for selection in (
                (prod, prod, ver), (prod, None, ver), (None, prod, None),
                (None, None, ver), (None, prod, prod),
                (None, prod, child), (None, prod, base),
                (None, prod, base / "nonexistent"),
                (None, Path("relative"), ver),
            ):
                with self.subTest(selection=selection), self.assertRaises(ValueError):
                    select_cgroups(*selection)
            alias = base / "alias"
            alias.symlink_to(prod, target_is_directory=True)
            with self.assertRaises(ValueError):
                select_cgroups(None, alias, prod)

    def test_cli_rejects_conflict_before_cookie_or_token_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            prod = self.fixture(base / "producer")
            ver = self.fixture(base / "verifier")
            args = ["benchmark_supernode.py",
                    "--core-cookie", str(base / "absent.cookie"),
                    "--height", "1", "--blockhash", "aa" * 32,
                    "--txid", "bb" * 32, "--policy-sha256", "cc" * 32,
                    "--worker-cgroup", str(prod),
                    "--producer-cgroup", str(prod),
                    "--verifier-cgroup", str(ver)]
            stderr = io.StringIO()
            with patch.object(sys, "argv", args), contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as ex:
                    main()
            self.assertEqual(ex.exception.code, 2)
            self.assertIn("cannot be combined", stderr.getvalue())

if __name__ == "__main__":
    unittest.main()
