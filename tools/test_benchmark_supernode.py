"""Unit checks for bounded Supernode benchmark helpers."""
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.benchmark_supernode import (
    main, loopback_url, percentiles, require_hash, run_job,
    select_cgroups, snapshot_cgroup,
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


class FakeRead:
    def call(self, method, params):
        assert method == "zk.proof.status"
        return {"job": {
            "status": "completed_unverified",
            "error": "fixture only",
            "result_sha256": None,
        }}


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
    def job(cgroups):
        # The fake RPC returns completed_unverified; no node, proof or tokens.
        return run_job(FakeRead(), FakeControl(), "fixture-artifact",
                       "aa" * 32, "bb" * 32, 1, 1, cgroups)

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
