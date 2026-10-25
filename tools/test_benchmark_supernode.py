"""Unit checks for bounded Supernode benchmark helpers."""
import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.benchmark_supernode import (
    cgroup_io_delta, main, loopback_url, percentiles, require_hash, run_job,
    select_cgroups, snapshot_cgroup, parse_cgroup_counter,
    read_cgroup_counter_file, MAX_CGROUP_IO_STAT_BYTES, MAX_CGROUP_METRIC_BYTES,
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
            self.assertEqual(after["producer"]["io_devices"]["8:0"]["rbytes"], 15)
            producer_delta = job["cgroups_io_delta"]["producer"]
            self.assertIsNone(producer_delta["io_read_delta_bytes"])
            self.assertIsNone(producer_delta["io_write_delta_bytes"])
            self.assertIn("filesystem identity changed",
                          producer_delta["errors"]["io_read_delta_bytes"])
            verifier_delta = job["cgroups_io_delta"]["verifier"]
            self.assertEqual(verifier_delta["io_read_delta_bytes"], 3)
            self.assertEqual(verifier_delta["io_write_delta_bytes"], 9)

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
            self.assertIn("filesystem identity changed",
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
