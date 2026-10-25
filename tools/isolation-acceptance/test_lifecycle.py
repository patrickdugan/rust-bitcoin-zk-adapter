"""Bounded offline fixtures. No services, signals, subprocesses or host /proc."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import lifecycle as lc


def proc(pid=42, start=123, argv=None, cgroup="0::/system.slice/test.service"):
    return dict(pid=pid, start_ticks=start, ppid=20, pgrp=40, session=40,
                state="S", argv=argv or ["sleep", "30"], cgroup=[cgroup])


def sample(children=(), main=10, active="active", sub="running"):
    return {"properties": {"MainPID": str(main), "ActiveState": active, "SubState": sub},
            "processes": [proc(main, argv=["broker"]), *children] if main else list(children)}


class LifecycleFixtures(unittest.TestCase):
    def test_shell_containing_sleep_is_not_a_worker(self):
        self.assertFalse(lc.is_sleep(proc(argv=["/bin/sh", "-c", "pgrep -f 'sleep 30'"]), 30))
        self.assertTrue(lc.is_sleep(proc(argv=["/usr/bin/sleep", "30"]), 30))
        self.assertFalse(lc.is_sleep(proc(argv=["sleep", "301"]), 30))

    def test_pid_reuse_is_not_a_survivor(self):
        self.assertFalse(lc.same_process(proc(), proc(start=124)))
        self.assertTrue(lc.same_process(proc(), proc()))
        self.assertFalse(lc.same_process(proc(), None))

    def test_detached_readiness_requires_live_session_leader(self):
        unit = "supernode-raito-verifier"
        p = proc(argv=["sleep", "902"], cgroup=f"0::/system.slice/{unit}.service")
        self.assertFalse(lc.detached_ready(p, 902, unit))
        p.update(session=p["pid"], pgrp=p["pid"])
        self.assertTrue(lc.detached_ready(p, 902, unit))
        self.assertFalse(lc.detached_ready(p, 901, unit))
        self.assertFalse(lc.detached_ready(p, 902, "supernode-proof-worker-broker"))
        for state in ("Z", "X"):
            self.assertFalse(lc.detached_ready(dict(p, state=state), 902, unit))

    def test_cleanup_requires_zombie_identity_to_disappear(self):
        obs = lc.Observation()
        child = proc()
        with patch.object(lc, "snapshot", return_value=sample([child])), patch.object(lc, "process", return_value=child):
            obs.capture("running")
        # Empty cgroup.procs alone must not erase an unreaped tracked PID.
        with patch.object(lc, "snapshot", return_value=sample()), patch.object(lc, "process", return_value=dict(child, state="Z")):
            self.assertFalse(obs.clean(timeout=0)[0])
        with patch.object(lc, "snapshot", return_value=sample()), patch.object(lc, "process", return_value=None):
            self.assertTrue(obs.clean(timeout=0)[0])

    def test_crash_requires_phase_and_real_worker_membership(self):
        unit = "supernode-proof-worker-broker"
        p = proc(cgroup=f"0::/system.slice/{unit}.service")
        event = {"services": {unit: sample([p])}}
        running = {"status": "running"}
        self.assertTrue(lc.crash_precondition(running, running, "running", None, None, event, unit))
        self.assertFalse(lc.crash_precondition({"status": "failed", "error": "broker at capacity"},
                                             running, "running", None, None, event, unit))
        self.assertFalse(lc.crash_precondition(running, {"status": "failed"}, "running", None, None, event, unit))
        self.assertFalse(lc.crash_precondition(running, running, "running", "RPC failed", None, event, unit))
        p["cgroup"] = [f"0::/system.slice/{unit}.service-other"]
        self.assertFalse(lc.crash_precondition(running, running, "running", None, None, event, unit))
        p["cgroup"] = [f"0::/system.slice/{unit}.service/nested"]
        self.assertTrue(lc.in_unit(p, unit))

    def test_parse_stat_with_spaces_and_parentheses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "42"
            root.mkdir()
            fields = ["S", "20", "40", "40"] + ["0"] * 15 + ["123"]
            (root / "stat").write_text("42 (name with ) parentheses) " + " ".join(fields))
            (root / "cmdline").write_bytes(b"/usr/bin/sleep\x0030\x00")
            (root / "cgroup").write_text("0::/system.slice/test.service\n")
            p = lc.process(42, Path(directory))
            self.assertEqual(lc.identity(p), (42, 123))
            self.assertEqual((p["ppid"], p["pgrp"], p["session"]), (20, 40, 40))
            self.assertEqual(p["argv"], ["/usr/bin/sleep", "30"])
            self.assertIsNone(lc.process(99, Path(directory)))

    def test_unreadable_proc_is_not_absence(self):
        with patch.object(Path, "read_text", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                lc.process(42, Path("fixture"))

    def test_only_running_service_with_exact_main_is_settled(self):
        self.assertTrue(lc.settled({"unit": sample()}))
        for bad in (sample([proc()]), sample(main=0), sample(active="inactive"), sample(sub="auto-restart")):
            self.assertFalse(lc.settled({"unit": bad}))

    def test_process_is_tracked_after_leaving_cgroup(self):
        obs = lc.Observation()
        child = proc()
        with patch.object(lc, "snapshot", return_value=sample([child])), patch.object(lc, "process", return_value=child):
            obs.capture("before")
        moved = proc(cgroup="0::/unexpected")
        with patch.object(lc, "snapshot", return_value=sample()), patch.object(lc, "process", return_value=moved):
            event = obs.capture("after")
        self.assertEqual(len(event["remaining"]), 1)
        self.assertEqual(event["remaining"][0]["cgroup"], ["0::/unexpected"])
        with patch.object(lc, "snapshot", return_value=sample()), patch.object(lc, "process", return_value=proc(start=999)):
            self.assertEqual(obs.capture("reused")["remaining"], [])

    def test_zombie_retained_as_terminal_evidence(self):
        obs = lc.Observation()
        zombie = dict(proc(), state="Z")
        with patch.object(lc, "snapshot", return_value=sample([zombie])), patch.object(lc, "process", return_value=zombie):
            clean, event = obs.clean(timeout=0)
        self.assertFalse(clean)
        self.assertEqual(event["remaining"][0]["state"], "Z")

    def test_timeout_fails_instead_of_treating_missing_data_as_zero(self):
        with patch.object(lc, "snapshot", side_effect=RuntimeError("systemctl failed")):
            with self.assertRaises(RuntimeError):
                lc.Observation().clean(timeout=0)

    def test_wait_observes_terminal_transition(self):
        obs = lc.Observation()
        with patch.object(obs, "capture", side_effect=[{"done": False}, {"done": True}]), patch.object(lc.time, "sleep"):
            ok, event = obs.wait("stop", lambda e: e["done"])
        self.assertTrue(ok)
        self.assertTrue(event["done"])


if __name__ == "__main__":
    unittest.main()
