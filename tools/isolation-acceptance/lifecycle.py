"""Linux lifecycle evidence, with no shell command matching or signal delivery.

Only process identities observed in the tested service cgroups are tracked.
Each observation retains PID/start ticks, parentage, argv and actual cgroup;
the identity is checked again even if it leaves the original cgroup.
"""
import json
from pathlib import Path
import subprocess
import time

UNITS = ("supernode-gateway", "supernode-proof-worker-broker", "supernode-raito-verifier")


def command(*argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=45, check=True).stdout.strip()


def process(pid, proc=Path("/proc")):
    root = proc / str(pid)
    try:
        stat = (root / "stat").read_text()
        # comm can contain spaces and parentheses. Fields after its last ')'
        # start at field 3; starttime is field 22.
        fields = stat[stat.rindex(")") + 2:].split()
        result = {"pid": int(pid), "state": fields[0], "ppid": int(fields[1]),
                  "pgrp": int(fields[2]), "session": int(fields[3]),
                  "start_ticks": int(fields[19]),
                  "argv": (root / "cmdline").read_bytes().decode(errors="replace").rstrip("\0").split("\0"),
                  "cgroup": (root / "cgroup").read_text().splitlines()}
        # Refuse a mixed observation if the PID was recycled during the read.
        again = (root / "stat").read_text()
        if again[again.rindex(")") + 2:].split()[19] != fields[19]:
            raise RuntimeError(f"PID {pid} changed identity during observation")
        return result
    except FileNotFoundError:
        return None  # Exited while observed; permission/parse errors stay fatal.


def identity(p):
    return p["pid"], p["start_ticks"]


def same_process(old, current):
    return current is not None and identity(old) == identity(current)


def is_sleep(p, seconds):
    return len(p["argv"]) == 2 and Path(p["argv"][0]).name == "sleep" and p["argv"][1] == str(seconds)


def in_unit(p, unit):
    scope = f"0::/system.slice/{unit}.service"
    return any(line == scope or line.startswith(scope + "/") for line in p["cgroup"])


def crash_precondition(job, current, phase, err, status_err, event, worker_unit):
    return (not err and not status_err and job.get("status") == phase
            and current.get("status") == phase and any(
                is_sleep(p, 30) and in_unit(p, worker_unit)
                for p in event["services"][worker_unit]["processes"]))


def snapshot(unit):
    if unit not in UNITS:
        raise ValueError("unexpected service unit")
    values = command("systemctl", "show", unit, "--property=ActiveState,SubState,MainPID,ControlGroup,InvocationID,Result")
    properties = dict(line.split("=", 1) for line in values.splitlines())
    path = properties["ControlGroup"]
    expected = f"/system.slice/{unit}.service"
    if path and path != expected:
        raise RuntimeError(f"unexpected ControlGroup for {unit}: {path}")
    root = Path("/sys/fs/cgroup") / expected.lstrip("/")
    processes = []
    if root.exists():
        for member_file in [root / "cgroup.procs", *root.glob("**/cgroup.procs")]:
            try:
                pids = member_file.read_text().split()
            except FileNotFoundError:
                continue
            for pid in pids:
                p = process(int(pid))
                if p is not None and identity(p) not in {identity(x) for x in processes}:
                    processes.append(p)
    return {"properties": properties, "processes": processes}


def settled(samples):
    return all(s["properties"]["ActiveState"] == "active"
               and s["properties"]["SubState"] == "running"
               and int(s["properties"]["MainPID"]) > 0
               and {p["pid"] for p in s["processes"]} == {int(s["properties"]["MainPID"])}
               for s in samples.values())


class Observation:
    def __init__(self):
        self.tracked = {}
        self.events = []

    def capture(self, label):
        samples = {unit: snapshot(unit) for unit in UNITS}
        for unit, sample in samples.items():
            main = int(sample["properties"]["MainPID"])
            for p in sample["processes"]:
                if p["pid"] != main:
                    self.tracked[identity(p)] = dict(p, observed_unit=unit)
        remaining = []
        for old in self.tracked.values():
            current = process(old["pid"])
            if same_process(old, current):
                remaining.append(dict(current, observed_unit=old["observed_unit"]))
        event = {"label": label, "monotonic": time.monotonic(), "services": samples,
                 "tracked": list(self.tracked.values()), "remaining": remaining}
        self.events.append(event)
        return event

    def wait(self, label, predicate, timeout=20):
        deadline = time.monotonic() + timeout
        while True:
            event = self.capture(label)
            if predicate(event):
                return True, event
            if time.monotonic() >= deadline:
                return False, event
            time.sleep(.1)

    def clean(self, timeout=20):
        return self.wait("terminal-cleanup", lambda e: not e["remaining"] and settled(e["services"]), timeout)

    def save(self, path):
        Path(path).write_text(json.dumps(self.events, indent=2) + "\n")
