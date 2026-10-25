#!/usr/bin/env python3
"""Measure Supernode RPC overhead and a real Raito fetch/verification job.

Requires a running local Bitcoin Core node, the approved Raito fetch worker,
and a configured heavy verifier. Makes NO claims of speed without measurements.
Stdlib-only. Keep bearer tokens and Bitcoin Core secrets in environment/cookie.
"""
import argparse
import base64
import hashlib
import ipaddress
import json
import math
import os
import re
import stat
from pathlib import Path
import statistics
import time
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler

RESPONSE_CAP = 1024 * 1024
DONE = {"verified_raito", "completed_unverified", "output_evicted", "failed", "interrupted"}
PENDING = {"queued", "running", "verifying_raito"}
MAX_CGROUP_COUNTER = (1 << 64) - 1
MAX_CGROUP_METRIC_BYTES = 128
MAX_CGROUP_IO_STAT_BYTES = 128 * 1024


class UniqueCgroupPath(argparse.Action):
    """Reject repeat flags; argparse otherwise silently keeps the last path."""

    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest) is not None:
            parser.error(f"{option_string} supplied more than once")
        setattr(namespace, self.dest, values)


def parse_cgroup_counter(value: str | None) -> int | None:
    """Accept only bounded unsigned kernel counters, not arbitrary decimals."""
    if value is None or re.fullmatch(r"[0-9]{1,20}", value) is None:
        return None
    number = int(value)
    return number if number <= MAX_CGROUP_COUNTER else None


def require_hash(value: str) -> str:
    if len(value) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in value):
        raise ValueError("expected 64 hexadecimal characters")
    return value.lower()


def loopback_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("benchmark endpoints must be loopback HTTP without URL credentials")
    host = parsed.hostname
    if host != "localhost":
        try:
            if not ipaddress.ip_address(host or "").is_loopback:
                raise ValueError("benchmark endpoint must be loopback")
        except ValueError as exc:
            raise ValueError("benchmark endpoint must be loopback") from exc
    return value


class RPC:
    def __init__(self, url: str, authorization: str):
        self.url = loopback_url(url)
        self.authorization = authorization
        self.opener = build_opener(ProxyHandler({}))

    def call(self, method: str, params: list):
        body = json.dumps({"jsonrpc": "1.0", "id": 1,
                           "method": method, "params": params}).encode()
        req = Request(self.url, data=body,
                      headers={"Content-Type": "application/json",
                               "Authorization": self.authorization},
                      method="POST")
        with self.opener.open(req, timeout=35) as resp:
            data = resp.read(RESPONSE_CAP + 1)
        if len(data) > RESPONSE_CAP:
            raise RuntimeError("RPC response exceeds benchmark safety cap")
        parsed = json.loads(data)
        if parsed.get("error") is not None:
            raise RuntimeError(f"{method}: {parsed['error']}")
        return parsed["result"]


def percentiles(samples: list[float]) -> dict:
    if not samples:
        return {}
    values = sorted(samples)

    def percentile(p: float) -> float:
        rank = (len(values) - 1) * p
        lower = math.floor(rank)
        higher = math.ceil(rank)
        return values[lower] + (values[higher] - values[lower]) * (rank - lower)

    return {"n": len(values), "p50_ms": round(percentile(.50), 3),
            "p95_ms": round(percentile(.95), 3),
            "p99_ms": round(percentile(.99), 3)}


class SelectedCgroups(dict):
    """Resolved paths plus the filesystem identities seen at selection time."""

    def __init__(self, paths: dict[str, Path],
                 expected_identities: dict[str, dict]):
        super().__init__(paths)
        self.expected_identities = expected_identities


def select_cgroups(worker: Path | None, producer: Path | None,
                   verifier: Path | None) -> dict[str, Path]:
    """Reject ambiguous labeling before reading credentials or sending RPCs."""
    if worker is not None and (producer is not None or verifier is not None):
        raise ValueError("--worker-cgroup cannot be combined with role-specific cgroups")
    if (producer is None) != (verifier is None):
        raise ValueError("--producer-cgroup and --verifier-cgroup must be supplied together")
    selected = ({"worker": worker} if worker is not None else
                {"producer": producer, "verifier": verifier}
                if producer is not None else {})
    canonical = {}
    for role, path in selected.items():
        if not path.is_absolute():
            raise ValueError(f"{role} cgroup path must be absolute")
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_dir():
                raise ValueError(f"{role} cgroup path must be a directory")
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"{role} cgroup path is unavailable: {type(exc).__name__}") from exc
        canonical[role] = resolved
    if "producer" in canonical:
        prod, ver = canonical["producer"], canonical["verifier"]
        if prod == ver or prod in ver.parents or ver in prod.parents:
            raise ValueError("producer and verifier cgroups must be distinct, non-overlapping paths")
    # Bind paths to the directory identities observed before RPC and token
    # access. A scope recreated later must not silently inherit the label.
    identities = {}
    for role, path in canonical.items():
        identity = cgroup_fs_identity(path)
        if identity is None:
            raise ValueError(f"{role} cgroup directory unavailable during selection")
        identities[role] = identity
    return SelectedCgroups(canonical, identities)


def cgroup_fs_identity(root: Path) -> dict | None:
    """Filesystem object ID for continuity checks, never a service UID."""
    try:
        metadata = root.stat()
    except OSError:
        return None
    if not stat.S_ISDIR(metadata.st_mode):
        return None
    return {"device": metadata.st_dev, "inode": metadata.st_ino}



def read_cgroup_counter_file(root: Path, filename: str, cap: int,
                             *, dir_fd: int | None = None) -> str:
    """Read bounded ASCII from a regular cgroup file without following links.

    O_NONBLOCK also prevents a swapped-in FIFO from stalling the benchmark.
    This is a Linux cgroup-v2 reader; kernel enforcement is checked elsewhere.
    """
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    # A directory descriptor pins all counters to the same filesystem
    # object if the path is renamed/replaced while a snapshot is running.
    target = filename if dir_fd is not None else root / filename
    fd = os.open(target, flags, dir_fd=dir_fd)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("not a regular counter file")
        payload = stream.read(cap + 1)
    if len(payload) > cap:
        raise ValueError(f"counter file exceeds {cap}-byte limit")
    try:
        return payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("counter file is not ASCII") from exc



def snapshot_cgroup(root: Path | None,
                    expected_identity: dict | None = None) -> dict:
    """Read one coherent cgroup scope through a pinned directory handle.

    Paths and role labels are operator supplied, never service attestations.
    """
    if root is None:
        return {}
    if not root.is_absolute():
        raise ValueError("cgroup path must be absolute")
    identity_before = cgroup_fs_identity(root)
    # O_DIRECTORY|O_NOFOLLOW rejects a replaced symlink at the final
    # component. dir_fd below prevents mixing two scopes during rename.
    try:
        directory_fd = os.open(
            root, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY)
    except OSError as exc:
        fields = ("memory_current_bytes", "memory_peak_bytes",
                  "swap_peak_bytes", "io_read_bytes", "io_write_bytes")
        cause = f"cgroup directory unavailable: {type(exc).__name__}"
        return {
            **{field: None for field in fields},
            "io_devices": None,
            "cgroup_fs_identity": None,
            "errors": {field: cause for field in fields},
        }
    try:
        return _snapshot_cgroup_pinned(
            root, directory_fd, identity_before, expected_identity)
    finally:
        os.close(directory_fd)


def _snapshot_cgroup_pinned(root: Path, directory_fd: int,
                            identity_before: dict | None,
                            expected_identity: dict | None = None) -> dict:
    """Sample only counter files belonging to the opened directory."""
    metadata = os.fstat(directory_fd)
    opened_identity = {"device": metadata.st_dev, "inode": metadata.st_ino}
    result = {key: None for key in (
        "memory_current_bytes", "memory_peak_bytes", "swap_peak_bytes",
        "io_read_bytes", "io_write_bytes")}
    # Preserve per-device identity to detect resets and device-set churn when
    # deriving I/O deltas. None indicates an unavailable io.stat sample.
    result["io_devices"] = None
    errors = {}
    for name, key in (("memory.current", "memory_current_bytes"),
                      ("memory.peak", "memory_peak_bytes"),
                      ("memory.swap.peak", "swap_peak_bytes")):
        try:
            raw = read_cgroup_counter_file(root, name, MAX_CGROUP_METRIC_BYTES,
                                           dir_fd=directory_fd).strip()
        except OSError as exc:
            errors[key] = f"{name} unavailable: {type(exc).__name__}"
            continue
        except ValueError as exc:
            errors[key] = f"{name} malformed: {exc}"
            continue
        parsed = parse_cgroup_counter(raw)
        if parsed is None:
            errors[key] = f"{name} malformed: expected unsigned 64-bit counter"
        else:
            result[key] = parsed

    try:
        raw_io = read_cgroup_counter_file(root, "io.stat", MAX_CGROUP_IO_STAT_BYTES,
                                          dir_fd=directory_fd)
    except (OSError, ValueError) as exc:
        cause = ("malformed" if isinstance(exc, ValueError) else "unavailable")
        for key in ("io_read_bytes", "io_write_bytes"):
            errors[key] = f"io.stat {cause}: {exc if cause == 'malformed' else type(exc).__name__}"
    else:
        rows = [line.split() for line in raw_io.splitlines() if line.strip()]
        if not rows:
            for key in ("io_read_bytes", "io_write_bytes"):
                errors[key] = "io.stat unavailable: no device rows"
        else:
            totals = {"rbytes": 0, "wbytes": 0}
            fields = {"rbytes": "io_read_bytes", "wbytes": "io_write_bytes"}
            devices = set()
            result["io_devices"] = {}
            for tokens in rows:
                device = tokens[0]
                if not re.fullmatch(r"[0-9]+:[0-9]+", device) or device in devices:
                    for key in fields.values():
                        errors[key] = "io.stat malformed: invalid or repeated device"
                    continue
                devices.add(device)
                values = {}
                malformed = False
                for token in tokens[1:]:
                    if "=" not in token:
                        malformed = True
                        break
                    key, value = token.split("=", 1)
                    if key in values:
                        malformed = True
                        break
                    values[key] = value
                result["io_devices"][device] = {}
                for field, metric in fields.items():
                    raw = values.get(field)
                    parsed = parse_cgroup_counter(raw)
                    if malformed or parsed is None:
                        errors[metric] = f"io.stat malformed: {field} missing or invalid on {device}"
                        result["io_devices"][device][field] = None
                    else:
                        totals[field] += parsed
                        result["io_devices"][device][field] = parsed
            for field, metric in fields.items():
                if metric not in errors:
                    if totals[field] > MAX_CGROUP_COUNTER:
                        errors[metric] = f"io.stat {field} total exceeds unsigned 64-bit range"
                    else:
                        result[metric] = totals[field]
    identity_after = cgroup_fs_identity(root)
    selection_changed = (expected_identity is not None
                         and expected_identity != opened_identity)
    if (identity_before is None or identity_before != opened_identity
            or identity_before != identity_after or selection_changed):
        # A once-valid path may have been replaced before the job started.
        # Refuse all counters rather than attaching them to the old role.
        result["cgroup_fs_identity"] = None
        result["io_devices"] = None
        cause = ("cgroup directory changed since selection"
                 if selection_changed else
                 "cgroup directory unavailable or changed during snapshot")
        for key in ("memory_current_bytes", "memory_peak_bytes",
                    "swap_peak_bytes", "io_read_bytes", "io_write_bytes"):
            result[key] = None
            errors[key] = cause
    else:
        result["cgroup_fs_identity"] = identity_before
    result["errors"] = errors
    return result



def cgroup_io_delta(before: dict, after: dict) -> dict:
    """Calculate trustworthy counter differences for unchanged device sets.

    Values describe the selected cgroup path only. Verify service identity
    independently, and treat recreated/reset counters as unavailable.
    """
    result = {
        "io_read_delta_bytes": None, "io_write_delta_bytes": None, "errors": {},
    }
    left, right = before.get("io_devices"), after.get("io_devices")
    measurements = (
        ("rbytes", "io_read_bytes", "io_read_delta_bytes"),
        ("wbytes", "io_write_bytes", "io_write_delta_bytes"),
    )
    first_id = before.get("cgroup_fs_identity")
    final_id = after.get("cgroup_fs_identity")
    if not isinstance(first_id, dict) or not isinstance(final_id, dict):
        for _, _, output in measurements:
            result["errors"][output] = "cgroup filesystem identity unavailable"
        return result
    if first_id != final_id:
        for _, _, output in measurements:
            result["errors"][output] = "cgroup filesystem identity changed between samples"
        return result
    if not isinstance(left, dict) or not isinstance(right, dict):
        for _, field, output in measurements:
            cause = (before.get("errors", {}).get(field) or
                     after.get("errors", {}).get(field))
            result["errors"][output] = cause or "io.stat unavailable in before or after sample"
        return result
    if left.keys() != right.keys():
        for _, _, output in measurements:
            result["errors"][output] = "io.stat device set changed between samples"
        return result
    for raw, field, output in measurements:
        cause = before.get("errors", {}).get(field)
        if cause:
            result["errors"][output] = f"before sample: {cause}"
            continue
        cause = after.get("errors", {}).get(field)
        if cause:
            result["errors"][output] = f"after sample: {cause}"
            continue
        amount = 0
        for device in sorted(left):
            previous = left[device].get(raw)
            current = right[device].get(raw)
            if not isinstance(previous, int) or not isinstance(current, int):
                result["errors"][output] = f"io.stat {raw} unavailable on {device}"
                break
            if current < previous:
                result["errors"][output] = f"io.stat {raw} decreased on {device}"
                break
            amount += current - previous
        if output not in result["errors"]:
            if amount > MAX_CGROUP_COUNTER:
                result["errors"][output] = "I/O interval total exceeds unsigned 64-bit range"
            else:
                result[output] = amount
    return result


def proof_retrieve(gateway: RPC, job_id: str, expected_sha: str) -> dict:
    digest = hashlib.sha256()
    total = 0
    chunks = 0
    before = time.monotonic()
    while True:
        resp = gateway.call("zk.proof.get", [job_id, total, 65536])
        if resp.get("proof_verified") is not True:
            raise RuntimeError("verified proof retrieval lost verified statement")
        data = bytes.fromhex(resp["data_hex"])
        if not data or resp["offset"] != total:
            raise RuntimeError("empty chunk or incorrect retrieval offset")
        digest.update(data)
        total += len(data)
        chunks += 1
        if resp.get("complete") is True:
            if total != resp["total_bytes"]:
                raise RuntimeError("proof result length mismatch")
            break
    actual = digest.hexdigest()
    if actual != expected_sha.lower():
        raise RuntimeError("reassembled proof SHA-256 mismatch")
    return {"proof_bytes": total, "chunks": chunks,
            "download_seconds": round(time.monotonic() - before, 3),
            "proof_sha256": actual, "digest_matches_job": True}


def measure_pair(core: RPC, gateway: RPC, height: int, samples: int) -> dict:
    direct, proxied = [], []
    expected = core.call("getblockhash", [height])
    for _ in range(samples):
        start = time.perf_counter()
        if core.call("getblockhash", [height]) != expected:
            raise RuntimeError("Bitcoin Core changed the requested block during baseline")
        direct.append((time.perf_counter() - start) * 1000)
        start = time.perf_counter()
        if gateway.call("getblockhash", [height]) != expected:
            raise RuntimeError("Supernode passthrough returned an unexpected block")
        proxied.append((time.perf_counter() - start) * 1000)
    return {"method": "getblockhash", "direct_core": percentiles(direct),
            "supernode_passthrough": percentiles(proxied)}


def run_job(gateway_read: RPC, gateway_control: RPC, artifact_id: str,
            policy: str, txid: str, memory_mib: int, deadline: float,
            cgroups: dict[str, Path]) -> dict:
    expected = getattr(cgroups, "expected_identities", {})
    before = {
        role: snapshot_cgroup(path, expected.get(role))
        for role, path in cgroups.items()
    }
    started = time.monotonic()
    response = gateway_control.call(
        "zk.proof.submit", ["raito", artifact_id, memory_mib, policy, txid])
    job_id = response["job"]["id"]
    seen = {}
    while True:
        record = gateway_read.call("zk.proof.status", [job_id])["job"]
        status = record["status"]
        seen.setdefault(status, round(time.monotonic() - started, 3))
        if status in DONE:
            break
        if status not in PENDING:
            raise RuntimeError(f"unrecognized proof job state {status}")
        if time.monotonic() - started > deadline:
            raise TimeoutError(f"proof job {job_id} exceeded benchmark deadline")
        time.sleep(.25)
    result = {
        "job_id": job_id,
        "status": record["status"],
        "job_error": record.get("error"),
        "wall_seconds": round(time.monotonic() - started, 3),
        "observed_status_transitions_seconds": seen,
        "result_sha256": record.get("result_sha256"),
        "proof_verified": status == "verified_raito",
    }
    after = {
        role: snapshot_cgroup(path, expected.get(role))
        for role, path in cgroups.items()
    }
    if "worker" in cgroups or not cgroups:
        # Preserve the original report keys for legacy and unconfigured runs.
        result["cgroup_before"] = before.get("worker", {})
        result["cgroup_after"] = after.get("worker", {})
        if "worker" in cgroups:
            result["cgroup_io_delta"] = cgroup_io_delta(before["worker"], after["worker"])
    else:
        result["cgroups_before"] = before
        result["cgroups_after"] = after
        result["cgroups_io_delta"] = {
            role: cgroup_io_delta(before[role], after[role]) for role in cgroups
        }
    if status == "verified_raito":
        receipt = gateway_read.call("zk.proof.receipt", [job_id])
        if receipt["verified_statement"]["txid"] != txid:
            raise RuntimeError("verified receipt TXID mismatch")
        result["receipt"] = receipt["verified_statement"]
        result.update(proof_retrieve(gateway_read, job_id, record["result_sha256"]))
    return result


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--gateway-url", default="http://127.0.0.1:18444")
    p.add_argument("--core-url", default="http://127.0.0.1:8332")
    p.add_argument("--core-cookie", required=True, type=Path)
    p.add_argument("--height", required=True, type=int)
    p.add_argument("--blockhash", required=True)
    p.add_argument("--txid", required=True)
    p.add_argument("--policy-sha256", required=True)
    p.add_argument("--memory-mib", type=int, default=2048)
    p.add_argument("--rpc-samples", type=int, default=5)
    p.add_argument("--runs", type=int, default=1)
    p.add_argument("--timeout-seconds", type=float, default=1300)
    p.add_argument("--worker-cgroup", type=Path, action=UniqueCgroupPath,
                   help="legacy single cgroup for combined workers (exclusive with role-specific options)")
    p.add_argument("--producer-cgroup", type=Path, action=UniqueCgroupPath)
    p.add_argument("--verifier-cgroup", type=Path, action=UniqueCgroupPath)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    txid, blockhash, policy = (
        require_hash(args.txid), require_hash(args.blockhash),
        require_hash(args.policy_sha256))
    if not (1 <= args.rpc_samples <= 50 and 1 <= args.runs <= 5
            and 1 <= args.memory_mib <= 32768 and args.height >= 0
            and args.timeout_seconds > 0):
        p.error("invalid benchmark limits")
    try:
        cgroups = select_cgroups(args.worker_cgroup, args.producer_cgroup,
                                 args.verifier_cgroup)
    except ValueError as exc:
        p.error(str(exc))
    read_token = os.environ["SUPERNODE_RPC_TOKEN"]
    control_token = os.environ["SUPERNODE_CONTROL_TOKEN"]
    cookie = args.core_cookie.read_text(encoding="utf8").strip()
    if ":" not in cookie:
        raise ValueError("invalid Bitcoin Core RPC cookie")
    core = RPC(args.core_url, "Basic " + base64.b64encode(cookie.encode()).decode())
    read = RPC(args.gateway_url, "Bearer " + read_token)
    control = RPC(args.gateway_url, "Bearer " + control_token)
    actual_blockhash = core.call("getblockhash", [args.height])
    if actual_blockhash != blockhash:
        raise ValueError("requested block is no longer active at Bitcoin Core height")
    baseline = measure_pair(core, read, args.height, args.rpc_samples)
    manifest = json.dumps({
        "schema": "raito_fetch_request_v1", "network": "main",
        "txid": txid, "block_hash": blockhash, "block_height": args.height
    }, separators=(",", ":")).encode()
    staged = control.call(
        "zk.artifact.put",
        [args.height, blockhash, "raito_fetch_request", manifest.hex()])
    artifact_id = staged["artifact"]["id"]
    results = [
        run_job(read, control, artifact_id, policy, txid, args.memory_mib,
                args.timeout_seconds, cgroups)
        for _ in range(args.runs)
    ]
    report = {"schema": "supernode_benchmark_v1", "rpc_baseline": baseline,
              "jobs": results, "environment": {
                  "core_url": args.core_url, "gateway_url": args.gateway_url,
                  "height": args.height, "blockhash": blockhash,
                  "cgroup": str(args.worker_cgroup) if args.worker_cgroup else None,
                  "cgroups": {role: str(path) for role, path in cgroups.items()},
                  "cgroup_roles_verified": False,
                  "cgroup_memory_peak_includes_prior_usage": True,
                  "job_status_samples_are_approximate": True,
                  "live_stark_verification_observed": any(
                      x["proof_verified"] for x in results)
              }}
    out = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(out + "\n", encoding="utf8")
    print(out)


if __name__ == "__main__":
    main()
