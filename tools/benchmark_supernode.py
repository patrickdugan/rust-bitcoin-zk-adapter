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
from pathlib import Path
import statistics
import time
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler

RESPONSE_CAP = 1024 * 1024
DONE = {"verified_raito", "completed_unverified", "output_evicted", "failed", "interrupted"}
PENDING = {"queued", "running", "verifying_raito"}
MAX_CGROUP_COUNTER = (1 << 64) - 1


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
    # Keep reading the validated canonical path if a supplied symlink is
    # later retargeted. Neither a resolved path nor its counters proves UID.
    return canonical


def snapshot_cgroup(root: Path | None) -> dict:
    """Read cgroup-v2 counters without inventing zeros for absent data.

    Paths and role labels are supplied by the operator; counter files do not
    authenticate the owning service. memory.peak may predate the job.
    """
    if root is None:
        return {}
    if not root.is_absolute():
        raise ValueError("cgroup path must be absolute")
    result = {key: None for key in (
        "memory_current_bytes", "memory_peak_bytes", "swap_peak_bytes",
        "io_read_bytes", "io_write_bytes")}
    errors = {}
    for name, key in (("memory.current", "memory_current_bytes"),
                      ("memory.peak", "memory_peak_bytes"),
                      ("memory.swap.peak", "swap_peak_bytes")):
        try:
            raw = (root / name).read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as exc:
            errors[key] = f"{name} unavailable: {type(exc).__name__}"
            continue
        parsed = parse_cgroup_counter(raw)
        if parsed is None:
            errors[key] = f"{name} malformed: expected unsigned 64-bit counter"
        else:
            result[key] = parsed

    try:
        rows = [line.split() for line in (root / "io.stat")
                .read_text(encoding="ascii").splitlines() if line.strip()]
    except (OSError, UnicodeError) as exc:
        for key in ("io_read_bytes", "io_write_bytes"):
            errors[key] = f"io.stat unavailable: {type(exc).__name__}"
    else:
        if not rows:
            for key in ("io_read_bytes", "io_write_bytes"):
                errors[key] = "io.stat unavailable: no device rows"
        else:
            totals = {"rbytes": 0, "wbytes": 0}
            fields = {"rbytes": "io_read_bytes", "wbytes": "io_write_bytes"}
            devices = set()
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
                for field, metric in fields.items():
                    raw = values.get(field)
                    parsed = parse_cgroup_counter(raw)
                    if malformed or parsed is None:
                        errors[metric] = f"io.stat malformed: {field} missing or invalid on {device}"
                    else:
                        totals[field] += parsed
            for field, metric in fields.items():
                if metric not in errors:
                    result[metric] = totals[field]
    result["errors"] = errors
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
    before = {role: snapshot_cgroup(path) for role, path in cgroups.items()}
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
    after = {role: snapshot_cgroup(path) for role, path in cgroups.items()}
    if "worker" in cgroups or not cgroups:
        # Preserve the original report keys for legacy and unconfigured runs.
        result["cgroup_before"] = before.get("worker", {})
        result["cgroup_after"] = after.get("worker", {})
    else:
        result["cgroups_before"] = before
        result["cgroups_after"] = after
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
