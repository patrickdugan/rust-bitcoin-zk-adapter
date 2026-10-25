#!/usr/bin/env python3
"""Stage 2 end-to-end: SYNTHETIC jobs through the real gateway and brokers.

Every proof byte here comes from mock-raito-fetch and every "receipt" from
mock-raito-verify, so a verified_raito status below means only that the
gateway accepted a receipt-shaped reply from the configured verifier. These
runs test plumbing, binding checks, UID boundaries and crash recovery; they
are not cryptographic acceptance.
"""
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from urllib.request import Request, build_opener, ProxyHandler
from lifecycle import Observation, command, is_sleep, in_unit, detached_ready, crash_precondition

SECRETS = "/root/rbzk-secrets"
READ = open(f"{SECRETS}/read").read().strip()
CTRL = open(f"{SECRETS}/control").read().strip()
GATEWAY = "http://127.0.0.1:18444"
HEIGHT = 900000
BLOCK = hashlib.sha256(f"rbzk-synthetic-{HEIGHT}".encode()).hexdigest()
TXID = "cd" * 32
POLICY = "ab" * 32
OPENER = build_opener(ProxyHandler({}))
RESULTS = []


def rpc(method, params, token=READ):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = Request(GATEWAY, data=body, method="POST", headers={
        "Content-Type": "application/json", "Authorization": "Bearer " + token})
    try:
        with OPENER.open(req, timeout=30) as resp:
            reply = json.loads(resp.read())
    except Exception as exc:  # HTTP errors carry JSON bodies too
        data = getattr(exc, "read", lambda: b"")()
        try:
            reply = json.loads(data)
        except ValueError:
            return None, f"{type(exc).__name__}"
    if reply.get("error"):
        return None, reply["error"].get("message", str(reply["error"]))
    return reply.get("result"), None


def mode(fetch=None, verify=None):
    if fetch is not None:
        open("/etc/supernode-test/fetch-mode", "w").write(fetch + "\n")
    if verify is not None:
        open("/etc/supernode-test/verify-mode", "w").write(verify + "\n")


def record(name, ok, detail, kind="synthetic"):
    RESULTS.append({"case": name, "outcome": "PASS" if ok else "FAIL",
                    "evidence": kind, "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}", flush=True)


def wait_gateway(timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        _, err = rpc("getblockchaininfo", [])
        if err is None:
            return True
        time.sleep(0.5)
    return False


def submit(token=CTRL):
    manifest = json.dumps({"schema": "raito_fetch_request_v1", "network": "main", "txid": TXID,
                           "block_hash": BLOCK, "block_height": HEIGHT}, separators=(",", ":")).encode()
    art, err = rpc("zk.artifact.put", [HEIGHT, BLOCK, "raito_fetch_request", manifest.hex()], CTRL)
    if err:
        raise RuntimeError(f"artifact put: {err}")
    job, err = rpc("zk.proof.submit", ["raito", art["artifact"]["id"], 1024, POLICY, TXID], token)
    if err:
        return None, err
    return job["job"]["id"], None


def status(job_id):
    res, err = rpc("zk.proof.status", [job_id])
    return (res or {}).get("job", {}), err


def wait_for(job_id, wanted, timeout=60):
    end, seen = time.time() + timeout, []
    while time.time() < end:
        job, err = status(job_id)
        st = job.get("status") if not err else f"ERR:{err}"
        if not seen or seen[-1] != st:
            seen.append(st)
        if st in wanted:
            return job, seen
        time.sleep(0.25)
    return job, seen


def retrieve(job_id):
    digest, offset, chunks = hashlib.sha256(), 0, 0
    while True:
        res, err = rpc("zk.proof.get", [job_id, offset, 65536])
        if err:
            return None, err
        data = bytes.fromhex(res["data_hex"])
        digest.update(data); offset += len(data); chunks += 1
        if res["complete"]:
            return {"bytes": offset, "chunks": chunks, "sha256": digest.hexdigest(),
                    "proof_verified_flag": res["proof_verified"]}, None


def jobfile_digests():
    return "\n".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p}"
                     for p in sorted(Path("/var/lib/supernode-gateway/jobs").glob("*.json")))


def main():
    assert wait_gateway(), "gateway not answering"
    mode("ok", "ok")

    # 1. Positive synthetic path and full chunked retrieval.
    jid, err = submit()
    job, seen = wait_for(jid, {"verified_raito", "completed_unverified", "failed"})
    receipt, rerr = rpc("zk.proof.receipt", [jid])
    got, gerr = retrieve(jid)
    ok = (job.get("status") == "verified_raito" and not rerr and got
          and got["sha256"] == job.get("result_sha256") == receipt["verified_statement"]["proof_sha256"])
    record("synthetic positive path, chunked retrieval digest", ok,
           f"transitions={seen} bytes={got and got['bytes']} chunks={got and got['chunks']}")
    good_job = jid

    # 2. Read token cannot use control methods.
    _, e1 = submit(token=READ)
    _, e2 = rpc("zk.proof.verify", [good_job], READ)
    record("read token refused for submit and verify", bool(e1) and bool(e2), f"submit={e1!r} verify={e2!r}")

    # 3. Verifier rejection -> completed_unverified; control-token re-verify without re-fetch.
    mode("ok", "reject")
    jid, _ = submit()
    job, seen = wait_for(jid, {"verified_raito", "completed_unverified", "failed"})
    _, rerr = rpc("zk.proof.receipt", [jid])
    rejected = job.get("status") == "completed_unverified" and rerr is not None
    mode("fill", "ok")   # any re-fetch would now fail on the staging bound
    res, verr = rpc("zk.proof.verify", [jid], CTRL)
    job2, seen2 = wait_for(jid, {"verified_raito", "completed_unverified", "failed"})
    record("verifier rejection preserved as completed_unverified", rejected, f"{seen} error={job.get('error')!r}")
    record("zk.proof.verify re-verifies retained proof without re-fetch",
           job2.get("status") == "verified_raito" and job2.get("result_sha256") == job.get("result_sha256") and not verr,
           f"{seen2} verr={verr!r}")
    mode("ok", "ok")

    # 4. Receipt binding: wrong TXID and forged proof digest from the verifier.
    for vmode in ("wrongtxid", "forgedproof"):
        mode("ok", vmode)
        jid, _ = submit()
        job, seen = wait_for(jid, {"verified_raito", "completed_unverified", "failed"})
        _, rerr = rpc("zk.proof.receipt", [jid])
        got, _ = retrieve(jid)
        record(f"forged typed receipt ({vmode}) not accepted",
               job.get("status") != "verified_raito" and rerr is not None and got and not got["proof_verified_flag"],
               f"{seen} error={job.get('error')!r}")
    mode("ok", "ok")

    # 5. Simulated reorg after acceptance (synthetic Core remap).
    os.makedirs("/var/lib/rbzk-mockcore", exist_ok=True)
    with open("/var/lib/rbzk-mockcore/overrides.json", "w") as f:
        json.dump({str(HEIGHT): "ee" * 32}, f)
    _, rerr = rpc("zk.proof.receipt", [good_job])
    _, gerr = rpc("zk.proof.get", [good_job, 0, 1024])
    os.remove("/var/lib/rbzk-mockcore/overrides.json")
    _, rerr2 = rpc("zk.proof.receipt", [good_job])
    record("simulated reorg: receipt and chunks refused while block inactive",
           rerr is not None and gerr is not None and rerr2 is None,
           f"receipt={rerr!r} get={gerr!r} after-restore={rerr2!r}", kind="synthetic (simulated reorg)")

    # 6. Malicious worker/verifier tamper attempts on gateway metadata.
    before = jobfile_digests()
    mode("tamper", "tamper")
    jid, _ = submit()
    job, seen = wait_for(jid, {"verified_raito", "completed_unverified", "failed"})
    after_old = "\n".join(l for l in jobfile_digests().splitlines() if jid not in l)
    unchanged = all(line in after_old for line in before.splitlines() if line)
    record("tampering worker+verifier cannot alter gateway job records",
           job.get("status") == "verified_raito" and unchanged, f"{seen}")
    mode("ok", "ok")

    # 7. Staging exhaustion by the producer.
    mode("fill", "ok")
    jid, _ = submit()
    job, seen = wait_for(jid, {"verified_raito", "completed_unverified", "failed"})
    left = sum(p.name != "lost+found" for p in Path("/var/lib/supernode-worker/staging").iterdir())
    mode("ok", "ok")
    jid2, _ = submit()
    job2, _ = wait_for(jid2, {"verified_raito", "completed_unverified", "failed"})
    record("staging exhaustion fails the job, leaves no staging files, broker recovers",
           job.get("status") == "failed" and left == 0 and job2.get("status") == "verified_raito",
           f"{seen} error={job.get('error')!r} leftover_entries={left} next={job2.get('status')}")

    # 8. Detached descendants may outlive a job's process group, but must
    # disappear on a completed service stop. Restart only after recording it.
    evidence_dir = os.path.join(os.environ.get("EV", "/root/rbzk-evidence"), "stage2")
    for unit, m, seconds in (("supernode-proof-worker-broker", ("detach", "ok"), 901),
                              ("supernode-raito-verifier", ("ok", "detach"), 902)):
        obs = Observation()
        baseline, _ = obs.clean()
        assert baseline, "services not idle before detached-child case"
        mode(*m)
        jid, err = submit()
        job, seen = wait_for(jid, {"verified_raito", "completed_unverified", "failed"})
        observed, before = obs.wait("after-job-before-stop", lambda e: any(
            p["observed_unit"] == unit and detached_ready(p, seconds, unit)
            for p in e["remaining"]), timeout=5)
        detached = [p for p in before["remaining"] if p["observed_unit"] == unit
                    and detached_ready(p, seconds, unit)]
        obs.save(os.path.join(evidence_dir, f"detach-{seconds}.json"))
        command("systemctl", "stop", unit)
        stopped, stop_event = obs.wait("service-stopped", lambda e:
            e["services"][unit]["properties"]["ActiveState"] == "inactive"
            and e["services"][unit]["properties"]["MainPID"] == "0"
            and not e["services"][unit]["processes"]
            and not any(p["observed_unit"] == unit for p in e["remaining"]))
        mode("ok", "ok")
        command("systemctl", "start", unit)
        # Explicit broker stop propagates through the gateway Requires=.
        command("systemctl", "start", "supernode-gateway")
        clean, _ = obs.clean()
        obs.save(os.path.join(evidence_dir, f"detach-{seconds}.json"))
        record(f"{unit}: setsid escapee after job / after unit restart",
               baseline and not err and job.get("status") == "verified_raito"
               and observed and bool(detached) and stopped and clean,
               f"transitions={seen} exact_detached={detached} stopped={stopped} clean={clean}")
        assert stopped and clean, "stop/restart cleanup failed; refusing to contaminate later cases"
        assert wait_gateway(), "gateway unavailable after broker restart"

    # 9. Require both the gateway phase and an actual sleeping subprocess in
    # the correct service cgroup before sending SIGKILL. Never kill on timeout.
    def crash(label, fmode, vmode, phase, unit, expect):
        obs = Observation()
        baseline, _ = obs.clean()
        assert baseline, "services not idle before crash case"
        mode(fmode, vmode)
        jid, err = submit()
        job, seen = wait_for(jid, {phase, "failed", "completed_unverified", "verified_raito"}, timeout=20)
        worker_unit = "supernode-proof-worker-broker" if phase == "running" else "supernode-raito-verifier"
        ready, before = obs.wait("before-SIGKILL", lambda e: any(
            is_sleep(p, 30) and in_unit(p, worker_unit)
            for p in e["services"][worker_unit]["processes"]), timeout=5)
        current, status_err = status(jid)
        precondition = ready and crash_precondition(job, current, phase, err, status_err, before, worker_unit)
        if not precondition:
            mode("ok", "ok")
            obs.save(os.path.join(evidence_dir, f"crash-{unit}-{phase}.json"))
            record(label, False, f"SIGKILL NOT RUN: precondition failed; transitions={seen} error={job.get('error')!r}")
            raise RuntimeError("crash precondition failed; later cases would be contaminated")
        prior = before["services"][unit]["properties"]
        obs.save(os.path.join(evidence_dir, f"crash-{unit}-{phase}.json"))
        signal_time = time.monotonic()
        command("systemctl", "kill", "-s", "SIGKILL", "--kill-whom=main", unit)
        restarted, _ = obs.wait("automatic-restart", lambda e:
            e["services"][unit]["properties"]["ActiveState"] == "active"
            and e["services"][unit]["properties"]["SubState"] == "running"
            and e["services"][unit]["properties"]["InvocationID"] != prior["InvocationID"]
            and int(e["services"][unit]["properties"]["MainPID"]) > 0, timeout=40)
        gateway_ready = wait_gateway(40)
        job2, seen2 = wait_for(jid, expect | {"failed"}, timeout=60)
        clean, final = obs.clean()
        # A broken cleanup must not pass merely because the 30-second mock
        # finished naturally while recovery polling was in progress.
        cleanup_seconds = time.monotonic() - signal_time
        within_bound = cleanup_seconds < 25
        mode("ok", "ok")
        obs.save(os.path.join(evidence_dir, f"crash-{unit}-{phase}.json"))
        record(label, restarted and gateway_ready and job2.get("status") in expect and clean and within_bound,
               f"phase_seen={phase} -> {seen2} error={job2.get('error')!r} "
               f"restarted={restarted} clean={clean} cleanup_seconds={cleanup_seconds:.3f} remaining={final['remaining']}")
        assert clean and within_bound, "lifecycle cleanup failed; refusing to contaminate later cases"
        return jid, job2

    crash("SIGKILL gateway while producer runs -> interrupted after restart",
          "sleep:30", "ok", "running", "supernode-gateway", {"interrupted"})
    crash("SIGKILL producer broker while running -> job ends, no stray worker",
          "sleep:30", "ok", "running", "supernode-proof-worker-broker", {"failed", "interrupted"})
    jid, job = crash("SIGKILL verifier broker while verifying -> completed_unverified",
                     "ok", "sleep:30", "verifying_raito", "supernode-raito-verifier", {"completed_unverified"})
    if job.get("status") == "completed_unverified":
        rpc("zk.proof.verify", [jid], CTRL)
        job3, seen3 = wait_for(jid, {"verified_raito", "completed_unverified"})
        record("re-verify after verifier crash", job3.get("status") == "verified_raito", f"{seen3}")
    jid, job = crash("SIGKILL gateway while verifying -> unverified/interrupted kept",
                     "ok", "sleep:30", "verifying_raito", "supernode-gateway",
                     {"completed_unverified", "interrupted"})

    # 10. Persisted state survives a clean gateway restart.
    command("systemctl", "restart", "supernode-gateway"); assert wait_gateway()
    rec, rerr = rpc("zk.proof.receipt", [good_job])
    record("verified receipt survives gateway restart (re-validated)", rerr is None, f"err={rerr!r}")

    out = {"schema": "rbzk_stage2_synthetic_v1",
           "note": "Synthetic fetch/verify stand-ins and synthetic Core; not cryptographic acceptance.",
           "results": RESULTS}
    with open(os.path.join(os.environ.get("EV", "/root/rbzk-evidence"), "stage2", "e2e.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(f"{sum(r['outcome'] == 'PASS' for r in RESULTS)}/{len(RESULTS)} passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Leave a machine-readable failed result even when setup/preconditions
        # fail. Exception text is bounded and contains no RPC credentials.
        record("harness completed", False, type(exc).__name__)
        raise
    finally:
        out = {"schema": "rbzk_stage2_synthetic_v1", "results": RESULTS,
               "note": "Synthetic only; not cryptographic acceptance."}
        with open(os.path.join(os.environ.get("EV", "/root/rbzk-evidence"), "stage2", "e2e.json"), "w") as f:
            json.dump(out, f, indent=2)
    sys.exit(0 if RESULTS and all(r["outcome"] == "PASS" for r in RESULTS) else 1)
