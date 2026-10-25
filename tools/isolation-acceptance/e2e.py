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
import subprocess
import sys
import time
from urllib.request import Request, build_opener, ProxyHandler

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


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()


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


def procs(unit):
    return sh(f"cat /sys/fs/cgroup/system.slice/{unit}.service/cgroup.procs 2>/dev/null | wc -l")


def jobfile_digests():
    return sh("sha256sum /var/lib/supernode-gateway/jobs/*.json 2>/dev/null | sort")


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
    left = sh("ls -A /var/lib/supernode-worker/staging | grep -v lost+found | wc -l")
    mode("ok", "ok")
    jid2, _ = submit()
    job2, _ = wait_for(jid2, {"verified_raito", "completed_unverified", "failed"})
    record("staging exhaustion fails the job, leaves no staging files, broker recovers",
           job.get("status") == "failed" and left == "0" and job2.get("status") == "verified_raito",
           f"{seen} error={job.get('error')!r} leftover_entries={left} next={job2.get('status')}")

    # 8. Detached (setsid) descendants of producer and verifier.
    for unit, m, marker in (("supernode-proof-worker-broker", ("detach", "ok"), "sleep 901"),
                            ("supernode-raito-verifier", ("ok", "detach"), "sleep 902")):
        mode(*m)
        jid, _ = submit()
        wait_for(jid, {"verified_raito", "completed_unverified", "failed"})
        time.sleep(1)
        survived = sh(f"pgrep -c -f '{marker}'")
        sh(f"systemctl restart {unit}")
        time.sleep(2)
        after = sh(f"pgrep -c -f '{marker}'")
        record(f"{unit}: setsid escapee after job / after unit restart", after == "0",
               f"alive_after_job={survived} alive_after_restart={after}")
        mode("ok", "ok")
        wait_gateway()

    # 9. SIGKILL during each lifecycle phase.
    def crash(label, fmode, vmode, phase, unit, expect):
        mode(fmode, vmode)
        jid, err = submit()
        job, seen = wait_for(jid, {phase}, timeout=20)
        sh(f"systemctl kill -s SIGKILL --kill-whom=main {unit}")
        time.sleep(5)
        wait_gateway(40)
        job2, seen2 = wait_for(jid, expect | {"failed"}, timeout=60)
        extra = {u: procs(u) for u in ("supernode-proof-worker-broker", "supernode-raito-verifier")}
        stray = sh("pgrep -c -f 'sleep 30'")
        mode("ok", "ok")
        record(label, job2.get("status") in expect and stray == "0",
               f"phase_seen={seen[-1] if seen else None} -> {seen2} error={job2.get('error')!r} "
               f"cgroup_procs={extra} stray_sleepers={stray} active={sh(f'systemctl is-active {unit}')}")
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
    sh("systemctl restart supernode-gateway"); wait_gateway()
    rec, rerr = rpc("zk.proof.receipt", [good_job])
    record("verified receipt survives gateway restart (re-validated)", rerr is None, f"err={rerr!r}")

    out = {"schema": "rbzk_stage2_synthetic_v1",
           "note": "Synthetic fetch/verify stand-ins and synthetic Core; not cryptographic acceptance.",
           "results": RESULTS}
    with open(os.path.join(os.environ.get("EV", "/root/rbzk-evidence"), "stage2", "e2e.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(f"{sum(r['outcome'] == 'PASS' for r in RESULTS)}/{len(RESULTS)} passed")


if __name__ == "__main__":
    sys.exit(main())
