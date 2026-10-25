#!/bin/bash
# Stage 2 runner: setup -> probes -> harness (synthetic) -> e2e/crash -> logs -> teardown.
set -u
K="${K:-$(cd "$(dirname "$0")" && pwd)}"
T="${T:?set T to the repository checkout with built services}"
E="${EV:-/root/rbzk-evidence}/stage2"; rm -rf $E; mkdir -p $E
export K T; [ -n "${EV:-}" ] && export EV
echo "stage2 start $(date -u +%FT%TZ)"; uname -r; systemd --version | head -1
bash $K/setup.sh 2>&1 | tee $E/setup.log
echo; bash $K/probes.sh 2>&1 | tee $E/probes.log
echo; echo "== benchmark harness against the synthetic deployment (dual cgroups)"
BH=$(python3 -c 'import hashlib;print(hashlib.sha256(b"rbzk-synthetic-900000").hexdigest())')
(cd $T && SUPERNODE_RPC_TOKEN=$(cat /root/rbzk-secrets/read) SUPERNODE_CONTROL_TOKEN=$(cat /root/rbzk-secrets/control) \
  timeout 300 python3 tools/benchmark_supernode.py --core-url http://127.0.0.1:18332 \
  --core-cookie /root/rbzk-secrets/core.cookie --height 900000 --blockhash $BH \
  --txid $(printf 'cd%.0s' $(seq 32)) --policy-sha256 $(printf 'ab%.0s' $(seq 32)) \
  --memory-mib 1024 --rpc-samples 10 --runs 1 --timeout-seconds 120 \
  --producer-cgroup /sys/fs/cgroup/system.slice/supernode-proof-worker-broker.service \
  --verifier-cgroup /sys/fs/cgroup/system.slice/supernode-raito-verifier.service \
  --output $E/benchmark-synthetic.json > $E/benchmark-stdout.log 2>&1; echo "harness_exit=$?")
python3 - $E/benchmark-synthetic.json <<'PY'
import json, sys
try:
    r = json.load(open(sys.argv[1]))
except Exception as e:
    print("no harness report:", e); raise SystemExit
j = r["jobs"][0]
print("status", j["status"], "proof_verified", j["proof_verified"], "obs_complete", j["observation_complete"],
      "transitions", j["observed_status_transitions_seconds"])
print("rpc_baseline", json.dumps(r["rpc_baseline"])[:400])
for role in ("producer", "verifier"):
    b, a = j["cgroups_before"][role], j["cgroups_after"][role]
    print(role, "peak", a.get("memory_peak_bytes"), "swap_peak", a.get("swap_peak_bytes"),
          "io_delta", j["cgroups_io_delta"][role], "errors", a.get("errors"))
print("live_stark_verification_observed =", r["environment"]["live_stark_verification_observed"],
      "(synthetic verifier: this flag cannot distinguish a mock)")
PY
echo; echo "== e2e and crash recovery (synthetic)"
EV="${EV:-/root/rbzk-evidence}" python3 $K/e2e.py 2>&1 | tee $E/e2e.log
for u in supernode-gateway supernode-proof-worker-broker supernode-raito-verifier rbzk-mockcore; do
  journalctl -u $u --since "-30min" --no-pager -o short-iso > $E/journal-$u.log 2>&1
done
grep -l -i -E "token|cookie" $E/journal-*.log && echo "WARNING: journal mentions token/cookie (inspect before publishing)" || echo "journals carry no token/cookie strings"
grep -r -F "$(cat /root/rbzk-secrets/read)" $E && echo "LEAK read token" || echo "no read token in evidence"
grep -r -F "$(cat /root/rbzk-secrets/control)" $E && echo "LEAK control token" || echo "no control token in evidence"
bash $K/teardown.sh
userdel rbzk-intruder 2>/dev/null
echo "stage2 end $(date -u +%FT%TZ)"
