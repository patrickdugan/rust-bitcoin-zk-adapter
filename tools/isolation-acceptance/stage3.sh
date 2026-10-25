#!/bin/bash
# Stage 3: build the pinned Raito verifier (upstream 48c237a, nightly-2025-07-14,
# dev=false), record digests and the policy SHA-256, then check it REJECTS
# non-proof inputs, directly and behind the isolated third-UID broker.
# No genuine Raito proof exists here, so nothing in this stage can show acceptance.
set -u
export PATH=/root/.cargo/bin:$PATH
K="${K:-$(cd "$(dirname "$0")" && pwd)}"
T="${T:?set T to the repository checkout with built services}"
E="${EV:-/root/rbzk-evidence}/stage3"; rm -rf $E; mkdir -p $E
export K T; [ -n "${EV:-}" ] && export EV
echo "stage3 start $(date -u +%FT%TZ)"
# V may point at an already built verifier (CI builds it in its own step).
if [ -z "${V:-}" ]; then
  B=/root/src/rbzk-raito; rm -rf $B; mkdir -p $B
  (cd $T && tar --exclude='*/target' --exclude=./target -cf - .) | (cd $B && tar xf -)
  rustup run nightly-2025-07-14 rustc -V
  (cd $B && /usr/bin/time -v cargo +nightly-2025-07-14 build --release -j2 \
    --manifest-path integrations/raito/Cargo.toml > $E/build.log 2>&1); rc=$?
  echo "build_exit=$rc"; tail -3 $E/build.log; grep -E "Maximum resident|Elapsed" $E/build.log
  V=$B/integrations/raito/target/release/rust-bitcoin-raito-sidecar
fi
[ -x "$V" ] || { echo "no verifier binary"; exit 1; }
LOCK="$(dirname "$V")/../../Cargo.lock"
sha256sum "$V" "$LOCK" | tee $E/verifier.sha256
grep -A2 'name = "raito-spv-verify"' "$LOCK" | tee $E/raito-pin.txt
POLICY=$($V --policy-sha256); echo "policy_sha256=$POLICY" | tee $E/policy.txt

echo "== direct rejection of non-proof inputs (real verifier, synthetic inputs)"
W=$(mktemp -d); TX=$(printf 'cd%.0s' $(seq 32)); BH=$(python3 -c 'import hashlib;print(hashlib.sha256(b"rbzk-synthetic-900000").hexdigest())')
: > $W/empty.bin; head -c 4096 /dev/urandom > $W/random.bin
head -c 65536 /dev/urandom | bzip2 > $W/random.bin.bz2
{ printf 'SYNTHETIC-NOT-A-RAITO-PROOF\n'; head -c 204800 /dev/urandom; } > $W/mock-proof.bin
head -c 900000000 /dev/zero | bzip2 > $W/zero-bomb.bin.bz2
for f in empty.bin random.bin random.bin.bz2 mock-proof.bin zero-bomb.bin.bz2; do
  /usr/bin/time -f "%e s %M KiB" timeout 120 $V --gateway $W/$f $TX $BH 900000 $POLICY $W/$f.receipt > $W/$f.out 2> $W/$f.err; rc=$?
  r=$( [ -s $W/$f.receipt ] && echo RECEIPT-WRITTEN || echo no-receipt)
  echo "$f: exit=$rc $r $(tail -1 $W/$f.err) | $(head -c 160 $W/$f.err | tr '\n' ' ')"
done | tee $E/direct-rejections.log
# Five deliberate non-proofs must each fail without writing any receipt.
python3 - "$E/direct-rejections.log" <<'PY' || { echo "FAIL negative input rejections incomplete"; exit 1; }
import re, sys
lines = open(sys.argv[1], encoding="utf8").read().splitlines()
for name in ("empty.bin", "random.bin", "random.bin.bz2",
             "mock-proof.bin", "zero-bomb.bin.bz2"):
    found = [line for line in lines if line.startswith(name + ": ")]
    if len(found) != 1 or not re.search(r"\\bexit=[1-9][0-9]* no-receipt\\b", found[0]):
        raise SystemExit("negative verifier case missing or unexpectedly accepted: " + name)
PY
echo "== wrong policy digest is refused before verification"
$V --gateway $W/random.bin.bz2 $TX $BH 900000 $(printf 'ab%.0s' $(seq 32)) $W/p.receipt > /dev/null 2> $W/p.err
wrong_policy_exit=$?
echo "wrong-policy exit=$wrong_policy_exit $(head -c 160 $W/p.err)" | tee -a $E/direct-rejections.log
if [ "$wrong_policy_exit" -eq 0 ] || [ -s "$W/p.receipt" ]; then
  echo "FAIL pinned Raito verifier accepted a mismatched policy"
  exit 1
fi

echo "== real verifier behind the isolated broker (third UID): synthetic job must stay unverified"
bash $K/setup.sh > $E/setup.log 2>&1
install -o root -g root -m 0755 $V /opt/supernode/bin/raito-verify
VSHA=$(sha256sum /opt/supernode/bin/raito-verify | cut -d' ' -f1)
sed -i "s|^SUPERNODE_VERIFY_BINARY=.*|SUPERNODE_VERIFY_BINARY=/opt/supernode/bin/raito-verify|; s|^SUPERNODE_VERIFY_BINARY_SHA256=.*|SUPERNODE_VERIFY_BINARY_SHA256=$VSHA|" /etc/supernode/verifier.env
systemctl restart supernode-raito-verifier supernode-gateway; sleep 3
python3 - "$POLICY" <<'PY' | tee $E/broker-real-verifier.log
import hashlib, json, sys, time
from urllib.request import Request, build_opener, ProxyHandler
policy = sys.argv[1]
read = open("/root/rbzk-secrets/read").read().strip(); ctrl = open("/root/rbzk-secrets/control").read().strip()
op = build_opener(ProxyHandler({}))
def rpc(m, p, t):
    req = Request("http://127.0.0.1:18444", data=json.dumps({"jsonrpc":"2.0","id":1,"method":m,"params":p}).encode(),
                  headers={"Content-Type":"application/json","Authorization":"Bearer "+t}, method="POST")
    try:
        r = json.loads(op.open(req, timeout=30).read())
    except Exception as e:
        r = json.loads(e.read())
    return r.get("result"), r.get("error")
h = 900000; bh = hashlib.sha256(b"rbzk-synthetic-900000").hexdigest(); tx = "cd"*32
man = json.dumps({"schema":"raito_fetch_request_v1","network":"main","txid":tx,"block_hash":bh,"block_height":h},separators=(",",":")).encode()
a, e = rpc("zk.artifact.put", [h, bh, "raito_fetch_request", man.hex()], ctrl)
j, e = rpc("zk.proof.submit", ["raito", a["artifact"]["id"], 1024, policy, tx], ctrl)
jid = j["job"]["id"]; seen = []; t0 = time.time()
while time.time() - t0 < 300:
    s, e = rpc("zk.proof.status", [jid], read); st = s["job"]["status"]
    if not seen or seen[-1] != st: seen.append(st)
    if st in ("verified_raito", "completed_unverified", "failed"): break
    time.sleep(0.5)
rcpt, rerr = rpc("zk.proof.receipt", [jid], read)
print("transitions", seen, "seconds", round(time.time()-t0, 1))
print("final", s["job"]["status"], "error", s["job"].get("error"))
print("receipt_refused", rerr is not None)
print("PASS" if s["job"]["status"] == "completed_unverified" and rerr is not None else "FAIL",
      "real pinned verifier (dev=false) behind third-UID broker leaves synthetic bytes unverified")
PY
journalctl -u supernode-raito-verifier --since "-10min" --no-pager -o cat | tail -5 > $E/verifier-journal-tail.log
bash $K/teardown.sh
rm -rf $W
echo "stage3 end $(date -u +%FT%TZ)"
