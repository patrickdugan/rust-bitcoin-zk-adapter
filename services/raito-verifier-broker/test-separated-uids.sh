#!/usr/bin/env bash
# Kernel-UID isolation and wire-format smoke test using a synthetic verifier.
# A real Cairo/STWO proof must be exercised separately on a live Core node.
set -euo pipefail

verifier_user="snverify_$$"
producer_user="snproduce_$$"
tmp="$(mktemp -d)"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    sudo kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  sudo userdel "$verifier_user" 2>/dev/null || true
  sudo userdel "$producer_user" 2>/dev/null || true
  sudo rm -rf -- "$tmp"
}
trap cleanup EXIT

chmod 0755 "$tmp"
sudo useradd --system --no-create-home --gid "$(id -g)" "$verifier_user"
sudo useradd --system --no-create-home --gid "$(id -g)" "$producer_user"
verifier_uid="$(id -u "$verifier_user")"
producer_uid="$(id -u "$producer_user")"
gateway_uid="$(id -u)"
test "$verifier_uid" != "$producer_uid"
test "$verifier_uid" != "$gateway_uid"
test "$producer_uid" != "$gateway_uid"

mkdir -p "$tmp/staging" "$tmp/socket" "$tmp/gateway"
printf '%s' 'trusted-verified-job-record' > "$tmp/gateway/job.json"
chmod 0700 "$tmp/gateway"
sudo chown "$verifier_uid:$(id -g)" "$tmp/staging" "$tmp/socket"
sudo chmod 0700 "$tmp/staging"
sudo chmod 0770 "$tmp/socket"

# Pinned synthetic verifier: writes a valid-shaped receipt, but deliberately
# attempts to corrupt gateway-owned metadata before doing so.
sudo tee "$tmp/staging/mock-raito-verifier.sh" >/dev/null <<EOF
#!/bin/sh
set -eu
[ "\$1" = "--gateway" ] || exit 20
proof="\$2"
txid="\$3"
block="\$4"
height="\$5"
policy="\$6"
out="\$7"
if (printf '%s' 'forged' > "$tmp/gateway/job.json") 2>/dev/null; then
  exit 21
fi
digest="\$(sha256sum "\$proof" | cut -d' ' -f1)"
printf '{"statement":"raito_spv_transaction_inclusion_v1","verifier":"raito-spv-verify/48c237ac941d8061a857ecd111d7e81107912556","txid":"%s","block_hash":"%s","block_height":%s,"proven_tip_height":%s,"tx_index":0,"proof_sha256":"%s","policy_sha256":"%s"}' "\$txid" "\$block" "\$height" "\$height" "\$digest" "\$policy" > "\$out"
EOF
sudo chown "$verifier_uid:$(id -g)" "$tmp/staging/mock-raito-verifier.sh"
sudo chmod 0700 "$tmp/staging/mock-raito-verifier.sh"
digest="$(sudo sha256sum "$tmp/staging/mock-raito-verifier.sh" | cut -d' ' -f1)"

binary="$PWD/services/raito-verifier-broker/target/debug/supernode-raito-verifier-broker"
sudo -u "$verifier_user" env \
  SUPERNODE_VERIFY_SOCKET="$tmp/socket/verifier.sock" \
  SUPERNODE_VERIFY_STAGING_DIR="$tmp/staging" \
  SUPERNODE_VERIFY_GATEWAY_UID="$gateway_uid" \
  SUPERNODE_VERIFY_PRODUCER_UID="$producer_uid" \
  SUPERNODE_VERIFY_BINARY="$tmp/staging/mock-raito-verifier.sh" \
  SUPERNODE_VERIFY_BINARY_SHA256="$digest" \
  SUPERNODE_VERIFY_WORKERS=1 \
  "$binary" &
server_pid=$!
for _ in $(seq 1 100); do
  if [[ -S "$tmp/socket/verifier.sock" ]]; then break; fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "verifier daemon terminated before socket startup" >&2
    exit 1
  fi
  sleep 0.05
done
test -S "$tmp/socket/verifier.sock"

python3 - "$tmp/socket/verifier.sock" "$tmp/gateway/job.json" <<'PY'
import hashlib
import json
import socket
import sys

socket_path, metadata = sys.argv[1:]
payload = b"synthetic-unverified-bytes-this-is-not-a-real-STARK-proof"

def communicate(job_id, *, proof_hash=None, network="main"):
    expected = hashlib.sha256(payload).hexdigest()
    header = dict(
        version=1, job_id=job_id, network=network,
        expected_txid="cd" * 32, block_hash="ef" * 32,
        block_height=900000, policy_sha256="12" * 32,
        proof_sha256=proof_hash or expected, proof_bytes=len(payload),
    )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(30)
        stream.connect(socket_path)
        stream.sendall(json.dumps(header, separators=(",", ":")).encode() + b"\n" + payload)
        response = b""
        while not response.endswith(b"\n"):
            part = stream.recv(1)
            assert part and len(response) < 4096, "truncated or oversized reply"
            response += part
    return json.loads(response)

valid = communicate("ab" * 32)
assert valid["error"] is None, valid
receipt = valid["receipt"]
assert receipt["txid"] == "cd" * 32
assert receipt["block_hash"] == "ef" * 32
assert receipt["proof_sha256"] == hashlib.sha256(payload).hexdigest()
assert receipt["policy_sha256"] == "12" * 32
assert "proof_verified" not in valid
forged = communicate("ac" * 32, proof_hash="88" * 32)
assert forged["receipt"] is None and forged["error"], forged
wrong_chain = communicate("ad" * 32, network="regtest")
assert wrong_chain["receipt"] is None and wrong_chain["error"], wrong_chain
assert open(metadata, encoding="utf8").read() == "trusted-verified-job-record"
print("Distinct UID verifier IPC and gateway metadata isolation passed with synthetic proof bytes")
PY

# Both producer and verifier identities are denied at the socket even when
# they have filesystem/group permission to connect.
for username in "$producer_user" "$verifier_user"; do
  sudo -u "$username" python3 - "$tmp/socket/verifier.sock" <<'PY'
import socket
import sys
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
    stream.settimeout(5)
    stream.connect(sys.argv[1])
    try:
        stream.sendall(b"{}\n")
        assert stream.recv(1) == b"", "unauthorized UID received verifier reply"
    except (BrokenPipeError, ConnectionResetError):
        pass
print("Untrusted UID rejected before proof request admission")
PY
done
