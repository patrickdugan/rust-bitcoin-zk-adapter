#!/usr/bin/env bash
# GitHub Actions integration: prove Linux UID isolation with a malicious
# synthetic Raito worker. Runs only on a disposable sudo-enabled CI runner.
set -euo pipefail

worker_user="snfetch_$$"
tmp="$(mktemp -d)"
worker_pid=""
cleanup() {
  if [[ -n "$worker_pid" ]]; then
    sudo kill "$worker_pid" 2>/dev/null || true
    wait "$worker_pid" 2>/dev/null || true
  fi
  sudo userdel "$worker_user" 2>/dev/null || true
  sudo rm -rf -- "$tmp"
}
trap cleanup EXIT
chmod 0755 "$tmp"
sudo useradd --system --no-create-home --gid "$(id -g)" "$worker_user"
broker_uid="$(id -u "$worker_user")"
gateway_uid="$(id -u)"
if [[ "$broker_uid" == "$gateway_uid" ]]; then
  echo "test identities are identical" >&2; exit 1
fi
mkdir -p "$tmp/socket" "$tmp/staging" "$tmp/gateway"
printf '%s' 'trusted-metadata-unchanged' > "$tmp/gateway/job.json"
chmod 0700 "$tmp/gateway"
sudo chown "$broker_uid:$(id -g)" "$tmp/socket" "$tmp/staging"
sudo chmod 0770 "$tmp/socket"
sudo chmod 0700 "$tmp/staging"
sudo tee "$tmp/staging/mock-worker.sh" >/dev/null <<EOF
#!/bin/sh
set -eu
output=""
while [ "\$#" -gt 0 ]; do
  case "\$1" in
    --output) output="\$2"; shift 2;;
    --input|--network|--blockhash|--height|--policy-sha256|--expected-txid) shift 2;;
    *) exit 31;;
  esac
done
# A compromised fetcher explicitly attempts to forge trusted metadata.
if (printf '%s' 'forged' > "$tmp/gateway/job.json") 2>/dev/null; then
  exit 32
fi
printf '%s' 'synthetic-unverified-worker-proof' > "\$output"
EOF
sudo chown "$broker_uid:$(id -g)" "$tmp/staging/mock-worker.sh"
sudo chmod 0700 "$tmp/staging/mock-worker.sh"
sudo touch "$tmp/staging/raito-config.json"
sudo chown "$broker_uid:$(id -g)" "$tmp/staging/raito-config.json"
sudo chmod 0600 "$tmp/staging/raito-config.json"
digest="$(sudo sha256sum "$tmp/staging/mock-worker.sh" | awk '{print $1}')"
binary="services/proof-worker-broker/target/debug/supernode-proof-worker-broker"
sudo -u "$worker_user" env \
  SUPERNODE_BROKER_SOCKET="$tmp/socket/broker.sock" \
  SUPERNODE_BROKER_STAGING_DIR="$tmp/staging" \
  SUPERNODE_BROKER_GATEWAY_UID="$gateway_uid" \
  SUPERNODE_BROKER_RAITO_WORKER="$tmp/staging/mock-worker.sh" \
  SUPERNODE_BROKER_RAITO_SHA256="$digest" \
  SUPERNODE_BROKER_RAITO_FETCH_CONFIG="$tmp/staging/raito-config.json" \
  "$PWD/$binary" &
worker_pid=$!
for _ in $(seq 1 100); do
  if [[ -S "$tmp/socket/broker.sock" ]]; then break; fi
  sleep 0.05
done
test -S "$tmp/socket/broker.sock"
python3 - "$tmp/socket/broker.sock" "$tmp/gateway/job.json" <<'PY'
import hashlib
import json
import socket
import sys

sockpath, metadata = sys.argv[1:]
payload = b"synthetic-input-for-authorized-Raito-job"
request = dict(
    version=1, job_id="ab" * 32, backend="raito", network="main",
    block_hash="cd" * 32, block_height=900000,
    policy_sha256="ef" * 32, expected_txid="12" * 32,
    input_bytes=len(payload)
)
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
    stream.settimeout(15)
    stream.connect(sockpath)
    stream.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\n" + payload)
    line = b""
    while not line.endswith(b"\n"):
        line += stream.recv(1)
        assert len(line) < 4096, "response header exceeded limit"
    reply = json.loads(line)
    assert reply["ok"] is True, reply
    assert "proof_verified" not in reply
    output = b""
    while len(output) < reply["output_bytes"]:
        part = stream.recv(min(65536, reply["output_bytes"] - len(output)))
        assert part, "truncated output"
        output += part
    assert hashlib.sha256(output).hexdigest() == reply["result_sha256"]
    assert output == b"synthetic-unverified-worker-proof"
with open(metadata, encoding="utf8") as record:
    assert record.read() == "trusted-metadata-unchanged"
print("Kernel UID isolation accepted unverified worker output and protected gateway metadata")
PY

# The socket is intentionally group-addressable. A subprocess using the
# broker UID must still fail kernel peer-credential authorization.
sudo -u "$worker_user" python3 - "$tmp/socket/broker.sock" <<'PY'
import socket
import sys
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.settimeout(5)
    s.connect(sys.argv[1])
    try:
        s.sendall(b"{}\n")
        reply = s.recv(1)
        assert reply == b"", "broker replied to a non-gateway UID"
    except (BrokenPipeError, ConnectionResetError):
        pass
print("Worker UID rejected by broker peer-credential gate")
PY
