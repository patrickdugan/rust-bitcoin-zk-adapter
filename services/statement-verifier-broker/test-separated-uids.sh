#!/usr/bin/env bash
# Separate-UID statement verification with the REAL verifiers and the real
# mainnet fixtures: the broker runs btc-header-fold and btc-pay-verify under a
# fresh system user, and the gateway's statements_gateway tests verify every
# bundle through its socket. Needs sudo (GitHub runners have it).
#
#   test-separated-uids.sh <btc-header-fold> <btc-pay-verify> <nova_vk.bin>
set -euo pipefail

nova_bin="$(realpath "$1")"
pay_bin="$(realpath "$2")"
nova_vk="$(realpath "$3")"
repo="$(cd "$(dirname "$0")/../.." && pwd)"
broker="$repo/services/statement-verifier-broker/target/debug/supernode-statement-verifier-broker"
pay_vkey="0x00de861a80542b3089fed26b37ac4e1f4bb8664dcddadb3a6de5ae7205751e75"

verifier_user="snstmt_$$"
tmp="$(mktemp -d)"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    sudo kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  sudo userdel "$verifier_user" 2>/dev/null || true
  sudo rm -rf -- "$tmp"
}
trap cleanup EXIT

chmod 0755 "$tmp"
sudo useradd --system --no-create-home --gid "$(id -g)" "$verifier_user"
verifier_uid="$(id -u "$verifier_user")"
gateway_uid="$(id -u)"
test "$verifier_uid" != "$gateway_uid"

# Root-owned, read-only executables and key, outside any writable staging.
sudo mkdir -p "$tmp/bin"
sudo install -o root -g root -m 0755 "$nova_bin" "$tmp/bin/btc-header-fold"
sudo install -o root -g root -m 0755 "$pay_bin" "$tmp/bin/btc-pay-verify"
sudo install -o root -g root -m 0644 "$nova_vk" "$tmp/bin/nova_vk.bin"
sudo chmod 0755 "$tmp/bin"

mkdir -p "$tmp/staging" "$tmp/socket" "$tmp/gateway"
# Stands in for the gateway's Core credential: the verifier UID must not read it.
printf '%s' 'rpcuser:secret' > "$tmp/gateway/cookie"
chmod 0700 "$tmp/gateway"
chmod 0600 "$tmp/gateway/cookie"
sudo chown "$verifier_uid:$(id -g)" "$tmp/staging" "$tmp/socket"
sudo chmod 0700 "$tmp/staging"
sudo chmod 0770 "$tmp/socket"

if sudo -u "$verifier_user" cat "$tmp/gateway/cookie" >/dev/null 2>&1; then
  echo "FAIL verifier UID can read the gateway's credential" >&2
  exit 1
fi

# Workers=4: the gateway tests run in parallel, each with its own gateway.
sudo -u "$verifier_user" env \
  SUPERNODE_STATEMENT_VERIFY_SOCKET="$tmp/socket/statements.sock" \
  SUPERNODE_STATEMENT_VERIFY_STAGING_DIR="$tmp/staging" \
  SUPERNODE_STATEMENT_VERIFY_GATEWAY_UID="$gateway_uid" \
  SUPERNODE_STATEMENT_NOVA_VERIFIER="$tmp/bin/btc-header-fold" \
  SUPERNODE_STATEMENT_NOVA_VERIFIER_SHA256="$(sha256sum "$tmp/bin/btc-header-fold" | cut -d' ' -f1)" \
  SUPERNODE_STATEMENT_NOVA_VK="$tmp/bin/nova_vk.bin" \
  SUPERNODE_STATEMENT_NOVA_VK_SHA256="$(sha256sum "$tmp/bin/nova_vk.bin" | cut -d' ' -f1)" \
  SUPERNODE_STATEMENT_PAYMENT_VERIFIER="$tmp/bin/btc-pay-verify" \
  SUPERNODE_STATEMENT_PAYMENT_VERIFIER_SHA256="$(sha256sum "$tmp/bin/btc-pay-verify" | cut -d' ' -f1)" \
  SUPERNODE_STATEMENT_PAYMENT_PAY_VKEY="$pay_vkey" \
  SUPERNODE_STATEMENT_VERIFY_WORKERS=4 \
  "$broker" &
server_pid=$!
for _ in $(seq 1 200); do
  if [[ -S "$tmp/socket/statements.sock" ]]; then break; fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "statement verifier broker terminated before socket startup" >&2
    exit 1
  fi
  sleep 0.05
done
test -S "$tmp/socket/statements.sock"

# The verifier's own UID has group access to the socket but is refused.
sudo -u "$verifier_user" python3 - "$tmp/socket/statements.sock" <<'PY'
import socket
import sys
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
    stream.settimeout(5)
    stream.connect(sys.argv[1])
    try:
        stream.sendall(b"{}\n")
        assert stream.recv(1) == b"", "unauthorized UID received a reply"
    except (BrokenPipeError, ConnectionResetError):
        pass
print("Foreign UID rejected before request admission")
PY

# Every real-fixture gateway test, verifying through the broker.
(
  cd "$repo/services/supernode-rpc"
  SUPERNODE_TEST_STATEMENT_SOCKET="$tmp/socket/statements.sock" \
  SUPERNODE_TEST_STATEMENT_UID="$verifier_uid" \
    cargo test --test statements_gateway -- --nocapture 2>&1 | tee "$tmp/gateway-tests.log"
)
if grep -q "skipped" "$tmp/gateway-tests.log"; then
  echo "FAIL a gateway test skipped instead of using the broker" >&2
  exit 1
fi
grep -q "test result: ok. 5 passed" "$tmp/gateway-tests.log"
if [[ -n "$(sudo ls -A "$tmp/staging")" ]]; then
  echo "FAIL broker left staging files behind" >&2
  exit 1
fi
echo "Real Nova, NSP1 and SP1 fixtures verified through the separate-UID statement broker"
