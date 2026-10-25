#!/bin/bash
# Stage 2 setup: install the repo's three systemd units UNCHANGED in the
# disposable Linux test host (WSL2 distro or CI runner), with synthetic Core/fetch/verify stand-ins, three
# service UIDs, root-owned executables and 64 MiB loop-ext4 staging bounds.
set -euo pipefail
K="${K:-$(cd "$(dirname "$0")" && pwd)}"
T="${T:?set T to the repository checkout with built services}"
E="${EV:-/root/rbzk-evidence}/stage2"; mkdir -p $E
bash $K/teardown.sh >/dev/null 2>&1 || true

getent group supernode-ipc >/dev/null || groupadd -r supernode-ipc
id supernode-gateway >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin -U supernode-gateway
id supernode-fetch   >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin -g supernode-ipc supernode-fetch
id supernode-verify  >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin -g supernode-ipc supernode-verify
id mockcore          >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin -U mockcore
usermod -aG supernode-ipc supernode-gateway
GW=$(id -u supernode-gateway); PR=$(id -u supernode-fetch); VF=$(id -u supernode-verify)

install -d -o root -g root -m 0755 /opt/supernode/bin /opt/supernode-test /etc/supernode /etc/supernode-test
install -o root -g root -m 0755 $T/services/supernode-rpc/target/debug/rust-bitcoin-supernode-rpc /opt/supernode/bin/
install -o root -g root -m 0755 $T/services/proof-worker-broker/target/debug/supernode-proof-worker-broker /opt/supernode/bin/
install -o root -g root -m 0755 $T/services/raito-verifier-broker/target/debug/supernode-raito-verifier-broker /opt/supernode/bin/
install -o root -g root -m 0755 $K/mock-raito-fetch $K/mock-raito-verify /opt/supernode/bin/
install -o root -g root -m 0755 $K/mockcore.py /opt/supernode-test/
echo ok > /etc/supernode-test/fetch-mode; echo ok > /etc/supernode-test/verify-mode
chmod 0644 /etc/supernode-test/*-mode

# Hard staging bounds: 64 MiB ext4 loop filesystems at the StateDirectory paths.
install -d -m 0700 /var/lib/rbzk-images
for role in worker verify; do
  img=/var/lib/rbzk-images/$role.img; mnt=/var/lib/supernode-$role/staging
  truncate -s 64M $img && mkfs.ext4 -q -F $img
  install -d -m 0755 /var/lib/supernode-$role; install -d $mnt
  mount -o loop,nodev,nosuid $img $mnt
done

umask 077
READ=$(head -c 32 /dev/urandom | sha256sum | cut -c1-64)
CTRL=$(head -c 32 /dev/urandom | sha256sum | cut -c1-64)
COOKIE="mock:$(head -c 16 /dev/urandom | sha256sum | cut -c1-32)"
install -d -m 0700 /root/rbzk-secrets
printf '%s\n' "$READ" > /root/rbzk-secrets/read; printf '%s\n' "$CTRL" > /root/rbzk-secrets/control
printf '%s\n' "$COOKIE" > /root/rbzk-secrets/core.cookie
printf 'MOCKCORE_COOKIE=%s\n' "$COOKIE" > /etc/supernode-test/mockcore.env
printf '%s\n' "$COOKIE" > /etc/supernode/gateway-core.cookie
chown supernode-gateway:supernode-gateway /etc/supernode/gateway-core.cookie; chmod 0400 /etc/supernode/gateway-core.cookie
echo '{}' > /etc/supernode/producer-raito-config.json
chown supernode-fetch:supernode-ipc /etc/supernode/producer-raito-config.json; chmod 0600 /etc/supernode/producer-raito-config.json
FSHA=$(sha256sum /opt/supernode/bin/mock-raito-fetch | cut -d' ' -f1)
VSHA=$(sha256sum /opt/supernode/bin/mock-raito-verify | cut -d' ' -f1)
cat > /etc/supernode/gateway.env <<EOF
BITCOIN_RPC_URL=http://127.0.0.1:18332
BITCOIN_RPC_COOKIE_FILE=/etc/supernode/gateway-core.cookie
SUPERNODE_BIND=127.0.0.1:18444
SUPERNODE_RPC_TOKEN=$READ
SUPERNODE_CONTROL_TOKEN=$CTRL
SUPERNODE_ARTIFACT_DIR=/var/lib/supernode-gateway/artifacts
SUPERNODE_JOB_DIR=/var/lib/supernode-gateway/jobs
SUPERNODE_PROOF_MEMORY_MIB=2048
SUPERNODE_PROOF_WORKERS=1
SUPERNODE_PROOF_BROKER_SOCKET=/run/supernode-worker/socket/broker.sock
SUPERNODE_PROOF_VERIFIER_SOCKET=/run/supernode-verify/socket/verify.sock
SUPERNODE_PROOF_BROKER_UID=$PR
SUPERNODE_PROOF_VERIFIER_UID=$VF
EOF
cat > /etc/supernode/producer.env <<EOF
SUPERNODE_BROKER_SOCKET=/run/supernode-worker/socket/broker.sock
SUPERNODE_BROKER_STAGING_DIR=/var/lib/supernode-worker/staging
SUPERNODE_BROKER_GATEWAY_UID=$GW
SUPERNODE_BROKER_RAITO_WORKER=/opt/supernode/bin/mock-raito-fetch
SUPERNODE_BROKER_RAITO_SHA256=$FSHA
SUPERNODE_BROKER_RAITO_FETCH_CONFIG=/etc/supernode/producer-raito-config.json
SUPERNODE_BROKER_WORKERS=1
EOF
cat > /etc/supernode/verifier.env <<EOF
SUPERNODE_VERIFY_SOCKET=/run/supernode-verify/socket/verify.sock
SUPERNODE_VERIFY_STAGING_DIR=/var/lib/supernode-verify/staging
SUPERNODE_VERIFY_GATEWAY_UID=$GW
SUPERNODE_VERIFY_PRODUCER_UID=$PR
SUPERNODE_VERIFY_BINARY=/opt/supernode/bin/mock-raito-verify
SUPERNODE_VERIFY_BINARY_SHA256=$VSHA
SUPERNODE_VERIFY_WORKERS=1
EOF
chmod 0600 /etc/supernode/*.env /etc/supernode-test/mockcore.env
umask 022

# The repo's units, byte-for-byte; record their digests.
for u in supernode-gateway supernode-proof-worker-broker supernode-raito-verifier; do
  install -m 0644 $T/deploy/systemd/$u.service /etc/systemd/system/
done
sha256sum $T/deploy/systemd/*.service /etc/systemd/system/supernode-*.service > $E/units.sha256
cat > /etc/systemd/system/rbzk-mockcore.service <<'EOF'
[Unit]
Description=SYNTHETIC Bitcoin Core stand-in for rbzk isolation tests
[Service]
User=mockcore
Group=mockcore
EnvironmentFile=/etc/supernode-test/mockcore.env
Environment=MOCKCORE_OVERRIDES=/var/lib/rbzk-mockcore/overrides.json
StateDirectory=rbzk-mockcore
StateDirectoryMode=0755
ExecStart=/usr/bin/python3 /opt/supernode-test/mockcore.py
EOF
systemctl daemon-reload
echo "== systemd-analyze verify (repo units, unchanged)"
systemd-analyze verify /etc/systemd/system/supernode-gateway.service \
  /etc/systemd/system/supernode-proof-worker-broker.service \
  /etc/systemd/system/supernode-raito-verifier.service > $E/systemd-analyze-verify.log 2>&1 && rc=0 || rc=$?
echo "verify_exit=$rc"
cat $E/systemd-analyze-verify.log
if [ "$rc" -ne 0 ]; then
  echo "FAIL systemd unit verification returned $rc"
  exit 1
fi
systemctl start rbzk-mockcore
systemctl start supernode-gateway   # pulls in both brokers via Requires=
sleep 3
for u in rbzk-mockcore supernode-proof-worker-broker supernode-raito-verifier supernode-gateway; do
  printf '%-32s %s\n' $u "$(systemctl is-active $u)"
done
sha256sum /opt/supernode/bin/* > $E/installed-binaries.sha256
cat $E/installed-binaries.sha256
