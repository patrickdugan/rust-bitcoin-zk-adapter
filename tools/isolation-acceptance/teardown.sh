#!/bin/bash
# Remove the stage 2 test deployment from the WSL2 test distro.
systemctl stop supernode-gateway supernode-proof-worker-broker supernode-raito-verifier rbzk-mockcore 2>/dev/null
for u in supernode-gateway supernode-proof-worker-broker supernode-raito-verifier rbzk-mockcore; do
  rm -f /etc/systemd/system/$u.service
done
systemctl daemon-reload
systemctl reset-failed 2>/dev/null
for role in worker verify; do umount /var/lib/supernode-$role/staging 2>/dev/null; done
rm -rf /var/lib/rbzk-images /var/lib/supernode-gateway /var/lib/supernode-worker /var/lib/supernode-verify \
  /var/lib/private/supernode-* /var/lib/rbzk-mockcore /etc/supernode /etc/supernode-test /opt/supernode /opt/supernode-test \
  /root/rbzk-secrets
pkill -f "sleep 90[12]" 2>/dev/null
exit 0
