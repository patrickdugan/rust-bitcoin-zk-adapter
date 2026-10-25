#!/bin/bash
# Stage 2 probes: record what the kernel/systemd actually enforce for the
# running three-UID deployment, then exercise the same mechanisms with small
# probe workloads in transient units. Each line ends PASS / FAIL / INFO.
set -u
E="${EV:-/root/rbzk-evidence}/stage2"; mkdir -p $E
CG=/sys/fs/cgroup/system.slice
res() { printf '%-58s %s\n' "$1" "$2"; }

echo "== deployment facts"
for u in supernode-gateway supernode-proof-worker-broker supernode-raito-verifier; do
  pid=$(systemctl show -p MainPID --value $u.service)
  echo "$u: $(systemctl show -p User,KillMode,MemoryMax,MemorySwapMax,TasksMax,NoNewPrivileges,ProtectHome,ProtectSystem $u.service | tr '\n' ' ')"
  echo "   main pid $pid uid/gid: $(ps -o uid=,gid=,supgid= -p $pid 2>/dev/null)"
  for f in memory.max memory.swap.max pids.max; do echo "   $f=$(cat $CG/$u.service/$f)"; done
done
uids=$(for u in supernode-gateway supernode-proof-worker-broker supernode-raito-verifier; do ps -o uid= -p $(systemctl show -p MainPID --value $u.service); done | sort -u | wc -l)
[ "$uids" = 3 ] && res "three distinct service UIDs running" PASS || res "three distinct service UIDs running ($uids)" FAIL
stat -c '%n %U:%G %a' /run/supernode-worker/socket /run/supernode-worker/socket/broker.sock \
  /run/supernode-verify/socket /run/supernode-verify/socket/verify.sock \
  /var/lib/supernode-gateway/jobs /var/lib/supernode-gateway/artifacts \
  /var/lib/supernode-worker/staging /var/lib/supernode-verify/staging /opt/supernode/bin/* 2>&1
for u in supernode-proof-worker-broker supernode-raito-verifier; do
  [ "$(cat $CG/$u.service/memory.swap.max)" = 0 ] && [ "$(cat $CG/$u.service/memory.max)" = 4294967296 ] && [ "$(cat $CG/$u.service/pids.max)" = 64 ] \
    && res "$u cgroup memory.max=4G swap.max=0 pids.max=64" PASS || res "$u cgroup limits as configured" FAIL
done

echo "== write access to gateway metadata from worker identities"
for who in supernode-fetch supernode-verify; do
  if setpriv --reuid=$who --regid=supernode-ipc --clear-groups sh -c 'echo x > /var/lib/supernode-gateway/jobs/probe.json' 2>/dev/null; then
    res "$who cannot write gateway job dir" FAIL; else res "$who cannot write gateway job dir" PASS; fi
  if setpriv --reuid=$who --regid=supernode-ipc --clear-groups sh -c 'ls /var/lib/supernode-gateway/jobs' >/dev/null 2>&1; then
    res "$who cannot list gateway job dir" FAIL; else res "$who cannot list gateway job dir" PASS; fi
  if setpriv --reuid=$who --regid=supernode-ipc --clear-groups sh -c 'echo x >> /opt/supernode/bin/mock-raito-verify' 2>/dev/null; then
    res "$who cannot modify approved executables" FAIL; else res "$who cannot modify approved executables" PASS; fi
done

echo "== socket peer authentication"
id rbzk-intruder >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin -g supernode-ipc rbzk-intruder
for s in /run/supernode-worker/socket/broker.sock /run/supernode-verify/socket/verify.sock; do
  out=$(setpriv --reuid=rbzk-intruder --regid=supernode-ipc --clear-groups python3 - "$s" <<'PY' 2>&1
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(sys.argv[1])
try:
    s.sendall(b'{"version":1}\n'); r = s.recv(1)
    print("REPLIED" if r else "CLOSED")
except (BrokenPipeError, ConnectionResetError):
    print("CLOSED")
PY
)
  [ "$out" = CLOSED ] && res "wrong-UID group member rejected at $(basename $s)" PASS || res "wrong-UID peer at $(basename $s): $out" FAIL
  out=$(setpriv --reuid=nobody --regid=nogroup --clear-groups python3 -c "import socket,sys;s=socket.socket(socket.AF_UNIX);s.connect('$s')" 2>&1 | tail -1)
  case "$out" in *Permission*) res "non-group user cannot connect to $(basename $s)" PASS;; *) res "non-group connect $(basename $s): $out" FAIL;; esac
done

echo "== ProtectHome blocks a cookie under /home"
id rbzkci >/dev/null 2>&1 || useradd -m -s /bin/bash rbzkci
install -d -o rbzkci -m 0755 /home/rbzkci/.bitcoin; echo "mock:homecookie" > /home/rbzkci/.bitcoin/.cookie; chmod 0644 /home/rbzkci/.bitcoin/.cookie
if systemd-run -q --wait --pipe -p User=supernode-gateway -p ProtectHome=yes cat /home/rbzkci/.bitcoin/.cookie >/dev/null 2>&1; then
  res "ProtectHome=yes hides /home cookie" FAIL; else res "ProtectHome=yes hides /home cookie" PASS; fi
systemd-run -q --wait --pipe -p User=supernode-gateway -p ProtectHome=no cat /home/rbzkci/.bitcoin/.cookie >/dev/null 2>&1 \
  && res "same read succeeds without ProtectHome (control)" INFO || res "control read without ProtectHome failed" INFO
rm -rf /home/rbzkci/.bitcoin

echo "== kernel enforcement with probe workloads (transient units, same properties, smaller MemoryMax)"
systemctl reset-failed rbzk-probe-mem 2>/dev/null
systemd-run -q --unit rbzk-probe-mem -p User=supernode-fetch -p MemoryMax=256M -p MemorySwapMax=0 -p TasksMax=64 -p KillMode=control-group \
  --wait python3 -c "
import time; chunks=[]
for i in range(1024):
    b=bytearray(1<<20); b[::4096]=b'x'*len(b[::4096]); chunks.append(b)
print('allocated', len(chunks), 'MiB')" >$E/probe-mem.log 2>&1; rc=$?
result=$(systemctl show -p Result --value rbzk-probe-mem 2>/dev/null)
echo "   exit=$rc result=$result $(journalctl -u rbzk-probe-mem -n 3 --no-pager -o cat 2>/dev/null | tr '\n' ' ' | cut -c1-200)"
[ "$rc" != 0 ] && res "MemoryMax=256M stops a 1 GiB allocation (swap.max=0)" PASS || res "MemoryMax probe allocated beyond limit" FAIL
systemctl reset-failed rbzk-probe-mem 2>/dev/null

systemd-run -q --unit rbzk-probe-pids -p User=supernode-fetch -p TasksMax=64 -p KillMode=control-group --wait --pipe python3 -c "
import os, time
ok=0; err=None
for i in range(200):
    try:
        pid=os.fork()
    except OSError as e:
        err=e.errno; break
    if pid==0:
        time.sleep(3); os._exit(0)
    ok+=1
print(ok, err)" >$E/probe-pids.log 2>&1
read forks errno < $E/probe-pids.log
echo "   forks=$forks errno=$errno"
[ "${forks:-999}" -lt 64 ] && [ "$errno" = 11 ] && res "TasksMax=64 bounds fork (EAGAIN after $forks children)" PASS || res "TasksMax probe: $forks forks errno $errno" FAIL
systemctl reset-failed rbzk-probe-pids 2>/dev/null

systemd-run -q --unit rbzk-probe-escape -p User=supernode-fetch -p KillMode=control-group \
  sh -c 'setsid sleep 903 </dev/null >/dev/null 2>&1 & sh -c "setsid sleep 903 & exit" ; exec sleep 600'
sleep 1
before=$(pgrep -c -f "sleep 903"); incg=$(cat /sys/fs/cgroup/system.slice/rbzk-probe-escape.service/cgroup.procs | wc -l)
systemctl kill -s SIGKILL --kill-whom=main rbzk-probe-escape; sleep 2
after=$(pgrep -c -f "sleep 903")
echo "   escaped setsid children before=$before (cgroup procs=$incg) after SIGKILL of main=$after"
[ "$before" -ge 2 ] && [ "$after" = 0 ] && res "KillMode=control-group reaps setsid escapees after main SIGKILL" PASS || res "escapees survived main SIGKILL ($after)" FAIL
systemctl reset-failed rbzk-probe-escape 2>/dev/null

echo "== hard staging-disk bound while a job writes"
df -B1 --output=size,avail /var/lib/supernode-worker/staging | tail -1
if setpriv --reuid=supernode-fetch --regid=supernode-ipc --clear-groups dd if=/dev/zero of=/var/lib/supernode-worker/staging/probe.fill bs=1M count=100 2>$E/probe-disk.log; then
  res "64 MiB staging fs refuses a 100 MiB write" FAIL; else
  res "64 MiB staging fs refuses a 100 MiB write ($(stat -c %s /var/lib/supernode-worker/staging/probe.fill) bytes written)" PASS; fi
grep -o "No space left on device" $E/probe-disk.log | head -1
rm -f /var/lib/supernode-worker/staging/probe.fill
