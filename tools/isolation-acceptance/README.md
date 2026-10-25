# Three-UID isolation acceptance kit (synthetic proofs)

These scripts install `deploy/systemd/*.service` **unchanged** on a
disposable Linux host with systemd and cgroup v2, such as a CI runner or a
WSL2 distro. They provision:

- the three service identities and the `supernode-ipc` group;
- root-owned executables under `/opt/supernode/bin`;
- 64 MiB loop-ext4 staging filesystems;
- clearly labeled synthetic stand-ins for Bitcoin Core (`mockcore.py`), the
  Raito fetcher (`mock-raito-fetch`) and the verifier (`mock-raito-verify`).

| Script | What it records |
| --- | --- |
| `probes.sh` | Service UIDs and live cgroup values (`memory.max`, `memory.swap.max`, `pids.max`). Worker write and list attempts on gateway metadata. Wrong-UID and non-group socket peers. `ProtectHome` cookie hiding. Then kernel enforcement with probe workloads: memory limit with no swap, `TasksMax`, `KillMode=control-group` reaping `setsid` escapees after a main-process SIGKILL, and the staging-disk bound. |
| `run_stage2.sh` | Runs `setup.sh`, then `probes.sh`. Next it runs `tools/benchmark_supernode.py` with producer and verifier cgroups, then `e2e.py`. `e2e.py` covers token scopes, verifier rejection followed by re-verification, forged receipts, a simulated reorg, tampering workers, staging exhaustion, detached descendants and SIGKILL at each lifecycle phase. Journals are captured last, and the run checks that they contain no tokens. |
| `stage3.sh` | Builds or takes the pinned Raito verifier (`48c237a`, `nightly-2025-07-14`). Records its SHA-256 and `--policy-sha256`. Shows it rejects empty, random, bzip2-random, mock and decompression-bomb inputs, directly and behind the third-UID broker. |

None of this is cryptographic acceptance. Every proof byte and every
verifier receipt here is synthetic, except in `stage3.sh`, which runs the
real pinned verifier only on inputs that must be rejected. The probe
workloads use a smaller `MemoryMax` than the units, so the
units' own 4 GiB limit is checked by reading `memory.max`, not by
exhausting it.

```sh
sudo env T="$PWD" EV=/tmp/evidence bash tools/isolation-acceptance/run_stage2.sh
sudo env T="$PWD" EV=/tmp/evidence V=/path/to/rust-bitcoin-raito-sidecar \
  bash tools/isolation-acceptance/stage3.sh
```

Build the gateway and both brokers first (`cargo build` in
`services/supernode-rpc`, `services/proof-worker-broker` and
`services/raito-verifier-broker`). The scripts change system state: users,
units, mounts and `/etc/supernode`. `teardown.sh` removes all of it except
the service accounts. Run them only on a disposable host.
