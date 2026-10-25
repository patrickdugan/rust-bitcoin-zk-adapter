# Benchmarking the Bitcoin Supernode with real Raito proofs

The benchmark harness measures local Bitcoin Core RPC calls against the
Supernode's proxied `getblockhash`, then stages a TXID-bound input manifest and
submits one or more real Raito proof fetch and verify jobs. It checks the
result SHA-256 by retrieving every 64 KiB proof chunk after verification.

It cannot synthesize a real Raito proof. The external upstream Raito bridge,
a synced mainnet Bitcoin Core node, the operator-owned pinned fetch worker,
and the pinned Cairo/STWO verifier must already be configured and reachable.

## Run on the Bitcoin Core host

Use a confirmed transaction and its *currently active* block hash and height.
`raito-verify --policy-sha256` prints the configured pinned policy digest.
Keep the read and control bearer tokens in environment variables.

```sh
export SUPERNODE_RPC_TOKEN='READ_TOKEN'
export SUPERNODE_CONTROL_TOKEN='CONTROL_TOKEN'

python3 tools/benchmark_supernode.py \
  --core-cookie /home/bitcoin/.bitcoin/.cookie \
  --height ACTUAL_MAINNET_HEIGHT \
  --blockhash ACTUAL_BLOCK_HASH \
  --txid ACTUAL_TXID \
  --policy-sha256 ACTUAL_POLICY_SHA256 \
  --memory-mib 2048 \
  --rpc-samples 10 \
  --runs 1 \
  --producer-cgroup /sys/fs/cgroup/supernode-fetch.service \
  --verifier-cgroup /sys/fs/cgroup/supernode-verify.service \
  --output supernode-live-benchmark.json
```

## Cgroup selection and report format

Use `--producer-cgroup PATH --verifier-cgroup PATH` **together** for separate
proof-fetch and STARK-verifier processes. The example paths above are
illustrative: select actual, existing service cgroup-v2 directories on the
operator's host. The parser requires absolute directory paths, checks their
canonical locations and rejects identical, nested or symlink-aliased
producer/verifier paths. Supplying only one role, or combining either role
with `--worker-cgroup`, is an argument error **before credentials are read**.
Repeating any cgroup flag, even with the same value, is also rejected
rather than silently taking the final occurrence. Once validated, scope
reads use the resolved canonical directory, so retargeting an input
symlink after argument parsing cannot silently swap the sampled role.

`--worker-cgroup PATH` remains the **legacy single-cgroup option** for an
operator-confirmed scope that encloses all workers to be measured. It keeps
per-job `cgroup_before`/`cgroup_after` and `environment.cgroup` keys
for existing consumers. Without any cgroup options those legacy per-job
fields remain empty objects. In separate-role mode each job instead has
`cgroups_before.producer`, `cgroups_after.producer`,
`cgroups_before.verifier`, `cgroups_after.verifier`, and the environment
contains `cgroups.producer` and `cgroups.verifier`. The legacy
`environment.cgroup` is `null` in separate-role mode; there is no
fabricated combined measurement. An additional `environment.cgroup_roles_verified`
field remains `false`: this script never authenticates service membership.

Each selected scope reports `memory_current_bytes`, `memory_peak_bytes`,
`swap_peak_bytes`, `io_read_bytes` and `io_write_bytes` from its own
files. Missing, unreadable, empty or malformed counters are `null` with
a description under the scope's `errors` map. A genuine counter value of
zero remains numeric zero. `io.stat` sums per-device `rbytes` and `wbytes`
only when the respective fields are present and valid on every listed device.
An absent `memory.swap.peak` on some kernels is reported as unavailable.
Counter-file reads are bounded to **128 bytes per memory metric** and
**128 KiB for `io.stat`**. The Linux reader requires regular ASCII counter
files and rejects symlinked files, FIFOs and oversized input. An oversized,
non-ASCII or non-regular counter is reported as `null` with an explicit
per-field error. These parser limits protect benchmark reporting against
malformed local fixtures; they do not establish process ownership or enforce
kernel resource budgets.
Snapshots are taken before submission and after completion. Each snapshot
also includes `io_devices`, which exposes the parsed per-device `rbytes`
and `wbytes` counters for an auditable cumulative total. The new
`cgroup_fs_identity` field records the sampled directory's filesystem
device and inode as a **continuity check**. If the path disappears or changes
to another directory while being sampled, all snapshot counters become
`null` with explicit errors. Intervals also fail closed when the directory
identity changes between snapshots, even when I/O counters increase.

For the **legacy single scope**, each job additionally has
`cgroup_io_delta.io_read_delta_bytes` and
`cgroup_io_delta.io_write_delta_bytes`. In paired mode, the matching
per-role fields live at `cgroups_io_delta.producer` and
`cgroups_io_delta.verifier`. They subtract counters for individual devices
between the before/after samples, retaining real zero deltas. A missing or
malformed sample, disappearing/new device, individual counter decrease
(reset/recreation), or arithmetic overflow yields `null` and an explanatory
`errors` entry. These are **I/O counters over the observation interval**,
not per-process accounting. The cgroup may contain other processes, and
kernel sampling cannot prove the producer/verifier identities or job ownership.
Filesystem device/inode values can be reused and do not authenticate a
service, UID, process membership or actual kernel resource limit. They
provide an additional best-effort guard against scope recreation.
The original `cgroup_before`/`cgroup_after` and `cgroups_before`/
`cgroups_after` fields remain available for existing readers; unconfigured
legacy runs continue to return empty snapshots without an interval delta.

**Operator prerequisite:** verify role-to-cgroup ownership through systemd
unit identity and actual process membership (such as `ControlGroup`,
`cgroup.procs` and `/proc/<pid>/cgroup`) before interpreting producer and
verifier labels. Counter numbers and path names do not establish ownership;
swapping the two paths simply swaps the reported labels. Confirm relevant
descendants are inside the scope. Neither this reporting change nor a
cgroup read establishes that memory, swap, PID or disk limits were enforced.

The cgroup `memory.peak` high-water mark can include page cache and previous
runs; reset counters or allocate a fresh scope for per-run peaks.
Polling job status every 250 milliseconds gives approximate stage timings.

For the existing legacy invocation, replace the two role-specific arguments
in the command above with `--worker-cgroup /sys/fs/cgroup/raito-workers`
after confirming that scope actually includes both service roles.

Output contains p50/p95/p99 RPC latency in milliseconds, per-job wall time,
observed state transitions, retrieved proof byte counts, and verification
result. A failure remains visible as `completed_unverified` or `failed`.
Only a real positive Raito verifier receipt sets
`live_stark_verification_observed: true`.

For fair comparisons, use the same Bitcoin Core instance, same block and
client process placement for both direct and proxied RPC. Run cold and warm
experiments with controlled caches, and record operating-system and hardware
configurations. The Raito bridge supplies precomputed chain-state proofs; its
remote service time and local transaction-proof assembly should be identified
separately from native STARK verification time. No benchmark here claims a
Bitcoin Core consensus-validation speedup.
