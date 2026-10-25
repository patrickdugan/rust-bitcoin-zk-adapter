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
producer/verifier paths, and two paths that name the same directory object
(device and inode, as a bind mount does). A bind mount of a *child* of the
other role's scope is not detected. Supplying only one role, or combining either role
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
provide an additional best-effort guard against scope recreation. The resolved cgroup paths also retain the filesystem
identity observed during argument validation, before any RPC credentials are
read. If an operator-selected scope is replaced before a job starts, the
benchmark **refuses `zk.proof.submit`** with an explicit error instead of
running expensive work against an ambiguous scope. This applies to every
job and the legacy single-cgroup option. Missing individual counter files
remain `null` with field errors and do not block an otherwise valid
scope. If a directory changes during the job, the after-snapshot and
derived I/O intervals remain unavailable; the reporter cannot retroactively
stop an already submitted job.
Each snapshot now opens the cgroup directory once and reads all counter
files relative to that pinned directory descriptor. This prevents a
transient rename/replacement of the path from mixing producer/verifier
counter files inside one snapshot. The final directory component must
remain a real directory rather than a symlink. A missing or replaced
directory makes its counters unavailable. Before/after snapshots still
require matching filesystem identities; neither descriptor pinning nor
inode comparison authenticates which service performed the work.
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
result. A terminal gateway failure remains visible as `completed_unverified`
or `failed`.

**Incomplete observations:** If `zk.proof.status` becomes unavailable, returns
an unsupported state, or exceeds the benchmark deadline, the job report
retains the last observed `status` (or `null` if none was received) with
`observation_complete: false`, an explicit `monitor_error`, and its available
before/after cgroup snapshots and interval I/O counters. These fields describe
what the benchmark observed; the actual gateway job may still be running.
An RPC exception's **type** is recorded without including remote error text.
A successful terminal-state poll sets `observation_complete: true`.

The `proof_verified` flag becomes true only after the gateway reports
`verified_raito`, a typed Raito receipt binds the submitted TXID, active block
hash/height, selected policy digest, retained proof SHA-256, pinned verifier
identity and statement identifier, and all downloaded proof chunks reassemble
to the saved SHA-256. The benchmark also requires the receipt response to
identify the same job, explicitly report `proof_verified: true`,
`active_chain_at_lookup: true` and `output_retained: true`. The typed
receipt's proven-tip height must be at least the block height; the block
height, proven tip and TX index must be unsigned 32-bit integers. Missing or
extra typed fields, incompatible bindings, broken retrieval or changed output
yield `proof_verified: false` and a `verification_error` while retaining
the cgroup evidence.

These are **independent consistency checks of the authenticated gateway
response**. The benchmark relies on the gateway's pinned STARK verifier for
cryptographic acceptance and its Bitcoin Core connection for the reported
active-chain check. This report does not independently revalidate Bitcoin
consensus or establish the operator's verifier/process identities. The
benchmark requires explicit block hash and height context before promoting
a verified result.

**Bounded proof retrieval:** The reporter enforces the pinned verifier
broker's **16 MiB compressed-proof limit**. It requests **64 KiB** chunks
and stops after at most **256 chunks** or **660 seconds**. Every chunk must
match the requested job ID and saved result SHA-256, return a typed
`verified_statement` identical to the previously validated receipt on
**every chunk** (including exact field types and no missing/extra claims),
report the same bounded `total_bytes`, have contiguous
`offset`/`next_offset` values, contain strict even-length hexadecimal
data of the expected chunk length, and carry the correct boolean `complete`
marker. A chunk whose statement changes mid-transfer is rejected even if
its bytes and SHA-256 otherwise match. When the job status supplies
`result_bytes`, the declared proof length must match it. The transfer
fails closed on inconsistent claims, malformed bytes or short chunks,
preserving the report's `verification_error`. This establishes transfer
integrity relative to the authenticated gateway's job record, not proof
validity by itself.

The environment's `live_stark_verification_observed` flag derives from
those completed checks. It relies on the actual authenticated gateway and
its pinned verifier; synthetic/mock RPCs in the unit tests demonstrate
report control flow rather than real cryptographic acceptance.

For fair comparisons, use the same Bitcoin Core instance, same block and
client process placement for both direct and proxied RPC. Run cold and warm
experiments with controlled caches, and record operating-system and hardware
configurations. The Raito bridge supplies precomputed chain-state proofs; its
remote service time and local transaction-proof assembly should be identified
separately from native STARK verification time. No benchmark here claims a
Bitcoin Core consensus-validation speedup.
