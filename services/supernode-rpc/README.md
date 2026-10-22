
## Bitcoin Core ZMQ sequence monitoring

Set `BITCOIN_ZMQ_SEQUENCE_URL=tcp://127.0.0.1:28333` and configure Bitcoin Core
with `zmqpubsequence=tcp://127.0.0.1:28333`. The gateway uses an async Rust
ZeroMQ subscriber, subscribes exclusively to `sequence`, checks frame shapes
and transport message counters, and records connect/disconnect and mempool
notification events.

`zk.chainstate` displays epoch, tip snapshot, transport health, and loss
counters; `zk.chain.refresh` reconciles against Bitcoin Core. Disconnections,
malformed messages, and counter gaps mark the local state dirty. TCP subscription
is restricted to loopback. PUB/SUB messages are not durable or authenticated.

# Bitcoin Supernode RPC v0.2

This is a Rust service providing a restricted JSON-RPC 2.0-compatible superset
of Bitcoin Core read methods, with separately authorized local artifact writes
and proof-job submissions. It is designed
for proof preparation and downstream clients such as Ark exits and custody
watchtowers. The default service does not build Raito or Cairo dependencies.

## Launch

Run Bitcoin Core with its JSON-RPC server enabled. For historical lookup and
Ark exit workflows, txindex=1 and access to historical blocks are typically
needed. Block pruning limits historical proof preparation.

Use either a Bitcoin Core RPC cookie file or user/password environment variables.
The gateway requires a read bearer token and binds to loopback. If artifact
storage or proof-job submission is enabled, it also requires a **distinct**
`SUPERNODE_CONTROL_TOKEN` of at least 24 characters. Only that control token
can call `zk.artifact.put` or `zk.proof.submit`. The ordinary read token
can retrieve chain evidence, artifact bytes and completed **unverified**
proof results. The gateway does not expose Bitcoin Core write RPCs.

Example:

    export BITCOIN_RPC_COOKIE_FILE=/path/to/bitcoin/.cookie
    export SUPERNODE_RPC_TOKEN=replace-with-at-least-16-random-characters
    export SUPERNODE_CONTROL_TOKEN=use-a-different-secret-at-least-24-characters
    cargo run --manifest-path services/supernode-rpc/Cargo.toml

Health check: GET http://127.0.0.1:18444/healthz
JSON-RPC: POST http://127.0.0.1:18444/

Example JSON-RPC message, authenticated with Authorization: Bearer <token>:

    {"jsonrpc":"2.0","id":1,"method":"zk.capabilities","params":[]}

    {"jsonrpc":"2.0","id":2,"method":"zk.gettxcontext",
     "params":["<txid>","<confirmed_block_hash>"]}

## ZMQ chain tracking

Configure Bitcoin Core with `zmqpubsequence=tcp://127.0.0.1:28333`
and set `BITCOIN_ZMQ_SEQUENCE_URL=tcp://127.0.0.1:28333` in the gateway.
The subscriber parses Bitcoin Core's multipart `sequence` messages, detects
transport gaps, marks its chain snapshot dirty on block connects or disconnects,
and reconciles state with Bitcoin Core. On reconnect it never assumes that
all intervening events were observed.

`zk.chainstate` reports connection health, message counters and the latest
snapshot. `zk.chain.refresh` forces an RPC reconciliation.
Missed notifications do not replace Bitcoin Core's active-chain checks.

## Disk-backed content-addressed artifact cache

Set `SUPERNODE_ARTIFACT_DIR` to a private writable directory.
`SUPERNODE_ARTIFACT_BUDGET_BYTES` defaults to 67108864 (64 MiB).
An artifact binds network, block hash, height, input kind and the data SHA-256.
It stores bounded bytes under a content-derived filename with atomic writes.
The cache retains at most 512 entries, evicting old entries on budget pressure.

`zk.artifact.put` accepts `[height,blockhash,kind,hexdata]`. Kinds contain
lowercase ASCII letters and underscores. It accepts the data only while its
block belongs to Bitcoin Core's active chain. `zk.artifact.get` accepts
`[artifact_id]`, rechecks the same Bitcoin Core height-to-hash mapping and
network before returning bytes, and reports when a changed chain epoch has
required revalidation. `zk.artifact.stats` reports bounded cache usage.

The 64 KiB JSON-RPC request limit restricts how much data can be uploaded per
request. Large proving inputs should be staged using a future authenticated
streaming/import interface, avoiding base64/hex expansion in the RPC gateway.

## Durable proof dispatch

With `SUPERNODE_JOB_DIR` set, the gateway loads job status files and
recovers jobs left queued or running as `interrupted`. It does not
automatically replay non-idempotent proving work after a crash.

Configure approved workers as absolute paths using either or both of
`SUPERNODE_RAITO_PROVER` and `SUPERNODE_SHINIGAMI_PROVER`. The
gateway launches those known binaries directly, without a shell, using the
following worker arguments:

```sh
approved-prover --input /private/job.input --output /private/job.output \
  --network main --blockhash HASH --height HEIGHT --policy-sha256 HASH
```

The process must create a non-empty output file and exit successfully.
The gateway records an output digest under status `completed_unverified`.
That status means **a worker produced bytes**. It does not attest to Raito,
Shinigami, or Bitcoin proof soundness. Proof verification and publication
require a separately checked verifier and policy binding.

`zk.proof.submit` takes `[backend,artifact_id,estimated_memory_mib,
policy_sha256]`. `zk.proof.status` takes `[job_id]`. Unconfigured
backends are rejected. Queue occupancy is capped at 16 jobs. Worker count
defaults to 1 and is capped at 4; runtime timeout is 600 seconds.
`SUPERNODE_PROOF_MEMORY_MIB` defaults to 4096 and sets an **admission
reservation** budget. It does not impose a hard RSS or GPU-memory cap:
operators must use cgroups or another OS/container limiter for workers.

## Available namespaced RPC

- zk.chainstate and zk.chain.refresh: Bitcoin Core ZMQ tracking status and reconciliation.
- zk.artifact.put/get/stats: bounded, reorg-checked proof input artifact storage.
- zk.proof.submit/status: durable, admission-controlled worker scheduling.
- zk.capabilities: indicates installed features, pending worker integrations,
  and fixed gateway limits.
- zk.nodeprofile: reads Bitcoin Core chain, index and mempool status.
- zk.getspendcontext: extends a confirmed transaction bundle with each input's
  exact satoshi amount and previous locking script. Caps at 256 inputs and
  fetches at most four unique parent transactions concurrently. Historical
  parent retrieval generally requires a synced txindex. It is a read-only
  Shinigami/Ark witness data adapter; script execution proofs are external.
- zk.gettxcontext: fetches a raw transaction, 80-byte header and Bitcoin Core
  gettxoutproof; validates txid, header hash, partial Merkle tree and active
  chain placement at lookup time. Returns the proof and raw hex for external
  verification, including eventual Raito/Shinigami proving workers.
- Selected Bitcoin Core read methods: see allowed_core_rpc() for the complete
  allowlist. Wallet, signing, broadcast, mining and shutdown methods are denied.

The service is not a drop-in substitute for all Bitcoin Core RPC commands.
Its custom methods extend a safe subset.

## Memory and concurrency

The default RPC request cap is 64 KiB, upstream response cap 24 MiB,
max inflight calls 4 (hard maximum 8), with a 30-second Bitcoin Core timeout.
Calls perform bounded streaming reads of Core responses, and each request
completes before its semaphore slot is released. An optional, bounded artifact store and durable proof-job dispatcher are
available, without enabling heavy Cairo/STWO inside this RPC process.

A proving worker should run as a different process with explicit memory limits,
bounded concurrency, persistent job records and content-addressed artifacts.

## Trust boundaries

The gateway authenticates a transaction against its supplied Merkle proof and
checks Bitcoin Core's active-chain view at request time. A reorg can occur
after the response. The caller decides acceptable confirmations, recency and
policy. Merkle inclusion is not Raito/Cairo proof verification.

Raito's proof verifier is already available in the optional
integrations/raito crate. Shinigami requires an independent execution/proving
adapter. The gateway advertises these workers as disconnected until they exist.

Ark support starts with Bitcoin settlement and exit anchor evidence. Its
off-chain VTXO validity/forfeit rules remain Ark-specific and cannot be
inferred from on-chain transaction inclusion alone.

## Planned methods

- zk.getproof: attested Raito proof artifacts and verified policy metadata.
- zk.subscribe: a future push-subscription API over the tracked ZMQ sequence stream.
- zk.getarkanchor: optional Ark adapter linking VTXO exits to on-chain anchors.


## Proof result retention and bounded chunk retrieval

The gateway now provides `zk.proof.get [job_id,offset,max_bytes]`. It returns
hex-encoded chunks of at most 65,536 bytes, recomputing the full SHA-256 digest
with a fixed-size streaming buffer for legacy results, or checking only
requested 64 KiB chunks against a SHA-256-index committed when the worker
finished. Both paths check Bitcoin Core active-chain binding before and
after retrieval. Results are always labeled
`proof_verified:false` until an independent verifier accepts them.

Worker outputs are retained under a global 256 MiB storage cap, with oldest
finished outputs evicted first and recorded as `output_evicted`. The job
metadata and original result digest remain available for auditing. Failed,
timed-out and interrupted workers have their input/output staging files
cleaned; abandoned files are removed on startup. These budgets govern files
**after** worker execution. Operators still need OS/cgroup memory and disk
limits while proving jobs run.


Proof workers generate a compact binary `.chunks` hash index alongside each
completed output; the job record commits to its SHA-256. Validating this small
index and the requested chunks avoids rereading a full 64 MiB proof for each
small RPC response. Clients should still recompute the original whole-output
SHA-256 after assembling all chunks. The chunk index authenticates bytes
against the locally recorded worker output, **not** the proof statement.



## Raito verified result publication

The optional `SUPERNODE_RAITO_VERIFIER` names an absolute, separately built
`integrations/raito` verifier binary. The operator must also set
`SUPERNODE_RAITO_VERIFIER_SHA256` to the lowercase SHA-256 of **that exact
executable**. The gateway checks the pin before every invocation. Worker
output can become a typed `verified_raito` job only after that executable
checks the Raito compressed SPV proof with `dev=false`, its default policy
matches the supplied `policy_sha256`, the proven transaction matches the
caller-provided TXID, and the block matches Bitcoin Core at verification time.

`zk.proof.submit` accepts a fifth optional argument, `expected_txid`, for
Raito jobs. Without it, or without an operator-configured verifier, completed
output stays `completed_unverified`. The policy hash is the SHA-256 of the
canonical JSON serialization of `VerifierConfig::default()` from the pinned
Raito integration. Arbitrary hashes supplied by an RPC client cannot authorize
verification. `zk.proof.receipt [job_id]` serves the typed result only after
a fresh active-chain check. `zk.proof.get` includes the checked Raito statement
on verified chunks. Verification failures preserve the unverified output for
inspection within retention limits. Quota eviction retains the verified
statement and original proof digest, with `output_retained:false`.

Proof verification is still a separate process and uses the same admission
reservation mechanism as proving. Operators must impose OS/cgroup memory
limits on both binaries. Raito's recursive proof validates its configured
statement; it cannot independently select Bitcoin's economic canonical chain.

## Real Raito proof fetch worker

For a fully fetched, compressed Raito SPV proof, build the separately compiled
`integrations/raito-fetcher` binary and configure its operator-owned JSON file
through `SUPERNODE_RAITO_FETCH_CONFIG=/absolute/path/fetcher-config.json`.
Set `SUPERNODE_RAITO_PROVER` to the absolute fetcher executable. The gateway
passes the configuration path only to Raito jobs, and supplies the expected TXID
as `--expected-txid` alongside the existing worker arguments.

The fetcher runs an independently pinned upstream `raito-spv-client fetch`
binary, using a local Bitcoin Core credential cookie and an operator-selected
Raito bridge URL. This process fetches the compressed proof bytes into the
bounded dispatcher output. The separately pinned `raito-verify` process
remains solely responsible for publishing a verified STARK statement.
The default Raito integration is optional and off unless configured.

Both fetch and verification need OS-level limits covering descendants, plus
per-job disk quotas. The current memory reservation and post-execution
result cap are admission/retention controls, not hard runtime isolation.


### Verification-pending state and recovery

A Raito job configured with both an expected TXID and a pinned verifier enters
`verifying_raito` when it has finished producing the compressed proof. It
serves hash-indexed chunks labeled `proof_verified:false` during that phase.
After a positive Cairo/STWO verifier result and an active-chain recheck it
becomes `verified_raito`. A verifier rejection returns the job to
`completed_unverified` with an error, retaining the untrusted bytes under
the output quota.

A gateway restart during `verifying_raito` likewise restores the job to
`completed_unverified` without promoting the statement or automatically
replaying the expensive verifier. Legacy completed outputs remain unverified
until an independent verifier accepts them.

In-flight `verifying_raito` outputs are pinned against completed-result quota eviction until the verifier finishes. These temporary files still count toward the quota; a sweep evicts older completed outputs first. The maximum number of active worker slots is four and each proof output is capped at 64 MiB. A hard disk quota is still required for workers while they write their outputs.

### Linux memory and swap preflight

Set `SUPERNODE_REQUIRE_CGROUP_MAX_MIB=4096` on the gateway if an operator
has already installed a **cgroup v2** memory limit for the worker processes.
The gateway forwards this value to the separately compiled Raito fetcher and
verifier, which both fail closed if their effective inherited cgroup ancestry
does not expose a finite `memory.max` at or below that budget together with
`memory.swap.max=0`. The verifier performs the check before decoding any
proof.

This check verifies an existing Linux kernel boundary. It does not create
cgroups, move processes, or provide worker isolation by itself. Configure
a systemd scope or container cgroup with a limit encompassing descendants of
the Raito fetch client and STARK verifier. An unset environment variable
keeps compatibility with development and CI; production must use explicit
hard limits. The gateway capability response continues to state that a
hard OS memory limit is not enforced by the gateway itself.

### Retry verification without repeating proof generation

`zk.proof.verify [job_id]` requires the **control token**. It schedules
verification of an existing `completed_unverified` Raito proof whose original
job record contains an expected TXID and SHA-256. The dispatcher checks the
entire retained output digest before admitting work, rechecks Bitcoin Core
chain placement, and enters `verifying_raito` atomically. The separately
pinned verifier runs with the same admission and worker-slot budgets as a
fresh proof. A verifier failure returns the result to
`completed_unverified`, retaining its original content digest and error for
inspection. Concurrent or duplicate verification requests are rejected.

The method is designed for recovery after the gateway restarts mid-verification
or when an operator fixes a policy/configuration problem. A fully evicted
output must be regenerated or independently restored before verification.

### Process-tree cleanup

On Unix, the gateway launches approved proof-worker and verifier binaries in
new process groups. A small RAII supervisor sends SIGKILL to the group when
the worker finishes or the gateway task times out, is cancelled, or is
dropped. This covers ordinary descendants of the optional Raito fetcher and
its upstream `raito-spv-client`, preventing common orphan-process leaks.

Programs that intentionally detach into separate sessions or process groups
can escape this mechanism. Production deployments must additionally keep
fetcher, verifier and their descendants inside OS-managed cgroups with hard
memory, swap, disk and process-count limits. The optional cgroup preflight
checks the inherited kernel boundary but never creates it.
