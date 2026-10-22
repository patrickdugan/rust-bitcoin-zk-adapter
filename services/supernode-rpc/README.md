
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
with a fixed-size streaming buffer and checking Bitcoin Core active-chain
binding both before and after retrieval. Results are always labeled
`proof_verified:false` until an independent verifier accepts them.

Worker outputs are retained under a global 256 MiB storage cap, with oldest
finished outputs evicted first and recorded as `output_evicted`. The job
metadata and original result digest remain available for auditing. Failed,
timed-out and interrupted workers have their input/output staging files
cleaned; abandoned files are removed on startup. These budgets govern files
**after** worker execution. Operators still need OS/cgroup memory and disk
limits while proving jobs run.
