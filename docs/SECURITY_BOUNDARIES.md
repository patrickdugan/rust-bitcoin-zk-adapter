# Supernode trust and deployment boundaries

This is a protocol-neutral Bitcoin Core RPC sidecar for preparing proofs,
dispatching expensive proof jobs, and checking Raito SPV statements.
TradeLayer, Ark VTXO settlement and other application rules remain outside
the generic gateway.

## Claims and evidence

| Evidence | Claim | Additional assumption |
| --- | --- | --- |
| Bitcoin Core `getblockhash(height)` | A given block is active when checked | Correct, authenticated local Bitcoin Core RPC |
| Native transaction Merkle proof | The TXID is included under a particular header | Header ancestry and chain selection are separate |
| Raito SPV STARK receipt | The upstream-pinned Raito verifier accepted its configured statement | Pinned code, program/policy hashes, proof bytes and TXID/block binding |
| `verified_raito` status | Gateway accepted the Raito result and saved a typed receipt | Integrity of the **gateway-owned persistent job records** |
| Ark/Shinigami application proof | Outside the Raito SPV statement | Separately implemented script/VTXO semantics |

Raito proof verification uses `dev=false`. For accepted proofs, the
Supernode also matches proof SHA-256, expected TXID, block hash/height
and the exact policy digest. Receipt retrieval rechecks Bitcoin Core's
active chain. The canonical economic chain and full Bitcoin consensus
validation are separate policies.

## Critical deployment requirement: job metadata ownership

Proof-generating workers are a lower-trust component. A worker can emit
arbitrary bytes and must never be able to create an accepted proof
statement by editing a job record. In legacy direct-execution mode,
the dispatcher launches workers and the verifier under the gateway UID.
This requires an explicit development override because **same-UID
subprocesses can access and alter same-UID files**.

An opt-in producer broker and an independently isolated STARK verifier
are implemented under `services/proof-worker-broker` and
`services/raito-verifier-broker`. Their Unix socket peers authenticate
each other's kernel UIDs and must be provisioned as distinct
unprivileged accounts. Isolated mode is enabled through the gateway's
`SUPERNODE_PROOF_BROKER_SOCKET` and `SUPERNODE_PROOF_VERIFIER_SOCKET`
configuration, together with their expected service UIDs.

The job directory is permissioned `0700`, which protects it from other
Unix users. These permissions provide **no isolation against a worker
running as the same UID**. The worker receives its input/output paths
under this directory. A malicious or compromised worker with filesystem
access could change a `<job_id>.json` record before a gateway restart,
including forging an internally consistent `verified_raito` receipt.
Field-binding checks detect accidental or inconsistent tampering;
they do not authenticate the provenance of a fully forged record.

**Before production**, separate the gateway's metadata from worker-writable
staging and require an OS-enforced identity or sandbox boundary:

1. Give the gateway an exclusive metadata directory and trusted verifier
   policy/receipt store; only the gateway service identity may write it.
2. Give each worker only its own bounded input/output staging area, under
   a separate worker identity or correctly configured filesystem sandbox.
   Use a privileged, narrowly scoped launcher/broker to open and supervise
   the worker; do not run the general-purpose RPC gateway as root.
3. The gateway must copy or import worker outputs through an authenticated
   broker that opens regular files safely and independently checks their
   entire SHA-256. The worker must not be able to write the gateway's job
   records or attestation state.
4. The Raito verifier must run from the operator-pinned binary with the
   chosen policy, and the gateway must accept only verifier-origin results.
   The optional separate-UID verifier service is implemented. Its socket
   authenticates peers through kernel credentials, while each end validates
   the full typed receipt and proof hash.
5. Test forged-job-file and compromised-prover scenarios after enforcing
   the boundary. Keep the draft PR out of production until this is proven.

The optional three-identity deployment provides the intended filesystem
boundary for untrusted producers and STARK-verifier processes. CI tests
exercise this with synthetic bytes and malicious mock processes under
separate Linux accounts. Operators must apply the corresponding filesystem
ownership, kernel process isolation and hard resource limits before using
the configuration with untrusted external proofs. A `chmod 0700` job
directory alone cannot isolate a worker with the gateway's own UID.

## Worker lifetime and resource limits

The dispatcher uses bounded work admission, queue sizes, timeouts and
retention caps. Admission reservations are **not kernel memory caps**.
The optional `SUPERNODE_REQUIRE_CGROUP_MAX_MIB` preflight checks an
already configured Linux cgroup-v2 `memory.max` and zero swap limit.
Fetch and verifier children inherit that kernel boundary.

On Unix, the supervisor launches a new process group and sends SIGKILL
to that group on normal worker completion, timeout and Tokio cancellation.
A worker can still create another session/process group, and SIGKILL of
the gateway process itself bypasses its Rust destructors. Configure
systemd/container cgroup lifetime control (`KillMode=control-group` or
equivalent) to kill all descendants during unit shutdown or gateway crash.

A separate Bitcoin Core service should have its own memory budget and
storage. Keep the gateway and workers in a bounded service/scope with
a finite `MemoryMax`, `MemorySwapMax=0`, `TasksMax`, disk quota, and
restricted runtime directories. Worker staging capacity while jobs run
needs a filesystem/cgroup quota; the 256 MiB retained-result cap acts
after output production.

## Authentication and expected operation

Read-token callers can inspect chain evidence, job states and bounded
proof bytes. Only the control token can upload artifacts, submit work or
invoke `zk.proof.verify` to repeat expensive verification. Tokens must
be distinct, kept out of logs, and transported through trusted local
channels. Remote deployment needs an authenticated transport proxy.

The optional upstream Raito bridge is an untrusted source of proof
bytes. The separate pinned Raito verifier and independent Bitcoin Core
checks decide acceptance. Do not use an upstream fetch exit code,
JSON receipt from a prover, SHA-256 output digest, or Merkle inclusion
alone as evidence of STARK validity.

## Acceptance gates

- All relevant Rust, Python, broker and verifier workflows pass on the
  PR's exact head, including separate-UID Unix integration tests.
- One genuine compressed Raito SPV proof fetched from the operator's
  mainnet node yields a typed receipt under the pinned verifier.
- Negative cases for invalid transaction, block, chain freshness, policy,
  proof bytes and tampered metadata are checked end to end.
- A compromised worker demonstrably cannot edit the gateway's durable
  job records or verifier-policy storage.
- Killing the gateway, worker and verifier under load leaves no child
  processes or unbounded artifacts, including after SIGKILL.
- Peak worker/verifier RAM, IO, latency and cold/warm Core overhead are
  recorded using `tools/benchmark_supernode.py`.

See [the live benchmark instructions](LIVE_SUPERNODE_BENCHMARK.md),
[the Supernode architecture](SUPERNODE_ARCHITECTURE.md), and
[the Raito fetch worker](../integrations/raito-fetcher/README.md), and
[the isolated verifier service](../services/raito-verifier-broker/README.md).
