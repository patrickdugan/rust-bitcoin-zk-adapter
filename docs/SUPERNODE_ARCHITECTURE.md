# Bitcoin Supernode architecture

**Status as of 2026-10-22:** A bounded Rust RPC gateway, ZMQ sequence
monitor, disk-backed artifact store, durable proof-job dispatcher and an
independently compiled, upstream-pinned Raito verifier exist. Bitcoin
Core continues to validate Bitcoin consensus. Full-block STARK proving,
Shinigami execution proofs and an Ark VTXO integration are planned services.

## Responsibility boundaries

| Layer | Owner | Guarantees |
| --- | --- | --- |
| Validated chain and mempool | Bitcoin Core | Consensus validation, chain selection, active chain, UTXO set |
| RPC superset | services/supernode-rpc | Authenticated read-only RPC subset and proof-input packages |
| Data model | rust-bitcoin | Canonical transaction/hash/script encoding and local Merkle checks |
| Chain proof verification | integrations/raito | Reuses Raito's STARK/MMR/SPV verifier with pinned program policy |
| Script execution proof | Shinigami worker (future) | Cairo execution under selected Bitcoin Script semantics |
| Ark application | Independent Ark adapter (future) | VTXO and exit-tree verification under Ark-specific rules |

A valid Bitcoin transaction Merkle proof checks inclusion in one supplied
header. Confirming that header belongs to the intended chain needs Bitcoin
Core or a sound chain-proof system with independently chosen checkpoint and
freshness criteria. A script-execution proof carries different claims from
a UTXO membership proof. VTXO custody and exit guarantees depend on Ark's
own contracts and protocol invariants.

## Current RPC contract

The service is a **restricted read-only Bitcoin Core RPC superset** rather
than a transparent replacement for every Bitcoin Core RPC method.

- Core read-only passthrough: a deliberate allowlist including getblock,
  getblockheader, getrawtransaction, gettxoutproof, getindexinfo and others.
- zk.capabilities: truthful worker and feature availability flags.
- zk.nodeprofile: Core chain and index state, including mempool status.
- zk.gettxcontext(txid, blockhash): retrieves transaction, header, Core
  Merkle proof and validates their consistency plus active-chain membership
  at lookup time.
- zk.getspendcontext(txid, blockhash): adds transaction-input-indexed
  prevout scriptPubKeys and exact satoshi amounts for script execution.
  Uses a maximum of 256 inputs and four parent-transaction fetch tasks.

The gateway currently exposes no broadcast/signing methods and runs on
loopback with its own bearer token. The upstream Bitcoin Core connection
also requires explicit credentials or cookie authentication and loopback
access. Production access from other machines should use independently
configured authenticated transport and review.

## Co-located node configuration

Example Bitcoin Core settings for a disk-backed archival node:

```ini
server=1
txindex=1
blockfilterindex=1
zmqpubsequence=tcp://127.0.0.1:28333
```

The block filter index is optional and useful for certain discovery
workloads. An unpruned chain plus transaction index improves historical
proof preparation. The optional sequence subscriber is implemented; applications still rely on
Bitcoin Core active-chain rechecks because ZMQ notifications may be lost.

For a single machine, budget memory by separating predictable node
storage/cache from volatile proof generation. The figures below are
**example operational limits**, not measured Raito requirements:

| Process | Starting isolation target |
| --- | --- |
| Bitcoin Core | Operator-chosen dbcache, e.g. 4 GiB where RAM permits |
| Rust RPC gateway | 4 in-flight requests; hard cap 8; 24 MiB per Core RPC response |
| Raito/STWO prover | Separate worker and cgroup/OS RSS limit; measure per-proof peak |
| Shinigami worker | Separate Cairo execution/proving budget |
| Proof artifacts | Disk-backed, content-addressed storage and bounded retention |

Multiple Core RPC calls can coexist inside one gateway request. Account for
several response buffers and decoded JSON objects per request. A workload
with large blocks can peak far above the nominal per-response cap. The
gateway currently has **no persistent proof queue and no LRU cache**.

## Efficient proving workflow

1. Obtain block data and witness/prevout information through Bitcoin Core
   once, keyed by the exact block hash and network.
2. Prepare reproducible, content-addressed proof inputs and associate
   them with an explicit program/version/verification policy.
3. Queue the proving computation with a resident-memory budget, fixed
   parallelism, restart-safe status and durable output.
4. Verify the resulting Raito/Shinigami proof through the upstream
   verifier, then bind the result to the expected transaction and
   selected chain-state policy.
5. Let Ark, bridges and watchtowers consume separately versioned receipts
   together with their own application-specific invariants.

Each cache key must bind network, block hash, proof-input hash, program
identity, verifier policy and proof version. The active-chain tip and
confirmations remain time-sensitive and require refresh even when a proof
is content-addressed. ZMQ sequence notifications should invalidate
height-to-hash lookups across reorgs.

## Planned interfaces

- zk.getblockcontext(blockhash): provable block-input manifest, heavy data
  streamed through disk with bounded memory.
- zk.proof.get and cancellation: publishing verified output artifacts and
  cleanly stopping an active worker are still pending; submit/status exist.
- zk.raito.verify: type-safe STARK verifier endpoint with explicit program
  hashes, work requirements and proof provenance.
- zk.shinigami.prepare: script witness bundle; execution/proof worker remains
  separate from the gateway.
- zk.watch: a future push API for the implemented ZMQ sequence tracking.
- Ark-specific adapters: funding, exit, forfeit and challenge evidence,
  with VTXO tree rules kept inside Ark components.

## Measurement plan

Collect p50/p95/p99 RPC latency and upstream bytes transferred, peak RSS,
on-disk proof sizes, prover wall time, verifier time, cache reuse across
transactions within the same Bitcoin block, and errors during reorgs.
Compare cold and warm block data paths before assigning any claimed
performance improvement to the RPC superset.

See [RPC implementation](../services/supernode-rpc/README.md) and
[Raito proof adapter](../integrations/raito/README.md).
