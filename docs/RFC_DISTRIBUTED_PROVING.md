# RFC: Distributed Bitcoin Proof Workloads, Reference SNARKs, and a Post-Quantum STARK Track

**Status:** research proposal; not implemented, not an acceptance report  
**Base:** `feat/raito-verified-results` at `682749aacd967785a3b5f5988857cf8c6a609322`  
**Scope:** protocol-neutral Bitcoin proof infrastructure; no changes to Raito, Bitcoin Core, service identities, or proof publication  
**Decision:** open for review. No new proof verifier or source is authorized by this RFC.

## Executive thesis

Develop a *composable proof-work graph* in which independently bounded workers can prove defined Bitcoin header or application-witness statements, while an independent verifier checks each proof and its connection to an authenticated chain state.

Pursue three **complementary, not interchangeable** ways to reduce single-machine proving cost:

1. **SSD-backed/out-of-core proving** of the existing Raito workload, keeping the pinned STWO verification statement unchanged.
2. **Specialized lightweight SNARK circuits** as a measurable reference for the same carefully specified Bitcoin *header transition* semantics, without Cairo VM overhead.
3. **Distributed segment proofs and verified aggregation**, initially for independently constrained header ranges; eventually a separately designed post-quantum-secure STARK/recursive backend.

The SSD-to-RAM offload experiment is already proceeding independently. This RFC does **not** replace or modify that experiment. In particular, distributing ten existing Raito tasks does not fix a single Raito task that already exceeds the available 28 GiB memory cap.

The eventual product is a proof-system-agnostic **Bitcoin evidence network**, not a new Bitcoin consensus engine and not an alternative definition of `verified_raito`.

## Why investigate this now

In the recorded Raito calibration on `zk` (see `evidence/raito-live-acceptance`, commit `356976b`):

| Pinned Raito batch | Cairo steps | Prover observation |
| --- | ---: | --- |
| 1 block, genesis onward | 6,242,367 | OOM at 28 GiB |
| 10 blocks, genesis onward | 6,324,042 | OOM at 28 GiB |

The difference of 81,675 steps across nine additional blocks is ~9,075 steps per block. The near-equal total steps suggest a large initial execution component *in this workload*. They do **not** quantify the memory saved by a specialized circuit, predict recursive-step costs, or imply that SSD spill can deliver the same proof at acceptable wall time. Those are experiments, not established results.

This proposal is distinct from the existing three-UID Supernode: the gateway, isolated producer broker, and independently pinned Raito verifier already exist, with synthetic lifecycle acceptance. Genuine pinned `dev=false` proof acceptance still requires authentic proof bytes plus Bitcoin Core chain checks.

## Explicit claim boundaries

A verifier must never silently promote a weaker fact into a stronger one.

| Statement | Necessary evidence | Not established by it |
| --- | --- | --- |
| Header-range validity | Proven linked headers, SHA-256d PoW, target/retarget and temporal context, cumulative work, correct starting-state binding | Full Bitcoin block/transaction/script validity or current best-chain selection |
| Header membership | Header-root commitment and membership witness anchored in an accepted range proof | Unspentness or ownership |
| Payment inclusion | TX Merkle path to a selected authenticated header's transaction root and correct output decoding | Current UTXO status, payment finality, full-consensus transaction validity |
| Unspent output | Membership in an **independently authenticated** UTXO-state commitment at a stated height | Control of its spending conditions or continuing lockup after the snapshot |
| Funds lower bound | Distinct unspent outpoints, sound bounded sum, and separately specified spend authority over selected outputs | Complete wallet balance, future spendability, or enforceable collateral |
| Raito STARK receipt | Genuine compressed Raito proof accepted by the exact pinned verifier with `dev=false`, bound to Core active-chain view and policy | Arbitrary other SNARK/STARK statements |
| PQ-secure statement | Full soundness analysis of the particular post-quantum proof system, recursion, commitment and transcript parameters | Quantum security of Bitcoin's ECDSA/Schnorr keys, Bitcoin PoW, or underlying chain selection |

For experimental checkpoint-based proof chains, the checkpoint authority and its time/freshness policy are **public trust assumptions**. A proof starting from a checkpoint is not a proof from genesis.

## Architecture: three layers

```text
               Bitcoin Core / external chain policy
               + authenticated checkpoint or genesis
                              |
                   Reference transition semantics
                              |
        +---------------------+--------------------+
        |                     |                    |
   Existing Raito         Specialized          Future PQ
   STWO (pinned)          SNARK/folding         STARK/recursion
   SSD offload test       reference             candidate
        |                     |                    |
        +---------------------+--------------------+
                              |
             Backend-specific independent verification
                              |
           Claim-typed, content-addressed proof graph
                              |
      Header history / payment witnesses / future UTXO evidence
```

The **reference implementation** is a deterministically testable statement specification, cross-checked against Bitcoin Core consensus vectors. A specialized SNARK is a performance/reference *proof implementation*, not the verifier of the Raito receipt, the oracle for Bitcoin consensus, or the basis of a post-quantum security claim.

The graph stores verified dependencies and context hashes; it does not give an untrusted worker the right to set a trusted gateway job state. The existing gateway-owned metadata and broker/verifier service separation remain mandatory.

## Conditional header-segment contract (proposed, NOT an existing API)

Let `S_i` be a publicly committed header-validation state at the start of a segment. It includes at minimum:

- Bitcoin network and precisely versioned consensus-rules profile;
- next height, preceding header hash, and 256-bit accumulated chainwork;
- all *necessary* contextual data for the next header's target calculation and retarget-boundary transitions (including Bitcoin's historical retarget details);
- the relevant previous eleven timestamps for median-time-past;
- an authenticated append-only commitment to the proven header history, including roots needed for subsequent payment inclusion;
- whether the start is bound to genesis or to a named, authenticated external checkpoint.

A shard proof asserts, conditional on a specified `S_i`, that a contiguous, uniquely ordered range of header bytes correctly updates state to `S_j`. The circuit must check at least header serialization, previous-hash links, SHA-256d proof-of-work, compact target encoding, network-specific target/retarget semantics, median-time-past, accumulated work arithmetic, and the history commitment.

**Future-time eligibility** is relative to a validating clock and belongs to a declared validation-time policy or an independent Core check; it cannot be inferred solely from header bytes. Version/activation and other header-context rules must be traced to the applicable Bitcoin Core consensus implementation. Any omitted rule makes the claim weaker and must be named. A network ruleset cannot silently switch within one proof chain.

A conditional shard may be computed speculatively, before its starting state has been authenticated. It becomes **accepted chain evidence** only after the verifier:

1. Verifies the shard with the exact pinned backend/verifier policy.
2. Verifies `S_i` matches the prior accepted state in *every* field, not just height and block hash.
3. Checks contiguous ranges with no gaps, overlaps or incompatible forks.
4. Anchors the first state to genesis or an explicitly selected checkpoint.
5. Separately checks canonical-chain selection and freshness when those are required by an application.

Parallel shard creation is possible given proposed boundary contexts. **Sequential Nova-style IVC folding is not automatically a logarithmic-depth parallel aggregation tree.** A separate proof-composition scheme must be demonstrated before claiming tree-aggregation latency.

## Proof-work graph and worker trust

A future scheduler may assign deterministic, content-addressed jobs whose identities bind:

- statement schema and version, network, ruleset and trust mode;
- exact input bytes/commitments and starting-state commitment;
- bounded segment range, end-state claim, dependencies and checkpoint identifier;
- backend implementation/build digest, verifier and security policy;
- resource budget, private/public witness designation and artifact digest.

Treat every worker as potentially malicious or flaky. Its `job finished`, returned digest, starting boundary and declared proof kind are all **untrusted**. Only an independent verifier under the gateway's existing trust boundaries can advance a claim-specific result from unverified to verified.

The coordinator must support bounded retries and reassignment with deterministic job identity; failed or interrupted work is not proof. Two workers producing matching hashes is not a replacement for proof verification. Cross-backend agreement can catch implementation defects but does not establish cryptographic soundness.

Header bytes are public and suitable for untrusted distributed workers. Private UTXO, wallet and proof-of-control witnesses must *not* be broadcast to arbitrary nodes; private distributed proving needs a separate, reviewed privacy/MPC protocol. Economic worker payment, reputation and remote proof-marketplace design are explicitly later-stage questions.

## SSD offload, local scaling and distribution: separate experiments

| Track | What changes | May reduce | Cannot by itself solve |
| --- | --- | --- | --- |
| Existing SSD-backed Raito trial | Trace/witness storage and memory access strategy, ideally no change to verifier's public statement | Peak RAM residency | Disk I/O time, fundamentally unsupported prover layouts, or pinned-proof compatibility |
| Specialized header SNARK | Arithmetization and proving backend, with separately verified equivalent header semantics | General-purpose VM trace overhead | Trusted starting-state/chain-selection questions |
| Multi-worker header segments | Bounded independent *conditional* proof jobs | Aggregate throughput and per-machine assignment size **if each segment already fits** | A single backend's irreducible per-proof memory floor |
| Distributed single proof | One proof computation internally split across machines | Possibly per-node memory pressure | Network overhead, prover redesign and privacy constraints |
| PQ-oriented STARK backend | Proof assumptions, arithmetization and verifier | Long-term cryptographic resilience, conditional on analysis | Bitcoin's own quantum exposure and existing classical trust roots |

Do not equate Linux swap with an engineered out-of-core prover. The SSD trial should record actual `memory.peak`, major faults, SSD read/write and amplification, CPU, throughput, wall time and whether the **unchanged pinned verifier** accepts its output. No new production acceptance is justified by a lower RSS alone.

A specialized SNARK produces **a different proof and verifier policy**. It must not be presented as Raito's pinned `verified_raito` receipt or passed to the STWO verifier as though it were equivalent. A STARK that merely verifies a classical SNARK's success does not magically confer post-quantum soundness on the original claim.

## Payment and funds modules: later, distinct statements

First reuse an accepted header-history commitment to authenticate a selected block header, then validate an ordinary transaction Merkle proof and output amount/script. It may be cheaper to leave the Merkle witness outside the SNARK and verify it natively; that is still a composite proof receipt with separately declared assumptions.

An unspentness or balance proof needs more. A UTXO commitment such as a Utreexo-style accumulator is **not committed in Bitcoin's headers** by default; a sound root must come from an independently validating/verified state transition or an explicitly trusted snapshot. A proof of selected UTXOs totaling at least a threshold is a **lower bound**, not an exhaustive wallet balance; duplications, arithmetic overflow and spend-control policy need explicit constraints. A collateral proof at height H is not a covenant or a lock and does not prevent a subsequent spend.

TradeLayer token-state, Litecoin Scrypt rules, Ark VTXO semantics and Shinigami script-execution validity must remain in their own backend/application rulesets rather than being silently included in a Bitcoin header proof.

## Roadmap: gated research, not a deployment order

**R0 — Reproducible semantics.** Define typed public inputs, the reference Rust header-state machine, boundary fixtures, retarget and MTP cases, endianness and 256-bit-work vectors. Compare against pinned Bitcoin Core results. Deliver a *specification and test corpus*, not a ZK-security claim.

**R1 — Small specialized reference circuit.** Experiment with 8- and 32-header batches. Record constraint count, setup/key material, prover/verifier wall time, peak RSS, proof size and validity/rejection of malicious boundary inputs. Prove contextual transitions, not just raw SHA-256d. Failure to fit a modest resource bound is a measured result, not a reason to weaken constraints.

**R2 — Distributed conditional shards.** Exercise four independent 32-header proofs whose proposed states match exactly. Verify, aggregate if supported by the chosen proof system, and reject gaps, overlaps, mixed networks, changed retarget context or forged checkpoints. Measure worker parallelism and the actual aggregation bottleneck.

**R3 — Portable composite payment evidence.** Verify a TX Merkle inclusion path against a selected header in the proven history, binding the chain-selection freshness policy outside the proof. No unsupported unspentness claim.

**R4 — Authenticated UTXO root and lower-bound funds proof.** Only after independently validated state commitments exist; measure 4, 16, 64, 256 synthetic UTXO witnesses and threshold constraints. Keep private proving experiments separate from public-work distribution.

**R5 — PQ proof research track.** Specify equivalent statements under a hash-based STARK or suitable PQ folding construction. Independently review proof-system assumptions, transcript hashes, soundness error, recursion and parameterization. Retain explicit backend security labels; no generic `quantum secure` checkbox.

Each milestone has its own independent design review and cannot inherit a successful Raito acceptance or a favorable SSD benchmark as its security proof.

## Measurement and stop/go decisions

All comparisons need the same stated header range, trust anchor, ruleset and verification objective. Record:

- source commit, compiler/dependencies, backend and verifier binary SHA-256, proof policy and circuit version;
- witness bytes, headers per segment, number of segments, degree of parallelism, setup/preprocessing cost;
- peak **kernel-enforced** RSS/cgroup memory, OOM and swap events, major page faults;
- SSD write/read traffic and amplification, disk footprint, I/O stall time and media endurance estimates;
- per-worker proving time, aggregate throughput, final-proof aggregation cost, verifier runtime and network transfer;
- proof bytes, cost per accepted *independently verified* statement, retry/failure rate and chain-freshness check.

Primary falsifiers: segments still hit the same fixed prover memory floor; folding/aggregation serializes the critical path; SSD I/O makes the system uneconomic; a proof neglects consensus-context fields; a result cannot be independently verified under a pinned policy. Record failures rather than changing the statement to force a pass.

## Existing work and integration policy

- Raito/STWO and the three-UID gateway remain their own pinned trust boundary. Parent PR #1 remains draft pending genuine proof acceptance.
- Option B source-readiness is separate draft PR #9: matching local bytes or bridge configuration remains **UNVERIFIED**.
- The `zk` SSD-to-RAM offload experiment is an independent ongoing measurement, not an implementation of this RFC; **no measured result of that trial is asserted here**.
- This RFC adds no scheduler, network calls, remote worker, cryptographic verifier, resource provisioning, new dependency or production status.
- Any future prototype belongs in an isolated optional integration/branch with vectors and an independently versioned receipt schema. It must not make the current gateway more trusting of workers.

## Unresolved design choices (must not be silently defaulted)

1. Genesis versus externally trusted checkpoint, including provenance/freshness policy.
2. Exact Bitcoin consensus-context state carried across segment boundaries and when Core remains the authority.
3. Proof system and recursive composition strategy: serial IVC, tree aggregation or separate proofs.
4. Authenticated append-only header commitment and its update circuit.
5. UTXO commitment provenance for any actual **unspent** or funds claim.
6. Post-quantum threat model, formal soundness/security margins and transcript/recursion assumptions.
7. Privacy-preserving distributed proving versus public-witness workers.
8. SSD spill implementation's compatibility with the pinned Raito verifier.

Until those choices are specified and verified, this is a research program, not a deployed proof network.

## Background reading (not endorsements of production readiness)

- Bitcoin developer guide, block chain and headers: https://developer.bitcoin.org/devguide/block_chain.html
- Nova / IVC and folding research: https://github.com/microsoft/Nova
- STWO / Circle STARK implementation: https://github.com/starkware-libs/stwo
- Existing architecture and security boundaries: [SUPERNODE_ARCHITECTURE.md](SUPERNODE_ARCHITECTURE.md), [SECURITY_BOUNDARIES.md](SECURITY_BOUNDARIES.md)
