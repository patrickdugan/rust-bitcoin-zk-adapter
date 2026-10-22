# Rust Bitcoin ZK Adapter

An **independent adjunct** to [`rust-bitcoin`](https://github.com/rust-bitcoin/rust-bitcoin) for Bitcoin overlay applications, starting with TradeLayer-compatible research.

## Scope (v0.1)

- Extract OP_RETURN candidate outputs from decoded Bitcoin blocks in deterministic order.
- Bind candidates to externally supplied chain metadata and prior state commitments.
- Create and recompute a domain-separated SHA-256 native receipt.
- Define the public-input boundary for a future zkVM proving backend.

**Important:** v0.1 contains **no ZK prover, no ZK verifier, and no overlay state transition engine**. A native hash receipt is not a validity proof. The caller must verify the canonical Bitcoin chain, block validity, sender/prevout information and applicable overlay consensus rules. This library must not independently validate Bitcoin consensus.

## Build

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

## Proposed evolution

1. Fixture corpus: historical block/transaction samples, accepted and rejected payloads, documented protocol activation heights.
2. Canonical overlay event parser with bounds checks, version-specific rules, and sender resolution through verified prevouts.
3. Pure state transition engine with checked integer arithmetic, deterministic ordering, reproducible state-root calculation, and differential tests against TradeLayer.js.
4. zkVM guest that executes the same transition function, a real prover, and an independent proof verifier.
5. Proof-input binding to Bitcoin chain commitments; reorg rollback and replay invariants.

## Threat boundaries

- Proof of a transition cannot establish that the supplied transactions belong to the canonical Bitcoin chain unless chain membership is separately authenticated.
- Script parsing must account for arbitrary bytes, malformed push opcodes and version-specific overlay encodings.
- Transaction order and sender resolution are protocol-specific.
- Nothing in this repository changes or forks rust-bitcoin or Bitcoin Core.

## License

MIT OR Apache-2.0, at your option.
