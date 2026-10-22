# rust-bitcoin-zk-adapter

A **protocol-neutral proof-sidecar toolkit** for Bitcoin applications built
on [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin).

This repository remains an independent consumer of upstream crates and
verification services. It does not patch or fork Bitcoin Core, rust-bitcoin,
or [Raito](https://github.com/starkware-bitcoin/raito).

## Roles

| Component | Responsibility |
| --- | --- |
| rust-bitcoin | Consensus-format types, transaction decoding, TXIDs, scripts |
| This sidecar | Bounded data extraction, proof-aware Bitcoin transaction adapters, developer tooling |
| Raito | Cairo/STARK compressed Bitcoin SPV verification, block inclusion and chain-state checks |
| Bitcoin Core | Authoritative Bitcoin consensus validation and canonical-chain selection |

Raito already implements [compressed SPV verification](https://github.com/starkware-bitcoin/raito/tree/main/crates/raito-spv-verify) in Rust, with a
[bzip2/bincode client](https://github.com/starkware-bitcoin/raito/tree/main/crates/raito-spv-client).
Heavy Cairo/STWO verification dependencies live in the separately built
[optional Raito integration](integrations/raito/), pinned to an upstream commit.
The default sidecar stays small and compiles without them.

## Bitcoin Supernode RPC

The [read-only Supernode RPC service](services/supernode-rpc/README.md)
provides proof-ready Bitcoin Core data access in Rust. It implements
namespaced transaction-inclusion and bounded prevout witness bundles,
backend capability reporting and
node/index discovery. Heavy proving remains isolated in external workers.

## Available functionality

- Extract OP_RETURN outputs from raw Bitcoin transactions and blocks.
- Decode bounded Bitcoin Script pushdata without application-protocol rules.
- Check ordinary Bitcoin transaction Merkle inclusion against a **supplied** block-header Merkle root.
- Recompute an application-defined native SHA-256 receipt over supplied candidate outputs.

A native receipt is **not a proof**. A transaction Merkle path binds the TXID to
a supplied header root; the header remains unauthenticated until an external
trusted Bitcoin node or sound proof verifier establishes its chain context.
Raito provides a complementary path for offline proofs, with its own pinned
verifier configuration and trust assumptions.

## Build and inspect

```sh
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo run --bin inspect_tx -- fixtures/mainnet/2033435de7ce307341231e818ed937cd3a5e8597381fd83a7e5b0234f61b38d3.hex
```

The raw sample is a documented Bitcoin mainnet transaction. See
[fixture provenance](docs/FIXTURE_PROVENANCE.md).

## Architecture

[Bitcoin Supernode architecture](docs/SUPERNODE_ARCHITECTURE.md) describes
Bitcoin Core coexistence, proving-worker isolation, chain reorg handling,
and the future Ark and Shinigami interfaces.


See [Raito integration design](docs/RAITO_INTEGRATION.md) for the upstream
verifier interfaces and an integration plan that reuses upstream proof logic.

## Repository scope

Bitcoin transaction semantics, lightweight proof-related utilities and
integration with reusable Bitcoin ZK clients such as Raito. Downstream
applications supply their own state machine, contract semantics and policies.

Previous application-specific experiments are preserved on the
[`archive/tradelayer-spike-2026-10-22` branch](https://github.com/patrickdugan/rust-bitcoin-zk-adapter/tree/archive/tradelayer-spike-2026-10-22).
Active development here is protocol-neutral.

## License

MIT (see [LICENSE](LICENSE)).
