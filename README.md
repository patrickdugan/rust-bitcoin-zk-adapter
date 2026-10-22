# Rust Bitcoin ZK Adapter

An **independent adjunct** to [`rust-bitcoin`](https://github.com/rust-bitcoin/rust-bitcoin) for Bitcoin overlay applications, starting with TradeLayer-compatible research.

## Scope (v0.2 research scaffold)

- Extract OP_RETURN candidate outputs from decoded Bitcoin blocks in deterministic order.
- Bind candidates to externally supplied chain metadata and prior state commitments.
- Create and recompute a domain-separated SHA-256 native receipt.
- Define the public-input boundary for a future zkVM proving backend.
- Parse OP_RETURN script pushes with explicit application resource guards.
- Recognize a strict syntax-only TradeLayer envelope (`tl` plus single base36 type byte).
- Run fixtures from confirmed Bitcoin mainnet, mainnet script archives, and a published regtest example.

**Important:** v0.2 contains **no ZK prover, no ZK verifier, and no overlay state transition engine**. A native hash receipt is not a validity proof. The caller must verify the canonical Bitcoin chain, block validity, sender/prevout information and applicable overlay consensus rules. This library must not independently validate Bitcoin consensus.

## Build

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

## Inspect a transaction

```bash
cargo run --bin inspect_tx -- fixtures/mainnet/2033435de7ce307341231e818ed937cd3a5e8597381fd83a7e5b0234f61b38d3.hex
```

This offline tool reads serialized Bitcoin transaction hex. It makes no network calls or claims about canonical-chain membership. See [fixture provenance](docs/FIXTURE_PROVENANCE.md). The TL parser is an experimental strict mode, not historical TradeLayer consensus equivalence.

## Differential replay

The [TradeLayer compatibility harness](docs/TRADELAYER_COMPAT.md) records how
strict Bitcoin Script decoding and legacy TradeLayer.js marker extraction
interpret the same input. Its synthetic fixtures include direct pushes,
PUSHDATA1, malformed scripts, split pushes, and possible duplicate markers.

Run it with:

    cargo run --bin replay_fixtures -- fixtures/tradelayer/replay_v1.json

The manifest also records chain, network, provenance and optional block height.
Those metadata fields are not verified as consensus assertions.

## Transaction Merkle inclusion

The [Merkle verifier](src/merkle.rs) checks transaction position, sibling
branch and tree width against the transaction Merkle root supplied by a
Bitcoin block header. It detects incorrect odd-leaf duplication and malformed
branches; tests include Bitcoin's genesis block.

A successful branch check authenticates an inclusion claim against a given
root. The caller must separately establish that its header is valid and on
the intended canonical chain using Bitcoin Core. Litecoin and Dogecoin
header validation likewise belongs to their respective full nodes.

## Litecoin testnet inclusion evidence

The [Litecoin testnet evidence verifier](src/evidence.rs) binds a raw
transaction to a declared txid, the Merkle root in a supplied block header,
the header's displayed block hash, and Litecoin Core's specific testnet
genesis hash. It reports OP_RETURN output indices in transaction order.

The verifier also reports strict and historical JavaScript decoding outcomes
for each OP_RETURN output, after verifying the transaction's Merkle path.

The cryptographic checks establish **internal consistency against supplied
inputs**. A trusted Litecoin Core node is required to establish that the
header and block height belong to its validated canonical testnet history.
This is separate from protocol activation and TradeLayer state replay.

```sh
cargo run --bin verify_litecoin_claim -- PATH_TO_EVIDENCE_JSON
```

## Export Litecoin testnet evidence from a local node

The [standard-library Python exporter](scripts/export_litecoin_testnet.py)
uses **Litecoin Core testnet JSON-RPC** with a pinned testnet genesis hash,
fetches a block by height, retrieves its ordered transaction IDs and
computes the Merkle branch of the target transaction. The resulting JSON
can be independently checked by the Rust verifier.

```sh
export LITECOIN_RPC_USER=your_rpc_user
export LITECOIN_RPC_PASSWORD=your_rpc_password
python3 scripts/export_litecoin_testnet.py \
    --height 3496378 \
    --txid bc395db7a7a11b42e9711e192a860da2fffe64955cae6dd673e267532f328b3d \
    --out testnet_evidence.json
cargo run --bin verify_litecoin_claim -- testnet_evidence.json
```

The height and txid above come from the JavaScript decoder test and remain
**unverified until the exporter succeeds against a Litecoin Core node**.
The exporter fails when the node's active chain differs from the expected
testnet genesis or the transaction is absent from the specified block.

Set `--cookie-file` to use Litecoin Core's RPC cookie in place of environment
credentials. RPC access defaults to loopback; remote RPC requires both
explicit permission and HTTPS. Never commit RPC credentials.

## Proposed evolution

1. Extend the corpus with real TradeLayer transactions from each supported chain, including accepted/rejected examples, prevouts and documented activation heights.
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

MIT (see [LICENSE](LICENSE)).
