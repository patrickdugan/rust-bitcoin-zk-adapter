# Optional Raito backend

This independent, separately built crate calls the actual
[raito-spv-verify](https://github.com/starkware-bitcoin/raito/tree/main/crates/raito-spv-verify)
Rust STARK verification function. The upstream revision is pinned to
`48c237ac941d8061a857ecd111d7e81107912556`.

It handles bounded bzip2 decompression and bincode decoding, checks an
expected transaction ID, extracts the transaction index from Raito's Merkle
proof, then invokes Raito verification with `dev=false`.

The main sidecar avoids Cairo/STWO dependencies. This backend pins the
upstream Raito package and uses its nightly-2025-07-14 toolchain.

```sh
cargo +nightly-2025-07-14 check --manifest-path integrations/raito/Cargo.toml
cargo +nightly-2025-07-14 run --manifest-path integrations/raito/Cargo.toml -- \
  ./proofs/tx_proof.bin.bz2 EXPECTED_TXID MIN_PROVEN_HEIGHT
```

Proof artifacts can be fetched through the upstream
[raito-spv-client](https://github.com/starkware-bitcoin/raito/tree/main/crates/raito-spv-client).

This bridge currently has an independent, manual compatibility workflow
because its research dependencies are expensive to compile. The Raito
README cautions against production deployment. Chain-tip selection and
economic finality are separate application policies. The verification
result is limited to the upstream proof statement and configured work bound.

**Status:** implementation scaffold. Its heavy backend must pass its own
build check before claiming compatibility with the pinned upstream revision.

Compatibility CI runs for changes to this integration directory.
