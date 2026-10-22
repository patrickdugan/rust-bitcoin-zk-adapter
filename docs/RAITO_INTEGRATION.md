# Raito integration architecture

**Upstream:** [starkware-bitcoin/raito](https://github.com/starkware-bitcoin/raito)
at commit `48c237ac941d8061a857ecd111d7e81107912556` (examined October 22, 2026).

Raito exposes useful Rust primitives already:

- [`raito-spv-client`](https://github.com/starkware-bitcoin/raito/tree/main/crates/raito-spv-client)
  loads bzip2-compressed, bincode-serialized `CompressedSpvProof` structures
  via `fetch::load_compressed_proof_from_bzip2`.
- [`raito-spv-verify`](https://github.com/starkware-bitcoin/raito/tree/main/crates/raito-spv-verify)
  exposes `verify_proof(proof, &VerifierConfig, dev).await`, which internally
  verifies transaction inclusion, block-header MMR inclusion, recursive Cairo
  proof and a configurable cumulative-work requirement.
- The [TypeScript/WASM SDK](https://github.com/starkware-bitcoin/raito/tree/main/raito-spv-verify-sdk)
  has reusable front-end interfaces.

## Integration boundary

```
Bitcoin transaction or Raito compressed SPV proof
           |
           v
    Optional Raito Rust adapter
    verify_proof(..., dev=false)
           |
           v
    Verified *under Raito's configured statement*
           |
           v
  rust-bitcoin transaction decoding
  generic OP_RETURN and witness extraction
           |
           v
     Downstream Bitcoin applications
```

A proof's **claimed** TXID must be compared to the actual transaction inside
its decoded proof artifact before verification. The verified transaction
and its enclosing block metadata should flow together as a typed result;
passing an unbound `bool` alongside an unrelated transaction is unsafe.

## Performance

The default crate retains only `rust-bitcoin` and uses a linear scan of
outputs. Compile STWO/Cairo only when the Raito backend is selected.
One full proof verification per unique proof is enough; reuse the verified
result across multiple app-specific inspectors. Cache only by a key that
binds proof content, program hashes, proof verification policy, proven chain
state and TXID. A naïve `txid`-only cache can reuse a receipt under a
different chain state or proof policy.

The native Merkle helper is a local sanity checker for externally supplied
headers, and does not replace Raito's compressed SPV verification.

## Security and protocol boundaries

Raito's README calls the system early-stage and unsuitable for production;
the validity claim depends on the Cairo/STWO verifier, program hashes,
cumulative-work policy and the proof statement. Its project explicitly
places objective canonical-chain selection outside Raito's scope.
Applications requiring chain-tip freshness or economic finality must
define their own policy and checkpoint selection.

Do not run Raito in development mode for security decisions because
`verify_proof` bypasses some checks when `dev=true`.
Do not treat parsing a proof file or matching a Merkle root as
verification of its Cairo/STARK proof.

## Optional Rust backend

The [isolated Raito integration](../integrations/raito/README.md) invokes
Raito's actual STARK verifier. It is kept separate from default builds and
requires its own nightly toolchain and compatibility checks.
