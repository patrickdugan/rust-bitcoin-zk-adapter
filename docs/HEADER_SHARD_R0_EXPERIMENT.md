# R0 experiment: mock-only header-shard boundary contract

**Status:** experimental / structural checker only; **no Bitcoin or cryptographic verification**.

This is the first bounded experiment following [distributed proving RFC #10](https://github.com/patrickdugan/rust-bitcoin-zk-adapter/pull/10). It is intentionally independent of Raito's current STWO proving implementation and of the separate SSD-to-RAM offload experiment. It adds no gateway method, service, verifier, scheduler, prover, networking or new dependency.

## Existing reference implementations — reuse, do not fork their semantics

- [TradeLayer-Rust `src/bitcoin_chainwork.rs`](https://github.com/patrickdugan/TradeLayer-Rust/blob/main/src/bitcoin_chainwork.rs) already contains an **experimental** Bitcoin-mainnet header validator with SHA256d checked linkage, exact difficulty/retarget context, median-time-past and cumulative work, plus genuine genesis/block-1 and numerical vectors. Its arbitrary checkpoints remain declared, unauthenticated state.
- [TradeLayer-Rust chainwork notes](https://github.com/patrickdugan/TradeLayer-Rust/blob/main/docs/BITCOIN_CHAINWORK.md) distinguish local header validity from full consensus and active best-chain selection.
- [Raito-Scrypt `consensus.py`](https://github.com/patrickdugan/Raito-Scrypt/blob/main/raito_scrypt/consensus.py) and `retarget.py` give Litecoin/Dogecoin **non-ZK** reference semantics; the Bitcoin-only mock contract here intentionally does **not** accept Litecoin/Dogecoin.
- Bitcoin Core remains the authority for authentic chain-state comparison. **Nothing in this experiment calls Core or claims a consensus-parity result.**

Future R1 development should first cross-check the actual header state-transition reference with Core and historical/retarget vectors. Only then should the SNARK and PQ/STARK implementations prove an independently pinned statement of those semantics.

## Input contract (research-only, v0)

A single in-memory JSON document, at most **128 KiB**, containing:

- `schema = bitcoin_header_shard_mock_v0`.
- `anchor = {"mode":"declared_checkpoint","id":"<32-byte lowercase hex>","provenance":"UNAUTHENTICATED"}`. No automatic promotion to a trusted genesis or checkpoint.
- `shards`: an explicitly ordered list of 1–64 claimed segments; each covers 1–512 headers and declares network `bitcoin-mainnet`, ruleset `bitcoin-mainnet-header-experimental-v0`, a shared anchor identifier, an inclusive start height and exclusive end height.
- Each segment has an arbitrary `claimed_segment_digest` and a `starting_state` and `ending_state`. This is a declaration *only*, never a proof. Each state contains `next_height`, 32-byte lowercase `tip_hash`, 256-bit `cumulative_work_hex`, 4-byte `last_nbits_hex`, `retarget_first_height`, `retarget_first_timestamp`, up to eleven prior timestamps, and a 32-byte lowercase `header_history_commitment`.

The checker rejects unknown or missing keys, duplicate JSON fields, invalid hexadecimal/bounded numbers, incompatible networks, unsupported trust modes, invalid retarget *anchor position*, wrong MTP-window *length*, impossible non-increasing declared chainwork, gaps, overlaps, reordering or a difference in **any** adjacent state field.

It does **not** validate a header, recompute SHA-256d, recompute nBits/chainwork/MTP values, authenticate a history commitment or statement digest, prove that a boundary was reached from Bitcoin genesis, or check network freshness. A malicious declarant can invent a perfectly self-consistent fake chainwork value that this shape checker accepts; this is explicitly tested.

Outputs are fixed at:

```json
{
  "schema": "bitcoin_header_shard_structure_result_v0",
  "status": "UNVERIFIED",
  "acceptance": "NOT_CHECKED",
  "checkpoint_authenticated": false,
  "proofs_verified": 0,
  "headers_cryptographically_validated": 0
}
```

Additional result fields identify the number of *claimed* shards, *compared* boundary pairs and a SHA-256 over canonicalized declaration JSON. **That hash is just a mock manifest identifier.** It does not authenticate a proof, header, checkpoint, UTXO set, payment or balance.

There is no source fallback, network endpoint, disk path, CPU/GPU reservation, service supervision, secret, cookie or access to actual Raito proofs in the checker.

## Deterministic offline evidence

Command (Python standard library only):

```sh
python3 -m py_compile tools/research/header_shard_manifest.py tools/research/test_header_shard_manifest.py
python3 -m unittest discover -s tools/research -p 'test_header_shard_manifest.py' -v
```

Independent synthetic fixture tests cover:

| Test class | Failure mode / requirement |
| --- | --- |
| 4 × 32-header claims | Compare three adjacent boundaries, return UNVERIFIED and 0 crypto validations |
| Gap / overlap / reverse order | Never reorder or silently insert a segment |
| Boundary mutation | Changed claimed hash, work, nBits, MTP, epoch timestamp or history commitment rejected |
| Origin and ruleset | Changed declared anchor, non-Bitcoin network or incompatible ruleset rejected |
| Forgery | Inflated but mutually consistent chainwork **still UNVERIFIED** |
| Strict JSON | Duplicate keys, unknown proof status fields, bad encoding, unsupported constants and missing fields rejected |
| Resource constraints | Byte budget, 64 claims, 512 headers per claim, integer/hex and timestamp bounds |
| Retarget shape | Declared outgoing/new epoch context must align with claimed height; no actual difficulty check |
| Replay identity | Canonical manifest ID stable under harmless JSON key reorder but different on changed claims |
| Checkpoint provenance | Only explicitly unauthenticated checkpoint declaration permitted |

Tests use invented hashes and simulated contexts, not genuine block headers or proof bytes. A green test suite is **not a SNARK benchmark** and not Raito acceptance.

## Next gates — NOT performed by R0

1. **Real Bitcoin header state semantics:** reuse/audit the existing Rust mainnet chainwork reference; prove genesis and historical vector parity, retarget boundaries, MTP, compact-target and 256-bit chainwork against independent Core results. Define the complete versioned proof public inputs before circuit work.
2. **Specialized proof experiment:** prove 8–32 headers with a selected SNARK, including all required rule constraints; independently verify proof outputs and measure RAM/constraints/time.
3. **Composition:** four independently proven 32-header segments whose entire boundaries match, with separately authenticated start state. *Four matching declarations alone are not four proofs.*
4. **PQ/STARK track:** independent soundness and transcript/recursion analysis. A classical SNARK inside a STARK does not automatically inherit post-quantum security.
5. **Operational/cost comparison:** measure actual per-shard peak RSS and aggregate throughput against the distinct Raito SSD spill trial. Never infer a memory win from the 28 GiB Raito OOM alone.

Until the independent cryptographic and chain checks exist, every candidate remains **UNVERIFIED**. Keep parent PR #1 draft, SSD experiments separate, and no changes to the existing `verified_raito` authority.
