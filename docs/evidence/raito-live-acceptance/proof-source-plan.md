# Genuine proof source: findings and costed plan (2026-10-25)

Outcome today: **BLOCKED**. No genuine compressed Raito proof can be fetched,
and producing one requires a proving campaign that this note costs below.
No expensive work was started.

## `zk` VPS preflight (re-measured)

| Item | Value |
| --- | --- |
| Host | `zk`, kernel 7.0.0-38-generic, 8 vCPU, 31.3 GiB RAM, 4 GiB swap (unused) |
| Disk | 199 GB free of 242 GB |
| Workload | idle (load 0.15); no other jobs |
| Service identities | `supernode-gateway` 999, `supernode-fetch` 997, `supernode-verify` 994 (left from the isolation run) |
| Repo checkout | `~/rbzk` at `10abe18`, isolation evidence in `~/rbzk-evidence` |
| Bitcoin Core | none installed or running |
| Genuine proof artifact | none on disk |

## Every upstream proof source is gone

| Source (pinned `48c237a`) | Check | Result |
| --- | --- | --- |
| Bridge `https://api.raito.wtf` (`/chainstate-proof/recent_proof`, MMR block proofs) | DNS | NXDOMAIN |
| GCS bucket `raito-proofs` (`recent_proof`, `recent_proven_height`, written by `scripts/data/build_recent_proof.py`) | HTTPS | `NoSuchBucket` |
| GitHub release `v0.1.0` "Compressed SPV" (2025-11-28) | API | no assets |
| `raito-landing/public/proofs/block_870000_proof.json` | content | placeholder hex, not a proof |

`raito-spv-client fetch` combines three things:

- the recursive **chain-state proof** (`recent_proof`), downloaded from the bridge;
- an MMR inclusion proof for the block, also from the bridge;
- the transaction Merkle proof, from Bitcoin Core.

Only the first part is expensive. The bridge node itself
(`crates/raito-bridge-node`) only indexes headers into an MMR, which is cheap.

## Options, cheapest first

**A. Ask for a retained artifact (about $0, days of waiting).** StarkWare
produced `recent_proof` until the bucket was deleted. One retained file of
roughly tens of MB, plus its proven height, would unblock everything. The
proof's internal transaction and block binding are then checked by the
pinned verifier. Patrick would send the request; nothing was posted.

**B. Local pieces only (cheap, needed for every option).**

- Pruned mainnet Bitcoin Core on `zk`: `prune=20000`, dbcache 16 GB. About
  1–2 days of initial block download, about 35 GB of disk, around 700 GB of
  download traffic. A full archival node (about 750 GB) does not fit in
  199 GB, but the fetch only needs `gettxoutproof` for a recent block, which
  a pruned node can serve.
- `raito-bridge-node` built from `48c237a` against that node, serving MMR
  proofs locally (header indexing only: hours, under 2 GB).
- Cost: about 2 extra VPS days (~$6 at ~$3/day).

**C. Re-prove the chain-state proof from genesis (expensive, uncertain).**
`prove_pow.py` runs the bootloader plus the `assumevalid` program over
header batches and folds them recursively into one proof. Rough numbers from
this project's own header-proving measurements (`chain_segment`):

| Quantity | Estimate |
| --- | --- |
| Header validation | ~81k Cairo steps/header × ~920k headers ≈ 7.5 × 10¹⁰ steps |
| Prover memory | ~3.7 KB/step, so 31 GiB fits ~7M steps per proof |
| Fixed cost per proof | bootloader ~3.9M steps plus in-Cairo verification of the previous STARK (not measured) |
| Throughput | ~100–150k steps/s on 8 cores |

The fixed cost per proof is the main risk. If verifying the previous proof
alone exceeds the remaining ~3M-step budget, one recursive step does not
fit in `zk`'s RAM at all, and a 128–256 GB machine is required.

Even if it fits, each proof covers only a few dozen headers, which means
tens of thousands of recursive steps. That is **weeks** of the `zk` box
(order $50–150), or about **3–7 days** on a 32-core / 256 GB machine
(order $300–1,000 at typical hourly rates). Upstream's own pipeline used
batches of up to 6,000 blocks on larger infrastructure.

Treat these as order-of-magnitude estimates until step C0 below has run.

## Recommended plan

1. **Option A first.** Patrick asks the Raito maintainers (starkware-bitcoin)
   for a retained `recent_proof` and its proven height.
2. **In parallel, option B** (~$6, about 2 days). This is needed for any
   positive run and gives the Core active-chain checks.
3. **C0 calibration** (a few hours, ~$1): build `prove_pow` from `48c237a`
   on `zk` and prove **one** recursive batch at two batch sizes. Measure
   wall time, peak RSS and steps per proof, then replace the estimates in
   option C with measured numbers before committing to C.
4. Run the positive acceptance and negative matrix (`wrong TXID`, block,
   height, policy, one-byte corruption, truncated retrieval) once a genuine
   proof exists. The tooling, pinned verifier (policy
   `18b4cf2dc3686f38978f4543a8bd42616b27caa6a6e0c87ce3c850b337a6664c`) and
   isolated deployment are ready on `zk`.

Decision needed from the operator: approve B (and C0), and whether to send
the request in A.
