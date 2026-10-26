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

## Results of B and C0 (run 2026-10-25 on `zk`, approved)

**B: running.**

- Bitcoin Core 31.1 (tarball checked against `SHA256SUMS`; signatures not
  checked). Digests: `bitcoind` `986e63b3…8a08`, `bitcoin-cli` `4e3a0fde…6034`.
- Runs as the systemd unit `bitcoind-main` with `prune=20000`,
  `dbcache=12000`, `blocksonly=1` and loopback RPC. All 960,000 headers
  arrived within minutes; block validation is in progress.
- `raito-bridge-node` runs as `raito-bridge` on `127.0.0.1:5000`, indexing
  blocks into the MMR behind Core's tip.

**Building the pinned tools needed two lockfile fixes.** Raito at `48c237a`
does not commit a `Cargo.lock`, and a fresh resolve no longer builds on the
pinned toolchain:

- `google-cloud-*` 1.18 requires rustc 1.91. Fixed by regenerating the
  lockfile with `CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback`.
- `ruint` 1.21.1 uses a const fn that is not yet stable. Fixed by
  `cargo update -p ruint --precise 1.17.0`.

Results, built with `nightly-2025-07-14 --locked --release`:

| Item | Value |
| --- | --- |
| Build | 7 min 57 s, 3.1 GB peak |
| `raito-assumevalid` | `c5b4ad25140f63659e9a6e4790c0f695cfa96f52f879a2a296ce2988a96ba0d0` |
| `raito-bridge-node` | `c780b977303d29582430f43492615f9984b0fcd8592c8eb643a7e6448512d0f4` |
| Generated `Cargo.lock` | `ba64309693ce745a50b070556146eb8ad0ee0ca7f8fb6dcba219ad8793c122c2` |

**C0: measured.** `raito-assumevalid prove` from genesis, stock prover,
under a transient unit with `MemoryMax=28G` and `MemorySwapMax=0`:

| Batch | Cairo steps | VM | Adapt | Prover |
| --- | --- | --- | --- | --- |
| 1 block (0–1) | 6,242,367 | 8.1 s | 2.5 s | **OOM-killed at 28 GiB** after ~55 s |
| 10 blocks (0–10) | 6,324,042 | 8.2 s | 16.6 s | **OOM-killed at 28 GiB** after ~4.5 min |

What this shows:

- **The marginal cost is ~9k steps per header.** That is far below the
  81k-step `chain_segment` figure used in the estimate above.
- **The cost is dominated by a fixed ~6.2M-step floor per proof**
  (bootloader plus program).
- **Even the first, non-recursive proof does not fit in 28 GiB on `zk`.**
  The stock preprocessed trace plus a 2²³-row trace exceed it. A bounded
  preprocessed trace would change what the pinned `dev=false` verifier
  expects, so it is not an option for acceptance. **Option C is BLOCKED
  on `zk`.**

Revised estimate for C on a larger machine: 920k headers × ~9k steps ≈
8.3 × 10⁹ marginal steps. With batches of a few thousand blocks, that is
about 150–300 recursive proofs. The size of each recursive (previous-proof
verification) step is still unmeasured; it is the next calibration, and it
needs a machine with **≥128 GB RAM**. Rough cost: 1–2 days on a 32–64 core,
256 GB machine, order **$100–400** (estimate, not measured).

**Next steps:**

1. Keep B running until Core reaches the tip. It is needed for any positive
   run.
2. Pursue option A (ask the Raito maintainers for a retained `recent_proof`).
3. If C is wanted, provision a ≥128 GB machine and re-run C0 with two
   batches to measure the recursive step before committing to the full chain.

## C0 with swap (2026-10-26 23:40 UTC, `zk`, Raito `48c237a` tools as above)

**Setup changes since the first run:**

- Bitcoin Core had been removed from `zk`, and Raito's documented public RPC
  (`bitcoin-mainnet.public.blastapi.io`) now answers "Blast API is no longer
  available". So the bridge read headers 0–2100 from a minimal Core-RPC
  stand-in (`getblockcount`, `getblockhash`, `getblockheader`). The stand-in
  serves the genuine mainnet headers from rust-bitcoin's `zk` fixtures; it
  checks their hash links and the genesis hash at startup.
- The bridge's real flag is `--db-path` (its README still says
  `--mmr-db-path`). Its JSON-RPC client rejects responses carrying
  `"error": null`.
- `litecoind-main` was stopped for the run and restarted afterwards.
- Each batch ran as a transient unit with `MemoryMax=29G`,
  `MemorySwapMax=16G`, using `raito-assumevalid prove --total-blocks 1
  --step-size 1`.

| Batch | Cairo steps | Result | Time | Peak |
| --- | --- | --- | --- | --- |
| 0→1 (from genesis, no recursion) | 6,242,367 | **Proved and self-verified** (`proof.json` 4,917,371 B, SHA-256 `e910eb99…ccff`) | 136 s total (VM 8 s, adapt 2.5 s, prove 126 s) | RSS 30.4 GB plus ~4.7 GB swap |
| 1→2 (verifies batch 0→1 in Cairo) | **25,413,480** | **OOM-killed** at 29 GiB RAM + 16 GiB swap | VM 19 s, adapt 9.6 s, killed ~2 min into proving | ≥ 45 GiB |

**What this shows:**

- Recursion multiplies the per-proof floor about 4×. Verifying the previous
  STARK costs about 19.2M Cairo steps.
- With the first batch at ~35 GB for 6.2M steps, a recursive batch at ~25M
  steps needs very roughly 100–140 GB. That is consistent with the earlier
  "≥128 GB" requirement.
- **Option C stays BLOCKED on `zk`.**
- The non-recursive genesis proof does now fit with swap. It is a genuine
  Raito `assumevalid` chain-state proof for block 1, but not a compressed SPV
  proof of a transaction, so it does not count toward the PR #1 positive
  gate.

Artifacts on `zk`: `~/c1` (logs, memory samples, both batch directories),
`~/hdrcore.py` (the stand-in), `~/zk_c1.sh` (the run script).
