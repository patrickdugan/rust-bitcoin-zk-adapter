# nova-header-chain

Imported from the `btc-header-fold` benchmark (local commit e50c76a). It is the prover and the
`btc_header_chain_v1` verifier behind `zk.statement.verify` (see `docs/BITCOIN_STATEMENTS.md`).

- `cargo test --release`: circuit tests on real mainnet headers, plus a real 100-header
  proof that is accepted, with tampered variants rejected.
- On CPUs without ADX (for example, Haswell VPS vCPUs), run `scripts/vendor-nova-noasm.sh` first.

The original benchmark notes follow.

Benchmark question: can a purpose-built Bitcoin header circuit with Nova
folding escape the memory floor that sank the Raito/STWO route? On the
31 GiB `zk` VPS, `raito-assumevalid` was OOM-killed above 28 GiB proving
even one block (fixed ~6.2M Cairo steps per proof). See
`rust-bitcoin-zk-adapter/docs/evidence/raito-live-acceptance/proof-source-plan.md`.

**Short answer: yes.** A 10-header fold step proves in a steady 1.5–1.7 s
with ~1.3 GB peak RSS. That is about 0.16 s and 83k R1CS constraints per
header. The compressed proof of 100 mainnet headers is 13 KB and verifies
in 2 s.

## What one fold step proves

The state is 17 field elements:

- height;
- previous block hash, as two 128-bit halves of its little-endian integer;
- cumulative chainwork;
- the epoch's nBits and the timestamp of the epoch's first block;
- the last 11 timestamps.

For each of the `k` headers in a step, the circuit (`src/lib.rs`) enforces:

- the previous-hash link;
- double SHA-256 of the 80-byte header at or below the target decoded from
  nBits;
- nBits validity: no sign bit, nonzero mantissa, exponent 3..=32, target at
  or below powLimit;
- nBits unchanged inside an epoch;
- at 2016-block boundaries, Core's `CalculateNextWorkRequired` exactly:
  clamp to [T/4, 4T], 256-bit multiply/divide, powLimit cap, and compact
  re-encoding including mantissa normalization;
- median-time-past (at least 6 of the previous 11 timestamps are strictly
  smaller);
- BIP34/66/65 version minimums with Core's signed comparison;
- work = floor(2^256 / (target + 1)), proven as w·(T+1) + R = 2^256 with
  R ≤ T, added to chainwork.

**Not in the proof:**

- the future-time rule (it needs a wall clock);
- best-chain selection (compare chainwork outside);
- targets below 2^128 and exponents below 3, both never seen on mainnet.

Runs start from an **authenticated checkpoint state** (`State::checkpoint`).
Its 17 values are public inputs, and the verifier must check them. This is
checkpointed mode; a genesis start needs a different MTP window
initialization for heights below 11.

The `native` module (`native::State::apply`) implements the
same rules natively and is used for witnesses and cross-checks.

## Tests (all pass)

`cargo test --release` runs 11 tests on real mainnet headers. They use Nova's
`TestConstraintSystem` and assert both satisfaction and the name of the first
failing constraint.

| Test | Result |
| --- | --- |
| Headers 1001–1010 | satisfied; outputs equal the native state |
| Block 2016 boundary | retarget clamped to the powLimit cap, satisfied |
| First real retarget at 32256 (`0x1d00ffff` → `0x1d00d86a`) | satisfied |
| Keeping the old nBits at 32256 | rejected at `retarget` |
| Wrong nBits at 2016 | rejected at `retarget` |
| Flipped nonce | rejected at `pow` |
| Wrong previous hash | rejected at `prev_link` |
| Timestamp equal to MTP | rejected at `mtp` |
| nBits change inside an epoch | rejected at `bits_continuity` |
| Checkpoint epoch above powLimit | rejected |
| Version 1 at the BIP34 height | rejected at `version` |
| Native rules over all headers 11–2100 | accepted; chainwork matches `(h+1)·0x100010001` |

`data/headers_0_2100.bin` comes from the rust-bitcoin `zk-client` fixtures.
`data/retarget.txt` holds headers 30240 and 32240–32300, written by
`scripts/fetch_headers.py`; every header's double SHA-256 was checked
against its block id.

## Results (zk VPS, 2026-10-25)

Host: 8 vCPU "Intel Core Processor (Haswell, no TSX)", 31 GiB RAM, kernel
7.0.0-38. A Litecoin node was syncing at ~100% of one core during all runs.

Engines are Pallas/Vesta with IPA commitments, so there is no trusted setup.
The compressed proof is Spartan `RelaxedR1CSSNARK` with IPA. Each run uses
`/usr/bin/time -v`.

The box lacks ADX, so `halo2curves`' `asm` feature had to be turned off: the
stock build dies with SIGILL. Field arithmetic is therefore the portable
path, slower than on a modern CPU with `asm`.

| Run | Headers | Primary constraints | Setup | Prove | Verify | Peak RSS |
| --- | --- | --- | --- | --- | --- | --- |
| k=1, 1 step | 1 | 97,049 | 5.4 s | 0.16 s | 0.13 s ok | 184 MiB |
| k=1, 1 step, flipped nonce | 1 | 97,049 | 5.3 s | 0.15 s | **REJECTED** (UnSat) | 195 MiB |
| k=1, 2 folds | 2 | 97,049 | 5.3 s | 0.46 s (2nd fold 0.31 s) | 0.26 s ok | 171 MiB |
| k=1, 100 folds | 100 | 97,049 | 5.4 s | 32.4 s (steady 0.325 s/fold) | 0.38 s ok | 293 MiB |
| k=10, 1 step | 10 | 842,330 | 30.1 s | 0.45 s | 0.51 s ok | 1.15 GiB |
| k=10, 10 folds | 100 | 842,330 | 30.0 s | 13.7 s (steady 1.5–1.7 s/fold) | 2.17 s ok | 1.29 GiB |
| ↳ compressed | 100 | — | 3.3 s | 125.4 s | 2.07 s ok, **12,976 B** | 2.49 GiB |
| k=100, 1 step | 100 | 8,295,140 | 244 s | 3.9 s (base step only) | 4.53 s ok | 10.7 GiB |
| k=10 across the 32256 retarget | 10 | 842,330 | 28.6 s | 0.47 s | 0.53 s ok | 1.18 GiB |

All proving runs had `outputs_match=true`: the recursive SNARK's final
state equals the native validator's.

Constraints per header: 82,809 marginal (`(c(k=10) − c(k=1)) / 9`). About
three quarters of that is the three SHA-256 compressions; Nova's augmented
circuit adds ~13k per step. The first fold step (`prove_step 0`) is a
no-op; its witness work happens in `RecursiveSNARK::new`. Steady-state
numbers are therefore taken from steps 1+.

### Stwo baseline on the same box

The baseline is `chain_segment` from rust-bitcoin `zk-client` (`9f9ec86a`),
proved directly with Stwo: no bootloader, k=20 bounded preprocessed trace.
`zk-sync` was rebuilt on `zk` with `-C target-cpu=native` (AVX2).

| Run | Cairo steps | Prove | Peak RSS | Proof |
| --- | --- | --- | --- | --- |
| 1 header | 83,342 | 12.0 s | 2.1 GiB | 15.0 MB |
| 8 headers | 649,554 | 18.5 s | 2.6 GiB | 14.9 MB |
| 4 × 8 headers | ~653k each | 14.2–17.4 s per segment | 2.7 GiB | 4 × ~15 MB |
| verify 4 segments | — | 0.65 s total (0.12 s STARK) | 36 MiB | — |

Per header that is about 1.9 s at 8 headers per segment. There is no
recursion: the light client verifies every segment proof, so a full chain
would be ~115k proofs and ~1.7 TB.

`chain_segment` also maintains Raito's block-hash MMR and a Blake2s
chain-state digest (an SPV accumulator), which this Nova circuit does not.
The statements are close but not identical.

| Per header, same box | Nova k=10 (this repo) | Stwo `chain_segment` (8/segment) | Raito `assumevalid` (stock Stwo) |
| --- | --- | --- | --- |
| Prove time | 0.16 s | ~1.9 s | OOM above 28 GiB at 1 block |
| Peak RSS | 1.3 GiB (2.5 GiB compressing) | 2.7 GiB | > 28 GiB |
| Final artifact | one 13 KB proof (any length) | 15 MB per 8 headers | — |
| Verify | 2.1 s (compressed) | ~0.03 s per segment | — |


## Go / no-go

**Go: folding escapes the memory floor.**

| Approach | Memory | Speed |
| --- | --- | --- |
| Raito `assumevalid` (Cairo VM + bootloader + full STWO preprocessed trace) | over 28 GiB for one block | — |
| This circuit, k=10 | ~1.3 GiB, flat in the number of folds | 0.16 s/header |
| This circuit, k=1 | ~0.3 GiB | 0.33 s/header |

Peak memory scales with headers per step (k), not with chain length.

Full-chain projection, untested: 920k headers × 0.16 s ≈ 41 hours on this
8-vCPU box at k=10, then a ~2-minute compression to a 13 KB proof. The
per-fold time drifted from 0.85 s to ~1.7 s over the first 5 folds and then
held steady. A long run should confirm that it stays flat.

Caveats:

- Not compatible with Raito's verifier. It is a separate proof system and
  statement, so it does not satisfy PR #1's Raito acceptance gate.
- Nova recursion is not audited here. Its soundness relies on the standard
  folding and Fiat-Shamir assumptions, and the compressed verifier is
  Spartan with IPA (2 s verify). HyperKZG over BN254 would verify faster
  but needs a ptau ceremony file.
- The proof is checkpointed and starts at height 1000. The checkpoint state
  is a trust input until a genesis-start run exists.
- The SHA-256 gadget is Nova's bellman-style gadget. Lookup-based or
  custom-gate SHA would cut the 83k constraints, so this is a conservative
  baseline.

## Reproduce

```sh
scripts/vendor-nova-noasm.sh        # as measured; required on CPUs without ADX
python3 scripts/fetch_headers.py    # only if data/retarget.txt is missing
cargo test --release
cargo run --release -- --start 1000 --k 10 --steps 10 --compress
```

`Cargo.toml` patches `nova-snark` to `vendor/nova-snark`, which is the
crate with `"asm"` removed from its x86_64 `halo2curves` features. Run the
script before the first build.

Raw outputs are in `results/` (`runs.log` has the `/usr/bin/time -v` peak
RSS and wall times). The first Stwo attempt in `runs.log` used a
laptop-built `zk-sync` (AVX-512) and died with SIGILL; the `stwo2_*` runs
are the rebuilt binary.

## Typed receipt (`verify`), 2026-10-28

Run `btc-header-fold --start H --k K --steps N --compress --save DIR` to
write `proof.bin`, `z0.bin` (the 17 checkpoint field elements), `steps.txt`
and `k.txt`. Then `btc-header-fold verify DIR` prints a
`btc_header_chain_v1` receipt. It gives the checkpoint and end height, tip
hash and chainwork, the header count, and the SHA-256 of the proof, the
checkpoint state and the verifier key. It exits 1 on rejection.

The verifier key is 257 MB, almost all IPA generators. It is a deterministic
function of the circuit shape, so `verify` rebuilds it when `vk.bin` is
absent. The rebuilt key matched the saved one's SHA-256
(`e46bb069…1698`), and integrators pin that hash.

`fixtures/nova100/` holds heights 1,001–1,100 from checkpoint 1,000, in
13.5 KB. Verification takes 81 s and 1.3 GB including the key rebuild; with
a cached key it takes 4.9 s. A flipped proof byte, an altered checkpoint and
a wrong step count are each rejected.
