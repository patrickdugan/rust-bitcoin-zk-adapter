# Plan: cheap Bitcoin proof backends for the adapter (2026-10-28)

> **Status (2026-10-28 night):** steps 1–4 are done and step 5 is open.
> Proving stays off the gateway: clients submit small bundles to
> `zk.statement.verify` (`docs/BITCOIN_STATEMENTS.md`) instead of the job
> queue.
>
> The payment verifier checks the Groth16 wrap (709-byte bundle, 0.28 s), not
> the 1.27 MB compressed proof, because the gateway's RPC body limit is
> 64 KiB.
>
> Both verifiers live in `integrations/`, with real mainnet fixtures, and run
> end to end in CI (`.github/workflows/bitcoin-statements.yml`).
>
> Added the same night:
> - `nova_spv_payment_v1`: a payment proved with no SP1 at all, from two
>   chained Nova proofs plus SPV, in about 3 laptop-minutes;
> - Core-attested `unspent_at_lookup`;
> - a lower-bound `zk.statement.balance`.

Goal: header-chain and payment proofs that run on commodity hardware, plugged
into the existing dispatcher. Each backend follows the dispatcher's pattern:

- an isolated producer broker;
- an isolated, pinned verifier broker;
- a typed receipt;
- Bitcoin Core active-chain checks on publication and retrieval.

## Why these two (measured on the 8-vCPU / 31 GiB `zk` VPS)

| Backend | Per header | Peak memory | Output |
| --- | --- | --- | --- |
| Nova folding (`btc-header-fold`) | 0.146 s, flat over 10,000 headers | 1.4 GB | one 13 KB compressed proof; verify 2.1 s |
| SP1 6.9.0 (Raito-Scrypt `research/bitcoin-bitvm`) | ~0.9 s | 18–22 GB per stage (4-segment aggregate 22.4 GB) | payment statement; Groth16 356 B for BitVM |
| Cairo/STWO (reference only) | ~0.39 s | 26.75 GB per 256-header proof | two-proof aggregation OOM at 28 GB |
| Raito upstream (reference only) | — | recursive batch over 45 GiB | — |

**Cairo/STWO and Raito stay as references; they are not shipped backends.**

## Backends

### 1. `nova_header_chain_v1`: checkpointed header-chain proof

**Status: cheapest; target for the first authentic receipt.**

- **Producer:** `btc-header-fold` prove, with k headers per fold from an
  authenticated checkpoint state.
- **Verifier:** a new `btc-header-fold verify` command that loads the
  compressed proof and the pinned verifier key, then emits the receipt.
- **Receipt fields:**
  - `statement` = "btc_header_chain_v1"
  - `verifier` = nova-snark version + vk digest
  - checkpoint state digest (its 17 public values)
  - end height, tip hash and chainwork
  - header count
  - proof sha256
- **Gateway checks:**
  - the checkpoint matches an operator-pinned checkpoint;
  - Core's `getblockhash(end height)` equals the tip hash on publication
    and on retrieval;
  - the chainwork is at least a configured floor.
- **Small enough to verify in CI:** a 100-header compressed proof and its
  key, each a few tens of KB. That gives the first real-proof acceptance
  test in CI, as opposed to synthetic bytes.

### 2. `sp1_btc_payment_v1`: payment inclusion under a proven header chain

**Status: already works end to end, including BitVM.**

- **Producer:** the SP1 host bins (`chain-prove`, `chain-agg-prove`,
  `node-prove`, `pay-build`, `pay-prove`, optionally `pay-wrap`).
- **Verifier:** `pay-verify`, with pins for the pay, node, leaf and segment
  vkeys, plus the Groth16 check through `sp1-verifier`.
- **Receipt:** the 349-byte `LIGHTO-BTC-PAYMENT-v1` statement fields (tip,
  block, txid, vout, value, script hash, confirmations), the pay vkey, and
  the proof sha256.
- **Gateway checks:** Core active-chain placement of both the tip and the
  block, and the statement's txid equals the job's expected TXID.

## Steps (smallest first)

1. Add a `verify` subcommand to `btc-header-fold` that writes receipt JSON.
   Check in a 100-header proof fixture plus its vk.
2. Add `--receipt-json` to `pay-verify`.
3. Adapter, `services/supernode-rpc`:
   - `JobKind::{NovaHeaders, Sp1Payment}`;
   - typed receipts in `verification.rs`;
   - verifier-broker allowlist entries with pinned binary SHA-256s.
4. Tests:
   - Nova: a real-proof accept test, plus tampered proof, wrong checkpoint
     and stale tip.
   - SP1: synthetic tests in CI, and the real proof verified on `zk`.
5. Run the isolation kit (`tools/isolation-acceptance`) against both new
   kinds.

## Not claimed

- **Checkpointed, not genesis:** checkpoint authenticity is an operator
  input.
- **No unspentness:** payment proofs show inclusion only.
- **Unapproved keys:** Nova and SP1 program keys are candidates.
- **No post-quantum soundness:** Nova runs over Pallas/Vesta and Groth16
  over BN254.
