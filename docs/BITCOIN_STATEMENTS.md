# Bitcoin statement proofs: `zk.statement.verify`

The gateway accepts two kinds of client-submitted Bitcoin proofs. Proving
happens elsewhere (see "Producing proofs"); the gateway only verifies.

| Kind | Statement | Bundle | Verifier | Verify cost (measured) |
| --- | --- | --- | --- | --- |
| `nova_header_chain_v1` | headers from a pinned checkpoint to an end tip, with height, hash and chainwork | NHC1, about 13.5 KB for 100 headers | `btc-header-fold verify-bundle` (`integrations/nova-header-chain`) | 2–5 s plus loading the 257 MB verifier key (a few seconds on Linux, about 40 s on Windows) |
| `sp1_btc_payment_v1` | output `txid:vout` with value and script hash, included in block B, under a proven header chain to tip T | BPG1, 709 bytes | `btc-pay-verify` (`integrations/sp1-btc-payment`) | 0.28 s; the binary is 441 KB |

## Request

```
zk.statement.verify [kind, bundle_hex, expected_txid?, expected_vout?]
```

- Requires the **control** token. A Nova check loads a large key, and only
  one verification runs at a time.
- `expected_txid` and `expected_vout` apply to payments only.

A receipt is returned only when all of the following hold:

1. **Pinned executable.** The verifier executable matches its operator SHA-256
   pin; this is re-hashed before every run.
2. **Executable accepts.** It accepts the bundle and exits 0.
3. **Receipt binds the inputs.** Its typed receipt (`deny_unknown_fields`)
   binds:
   - the submitted bytes (proof and statement SHA-256);
   - the pinned keys:
     - Nova: the verifier-key SHA-256 and a pinned checkpoint-state digest;
     - payments: the payment program key, plus the node, leaf and segment
       program words committed in the statement.
4. **Bitcoin Core agrees at lookup.**
   - For every proven point, `getblockhash(height)` equals the proven hash.
   - For each chain tip, `getblockheader(hash).chainwork` equals the proven
     chainwork.
   - For payments, the block hash must also match, and so must
     `expected_txid` and `expected_vout` when given.

**Unspentness at lookup.** For a payment, the gateway also asks Core for
`gettxout(txid, vout, include_mempool=true)` and reports it as
`unspent_at_lookup`:

- When Core reports the output unspent, its value and script must equal the
  proven ones, or the request fails (-32054).
- This is Core's view, not a proof.

## Balance (lower bound)

```
zk.statement.balance [[bundle_hex, ...]]   # 1–32 payment bundles to one script
```

**What it does.** Each bundle is verified and bound as above. The result
gives:

- `proven_received_sats`;
- `proven_and_unspent_at_lookup_sats`;
- one entry per output.

**Rejected inputs.** Mixed scripts and duplicate outpoints are refused.

**Why it is only a lower bound.** Inclusion proofs cannot show that no
*other* outputs to the script exist. Proving unspentness in zero knowledge
would mean checking every input of every later block against an accumulator
(Utreexo-style). That is block-validation cost, the regime where Raito's
recursive batch needed more than 45 GiB. The cheap route is therefore:

- proven inclusion;
- Core-attested unspentness;
- an explicit not-claimed list.

A full balance proof would need a UTXO-set commitment proven per block. That
is out of reach on the measured hardware; it is listed under "Next".

Error codes:

| Code | Meaning |
| --- | --- |
| -32053 | rejected by the verifier, or receipt binding failed |
| -32050 | not on the active chain |
| -32051 | chainwork mismatch |
| -32052 | wrong expected output |
| -32054 | Core's unspent output differs from the proven one |
| -32002 | control token required |

## Operator configuration

```
SUPERNODE_STATEMENT_DIR=/var/lib/supernode/statements   # absolute; needs SUPERNODE_CONTROL_TOKEN

SUPERNODE_NOVA_VERIFIER=/opt/zk/btc-header-fold
SUPERNODE_NOVA_VERIFIER_SHA256=<sha256 of that binary>
SUPERNODE_NOVA_VK=/opt/zk/nova_vk_k10.bin                # btc-header-fold vk-export 10 OUT
SUPERNODE_NOVA_VK_SHA256=e46bb06929d701f1986d320e004e8ed744b0e5f74eb9f5e9c9bd0e2fe6ad1698
SUPERNODE_NOVA_CHECKPOINTS=<checkpoint_state_sha256>[,<...>]

SUPERNODE_PAYMENT_VERIFIER=/opt/zk/btc-pay-verify
SUPERNODE_PAYMENT_VERIFIER_SHA256=<sha256 of that binary>
SUPERNODE_PAYMENT_PAY_VKEY=0x00de861a80542b3089fed26b37ac4e1f4bb8664dcddadb3a6de5ae7205751e75
SUPERNODE_PAYMENT_PROGRAM_WORDS=<node>,<leaf>,<segment>
```

**Verifier key.** It is a deterministic function of the circuit shape. Linux
and Windows builds produce the same SHA-256 (`e46bb069…1698` for fold width
10). CI checks the pin.

**Program words.** These are the three 32-byte words at statement offsets
32, 64 and 96. For the candidate keys from the demo run:

```
a95b1a6090a64052fb6c2c12a0c5c861843a8b04b68e2218f77c9c4693510d76,
12c6f307aff4045af93b5a1d0221eb303955312728625960efa42d592e843701,
99dedc0b1be5794d932fb94e6d90030e663383572f25bb5161e7347ab0fc4550
```

## Producing proofs

**Header chain.** Run:

```
btc-header-fold --data DIR --start H --k 10 --steps N --compress --save OUT
btc-header-fold pack OUT bundle.nhc1
```

- This takes 0.146 s per header and 1.4 GB peak, flat over 10,000 headers on
  the 8-vCPU `zk` VPS.
- `--start` must be an operator-pinned checkpoint. The receipt reports its
  `checkpoint_state_sha256`.
- For a checkpoint at any height, pass `--checkpoint-state FILE` (the
  128-byte SP1 chain start state) and `--headers-txt FILE` (lines of
  `height hex`).

**Payment.** Use the SP1 host bins on Raito-Scrypt `research/bitcoin-bitvm`:

1. `chain-segment`, then `chain-prove` per 252-header segment;
2. `chain-agg-prove`;
3. `node-prove`;
4. `pay-build`;
5. `pay-wrap`, which produces the Groth16 proof.

Then run `btc-pay-verify pack groth16.proof.hex public_values.hex bundle.bpg1`.

- Stages take about 4 minutes each, at 18–22 GB peak.
- The Groth16 wrap takes 15 minutes and needs Docker.
- `pay-verify ... RECEIPT_JSON` checks the compressed (pre-wrap) proof against
  the same pins and writes the same receipt fields.

## Fixtures (real mainnet proofs)

**`integrations/nova-header-chain/fixtures/nova100.nhc1`**

- Covers heights 1,001–1,100 from checkpoint 1,000.
- End tip `000000009cd3…eb4b`, chainwork `0x44d044d044d`.

**`integrations/nova-header-chain/fixtures/tip959994.nhc1`**

- Covers 1,000 current-difficulty headers, 958,994 → 959,994.
- Built on a laptop: 76 s to fold, 27 s to compress, 0.076 s per header.
- Same verifier key; 842k R1CS constraints per 10-header step.
- Checkpoint: the SP1 start state at 958,986
  (`fixtures/checkpoint_958986.state`, chainwork from Core), advanced
  natively by 8 headers.
- Its end tip hash and chainwork equal the payment proof's tip. The gateway
  test `modern_header_chain_proof_ends_at_the_payment_proof_tip` checks this.

**`integrations/sp1-btc-payment/fixtures/payment.bpg1`**

- tx `fd2fdd44…daa6`, output 0, value 2,010,000 sats.
- Block 959,984; tip 959,994 (11 confirmations).
- The checkpoint is 958,986: four 252-header segments → leaf aggregate →
  node → payment → Groth16.

## Not claimed

- **Checkpoints.** They are operator-pinned, not proven from genesis.
- **Unspentness.** Proofs show inclusion only. `unspent_at_lookup` is
  Bitcoin Core's view.
- **Balance completeness.** `zk.statement.balance` is a lower bound.
- **Best chain and future time.** Best-chain selection and the future-time
  rule are outside the proof; Core's chainwork equality stands in for them at
  lookup.
- **Key audit.** Program keys are pinned candidates, not audited releases.
- **Post-quantum soundness.** Nova uses Pallas/Vesta; Groth16 uses BN254.

## Next

**Current-tip header proofs.** Extend Nova proofs to the current tip from a
recent pinned checkpoint:

- 1,000 headers fold in about 100–150 s at 1.4 GB, which fits a laptop.
- A long-running prover that keeps its `RecursiveSNARK` could follow the
  tip one 10-header step at a time. This is not built yet.

**Linking header and payment proofs.** Today the gateway checks both kinds
against Core separately. A test shows that they agree on the tip (958,994 →
959,994), but the gateway does not require it.

- Next, accept a payment only under a pinned or just-verified Nova end state.
- Or make the payment program accept a Nova chain proof instead of the SP1
  node proof. That would replace 18–22 GB stages with 1.4 GB folding for the
  chain part.

**Full balances.** A UTXO-set commitment (for example, Utreexo roots) proven
per block, so that non-spending and completeness can be shown. The cost is
roughly full block validation; this is research, not a next step.
