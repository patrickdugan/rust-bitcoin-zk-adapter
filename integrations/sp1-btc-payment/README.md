# sp1-btc-payment

`btc-pay-verify` checks the SP1 Groth16 (BN254) proof of a Bitcoin payment's
inclusion and prints a `btc_payment_v1` receipt. It is the verifier behind
`zk.statement.verify` for `sp1_btc_payment_v1`; see
`docs/BITCOIN_STATEMENTS.md`.

```
btc-pay-verify pack groth16.proof.hex public_values.hex bundle.bpg1
btc-pay-verify bundle.bpg1 0x<pay program bytes32 key>
```

**What the proof shows.** The proofs come from the payment program on
Raito-Scrypt `research/bitcoin-bitvm`. That program verifies, inside SP1, a
top node proof over a checkpointed Bitcoin header chain:

- SHA256d PoW on every header;
- retargets;
- BIP34/66/65 floors.

It then proves that the transaction is in a block of that chain, using a
Merkle path and parsing segwit transactions.

**Test.** `cargo test --release` verifies the real mainnet fixture and checks
that every statement field and the proof are bound. The fixture is tx
`fd2fdd44…daa6`, output 0, 2,010,000 sats, block 959,984, tip 959,994.
