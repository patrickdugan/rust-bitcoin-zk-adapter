# Isolated statement verifier service

`supernode-statement-verifier-broker` runs the operator-pinned Bitcoin
statement verifiers under their own Unix identity. These are
`btc-header-fold verify-bundle` (Nova header chain, NHC1) and
`btc-pay-verify` (SP1 Groth16 payment, BPG1). The gateway, which holds the
Bitcoin Core credentials, no longer runs them as its own children.

It is a dumb runner. Over a Unix socket it takes a kind
(`nova_header_chain_v1` or `sp1_btc_payment_v1`) and the bundle bytes. It
runs the pinned executable and returns the exit status and at most 8 KiB of
stdout.

The gateway keeps all the judgement:
- it parses the typed receipt;
- it checks the receipt against its own pins (bundle digest, Nova key,
  checkpoints, payment program words);
- it binds every chain claim to Core.

NSP1 payments reach the broker as their two NHC1 parts.

The protocol is `StatementRunRequest` / `StatementRunReply` in
`integrations/worker-broker-protocol`. Each message is a JSON header line,
followed by the raw bundle bytes or the raw stdout bytes.

## What it enforces

- **Peer identity.** It checks the kernel peer UID of every connection
  against `SUPERNODE_STATEMENT_VERIFY_GATEWAY_UID`.
- **Its own identity.** It refuses root, and refuses a UID equal to the
  gateway's.
- **Pinned files.** Each binary is SHA-256 pinned, checked at startup and
  again before every run. The Nova verifier key is pinned too, and checked at
  startup.
- **The bundle.** Its SHA-256 must match the request header, and its size
  is bounded at 32 KiB.
- **Staging.** Each run gets a private `0700` directory under the staging
  root, which must be owned by the broker UID. Leftovers are removed at
  startup.
- **Process lifetime.** Each run has its own process group. The group is
  killed and reaped on timeout (300 s), on gateway disconnect, or on
  trailing bytes from the gateway.
- **Concurrency.** An admission semaphore allows
  `SUPERNODE_STATEMENT_VERIFY_WORKERS` runs at once (1 to 4, default 1).

The gateway client (`services/supernode-rpc/src/statement_broker.rs`) checks
that the socket's peer UID is `SUPERNODE_STATEMENT_VERIFIER_UID` before it
sends a byte.

Configuration and the sample unit are in `docs/BITCOIN_STATEMENTS.md` and
`deploy/systemd/supernode-statement-verifier.service`.

## Tests

```sh
cargo test --manifest-path services/statement-verifier-broker/Cargo.toml
# Real verifiers, real fixtures, a fresh system user (needs sudo):
bash services/statement-verifier-broker/test-separated-uids.sh \
  <btc-header-fold> <btc-pay-verify> <nova_vk.bin>
```
