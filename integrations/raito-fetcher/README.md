# Raito proof fetch worker

This optional Rust executable connects the Supernode's durable jobs to the
upstream `raito-spv-client fetch` CLI. It downloads a real bzip2-compressed
Raito SPV proof through an operator-selected Raito bridge and a local archival
Bitcoin Core node. It **does not verify the proof**. Verification remains
isolated in `integrations/raito`, pinned to the upstream Cairo/STWO code and
the requested Bitcoin block and TXID.

## Build and install

```sh
cargo build --release --manifest-path integrations/raito-fetcher/Cargo.toml
# Build upstream raito-spv-client at the same audited revision used by the verifier.
cargo +nightly-2025-07-14 install --git https://github.com/starkware-bitcoin/raito \
  --rev 48c237ac941d8061a857ecd111d7e81107912556 raito-spv-client
```

Prepare a 0600 operator configuration at an absolute path:

```json
{
  "client_binary": "/opt/raito/bin/raito-spv-client",
  "client_sha256": "REPLACE_WITH_SHA256_OF_PINNED_BINARY",
  "bitcoin_rpc_url": "http://127.0.0.1:8332",
  "bitcoin_rpc_cookie_file": "/home/bitcoin/.bitcoin/.cookie",
  "raito_bridge_url": "https://api.raito.wtf"
}
```

Only the absolute, operator-owned config path is forwarded to the worker via
`SUPERNODE_RAITO_FETCH_CONFIG`. Bitcoin Core credentials are read from the
local cookie and passed to the upstream client via its `USERPWD` environment,
rather than placing passwords in process arguments.

## Input artifact and submission

Stage a small JSON file as an authenticated `zk.artifact.put` input under the
kind `raito_fetch_request`, bound to the chosen Bitcoin network, active block
hash and block height. The blob itself must contain:

```json
{
  "schema": "raito_fetch_request_v1",
  "network": "main",
  "txid": "ACTUAL_CONFIRMED_TXID",
  "block_hash": "ACTUAL_ACTIVE_BLOCK_HASH",
  "block_height": 900000
}
```

Upload the UTF-8 bytes as hex in `zk.artifact.put [height,blockhash,
"raito_fetch_request",hexdata]`, then submit
`zk.proof.submit ["raito", artifact_id, memory_mib, policy_sha256,
expected_txid]`. The gateway checks Core active-chain membership at
submission. The fetch worker separately matches the staged manifest to the
job's TXID, height and block hash, and rejects `regtest`, `test`, and
`signet` under the pinned mainnet Raito policy.

Set `SUPERNODE_RAITO_PROVER` to the absolute executable path of this fetcher,
`SUPERNODE_RAITO_VERIFIER` to the separate heavy Raito verifier, and
`SUPERNODE_RAITO_VERIFIER_SHA256` to its operator-approved SHA-256.
Use `raito-verify --policy-sha256` to compute the policy hash supplied
to `zk.proof.submit`.

The fetcher invokes the pinned Raito client without its `--verify` flag.
The dispatcher reports `completed_unverified` until the heavy external Raito
verifier accepts the exact compressed bytes and publishes `verified_raito`.
A successful HTTP fetch or exit status has no STARK validity meaning.

## Runtime limits and deployment

Config files and cookies must be regular files, with a 0600 configuration
file on Unix. The upstream CLI binary is checked against its SHA-256 pin;
the Raito bridge must use HTTPS and Bitcoin Core RPC must be loopback.
Request manifests are capped at 4 KiB and compressed outputs at 16 MiB.
The worker's own timeout is 540 seconds, leaving room under the gateway's
600-second limit. Both limits are wall-clock watchdogs.

**Before production**, run the gateway, fetcher (including its upstream
child process), and STARK verifier under separate OS cgroups or equivalent
container memory/process/disk quotas. A watchdog that kills a wrapper
process need not kill its descendants. The existing job scheduler's MiB
reservation is admission accounting and the 256 MiB retention cap applies
only after execution. Raito upstream itself still labels the technology
experimental.

### Linux memory and swap preflight

Set `SUPERNODE_REQUIRE_CGROUP_MAX_MIB=4096` on the gateway if an operator
has already installed a **cgroup v2** memory limit for the worker processes.
The gateway forwards this value to the separately compiled Raito fetcher and
verifier, which both fail closed if their effective inherited cgroup ancestry
does not expose a finite `memory.max` at or below that budget together with
`memory.swap.max=0`. The verifier performs the check before decoding any
proof.

This check verifies an existing Linux kernel boundary. It does not create
cgroups, move processes, or provide worker isolation by itself. Configure
a systemd scope or container cgroup with a limit encompassing descendants of
the Raito fetch client and STARK verifier. An unset environment variable
keeps compatibility with development and CI; production must use explicit
hard limits. The gateway capability response continues to state that a
hard OS memory limit is not enforced by the gateway itself.
