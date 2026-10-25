# Isolated Raito STARK verifier service

The optional verifier daemon keeps Cairo/STWO proof parsing outside the
Supernode RPC gateway's Unix identity. It receives compressed SPV proof bytes
over authenticated, bounded Unix IPC, calls the operator-pinned Raito verifier
with development mode disabled, checks the resulting typed statement, and
returns a **receipt only after successful verification**.

The proof-producing broker runs under a third Unix identity. Bitcoin Core
remains responsible for validating and selecting the active chain. The
gateway checks active-chain membership before and after verification, and
again each time it serves the durable receipt.

## Three separate service identities

Provision distinct unprivileged accounts such as `supernode-gateway`,
`supernode-fetch` and `supernode-verify`. The verifier checks all three UIDs
are different and refuses to run as root. The gateway checks the verifier
socket's kernel peer UID, and the verifier daemon checks the gateway UID.
The producer can neither write trusted job metadata nor call the verifier
socket as the gateway.

Give the verifier a private staging root, for example
`/var/lib/supernode-verify/staging`, owned by the verifier UID with mode
`0700`. Place the Unix socket under a separate directory owned by the
verifier UID and a dedicated gateway/verifier IPC group, with directory mode
`0770`. The socket is created with mode `0660`.

The gateway's `SUPERNODE_JOB_DIR` must remain `0700` and owned by the
gateway identity; neither producer nor verifier should have access. Keep the
compiled `raito-verify` binary root-owned, outside worker-writable paths,
and mounted read-only to the verifier service. A SHA-256 pin alone does not
prevent execution-time substitution if the verifier UID can replace the
binary between checking and spawning it.

## Build and service settings

```sh
cargo build --release --manifest-path services/raito-verifier-broker/Cargo.toml
cargo +nightly-2025-07-14 build --release --manifest-path integrations/raito/Cargo.toml
```

Set these in the **verifier service**, using real absolute paths and UIDs:

```ini
SUPERNODE_VERIFY_SOCKET=/run/supernode-verify/socket/verify.sock
SUPERNODE_VERIFY_STAGING_DIR=/var/lib/supernode-verify/staging
SUPERNODE_VERIFY_GATEWAY_UID=1234
SUPERNODE_VERIFY_PRODUCER_UID=1235
SUPERNODE_VERIFY_BINARY=/opt/supernode/bin/raito-verify
SUPERNODE_VERIFY_BINARY_SHA256=64_LOWERCASE_SHA256_OF_Raito_BINARY
SUPERNODE_VERIFY_WORKERS=1
SUPERNODE_REQUIRE_CGROUP_MAX_MIB=4096
```

Set these in the **gateway service**, in addition to the Bitcoin Core RPC
credentials, distinct read/control tokens, job and artifact directories and
the proof-producer broker configuration:

```ini
SUPERNODE_PROOF_VERIFIER_SOCKET=/run/supernode-verify/socket/verify.sock
SUPERNODE_PROOF_VERIFIER_UID=1236
SUPERNODE_PROOF_BROKER_SOCKET=/run/supernode-worker/socket/broker.sock
SUPERNODE_PROOF_BROKER_UID=1235
```

In isolated mode, remove `SUPERNODE_RAITO_VERIFIER` and
`SUPERNODE_RAITO_VERIFIER_SHA256` from the gateway environment. The
verifier identity, rather than the gateway, owns the pin and executable.
The gateway's `SUPERNODE_ALLOW_SAME_UID_VERIFIER=1` switch is a
development-only override for the legacy direct-verifier path.

The verifier daemon expects a Unix socket parent that already exists. Use
systemd-managed runtime directories to remove stale sockets after service
shutdown. Keep verifier and producer staging in separate filesystems or
OS-enforced private directories.

## Runtime isolation

The verifier daemon launches each pinned Raito executable into a new
process group; its cleanup handler terminates the group on normal exit,
failure, timeout and cancellation. Run it under an OS service cgroup with
`KillMode=control-group` so descendants are also killed if the daemon itself
is terminated abruptly. Configure hard `MemoryMax`,
`MemorySwapMax=0`, `TasksMax`, and a bounded staging filesystem or
filesystem quota. The optional cgroup-v2 preflight checks an existing
kernel memory/swap boundary but does not create one.

The input limit is 16 MiB compressed, with a 4 KiB JSON request header and
fixed 64 KiB upload chunks. Receipt output is capped at 4 KiB.
`MAX_VERIFIER_TIME` is 600 seconds, and each IPC read has a 30-second
idle timeout. Hard staging filesystem limits must apply **while proofs are
being transferred and verified**.

## Verification semantics

The verifier daemon independently SHA-256-checks the exact uploaded bytes
against the authenticated request, invokes the pinned upstream
`raito-verify --gateway` binary, and checks the generated receipt's TXID,
block hash/height, policy digest and proof digest. The gateway repeats
those checks before moving a durable job to `verified_raito`.

A receipt supports the Raito SPV transaction-inclusion statement under
the selected pinned policy. Bitcoin Core's active-chain selection, full
Bitcoin consensus execution and application-specific Ark/TradeLayer
invariants have separate guarantees.

## Acceptance tests

```sh
cargo test --manifest-path services/raito-verifier-broker/Cargo.toml
cargo clippy --manifest-path services/raito-verifier-broker/Cargo.toml --all-targets -- -D warnings
bash services/raito-verifier-broker/test-separated-uids.sh
```

The Linux CI test uses a **synthetic mock verifier** to check Unix peer
credentials, metadata isolation, input hashes, malformed-network rejection,
and receipt-field binding. It does not claim STARK cryptographic validity.
Actual Raito acceptance requires a genuine compressed proof, pinned upstream
binary, and running Bitcoin Core mainnet node. Collect proof latency, peak
resident memory, disk I/O and retry/reorg behavior before promoting the
parent PR to production.
