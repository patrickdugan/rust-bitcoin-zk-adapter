# Isolated Raito proof-worker broker (Linux/Unix)

This optional broker runs **under a separate unprivileged Unix UID** from
the gateway. It accepts a single supported backend (`raito`) over a
versioned, length-bounded Unix domain socket; launches an operator-pinned
fetcher; and returns **unverified compressed proof bytes** in 64 KiB chunks.

The gateway alone writes durable `<job_id>.json` records and typed
`verified_raito` receipts. It independently hashes the broker transfer,
revalidates the active chain with Bitcoin Core, and invokes the separately
pinned Cairo/STWO verifier with `dev=false`. No broker response can claim
cryptographic verification.

## Service identities and directory layout

Provision three service ownership domains on Linux:

- `supernode-gateway`: gateway RPC, 0700 artifact and job metadata directories.
- `supernode-fetch`: broker, upstream Raito fetcher and Bitcoin Core cookie
  access, with its own 0700 staging directory.
- `supernode-verify`: independently pinned Raito/STWO verifier and 0700
  proof staging directory, separate from both gateway and fetcher.
- Operator-controlled Unix socket IPC groups connect the gateway to each
  broker separately. Socket parents use mode `0770` and sockets use
  mode `0660`, supplemented by kernel peer-UID checks.

The broker checks that its **peer's kernel UID equals the gateway UID**.
The gateway also checks that the **socket peer's UID equals the configured
broker UID**, which must differ from the gateway's own UID. The broker
daemon will refuse startup when both identities match. The gateway will
refuse startup with a direct worker binary unless the operator sets the
explicit `SUPERNODE_ALLOW_SAME_UID_WORKERS=1` development override.

The broker's staging root and its socket parent must be separate, absolute,
owned by the broker account, and symlink-safe. The gateway's metadata root
must be owned by the gateway account and inaccessible to the broker account.
Workers receive paths only inside their own private broker staging directory.
The broker never receives the gateway's job-directory path.

## Broker configuration

Build the standalone service:

```sh
cargo build --release --manifest-path services/proof-worker-broker/Cargo.toml
```

A broker service should receive the following configuration in a protected
systemd environment file with concrete, operator-selected paths and IDs:

```ini
SUPERNODE_BROKER_SOCKET=/run/supernode-worker/socket/broker.sock
SUPERNODE_BROKER_STAGING_DIR=/var/lib/supernode-worker/staging
SUPERNODE_BROKER_GATEWAY_UID=1234
SUPERNODE_BROKER_RAITO_WORKER=/opt/supernode/bin/rust-bitcoin-raito-fetcher
SUPERNODE_BROKER_RAITO_SHA256=64_LOWERCASE_HEX_OF_FETCHER_EXECUTABLE
SUPERNODE_BROKER_RAITO_FETCH_CONFIG=/etc/supernode/raito-fetcher.json
SUPERNODE_BROKER_WORKERS=1
SUPERNODE_REQUIRE_CGROUP_MAX_MIB=4096
```

The broker environment is accessible only to the broker identity. The
fetcher config must contain a pinned upstream `raito-spv-client` binary, an
operator-selected Raito HTTPS bridge and a readable Bitcoin Core cookie.
Use the actual UID from `id -u supernode-gateway`.

Gateway configuration:

```ini
SUPERNODE_PROOF_BROKER_SOCKET=/run/supernode-worker/socket/broker.sock
SUPERNODE_PROOF_BROKER_UID=1235
SUPERNODE_PROOF_VERIFIER_SOCKET=/run/supernode-verify/socket/verify.sock
SUPERNODE_PROOF_VERIFIER_UID=1236
```

Use `SUPERNODE_PROOF_BROKER_UID` from `id -u supernode-fetch`.
Remove direct gateway `SUPERNODE_RAITO_PROVER`,
`SUPERNODE_SHINIGAMI_PROVER` and
`SUPERNODE_RAITO_FETCH_CONFIG` settings when broker mode is enabled.
Both processes should be started by systemd services with independently
restricted home, runtime and state directories.

Use `MemoryMax`, `MemorySwapMax=0`, `TasksMax`,
`KillMode=control-group` and a **hard filesystem quota or bounded tmpfs**
for broker staging; process-group cleanup and a 64 MiB post-run output check
are separate safeguards. Use the optional cgroup preflight in the fetcher
and verifier to ensure the kernel memory/swap boundary already exists.

## IPC contract and explicit failure behavior

The request is a bounded newline-delimited JSON header followed by
`input_bytes` raw bytes (at most 2 MiB):

```json
{
  "version": 1,
  "job_id": "64-lowercase-hex",
  "backend": "raito",
  "network": "main",
  "block_hash": "64-lowercase-hex",
  "block_height": 900000,
  "policy_sha256": "64-lowercase-hex",
  "expected_txid": "64-lowercase-hex",
  "input_bytes": 300
}
```

The broker returns a framed reply carrying only `ok`, byte length and
SHA-256 digest followed by up to 64 MiB raw bytes. These bytes are always
unverified. The gateway streams them to a new, private output file and
recomputes SHA-256 before recording the result. The existing digest-indexed
result retrieval and independent Raito verifier take over from there.

Requests from the wrong peer UID, unknown backend, unexpected JSON fields,
oversized input, duplicate staging path or bad executable hash fail closed.
A disconnected broker makes the job fail and preserves the error rather
than falling back to same-UID execution. Interrupted jobs remain recorded
as unverified/failed and are not silently replayed.

## Remaining production acceptance

The separate worker UID protects the gateway's metadata from a compromised
proof *fetcher* when the operator enforces OS filesystem permissions.
The optional `services/raito-verifier-broker` now places the pinned
Cairo/STWO verifier under a **third service UID**. Its socket authenticates
the gateway via `SO_PEERCRED`, and its output is checked again before the
gateway promotes any typed receipt. Legacy same-UID execution remains a
development-only mode enabled by an explicit override. See
[the isolated Raito verifier instructions](../raito-verifier-broker/README.md).

Before treating this as production-ready, test actual separate-UID deployment,
symlink/hardlink races, gateway and broker SIGKILL, stale socket cleanup,
worker output quota and process-tree termination. Obtain one genuine Raito
compressed proof from a real Bitcoin Core mainnet host and inspect the typed
verified receipt. Keep Issue #2 open until these gates pass.

## Negative local-identity tests

The CI script additionally connects from the worker/broker UID and checks
that the socket refuses the request even though filesystem group membership
would permit opening it. The kernel peer-credential gate is independent of
the socket's mode bits. The broker returns bounded error frames for malformed
authorized requests while preserving the rule that no broker response may
assert a verified Raito statement.
