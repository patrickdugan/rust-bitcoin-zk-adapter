# Three-identity Linux deployment templates

These are example systemd units for the **optional isolation mode** of the
rust-bitcoin-zk-adapter Supernode. They need an administrator to create service
identities, install the binaries under read-only ownership, create protected
environment files, and provision bounded staging filesystems before startup.
There is no automatic installer, and these templates should not be installed
unchanged.

The gateway, proof-producing worker broker, and Cairo/STWO verifier run as
`supernode-gateway`, `supernode-fetch`, and `supernode-verify`, respectively.
The optional statement verifier (`supernode-statement-verifier.service`) runs
the Nova and SP1 payment verifiers as a fourth identity,
`supernode-stmt-verify`, with no network and no Core credentials.
`supernode-ipc` is the group used for the two broker sockets. The kernel
peer-UID checks remain mandatory even when socket group access is granted.

The example limits are operator starting points, not measured Raito RAM
requirements. The producer and verifier units use `MemoryMax=4G`,
`MemorySwapMax=0`, `TasksMax=64`, `KillMode=control-group`, and
`NoNewPrivileges=yes`. The gateway has a separate memory budget.

Service settings must match the Rust configuration:

| Service | Required environment paths |
| --- | --- |
| Gateway | `SUPERNODE_JOB_DIR=/var/lib/supernode-gateway/jobs`, `SUPERNODE_ARTIFACT_DIR=/var/lib/supernode-gateway/artifacts`, `SUPERNODE_PROOF_BROKER_SOCKET=/run/supernode-worker/socket/broker.sock`, `SUPERNODE_PROOF_VERIFIER_SOCKET=/run/supernode-verify/socket/verify.sock` |
| Producer | `SUPERNODE_BROKER_STAGING_DIR=/var/lib/supernode-worker/staging`, `SUPERNODE_BROKER_SOCKET=/run/supernode-worker/socket/broker.sock` |
| Verifier | `SUPERNODE_VERIFY_STAGING_DIR=/var/lib/supernode-verify/staging`, `SUPERNODE_VERIFY_SOCKET=/run/supernode-verify/socket/verify.sock` |
| Statement verifier (optional) | `SUPERNODE_STATEMENT_VERIFY_STAGING_DIR=/var/lib/supernode-stmt-verify/staging`, `SUPERNODE_STATEMENT_VERIFY_SOCKET=/run/supernode-stmt-verify/socket/statements.sock`; the gateway sets `SUPERNODE_STATEMENT_VERIFIER_SOCKET` to the same path and `SUPERNODE_STATEMENT_VERIFIER_UID` (see `docs/BITCOIN_STATEMENTS.md`) |

The gateway must also configure the broker and verifier UIDs (available via
`id -u`) and a read token distinct from the control token. The verifier
environment must configure the separate producer/gateway UIDs and the
operator-pinned Raito executable SHA-256. The broker owns the pinned fetcher configuration and its Bitcoin Core
credential file. Because the producer unit sets `ProtectHome=yes`, place
that credential outside `/home`, in a protected service-readable directory
such as `/etc/supernode/producer-bitcoin-rpc-credential`. The fetcher's
`bitcoin_rpc_cookie_file` field accepts the usual `user:password` format.
For a dedicated RPC identity, configure Bitcoin Core's `rpcauth` policy
accordingly. The gateway's Bitcoin Core RPC credentials must remain private
to the gateway.

**Hard disk quota:** `StateDirectory` supplies ownership and restart-persistent
staging but does **not** give it a hard byte ceiling. Configure an ext4/XFS
project quota, btrfs quota, or separately provisioned bounded tmpfs with the
correct Unix ownership. Both prover and verifier can produce temporary files
before the gateway's retained-output budget applies.

**No root STARK execution:** The verifier daemon rejects root identity and
refuses startup unless its UID differs from the gateway and producer UIDs.
The untrusted Raito proof producer cannot write the gateway's `0700` metadata
directory, even though the Unix sockets are group-addressable. Enforce actual
filesystem ownership and verify using the malicious-worker Linux integration
tests before a live test with a genuine Raito proof.

The pinned upstream Raito verifier is experimental and the parent feature
branch remains a draft pending genuine-proof acceptance and measured peak RAM,
I/O, and proof latency. More information is in
[the isolated verifier README](../../services/raito-verifier-broker/README.md)
and [the security boundaries](../../docs/SECURITY_BOUNDARIES.md).
