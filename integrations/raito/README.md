# Optional Raito backend

This independent, separately built crate calls the actual
[raito-spv-verify](https://github.com/starkware-bitcoin/raito/tree/main/crates/raito-spv-verify)
Rust STARK verification function. The upstream revision is pinned to
`48c237ac941d8061a857ecd111d7e81107912556`.

It handles bounded bzip2 decompression and bincode decoding, checks an
expected transaction ID, extracts the transaction index from Raito's Merkle
proof, then invokes Raito verification with `dev=false`.

The main sidecar avoids Cairo/STWO dependencies. This backend pins the
upstream Raito package and uses its nightly-2025-07-14 toolchain.

```sh
cargo +nightly-2025-07-14 check --manifest-path integrations/raito/Cargo.toml
cargo +nightly-2025-07-14 run --manifest-path integrations/raito/Cargo.toml -- \
  ./proofs/tx_proof.bin.bz2 EXPECTED_TXID MIN_PROVEN_HEIGHT
```

Proof artifacts can be fetched through the upstream
[raito-spv-client](https://github.com/starkware-bitcoin/raito/tree/main/crates/raito-spv-client).

This bridge currently has an independent, manual compatibility workflow
because its research dependencies are expensive to compile. The Raito
README cautions against production deployment. Chain-tip selection and
economic finality are separate application policies. The verification
result is limited to the upstream proof statement and configured work bound.

**Status:** implementation scaffold. Its heavy backend must pass its own
build check before claiming compatibility with the pinned upstream revision.

Compatibility CI runs for changes to this integration directory.


## Machine-mode result verifier

After building the pinned integration, use the executable with:

```sh
raito-verify --gateway PROOF_FILE EXPECTED_TXID BLOCKHASH BLOCKHEIGHT \
  POLICY_SHA256 RECEIPT_JSON
```

The policy digest is SHA-256 of `serde_json::to_vec(&VerifierConfig::default())`
under the pinned upstream revision. Machine mode rejects any other policy,
runs `verify_proof(..., dev=false)`, checks the proof's transaction/block
against the requested job, and writes a structured receipt with the hash of
the exact compressed bytes that were decoded. The gateway verifies those
fields against the persistent job record and the worker's own SHA-256. Its
separate executable pin prevents accidental substitution with a mock or
different upstream verifier.


### Operator policy digest and live proof validation

The separately built verifier can print its exact pinned default policy
digest with `raito-verify --policy-sha256`. Include that SHA-256 as the
`policy_sha256` argument to the dispatcher. The executable itself must be
pinned by the operator through `SUPERNODE_RAITO_VERIFIER_SHA256`.

A live compressed proof can be obtained with upstream `raito-spv-client fetch`
for an already-confirmed Bitcoin transaction and validated independently:

```sh
raito-spv-client fetch --txid "$TXID" \
  --proof-path ./proof.bin.bz2 \
  --bitcoin-rpc-url http://127.0.0.1:8332 \
  --bitcoin-rpc-userpwd "$CORE_USERPWD" \
  --raito-rpc-url https://api.raito.wtf --verify

raito-verify ./proof.bin.bz2 "$TXID" "$BLOCK_HEIGHT"
raito-verify --policy-sha256
sha256sum /absolute/path/to/raito-verify
```

For gateway acceptance, a separately configured, approved Raito **worker**
must write those exact compressed proof bytes to its `--output` path. That
worker follows the dispatcher argument contract in the Supernode README.
The read/control tokens remain distinct. Submit a Raito job with
`["raito",artifact_id,memory_mib,policy_sha256,expected_txid]`. A valid
result moves to `verified_raito`; inspect it using
`zk.proof.receipt [job_id]` and `zk.proof.get [job_id,offset,max_bytes]`.
An invalid or unsupported proof remains `completed_unverified`.

The gateway's JSON input limit is 64 KiB and its artifact cache limits
individual inputs to 2 MiB. Large proof staging needs an operator-approved
worker or a future bounded streaming/import interface. The bridge's
availability, supported heights and proof policy must be confirmed in the
actual deployment. Record peak RSS and wall clock time for the independent
prover and verifier before assigning production resource limits.

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
