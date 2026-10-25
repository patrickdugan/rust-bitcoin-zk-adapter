# Negative and isolation matrix (2026-10-25)

Run on the operator VPS `zk` (Ubuntu, kernel 7.0.0-38-generic, 8 vCPU,
31 GiB RAM, 4 GiB swap, systemd, cgroup2fs) at evidence-branch commit
`10abe1888458fc414609ea6c8686e1298aa30b1d` (includes PR #7), using
`tools/isolation-acceptance`. The repo's three systemd units were
installed **unchanged**.

Evidence categories:

- **OS isolation**: real kernel/systemd enforcement on that host.
- **synthetic**: mock fetcher, mock verifier and a synthetic Core.
- **real verifier, synthetic input**: the pinned `raito-verify` with
  `dev=false` on inputs that must be rejected.

No case used a genuine Raito proof.

| Case | Category | Result |
| --- | --- | --- |
| Three distinct non-root service UIDs | OS isolation | PASS |
| Producer and verifier cgroups at `memory.max`=4G, `memory.swap.max`=0, `pids.max`=64 | OS isolation | PASS |
| Fetch and verify UIDs cannot write or list the gateway job dir, or modify approved executables | OS isolation | PASS |
| Wrong-UID group member rejected at both sockets (`SO_PEERCRED`); non-group user cannot connect | OS isolation | PASS |
| `ProtectHome=yes` hides a cookie under `/home` | OS isolation | PASS |
| `MemoryMax=256M` with no swap stops a 1 GiB allocation (probe unit) | OS isolation | PASS |
| `TasksMax=64` stops fork with EAGAIN after 63 children | OS isolation | PASS |
| `KillMode=control-group` reaps `setsid` escapees after the main process is SIGKILLed | OS isolation | PASS |
| 64 MiB staging fs refuses a 100 MiB write (53,477,376 bytes written) | OS isolation | PASS |
| Positive path, 4-chunk retrieval digest matches (204,828 bytes) | synthetic | PASS |
| Read token refused for submit and verify | synthetic | PASS |
| Verifier rejection kept as `completed_unverified`; `zk.proof.verify` re-verifies without re-fetch | synthetic | PASS |
| Forged receipt: wrong TXID, or wrong proof digest | synthetic | PASS (rejected) |
| Simulated reorg: receipt and chunks refused, then restored | synthetic (simulated reorg) | PASS |
| Tampering worker and verifier cannot alter gateway job records | synthetic + OS isolation | PASS |
| Staging exhaustion fails the job, leaves no files, broker recovers | synthetic + OS isolation | PASS |
| Detached descendants of producer and verifier reaped | synthetic + OS isolation | PASS |
| SIGKILL gateway while running → `interrupted`, no remaining processes (cleanup 3.8 s) | synthetic + OS isolation | PASS |
| SIGKILL producer broker while running → `failed`, no stray worker (3.7 s) | synthetic + OS isolation | PASS |
| SIGKILL verifier broker while verifying → `completed_unverified`, then re-verified | synthetic + OS isolation | PASS |
| SIGKILL gateway while verifying → `completed_unverified` kept | synthetic + OS isolation | PASS |
| Verified receipt survives a gateway restart (re-validated) | synthetic | PASS |
| Journals and evidence contain no read or control token | OS isolation | PASS |
| Pinned verifier rejects empty, random, random-bz2 and mock inputs, and a 900 MB bzip2 zero bomb ("decompressed proof exceeds limit", 136 MiB RSS) | real verifier, synthetic input | PASS |
| Pinned verifier refuses a wrong policy digest | real verifier, synthetic input | PASS |
| Pinned verifier behind the third-UID broker leaves synthetic bytes `completed_unverified` | real verifier, synthetic input | PASS |
| Wrong TXID, block, policy, one-byte corruption or stale chain on a **genuine** proof | authentic | **BLOCKED** (no genuine proof) |

Pinned verifier build on `zk`: `rust-bitcoin-raito-sidecar` SHA-256
`0fc693962584a30e8e1b671880fdddc08e5bc87e5f82adda944b5c0a746cfc49`. The
generated `Cargo.lock` has SHA-256
`210370d01b7879f608188a73e9b5a38a338e622f569c2d4726ee9a07b800a72f`;
no lockfile is committed, so this digest is not reproducible from the
commit alone. Policy SHA-256:
`18b4cf2dc3686f38978f4543a8bd42616b27caa6a6e0c87ce3c850b337a6664c`.
Release build: 2 min 36 s wall, 1.43 GB peak RSS.

The harness reported `live_stark_verification_observed = true` on the
synthetic deployment. That field cannot tell a mock verifier from the
real one, so do not use it as acceptance evidence.
