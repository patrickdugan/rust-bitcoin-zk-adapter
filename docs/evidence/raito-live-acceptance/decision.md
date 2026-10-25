# Acceptance decision (2026-10-25)

Feature head `39e114077014fab7a18e6a705817209c78157ec8`. The evidence is
kept in three separate categories, and none of them substitutes for another:

1. **Synthetic CI**: GitHub Actions with mock workers and verifiers.
2. **Authentic cryptographic acceptance**: a genuine Raito proof accepted by
   the pinned verifier with `dev=false`.
3. **Demonstrated OS isolation**: kernel-enforced UID, cgroup and filesystem
   boundaries observed on a real Linux/systemd host.

| Gate (docs/SECURITY_BOUNDARIES.md) | Category | Result | Basis |
| --- | --- | --- | --- |
| All relevant workflows pass on the exact head | synthetic CI | **PASS** | 11/11 runs on `39e1140` (environment.md) |
| One genuine compressed Raito SPV proof yields a typed receipt under the pinned verifier | authentic | **BLOCKED** | No mainnet Core, bridge NXDOMAIN, no proof artifact (positive.json) |
| Negative cases checked end to end on a genuine proof | authentic | **BLOCKED** | Needs the retained genuine proof |
| Compromised worker cannot edit gateway job records or verifier policy | OS isolation | **PASS** (synthetic workers) | zk VPS, negative-matrix.md |
| SIGKILL of gateway/worker/verifier leaves no children or unbounded artifacts | OS isolation | **PASS** (synthetic jobs) | zk VPS, negative-matrix.md |
| Peak RAM, I/O, latency, cold/warm Core overhead recorded with the benchmark harness | authentic | **BLOCKED** | Needs a genuine proof run on the operator host |

## Recommendation

**Keep PR #1 in draft and Issue #2 open.** Do not merge to `main`. The
cryptographic gate cannot be attempted until an operator supplies both of
these:

- a synced archival mainnet Bitcoin Core with loopback authenticated RPC;
- a reachable Raito bridge, or a retained genuine compressed proof with its
  TXID, block hash and height.

`api.raito.wtf` no longer resolves. Unless upstream restores it, this
probably means running Raito's bridge and proof pipeline from the pinned
revision. That is a material cost decision for the operator.
