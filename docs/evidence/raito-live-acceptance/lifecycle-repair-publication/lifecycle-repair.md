# Lifecycle repair review and Linux handoff

Local patch only; no publication, workflow dispatch, merge or service changes.
PR #1 remains draft. Isolation acceptance remains pending a patched Linux run.
Nothing here demonstrates acceptance of a genuine Raito proof.

## Source and ownership check

Fresh clone on 2026-10-25 found evidence head
`23b86c701b8e0c9fbab15d23e89a26c45b4e0ac5`, based on feature head
`39e114077014fab7a18e6a705817209c78157ec8`. PR #1 metadata, PR searches,
its discussion showed no newer corrective work. No existing checkout was edited. Local branch:
`fix/isolation-lifecycle-evidence`.

## Evidence qualification

The disconnect-cancellation gaps were established by source inspection, not
local runtime reproduction. Historical Linux process counts are consistent
with that diagnosis, but do not prove individual process identities. The
new Rust regressions and patched systemd acceptance are NOT_RUN.

## The six failures

Original source: [run 40163436504](https://github.com/patrickdugan/rust-bitcoin-zk-adapter/actions/runs/40163436504),
job 121079557172. Original result: 11/17 passed, six failed. That result is
historical and has not been replaced by a new acceptance result.

| Case | Original observation | Assessment and repair |
| --- | --- | --- |
| Producer setsid child | after job 2, after restart 1 | `shell=True` runs `pgrep -f 'sleep 901'` through a shell whose own command line matches. The count cannot identify a survivor. A detached child may outlive its job process group by design, but must die when its enclosing service stops. Now require an observed exact child in the producer cgroup, save PID/start ticks/parent/group/session, stop synchronously, require inactive/MainPID=0/empty cgroup and tracked PID disappearance, then start services. |
| Verifier setsid child | after job 1, after restart 1 | Same checker contamination for `sleep 902`; these counts do not prove a surviving verifier child. Apply the same exact-identity and terminal-stop checks. |
| Gateway SIGKILL during production | running -> interrupted; producer cgroup 3; global sleepers 2 | The global count is contaminated, but the code independently reveals real orphaned work: the producer awaits its worker without watching the gateway connection. Two extra producer processes are consistent with the sleeping mock and its shell. Now cancel worker supervision on client EOF/error/trailing bytes, releasing staging and admission capacity; verify exact children disappear within a bounded teardown wait. |
| Producer broker SIGKILL | phase_seen=failed; broker at capacity; -> failed | Invalid crash experiment: production was never established. The preceding disconnected gateway left a producer job occupying the single slot. Now require both current `running` status and an exact `sleep 30` in the producer cgroup before signaling. Failure records SIGKILL NOT RUN and halts later cases to prevent contamination. |
| Verifier broker SIGKILL | verifying_raito -> completed_unverified; both broker cgroups 1; sleepers 1 | State recovery already matched the expected fail-closed result, and the cgroup counts show only the daemons at that observation. The global sleeper count cannot prove a leak. Now track exact children and require a new service invocation, recovered job state and terminal cleanup; no fixed five-second assumption. |
| Gateway SIGKILL during verification | verifying_raito -> completed_unverified; verifier cgroup 3; sleepers 2 | Same real disconnect-cancellation gap in the verifier broker, plus the contaminated checker. Now cancel verifier supervision on client loss and verify exact child identities terminate. Receipt validation and completed_unverified semantics remain intact. |

These are supported code-level diagnoses, not retrospective proof of each
process in the old run: that run lacks exact PID/start-time evidence. No
containment escape beyond the service cgroup has been demonstrated.

## Change boundaries

- Both broker main.rs files: watch the already-complete request socket while
  supervising computation. Dropping supervision uses existing kill-on-drop
  and process-group cleanup. No new signal target or OS permission is added.
- Both services gain Linux regression tests for EOF and forbidden trailing
  bytes after an actual mock worker starts, asserting child termination,
  staging removal and admission-slot release.
- e2e.py and new lifecycle.py: replace shell/global counts with checked argv
  commands and exact service/process evidence, phase preconditions, bounded
  teardown polling and persisted observation JSON. Missing/unreadable data
  fails; PID reuse cannot count as a survivor. Zombies remain visible and
  fail acceptance cleanup until reaped; they are labeled by process state.
  Crash recovery must also finish in under 25 seconds, before the freshly
  established mock's normal 30-second sleep would complete.
- run_stage2.sh: propagate e2e failure through tee and emit FAIL even when
  Python cannot start; continue normal log collection and teardown.
- test_lifecycle.py and the isolation workflow: add offline evidence fixtures.

Process-group cleanup still cannot kill a descendant that calls setsid.
The service cgroup remains the hard containment boundary for that case.
The patch deliberately continues testing terminal service teardown for
detached children, as the original acceptance case required. It does not
claim per-job cgroup isolation or change production unit settings.

## Validation in this task

| Check | Outcome |
| --- | --- |
| Offline lifecycle unittest fixtures | PASS, 10 tests; fake proc files and mocked service state only |
| Python py_compile of e2e/lifecycle/test_lifecycle | PASS |
| rustfmt --edition 2021 --check on both broker main.rs files | PASS; syntax/format only, not type checking |
| bash -n tools/isolation-acceptance/run_stage2.sh | PASS under Windows Git Bash; no script execution |
| git diff --check | PASS |
| Initial fixture attempt using sandbox default temp directory | FAILED due temp-path permissions; rerun with TEMP/TMP inside this checkout passed |
| Host RAM resource check | UNAVAILABLE: CIM access denied; sandbox process visibility cannot establish MSI host memory usage |
| Rust cargo test/clippy and Linux service acceptance | NOT RUN: Windows environment, no authorized disposable Linux target supplied |
| Genuine proof pipeline | NOT RUN; separate unchanged gate |

No user jobs were stopped, suspended, reprioritized or otherwise modified.
No heavy build was attempted while host memory could not be established.

## Unexecuted Linux run contract

Use an **already authorized disposable Linux host**, never the MSI Windows
host or an existing user workload environment. Requirements: systemd as PID 1,
unified cgroup v2, root/admin authority for the kit's user/service/mount changes,
loop-ext4 support, free staging disk, a suitable Rust toolchain and enough
available memory for three bounded builds. No VM/VPS provisioning is authorized.

Apply the supplied patch onto the exact evidence base in a clean isolated
checkout. Record the resulting commit SHA and a clean `git status`, host
facts, toolchain versions and binary SHA-256 values. Do not run an old
published workflow and mistake its result for this unpushed patch.

```sh
# Unexecuted. Run only inside the approved disposable Linux environment.
set -euo pipefail
git rev-parse HEAD
git status --porcelain
python3 -m unittest discover -s tools/isolation-acceptance -p test_lifecycle.py -v
for m in services/proof-worker-broker services/raito-verifier-broker; do
  cargo fmt --manifest-path "$m/Cargo.toml" -- --check
  cargo test --manifest-path "$m/Cargo.toml" --all-targets -j 1
  cargo clippy --manifest-path "$m/Cargo.toml" --all-targets -j 1 -- -D warnings
done
for m in services/supernode-rpc services/proof-worker-broker services/raito-verifier-broker; do
  cargo build --manifest-path "$m/Cargo.toml" -j 1
done
export EV="$(mktemp -d /tmp/rbzk-lifecycle-evidence.XXXXXX)"
sudo env T="$PWD" EV="$EV" bash tools/isolation-acceptance/run_stage2.sh 2>&1 | tee "$EV/stage2.log"
```

Acceptance requires all 17 synthetic e2e cases passing, no aborted harness,
all existing kernel probes passing, and the six detach/crash JSON files
showing the required preconditions and terminal cleanup. Preserve those
files, sanitized journals, e2e.json, installed-binary hashes and source SHA.
For any survivor report its exact PID/start ticks, PPID/group/session,
actual cgroup, service invocation/state and terminal observation; distinguish
running processes from unreaped zombies. Do not weaken checks on failure.

The real pinned-verifier rejection stage can be rerun separately if required
by the review, but cannot establish genuine-proof acceptance. PR #1 must
remain draft until its independent genuine-proof and production gates pass.

Remaining blocker: execute the patched Rust tests and synthetic isolation
acceptance on the target described above. Status: NOT RUN / pending target;
not denied and not an uncertain operation. No live kill test was attempted.
