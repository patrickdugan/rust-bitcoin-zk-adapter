# Reaping and detached-readiness correction

This follows publication commit `06d15a3f09319a9f0adbd6e358d17c72c86b33b7`
on the same draft PR #7. The original local commit and prior sanitized
evidence remain preserved. No unrelated benchmark or proof behavior changes.

## Runtime evidence motivating the correction

[Automatic run 40172671425](https://github.com/patrickdugan/rust-bitcoin-zk-adapter/actions/runs/40172671425)
tested merge `438d1abbe1c5cfc0be2e6283df3dd3aa61179558`, whose source tree
equals publication head `06d15a3`. Rust and both broker unit workflows passed,
but full synthetic isolation failed:

- Verifier detached-child readiness was never established: no exact `sleep
  902` was observed. Stop/restart cleanup was clean. This was not evidence
  of a surviving detached child.
- Gateway SIGKILL during production recovered the job as interrupted, but
  producer PID 6655, start ticks 16252, PPID 6437, group 6655, session 6437
  remained state `Z` in the producer service cgroup after 23.606 seconds.
  It was a terminated, unreaped child, not an executing process escaping
  its cgroup. Later crash/retry/restart cases were not run after this failure.

## Focused corrections

Both brokers now watch the completed-request socket inside the function that
owns the subprocess. On disconnect, trailing bytes or timeout, they kill the
process group and explicitly await the owned child with a five-second reap
deadline before releasing staging and admission capacity. The existing
kill-on-drop/group guards remain the fallback for unexpected task cancellation.
The acceptance harness still fails while any exact tracked zombie exists.

The synthetic detached fixtures use Python Popen's synchronous exec handshake
with start_new_session=True. Thus the parent cannot finish and trigger group
cleanup before the detached child has created its new session and executed.
Both fixture roles require recorded PID == process group == session, exact
sleep argv and actual service cgroup membership. Missing readiness is a failure.

Existing bounded Linux broker regressions now record the direct child and
require waitpid(WNOHANG) to return ECHILD after the service task completes,
proving the broker already reaped it. The grandchild must also disappear;
state Z no longer satisfies that regression's cleanup condition. Offline
fixtures additionally reject zombies and wrong-session detached readiness,
and require an exact tracked zombie to disappear before cleanup succeeds.

The three piped acceptance workflow steps explicitly select Bash, enabling
pipefail so tee cannot mask the underlying Stage 2 or verifier command failure.
Outcome annotations and retained evidence still provide the final result.

## Validation scope

Local checks are limited to twelve offline mocked lifecycle fixtures, Python
syntax, Rust formatting and shell syntax. No local Linux process or service
tests, proving workloads, manual workflow dispatch, account/security changes,
merge or deployment are authorized or performed. Existing user workloads
remain untouched. Rust execution and full lifecycle acceptance for this
correction remain NOT_RUN until automatic exact-source CI provides results;
the draft PR description records those terminal run identities and outcomes.

All seventeen original synthetic e2e cases, including the previously skipped
crash/retry/restart cases, must actually run before full acceptance can pass.
Genuine Raito proof acceptance remains an independent NOT_RUN gate; synthetic
receipts and pinned-verifier rejection of non-proofs cannot establish it.
