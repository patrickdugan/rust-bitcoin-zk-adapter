# Claude handoff: live Raito proof acceptance and OS isolation

Prepared 2026-10-23 for **patrickdugan/rust-bitcoin-zk-adapter**.

## Mission and baseline

Orchestrate the remaining production acceptance for the protocol-neutral Bitcoin Supernode / Raito integration. Work on **`feat/raito-verified-results`**, stacked on draft [PR #1](https://github.com/patrickdugan/rust-bitcoin-zk-adapter/pull/1); keep `main` unchanged pending actual live acceptance. [Issue #2](https://github.com/patrickdugan/rust-bitcoin-zk-adapter/issues/2) stays open.

Baseline `abfdb361c1b07fa97cc60e759bfa2c5b6f66d1c4`: all **11 relevant GitHub Actions workflow runs passed**, including pinned nightly Raito compatibility. Recheck new head CI before making later claims. PR #3 isolates Raito proof production under a second Unix UID; PR #4 isolates Cairo/STWO verification under a third UID; PR #5 hardened the gateway's proof-import file ownership and cancellation cleanup. All three landed in the **feature branch**. Their tests include synthetic IPC and malicious-worker cases, **not a genuine STARK proof**. Proof hashes, a worker's success exit and a mock verified receipt never establish cryptographic acceptance.

Your goal is **one real compressed mainnet Raito SPV proof accepted by the exact pinned external verifier with `dev=false`**, followed by authenticated gateway receipt/Bitcoin Core active-chain checks and measured OS-enforced isolation. Treat unavailable operator host/bridge access as an explicit blocker.

## Read first

`AGENTS.md`; `docs/SECURITY_BOUNDARIES.md`; `docs/LIVE_SUPERNODE_BENCHMARK.md`; `docs/RAITO_INTEGRATION.md`; `integrations/raito-fetcher/README.md`; `services/proof-worker-broker/README.md`; `services/raito-verifier-broker/README.md`; `services/supernode-rpc/README.md`; `deploy/systemd/*.service`; `tools/benchmark_supernode.py`; PR #1 current state and recent workflow runs.

## Work package 1: validate host and boundaries

1. Record current feature SHA, CI outcomes, Rust toolchains, exact binary hashes, service versions and UTC date. Check connected or authorized Linux hosts and available mainnet Bitcoin Core, rather than assuming access.
2. Verify a synced, operator-controlled **archival mainnet Bitcoin Core** with loopback authenticated RPC. Choose an old-enough confirmed TXID and derive its active block hash and height from Core; record TXID/height/hash with source commands. Check usable `txindex`/historic transaction access if needed.
3. Verify an accessible Raito bridge and its cost/availability **before** running any costly proof. Audit pinned upstream revision `48c237ac941d8061a857ecd111d7e81107912556` and `nightly-2025-07-14`. Derive the exact verifier policy SHA-256 with `raito-verify --policy-sha256`; compute installed binary SHA-256 on the host.
4. Run gateway, producer and verifier under three distinct non-root UIDs, with broker socket `SO_PEERCRED` checks, gateway-only `0700` job metadata, service-private staging, protected Core cookie and immutable/root-owned approved executables. Keep both same-UID development overrides **off**.
5. Adapt the supplied systemd units and check actual **cgroup v2** enforcement of `memory.max`, `memory.swap.max=0`, pids/TasksMax, `KillMode=control-group`, service descendant membership, and a **hard staging-disk bound while jobs run**. Resource admission and the 256 MiB completed-result retention quota are insufficient by themselves. Validate correct socket path ownership/permissions and whether `ProtectHome` blocks cookie access.
6. Run the existing separate-UID Linux regression scripts and `systemd-analyze verify` in a disposable operator-approved test environment.

Checkpoint: issue a sanitized environmental matrix and mark **PASS**, **FAIL** or **BLOCKED** per boundary. If host/cookies/bridge/quota are unavailable, continue offline QA and report exact missing inputs. **Never request private keys or transfer funds.**

## Work package 2: one genuine positive proof

Build the Raito fetcher and producer broker, the pinned Cairo/STWO integration, and isolated verifier broker following their READMEs. The Raito fetch worker uses the operator-pinned `raito-spv-client fetch` via a configured HTTPS bridge. Prepare `raito_fetch_request_v1` with the actual mainnet TXID, active block hash and height. Stage the manifest using authenticated `zk.artifact.put` with kind `raito_fetch_request`, then call `zk.proof.submit ["raito", artifact_id, memory_mib, policy_sha256, expected_txid]`.

Observe status transitions `queued`, `running`, `verifying_raito`, `verified_raito` through `zk.proof.status`. If the verifier rejects, expect `completed_unverified` with a preserved error; record it as a non-acceptance. Only claim success on a real pinned-verifier receipt under `dev=false` with independently checked TXID, block hash/height, exact policy SHA-256, compressed proof SHA-256 and Bitcoin Core current active-chain placement. Retrieve `zk.proof.receipt` and every bounded `zk.proof.get` chunk, recomputing the full digest. Test control-token-only `zk.proof.verify [job_id]` on a retained unverified result without re-fetching.

Command shape from the documented benchmark (replace **every** placeholder with measured host values):

```bash
export SUPERNODE_RPC_TOKEN='<private read token>'
export SUPERNODE_CONTROL_TOKEN='<private control token>'
python3 tools/benchmark_supernode.py \
  --core-cookie /path/to/approved/core/.cookie \
  --height ACTUAL_MAINNET_HEIGHT \
  --blockhash ACTUAL_ACTIVE_BLOCK_HASH \
  --txid ACTUAL_CONFIRMED_TXID \
  --policy-sha256 ACTUAL_POLICY_SHA256 \
  --memory-mib 2048 --rpc-samples 10 --runs 1 \
  --worker-cgroup /sys/fs/cgroup/ACTUAL_SERVICE_CGROUP \
  --output supernode-live-benchmark.json
```

The `--worker-cgroup` path must exist and enclose the processes being measured. Producer and verifier in different cgroups need separately labeled snapshots or a companion benchmark enhancement. A status poll every 250 ms only gives approximate stage boundaries. `memory.peak` can include page cache or previous runs.

## Work package 3: adversarial acceptance on retained real proof

Use saved proof bytes to test wrong TXID, wrong block hash or height, insufficient/wrong policy, one-byte proof corruption, truncated chunk, forged typed receipt, and stale Core active-chain context. Verify rejection on receipt/status/retrieval endpoints, plus state and durable metadata integrity. Make separate observations for tests using a **genuine proof artifact** and tests using a synthetic mock.

Repeat Unix negative tests for wrong peer UID, malicious worker changes to gateway JSON, symlink/hardlink staging, overlong headers, and digest mismatch. Under controlled conditions test SIGKILL of gateway, producer and verifier at different lifecycle phases; verify restarts preserve `completed_unverified` or `interrupted` as appropriate. Test detached descendants, cgroup control-group cleanup, staging-quota exhaustion and absence of leaked children/outputs.

For chain reorganization, a controlled test-node/proxy or regtest simulated active-chain change is useful; label it **simulated reorg**. Do not claim that an authentic mainnet reorg occurred without observing one. Mark any genuinely untestable live-mainnet condition **BLOCKED**.

## Work package 4: quantitative resource report

Capture same-host direct-Core vs gateway RPC latency p50/p95/p99 with comparable cold/warm conditions. Report actual fetch/bridge wall time, local assembly if separable, STARK verification time, total job time, compressed proof size, chunk count and digest, CPU utilization, producer/verifier peak cgroup memory, swap, process counts, `memory.events`, disk space high-water and **delta** of cgroup `io.stat` before/after values. Include OS/kernel, hardware, compiler and executable hashes, upstream revision, Core height/hash and observed benchmark timestamps.

Start with **one** genuine proof. Reuse it for negative/verifier tests; get explicit authorization before material paid bridge usage, costly new proof runs or extra infrastructure. Record observed numbers only. This project does not claim Bitcoin Core consensus-validation speedups, Bitcoin chain selection by the proof alone, or application-level Ark/TradeLayer transition validity.

## Engineering workflow and evidence requirements

Maintain protocol neutrality; keep application-specific semantics out. For code fixes, branch from the Raito feature branch and open reviewable PRs against it. Run appropriate format, Rust tests, warnings-as-errors Clippy, separate-UID integration, nightly Raito compatibility and Python benchmark tests. Add regression vectors for every bug.

Save **small sanitized evidence** to `docs/evidence/raito-live-acceptance/`: `environment.md`, `positive.json`, `negative-matrix.md`, `resources.json`, `commands.md`, `decision.md`. Keep large proof blobs in operator-approved artifact storage and record the content SHA-256 and retrieval location; never commit secrets, cookie files, bearer tokens, raw private host configuration or paid-provider credentials. Include exact git commits and GitHub Actions URLs.

Post factual progress on draft PR #1. Keep PR #1 draft and Issue #2 open until a genuine pinned-verifier positive result, negative-case evidence, actual kernel isolation and honest resource measurements satisfy the acceptance criteria. In `decision.md`, give per-gate PASS/FAIL/BLOCKED and a definite recommendation. End the orchestration with exact changes/PRs, what ran, CI/host evidence, blockers, approximate spend, and any operator action still required.

**First step:** inspect GitHub head and accessible host, then execute free preflight and existing tests. Continue without asking for repeated confirmation on routine code/CI work. Escalate only access, safety, secrets or budget decisions.
