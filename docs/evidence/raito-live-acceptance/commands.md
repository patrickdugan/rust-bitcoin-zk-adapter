# Commands (2026-10-25)

Secrets never appear here. Tokens and cookies were generated per run with
`head -c 32 /dev/urandom | sha256sum`, read from root-only files, and
removed by `teardown.sh`.

## PR #6 audit and integration

```sh
git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*'
git diff 21e6a2e..origin/pr/6 --stat          # 3 files, tools/ and docs/ only
python3 -m py_compile tools/benchmark_supernode.py
python3 -m unittest tools.test_benchmark_supernode -v   # Linux, as root and as a non-root user
# Real cgroup v2 bind mount, PR head 2760b49 vs fix 500e491:
mkdir /sys/fs/cgroup/rbzk-bindtest /tmp/rbzk-alias
mount --bind /sys/fs/cgroup/rbzk-bindtest /tmp/rbzk-alias
python3 -c "from tools.benchmark_supernode import select_cgroups; ..."
git merge --no-ff origin/fix/labeled-benchmark-cgroups   # -> 39e1140
git push origin HEAD:feat/raito-verified-results
```

## Availability preflight (no credentials used)

```sh
nslookup api.raito.wtf; curl -m 15 https://api.raito.wtf/   # NXDOMAIN, no connection
ssh -o BatchMode=yes -o ConnectTimeout=12 <operator VPS>   # connection timed out
# Local nodes: bitcoind -datadir=C:\BitcoinTestnet (testnet4), -datadir=C:\BitcoinSignet\node
git -C raito ls-tree -r 48c237a | grep -i proof            # no genuine proof artifact
```

## Isolation acceptance (disposable GitHub-hosted runner)

Workflow `.github/workflows/isolation-acceptance.yml`, run on branch
`evidence/raito-live-acceptance`:

```sh
cargo build --manifest-path services/{supernode-rpc,proof-worker-broker,raito-verifier-broker}/Cargo.toml
sudo env T="$GITHUB_WORKSPACE" EV="$RUNNER_TEMP/evidence" bash tools/isolation-acceptance/run_stage2.sh
cargo +nightly-2025-07-14 build --release --manifest-path integrations/raito/Cargo.toml
sudo env T=... EV=... V=.../rust-bitcoin-raito-sidecar bash tools/isolation-acceptance/stage3.sh
```

Inside `run_stage2.sh` the benchmark harness runs against the synthetic
deployment:

```sh
SUPERNODE_RPC_TOKEN=<read> SUPERNODE_CONTROL_TOKEN=<control> python3 tools/benchmark_supernode.py \
  --core-url http://127.0.0.1:18332 --core-cookie <synthetic core cookie> \
  --height 900000 --blockhash <sha256("rbzk-synthetic-900000")> \
  --txid cdcd…cd --policy-sha256 abab…ab --memory-mib 1024 --rpc-samples 10 --runs 1 \
  --producer-cgroup /sys/fs/cgroup/system.slice/supernode-proof-worker-broker.service \
  --verifier-cgroup /sys/fs/cgroup/system.slice/supernode-raito-verifier.service
```

## Not run (blocked)

The handoff's live command needs operator values that do not exist here:
an archival mainnet Core cookie, a confirmed TXID with its active block, a
reachable bridge and the operator's service cgroups. It was not run.
