# Benchmarking the Bitcoin Supernode with real Raito proofs

The benchmark harness measures local Bitcoin Core RPC calls against the
Supernode's proxied `getblockhash`, then stages a TXID-bound input manifest and
submits one or more real Raito proof fetch and verify jobs. It checks the
result SHA-256 by retrieving every 64 KiB proof chunk after verification.

It cannot synthesize a real Raito proof. The external upstream Raito bridge,
a synced mainnet Bitcoin Core node, the operator-owned pinned fetch worker,
and the pinned Cairo/STWO verifier must already be configured and reachable.

## Run on the Bitcoin Core host

Use a confirmed transaction and its *currently active* block hash and height.
`raito-verify --policy-sha256` prints the configured pinned policy digest.
Keep the read and control bearer tokens in environment variables.

```sh
export SUPERNODE_RPC_TOKEN='READ_TOKEN'
export SUPERNODE_CONTROL_TOKEN='CONTROL_TOKEN'

python3 tools/benchmark_supernode.py \
  --core-cookie /home/bitcoin/.bitcoin/.cookie \
  --height ACTUAL_MAINNET_HEIGHT \
  --blockhash ACTUAL_BLOCK_HASH \
  --txid ACTUAL_TXID \
  --policy-sha256 ACTUAL_POLICY_SHA256 \
  --memory-mib 2048 \
  --rpc-samples 10 \
  --runs 1 \
  --worker-cgroup /sys/fs/cgroup/raito-workers \
  --output supernode-live-benchmark.json
```

`--worker-cgroup` is optional and should refer to the cgroup enclosing
the relevant prover, verifier and their subprocesses. The report records
`memory.peak`, `memory.current`, and cumulative `io.stat` counters where
available. The cgroup memory high-water mark may include page cache and
previous runs; reset counters or allocate a fresh cgroup for per-run peaks.
IO totals require subtracting the before counters from the after counters.
Polling job status every 250 milliseconds gives approximate stage timings.
Separate cgroups are recommended to isolate peak RSS and IO by process.

Output contains p50/p95/p99 RPC latency in milliseconds, per-job wall time,
observed state transitions, retrieved proof byte counts, and verification
result. A failure remains visible as `completed_unverified` or `failed`.
Only a real positive Raito verifier receipt sets
`live_stark_verification_observed: true`.

For fair comparisons, use the same Bitcoin Core instance, same block and
client process placement for both direct and proxied RPC. Run cold and warm
experiments with controlled caches, and record operating-system and hardware
configurations. The Raito bridge supplies precomputed chain-state proofs; its
remote service time and local transaction-proof assembly should be identified
separately from native STARK verification time. No benchmark here claims a
Bitcoin Core consensus-validation speedup.
