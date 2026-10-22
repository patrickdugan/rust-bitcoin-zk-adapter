# Bitcoin Supernode RPC v0.1

This is a separate Rust service providing a deliberately restricted
JSON-RPC 2.0-compatible superset of Bitcoin Core read methods. It is designed
for proof preparation and downstream clients such as Ark exits and custody
watchtowers. The default service does not build Raito or Cairo dependencies.

## Launch

Run Bitcoin Core with its JSON-RPC server enabled. For historical lookup and
Ark exit workflows, txindex=1 and access to historical blocks are typically
needed. Block pruning limits historical proof preparation.

Use either a Bitcoin Core RPC cookie file or user/password environment variables.
The gateway requires its own independent bearer token and binds to loopback.

Example:

    export BITCOIN_RPC_COOKIE_FILE=/path/to/bitcoin/.cookie
    export SUPERNODE_RPC_TOKEN=replace-with-at-least-16-random-characters
    cargo run --manifest-path services/supernode-rpc/Cargo.toml

Health check: GET http://127.0.0.1:18444/healthz
JSON-RPC: POST http://127.0.0.1:18444/

Example JSON-RPC message, authenticated with Authorization: Bearer <token>:

    {"jsonrpc":"2.0","id":1,"method":"zk.capabilities","params":[]}

    {"jsonrpc":"2.0","id":2,"method":"zk.gettxcontext",
     "params":["<txid>","<confirmed_block_hash>"]}

## Available namespaced RPC

- zk.capabilities: indicates installed features, pending worker integrations,
  and fixed gateway limits.
- zk.nodeprofile: reads Bitcoin Core chain, index and mempool status.
- zk.gettxcontext: fetches a raw transaction, 80-byte header and Bitcoin Core
  gettxoutproof; validates txid, header hash, partial Merkle tree and active
  chain placement at lookup time. Returns the proof and raw hex for external
  verification, including eventual Raito/Shinigami proving workers.
- Selected Bitcoin Core read methods: see allowed_core_rpc() for the complete
  allowlist. Wallet, signing, broadcast, mining and shutdown methods are denied.

The service is not a drop-in substitute for all Bitcoin Core RPC commands.
Its custom methods extend a safe subset.

## Memory and concurrency

The default RPC request cap is 64 KiB, upstream response cap 24 MiB,
max inflight calls 4 (hard maximum 8), with a 30-second Bitcoin Core timeout.
Calls perform bounded streaming reads of Core responses, and each request
completes before its semaphore slot is released. There is no unbounded block
cache or proof queue in v0.1. OS and Bitcoin Core caches remain useful; adding
a size-bounded, reorg-aware content cache is a later milestone.

A proving worker should run as a different process with explicit memory limits,
bounded concurrency, persistent job records and content-addressed artifacts.

## Trust boundaries

The gateway authenticates a transaction against its supplied Merkle proof and
checks Bitcoin Core's active-chain view at request time. A reorg can occur
after the response. The caller decides acceptable confirmations, recency and
policy. Merkle inclusion is not Raito/Cairo proof verification.

Raito's proof verifier is already available in the optional
integrations/raito crate. Shinigami requires an independent execution/proving
adapter. The gateway advertises these workers as disconnected until they exist.

Ark support starts with Bitcoin settlement and exit anchor evidence. Its
off-chain VTXO validity/forfeit rules remain Ark-specific and cannot be
inferred from on-chain transaction inclusion alone.

## Planned methods

- zk.getspendcontext: bounded, prevout-aware witness bundles for Shinigami.
- zk.proof.submit/status: memory-budgeted proof-worker jobs.
- zk.getproof: attested Raito proof artifacts and verified policy metadata.
- zk.subscribe: reorg/sequence-aware event transport from Bitcoin Core ZMQ.
- zk.getarkanchor: optional Ark adapter linking VTXO exits to on-chain anchors.
