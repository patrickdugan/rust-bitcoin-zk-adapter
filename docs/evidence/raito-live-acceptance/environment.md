# Environment matrix (2026-10-25)

Sanitized: no tokens, cookies, private host configuration or addresses
beyond what is already public in this repository.

## Code under test

| Item | Value |
| --- | --- |
| Feature branch head | `39e114077014fab7a18e6a705817209c78157ec8` (`feat/raito-verified-results`, merge of PR #6) |
| Tree | `856a88e4aff5bcd08002f5bf18f1f3946882c295` (identical to PR #6 head `500e491`) |
| Previous baseline | `21e6a2e629ab17ce3d7e9bd866ac8b29d922c7ee` |
| Pinned Raito | `starkware-bitcoin/raito@48c237ac941d8061a857ecd111d7e81107912556` (2025-11-28), toolchain `nightly-2025-07-14` |
| Draft PR #1 | still draft, untouched |

## GitHub Actions on `39e1140` (all `success`)

| Workflow | Event | Run |
| --- | --- | --- |
| Rust CI | push | [40162743431](https://github.com/patrickdugan/rust-bitcoin-zk-adapter/actions/runs/40162743431) |
| Benchmark harness checks | push | [40162743419](https://github.com/patrickdugan/rust-bitcoin-zk-adapter/actions/runs/40162743419) |
| Rust CI | pull_request | [40162747687](https://github.com/patrickdugan/rust-bitcoin-zk-adapter/actions/runs/40162747687) |
| Benchmark harness checks | pull_request | [40162747678](https://github.com/patrickdugan/rust-bitcoin-zk-adapter/actions/runs/40162747678) |
| Supernode systemd isolation templates | pull_request | [40162747602](https://github.com/patrickdugan/rust-bitcoin-zk-adapter/actions/runs/40162747602) |
| Isolated proof worker broker | pull_request | [40162747593](https://github.com/patrickdugan/rust-bitcoin-zk-adapter/actions/runs/40162747593) |
| Isolated Raito verifier | pull_request | [40162747752](https://github.com/patrickdugan/rust-bitcoin-zk-adapter/actions/runs/40162747752) |
| Raito fetch worker | pull_request | [40162747690](https://github.com/patrickdugan/rust-bitcoin-zk-adapter/actions/runs/40162747690) |
| Proof worker cgroup preflight | pull_request | [40162747651](https://github.com/patrickdugan/rust-bitcoin-zk-adapter/actions/runs/40162747651) |
| Supernode RPC compatibility | pull_request | [40162747674](https://github.com/patrickdugan/rust-bitcoin-zk-adapter/actions/runs/40162747674) |
| Raito integration compatibility | pull_request | [40162747800](https://github.com/patrickdugan/rust-bitcoin-zk-adapter/actions/runs/40162747800) |

These are **synthetic CI results**: mock workers, mock verifiers and
synthetic bytes. The Raito integration workflow runs `cargo check`, not a
build, and the integration has no committed `Cargo.lock`.

## Hosts and external inputs

| Boundary / input | Status | Observation |
| --- | --- | --- |
| Operator archival **mainnet** Bitcoin Core with loopback authenticated RPC | **BLOCKED** | Only a testnet4 node (RPC 48332) and a signet node run on the workstation; no mainnet datadir or 8332 listener. |
| Raito bridge `https://api.raito.wtf` (and `raito.wtf`) | **BLOCKED** | DNS: `Non-existent domain` (NXDOMAIN), 2026-10-25. Pinned `raito-spv-client fetch` has no source of proof bytes. |
| Genuine compressed Raito SPV proof artifact | **BLOCKED** | None available. `raito-landing/public/proofs/block_870000_proof.json` in the pinned revision holds placeholder hex, not a STARK proof. |
| Operator Linux VPS | **BLOCKED** | `ssh: connect to host … port 22: Connection timed out`. |
| Disposable Linux test environment (WSL2 Ubuntu 24.04.5, kernel 6.18.54.1-microsoft-standard-WSL2, systemd 255, cgroup2fs with cpu/io/memory/pids controllers, 4.5 GB VM cap, 2 GB swap) | available, intermittently | Its VM could not start while the host was out of memory: `Wsl/Service/CreateInstance/CreateVm/HCS/ERROR_NO_SYSTEM_RESOURCES`. |
| Workstation | info | AMD Ryzen AI 9 365 (10C/20T), 31 GB RAM, Windows 11 Home build 26200. |

No private keys, funds, paid bridge usage or new infrastructure were used.
