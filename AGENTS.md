# Agent instructions

- This is a protocol-neutral rust-bitcoin sidecar. Keep application-specific protocol
  engines in their own repositories.
- Reuse mature verification libraries, especially Raito, rather than reproducing
  STARK verification or Bitcoin consensus in this crate.
- Isolate expensive proof backends in optional, separately compiled integrations.
- Label every proof statement precisely: Merkle inclusion, header authenticity,
  cumulative work, canonical-chain selection, and app transition validity
  are separate claims.
- No unsafe Rust in the default crate. Keep parsers bounded and test malformed data.
- Provide test vectors and CI checks for each change.
- Never call a SHA-256 native receipt a ZK proof.
