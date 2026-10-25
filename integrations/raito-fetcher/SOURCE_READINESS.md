# Option B: offline proof-source readiness contract

This is a **declaration-only** interface in `src/source_readiness.rs`, intentionally **not wired to the live fetcher**, proof dispatcher, verifier, or any RPC. It makes no network connections, does not inspect an operator's private fetch configuration or Core cookie, does not invoke binaries, and does not claim proof authenticity.

## Inputs and source selection

The caller supplies in-memory JSON for an existing `raito_fetch_request_v1` request (max **4 KiB**) and an explicit `raito_source_selection_v1` declaration (max **8 KiB**), alongside the existing `WorkerArgs` identity. The request must be **mainnet** and match the expected TXID, block hash, and height. Only one source is supported per declaration; none or both are rejected. There is **no priority/fallback policy**.

Local declaration, supplied using a **synthetic** file for tests:

```json
{"schema":"raito_source_selection_v1",
 "local_artifact":{"path":"/absolute/synthetic-proof.bin","bytes":123,
                   "sha256":"64-character-hex-digest"},
 "bridge":null}
```

The local path must be absolute, point to a non-symlink regular nonempty file at most **16 MiB**, and match the independently declared byte length and SHA-256. This establishes only that the declared bytes were observed in an offline read. It is **not** a compression-format check, external provenance authentication, STARK verification, Bitcoin chain confirmation, or a safe immutable handle for later use. It must not be used as a bypass around the production source/verification pipeline.

Configured bridge metadata declaration:

```json
{"schema":"raito_source_selection_v1","local_artifact":null,
 "bridge":{"raito_bridge_url":"https://api.raito.wtf",
           "client_sha256":"64-character-hex-digest"}}
```

The bridge case accepts the existing fetcher's `FetchConfig` JSON **as in-memory bytes only**, validates its strict schema and the existing URL rules, and compares the declared URL and client SHA-256. It does **not** read the client binary, check its live digest, touch the cookie, resolve DNS, make an HTTP call, or query Core. A configured URL is `availability: NOT_CHECKED`.

## Output and limits

`SourceReadiness` returns one of two distinct metadata outcomes:
- `kind: declared_local_artifact`, `integrity: declared_bytes_sha256_match`, `availability: local_bytes_observed_only`.
- `kind: configured_bridge_metadata`, `integrity: configuration_fields_match_only`, `availability: NOT_CHECKED`.

**Both always return `acceptance: UNVERIFIED`.** No output can be `verified_raito`; no network availability, proof compatibility, chain authenticity or cryptographic acceptance can be inferred. The pinned external verifier with `dev=false`, independently authenticated Bitcoin Core active-chain checks and the existing durable gateway remain mandatory before a real verification status.

Malformed/unknown JSON fields, unsupported schema/network, missing declarations, both declarations, wrong identity, malformed endpoint or SHA, missing local file, symlink, oversize file and byte/hash mismatch all return errors without selecting another source.

## Scope and fixtures

The module is deliberately isolated from runtime execution. Synthetic temporary-file Rust tests cover explicit ambiguity, configuration mismatches, missing/malformed inputs, wrong block/network, 4/8 KiB declaration caps, 16 MiB output cap, symlink refusal, and honest `UNVERIFIED` results. Fixture bytes explicitly are **not Raito proofs**. No genuine compressed-proof acceptance is tested.

The policy choice of how an operator might prefer one source over another is **unresolved**: do not implement fallback or automatic precedence. A real proof must still pass all external verifier and chain prerequisites.
