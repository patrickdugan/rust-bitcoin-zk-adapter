"""R0 mock-only Bitcoin header shard manifest *structure* checker.

It cannot validate headers, PoW, difficulty, cumulative work, proof bytes,
Bitcoin Core chain selection, checkpoint authenticity or SNARK/STARK proofs.
It neither opens files nor makes network calls. Always returns UNVERIFIED.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

SCHEMA = "bitcoin_header_shard_mock_v0"
STATE_KEYS = frozenset({
    "next_height", "tip_hash", "cumulative_work_hex", "last_nbits_hex",
    "retarget_first_height", "retarget_first_timestamp",
    "last_11_timestamps", "header_history_commitment",
})
SHARD_KEYS = frozenset({
    "schema", "network", "ruleset", "anchor_id", "start_height",
    "end_height_exclusive", "starting_state", "ending_state",
    "claimed_segment_digest",
})
MAX_MANIFEST_BYTES = 128 * 1024
MAX_SHARDS = 64
MAX_HEADERS_PER_SHARD = 512
MAX_NEXT_HEIGHT = 1 << 32
NETWORK = "bitcoin-mainnet"
RULESET = "bitcoin-mainnet-header-experimental-v0"
HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
HEX_NBITS = re.compile(r"[0-9a-f]{8}\Z")


class ManifestError(ValueError):
    """Malformed, ambiguous or mutually inconsistent mock claims."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ManifestError(reason)


def _exact_keys(value: Any, expected: frozenset[str], label: str) -> dict:
    _require(isinstance(value, dict), f"{label} must be an object")
    _require(value.keys() == expected, f"{label} has missing or unknown fields")
    return value


def _u32(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 0xFFFFFFFF


def _hex(value: Any, pattern: re.Pattern) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _pairs_unique(pairs: list[tuple[str, Any]]) -> dict:
    output = {}
    for name, value in pairs:
        _require(name not in output, f"repeated JSON field: {name}")
        output[name] = value
    return output


def _reject_constant(value: str) -> None:
    raise ManifestError(f"unsupported JSON number: {value}")


def _state(value: Any, label: str) -> dict:
    state = _exact_keys(value, STATE_KEYS, label)
    height = state["next_height"]
    _require(type(height) is int and 1 <= height <= MAX_NEXT_HEIGHT,
             f"{label}: invalid next height")
    _require(_hex(state["tip_hash"], HEX_256), f"{label}: invalid tip hash")
    _require(_hex(state["cumulative_work_hex"], HEX_256),
             f"{label}: invalid chainwork declaration")
    _require(_hex(state["last_nbits_hex"], HEX_NBITS),
             f"{label}: invalid nBits declaration")
    first = state["retarget_first_height"]
    _require(_u32(first) and first == ((height - 1) // 2016) * 2016,
             f"{label}: invalid retarget-epoch anchor")
    _require(_u32(state["retarget_first_timestamp"]),
             f"{label}: invalid retarget timestamp")
    timestamps = state["last_11_timestamps"]
    _require(
        isinstance(timestamps, list)
        and len(timestamps) == min(height, 11)
        and all(_u32(v) for v in timestamps),
        f"{label}: invalid median-time-past context",
    )
    _require(_hex(state["header_history_commitment"], HEX_256),
             f"{label}: invalid history commitment")
    return state


def check_mock_manifest(raw: bytes) -> dict:
    """Check only shape, strict ordering and exact *claimed* boundary equality.

    This is NOT even an SPV proof. Returned SHA-256 names the JSON declaration,
    not any independently checked Bitcoin data or authenticated proof.
    """
    _require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_MANIFEST_BYTES,
             "manifest absent or exceeds bounded input limit")
    try:
        manifest = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs_unique,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ManifestError("malformed JSON manifest") from exc
    root = _exact_keys(manifest, frozenset({"schema", "anchor", "shards"}), "manifest")
    _require(root["schema"] == SCHEMA, "unsupported manifest schema")
    anchor = _exact_keys(root["anchor"],
                         frozenset({"mode", "id", "provenance"}), "anchor")
    _require(anchor["mode"] == "declared_checkpoint"
             and anchor["provenance"] == "UNAUTHENTICATED"
             and _hex(anchor["id"], HEX_256),
             "unsupported or implicitly trusted checkpoint")
    shards = root["shards"]
    _require(isinstance(shards, list) and 1 <= len(shards) <= MAX_SHARDS,
             "missing or excessive shard claims")
    previous = None
    for index, candidate in enumerate(shards):
        name = f"shard {index}"
        shard = _exact_keys(candidate, SHARD_KEYS, name)
        _require(shard["schema"] == SCHEMA, f"{name}: invalid schema")
        _require(shard["network"] == NETWORK and shard["ruleset"] == RULESET,
                 f"{name}: mismatched Bitcoin network or ruleset")
        _require(shard["anchor_id"] == anchor["id"], f"{name}: changed checkpoint")
        _require(_hex(shard["claimed_segment_digest"], HEX_256),
                 f"{name}: invalid claimed segment digest")
        start, end = shard["start_height"], shard["end_height_exclusive"]
        _require(type(start) is int and type(end) is int
                 and 1 <= start < end <= MAX_NEXT_HEIGHT
                 and end - start <= MAX_HEADERS_PER_SHARD,
                 f"{name}: invalid or excessive header range")
        before = _state(shard["starting_state"], f"{name} start state")
        after = _state(shard["ending_state"], f"{name} end state")
        _require(before["next_height"] == start
                 and after["next_height"] == end,
                 f"{name}: boundary height mismatch")
        # This only rejects an obviously impossible *claim*. No work
        # calculation or PoW/retarget validation is being performed.
        _require(int(after["cumulative_work_hex"], 16)
                 > int(before["cumulative_work_hex"], 16),
                 f"{name}: declared work is non-increasing")
        if previous is not None:
            _require(start == previous["end_height_exclusive"],
                     f"{name}: gap, overlap or reordered segment")
            _require(before == previous["ending_state"],
                     f"{name}: changed shard boundary context")
        previous = shard
    canonical = json.dumps(root, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False).encode("ascii")
    return {
        "schema": "bitcoin_header_shard_structure_result_v0",
        "status": "UNVERIFIED",
        "acceptance": "NOT_CHECKED",
        "checkpoint_authenticated": False,
        "proofs_verified": 0,
        "headers_cryptographically_validated": 0,
        "boundary_links_compared": len(shards) - 1,
        "shard_claims": len(shards),
        "manifest_sha256": hashlib.sha256(
            b"BTC-SYNTHETIC-SHARD-MANIFEST-V0\x00" + canonical
        ).hexdigest(),
        "note": "Structural consistency only; no Bitcoin proof, PoW, chainwork or Core checks",
    }
