use rust_bitcoin_zk_adapter::compat::legacy_txindex_payload;
use rust_bitcoin_zk_adapter::op_return::{decode_op_return, decode_tradelayer_envelope};
use rust_bitcoin_zk_adapter::replay::{
    parse_script_hex, run_fixture_set, FixtureSet, LegacyOutcome, StrictOutcome,
};
const DATA: &str = include_str!("../fixtures/tradelayer/replay_v1.json");
#[test]
fn replay_synthetic_cases() {
    let set: FixtureSet = serde_json::from_str(DATA).unwrap();
    assert_eq!(run_fixture_set(&set), Ok(12));
}
#[test]
fn fixture_tampering_is_detected() {
    let mut set: FixtureSet = serde_json::from_str(DATA).unwrap();
    set.fixtures[0].expected_strict = StrictOutcome::Ignored;
    assert!(run_fixture_set(&set).is_err());
}
#[test]
fn duplicate_ids_and_schema_are_rejected() {
    let mut set: FixtureSet = serde_json::from_str(DATA).unwrap();
    set.schema_version = 2;
    assert!(run_fixture_set(&set).is_err());
    set.schema_version = 1;
    let duplicate = set.fixtures[0].clone();
    set.fixtures.push(duplicate);
    assert!(run_fixture_set(&set).is_err());
}
#[test]
fn legacy_and_strict_observe_different_payloads() {
    let script = parse_script_hex("6a0a746c32303b3b7a3b3273").unwrap();
    let data = decode_op_return(&script).unwrap();
    let envelope = decode_tradelayer_envelope(&data).unwrap().unwrap();
    assert_eq!(envelope.tx_type, 2);
    assert_eq!(envelope.body, "0;;z;2s");
    assert_eq!(legacy_txindex_payload(&script), Some("20;;z;2s".into()));
}
#[test]
fn invalid_and_oversized_hex_fail() {
    assert!(parse_script_hex("6a0").is_err());
    assert!(parse_script_hex("👀").is_err());
    assert!(parse_script_hex("xy").is_err());
    assert!(parse_script_hex(&"6a".repeat(100_001)).is_err());
}
#[test]
fn legacy_observation_has_explicit_payload_type() {
    let set: FixtureSet = serde_json::from_str(DATA).unwrap();
    assert!(matches!(
        set.fixtures[0].expected_legacy,
        LegacyOutcome::Payload { .. }
    ));
}
