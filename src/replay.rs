//! Versioned strict-vs-legacy replay fixture format.
//! Parser comparisons do not establish historical consensus validity.
use crate::compat::legacy_txindex_payload;
use crate::op_return::{decode_op_return, decode_tradelayer_envelope, MAX_SCRIPT_BYTES};
use serde::Deserialize;
use std::collections::BTreeSet;

pub const FIXTURE_SCHEMA_VERSION: u32 = 1;
pub const MAX_FIXTURES: usize = 1_024;

#[derive(Debug, Clone, Deserialize)]
pub struct FixtureSet {
    pub schema_version: u32,
    pub fixtures: Vec<ReplayFixture>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct ReplayFixture {
    pub id: String,
    pub provenance: Provenance,
    pub chain: Chain,
    pub network: Network,
    pub block_height: Option<u64>,
    pub source_url: Option<String>,
    pub script_hex: String,
    pub expected_strict: StrictOutcome,
    pub expected_legacy: LegacyOutcome,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance { Synthetic, SourceLinkedUnverified }
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Chain { Bitcoin, Litecoin, Dogecoin }
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network { Mainnet, Testnet, Regtest }
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StrictOutcome {
    Envelope { tx_type: u8, body: String },
    Ignored,
    Error { code: String },
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LegacyOutcome { Payload { payload: String }, Ignored }

/// ASCII-hex parser with bounded input and exact-length decoding.
pub fn parse_script_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.is_ascii() || hex.len() & 1 != 0 || hex.len() > MAX_SCRIPT_BYTES * 2 {
        return Err("invalid or oversized ASCII hex".into());
    }
    let mut script = Vec::with_capacity(hex.len() / 2);
    for index in (0..hex.len()).step_by(2) {
        let value = u8::from_str_radix(&hex[index..index + 2], 16)
            .map_err(|_| "invalid hex digit")?;
        script.push(value);
    }
    Ok(script)
}
pub fn run_fixture_set(set: &FixtureSet) -> Result<usize, String> {
    if set.schema_version != FIXTURE_SCHEMA_VERSION {
        return Err("unsupported fixture schema version".into());
    }
    if set.fixtures.is_empty() || set.fixtures.len() > MAX_FIXTURES {
        return Err("fixture set is empty or exceeds size limit".into());
    }
    let mut ids = BTreeSet::new();
    for case in &set.fixtures {
        if case.id.trim().is_empty() || !ids.insert(case.id.as_str()) {
            return Err(format!("empty or duplicate fixture id: {}", case.id));
        }
        if matches!(case.provenance, Provenance::SourceLinkedUnverified)
            && case.source_url.is_none()
        {
            return Err(format!("{}: missing provenance link", case.id));
        }
        let script = parse_script_hex(&case.script_hex)
            .map_err(|error| format!("{}: {error}", case.id))?;
        let strict = match decode_op_return(&script)
            .and_then(|data| decode_tradelayer_envelope(&data))
        {
            Ok(Some(envelope)) => StrictOutcome::Envelope {
                tx_type: envelope.tx_type,
                body: envelope.body,
            },
            Ok(None) => StrictOutcome::Ignored,
            Err(error) => StrictOutcome::Error {
                code: format!("{error:?}"),
            },
        };
        if strict != case.expected_strict {
            return Err(format!(
                "{}: strict expected {:?}, received {:?}",
                case.id, case.expected_strict, strict
            ));
        }
        let legacy = match legacy_txindex_payload(&script) {
            Some(payload) => LegacyOutcome::Payload { payload },
            None => LegacyOutcome::Ignored,
        };
        if legacy != case.expected_legacy {
            return Err(format!(
                "{}: legacy expected {:?}, received {:?}",
                case.id, case.expected_legacy, legacy
            ));
        }
    }
    Ok(set.fixtures.len())
}
