//! Offline, declaration-only Raito proof source readiness. Never fetches,
//! verifies, publishes, or asserts that a source is genuinely authenticated.
use super::{
    is_sha256, read_bounded_regular, validate_url, FetchConfig, FetchRequest, WorkerArgs,
    MAX_COMPRESSED_PROOF_BYTES, MAX_CONFIG_BYTES, MAX_REQUEST_BYTES, SCHEMA,
};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::{BlockHash, Txid};
use serde::Deserialize;
use std::{fs, path::PathBuf, str::FromStr};

const SELECTION_SCHEMA: &str = "raito_source_selection_v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    schema: String,
    local_artifact: Option<LocalArtifact>,
    bridge: Option<BridgeDeclaration>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalArtifact {
    path: PathBuf,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeDeclaration {
    raito_bridge_url: String,
    client_sha256: String,
}

/// An offline-only observation, never a Supernode job state or STARK receipt.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct SourceReadiness {
    pub kind: &'static str,
    pub integrity: &'static str,
    pub acceptance: &'static str,
    pub availability: &'static str,
    pub bytes: Option<u64>,
    pub sha256: Option<String>,
}

fn validate_request_identity(raw: &[u8], job: &WorkerArgs) -> Result<(), String> {
    if raw.is_empty() || raw.len() as u64 > MAX_REQUEST_BYTES {
        return Err("missing or oversized Raito request".into());
    }
    let request: FetchRequest =
        serde_json::from_slice(raw).map_err(|_| "malformed Raito request")?;
    if request.schema != SCHEMA
        || request.network != "main"
        || Txid::from_str(&request.txid).map_err(|_| "invalid TXID")? != job.txid
        || BlockHash::from_str(&request.block_hash).map_err(|_| "invalid block hash")?
            != job.block_hash
        || request.block_height != job.height
    {
        return Err("request differs from authorized job identity".into());
    }
    Ok(())
}

/// Exactly one source must be explicitly declared. No preference or fallback.
/// The bridge configuration is parsed IN MEMORY; no client/cookie is opened.
/// A selected URL establishes only matching configuration metadata.
#[allow(dead_code)]
pub(super) fn select_offline(
    declaration: &[u8],
    request: &[u8],
    job: &WorkerArgs,
    configured_bridge_json: Option<&[u8]>,
) -> Result<SourceReadiness, String> {
    if declaration.is_empty() || declaration.len() as u64 > MAX_CONFIG_BYTES {
        return Err("missing or oversized source declaration".into());
    }
    validate_request_identity(request, job)?;
    let selected: Selection =
        serde_json::from_slice(declaration).map_err(|_| "malformed source declaration")?;
    if selected.schema != SELECTION_SCHEMA {
        return Err("unsupported source declaration schema".into());
    }
    match (selected.local_artifact, selected.bridge) {
        (Some(local), None) => {
            if !local.path.is_absolute()
                || !is_sha256(&local.sha256)
                || !(1..=MAX_COMPRESSED_PROOF_BYTES).contains(&local.bytes)
            {
                return Err("invalid local artifact declaration".into());
            }
            // No symlink, empty file, or file larger than the fetcher's
            // existing 16 MiB output cap is accepted. No decompression.
            let before = fs::symlink_metadata(&local.path)
                .map_err(|_| "declared local artifact unavailable")?;
            if !before.file_type().is_file() || before.len() != local.bytes {
                return Err("declared artifact type or length mismatch".into());
            }
            let bytes = read_bounded_regular(&local.path, MAX_COMPRESSED_PROOF_BYTES)
                .map_err(|_| "declared artifact is missing, unsafe or oversized")?;
            if bytes.len() as u64 != local.bytes
                || sha256::Hash::hash(&bytes).to_string() != local.sha256.to_lowercase()
            {
                return Err("declared artifact bytes or SHA-256 mismatch".into());
            }
            let after =
                fs::symlink_metadata(&local.path).map_err(|_| "declared artifact disappeared")?;
            if !after.file_type().is_file()
                || after.len() != local.bytes
                || before.len() != after.len()
            {
                return Err("declared artifact changed during inspection".into());
            }
            Ok(SourceReadiness {
                kind: "declared_local_artifact",
                integrity: "declared_bytes_sha256_match",
                acceptance: "UNVERIFIED",
                availability: "local_bytes_observed_only",
                bytes: Some(local.bytes),
                sha256: Some(local.sha256.to_lowercase()),
            })
        }
        (None, Some(bridge)) => {
            let raw = configured_bridge_json.ok_or("bridge config not supplied")?;
            if raw.is_empty() || raw.len() as u64 > MAX_CONFIG_BYTES {
                return Err("missing or oversized bridge config".into());
            }
            let config: FetchConfig =
                serde_json::from_slice(raw).map_err(|_| "malformed existing fetch config")?;
            validate_url(&bridge.raito_bridge_url, false)?;
            validate_url(&config.raito_bridge_url, false)?;
            validate_url(&config.bitcoin_rpc_url, true)?;
            if !config.client_binary.is_absolute()
                || !config.bitcoin_rpc_cookie_file.is_absolute()
                || !is_sha256(&config.client_sha256)
                || !is_sha256(&bridge.client_sha256)
                || bridge.raito_bridge_url != config.raito_bridge_url
                || bridge.client_sha256.to_lowercase() != config.client_sha256.to_lowercase()
            {
                return Err("bridge source differs from existing fetch configuration".into());
            }
            Ok(SourceReadiness {
                kind: "configured_bridge_metadata",
                integrity: "configuration_fields_match_only",
                acceptance: "UNVERIFIED",
                availability: "NOT_CHECKED",
                bytes: None,
                sha256: None,
            })
        }
        (None, None) => Err("source missing; select exactly one".into()),
        (Some(_), Some(_)) => Err("ambiguous conflicting sources; no precedence defined".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env, fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn job() -> WorkerArgs {
        WorkerArgs {
            input: PathBuf::from("/synthetic/request"),
            output: PathBuf::from("/synthetic/output"),
            txid: Txid::from_str(&"12".repeat(32)).unwrap(),
            block_hash: BlockHash::from_str(&"ab".repeat(32)).unwrap(),
            height: 300,
        }
    }
    fn request() -> Vec<u8> {
        serde_json::json!({"schema":SCHEMA,"network":"main",
            "txid":"12".repeat(32),"block_hash":"ab".repeat(32),
            "block_height":300})
        .to_string()
        .into_bytes()
    }
    fn select(local: Option<serde_json::Value>, bridge: Option<serde_json::Value>) -> Vec<u8> {
        serde_json::json!({"schema":SELECTION_SCHEMA,
            "local_artifact":local,"bridge":bridge})
        .to_string()
        .into_bytes()
    }
    fn bridge() -> serde_json::Value {
        serde_json::json!({"raito_bridge_url":"https://api.raito.wtf",
            "client_sha256":"cd".repeat(32)})
    }
    fn config() -> Vec<u8> {
        serde_json::json!({"client_binary":"/synthetic/client",
            "client_sha256":"cd".repeat(32),
            "bitcoin_rpc_url":"http://127.0.0.1:8332",
            "bitcoin_rpc_cookie_file":"/synthetic/not-read.cookie",
            "raito_bridge_url":"https://api.raito.wtf"})
        .to_string()
        .into_bytes()
    }
    fn temp_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = env::temp_dir().join(format!(
            "raito-source-offline-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        dir
    }
    fn local(path: &std::path::Path, payload: &[u8]) -> serde_json::Value {
        serde_json::json!({"path":path,
            "bytes":payload.len(),"sha256":sha256::Hash::hash(payload).to_string()})
    }
    #[test]
    fn explicit_source_required_and_ambiguity_fails_closed() {
        assert!(select_offline(&select(None, None), &request(), &job(), None).is_err());
        assert!(select_offline(
            &select(Some(serde_json::json!({})), Some(bridge())),
            &request(),
            &job(),
            Some(&config())
        )
        .unwrap_err()
        .contains("ambiguous"));
        assert!(select_offline(b"{}", &request(), &job(), None).is_err());
        assert!(select_offline(b"{", &request(), &job(), None).is_err());
        assert!(select_offline(&vec![b'x'; 8193], &request(), &job(), None).is_err());
    }
    #[test]
    fn bridge_metadata_never_means_availability_or_verification() {
        let ok = select_offline(
            &select(None, Some(bridge())),
            &request(),
            &job(),
            Some(&config()),
        )
        .unwrap();
        assert_eq!(ok.acceptance, "UNVERIFIED");
        assert_eq!(ok.availability, "NOT_CHECKED");
        assert_eq!(ok.bytes, None);
        assert!(select_offline(&select(None, Some(bridge())), &request(), &job(), None).is_err());
        let mut wrong = bridge();
        wrong["client_sha256"] = serde_json::json!("ef".repeat(32));
        assert!(select_offline(
            &select(None, Some(wrong)),
            &request(),
            &job(),
            Some(&config())
        )
        .is_err());
        let mut wrong = bridge();
        wrong["raito_bridge_url"] = serde_json::json!("https://different.example");
        assert!(select_offline(
            &select(None, Some(wrong)),
            &request(),
            &job(),
            Some(&config())
        )
        .is_err());
        let mut bad = bridge();
        bad["raito_bridge_url"] = serde_json::json!("http://api.raito.wtf");
        assert!(select_offline(
            &select(None, Some(bad)),
            &request(),
            &job(),
            Some(&config())
        )
        .is_err());
    }
    #[test]
    fn request_identity_and_schema_mismatch_rejected() {
        let decl = select(None, Some(bridge()));
        let mut mismatched: serde_json::Value = serde_json::from_slice(&request()).unwrap();
        mismatched["block_height"] = serde_json::json!(301);
        assert!(select_offline(
            &decl,
            &mismatched.to_string().into_bytes(),
            &job(),
            Some(&config())
        )
        .is_err());
        mismatched["block_height"] = serde_json::json!(300);
        mismatched["network"] = serde_json::json!("signet");
        assert!(select_offline(
            &decl,
            &mismatched.to_string().into_bytes(),
            &job(),
            Some(&config())
        )
        .is_err());
        assert!(select_offline(&decl, &vec![b'x'; 4097], &job(), Some(&config())).is_err());
        let unknown = serde_json::json!({"schema":SELECTION_SCHEMA,"bridge":bridge(),
            "unexpected":true})
        .to_string();
        assert!(select_offline(unknown.as_bytes(), &request(), &job(), Some(&config())).is_err());
    }
    #[test]
    fn local_bytes_hash_and_limits_are_observations_only() {
        let dir = temp_dir();
        let p = dir.join("synthetic.bin");
        fs::write(&p, b"synthetic-not-raito").unwrap();
        let payload = b"synthetic-not-raito";
        let ok = select_offline(
            &select(Some(local(&p, payload)), None),
            &request(),
            &job(),
            None,
        )
        .unwrap();
        assert_eq!(ok.kind, "declared_local_artifact");
        assert_eq!(ok.integrity, "declared_bytes_sha256_match");
        assert_eq!(ok.acceptance, "UNVERIFIED");
        assert!(select_offline(
            &select(Some(local(&p, b"wrong")), None),
            &request(),
            &job(),
            None
        )
        .is_err());
        assert!(select_offline(
            &select(Some(local(&dir.join("missing"), payload)), None),
            &request(),
            &job(),
            None
        )
        .is_err());
        fs::write(&p, vec![b'x'; (MAX_COMPRESSED_PROOF_BYTES + 1) as usize]).unwrap();
        assert!(select_offline(
            &select(Some(local(&p, &[b'x'])), None),
            &request(),
            &job(),
            None
        )
        .is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn symlinked_artifact_refused() {
        let dir = temp_dir();
        let real = dir.join("real");
        let link = dir.join("link");
        fs::write(&real, b"synthetic").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(select_offline(
            &select(Some(local(&link, b"synthetic")), None),
            &request(),
            &job(),
            None
        )
        .is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
