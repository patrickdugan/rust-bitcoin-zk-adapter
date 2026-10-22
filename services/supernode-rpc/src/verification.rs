//! Trust boundary between durable worker output and an operator-pinned
//! Raito STARK verifier. A digest or a worker's exit code never proves a claim.
use crate::jobs::{JobKind, JobRecord};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{process::Command, time::timeout};

pub const VERIFIER_ID: &str = "raito-spv-verify/48c237ac941d8061a857ecd111d7e81107912556";
pub const STATEMENT: &str = "raito_spv_transaction_inclusion_v1";
const MAX_RECEIPT_BYTES: u64 = 4096;
const MAX_VERIFIER_BINARY_BYTES: u64 = 512 * 1024 * 1024;
const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Clone, Debug)]
pub struct RaitoVerifier {
    pub executable: PathBuf,
    /// SHA-256 pinned by the operator to the audited verifier executable.
    pub binary_sha256: String,
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn file_digest(path: &Path) -> Result<String, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.file_type().is_file() || meta.len() > MAX_VERIFIER_BINARY_BYTES {
        return Err("Raito verifier binary is absent, unsafe or oversized".into());
    }
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut engine = sha256::Hash::engine();
    let mut buffer = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_VERIFIER_BINARY_BYTES {
            return Err("Raito verifier executable changed while hashing".into());
        }
        engine.input(&buffer[..n]);
    }
    Ok(sha256::Hash::from_engine(engine).to_string())
}

impl RaitoVerifier {
    pub fn validate(&self) -> Result<(), String> {
        if !self.executable.is_absolute() || !valid_hash(&self.binary_sha256) {
            return Err("Raito verifier requires an absolute binary path and SHA-256 pin".into());
        }
        if file_digest(&self.executable)? != self.binary_sha256 {
            return Err("Raito verifier executable differs from the operator's SHA-256 pin".into());
        }
        Ok(())
    }

    /// The report is trusted only because the operator pinned the verifier
    /// executable. The external program calls real Raito STARK verification.
    pub async fn verify(
        &self,
        root: &Path,
        record: &JobRecord,
        result_sha256: &str,
    ) -> Result<RaitoVerifiedReceipt, String> {
        self.validate()?;
        let txid = record
            .expected_txid
            .as_deref()
            .ok_or("Raito verification requires an expected TXID")?;
        let output = root.join(format!("{}.output", record.id));
        let receipt_path = root.join(format!("{}.verifytmp", record.id));
        // create_new in the verifier prevents a stale or pre-planted receipt.
        if receipt_path.exists() {
            return Err("stale Raito verification receipt path".into());
        }

        let result = async {
            let mut command = Command::new(&self.executable);
            command
                .arg("--gateway")
                .arg(&output)
                .arg(txid)
                .arg(&record.block_hash)
                .arg(record.block_height.to_string())
                .arg(&record.policy_sha256)
                .arg(&receipt_path)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            // Forward only the operator-selected cgroup preflight gate.
            // An unrecognized/non-Unicode value fails closed in the worker.
            if let Some(limit) = std::env::var_os("SUPERNODE_REQUIRE_CGROUP_MAX_MIB") {
                command.env("SUPERNODE_REQUIRE_CGROUP_MAX_MIB", limit);
            }
            let status = timeout(VERIFICATION_TIMEOUT, command.status())
            .await
            .map_err(|_| "Raito verifier exceeded execution timeout".to_string())?
            .map_err(|e| e.to_string())?;
            if !status.success() {
                return Err(format!("Raito verifier rejected proof: {status}"));
            }
            let meta = fs::symlink_metadata(&receipt_path).map_err(|e| e.to_string())?;
            if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > MAX_RECEIPT_BYTES {
                return Err("Raito verifier returned unsafe or oversized receipt".into());
            }
            let mut bytes = Vec::with_capacity(meta.len() as usize);
            File::open(&receipt_path)
                .map_err(|e| e.to_string())?
                .take(MAX_RECEIPT_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() as u64 > MAX_RECEIPT_BYTES {
                return Err("Raito verifier receipt grew beyond size limit".into());
            }
            let report: RaitoVerifiedReceipt =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            report.validate(record, result_sha256)?;
            Ok(report)
        }
        .await;
        let _ = fs::remove_file(&receipt_path);
        result
    }
}

/// A typed statement accepted by the separately compiled Raito verifier.
/// Bitcoin Core's active-chain check is performed separately when published
/// and again whenever the gateway serves the receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RaitoVerifiedReceipt {
    pub statement: String,
    pub verifier: String,
    pub txid: String,
    pub block_hash: String,
    pub block_height: u32,
    pub proven_tip_height: u32,
    pub tx_index: u32,
    pub proof_sha256: String,
    pub policy_sha256: String,
}

impl RaitoVerifiedReceipt {
    pub fn validate(&self, record: &JobRecord, expected_digest: &str) -> Result<(), String> {
        if record.kind != JobKind::Raito
            || self.statement != STATEMENT
            || self.verifier != VERIFIER_ID
            || record.expected_txid.as_deref() != Some(self.txid.as_str())
            || self.block_hash != record.block_hash
            || u64::from(self.block_height) != record.block_height
            || self.proven_tip_height < self.block_height
            || self.policy_sha256 != record.policy_sha256
            || self.proof_sha256 != expected_digest
        {
            return Err("Raito receipt does not bind the job, proof, block and policy".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs::{JobKind, JobStatus};

    fn fixture() -> (JobRecord, RaitoVerifiedReceipt) {
        let receipt = RaitoVerifiedReceipt {
            statement: STATEMENT.into(),
            verifier: VERIFIER_ID.into(),
            txid: "ab".repeat(32),
            block_hash: "cd".repeat(32),
            block_height: 42,
            proven_tip_height: 43,
            tx_index: 5,
            proof_sha256: "ef".repeat(32),
            policy_sha256: "12".repeat(32),
        };
        let job = JobRecord {
            id: "34".repeat(32),
            kind: JobKind::Raito,
            input_artifact_id: "56".repeat(32),
            network: "regtest".into(),
            block_hash: receipt.block_hash.clone(),
            block_height: 42,
            chain_epoch: 0,
            policy_sha256: receipt.policy_sha256.clone(),
            estimated_memory_mib: 2,
            expected_txid: Some(receipt.txid.clone()),
            status: JobStatus::CompletedUnverified,
            result_sha256: Some(receipt.proof_sha256.clone()),
            result_bytes: Some(1024),
            result_chunk_index_sha256: None,
            verified_raito: None,
            error: None,
            submitted_unix: 1,
            finished_unix: Some(2),
        };
        (job, receipt)
    }

    #[test]
    fn receipt_claims_are_strictly_bound_to_expected_proof_and_block() {
        let (job, mut receipt) = fixture();
        assert!(receipt.validate(&job, &"ef".repeat(32)).is_ok());
        receipt.block_height = 43;
        assert!(receipt.validate(&job, &"ef".repeat(32)).is_err());
        receipt.block_height = 42;
        receipt.proof_sha256 = "ab".repeat(32);
        assert!(receipt.validate(&job, &"ef".repeat(32)).is_err());
        receipt.proof_sha256 = "ef".repeat(32);
        receipt.policy_sha256 = "cd".repeat(32);
        assert!(receipt.validate(&job, &"ef".repeat(32)).is_err());
        receipt.policy_sha256 = job.policy_sha256.clone();
        receipt.proven_tip_height = 41;
        assert!(receipt.validate(&job, &"ef".repeat(32)).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pinned_external_verifier_receipt_contract_rejects_replacement() {
        // The fixture is a *mock verifier* for IPC/receipt plumbing only.
        // Real Raito STARK verification lives in integrations/raito.
        use std::os::unix::fs::PermissionsExt;
        let (job, receipt) = fixture();
        let root =
            std::env::temp_dir().join(format!("raito-receipt-contract-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("mock-raito-verifier.sh");
        let script = format!(
            "#!/bin/sh\ncat > \"$7\" <<'RECEIPT'\n{}\nRECEIPT\n",
            serde_json::to_string(&receipt).unwrap()
        );
        fs::write(&executable, &script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let verifier = RaitoVerifier {
            executable: executable.clone(),
            binary_sha256: file_digest(&executable).unwrap(),
        };
        let actual = verifier
            .verify(&root, &job, &receipt.proof_sha256)
            .await
            .unwrap();
        assert_eq!(actual, receipt);
        assert!(!root.join(format!("{}.verifytmp", job.id)).exists());

        // A changed executable cannot be used with the old trusted pin.
        fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        assert!(verifier.validate().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn receipt_rejects_unknown_fields() {
        let (_, receipt) = fixture();
        let mut serialized = serde_json::to_value(&receipt).unwrap();
        serialized["untrusted"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RaitoVerifiedReceipt>(serialized).is_err());
    }
}
