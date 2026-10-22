//! Gateway client for a separately privileged Raito STARK verification
//! service. Proof bytes originate in the gateway-owned job store, and only
//! an authenticated verifier UID can return a typed Raito proof statement.

use crate::{jobs::JobRecord, verification::RaitoVerifiedReceipt};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use std::{
    fs,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
use supernode_worker_broker_protocol::{
    read_header, write_header, VerifyReply, VerifyRequest,
    MAX_VERIFY_PROOF_BYTES, TRANSFER_CHUNK_BYTES, VERSION,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

const VERIFIER_ROUNDTRIP: Duration = Duration::from_secs(660);

#[derive(Clone, Debug)]
pub struct IsolatedRaitoVerifier {
    socket: PathBuf,
    uid: u32,
}

impl IsolatedRaitoVerifier {
    pub fn new(socket: PathBuf, uid: u32) -> Result<Self, String> {
        if !socket.is_absolute() || socket.to_string_lossy().len() > 512 {
            return Err("isolated Raito verifier socket path must be absolute and bounded".into());
        }
        if uid == nix::unistd::Uid::effective().as_raw() {
            return Err("Raito verifier must use a UID distinct from gateway".into());
        }
        Ok(Self { socket, uid })
    }

    pub async fn verify(
        &self,
        root: &Path,
        record: &JobRecord,
        digest: &str,
    ) -> Result<RaitoVerifiedReceipt, String> {
        timeout(VERIFIER_ROUNDTRIP, self.transfer(root, record, digest))
            .await
            .map_err(|_| "isolated Raito verifier exceeded IPC execution deadline".to_owned())?
    }

    async fn transfer(
        &self,
        root: &Path,
        record: &JobRecord,
        digest: &str,
    ) -> Result<RaitoVerifiedReceipt, String> {
        let txid = record.expected_txid.as_deref()
            .ok_or("expected transaction ID required for isolated Raito verification")?;
        let proof = root.join(format!("{}.output", record.id));
        let info = fs::symlink_metadata(&proof).map_err(|e| e.to_string())?;
        if !info.file_type().is_file()
            || info.len() == 0
            || info.len() > MAX_VERIFY_PROOF_BYTES
        {
            return Err("Raito compressed proof missing or outside 16 MiB bound".into());
        }
        let request = VerifyRequest {
            version: VERSION,
            job_id: record.id.clone(),
            network: record.network.clone(),
            expected_txid: txid.to_owned(),
            block_hash: record.block_hash.clone(),
            block_height: record.block_height,
            policy_sha256: record.policy_sha256.clone(),
            proof_sha256: digest.to_owned(),
            proof_bytes: info.len(),
        };
        request.validate()?;
        let mut stream = UnixStream::connect(&self.socket).await.map_err(|e| e.to_string())?;
        if !stream.peer_cred().is_ok_and(|peer| peer.uid() == self.uid) {
            return Err("verifier socket peer UID differs from operator-approved verifier UID".into());
        }
        write_header(&mut stream, &request).await?;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&proof)
            .map_err(|e| e.to_string())?;
        let mut file = tokio::fs::File::from_std(file);
        let mut offset = 0u64;
        let mut sha = sha256::Hash::engine();
        let mut chunk = [0u8; TRANSFER_CHUNK_BYTES];
        while offset < request.proof_bytes {
            let length = (request.proof_bytes - offset).min(chunk.len() as u64) as usize;
            file.read_exact(&mut chunk[..length]).await.map_err(|e| e.to_string())?;
            stream.write_all(&chunk[..length]).await.map_err(|e| e.to_string())?;
            sha.input(&chunk[..length]);
            offset += length as u64;
        }
        stream.flush().await.map_err(|e| e.to_string())?;
        if sha256::Hash::from_engine(sha).to_string() != digest {
            return Err("Raito proof changed during transfer to isolated verifier".into());
        }
        let reply: VerifyReply = read_header(&mut stream).await?;
        let value = reply.accepted()?;
        let receipt: RaitoVerifiedReceipt =
            serde_json::from_value(value.clone())
                .map_err(|_| "isolated verifier returned malformed typed receipt")?;
        receipt.validate(record, digest)?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs::{JobKind, JobStatus};
    use crate::verification::{STATEMENT, VERIFIER_ID};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::net::UnixListener;

    fn record() -> JobRecord {
        JobRecord {
            id: "ab".repeat(32),
            kind: JobKind::Raito,
            input_artifact_id: "cd".repeat(32),
            network: "main".into(),
            block_hash: "ef".repeat(32),
            block_height: 900000,
            chain_epoch: 0,
            policy_sha256: "12".repeat(32),
            estimated_memory_mib: 1,
            expected_txid: Some("34".repeat(32)),
            status: JobStatus::VerifyingRaito,
            result_sha256: None,
            result_bytes: None,
            result_chunk_index_sha256: None,
            verified_raito: None,
            error: None,
            submitted_unix: 1,
            finished_unix: None,
        }
    }

    #[tokio::test]
    async fn verifier_ipc_rejects_unexpected_kernel_peer_uid() {
        let root = std::env::temp_dir().join(format!(
            "supernode-verifier-peer-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let record = record();
        let bytes = b"synthetic-unverified-not-a-real-STARK";
        fs::write(root.join(format!("{}.output", record.id)), bytes).unwrap();
        let socket = root.join("verifier.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let uid = nix::unistd::Uid::effective().as_raw();
        // Build a deliberately wrong UID: a real verifier must differ from
        // the gateway and the wrong socket peer is rejected before upload.
        let client = IsolatedRaitoVerifier {
            socket, uid: uid.wrapping_add(1),
        };
        let accept = tokio::spawn(async move {
            let _connection = listener.accept().await.unwrap();
        });
        let digest = sha256::Hash::hash(bytes).to_string();
        assert!(client.verify(&root, &record, &digest).await.is_err());
        accept.await.unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn verifier_ipc_rejects_forged_receipt_even_with_correct_bytes() {
        let root = std::env::temp_dir().join(format!(
            "supernode-verifier-proof-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let record = record();
        let bytes = b"synthetic-data-not-a-valid-raito-proof".to_vec();
        let digest = sha256::Hash::hash(&bytes).to_string();
        fs::write(root.join(format!("{}.output", record.id)), &bytes).unwrap();
        let socket = root.join("verify.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        // This IPC-only mock deliberately substitutes a different TXID.
        let claim = serde_json::json!({
            "statement":STATEMENT, "verifier":VERIFIER_ID,
            "txid":"ff".repeat(32), "block_hash":record.block_hash,
            "block_height":record.block_height, "proven_tip_height":900001,
            "tx_index":0,"proof_sha256":digest,
            "policy_sha256":record.policy_sha256
        });
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let req: VerifyRequest = read_header(&mut peer).await.unwrap();
            req.validate().unwrap();
            let mut all = vec![0; req.proof_bytes as usize];
            peer.read_exact(&mut all).await.unwrap();
            assert_eq!(all, bytes);
            write_header(&mut peer, &VerifyReply {
                version: VERSION, receipt: Some(claim), error: None,
            }).await.unwrap();
        });
        let client = IsolatedRaitoVerifier {
            socket, uid: nix::unistd::Uid::effective().as_raw()
        };
        assert!(client.verify(&root, &record, &digest).await.is_err());
        server.await.unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
