//! Client of the optional isolated proof-producing worker service.
//! The broker runs under a distinct UID and can return only unverified
//! proof bytes. The gateway independently rehashes all received data and
//! then calls its pinned Raito verifier before publishing any receipt.

use crate::jobs::{JobKind, JobRecord};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use std::{path::{Path, PathBuf}, time::Duration};
use supernode_worker_broker_protocol::{
    read_header, write_header, RunReply, RunRequest, VERSION, MAX_INPUT_BYTES,
    TRANSFER_CHUNK_BYTES,
};
use tokio::{
    fs::OpenOptions,
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

const MAX_BROKER_DURATION: Duration = Duration::from_secs(660);

#[derive(Clone, Debug)]
pub struct BrokerClient {
    socket: PathBuf,
    expected_uid: u32,
}

impl BrokerClient {
    pub fn new(socket: PathBuf, expected_uid: u32) -> Result<Self, String> {
        if !socket.is_absolute() || socket.to_string_lossy().len() > 512 {
            return Err("broker socket path must be an absolute, bounded Unix path".into());
        }
        Ok(Self { socket, expected_uid })
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Run the approved Raito backend through the dedicated lower-trust
    /// service, importing its bytes into a gateway-owned output file.
    pub async fn run(
        &self,
        record: &JobRecord,
        input: &[u8],
        output: &Path,
    ) -> Result<(), String> {
        if record.kind != JobKind::Raito {
            return Err("isolated broker presently supports only Raito workers".into());
        }
        if input.is_empty() || input.len() > MAX_INPUT_BYTES {
            return Err("broker input is absent or larger than the bounded cache".into());
        }
        let request = RunRequest {
            version: VERSION,
            job_id: record.id.clone(),
            backend: "raito".into(),
            network: record.network.clone(),
            block_hash: record.block_hash.clone(),
            block_height: record.block_height,
            policy_sha256: record.policy_sha256.clone(),
            expected_txid: record.expected_txid.clone(),
            input_bytes: input.len() as u64,
        };
        request.validate()?;
        let result = timeout(MAX_BROKER_DURATION, self.transfer(&request, input, output))
            .await
            .map_err(|_| "broker worker or proof transfer exceeded deadline".to_owned())?;
        if result.is_err() {
            let _ = tokio::fs::remove_file(output).await;
        }
        result
    }

    async fn transfer(
        &self,
        request: &RunRequest,
        input: &[u8],
        output: &Path,
    ) -> Result<(), String> {
        let mut stream = UnixStream::connect(&self.socket).await.map_err(|e| e.to_string())?;
        let peer = stream.peer_cred().map_err(|e| e.to_string())?;
        if peer.uid() != self.expected_uid {
            return Err("broker socket peer UID differs from operator-approved UID".into());
        }
        write_header(&mut stream, request).await?;
        stream.write_all(input).await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;
        let reply: RunReply = read_header(&mut stream).await?;
        if !reply.ok {
            return Err(format!(
                "broker rejected job: {}",
                reply.error.as_deref().unwrap_or("unspecified broker failure")
            ));
        }
        let (length, expected_sha) = reply.accepted()?;
        // The gateway creates this file under its 0700 job directory. A
        // broker/worker identity cannot address, traverse or overwrite it.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .await
            .map_err(|e| e.to_string())?;
        let mut remaining = length;
        let mut engine = sha256::Hash::engine();
        let mut buffer = [0u8; TRANSFER_CHUNK_BYTES];
        while remaining > 0 {
            let count = remaining.min(TRANSFER_CHUNK_BYTES as u64) as usize;
            stream.read_exact(&mut buffer[..count]).await.map_err(|e| e.to_string())?;
            engine.input(&buffer[..count]);
            file.write_all(&buffer[..count]).await.map_err(|e| e.to_string())?;
            remaining -= count as u64;
        }
        file.sync_all().await.map_err(|e| e.to_string())?;
        let got = sha256::Hash::from_engine(engine).to_string();
        if got != expected_sha {
            return Err("broker transfer differs from its declared SHA-256".into());
        }
        // The index and proof verification are performed by the gateway
        // after this transfer. The broker's hash is never an attestation.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs::{JobStatus, JobRecord};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::net::UnixListener;
    use supernode_worker_broker_protocol::{write_header, RunReply};

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "supernode-gateway-broker-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ))
    }
    fn record() -> JobRecord {
        JobRecord {
            id: "aa".repeat(32),
            kind: JobKind::Raito,
            input_artifact_id: "bb".repeat(32),
            network: "main".into(),
            block_hash: "cc".repeat(32),
            block_height: 500,
            chain_epoch: 0,
            policy_sha256: "dd".repeat(32),
            estimated_memory_mib: 1,
            expected_txid: Some("ee".repeat(32)),
            status: JobStatus::Running,
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
    async fn bounded_transfer_checks_peer_uid_and_digest() {
        let root = temp_root();
        std::fs::create_dir_all(&root).unwrap();
        let socket = root.join("worker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let uid = nix::unistd::Uid::effective().as_raw();
        let broker = BrokerClient::new(socket, uid).unwrap();
        let payload = b"synthetic-unverified-broker-proof".to_vec();
        let response = payload.clone();
        let task = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let req: RunRequest = read_header(&mut peer).await.unwrap();
            req.validate().unwrap();
            let mut input = vec![0u8; req.input_bytes as usize];
            peer.read_exact(&mut input).await.unwrap();
            assert_eq!(&input, b"input-manifest");
            write_header(&mut peer, &RunReply {
                version: VERSION, ok: true,
                output_bytes: response.len() as u64,
                result_sha256: Some(sha256::Hash::hash(&response).to_string()),
                error: None,
            }).await.unwrap();
            peer.write_all(&response).await.unwrap();
        });
        let output = root.join("proof.out");
        broker.run(&record(), b"input-manifest", &output).await.unwrap();
        task.await.unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), payload);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn wrong_peer_uid_is_rejected_before_upload() {
        let root = temp_root();
        std::fs::create_dir_all(&root).unwrap();
        let socket = root.join("worker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let uid = nix::unistd::Uid::effective().as_raw();
        let broker = BrokerClient::new(socket, uid.wrapping_add(1)).unwrap();
        let task = tokio::spawn(async move {
            let _connection = listener.accept().await.unwrap();
        });
        assert!(broker.run(&record(), b"input-manifest", &root.join("out")).await.is_err());
        task.await.unwrap();
        assert!(!root.join("out").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
