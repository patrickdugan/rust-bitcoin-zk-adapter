//! Gateway client for the separate-UID statement verifier broker. The broker
//! runs the pinned Nova and SP1 payment verifiers and returns their stdout;
//! the gateway still parses the typed receipt and binds it to Bitcoin Core.

use bitcoin::hashes::{sha256, Hash};
use std::{path::PathBuf, time::Duration};
use supernode_worker_broker_protocol::{
    read_header, write_header, StatementRunReply, StatementRunRequest, VERSION,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

/// The broker allows a verifier 300 s; leave room for transfer and reaping.
const BROKER_ROUNDTRIP: Duration = Duration::from_secs(330);

#[derive(Clone, Debug)]
pub struct IsolatedStatementRunner {
    socket: PathBuf,
    uid: u32,
}

impl IsolatedStatementRunner {
    pub fn new(socket: PathBuf, uid: u32) -> Result<Self, String> {
        if !socket.is_absolute() || socket.to_string_lossy().len() > 512 {
            return Err("statement verifier socket path must be absolute and bounded".into());
        }
        if uid == 0 || uid == nix::unistd::Uid::effective().as_raw() {
            return Err("statement verifier must use a non-root UID distinct from gateway".into());
        }
        Ok(Self { socket, uid })
    }

    /// Run the broker's pinned verifier for `kind` on `bundle`: whether it
    /// exited successfully, its exit status, and its bounded stdout.
    pub async fn run(&self, kind: &str, bundle: &[u8]) -> Result<(bool, String, Vec<u8>), String> {
        timeout(BROKER_ROUNDTRIP, self.exchange(kind, bundle))
            .await
            .map_err(|_| "statement verifier broker exceeded its deadline".to_owned())?
    }

    async fn exchange(&self, kind: &str, bundle: &[u8]) -> Result<(bool, String, Vec<u8>), String> {
        let request = StatementRunRequest {
            version: VERSION,
            kind: kind.into(),
            bundle_sha256: sha256::Hash::hash(bundle).to_string(),
            bundle_bytes: bundle.len() as u64,
        };
        request.validate()?;
        let mut stream = UnixStream::connect(&self.socket)
            .await
            .map_err(|e| format!("statement verifier socket: {e}"))?;
        if !stream.peer_cred().is_ok_and(|peer| peer.uid() == self.uid) {
            return Err(
                "statement verifier socket peer UID differs from the operator-approved UID".into(),
            );
        }
        write_header(&mut stream, &request).await?;
        stream.write_all(bundle).await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;
        let reply: StatementRunReply = read_header(&mut stream).await?;
        let length = reply.completed()?;
        let mut stdout = vec![0u8; length as usize];
        stream
            .read_exact(&mut stdout)
            .await
            .map_err(|e| e.to_string())?;
        Ok((reply.exit_success, reply.exit_status, stdout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    fn socket_path(tag: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("stmt-{tag}-{}-{stamp}.sock", std::process::id()))
    }

    #[test]
    fn refuses_own_uid_and_relative_socket() {
        let own = nix::unistd::Uid::effective().as_raw();
        assert!(IsolatedStatementRunner::new(PathBuf::from("/run/s.sock"), own).is_err());
        assert!(IsolatedStatementRunner::new(PathBuf::from("s.sock"), own + 1).is_err());
        assert!(IsolatedStatementRunner::new(PathBuf::from("/run/s.sock"), 0).is_err());
    }

    /// A listener under the gateway's own UID is not the approved broker:
    /// the client refuses it before sending the bundle.
    #[tokio::test]
    async fn refuses_a_peer_with_the_wrong_uid() {
        let path = socket_path("peer");
        let listener = UnixListener::bind(&path).unwrap();
        let accept = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut seen = Vec::new();
            let _ = peer.read_to_end(&mut seen).await;
            seen
        });
        let runner = IsolatedStatementRunner {
            socket: path.clone(),
            uid: nix::unistd::Uid::effective().as_raw() + 1,
        };
        let err = runner
            .run("sp1_btc_payment_v1", b"bundle")
            .await
            .unwrap_err();
        assert!(err.contains("peer UID"), "{err}");
        assert!(
            accept.await.unwrap().is_empty(),
            "no bytes reached the peer"
        );
        let _ = std::fs::remove_file(path);
    }

    /// The reply framing: header, then exactly `stdout_bytes` raw bytes.
    #[tokio::test]
    async fn reads_stdout_after_the_reply_header() {
        let path = socket_path("reply");
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let req: StatementRunRequest = read_header(&mut peer).await.unwrap();
            let mut bundle = vec![0u8; req.bundle_bytes as usize];
            peer.read_exact(&mut bundle).await.unwrap();
            assert_eq!(req.bundle_sha256, sha256::Hash::hash(&bundle).to_string());
            let stdout = br#"{"error":"bad proof"}"#;
            let reply = StatementRunReply {
                version: VERSION,
                exit_success: false,
                exit_status: "exit status: 1".into(),
                stdout_bytes: stdout.len() as u64,
                error: None,
            };
            write_header(&mut peer, &reply).await.unwrap();
            peer.write_all(stdout).await.unwrap();
        });
        let runner = IsolatedStatementRunner {
            socket: path.clone(),
            uid: nix::unistd::Uid::effective().as_raw(),
        };
        let (ok, status, stdout) = runner.run("nova_header_chain_v1", b"x").await.unwrap();
        assert!(!ok);
        assert_eq!(status, "exit status: 1");
        assert_eq!(stdout, br#"{"error":"bad proof"}"#);
        assert!(runner.run("nova_spv_payment_v1", b"x").await.is_err());
        let _ = std::fs::remove_file(path);
    }
}
