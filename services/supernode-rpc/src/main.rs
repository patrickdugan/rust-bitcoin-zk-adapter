//! Locally bound authenticated Bitcoin Core RPC superset.
use rust_bitcoin_supernode_rpc::cache::{ArtifactStore, MAX_STORE_BYTES};
use rust_bitcoin_supernode_rpc::chain::{
    run_sequence_subscriber, validate_local_sequence_endpoint, ChainTracker,
};
use rust_bitcoin_supernode_rpc::jobs::{JobLimits, JobManager, WorkerPrograms};
#[cfg(unix)]
use rust_bitcoin_supernode_rpc::broker::BrokerClient;
use rust_bitcoin_supernode_rpc::verification::RaitoVerifier;
use rust_bitcoin_supernode_rpc::{router, CoreRpc, Gateway};
use std::sync::Arc;
use std::{env, error::Error, net::SocketAddr};

fn credential_pair() -> Result<(String, String), Box<dyn Error>> {
    if let Ok(path) = env::var("BITCOIN_RPC_COOKIE_FILE") {
        let cookie = std::fs::read_to_string(path)?;
        let (username, password) = cookie
            .trim()
            .split_once(':')
            .ok_or("invalid Bitcoin Core cookie format")?;
        return Ok((username.to_owned(), password.to_owned()));
    }
    Ok((
        env::var("BITCOIN_RPC_USER")?,
        env::var("BITCOIN_RPC_PASSWORD")?,
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let upstream = env::var("BITCOIN_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8332".into());
    let bind: SocketAddr = env::var("SUPERNODE_BIND")
        .unwrap_or_else(|_| "127.0.0.1:18444".into())
        .parse()?;
    if !bind.ip().is_loopback() {
        return Err("Supernode v0.1 must bind to loopback".into());
    }
    if let Some(raw) = env::var_os("SUPERNODE_REQUIRE_CGROUP_MAX_MIB") {
        let limit: u32 = raw
            .into_string()
            .map_err(|_| "invalid cgroup MiB limit encoding")?
            .parse()?;
        if !(128..=32_768).contains(&limit) {
            return Err("cgroup MiB limit outside permitted range".into());
        }
    }
    let token = env::var("SUPERNODE_RPC_TOKEN")?;
    let max_inflight = env::var("SUPERNODE_MAX_INFLIGHT")
        .unwrap_or_else(|_| "4".into())
        .parse()?;
    let (username, password) = credential_pair()?;
    let core = CoreRpc::new(&upstream, username, password)?;
    let endpoint = env::var("BITCOIN_ZMQ_SEQUENCE_URL").ok();
    if let Some(ref url) = endpoint {
        validate_local_sequence_endpoint(url)?;
    }
    let tracker = Arc::new(ChainTracker::new(endpoint.is_some()));
    let mut gateway =
        Gateway::new(core.clone(), token, max_inflight)?.with_chain_tracker(tracker.clone());
    let control = env::var("SUPERNODE_CONTROL_TOKEN").ok();
    if env::var("SUPERNODE_ARTIFACT_DIR").is_ok() && control.is_none() {
        return Err("SUPERNODE_CONTROL_TOKEN is required when artifact storage is enabled".into());
    }
    if let Some(control) = control {
        gateway = gateway.with_control_token(control)?;
    }
    let mut artifacts = None;
    if let Ok(root) = env::var("SUPERNODE_ARTIFACT_DIR") {
        let bytes: u64 = env::var("SUPERNODE_ARTIFACT_BUDGET_BYTES")
            .unwrap_or_else(|_| MAX_STORE_BYTES.to_string())
            .parse()?;
        let store = Arc::new(ArtifactStore::new(root.into(), bytes)?);
        gateway = gateway.with_artifact_store(store.clone());
        artifacts = Some(store);
    }
    if let Ok(path) = env::var("SUPERNODE_JOB_DIR") {
        let store = artifacts.ok_or("proof jobs require SUPERNODE_ARTIFACT_DIR")?;
        let budget: u32 = env::var("SUPERNODE_PROOF_MEMORY_MIB")
            .unwrap_or_else(|_| "4096".into())
            .parse()?;
        let workers: usize = env::var("SUPERNODE_PROOF_WORKERS")
            .unwrap_or_else(|_| "1".into())
            .parse()?;
        #[cfg(unix)]
        let broker_socket = env::var("SUPERNODE_PROOF_BROKER_SOCKET").ok();
        #[cfg(not(unix))]
        let broker_socket: Option<String> = None;
        if broker_socket.is_some()
            && (env::var("SUPERNODE_RAITO_PROVER").is_ok()
                || env::var("SUPERNODE_SHINIGAMI_PROVER").is_ok()
                || env::var("SUPERNODE_RAITO_FETCH_CONFIG").is_ok())
        {
            return Err("isolated broker owns worker binaries/config; remove gateway direct-worker settings".into());
        }
        if broker_socket.is_none()
            && (env::var("SUPERNODE_RAITO_PROVER").is_ok()
                || env::var("SUPERNODE_SHINIGAMI_PROVER").is_ok())
            && env::var("SUPERNODE_ALLOW_SAME_UID_WORKERS").as_deref() != Ok("1")
        {
            return Err("direct same-UID worker execution needs explicit development opt-in".into());
        }
        let backend = WorkerPrograms {
            raito: env::var("SUPERNODE_RAITO_PROVER").ok().map(Into::into),
            shinigami: env::var("SUPERNODE_SHINIGAMI_PROVER").ok().map(Into::into),
        };
        let verifier = match env::var("SUPERNODE_RAITO_VERIFIER") {
            Ok(executable) => Some(RaitoVerifier {
                executable: executable.into(),
                binary_sha256: env::var("SUPERNODE_RAITO_VERIFIER_SHA256")?,
            }),
            Err(_) => None,
        };
        let manager = JobManager::new_with_verifier(
            path.into(),
            store,
            core.clone(),
            tracker.clone(),
            backend,
            verifier,
            JobLimits {
                memory_budget_mib: budget,
                worker_count: workers,
                raito_fetch_config: env::var("SUPERNODE_RAITO_FETCH_CONFIG")
                    .ok()
                    .map(Into::into),
            },
        )?;
        #[cfg(unix)]
        let manager = if let Some(socket) = broker_socket {
            let uid: u32 = env::var("SUPERNODE_PROOF_BROKER_UID")?.parse()?;
            if uid == nix::unistd::Uid::effective().as_raw() {
                return Err("broker must run with a UID distinct from gateway".into());
            }
            manager.with_broker(BrokerClient::new(socket.into(), uid)?)?
        } else {
            manager
        };
        gateway = gateway.with_job_manager(manager);
    }
    if let Some(url) = endpoint {
        tokio::spawn(run_sequence_subscriber(url, tracker, core));
    }
    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!(
        "Bitcoin supernode RPC listening at {}",
        listener.local_addr()?
    );
    axum::serve(listener, router(gateway)).await?;
    Ok(())
}
