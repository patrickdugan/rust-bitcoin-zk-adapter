//! Locally bound authenticated Bitcoin Core RPC superset.
use rust_bitcoin_supernode_rpc::cache::{ArtifactStore, MAX_STORE_BYTES};
use rust_bitcoin_supernode_rpc::chain::{
    run_sequence_subscriber, validate_local_sequence_endpoint, ChainTracker,
};
use rust_bitcoin_supernode_rpc::jobs::{JobManager, WorkerPrograms};
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
        let backend = WorkerPrograms {
            raito: env::var("SUPERNODE_RAITO_PROVER").ok().map(Into::into),
            shinigami: env::var("SUPERNODE_SHINIGAMI_PROVER").ok().map(Into::into),
        };
        let manager = JobManager::new(
            path.into(),
            store,
            core.clone(),
            tracker.clone(),
            backend,
            budget,
            workers,
        )?;
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
