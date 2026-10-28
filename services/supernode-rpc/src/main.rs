//! Locally bound authenticated Bitcoin Core RPC superset.
#[cfg(unix)]
use rust_bitcoin_supernode_rpc::broker::BrokerClient;
use rust_bitcoin_supernode_rpc::cache::{ArtifactStore, MAX_STORE_BYTES};
use rust_bitcoin_supernode_rpc::chain::{
    run_sequence_subscriber, validate_local_sequence_endpoint, ChainTracker,
};
use rust_bitcoin_supernode_rpc::jobs::{JobLimits, JobManager, WorkerPrograms};
use rust_bitcoin_supernode_rpc::statements::{
    NovaPolicy, PaymentPolicy, PinnedProgram, StatementVerifiers,
};
use rust_bitcoin_supernode_rpc::verification::RaitoVerifier;
#[cfg(unix)]
use rust_bitcoin_supernode_rpc::verification_broker::IsolatedRaitoVerifier;
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

/// Operator pins for client-submitted statement proofs. Each verifier is
/// enabled only when its executable variable is set.
fn statement_verifiers(dir: std::path::PathBuf) -> Result<StatementVerifiers, Box<dyn Error>> {
    let program = |prefix: &str| -> Result<Option<PinnedProgram>, Box<dyn Error>> {
        Ok(match env::var(format!("{prefix}_VERIFIER")) {
            Ok(path) => Some(PinnedProgram {
                executable: path.into(),
                binary_sha256: env::var(format!("{prefix}_VERIFIER_SHA256"))?,
            }),
            Err(_) => None,
        })
    };
    let nova = match program("SUPERNODE_NOVA")? {
        Some(program) => Some(NovaPolicy {
            program,
            vk_path: env::var("SUPERNODE_NOVA_VK")?.into(),
            vk_sha256: env::var("SUPERNODE_NOVA_VK_SHA256")?,
            checkpoints: env::var("SUPERNODE_NOVA_CHECKPOINTS")?
                .split(',')
                .map(|c| c.trim().to_owned())
                .collect(),
        }),
        None => None,
    };
    let payment = match program("SUPERNODE_PAYMENT")? {
        Some(program) => {
            let words = env::var("SUPERNODE_PAYMENT_PROGRAM_WORDS")?;
            let words: Vec<&str> = words.split(',').map(str::trim).collect();
            let [node, leaf, segment] = words[..] else {
                return Err("SUPERNODE_PAYMENT_PROGRAM_WORDS needs node,leaf,segment".into());
            };
            Some(PaymentPolicy {
                program,
                pay_vkey: env::var("SUPERNODE_PAYMENT_PAY_VKEY")?,
                node_program_words: node.into(),
                leaf_program_words: leaf.into(),
                segment_program_words: segment.into(),
            })
        }
        None => None,
    };
    Ok(StatementVerifiers::new(dir, nova, payment)?)
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
    if env::var("SUPERNODE_STATEMENT_DIR").is_ok() && control.is_none() {
        return Err(
            "SUPERNODE_CONTROL_TOKEN is required when statement verifiers are enabled".into(),
        );
    }
    if let Some(control) = control {
        gateway = gateway.with_control_token(control)?;
    }
    if let Ok(dir) = env::var("SUPERNODE_STATEMENT_DIR") {
        gateway = gateway.with_statement_verifiers(Arc::new(statement_verifiers(dir.into())?));
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
        #[cfg(unix)]
        if broker_socket.is_some() && nix::unistd::Uid::effective().is_root() {
            return Err("isolated Supernode gateway must use an unprivileged OS UID".into());
        }
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
            return Err(
                "direct same-UID worker execution needs explicit development opt-in".into(),
            );
        }
        let backend = WorkerPrograms {
            raito: env::var("SUPERNODE_RAITO_PROVER").ok().map(Into::into),
            shinigami: env::var("SUPERNODE_SHINIGAMI_PROVER").ok().map(Into::into),
        };
        #[cfg(unix)]
        let verify_socket = env::var("SUPERNODE_PROOF_VERIFIER_SOCKET").ok();
        #[cfg(not(unix))]
        let verify_socket: Option<String> = None;
        if verify_socket.is_some() && broker_socket.is_none() {
            return Err(
                "separate-UID Raito verification requires separate-UID proof production".into(),
            );
        }
        if verify_socket.is_some() && env::var("SUPERNODE_RAITO_VERIFIER").is_ok() {
            return Err("isolated verifier socket excludes gateway direct STARK executable".into());
        }
        if verify_socket.is_none()
            && env::var("SUPERNODE_RAITO_VERIFIER").is_ok()
            && env::var("SUPERNODE_ALLOW_SAME_UID_VERIFIER").as_deref() != Ok("1")
        {
            return Err(
                "direct same-UID STARK verifier requires explicit development opt-in".into(),
            );
        }
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
        #[cfg(unix)]
        let manager = if let Some(socket) = verify_socket {
            let uid: u32 = env::var("SUPERNODE_PROOF_VERIFIER_UID")?.parse()?;
            let producer: u32 = env::var("SUPERNODE_PROOF_BROKER_UID")?.parse()?;
            if uid == producer {
                return Err("Raito verifier and proof producer must use distinct OS UIDs".into());
            }
            manager.with_isolated_verifier(IsolatedRaitoVerifier::new(socket.into(), uid)?)?
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
