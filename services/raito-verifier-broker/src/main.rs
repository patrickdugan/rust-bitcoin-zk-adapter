//! A separate-UID daemon for the operator-pinned, non-development Raito
//! Cairo/STWO verifier. A proof-producing worker cannot write its staging
//! area, substitute its executable, or directly claim a verification result.
use bitcoin::hashes::{sha256, Hash, HashEngine};
use serde::Deserialize;
use std::{
    env,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use supernode_worker_broker_protocol::{
    hex_hash, read_header, write_header, VerifyReply, VerifyRequest, TRANSFER_CHUNK_BYTES, VERSION,
};
use tokio::{
    io::AsyncReadExt,
    net::{UnixListener, UnixStream},
    process::Command,
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

const MAX_RECEIPT_BYTES: u64 = 4096;
const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_IO_IDLE: Duration = Duration::from_secs(30);
const MAX_VERIFIER_TIME: Duration = Duration::from_secs(600);
const STATEMENT: &str = "raito_spv_transaction_inclusion_v1";
const VERIFIER: &str = "raito-spv-verify/48c237ac941d8061a857ecd111d7e81107912556";

struct Config {
    socket: PathBuf,
    staging: PathBuf,
    gateway_uid: u32,
    binary: PathBuf,
    binary_sha: String,
    slots: Arc<Semaphore>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckedRaitoReceipt {
    statement: String,
    verifier: String,
    txid: String,
    block_hash: String,
    block_height: u32,
    proven_tip_height: u32,
    tx_index: u32,
    proof_sha256: String,
    policy_sha256: String,
}

impl CheckedRaitoReceipt {
    fn validate(&self, req: &VerifyRequest) -> Result<(), String> {
        if self.statement != STATEMENT
            || self.verifier != VERIFIER
            || self.txid != req.expected_txid
            || self.block_hash != req.block_hash
            || u64::from(self.block_height) != req.block_height
            || self.proven_tip_height < self.block_height
            || self.policy_sha256 != req.policy_sha256
            || self.proof_sha256 != req.proof_sha256
        {
            return Err("Raito receipt mismatched authorized statement".into());
        }
        let _index = self.tx_index;
        Ok(())
    }
}

fn digest(path: &Path, maximum: u64) -> Result<(String, u64), String> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.file_type().is_file() || m.len() == 0 || m.len() > maximum {
        return Err("unsafe, absent or oversized verifier file".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| e.to_string())?;
    let mut hash = sha256::Hash::engine();
    let mut total = 0u64;
    let mut chunk = [0u8; TRANSFER_CHUNK_BYTES];
    loop {
        let n = file.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > maximum {
            return Err("verifier file changed or grew beyond cap".into());
        }
        hash.input(&chunk[..n]);
    }
    Ok((sha256::Hash::from_engine(hash).to_string(), total))
}

fn private_directory(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("staging directory must be absolute".into());
    }
    fs::create_dir_all(path).map_err(|e| e.to_string())?;
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.file_type().is_dir() || m.uid() != nix::unistd::Uid::effective().as_raw() {
        return Err("staging directory must be owned by verifier service UID".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
}

fn load_config() -> Result<Config, String> {
    let current_uid = nix::unistd::Uid::effective().as_raw();
    let gateway_uid: u32 = env::var("SUPERNODE_VERIFY_GATEWAY_UID")
        .map_err(|e| e.to_string())?
        .parse()
        .map_err(|_| "invalid gateway UID")?;
    let producer_uid: u32 = env::var("SUPERNODE_VERIFY_PRODUCER_UID")
        .map_err(|e| e.to_string())?
        .parse()
        .map_err(|_| "invalid producer UID")?;
    if current_uid == 0
        || current_uid == gateway_uid
        || current_uid == producer_uid
        || gateway_uid == producer_uid
    {
        return Err(
            "verifier, gateway and producer require three distinct non-root identities".into(),
        );
    }
    let staging =
        PathBuf::from(env::var("SUPERNODE_VERIFY_STAGING_DIR").map_err(|e| e.to_string())?);
    private_directory(&staging)?;
    let socket = PathBuf::from(env::var("SUPERNODE_VERIFY_SOCKET").map_err(|e| e.to_string())?);
    let parent = socket.parent().ok_or("socket missing directory")?;
    let socket_dir = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
    if !socket.is_absolute()
        || !socket_dir.file_type().is_dir()
        || socket_dir.uid() != current_uid
        || socket_dir.mode() & 0o002 != 0
        || fs::symlink_metadata(&socket).is_ok()
        || parent == staging
    {
        return Err("verifier socket directory or path is unsafe".into());
    }
    let binary = PathBuf::from(env::var("SUPERNODE_VERIFY_BINARY").map_err(|e| e.to_string())?);
    let binary_sha = env::var("SUPERNODE_VERIFY_BINARY_SHA256").map_err(|e| e.to_string())?;
    if !binary.is_absolute()
        || !hex_hash(&binary_sha)
        || digest(&binary, MAX_BINARY_BYTES)?.0 != binary_sha
    {
        return Err("operator Raito verifier binary differs from SHA-256 pin".into());
    }
    let workers: usize = env::var("SUPERNODE_VERIFY_WORKERS")
        .unwrap_or("1".into())
        .parse()
        .map_err(|_| "invalid verifier process count")?;
    if !(1..=4).contains(&workers) {
        return Err("verifier process count outside 1-4".into());
    }
    Ok(Config {
        socket,
        staging,
        gateway_uid,
        binary,
        binary_sha,
        slots: Arc::new(Semaphore::new(workers)),
    })
}

struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct ProcessGroup(nix::unistd::Pid);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        let _ = nix::sys::signal::killpg(self.0, nix::sys::signal::Signal::SIGKILL);
    }
}
fn recover(root: &Path) -> Result<(), String> {
    for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if hex_hash(&entry.file_name().to_string_lossy()) {
            let path = entry.path();
            if fs::symlink_metadata(&path)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_dir()
            {
                fs::remove_dir_all(&path).map_err(|e| e.to_string())?;
            } else {
                fs::remove_file(&path).map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

async fn launch_verifier(
    config: &Config,
    request: &VerifyRequest,
    input: &Path,
    report: &Path,
) -> Result<(), String> {
    if digest(&config.binary, MAX_BINARY_BYTES)?.0 != config.binary_sha {
        return Err("verifier binary changed before execution".into());
    }
    let mut command = Command::new(&config.binary);
    command
        .arg("--gateway")
        .arg(input)
        .arg(&request.expected_txid)
        .arg(&request.block_hash)
        .arg(request.block_height.to_string())
        .arg(&request.policy_sha256)
        .arg(report)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let Some(limit) = env::var_os("SUPERNODE_REQUIRE_CGROUP_MAX_MIB") {
        command.env("SUPERNODE_REQUIRE_CGROUP_MAX_MIB", limit);
    }
    use std::os::unix::process::CommandExt;
    command.as_std_mut().process_group(0);
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let pid = i32::try_from(child.id().ok_or("verifier process missing PID")?)
        .map_err(|_| "verifier PID outside i32")?;
    let _group = ProcessGroup(nix::unistd::Pid::from_raw(pid));
    let status = timeout(MAX_VERIFIER_TIME, child.wait())
        .await
        .map_err(|_| "Raito STARK verifier timed out".to_owned())?
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("pinned Raito verifier rejected proof: {status}"));
    }
    Ok(())
}

async fn validate_request(
    stream: &mut UnixStream,
    config: &Config,
    _permit: OwnedSemaphorePermit,
) -> Result<serde_json::Value, String> {
    let peer = stream.peer_cred().map_err(|e| e.to_string())?;
    if peer.uid() != config.gateway_uid {
        return Err("Raito verifier rejected foreign peer UID".into());
    }
    let request: VerifyRequest = timeout(MAX_IO_IDLE, read_header(&mut *stream))
        .await
        .map_err(|_| "verifier IPC request header timed out".to_owned())??;
    request.validate()?;
    let directory = config.staging.join(&request.job_id);
    if fs::symlink_metadata(&directory).is_ok() {
        return Err("Raito verifier staging for job ID already exists".into());
    }
    fs::create_dir(&directory).map_err(|e| e.to_string())?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    let _cleanup = Cleanup(directory.clone());
    let proof = directory.join("proof.bin.bz2");
    let report = directory.join("receipt.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&proof)
        .map_err(|e| e.to_string())?;
    let mut engine = sha256::Hash::engine();
    let mut remaining = request.proof_bytes;
    let mut buf = [0u8; TRANSFER_CHUNK_BYTES];
    while remaining > 0 {
        let n = remaining.min(TRANSFER_CHUNK_BYTES as u64) as usize;
        timeout(MAX_IO_IDLE, stream.read_exact(&mut buf[..n]))
            .await
            .map_err(|_| "verifier proof upload deadline exceeded".to_owned())?
            .map_err(|e| e.to_string())?;
        file.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        engine.input(&buf[..n]);
        remaining -= n as u64;
    }
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    if sha256::Hash::from_engine(engine).to_string() != request.proof_sha256 {
        return Err("Raito compressed proof mismatched submitted SHA-256".into());
    }
    launch_verifier(config, &request, &proof, &report).await?;
    let (_, length) = digest(&report, MAX_RECEIPT_BYTES)?;
    let mut bytes = Vec::with_capacity(length as usize);
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&report)
        .map_err(|e| e.to_string())?
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 != length {
        return Err("Raito receipt changed or exceeded bounded read length".into());
    }
    let checked: CheckedRaitoReceipt =
        serde_json::from_slice(&bytes).map_err(|_| "invalid Raito verifier receipt")?;
    checked.validate(&request)?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

async fn serve(mut stream: UnixStream, config: Arc<Config>) {
    let permit = match config.slots.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            let _ = write_header(&mut stream, &VerifyReply::rejected("verifier at capacity")).await;
            return;
        }
    };
    let result = validate_request(&mut stream, &config, permit).await;
    let reply = match result {
        Ok(receipt) => VerifyReply {
            version: VERSION,
            receipt: Some(receipt),
            error: None,
        },
        Err(error) => VerifyReply::rejected(&error),
    };
    let _ = write_header(&mut stream, &reply).await;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Arc::new(load_config()?);
    recover(&config.staging)?;
    let listener = UnixListener::bind(&config.socket)?;
    fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o660))?;
    eprintln!(
        "Separate-UID Raito verifier socket: {}",
        config.socket.display()
    );
    loop {
        let (stream, _) = listener.accept().await?;
        if !stream
            .peer_cred()
            .is_ok_and(|peer| peer.uid() == config.gateway_uid)
        {
            continue;
        }
        let config = Arc::clone(&config);
        tokio::spawn(serve(stream, config));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn typed_receipt_binds_transaction_block_and_policy() {
        let req = VerifyRequest {
            version: VERSION,
            job_id: "ab".repeat(32),
            network: "main".into(),
            expected_txid: "cd".repeat(32),
            block_hash: "ef".repeat(32),
            block_height: 900000,
            policy_sha256: "12".repeat(32),
            proof_sha256: "34".repeat(32),
            proof_bytes: 16,
        };
        let mut receipt = CheckedRaitoReceipt {
            statement: STATEMENT.into(),
            verifier: VERIFIER.into(),
            txid: req.expected_txid.clone(),
            block_hash: req.block_hash.clone(),
            block_height: 900000,
            proven_tip_height: 900002,
            tx_index: 0,
            proof_sha256: req.proof_sha256.clone(),
            policy_sha256: req.policy_sha256.clone(),
        };
        assert!(receipt.validate(&req).is_ok());
        receipt.block_height = 7;
        assert!(receipt.validate(&req).is_err());
        receipt.block_height = 900000;
        receipt.policy_sha256 = "ab".repeat(32);
        assert!(receipt.validate(&req).is_err());
    }
}
