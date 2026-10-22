//! Proof workers run under this broker's service UID, which must differ from
//! the trusted gateway UID. The broker has no access to gateway job records
//! or verified receipt storage. It returns untrusted bytes, never proof claims.

use bitcoin::hashes::{sha256, Hash, HashEngine};
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
    hex_hash, read_header, write_header, RunReply, RunRequest, MAX_OUTPUT_BYTES,
    TRANSFER_CHUNK_BYTES, VERSION,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::Command,
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

const MAX_CLIENT_DURATION: Duration = Duration::from_secs(30);
const MAX_WORKER_DURATION: Duration = Duration::from_secs(600);
const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;

struct Config {
    socket: PathBuf,
    root: PathBuf,
    gateway_uid: u32,
    worker: PathBuf,
    worker_sha256: String,
    fetch_config: PathBuf,
    slots: Arc<Semaphore>,
}

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ProcessGroupCleanup(nix::unistd::Pid);
impl Drop for ProcessGroupCleanup {
    fn drop(&mut self) {
        let _ = nix::sys::signal::killpg(self.0, nix::sys::signal::Signal::SIGKILL);
    }
}

fn file_digest(path: &Path, max_bytes: u64) -> Result<(String, u64), String> {
    let info = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !info.file_type().is_file() || info.len() == 0 || info.len() > max_bytes {
        return Err("broker output or executable absent, unsafe or too large".into());
    }
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| e.to_string())?;
    let mut digest = sha256::Hash::engine();
    let mut buffer = [0u8; TRANSFER_CHUNK_BYTES];
    let mut length = 0u64;
    loop {
        let n = f.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        length = length.saturating_add(n as u64);
        if length > max_bytes {
            return Err("broker output changed or grew beyond byte cap".into());
        }
        digest.input(&buffer[..n]);
    }
    Ok((sha256::Hash::from_engine(digest).to_string(), length))
}

fn private_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("broker staging root must be absolute".into());
    }
    fs::create_dir_all(path).map_err(|e| e.to_string())?;
    let info = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !info.file_type().is_dir() || info.uid() != nix::unistd::Uid::effective().as_raw() {
        return Err("broker staging directory must be owned by broker UID".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
}

fn socket_directory(path: &Path) -> Result<(), String> {
    let parent = path.parent().ok_or("broker socket missing directory")?;
    if !path.is_absolute() || !parent.is_dir() {
        return Err("broker socket must have an existing absolute parent directory".into());
    }
    let metadata = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o002 != 0
    {
        return Err("broker socket parent must be owned by broker and not world-writable".into());
    }
    if fs::symlink_metadata(path).is_ok() {
        return Err(
            "broker socket path already exists; remove only after verifying stale service".into(),
        );
    }
    Ok(())
}

fn load_config() -> Result<Config, String> {
    let gateway_uid: u32 = env::var("SUPERNODE_BROKER_GATEWAY_UID")
        .map_err(|e| e.to_string())?
        .parse()
        .map_err(|_| "invalid gateway UID")?;
    if gateway_uid == nix::unistd::Uid::effective().as_raw() {
        return Err("broker service and gateway must use distinct OS UIDs".into());
    }
    let root = PathBuf::from(env::var("SUPERNODE_BROKER_STAGING_DIR").map_err(|e| e.to_string())?);
    private_root(&root)?;
    let socket = PathBuf::from(env::var("SUPERNODE_BROKER_SOCKET").map_err(|e| e.to_string())?);
    socket_directory(&socket)?;
    if root == socket.parent().ok_or("missing socket parent")? {
        return Err("broker staging and IPC socket directory must be separate".into());
    }
    let worker =
        PathBuf::from(env::var("SUPERNODE_BROKER_RAITO_WORKER").map_err(|e| e.to_string())?);
    let worker_sha256 = env::var("SUPERNODE_BROKER_RAITO_SHA256").map_err(|e| e.to_string())?;
    if !worker.is_absolute()
        || !hex_hash(&worker_sha256)
        || file_digest(&worker, MAX_BINARY_BYTES)?.0 != worker_sha256
    {
        return Err("broker worker path or SHA-256 pin invalid".into());
    }
    let fetch_config =
        PathBuf::from(env::var("SUPERNODE_BROKER_RAITO_FETCH_CONFIG").map_err(|e| e.to_string())?);
    if !fetch_config.is_absolute()
        || !fs::symlink_metadata(&fetch_config)
            .map(|m| m.file_type().is_file())
            .unwrap_or(false)
    {
        return Err("broker Raito fetch config must be absolute regular file".into());
    }
    let max_workers: usize = env::var("SUPERNODE_BROKER_WORKERS")
        .unwrap_or("1".into())
        .parse()
        .map_err(|_| "invalid broker worker count")?;
    if !(1..=4).contains(&max_workers) {
        return Err("broker worker count must be between 1 and 4".into());
    }
    Ok(Config {
        socket,
        root,
        gateway_uid,
        worker,
        worker_sha256,
        fetch_config,
        slots: Arc::new(Semaphore::new(max_workers)),
    })
}

fn clean_stale(root: &Path) -> Result<(), String> {
    for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if hex_hash(&name) {
            let meta = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
            if meta.file_type().is_dir() {
                fs::remove_dir_all(entry.path()).map_err(|e| e.to_string())?;
            } else {
                fs::remove_file(entry.path()).map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

async fn launch_worker(
    config: &Config,
    req: &RunRequest,
    input: &Path,
    output: &Path,
) -> Result<(), String> {
    if file_digest(&config.worker, MAX_BINARY_BYTES)?.0 != config.worker_sha256 {
        return Err("approved Raito executable differs from pinned SHA-256".into());
    }
    let mut command = Command::new(&config.worker);
    command
        .arg("--input")
        .arg(input)
        .arg("--output")
        .arg(output)
        .arg("--network")
        .arg(&req.network)
        .arg("--blockhash")
        .arg(&req.block_hash)
        .arg("--height")
        .arg(req.block_height.to_string())
        .arg("--policy-sha256")
        .arg(&req.policy_sha256)
        .arg("--expected-txid")
        .arg(req.expected_txid.as_deref().unwrap_or(""))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("SUPERNODE_RAITO_FETCH_CONFIG", &config.fetch_config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let Some(limit) = env::var_os("SUPERNODE_REQUIRE_CGROUP_MAX_MIB") {
        command.env("SUPERNODE_REQUIRE_CGROUP_MAX_MIB", limit);
    }
    // A distinct process group lets the broker kill ordinary grandchildren.
    // The enclosing systemd service cgroup also kills detached processes.
    use std::os::unix::process::CommandExt;
    command.as_std_mut().process_group(0);
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let pid = i32::try_from(child.id().ok_or("worker has no PID")?)
        .map_err(|_| "worker PID exceeds signed range")?;
    let _cleanup = ProcessGroupCleanup(nix::unistd::Pid::from_raw(pid));
    let status = timeout(MAX_WORKER_DURATION, child.wait())
        .await
        .map_err(|_| "broker worker exceeded 600-second timeout")?
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("approved Raito worker exited with {status}"));
    }
    Ok(())
}

async fn accept_one(
    mut stream: UnixStream,
    config: Arc<Config>,
    _permit: OwnedSemaphorePermit,
) -> Result<(), String> {
    let peer = stream.peer_cred().map_err(|e| e.to_string())?;
    if peer.uid() != config.gateway_uid {
        return Err("unauthorized gateway UID at broker socket".into());
    }
    let request: RunRequest = timeout(MAX_CLIENT_DURATION, read_header(&mut stream))
        .await
        .map_err(|_| "broker input header timed out")??;
    request.validate()?;
    let jobdir = config.root.join(&request.job_id);
    if fs::symlink_metadata(&jobdir).is_ok() {
        return Err("broker job ID already has staging; refuse replay".into());
    }
    fs::create_dir(&jobdir).map_err(|e| e.to_string())?;
    fs::set_permissions(&jobdir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let _cleanup = Cleanup(jobdir.clone());
    let input = jobdir.join("input.bin");
    let output = jobdir.join("output.bin");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&input)
        .map_err(|e| e.to_string())?;
    let mut left = request.input_bytes;
    let mut buf = [0u8; TRANSFER_CHUNK_BYTES];
    while left > 0 {
        let count = left.min(buf.len() as u64) as usize;
        timeout(MAX_CLIENT_DURATION, stream.read_exact(&mut buf[..count]))
            .await
            .map_err(|_| "broker input body timed out")?
            .map_err(|e| e.to_string())?;
        file.write_all(&buf[..count]).map_err(|e| e.to_string())?;
        left -= count as u64;
    }
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    launch_worker(&config, &request, &input, &output).await?;
    let (digest, size) = file_digest(&output, MAX_OUTPUT_BYTES)?;
    let reply = RunReply {
        version: VERSION,
        ok: true,
        output_bytes: size,
        result_sha256: Some(digest),
        error: None,
    };
    write_header(&mut stream, &reply).await?;
    let mut result = tokio::fs::File::open(&output)
        .await
        .map_err(|e| e.to_string())?;
    let mut remaining = size;
    while remaining > 0 {
        let count = remaining.min(buf.len() as u64) as usize;
        result
            .read_exact(&mut buf[..count])
            .await
            .map_err(|e| e.to_string())?;
        stream
            .write_all(&buf[..count])
            .await
            .map_err(|e| e.to_string())?;
        remaining -= count as u64;
    }
    stream.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn serve_one(stream: UnixStream, config: Arc<Config>) {
    let mut stream = stream;
    // Connection admission is bounded before data arrives. Local peers
    // cannot queue unlimited expensive proofs on this worker account.
    let permit = match config.slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            let _ = write_header(&mut stream, &RunReply::rejected("broker at capacity")).await;
            return;
        }
    };
    // Transfer errors may occur after a success header; the client rejects
    // incomplete data and its own independently recomputed SHA-256.
    let _ = accept_one(stream, config, permit).await;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Arc::new(load_config()?);
    clean_stale(&config.root)?;
    let listener = UnixListener::bind(&config.socket)?;
    fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o660))?;
    eprintln!(
        "Isolated proof broker listening at {}",
        config.socket.display()
    );
    loop {
        let (stream, _) = listener.accept().await?;
        let config = Arc::clone(&config);
        tokio::spawn(serve_one(stream, config));
    }
}
