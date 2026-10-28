//! A separate-UID runner for the operator-pinned Bitcoin statement verifiers
//! (`btc-header-fold verify-bundle` and `btc-pay-verify`). The gateway holds
//! Bitcoin Core credentials; a parser bug in a verifier runs here instead.
//!
//! The broker is deliberately dumb: it takes a kind and the bundle bytes,
//! runs the pinned executable for that kind and returns its bounded stdout.
//! The gateway parses and checks the typed receipt and binds it to Core.
use bitcoin::hashes::{sha256, Hash, HashEngine};
use std::{
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use supernode_worker_broker_protocol::{
    hex_hash, read_header, write_header, StatementRunReply, StatementRunRequest,
    MAX_STATEMENT_STDOUT_BYTES, TRANSFER_CHUNK_BYTES, VERSION,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::Command,
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;
/// The Nova verifier key is about 250 MB.
const MAX_KEY_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_IO_IDLE: Duration = Duration::from_secs(30);
const MAX_VERIFIER_TIME: Duration = Duration::from_secs(300);

/// An executable pinned by SHA-256, checked at startup and before each run.
struct Pinned {
    binary: PathBuf,
    binary_sha: String,
}

struct Config {
    socket: PathBuf,
    staging: PathBuf,
    gateway_uid: u32,
    /// `btc-header-fold` and its verifier key.
    nova: Option<(Pinned, PathBuf)>,
    /// `btc-pay-verify` and the `0x`-prefixed payment program key.
    payment: Option<(Pinned, String)>,
    slots: Arc<Semaphore>,
    counter: AtomicU64,
}

impl Config {
    /// The pinned program and its arguments for `kind`, reading `input`.
    fn command(&self, kind: &str, input: &Path) -> Result<(&Pinned, Vec<OsString>), String> {
        match kind {
            "nova_header_chain_v1" => {
                let (program, vk) = self.nova.as_ref().ok_or("Nova verifier not configured")?;
                let args = vec![
                    "verify-bundle".into(),
                    input.as_os_str().to_owned(),
                    "--vk".into(),
                    vk.as_os_str().to_owned(),
                ];
                Ok((program, args))
            }
            "sp1_btc_payment_v1" => {
                let (program, key) = self
                    .payment
                    .as_ref()
                    .ok_or("payment verifier not configured")?;
                Ok((program, vec![input.as_os_str().to_owned(), key.into()]))
            }
            _ => Err("unsupported statement kind".into()),
        }
    }
}

fn digest(path: &Path, maximum: u64) -> Result<(String, u64), String> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.file_type().is_file() || m.len() == 0 || m.len() > maximum {
        return Err("unsafe, absent or oversized pinned file".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| e.to_string())?;
    let mut hash = sha256::Hash::engine();
    let mut total = 0u64;
    let mut chunk = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > maximum {
            return Err("pinned file changed or grew beyond cap".into());
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

/// `{prefix}` and `{prefix}_SHA256`, when the executable variable is set.
fn pinned(prefix: &str) -> Result<Option<Pinned>, String> {
    let Ok(binary) = env::var(prefix) else {
        return Ok(None);
    };
    let binary = PathBuf::from(binary);
    let binary_sha = env::var(format!("{prefix}_SHA256")).map_err(|e| e.to_string())?;
    if !binary.is_absolute()
        || !hex_hash(&binary_sha)
        || digest(&binary, MAX_BINARY_BYTES)?.0 != binary_sha
    {
        return Err(format!("{prefix} differs from its SHA-256 pin"));
    }
    Ok(Some(Pinned { binary, binary_sha }))
}

fn load_config() -> Result<Config, String> {
    let current_uid = nix::unistd::Uid::effective().as_raw();
    let gateway_uid: u32 = env::var("SUPERNODE_STATEMENT_VERIFY_GATEWAY_UID")
        .map_err(|e| e.to_string())?
        .parse()
        .map_err(|_| "invalid gateway UID")?;
    if current_uid == 0 || gateway_uid == 0 || current_uid == gateway_uid {
        return Err("statement verifier and gateway require distinct non-root identities".into());
    }
    let staging = PathBuf::from(
        env::var("SUPERNODE_STATEMENT_VERIFY_STAGING_DIR").map_err(|e| e.to_string())?,
    );
    private_directory(&staging)?;
    let socket =
        PathBuf::from(env::var("SUPERNODE_STATEMENT_VERIFY_SOCKET").map_err(|e| e.to_string())?);
    let parent = socket.parent().ok_or("socket missing directory")?;
    let socket_dir = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
    if !socket.is_absolute()
        || !socket_dir.file_type().is_dir()
        || socket_dir.uid() != current_uid
        || socket_dir.mode() & 0o002 != 0
        || fs::symlink_metadata(&socket).is_ok()
        || parent == staging
    {
        return Err("statement verifier socket directory or path is unsafe".into());
    }
    let nova = match pinned("SUPERNODE_STATEMENT_NOVA_VERIFIER")? {
        Some(program) => {
            let vk =
                PathBuf::from(env::var("SUPERNODE_STATEMENT_NOVA_VK").map_err(|e| e.to_string())?);
            let vk_sha =
                env::var("SUPERNODE_STATEMENT_NOVA_VK_SHA256").map_err(|e| e.to_string())?;
            // Checked once here; the verifier reports the key's digest in
            // every receipt and the gateway compares it with its own pin.
            if !vk.is_absolute() || !hex_hash(&vk_sha) || digest(&vk, MAX_KEY_BYTES)?.0 != vk_sha {
                return Err("Nova verifier key differs from its SHA-256 pin".into());
            }
            Some((program, vk))
        }
        None => None,
    };
    let payment = match pinned("SUPERNODE_STATEMENT_PAYMENT_VERIFIER")? {
        Some(program) => {
            let key =
                env::var("SUPERNODE_STATEMENT_PAYMENT_PAY_VKEY").map_err(|e| e.to_string())?;
            if !key.strip_prefix("0x").is_some_and(hex_hash) {
                return Err("payment program key must be 0x-prefixed bytes32".into());
            }
            Some((program, key))
        }
        None => None,
    };
    if nova.is_none() && payment.is_none() {
        return Err("no statement verifier configured".into());
    }
    let workers: usize = env::var("SUPERNODE_STATEMENT_VERIFY_WORKERS")
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
        nova,
        payment,
        slots: Arc::new(Semaphore::new(workers)),
        counter: AtomicU64::new(0),
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
    stream: &mut UnixStream,
    program: &Pinned,
    args: Vec<OsString>,
    stdout: fs::File,
) -> Result<ExitStatus, String> {
    if digest(&program.binary, MAX_BINARY_BYTES)?.0 != program.binary_sha {
        return Err("verifier binary changed before execution".into());
    }
    let mut command = Command::new(&program.binary);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::null())
        .kill_on_drop(true);
    use std::os::unix::process::CommandExt;
    command.as_std_mut().process_group(0);
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let pid = i32::try_from(child.id().ok_or("verifier process missing PID")?)
        .map_err(|_| "verifier PID outside i32")?;
    let _group = ProcessGroup(nix::unistd::Pid::from_raw(pid));
    // Keep ownership of Child across client cancellation. Dropping the wait
    // future alone kills on drop but can leave this broker's child unreaped.
    let mut unexpected = [0u8; 1];
    let result = tokio::select! {
        biased;
        _ = stream.read(&mut unexpected) => {
            Err("gateway disconnected or sent trailing request bytes".to_owned())
        }
        result = timeout(MAX_VERIFIER_TIME, child.wait()) => {
            result.map_err(|_| "statement verifier timed out".to_owned())
                .and_then(|status| status.map_err(|e| e.to_string()))
        }
    };
    // Retire the group, then reap the owned child before releasing staging
    // and admission capacity.
    drop(_group);
    if result.is_err() {
        timeout(Duration::from_secs(5), child.wait())
            .await
            .map_err(|_| "cancelled subprocess was not reaped within five seconds")?
            .map_err(|e| format!("failed to reap cancelled subprocess: {e}"))?;
    }
    result
}

/// Receive one bundle, run its pinned verifier, and return the exit status
/// with the verifier's bounded stdout.
async fn run_request(
    stream: &mut UnixStream,
    config: &Config,
    _permit: OwnedSemaphorePermit,
) -> Result<(ExitStatus, Vec<u8>), String> {
    let peer = stream.peer_cred().map_err(|e| e.to_string())?;
    if peer.uid() != config.gateway_uid {
        return Err("statement verifier rejected foreign peer UID".into());
    }
    let request: StatementRunRequest = timeout(MAX_IO_IDLE, read_header(&mut *stream))
        .await
        .map_err(|_| "verifier IPC request header timed out".to_owned())??;
    request.validate()?;
    let n = config.counter.fetch_add(1, Ordering::Relaxed);
    let name = sha256::Hash::hash(
        format!("{}-{}-{n}", request.bundle_sha256, std::process::id()).as_bytes(),
    )
    .to_string();
    let directory = config.staging.join(name);
    fs::create_dir(&directory).map_err(|e| e.to_string())?;
    let _cleanup = Cleanup(directory.clone());
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    let input = directory.join("bundle.bin");
    let output = directory.join("stdout.json");
    let create = |path: &Path| {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| e.to_string())
    };
    let mut file = create(&input)?;
    let mut engine = sha256::Hash::engine();
    let mut remaining = request.bundle_bytes;
    let mut buf = [0u8; TRANSFER_CHUNK_BYTES];
    while remaining > 0 {
        let n = remaining.min(TRANSFER_CHUNK_BYTES as u64) as usize;
        timeout(MAX_IO_IDLE, stream.read_exact(&mut buf[..n]))
            .await
            .map_err(|_| "verifier bundle upload deadline exceeded".to_owned())?
            .map_err(|e| e.to_string())?;
        file.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        engine.input(&buf[..n]);
        remaining -= n as u64;
    }
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    if sha256::Hash::from_engine(engine).to_string() != request.bundle_sha256 {
        return Err("bundle mismatched submitted SHA-256".into());
    }
    let (program, args) = config.command(&request.kind, &input)?;
    let status = launch_verifier(stream, program, args, create(&output)?).await?;
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&output)
        .map_err(|e| e.to_string())?
        .take(MAX_STATEMENT_STDOUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_STATEMENT_STDOUT_BYTES {
        return Err("statement verifier stdout exceeds size limit".into());
    }
    Ok((status, bytes))
}

async fn serve(mut stream: UnixStream, config: Arc<Config>) {
    let permit = match config.slots.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            let _ = write_header(
                &mut stream,
                &StatementRunReply::rejected("verifier at capacity"),
            )
            .await;
            return;
        }
    };
    match run_request(&mut stream, &config, permit).await {
        Ok((status, stdout)) => {
            let reply = StatementRunReply {
                version: VERSION,
                exit_success: status.success(),
                exit_status: status.to_string(),
                stdout_bytes: stdout.len() as u64,
                error: None,
            };
            if write_header(&mut stream, &reply).await.is_ok() {
                let _ = stream.write_all(&stdout).await;
            }
        }
        Err(error) => {
            let _ = write_header(&mut stream, &StatementRunReply::rejected(&error)).await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Arc::new(load_config()?);
    recover(&config.staging)?;
    let listener = UnixListener::bind(&config.socket)?;
    fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o660))?;
    eprintln!(
        "Separate-UID statement verifier socket: {} (nova: {}, payment: {})",
        config.socket.display(),
        config.nova.is_some(),
        config.payment.is_some()
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

    struct Fixture {
        root: PathBuf,
        config: Arc<Config>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// A same-UID config whose payment "verifier" is `script`.
    fn fixture(script: &[u8]) -> Fixture {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!("stmt-broker-{}-{stamp}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let staging = root.join("staging");
        fs::create_dir(&staging).unwrap();
        let binary = root.join("mock");
        fs::write(&binary, script).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let program = Pinned {
            binary_sha: digest(&binary, MAX_BINARY_BYTES).unwrap().0,
            binary,
        };
        let config = Arc::new(Config {
            socket: root.join("unused.sock"),
            staging,
            gateway_uid: nix::unistd::Uid::effective().as_raw(),
            nova: None,
            payment: Some((program, format!("0x{}", "ab".repeat(32)))),
            slots: Arc::new(Semaphore::new(1)),
            counter: AtomicU64::new(0),
        });
        Fixture { root, config }
    }

    fn request(bundle: &[u8], kind: &str) -> StatementRunRequest {
        StatementRunRequest {
            version: VERSION,
            kind: kind.into(),
            bundle_sha256: sha256::Hash::hash(bundle).to_string(),
            bundle_bytes: bundle.len() as u64,
        }
    }

    async fn exchange(
        config: Arc<Config>,
        req: &StatementRunRequest,
        bundle: &[u8],
    ) -> (StatementRunReply, Vec<u8>) {
        let (mut client, incoming) = UnixStream::pair().unwrap();
        let service = tokio::spawn(serve(incoming, config));
        write_header(&mut client, req).await.unwrap();
        client.write_all(bundle).await.unwrap();
        let reply: StatementRunReply = read_header(&mut client).await.unwrap();
        let mut stdout = vec![0u8; reply.stdout_bytes as usize];
        client.read_exact(&mut stdout).await.unwrap();
        service.await.unwrap();
        (reply, stdout)
    }

    #[tokio::test]
    async fn runs_the_pinned_program_and_returns_its_stdout() {
        // Echo the arguments and the bundle digest, then exit with the
        // bundle's first byte so both outcomes are covered.
        let f = fixture(
            b"#!/bin/sh\nprintf '%s|%s|' \"$(basename \"$1\")\" \"$2\"\nsha256sum \"$1\" | cut -c1-64\nexit \"$(head -c1 \"$1\")\"\n",
        );
        let (reply, stdout) = exchange(
            f.config.clone(),
            &request(b"0abc", "sp1_btc_payment_v1"),
            b"0abc",
        )
        .await;
        assert_eq!(reply.completed(), Ok(stdout.len() as u64));
        assert!(reply.exit_success);
        let expected = format!(
            "bundle.bin|0x{}|{}\n",
            "ab".repeat(32),
            sha256::Hash::hash(b"0abc")
        );
        assert_eq!(String::from_utf8(stdout).unwrap(), expected);

        let (reply, stdout) = exchange(
            f.config.clone(),
            &request(b"3abc", "sp1_btc_payment_v1"),
            b"3abc",
        )
        .await;
        assert!(reply.error.is_none() && !reply.exit_success, "{reply:?}");
        assert!(!stdout.is_empty(), "a rejecting run still returns stdout");

        // A kind whose verifier the operator did not configure.
        let (reply, _) = exchange(
            f.config.clone(),
            &request(b"0abc", "nova_header_chain_v1"),
            b"0abc",
        )
        .await;
        assert!(reply.error.unwrap().contains("not configured"));
        // A bundle that differs from its declared digest.
        let mut forged = request(b"0abc", "sp1_btc_payment_v1");
        forged.bundle_sha256 = "88".repeat(32);
        let (reply, _) = exchange(f.config.clone(), &forged, b"0abc").await;
        assert!(reply.error.unwrap().contains("SHA-256"));
        assert_eq!(fs::read_dir(&f.config.staging).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn substituted_binary_and_oversized_stdout_are_refused() {
        let f = fixture(b"#!/bin/sh\nhead -c 9000 /dev/zero | tr '\\0' a\n");
        let (reply, _) =
            exchange(f.config.clone(), &request(b"x", "sp1_btc_payment_v1"), b"x").await;
        assert!(reply.error.unwrap().contains("size limit"));
        let (program, _) = f.config.payment.as_ref().unwrap();
        fs::write(&program.binary, b"#!/bin/sh\necho forged\n").unwrap();
        let (reply, _) =
            exchange(f.config.clone(), &request(b"x", "sp1_btc_payment_v1"), b"x").await;
        assert!(reply.error.unwrap().contains("changed"));
    }

    // Neither EOF nor trailing bytes may leave a running verifier, staging
    // directory or occupied admission slot behind.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn disconnect_and_trailing_bytes_cancel_running_work() {
        for trailing in [false, true] {
            let f = fixture(
                b"#!/bin/sh\necho $$ > \"$(dirname \"$0\")/parent.pid\"\nsleep 30 &\necho $! > \"$(dirname \"$0\")/child.pid\"\nwait\n",
            );
            let (mut client, incoming) = UnixStream::pair().unwrap();
            let service = tokio::spawn(serve(incoming, f.config.clone()));
            write_header(&mut client, &request(b"12345678", "sp1_btc_payment_v1"))
                .await
                .unwrap();
            client.write_all(b"12345678").await.unwrap();
            let marker = f.root.join("child.pid");
            timeout(Duration::from_secs(3), async {
                while !fs::read_to_string(&marker).is_ok_and(|s| s.trim().parse::<u32>().is_ok()) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            let pid: u32 = fs::read_to_string(marker).unwrap().trim().parse().unwrap();
            let parent_pid: i32 = fs::read_to_string(f.root.join("parent.pid"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            if trailing {
                client.write_all(b"unexpected").await.unwrap();
            } else {
                drop(client);
            }
            timeout(Duration::from_secs(3), service)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                nix::sys::wait::waitpid(
                    nix::unistd::Pid::from_raw(parent_pid),
                    Some(nix::sys::wait::WaitPidFlag::WNOHANG)
                ),
                Err(nix::errno::Errno::ECHILD)
            );
            assert_eq!(f.config.slots.available_permits(), 1);
            assert_eq!(fs::read_dir(&f.config.staging).unwrap().count(), 0);
            timeout(Duration::from_secs(3), async {
                while !fs::read_to_string(format!("/proc/{pid}/stat"))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        }
    }
}
