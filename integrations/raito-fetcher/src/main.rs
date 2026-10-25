//! Operator-approved Raito compressed SPV proof fetcher.
//! Fetching bytes is NEVER evidence of proof validity. The Supernode's
//! independently pinned Raito verifier checks the resulting STARK statement.

// Readiness is deliberately not wired into fetch(), job status or receipt publication.
#[allow(dead_code)]
mod source_readiness;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::{BlockHash, Txid};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::Stdio,
    str::FromStr,
    time::Duration,
};
use tokio::{process::Command, time::timeout};
use url::{Host, Url};

const MAX_CONFIG_BYTES: u64 = 8192;
const MAX_REQUEST_BYTES: u64 = 4096;
const MAX_COOKIE_BYTES: u64 = 4096;
const MAX_COMPRESSED_PROOF_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CLIENT_BYTES: u64 = 512 * 1024 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(540);
const SCHEMA: &str = "raito_fetch_request_v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchConfig {
    client_binary: PathBuf,
    client_sha256: String,
    bitcoin_rpc_url: String,
    bitcoin_rpc_cookie_file: PathBuf,
    raito_bridge_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchRequest {
    schema: String,
    network: String,
    txid: String,
    block_hash: String,
    block_height: u32,
}

#[derive(Debug)]
struct WorkerArgs {
    input: PathBuf,
    output: PathBuf,
    txid: Txid,
    block_hash: BlockHash,
    height: u32,
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn read_bounded_regular(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > max {
        return Err("file is absent, unsafe, empty or exceeds its size cap".into());
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > max {
        return Err("file grew beyond permitted length".into());
    }
    Ok(bytes)
}

fn file_digest(path: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_CLIENT_BYTES {
        return Err("upstream Raito client executable is absent or unsafe".into());
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
        if total > MAX_CLIENT_BYTES {
            return Err("Raito client grew while hashing".into());
        }
        engine.input(&buffer[..n]);
    }
    Ok(sha256::Hash::from_engine(engine).to_string())
}

fn operator_config(path: &Path) -> Result<FetchConfig, String> {
    if !path.is_absolute() {
        return Err("Raito fetch config must be an absolute path".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::symlink_metadata(path)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err("Raito fetch config must be accessible only to its owner".into());
        }
    }
    let bytes = read_bounded_regular(path, MAX_CONFIG_BYTES)?;
    let conf: FetchConfig = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if !conf.client_binary.is_absolute()
        || !conf.bitcoin_rpc_cookie_file.is_absolute()
        || !is_sha256(&conf.client_sha256)
        || file_digest(&conf.client_binary)? != conf.client_sha256
    {
        return Err("operator's Raito client executable SHA-256 pin or path is invalid".into());
    }
    validate_url(&conf.bitcoin_rpc_url, true)?;
    validate_url(&conf.raito_bridge_url, false)?;
    Ok(conf)
}

fn validate_url(value: &str, is_core: bool) -> Result<(), String> {
    let url = Url::parse(value).map_err(|e| e.to_string())?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err("upstream URL may not contain credentials, query or fragment".into());
    }
    if is_core {
        let loopback = match url.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            Some(Host::Domain(domain)) => domain == "localhost",
            None => false,
        };
        if !matches!(url.scheme(), "http" | "https") || !loopback {
            return Err("Bitcoin Core RPC must use a loopback HTTP(S) endpoint".into());
        }
    } else if url.scheme() != "https" || url.host().is_none() {
        return Err("Raito bridge must use an HTTPS endpoint".into());
    }
    Ok(())
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<WorkerArgs, String> {
    let mut fields = BTreeMap::new();
    let mut iter = args;
    while let Some(key) = iter.next() {
        if !matches!(
            key.as_str(),
            "--input"
                | "--output"
                | "--network"
                | "--blockhash"
                | "--height"
                | "--policy-sha256"
                | "--expected-txid"
        ) {
            return Err(format!("unexpected worker argument: {key}"));
        }
        let value = iter.next().ok_or("missing worker argument value")?;
        if fields.insert(key, value).is_some() {
            return Err("duplicate worker argument".into());
        }
    }
    if fields.len() != 7 {
        return Err(
            "expected worker input, output, network, blockhash, height, policy, TXID".into(),
        );
    }
    let get = |key: &str| -> Result<&str, String> {
        fields
            .get(key)
            .map(String::as_str)
            .ok_or("required worker argument missing".into())
    };
    if get("--network")? != "main" {
        return Err("pinned Raito SPV policy currently supports Bitcoin mainnet only".into());
    }
    if !is_sha256(get("--policy-sha256")?) {
        return Err("invalid Raito verification policy digest".into());
    }
    let input = PathBuf::from(get("--input")?);
    let output = PathBuf::from(get("--output")?);
    if input.parent() != output.parent() || input == output {
        return Err("Raito input and output must occupy the same private job directory".into());
    }
    Ok(WorkerArgs {
        input,
        output,
        txid: Txid::from_str(get("--expected-txid")?).map_err(|e| e.to_string())?,
        block_hash: BlockHash::from_str(get("--blockhash")?).map_err(|e| e.to_string())?,
        height: get("--height")?
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?,
    })
}

fn validate_request(args: &WorkerArgs) -> Result<(), String> {
    let bytes = read_bounded_regular(&args.input, MAX_REQUEST_BYTES)?;
    let req: FetchRequest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if req.schema != SCHEMA
        || req.network != "main"
        || Txid::from_str(&req.txid).map_err(|e| e.to_string())? != args.txid
        || BlockHash::from_str(&req.block_hash).map_err(|e| e.to_string())? != args.block_hash
        || req.block_height != args.height
    {
        return Err("Raito proof fetch request differs from authorized job".into());
    }
    Ok(())
}

fn bitcoin_cookie(path: &Path) -> Result<String, String> {
    let raw = String::from_utf8(read_bounded_regular(path, MAX_COOKIE_BYTES)?)
        .map_err(|e| e.to_string())?;
    let cookie = raw.trim_end_matches(['\r', '\n']);
    let (user, pass) = cookie
        .split_once(':')
        .ok_or("invalid Bitcoin Core cookie")?;
    if user.is_empty() || pass.is_empty() || cookie.contains(['\r', '\n']) {
        return Err("invalid Bitcoin Core cookie".into());
    }
    Ok(cookie.to_owned())
}

/// Invoke pinned upstream client, keeping Core credentials out of argv.
/// The worker does NOT request upstream `--verify`; Supernode verifies later.
async fn fetch(args: &WorkerArgs, config: &FetchConfig) -> Result<(), String> {
    validate_request(args)?;
    if fs::symlink_metadata(&args.output).is_ok() {
        return Err("Raito proof output already exists".into());
    }
    // Re-check executable immediately before spawning: configuration may have
    // been read earlier and the operator may have rotated the binary.
    if file_digest(&config.client_binary)? != config.client_sha256 {
        return Err("Raito client executable hash changed before invocation".into());
    }
    let cookie = bitcoin_cookie(&config.bitcoin_rpc_cookie_file)?;
    let status = timeout(
        FETCH_TIMEOUT,
        Command::new(&config.client_binary)
            .arg("fetch")
            .arg("--txid")
            .arg(args.txid.to_string())
            .arg("--proof-path")
            .arg(&args.output)
            .arg("--raito-rpc-url")
            .arg(&config.raito_bridge_url)
            .arg("--bitcoin-rpc-url")
            .arg(&config.bitcoin_rpc_url)
            .env_clear()
            .env("USERPWD", cookie)
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await
    .map_err(|_| "upstream Raito client exceeded fetch timeout".to_owned())?
    .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("upstream Raito client fetch failed: {status}"));
    }
    let meta = fs::symlink_metadata(&args.output).map_err(|e| e.to_string())?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > MAX_COMPRESSED_PROOF_BYTES {
        return Err("Raito proof output is unsafe or exceeds 16 MiB cap".into());
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    supernode_cgroup_guard::enforce_optional_memory_limit()?;
    let args = parse_args(env::args().skip(1))?;
    let path = PathBuf::from(env::var("SUPERNODE_RAITO_FETCH_CONFIG")?);
    let config = operator_config(&path)?;
    if let Err(error) = fetch(&args, &config).await {
        let _ = fs::remove_file(&args.output);
        return Err(error.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    fn tmp(label: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "raito-fetch-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
    fn make_args(dir: &Path) -> WorkerArgs {
        WorkerArgs {
            input: dir.join("one.input"),
            output: dir.join("one.output"),
            txid: Txid::from_str(&"12".repeat(32)).unwrap(),
            block_hash: BlockHash::from_str(&"ab".repeat(32)).unwrap(),
            height: 300,
        }
    }
    fn prepare_request(args: &WorkerArgs) {
        fs::write(
            &args.input,
            serde_json::json!({
                "schema":SCHEMA, "network":"main", "txid":args.txid.to_string(),
                "block_hash":args.block_hash.to_string(), "block_height":args.height
            })
            .to_string(),
        )
        .unwrap();
    }
    #[test]
    fn strict_fetch_request_and_urls() {
        let dir = tmp("validation");
        fs::create_dir_all(&dir).unwrap();
        let args = make_args(&dir);
        prepare_request(&args);
        assert!(validate_request(&args).is_ok());
        fs::write(&args.input, br#"{"schema":"wrong"}"#).unwrap();
        assert!(validate_request(&args).is_err());
        assert!(validate_url("http://127.0.0.1:8332", true).is_ok());
        assert!(validate_url("https://api.raito.wtf", false).is_ok());
        assert!(validate_url("http://remote.example:8332", true).is_err());
        assert!(validate_url("http://api.raito.wtf", false).is_err());
        assert!(validate_url("http://evil:pass@127.0.0.1:8332", true).is_err());
        let parsed = parse_args(
            [
                "--input",
                "in",
                "--output",
                "out",
                "--network",
                "regtest",
                "--blockhash",
                &"ab".repeat(32),
                "--height",
                "300",
                "--policy-sha256",
                &"cd".repeat(32),
                "--expected-txid",
                &"12".repeat(32),
            ]
            .into_iter()
            .map(str::to_owned),
        );
        assert!(parsed.is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn approved_client_fetches_but_never_attests_to_a_stark() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("client");
        fs::create_dir_all(&dir).unwrap();
        let args = make_args(&dir);
        prepare_request(&args);
        let cookie = dir.join("core.cookie");
        fs::write(&cookie, "__cookie__:test-secret\n").unwrap();
        fs::set_permissions(&cookie, fs::Permissions::from_mode(0o600)).unwrap();
        let client = dir.join("mock-raito-spv-client.sh");
        fs::write(&client, "#!/bin/sh\nout=\n[ \"$1\" = fetch ] || exit 30\nshift\nwhile [ \"$#\" -gt 0 ]; do\n case \"$1\" in\n --txid|--raito-rpc-url|--bitcoin-rpc-url) shift 2;;\n --proof-path) out=\"$2\"; shift 2;;\n *) exit 31;;\n esac\ndone\n[ \"$USERPWD\" = \"__cookie__:test-secret\" ] || exit 32\nprintf 'unverified-compressed-proof-test-bytes' > \"$out\"\n").unwrap();
        fs::set_permissions(&client, fs::Permissions::from_mode(0o700)).unwrap();
        let conf = FetchConfig {
            client_sha256: file_digest(&client).unwrap(),
            client_binary: client.clone(),
            bitcoin_rpc_url: "http://127.0.0.1:8332".into(),
            bitcoin_rpc_cookie_file: cookie,
            raito_bridge_url: "https://api.raito.wtf".into(),
        };
        let conf_path = dir.join("fetch.json");
        fs::write(
            &conf_path,
            serde_json::json!({
                "client_binary":conf.client_binary,
                "client_sha256":conf.client_sha256,
                "bitcoin_rpc_url":conf.bitcoin_rpc_url,
                "bitcoin_rpc_cookie_file":conf.bitcoin_rpc_cookie_file,
                "raito_bridge_url":conf.raito_bridge_url,
            })
            .to_string(),
        )
        .unwrap();
        fs::set_permissions(&conf_path, fs::Permissions::from_mode(0o600)).unwrap();
        let loaded = operator_config(&conf_path).unwrap();
        fetch(&args, &loaded).await.unwrap();
        assert_eq!(
            fs::read(&args.output).unwrap(),
            b"unverified-compressed-proof-test-bytes"
        );
        assert!(fetch(&args, &loaded).await.is_err());
        fs::remove_file(&args.output).unwrap();
        fs::write(&client, "#!/bin/sh\nexit 0\n").unwrap();
        assert!(operator_config(&conf_path).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
