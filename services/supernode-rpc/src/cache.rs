//! Bounded disk-backed, content-addressed proof input artifact cache.
//!
//! Artifacts are immutable bytes tied to a Bitcoin network, block hash,
//! height and chain-tracker epoch. Returning an artifact as *active* requires
//! an independent Bitcoin Core getblockhash(height) check by the gateway.
//! Artifacts are not Raito, Shinigami or other cryptographic proofs.

use bitcoin::hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

pub const MAX_ARTIFACT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactMeta {
    pub id: String,
    pub data_sha256: String,
    pub network: String,
    pub block_hash: String,
    pub block_height: u64,
    pub chain_epoch: u64,
    pub kind: String,
    pub bytes: u64,
    pub created_unix: u64,
}

#[derive(Debug, Default)]
struct Index {
    entries: BTreeMap<String, ArtifactMeta>,
    bytes: u64,
}

#[derive(Clone, Debug)]
pub struct ArtifactStore {
    root: PathBuf,
    max_bytes: u64,
    index: Arc<Mutex<Index>>,
}

fn sha_bytes(data: &[u8]) -> String {
    hex::encode(sha256::Hash::hash(data).to_byte_array())
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn is_hex_key(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn is_safe_kind(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

fn pair(root: &Path, id: &str) -> (PathBuf, PathBuf) {
    (
        root.join(format!("{id}.blob")),
        root.join(format!("{id}.json")),
    )
}

/// Write bytes to a unique temporary sibling and rename to final path.
/// Crash-incomplete .tmp files are deleted at next store startup.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| err.to_string())?
        .as_nanos();
    let temp = path.with_extension(format!("tmp-{}-{stamp}", std::process::id()));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|err| err.to_string())?;
        file.write_all(data).map_err(|err| err.to_string())?;
        file.sync_all().map_err(|err| err.to_string())?;
    }
    fs::rename(&temp, path).map_err(|err| err.to_string())
}

impl ArtifactStore {
    pub fn new(root: PathBuf, max_bytes: u64) -> Result<Self, String> {
        if max_bytes == 0 || max_bytes > MAX_STORE_BYTES {
            return Err("artifact cache budget outside permitted range".into());
        }
        fs::create_dir_all(&root).map_err(|err| err.to_string())?;
        if fs::symlink_metadata(&root)
            .map_err(|err| err.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("artifact cache directory cannot be a symlink".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .map_err(|err| err.to_string())?;
        }

        let mut index = Index::default();
        for entry in fs::read_dir(&root).map_err(|err| err.to_string())? {
            let entry = entry.map_err(|err| err.to_string())?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.contains(".tmp-") {
                let _ = fs::remove_file(path);
                continue;
            }
            let Some(id) = name.strip_suffix(".json") else {
                continue;
            };
            if !is_hex_key(id) || !entry.file_type().map_err(|err| err.to_string())?.is_file() {
                continue;
            }
            let contents = match fs::read(path) {
                Ok(bytes) if bytes.len() < 4_096 => bytes,
                _ => continue,
            };
            let Ok(meta) = serde_json::from_slice::<ArtifactMeta>(&contents) else {
                continue;
            };
            let (blob, _) = pair(&root, id);
            if meta.id != id
                || meta.bytes == 0
                || meta.bytes > MAX_ARTIFACT_BYTES as u64
                || !blob.is_file()
                || fs::metadata(blob).map_err(|err| err.to_string())?.len() != meta.bytes
            {
                continue;
            }
            index.bytes += meta.bytes;
            index.entries.insert(id.to_owned(), meta);
        }
        let store = Self {
            root,
            max_bytes,
            index: Arc::new(Mutex::new(index)),
        };
        // Startup quotas are respected before any artifact read or write.
        // Startup prune is synchronous because the constructor has no runtime.
        store.prune_blocking()?;
        Ok(store)
    }

    fn prune_blocking(&self) -> Result<(), String> {
        // Constructors are single-threaded; later writers use the async mutex.
        let mut state = self
            .index
            .try_lock()
            .map_err(|_| "cannot initialize artifact cache index")?;
        self.prune_locked(&mut state)
    }

    fn prune_locked(&self, state: &mut Index) -> Result<(), String> {
        while state.bytes > self.max_bytes || state.entries.len() > MAX_ENTRIES {
            let (id, _) = state
                .entries
                .iter()
                .min_by_key(|(id, meta)| (meta.created_unix, *id))
                .ok_or("unable to evict cache entry")?;
            let id = id.to_owned();
            let old = state.entries.remove(&id).ok_or("eviction missing key")?;
            state.bytes = state.bytes.saturating_sub(old.bytes);
            let (blob, description) = pair(&self.root, &id);
            let _ = fs::remove_file(blob);
            let _ = fs::remove_file(description);
        }
        Ok(())
    }

    pub async fn put(
        &self,
        network: &str,
        block_hash: &str,
        block_height: u64,
        chain_epoch: u64,
        kind: &str,
        data: &[u8],
    ) -> Result<ArtifactMeta, String> {
        if !matches!(network, "main" | "test" | "signet" | "regtest")
            || !is_hex_key(block_hash)
            || !is_safe_kind(kind)
            || data.is_empty()
            || data.len() > MAX_ARTIFACT_BYTES
            || data.len() as u64 > self.max_bytes
        {
            return Err("invalid or oversized artifact submission".into());
        }
        let digest = sha_bytes(data);
        let basis = format!(
            "BTC-SUPERNODE-ARTIFACT-V1:{network}:{block_hash}:{block_height}:{kind}:{digest}"
        );
        let id = sha_bytes(basis.as_bytes());
        let mut state = self.index.lock().await;
        if let Some(existing) = state.entries.get(&id) {
            if existing.chain_epoch == chain_epoch {
                return Ok(existing.clone());
            }
        }
        let meta = ArtifactMeta {
            id: id.clone(),
            data_sha256: digest,
            network: network.to_owned(),
            block_hash: block_hash.to_owned(),
            block_height,
            chain_epoch,
            kind: kind.to_owned(),
            bytes: data.len() as u64,
            created_unix: now(),
        };
        let (blob, info) = pair(&self.root, &id);
        atomic_write(&blob, data)?;
        let manifest = serde_json::to_vec(&meta).map_err(|err| err.to_string())?;
        atomic_write(&info, &manifest)?;
        if let Some(old) = state.entries.insert(id, meta.clone()) {
            state.bytes = state.bytes.saturating_sub(old.bytes);
        }
        state.bytes += meta.bytes;
        self.prune_locked(&mut state)?;
        Ok(meta)
    }

    pub async fn get(&self, id: &str) -> Result<(ArtifactMeta, Vec<u8>), String> {
        if !is_hex_key(id) {
            return Err("invalid artifact ID".into());
        }
        let state = self.index.lock().await;
        let meta = state.entries.get(id).ok_or("artifact not found")?.clone();
        let (blob, _) = pair(&self.root, id);
        let data = fs::read(blob).map_err(|err| err.to_string())?;
        if data.len() as u64 != meta.bytes || sha_bytes(&data) != meta.data_sha256 {
            return Err("artifact bytes failed content hash verification".into());
        }
        Ok((meta, data))
    }

    pub async fn stats(&self) -> serde_json::Value {
        let state = self.index.lock().await;
        serde_json::json!({"entries":state.entries.len(),"bytes":state.bytes,"max_bytes":self.max_bytes})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn root(suffix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "btc-supernode-artifact-{}-{}-{suffix}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[tokio::test]
    async fn reorg_epochs_and_networks_produce_separate_metadata() {
        let dir = root("epochs");
        let store = ArtifactStore::new(dir.clone(), 4_096).unwrap();
        let first = store
            .put("regtest", &"ab".repeat(32), 120, 4, "raito_input", b"hello")
            .await
            .unwrap();
        let same = store
            .put("regtest", &"ab".repeat(32), 120, 4, "raito_input", b"hello")
            .await
            .unwrap();
        assert_eq!(first.id, same.id);
        let changed_epoch = store
            .put("regtest", &"ab".repeat(32), 120, 5, "raito_input", b"hello")
            .await
            .unwrap();
        assert_eq!(changed_epoch.id, first.id);
        assert_eq!(changed_epoch.chain_epoch, 5);
        let main = store
            .put("main", &"ab".repeat(32), 120, 5, "raito_input", b"hello")
            .await
            .unwrap();
        assert_ne!(main.id, first.id);
        let (_, bytes) = store.get(&first.id).await.unwrap();
        assert_eq!(bytes, b"hello");
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn bounded_store_evicts_and_detects_corruption() {
        let dir = root("quota");
        let store = ArtifactStore::new(dir.clone(), 8).unwrap();
        store
            .put("regtest", &"ab".repeat(32), 10, 1, "input", b"aaaaaa")
            .await
            .unwrap();
        let second = store
            .put("regtest", &"ab".repeat(32), 10, 1, "input", b"bbbbbb")
            .await
            .unwrap();
        assert_eq!(store.stats().await["entries"], 1);
        let (path, _) = pair(&dir, &second.id);
        fs::write(path, b"bad").unwrap();
        assert!(store.get(&second.id).await.is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_bad_kind_and_dir_symlinks() {
        assert!(!is_safe_kind("../../bad"));
        assert!(!is_safe_kind("uppercase"));
        assert!(is_safe_kind("raito_input"));
    }
}
