//! Durable, admission-controlled proving dispatch to operator-configured workers.
//!
//! The RPC client cannot choose commands or read arbitrary files. A job's
//! memory estimate is an *admission reservation*, not an operating-system RSS
//! limit. Configure cgroups/containers around approved prover binaries.

use bitcoin::hashes::{sha256, Hash, HashEngine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::str::FromStr;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    process::Command,
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

use crate::{
    cache::ArtifactStore,
    chain::ChainTracker,
    verification::{RaitoVerifiedReceipt, RaitoVerifier},
    CoreRpc,
};

pub const MAX_PENDING_JOBS: usize = 16;
pub const MAX_JOB_HISTORY: usize = 128;
pub const MAX_ESTIMATED_MEMORY_MIB: u32 = 32 * 1024;
pub const MAX_WORKER_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_RETAINED_RESULT_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_RESULT_CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_WORKER_DURATION: Duration = Duration::from_secs(600);

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn is_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|ch| ch.is_ascii_hexdigit())
}
fn secure_dir(root: &Path) -> Result<(), String> {
    fs::create_dir_all(root).map_err(|err| err.to_string())?;
    if fs::symlink_metadata(root)
        .map_err(|err| err.to_string())?
        .file_type()
        .is_symlink()
    {
        return Err("job directory cannot be a symlink".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .map_err(|err| err.to_string())?;
    }
    Ok(())
}
fn atomic_json(root: &Path, job: &JobRecord) -> Result<(), String> {
    let path = root.join(format!("{}.json", job.id));
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| err.to_string())?
        .as_nanos();
    let temp = root.join(format!("{}.tmp-{}-{micros}", job.id, std::process::id()));
    let bytes = serde_json::to_vec(job).map_err(|err| err.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|err| err.to_string())?;
    file.write_all(&bytes).map_err(|err| err.to_string())?;
    file.sync_all().map_err(|err| err.to_string())?;
    fs::rename(&temp, &path).map_err(|err| err.to_string())
}
fn hash_bytes(bytes: &[u8]) -> String {
    hex::encode(sha256::Hash::hash(bytes).to_byte_array())
}

/// Calculate one full result digest and a hash for each aligned 64 KiB
/// chunk using a fixed buffer. The index is at most 32 KiB for a 64 MiB file.
fn checked_result_digest(path: &Path) -> Result<(String, u64, Vec<u8>), String> {
    let metadata = fs::symlink_metadata(path).map_err(|err| err.to_string())?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_WORKER_OUTPUT_BYTES
    {
        return Err("worker output absent, unsafe or over size cap".into());
    }
    let mut file = File::open(path).map_err(|err| err.to_string())?;
    let mut whole = sha256::Hash::engine();
    let mut indexes = Vec::new();
    let mut buffer = [0u8; MAX_RESULT_CHUNK_BYTES];
    let mut offset = 0u64;
    while offset < metadata.len() {
        let n = (metadata.len() - offset).min(MAX_RESULT_CHUNK_BYTES as u64) as usize;
        file.read_exact(&mut buffer[..n])
            .map_err(|err| err.to_string())?;
        whole.input(&buffer[..n]);
        indexes.extend_from_slice(sha256::Hash::hash(&buffer[..n]).as_byte_array());
        offset += n as u64;
    }
    let mut extra = [0u8; 1];
    if file.read(&mut extra).map_err(|err| err.to_string())? != 0 {
        return Err("worker output changed while hashing".into());
    }
    Ok((
        hex::encode(sha256::Hash::from_engine(whole).to_byte_array()),
        offset,
        indexes,
    ))
}

/// Publish the small chunk index atomically and bind it to the job record.
fn write_chunk_index(root: &Path, id: &str, index: &[u8]) -> Result<(), String> {
    let output = root.join(format!("{id}.chunks"));
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| err.to_string())?
        .as_nanos();
    let temporary = root.join(format!("{id}.tmp-{}-{ns}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|err| err.to_string())?;
    file.write_all(index).map_err(|err| err.to_string())?;
    file.sync_all().map_err(|err| err.to_string())?;
    fs::rename(temporary, output).map_err(|err| err.to_string())
}

/// Read only the aligned chunks touched by the requested slice. Each chunk
/// is authenticated against the small digest index stored alongside the job.
fn indexed_chunk(
    root: &Path,
    id: &str,
    expected_index_sha: &str,
    length: u64,
    offset: u64,
    requested: usize,
) -> Result<Vec<u8>, String> {
    let path = root.join(format!("{id}.output"));
    let meta = fs::symlink_metadata(&path).map_err(|err| err.to_string())?;
    if !meta.file_type().is_file() || meta.len() != length {
        return Err("worker result no longer has the expected length".into());
    }
    let index_path = root.join(format!("{id}.chunks"));
    let expected_count = length.div_ceil(MAX_RESULT_CHUNK_BYTES as u64) as usize;
    let index_meta = fs::symlink_metadata(&index_path).map_err(|err| err.to_string())?;
    if !index_meta.file_type().is_file() || index_meta.len() != (expected_count * 32) as u64 {
        return Err("worker chunk index absent or incorrect length".into());
    }
    let index = fs::read(index_path).map_err(|err| err.to_string())?;
    if hash_bytes(&index) != expected_index_sha {
        return Err("worker chunk index failed SHA-256 integrity check".into());
    }
    if requested == 0 {
        return Ok(Vec::new());
    }
    let mut file = File::open(&path).map_err(|err| err.to_string())?;
    let end = offset + requested as u64;
    let first = offset / MAX_RESULT_CHUNK_BYTES as u64;
    let last = (end - 1) / MAX_RESULT_CHUNK_BYTES as u64;
    let mut answer = Vec::with_capacity(requested);
    for chunk_no in first..=last {
        let start = chunk_no * MAX_RESULT_CHUNK_BYTES as u64;
        let len = (length - start).min(MAX_RESULT_CHUNK_BYTES as u64) as usize;
        let mut chunk = vec![0u8; len];
        file.seek(SeekFrom::Start(start))
            .map_err(|err| err.to_string())?;
        file.read_exact(&mut chunk).map_err(|err| err.to_string())?;
        let hash_start = chunk_no as usize * 32;
        let digest = sha256::Hash::hash(&chunk).to_byte_array();
        if digest[..] != index[hash_start..hash_start + 32] {
            return Err("worker output chunk failed SHA-256 integrity check".into());
        }
        let begin = (offset.max(start) - start) as usize;
        let finish = (end.min(start + len as u64) - start) as usize;
        answer.extend_from_slice(&chunk[begin..finish]);
    }
    let end_meta = file.metadata().map_err(|err| err.to_string())?;
    if end_meta.len() != length {
        return Err("worker result size changed during reading".into());
    }
    Ok(answer)
}

/// Bound the total amount of *retained* worker output. An evicted job keeps
/// its SHA-256 audit digest but cannot serve stale data to RPC consumers.
fn prune_result_files(
    root: &Path,
    records: &mut BTreeMap<String, JobRecord>,
    max_bytes: u64,
) -> Result<(), String> {
    let mut retained = Vec::new();
    let mut total = 0u64;
    for (id, record) in records.iter_mut() {
        if !matches!(
            record.status,
            JobStatus::CompletedUnverified | JobStatus::VerifyingRaito | JobStatus::VerifiedRaito
        ) {
            continue;
        }
        let path = root.join(format!("{id}.output"));
        let length = fs::symlink_metadata(&path)
            .ok()
            .filter(|meta| meta.file_type().is_file())
            .map(|meta| meta.len());
        match length {
            Some(length) if (1..=MAX_WORKER_OUTPUT_BYTES).contains(&length) => {
                record.result_bytes = Some(length);
                total = total.saturating_add(length);
                // A verifier is actively reading this file. Evict only
                // completed results, otherwise a quota sweep can corrupt
                // ongoing verification and waste a costly STARK run.
                if record.status != JobStatus::VerifyingRaito {
                    retained.push((record.submitted_unix, id.clone(), length));
                }
            }
            _ => {
                record.status = JobStatus::OutputEvicted;
                record.result_bytes = None;
                record.error = Some("worker result is no longer retained".into());
                atomic_json(root, record)?;
            }
        }
    }
    retained.sort();
    for (_, id, size) in retained {
        if total <= max_bytes {
            break;
        }
        let record = records.get_mut(&id).ok_or("retained result missing")?;
        let path = root.join(format!("{id}.output"));
        fs::remove_file(&path).map_err(|err| err.to_string())?;
        let _ = fs::remove_file(root.join(format!("{id}.chunks")));
        total = total.saturating_sub(size);
        record.status = JobStatus::OutputEvicted;
        record.result_bytes = None;
        record.error = Some("worker result evicted by disk quota".into());
        atomic_json(root, record)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    Raito,
    Shinigami,
}
impl JobKind {
    fn from_name(value: &str) -> Result<Self, String> {
        match value {
            "raito" => Ok(Self::Raito),
            "shinigami" => Ok(Self::Shinigami),
            _ => Err("unsupported proving backend".into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    CompletedUnverified,
    VerifyingRaito,
    VerifiedRaito,
    OutputEvicted,
    Failed,
    Interrupted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRecord {
    pub id: String,
    pub kind: JobKind,
    pub input_artifact_id: String,
    pub network: String,
    pub block_hash: String,
    pub block_height: u64,
    pub chain_epoch: u64,
    pub policy_sha256: String,
    pub estimated_memory_mib: u32,
    #[serde(default)]
    pub expected_txid: Option<String>,
    pub status: JobStatus,
    pub result_sha256: Option<String>,
    #[serde(default)]
    pub result_bytes: Option<u64>,
    #[serde(default)]
    pub result_chunk_index_sha256: Option<String>,
    #[serde(default)]
    pub verified_raito: Option<RaitoVerifiedReceipt>,
    pub error: Option<String>,
    pub submitted_unix: u64,
    pub finished_unix: Option<u64>,
}

#[derive(Clone, Default)]
pub struct WorkerPrograms {
    pub raito: Option<PathBuf>,
    pub shinigami: Option<PathBuf>,
}
impl WorkerPrograms {
    fn executable(&self, kind: &JobKind) -> Option<PathBuf> {
        match kind {
            JobKind::Raito => self.raito.clone(),
            JobKind::Shinigami => self.shinigami.clone(),
        }
    }
    fn enabled(&self, kind: &JobKind) -> bool {
        self.executable(kind)
            .is_some_and(|path| path.is_absolute() && path.is_file())
    }
}

/// Shared dispatcher limits, including the advisory prover/verifier memory pool.
#[derive(Debug, Clone)]
pub struct JobLimits {
    pub memory_budget_mib: u32,
    pub worker_count: usize,
    /// Operator-owned configuration; only forwarded to approved Raito workers.
    pub raito_fetch_config: Option<PathBuf>,
}

pub struct JobManager {
    root: PathBuf,
    artifacts: Arc<ArtifactStore>,
    core: CoreRpc,
    chain: Arc<ChainTracker>,
    workers: WorkerPrograms,
    raito_verifier: Option<RaitoVerifier>,
    raito_fetch_config: Option<PathBuf>,
    memory: Arc<Semaphore>,
    slots: Arc<Semaphore>,
    queue_slots: Arc<Semaphore>,
    memory_budget_mib: u32,
    worker_count: usize,
    records: Mutex<BTreeMap<String, JobRecord>>,
}

impl JobManager {
    pub fn new(
        root: PathBuf,
        artifacts: Arc<ArtifactStore>,
        core: CoreRpc,
        chain: Arc<ChainTracker>,
        workers: WorkerPrograms,
        memory_budget_mib: u32,
        worker_count: usize,
    ) -> Result<Arc<Self>, String> {
        Self::new_with_verifier(
            root,
            artifacts,
            core,
            chain,
            workers,
            None,
            JobLimits {
                memory_budget_mib,
                worker_count,
                raito_fetch_config: None,
            },
        )
    }

    pub fn new_with_verifier(
        root: PathBuf,
        artifacts: Arc<ArtifactStore>,
        core: CoreRpc,
        chain: Arc<ChainTracker>,
        workers: WorkerPrograms,
        raito_verifier: Option<RaitoVerifier>,
        limits: JobLimits,
    ) -> Result<Arc<Self>, String> {
        let JobLimits {
            memory_budget_mib,
            worker_count,
            raito_fetch_config,
        } = limits;
        if let Some(ref path) = raito_fetch_config {
            if !path.is_absolute()
                || !fs::symlink_metadata(path)
                    .map(|m| m.file_type().is_file())
                    .unwrap_or(false)
            {
                return Err("Raito fetch configuration must be an absolute regular file".into());
            }
        }
        if let Some(ref verifier) = raito_verifier {
            verifier.validate()?;
        }
        if memory_budget_mib == 0
            || memory_budget_mib > MAX_ESTIMATED_MEMORY_MIB
            || !(1..=4).contains(&worker_count)
        {
            return Err("invalid proof worker count or memory budget".into());
        }
        secure_dir(&root)?;
        for binary in [&workers.raito, &workers.shinigami].into_iter().flatten() {
            if !binary.is_absolute() || !binary.is_file() {
                return Err(
                    "proof worker executable path must be an existing absolute file".into(),
                );
            }
        }
        let mut records = BTreeMap::new();
        for entry in fs::read_dir(&root).map_err(|err| err.to_string())? {
            let entry = entry.map_err(|err| err.to_string())?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains(".tmp-") || name.strip_suffix(".verifytmp").is_some_and(is_hash) {
                let _ = fs::remove_file(entry.path());
                continue;
            }
            let Some(id) = name.strip_suffix(".json") else {
                continue;
            };
            if !is_hash(id) || !entry.file_type().map_err(|err| err.to_string())?.is_file() {
                continue;
            }
            let Ok(bytes) = fs::read(entry.path()) else {
                continue;
            };
            if bytes.len() > 4_096 {
                continue;
            }
            let Ok(mut record) = serde_json::from_slice::<JobRecord>(&bytes) else {
                continue;
            };
            if record.id != id {
                continue;
            }
            if record.status == JobStatus::VerifyingRaito {
                // Preserve a complete proof artifact after a gateway crash.
                // A verifier may have been killed during restart; its result
                // was never durably accepted as a verified statement.
                record.status = JobStatus::CompletedUnverified;
                record.error = Some("gateway restarted during Raito verification".into());
                record.finished_unix = Some(unix_time());
                atomic_json(&root, &record)?;
            }
            if matches!(record.status, JobStatus::Queued | JobStatus::Running) {
                record.status = JobStatus::Interrupted;
                record.error = Some("gateway restarted; job must be resubmitted".into());
                record.finished_unix = Some(unix_time());
                atomic_json(&root, &record)?;
            }
            records.insert(id.to_owned(), record);
        }
        if records.len() > MAX_JOB_HISTORY {
            let oldest = records
                .iter()
                .map(|(id, rec)| (rec.submitted_unix, id.clone()))
                .collect::<Vec<_>>();
            let mut oldest = oldest;
            oldest.sort();
            for (_, id) in oldest.into_iter().take(records.len() - MAX_JOB_HISTORY) {
                records.remove(&id);
                let _ = fs::remove_file(root.join(format!("{id}.json")));
                let _ = fs::remove_file(root.join(format!("{id}.input")));
                let _ = fs::remove_file(root.join(format!("{id}.output")));
                let _ = fs::remove_file(root.join(format!("{id}.chunks")));
            }
        }
        // Orphaned inputs and failed/abandoned outputs are not retained
        // across restarts. Only a completed record may own an output file.
        for entry in fs::read_dir(&root).map_err(|err| err.to_string())? {
            let entry = entry.map_err(|err| err.to_string())?;
            let name = entry.file_name().to_string_lossy().to_string();
            let cleanup = name.strip_suffix(".chunks").is_some_and(|id| {
                is_hash(id)
                    && !records.get(id).is_some_and(|r| {
                        matches!(
                            r.status,
                            JobStatus::CompletedUnverified
                                | JobStatus::VerifyingRaito
                                | JobStatus::VerifiedRaito
                        )
                    })
            }) || name.strip_suffix(".input").is_some_and(is_hash)
                || name.strip_suffix(".output").is_some_and(|id| {
                    is_hash(id)
                        && !records.get(id).is_some_and(|record| {
                            matches!(
                                record.status,
                                JobStatus::CompletedUnverified
                                    | JobStatus::VerifyingRaito
                                    | JobStatus::VerifiedRaito
                            )
                        })
                });
            if cleanup && entry.file_type().map_err(|err| err.to_string())?.is_file() {
                let _ = fs::remove_file(entry.path());
            }
        }
        prune_result_files(&root, &mut records, MAX_RETAINED_RESULT_BYTES)?;
        Ok(Arc::new(Self {
            root,
            artifacts,
            core,
            chain,
            workers,
            raito_verifier,
            raito_fetch_config,
            memory: Arc::new(Semaphore::new(memory_budget_mib as usize)),
            slots: Arc::new(Semaphore::new(worker_count)),
            queue_slots: Arc::new(Semaphore::new(MAX_PENDING_JOBS)),
            memory_budget_mib,
            worker_count,
            records: Mutex::new(records),
        }))
    }

    pub fn capabilities(&self) -> Value {
        json!({
            "queue_enabled":true,
            "raito_worker_configured":self.workers.enabled(&JobKind::Raito),
            "raito_verifier_configured":self.raito_verifier.is_some(),
            "raito_fetch_configured":self.raito_fetch_config.is_some(),
            "typed_raito_receipts_enabled":self.raito_verifier.is_some(),
            "verification_retry_available":self.raito_verifier.is_some(),
            "shinigami_worker_configured":self.workers.enabled(&JobKind::Shinigami),
            "max_pending":MAX_PENDING_JOBS,
            "max_worker_count":self.worker_count,
            "memory_admission_budget_mib":self.memory_budget_mib,
            "hard_os_memory_limit_enforced":false,
            "max_worker_time_seconds":MAX_WORKER_DURATION.as_secs(),
            "max_result_chunk_bytes":MAX_RESULT_CHUNK_BYTES,
            "max_retained_result_bytes":MAX_RETAINED_RESULT_BYTES,
            "results_are_cryptographically_verified":false
        })
    }

    pub fn raito_verifier_configured(&self) -> bool {
        self.raito_verifier.is_some()
    }

    pub fn raito_worker_configured(&self) -> bool {
        self.workers.enabled(&JobKind::Raito)
    }

    pub async fn status(&self, id: &str) -> Result<JobRecord, String> {
        if !is_hash(id) {
            return Err("invalid job identifier".into());
        }
        self.records
            .lock()
            .await
            .get(id)
            .cloned()
            .ok_or("job identifier not found".into())
    }

    async fn check_chain(&self, record: &JobRecord) -> Result<(), String> {
        let actual = self
            .core
            .call("getblockhash", json!([record.block_height]))
            .await
            .map_err(|error| error.message)?;
        if actual.as_str() != Some(record.block_hash.as_str()) {
            return Err("job's block was disconnected or chain changed".into());
        }
        let network = self
            .core
            .call("getblockchaininfo", json!([]))
            .await
            .map_err(|error| error.message)?;
        if network["chain"].as_str() != Some(record.network.as_str()) {
            return Err("proving input belongs to a different Bitcoin network".into());
        }
        Ok(())
    }

    /// Admission consumes a bounded queue slot. Memory and process slots are
    /// reserved when execution starts; requested MiB is advisory sizing.
    pub async fn submit(
        self: &Arc<Self>,
        backend: &str,
        artifact_id: &str,
        memory_mib: u32,
        policy_sha256: &str,
    ) -> Result<JobRecord, String> {
        self.submit_with_txid(backend, artifact_id, memory_mib, policy_sha256, None)
            .await
    }

    pub async fn submit_with_txid(
        self: &Arc<Self>,
        backend: &str,
        artifact_id: &str,
        memory_mib: u32,
        policy_sha256: &str,
        expected_txid: Option<&str>,
    ) -> Result<JobRecord, String> {
        let kind = JobKind::from_name(backend)?;
        if expected_txid.is_some() && kind != JobKind::Raito {
            return Err("only Raito submissions may specify an expected TXID".into());
        }
        let expected_txid = expected_txid
            .map(|txid| bitcoin::Txid::from_str(txid).map(|parsed| parsed.to_string()))
            .transpose()
            .map_err(|_| "invalid expected Bitcoin TXID")?;
        if !self.workers.enabled(&kind) {
            return Err("requested proving worker is not configured".into());
        }
        if memory_mib == 0 || memory_mib > self.memory_budget_mib || !is_hash(policy_sha256) {
            return Err("invalid memory reservation or policy hash".into());
        }
        let queue_permit = self
            .queue_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| "proof queue capacity exhausted")?;
        let (meta, _) = self.artifacts.get(artifact_id).await?;
        let marker = format!(
            "{}:{}:{:?}:{}:{policy_sha256}:{}",
            meta.id,
            meta.block_hash,
            kind,
            unix_time(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let id = hash_bytes(marker.as_bytes());
        let record = JobRecord {
            id: id.clone(),
            kind,
            input_artifact_id: meta.id,
            network: meta.network,
            block_hash: meta.block_hash,
            block_height: meta.block_height,
            chain_epoch: meta.chain_epoch,
            policy_sha256: policy_sha256.to_owned(),
            estimated_memory_mib: memory_mib,
            expected_txid,
            status: JobStatus::Queued,
            result_sha256: None,
            result_bytes: None,
            result_chunk_index_sha256: None,
            verified_raito: None,
            error: None,
            submitted_unix: unix_time(),
            finished_unix: None,
        };
        self.check_chain(&record).await?;
        // Epoch is captured for diagnostics; active-chain checks decide validity.
        let _observed_epoch = self.chain.epoch().await;
        {
            let mut state = self.records.lock().await;
            if state.len() >= MAX_JOB_HISTORY {
                let oldest_done = state
                    .iter()
                    .filter(|(_, record)| {
                        !matches!(
                            record.status,
                            JobStatus::Queued | JobStatus::Running | JobStatus::VerifyingRaito
                        )
                    })
                    .min_by_key(|(_, record)| record.submitted_unix)
                    .map(|(id, _)| id.clone());
                if let Some(old_id) = oldest_done {
                    state.remove(&old_id);
                    let _ = fs::remove_file(self.root.join(format!("{old_id}.json")));
                    let _ = fs::remove_file(self.root.join(format!("{old_id}.input")));
                    let _ = fs::remove_file(self.root.join(format!("{old_id}.output")));
                    let _ = fs::remove_file(self.root.join(format!("{old_id}.chunks")));
                } else {
                    return Err("job record retention cap reached".into());
                }
            }
            atomic_json(&self.root, &record)?;
            state.insert(id.clone(), record.clone());
        }
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            manager.run(id, queue_permit).await;
        });
        Ok(record)
    }

    async fn set_status(
        &self,
        id: &str,
        status: JobStatus,
        digest: Option<String>,
        length: Option<u64>,
        index_sha256: Option<String>,
        error: Option<String>,
    ) {
        let mut records = self.records.lock().await;
        if let Some(record) = records.get_mut(id) {
            record.status = status.clone();
            record.result_sha256 = digest;
            record.result_bytes = length;
            record.result_chunk_index_sha256 = index_sha256;
            record.verified_raito = None;
            record.error = error;
            if !matches!(
                status,
                JobStatus::Queued | JobStatus::Running | JobStatus::VerifyingRaito
            ) {
                record.finished_unix = Some(unix_time());
            }
            if let Err(err) = atomic_json(&self.root, record) {
                eprintln!("Could not persist proof job status: {err}");
            }
        }
        if matches!(
            status,
            JobStatus::CompletedUnverified | JobStatus::VerifyingRaito
        ) {
            if let Err(err) =
                prune_result_files(&self.root, &mut records, MAX_RETAINED_RESULT_BYTES)
            {
                eprintln!("Could not enforce proof output retention quota: {err}");
            }
        }
    }

    /// Verify the retained output without re-running an expensive prover.
    /// A fresh RPC submission is never able to claim verification by itself.
    pub async fn retry_verification(self: &Arc<Self>, id: &str) -> Result<JobRecord, String> {
        if self.raito_verifier.is_none() {
            return Err("Raito verifier is not configured".into());
        }
        let queue_permit = self
            .queue_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| "proof verification queue capacity exhausted")?;
        let original = self.status(id).await?;
        if original.kind != JobKind::Raito
            || original.expected_txid.is_none()
            || original.status != JobStatus::CompletedUnverified
        {
            return Err(
                "only retained unverified Raito jobs with an expected TXID can be retried".into(),
            );
        }
        let digest = original
            .result_sha256
            .as_deref()
            .ok_or("job lacks a persisted result digest")?;
        self.check_chain(&original).await?;
        let path = self.root.join(format!("{id}.output"));
        let (actual, size, _) = checked_result_digest(&path)?;
        if digest != actual || original.result_bytes.is_some_and(|n| n != size) {
            return Err("retained output differs from the persisted digest or size".into());
        }
        let mut updated = original.clone();
        updated.status = JobStatus::VerifyingRaito;
        updated.error = None;
        updated.finished_unix = None;
        {
            let mut state = self.records.lock().await;
            if state
                .get(id)
                .is_none_or(|record| record.status != JobStatus::CompletedUnverified)
            {
                return Err("proof verification is already running or the job changed".into());
            }
            atomic_json(&self.root, &updated)?;
            state.insert(id.to_owned(), updated.clone());
        }
        let manager = Arc::clone(self);
        let id = id.to_owned();
        let digest = actual;
        tokio::spawn(async move {
            let _permit = queue_permit;
            if let Err(error) = manager
                .verify_existing_record(&original, &digest, size)
                .await
            {
                manager.mark_verification_failed(&id, error).await;
            }
        });
        Ok(updated)
    }

    /// One shared verification path for freshly produced and retained proof
    /// bytes. Both cases consume the same admission/worker-slot semaphores.
    async fn verify_existing_record(
        &self,
        record: &JobRecord,
        digest: &str,
        size: u64,
    ) -> Result<(), String> {
        let verifier = self
            .raito_verifier
            .as_ref()
            .ok_or("Raito verifier is not configured")?;
        let _memory = self
            .memory
            .clone()
            .acquire_many_owned(record.estimated_memory_mib)
            .await
            .map_err(|error| error.to_string())?;
        let _slot = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|error| error.to_string())?;
        self.check_chain(record).await?;
        let report = verifier.verify(&self.root, record, digest).await?;
        let path = self.root.join(format!("{}.output", record.id));
        let (actual, actual_size, _) = checked_result_digest(&path)?;
        if actual != digest || actual_size != size {
            return Err("proof output changed during Raito verification".into());
        }
        self.check_chain(record).await?;
        self.publish_raito_verified(&record.id, report).await
    }

    async fn mark_verification_failed(&self, id: &str, error: String) {
        let mut state = self.records.lock().await;
        if let Some(current) = state
            .get_mut(id)
            .filter(|record| record.status == JobStatus::VerifyingRaito)
        {
            current.status = JobStatus::CompletedUnverified;
            current.finished_unix = Some(unix_time());
            current.error = Some(format!("Raito verification: {error}"));
            if let Err(error) = atomic_json(&self.root, current) {
                eprintln!("Could not persist verification failure: {error}");
            }
        }
    }

    /// Publish a typed receipt only when it comes from the operator-pinned
    /// external Raito verifier and is bound to the recorded worker bytes.
    async fn publish_raito_verified(
        &self,
        id: &str,
        report: RaitoVerifiedReceipt,
    ) -> Result<(), String> {
        let mut state = self.records.lock().await;
        let record = state.get(id).ok_or("verified job missing")?;
        if record.status != JobStatus::VerifyingRaito {
            return Err("job output was evicted or verification was interrupted".into());
        }
        let digest = record
            .result_sha256
            .as_deref()
            .ok_or("job has no recorded proof digest")?;
        report.validate(record, digest)?;
        let mut updated = record.clone();
        updated.status = JobStatus::VerifiedRaito;
        updated.finished_unix = Some(unix_time());
        updated.error = None;
        updated.verified_raito = Some(report);
        atomic_json(&self.root, &updated)?;
        state.insert(id.to_owned(), updated);
        prune_result_files(&self.root, &mut state, MAX_RETAINED_RESULT_BYTES)?;
        Ok(())
    }

    pub async fn verified_receipt(&self, id: &str) -> Result<Value, String> {
        let record = self.status(id).await?;
        if !matches!(
            record.status,
            JobStatus::VerifiedRaito | JobStatus::OutputEvicted
        ) {
            return Err("job does not have a verified Raito status".into());
        }
        let receipt = record
            .verified_raito
            .as_ref()
            .ok_or("Raito proof has no verified receipt")?;
        let digest = record
            .result_sha256
            .as_deref()
            .ok_or("job has no recorded proof digest")?;
        receipt.validate(&record, digest)?;
        self.check_chain(&record).await?;
        Ok(json!({
            "job_id":record.id,
            "proof_verified":true,
            "verified_statement":receipt,
            "active_chain_at_lookup":true,
            "output_retained":record.status == JobStatus::VerifiedRaito,
            "result_sha256":record.result_sha256
        }))
    }

    /// Return small, hash-checked chunks. Cryptographic verification is
    /// asserted only for an accepted typed Raito receipt. Chain binding is
    /// rechecked on each retrieval.
    pub async fn result_chunk(
        &self,
        id: &str,
        offset: u64,
        requested: usize,
    ) -> Result<Value, String> {
        if requested == 0 || requested > MAX_RESULT_CHUNK_BYTES {
            return Err("chunk size exceeds bounded RPC result limit".into());
        }
        let record = self.status(id).await?;
        if !matches!(
            record.status,
            JobStatus::CompletedUnverified | JobStatus::VerifyingRaito | JobStatus::VerifiedRaito
        ) {
            return Err("job does not have a retained completed result".into());
        }
        self.check_chain(&record).await?;
        let path = self.root.join(format!("{id}.output"));
        let metadata = fs::symlink_metadata(&path).map_err(|err| err.to_string())?;
        if !metadata.file_type().is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_WORKER_OUTPUT_BYTES
        {
            return Err("retained output absent or unsafe".into());
        }
        let length = metadata.len();
        if record
            .result_bytes
            .is_some_and(|expected| expected != length)
        {
            return Err("retained output length mismatch".into());
        }
        if offset > length {
            return Err("result chunk offset out of range".into());
        }
        let count = requested.min((length - offset) as usize);
        // Indexed outputs need at most two 64 KiB reads. Older records are
        // supported with the slower whole-file digest fallback.
        let chunk = if let Some(index_sha) = record.result_chunk_index_sha256.as_deref() {
            indexed_chunk(&self.root, id, index_sha, length, offset, count)?
        } else {
            let (digest, checked_length, _) = checked_result_digest(&path)?;
            if checked_length != length || record.result_sha256.as_deref() != Some(&digest) {
                return Err("legacy output failed full SHA-256 verification".into());
            }
            let mut file = File::open(&path).map_err(|err| err.to_string())?;
            file.seek(SeekFrom::Start(offset))
                .map_err(|err| err.to_string())?;
            let mut buf = vec![0u8; count];
            file.read_exact(&mut buf).map_err(|err| err.to_string())?;
            buf
        };
        self.check_chain(&record).await?;
        Ok(json!({
            "job_id":id,
            "result_sha256":record.result_sha256,
            "chunk_index_sha256":record.result_chunk_index_sha256,
            "total_bytes":length,
            "offset":offset,
            "data_hex":hex::encode(chunk),
            "next_offset":offset + count as u64,
            "complete":offset + count as u64 == length,
            "proof_verified":record.status == JobStatus::VerifiedRaito && record.verified_raito.is_some(),
            "verified_statement":record.verified_raito
        }))
    }

    async fn run(self: Arc<Self>, id: String, _queue_permit: OwnedSemaphorePermit) {
        let Some(record) = self.records.lock().await.get(&id).cloned() else {
            return;
        };
        let input_path = self.root.join(format!("{id}.input"));
        let output_path = self.root.join(format!("{id}.output"));
        let index_path = self.root.join(format!("{id}.chunks"));
        let result: Result<(String, u64, String), String> = async {
            let _memory = self
                .memory
                .clone()
                .acquire_many_owned(record.estimated_memory_mib)
                .await
                .map_err(|err| err.to_string())?;
            let _slot = self
                .slots
                .clone()
                .acquire_owned()
                .await
                .map_err(|err| err.to_string())?;
            self.check_chain(&record).await?;
            let (_, data) = self.artifacts.get(&record.input_artifact_id).await?;
            self.set_status(&id, JobStatus::Running, None, None, None, None)
                .await;

            let worker = self
                .workers
                .executable(&record.kind)
                .ok_or("configured worker disappeared")?;
            fs::write(&input_path, data).map_err(|err| err.to_string())?;

            // Only the operator chooses executable paths. No shell is used,
            // and no RPC field can become part of the executable filename.
            let mut cmd = Command::new(worker);
            cmd.arg("--input")
                .arg(&input_path)
                .arg("--output")
                .arg(&output_path)
                .arg("--network")
                .arg(&record.network)
                .arg("--blockhash")
                .arg(&record.block_hash)
                .arg("--height")
                .arg(record.block_height.to_string())
                .arg("--policy-sha256")
                .arg(&record.policy_sha256)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            if record.kind == JobKind::Raito {
                // TXID and fetch-config come from a canonical job record and
                // operator-owned gateway configuration, never an RPC command.
                if let Some(ref txid) = record.expected_txid {
                    cmd.arg("--expected-txid").arg(txid);
                }
                if let Some(ref config) = self.raito_fetch_config {
                    cmd.env("SUPERNODE_RAITO_FETCH_CONFIG", config);
                }
                if let Some(limit) = std::env::var_os("SUPERNODE_REQUIRE_CGROUP_MAX_MIB") {
                    cmd.env("SUPERNODE_REQUIRE_CGROUP_MAX_MIB", limit);
                }
            }

            let status = timeout(MAX_WORKER_DURATION, cmd.status())
                .await
                .map_err(|_| "worker runtime budget exceeded")?
                .map_err(|err| err.to_string())?;
            if !status.success() {
                return Err(format!("approved worker exited with status {status}"));
            }
            self.check_chain(&record).await?;
            let (digest, size, index) = checked_result_digest(&output_path)?;
            let index_digest = hash_bytes(&index);
            write_chunk_index(&self.root, &id, &index)?;
            Ok((digest, size, index_digest))
        }
        .await;
        let _ = fs::remove_file(&input_path);
        if result.is_err() {
            let _ = fs::remove_file(&output_path);
            let _ = fs::remove_file(&index_path);
        }
        match result {
            Ok((digest, size, index_digest)) => {
                let should_verify = record.kind == JobKind::Raito
                    && self.raito_verifier.is_some()
                    && record.expected_txid.is_some();
                self.set_status(
                    &id,
                    if should_verify {
                        JobStatus::VerifyingRaito
                    } else {
                        JobStatus::CompletedUnverified
                    },
                    Some(digest.clone()),
                    Some(size),
                    Some(index_digest),
                    None,
                )
                .await;
                if should_verify {
                    if let Err(error) = self.verify_existing_record(&record, &digest, size).await {
                        // Retained output remains available for later verification
                        // attempts while its statement is explicitly unverified.
                        self.mark_verification_failed(&id, error).await;
                    }
                }
            }
            Err(err) => {
                self.set_status(&id, JobStatus::Failed, None, None, None, Some(err))
                    .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainTracker;

    fn tmp(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "supernode-jobs-{}-{label}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
    fn manager(root: &Path) -> Arc<JobManager> {
        let artifacts = Arc::new(ArtifactStore::new(root.join("artifacts"), 4096).unwrap());
        let core = CoreRpc::new("http://127.0.0.1:1", "user".into(), "secret".into()).unwrap();
        JobManager::new(
            root.join("jobs"),
            artifacts,
            core,
            Arc::new(ChainTracker::new(false)),
            WorkerPrograms::default(),
            64,
            1,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn rejects_unconfigured_workers_and_invalid_memory_budgets() {
        let dir = tmp("reject");
        let jobs = manager(&dir);
        assert!(!jobs.capabilities()["raito_worker_configured"]
            .as_bool()
            .unwrap());
        assert!(jobs
            .submit("raito", &"00".repeat(32), 10, &"ff".repeat(32))
            .await
            .is_err());
        assert!(jobs
            .submit("arbitrary_binary", &"00".repeat(32), 10, &"ff".repeat(32))
            .await
            .is_err());
        assert!(JobManager::new(
            dir.join("other"),
            Arc::new(ArtifactStore::new(dir.join("other_artifacts"), 4096).unwrap()),
            CoreRpc::new("http://127.0.0.1:1", "u".into(), "p".into()).unwrap(),
            Arc::new(ChainTracker::new(false)),
            WorkerPrograms::default(),
            0,
            1
        )
        .is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn persisted_running_job_is_interrupted_after_restart() {
        let dir = tmp("recovery");
        let jobs = manager(&dir);
        let record = JobRecord {
            id: "ab".repeat(32),
            kind: JobKind::Raito,
            input_artifact_id: "cd".repeat(32),
            network: "regtest".into(),
            block_hash: "ef".repeat(32),
            block_height: 1,
            chain_epoch: 0,
            policy_sha256: "12".repeat(32),
            estimated_memory_mib: 16,
            expected_txid: None,
            status: JobStatus::Running,
            result_sha256: None,
            result_bytes: None,
            result_chunk_index_sha256: None,
            verified_raito: None,
            error: None,
            submitted_unix: 1,
            finished_unix: None,
        };
        atomic_json(&jobs.root, &record).unwrap();
        let abandoned_input = jobs.root.join(format!("{}.input", record.id));
        let abandoned_output = jobs.root.join(format!("{}.output", record.id));
        let abandoned_index = jobs.root.join(format!("{}.chunks", record.id));
        fs::write(&abandoned_index, b"stale-index").unwrap();
        fs::write(&abandoned_input, b"stale-input").unwrap();
        fs::write(&abandoned_output, b"stale-output").unwrap();
        let restarted = manager(&dir);
        assert!(!abandoned_input.exists());
        assert!(!abandoned_output.exists());
        assert!(!abandoned_index.exists());
        let status = restarted.status(&record.id).await.unwrap();
        assert_eq!(status.status, JobStatus::Interrupted);
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn interrupted_raito_verification_preserves_unverified_proof_and_hashes() {
        let dir = tmp("verifier-recovery");
        let initial = manager(&dir);
        let id = "24".repeat(32);
        let bytes = b"synthetic-unverified-stark-bytes";
        fs::write(initial.root.join(format!("{id}.output")), bytes).unwrap();
        let record = JobRecord {
            id: id.clone(),
            kind: JobKind::Raito,
            input_artifact_id: "cd".repeat(32),
            network: "regtest".into(),
            block_hash: "ab".repeat(32),
            block_height: 13,
            chain_epoch: 0,
            policy_sha256: "ef".repeat(32),
            estimated_memory_mib: 1,
            expected_txid: Some("12".repeat(32)),
            status: JobStatus::VerifyingRaito,
            result_sha256: Some(hash_bytes(bytes)),
            result_bytes: Some(bytes.len() as u64),
            result_chunk_index_sha256: None,
            verified_raito: None,
            error: None,
            submitted_unix: 1,
            finished_unix: None,
        };
        atomic_json(&initial.root, &record).unwrap();
        drop(initial);
        let restarted = manager(&dir);
        let state = restarted.status(&id).await.unwrap();
        assert_eq!(state.status, JobStatus::CompletedUnverified);
        assert_eq!(state.result_sha256, Some(hash_bytes(bytes)));
        assert!(state.verified_raito.is_none());
        assert!(restarted.root.join(format!("{id}.output")).exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn indexed_proof_chunks_cross_boundaries_and_reject_corruption() {
        let directory = tmp("chunk-index");
        fs::create_dir_all(&directory).unwrap();
        let id = "ab".repeat(32);
        let size = MAX_RESULT_CHUNK_BYTES * 2 + 5;
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let result_path = directory.join(format!("{id}.output"));
        fs::write(&result_path, &data).unwrap();
        let (digest, length, index) = checked_result_digest(&result_path).unwrap();
        assert_eq!(digest, hash_bytes(&data));
        assert_eq!(length, size as u64);
        assert_eq!(index.len(), 96);
        let index_sha = hash_bytes(&index);
        write_chunk_index(&directory, &id, &index).unwrap();

        let crossing = indexed_chunk(
            &directory,
            &id,
            &index_sha,
            length,
            MAX_RESULT_CHUNK_BYTES as u64 - 4,
            20,
        )
        .unwrap();
        assert_eq!(
            crossing,
            data[MAX_RESULT_CHUNK_BYTES - 4..MAX_RESULT_CHUNK_BYTES + 16]
        );
        let tail = indexed_chunk(
            &directory,
            &id,
            &index_sha,
            length,
            (MAX_RESULT_CHUNK_BYTES * 2) as u64,
            5,
        )
        .unwrap();
        assert_eq!(tail, data[MAX_RESULT_CHUNK_BYTES * 2..]);

        let mut tampered = data;
        tampered[MAX_RESULT_CHUNK_BYTES + 1] ^= 0x55;
        fs::write(&result_path, &tampered).unwrap();
        assert!(indexed_chunk(&directory, &id, &index_sha, length, 0, 128).is_ok());
        assert!(indexed_chunk(
            &directory,
            &id,
            &index_sha,
            length,
            MAX_RESULT_CHUNK_BYTES as u64 - 4,
            20,
        )
        .is_err());

        fs::write(directory.join(format!("{id}.chunks")), b"corrupt").unwrap();
        assert!(indexed_chunk(&directory, &id, &index_sha, length, 0, 16).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn total_retained_result_quota_evicts_oldest_records() {
        let directory = tmp("result-quota");
        fs::create_dir_all(&directory).unwrap();
        let mut records = BTreeMap::new();
        for index in 1..=3u8 {
            let id = format!("{index:064x}");
            let bytes = vec![index; 6];
            fs::write(directory.join(format!("{id}.output")), &bytes).unwrap();
            let record = JobRecord {
                id: id.clone(),
                kind: JobKind::Raito,
                input_artifact_id: "ee".repeat(32),
                network: "regtest".into(),
                block_hash: "ab".repeat(32),
                block_height: 42,
                chain_epoch: 0,
                policy_sha256: "dd".repeat(32),
                estimated_memory_mib: 1,
                expected_txid: None,
                status: JobStatus::CompletedUnverified,
                result_sha256: Some(hash_bytes(&bytes)),
                result_bytes: Some(bytes.len() as u64),
                result_chunk_index_sha256: None,
                verified_raito: None,
                error: None,
                submitted_unix: index as u64,
                finished_unix: Some(100),
            };
            records.insert(id.clone(), record);
        }
        prune_result_files(&directory, &mut records, 12).unwrap();
        let oldest_id = format!("{:064x}", 1u8);
        assert_eq!(records[&oldest_id].status, JobStatus::OutputEvicted);
        assert_eq!(records[&oldest_id].result_sha256, Some(hash_bytes(&[1; 6])));
        assert!(!directory.join(format!("{oldest_id}.output")).exists());
        for index in [2u8, 3u8] {
            let id = format!("{index:064x}");
            assert_eq!(records[&id].status, JobStatus::CompletedUnverified);
            assert!(directory.join(format!("{id}.output")).exists());
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn retention_never_evicts_an_inflight_raito_verifier() {
        let directory = tmp("quota-verifier");
        fs::create_dir_all(&directory).unwrap();
        let mut records = BTreeMap::new();
        for (index, status) in [
            (1u8, JobStatus::CompletedUnverified),
            (2u8, JobStatus::VerifyingRaito),
            (3u8, JobStatus::CompletedUnverified),
        ] {
            let id = format!("{index:064x}");
            let bytes = vec![index; 6];
            fs::write(directory.join(format!("{id}.output")), &bytes).unwrap();
            let record = JobRecord {
                id: id.clone(),
                kind: JobKind::Raito,
                input_artifact_id: "ee".repeat(32),
                network: "regtest".into(),
                block_hash: "ab".repeat(32),
                block_height: 42,
                chain_epoch: 0,
                policy_sha256: "dd".repeat(32),
                estimated_memory_mib: 1,
                expected_txid: Some("aa".repeat(32)),
                status,
                result_sha256: Some(hash_bytes(&bytes)),
                result_bytes: Some(bytes.len() as u64),
                result_chunk_index_sha256: None,
                verified_raito: None,
                error: None,
                submitted_unix: index as u64,
                finished_unix: None,
            };
            records.insert(id, record);
        }
        // With a six-byte budget, both completed outputs must be evicted
        // while the in-flight verifier's six-byte proof stays untouched.
        prune_result_files(&directory, &mut records, 6).unwrap();
        let pinned_id = format!("{:064x}", 2u8);
        assert_eq!(records[&pinned_id].status, JobStatus::VerifyingRaito);
        assert_eq!(
            fs::read(directory.join(format!("{pinned_id}.output"))).unwrap(),
            vec![2; 6]
        );
        for index in [1u8, 3u8] {
            let id = format!("{index:064x}");
            assert_eq!(records[&id].status, JobStatus::OutputEvicted);
            assert!(!directory.join(format!("{id}.output")).exists());
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn verified_raito_receipt_survives_quota_eviction_and_restart() {
        let directory = tmp("verified-retention");
        fs::create_dir_all(&directory).unwrap();
        let id = "ab".repeat(32);
        let bytes = b"synthetic-receipt-retention-test";
        fs::write(directory.join(format!("{id}.output")), bytes).unwrap();
        let receipt = RaitoVerifiedReceipt {
            statement: crate::verification::STATEMENT.into(),
            verifier: crate::verification::VERIFIER_ID.into(),
            txid: "12".repeat(32),
            block_hash: "34".repeat(32),
            block_height: 71,
            proven_tip_height: 74,
            tx_index: 1,
            proof_sha256: hash_bytes(bytes),
            policy_sha256: "56".repeat(32),
        };
        let record = JobRecord {
            id: id.clone(),
            kind: JobKind::Raito,
            input_artifact_id: "78".repeat(32),
            network: "regtest".into(),
            block_hash: receipt.block_hash.clone(),
            block_height: 71,
            chain_epoch: 0,
            policy_sha256: receipt.policy_sha256.clone(),
            estimated_memory_mib: 1,
            expected_txid: Some(receipt.txid.clone()),
            status: JobStatus::VerifiedRaito,
            result_sha256: Some(receipt.proof_sha256.clone()),
            result_bytes: Some(bytes.len() as u64),
            result_chunk_index_sha256: None,
            verified_raito: Some(receipt.clone()),
            error: None,
            submitted_unix: 1,
            finished_unix: Some(2),
        };
        atomic_json(&directory, &record).unwrap();
        let mut records = BTreeMap::from([(id.clone(), record)]);
        prune_result_files(&directory, &mut records, 0).unwrap();
        assert_eq!(records[&id].status, JobStatus::OutputEvicted);
        assert!(records[&id].result_bytes.is_none());
        assert_eq!(records[&id].verified_raito.as_ref(), Some(&receipt));
        assert!(receipt.validate(&records[&id], &hash_bytes(bytes)).is_ok());
        assert!(!directory.join(format!("{id}.output")).exists());

        let reloaded: JobRecord =
            serde_json::from_slice(&fs::read(directory.join(format!("{id}.json"))).unwrap())
                .unwrap();
        assert_eq!(reloaded.status, JobStatus::OutputEvicted);
        assert_eq!(reloaded.verified_raito, Some(receipt));
        assert_eq!(reloaded.result_sha256, Some(hash_bytes(bytes)));
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn full_dispatch_mock_raito_receipt_is_typed_and_reorg_checked() {
        // Synthetic IPC test only: the mock verifier is not Cairo/STWO.
        // Genuine proof acceptance is tested separately on a live node.
        use axum::{routing::post, Json, Router};
        use std::os::unix::fs::PermissionsExt;
        use tokio::net::TcpListener;

        let directory = tmp("verified-dispatch");
        fs::create_dir_all(&directory).unwrap();
        let expected_hash = "ab".repeat(32);
        let expected_txid = "12".repeat(32);
        let policy = "ef".repeat(32);
        let content = b"synthetic-fetched-proof-not-real-stark";
        let receipt = RaitoVerifiedReceipt {
            statement: crate::verification::STATEMENT.into(),
            verifier: crate::verification::VERIFIER_ID.into(),
            txid: expected_txid.clone(),
            block_hash: expected_hash.clone(),
            block_height: 100,
            proven_tip_height: 105,
            tx_index: 1,
            proof_sha256: hash_bytes(content),
            policy_sha256: policy.clone(),
        };

        let fetcher = directory.join("mock-fetcher.sh");
        let fetcher_body = "#!/bin/sh\ninput=\noutput=\ntxid=\nwhile [ \"$#\" -gt 0 ]; do\n case \"$1\" in\n  --input) input=\"$2\"; shift 2;;\n  --output) output=\"$2\"; shift 2;;\n  --expected-txid) txid=\"$2\"; shift 2;;\n  --network|--blockhash|--height|--policy-sha256) shift 2;;\n  *) exit 41;;\n esac\ndone\n[ -s \"$SUPERNODE_RAITO_FETCH_CONFIG\" ] || exit 42\n[ -f \"$input\" ] || exit 43\n[ \"$txid\" = \"EXPECTED_TXID\" ] || exit 44\nprintf 'synthetic-fetched-proof-not-real-stark' > \"$output\"\n".replace("EXPECTED_TXID", &expected_txid);
        fs::write(&fetcher, fetcher_body).unwrap();
        fs::set_permissions(&fetcher, fs::Permissions::from_mode(0o700)).unwrap();

        let verifier = directory.join("mock-verifier.sh");
        let verifier_body = format!(
            "#!/bin/sh\n[ \"$1\" = --gateway ] || exit 31\n[ \"$3\" = \"{expected_txid}\" ] || exit 32\n[ \"$4\" = \"{expected_hash}\" ] || exit 33\n[ \"$6\" = \"{policy}\" ] || exit 34\ncat > \"$7\" <<'RECEIPT'\n{}\nRECEIPT\n",
            serde_json::to_string(&receipt).unwrap()
        );
        fs::write(&verifier, &verifier_body).unwrap();
        fs::set_permissions(&verifier, fs::Permissions::from_mode(0o700)).unwrap();

        let active = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let active_clone = active.clone();
        let main_hash = expected_hash.clone();
        let server = Router::new().route(
            "/",
            post(move |Json(body): Json<Value>| {
                let active = active_clone.clone();
                let hash = main_hash.clone();
                async move {
                    let result = if body["method"] == "getblockhash" {
                        if active.load(std::sync::atomic::Ordering::SeqCst) {
                            json!(hash)
                        } else {
                            json!("cc".repeat(32))
                        }
                    } else if body["method"] == "getblockchaininfo" {
                        json!({"chain":"main"})
                    } else {
                        Value::Null
                    };
                    Json(json!({"result":result,"error":null,"id":"supernode"}))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, server).await.unwrap() });

        let config_path = directory.join("operator-raito-config.json");
        fs::write(&config_path, b"operator-only-config-path").unwrap();
        let artifacts = Arc::new(ArtifactStore::new(directory.join("artifacts"), 4096).unwrap());
        let staged = artifacts
            .put(
                "main",
                &expected_hash,
                100,
                0,
                "raito_fetch_request",
                b"synthetic-job-manifest",
            )
            .await
            .unwrap();
        let core = CoreRpc::new(&rpc_url, "unit".into(), "test".into()).unwrap();
        let manager = JobManager::new_with_verifier(
            directory.join("jobs"),
            artifacts.clone(),
            core.clone(),
            Arc::new(ChainTracker::new(false)),
            WorkerPrograms {
                raito: Some(fetcher),
                shinigami: None,
            },
            Some(RaitoVerifier {
                executable: verifier,
                binary_sha256: hash_bytes(verifier_body.as_bytes()),
            }),
            JobLimits {
                memory_budget_mib: 2,
                worker_count: 1,
                raito_fetch_config: Some(config_path),
            },
        )
        .unwrap();
        let started = manager
            .submit_with_txid("raito", &staged.id, 2, &policy, Some(&expected_txid))
            .await
            .unwrap();
        let finished = timeout(Duration::from_secs(8), async {
            loop {
                let job = manager.status(&started.id).await.unwrap();
                if matches!(
                    job.status,
                    JobStatus::VerifiedRaito
                        | JobStatus::Failed
                        | JobStatus::CompletedUnverified
                        | JobStatus::OutputEvicted
                ) {
                    break job;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            finished.status,
            JobStatus::VerifiedRaito,
            "{:?}",
            finished.error
        );
        assert_eq!(finished.verified_raito.as_ref(), Some(&receipt));
        let published = manager.verified_receipt(&started.id).await.unwrap();
        assert_eq!(published["proof_verified"], true);
        assert_eq!(published["verified_statement"]["txid"], expected_txid);
        let part = manager.result_chunk(&started.id, 0, 20).await.unwrap();
        assert_eq!(part["proof_verified"], true);
        assert_eq!(
            hex::decode(part["data_hex"].as_str().unwrap()).unwrap(),
            &content[..20]
        );

        // A verified job is immutable under a duplicate retry. Model the
        // restart recovery state and verify the existing proof a second time.
        assert!(manager.retry_verification(&started.id).await.is_err());
        {
            let mut state = manager.records.lock().await;
            let mut old = state.get(&started.id).unwrap().clone();
            old.status = JobStatus::CompletedUnverified;
            old.verified_raito = None;
            old.error = Some("simulated verifier restart".into());
            atomic_json(&manager.root, &old).unwrap();
            state.insert(started.id.clone(), old);
        }
        let retried = manager.retry_verification(&started.id).await.unwrap();
        assert_eq!(retried.status, JobStatus::VerifyingRaito);
        assert!(manager.retry_verification(&started.id).await.is_err());
        let reverified = timeout(Duration::from_secs(8), async {
            loop {
                let job = manager.status(&started.id).await.unwrap();
                if matches!(job.status, JobStatus::VerifiedRaito | JobStatus::Failed)
                    || (job.status == JobStatus::CompletedUnverified && job.error.is_some())
                {
                    break job;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            reverified.status,
            JobStatus::VerifiedRaito,
            "{:?}",
            reverified.error
        );
        assert_eq!(reverified.verified_raito.as_ref(), Some(&receipt));

        // Receipt survives a gateway restart with a new in-memory job map.
        let reopened = JobManager::new(
            directory.join("jobs"),
            artifacts,
            core,
            Arc::new(ChainTracker::new(false)),
            WorkerPrograms::default(),
            2,
            1,
        )
        .unwrap();
        assert_eq!(
            reopened.verified_receipt(&started.id).await.unwrap()["proof_verified"],
            true
        );

        let mut tampered = finished.clone();
        tampered.verified_raito.as_mut().unwrap().txid = "cd".repeat(32);
        atomic_json(&manager.root, &tampered).unwrap();
        let tampered_load = JobManager::new(
            directory.join("jobs"),
            Arc::new(ArtifactStore::new(directory.join("artifacts"), 4096).unwrap()),
            CoreRpc::new(&rpc_url, "unit".into(), "test".into()).unwrap(),
            Arc::new(ChainTracker::new(false)),
            WorkerPrograms::default(),
            2,
            1,
        )
        .unwrap();
        assert!(tampered_load.verified_receipt(&started.id).await.is_err());
        atomic_json(&manager.root, &finished).unwrap();
        active.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(manager.verified_receipt(&started.id).await.is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn approved_worker_runs_and_receipt_is_explicitly_unverified() {
        use axum::{routing::post, Json, Router};
        use std::os::unix::fs::PermissionsExt;
        use tokio::net::TcpListener;

        let directory = tmp("worker");
        fs::create_dir_all(&directory).unwrap();
        let executable = directory.join("mock-approved-prover.sh");
        fs::write(
            &executable,
            "#!/bin/sh\ninput=\noutput=\nwhile [ \"$#\" -gt 0 ]; do\n  case \"$1\" in\n    --input) input=\"$2\"; shift 2 ;;\n    --output) output=\"$2\"; shift 2 ;;\n    *) shift 2 ;;\n  esac\ndone\ncp \"$input\" \"$output\"\n",
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

        let initial_hash = "ab".repeat(32);
        let active_hash = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let hash = initial_hash.clone();
        let active = active_hash.clone();
        let server = Router::new().route(
            "/",
            post(move |Json(body): Json<Value>| {
                let hash = hash.clone();
                let active = active.clone();
                async move {
                    let result = if body["method"] == "getblockhash" {
                        if active.load(std::sync::atomic::Ordering::SeqCst) {
                            json!(hash)
                        } else {
                            json!("cc".repeat(32))
                        }
                    } else if body["method"] == "getblockchaininfo" {
                        json!({"chain":"regtest"})
                    } else {
                        Value::Null
                    };
                    Json(json!({"result":result,"error":null,"id":"supernode"}))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, server).await.unwrap() });

        let cache = Arc::new(ArtifactStore::new(directory.join("artifacts"), 4096).unwrap());
        let content = b"synthetic-data-not-a-zk-proof";
        let staged = cache
            .put("regtest", &initial_hash, 100, 0, "raito_input", content)
            .await
            .unwrap();

        let jobs = JobManager::new(
            directory.join("jobs"),
            cache,
            CoreRpc::new(&rpc_url, "unit".into(), "test".into()).unwrap(),
            Arc::new(ChainTracker::new(false)),
            WorkerPrograms {
                raito: Some(executable),
                shinigami: None,
            },
            2,
            1,
        )
        .unwrap();
        assert!(jobs.capabilities()["raito_worker_configured"]
            .as_bool()
            .unwrap());
        assert!(jobs
            .submit("raito", &staged.id, 3, &"dd".repeat(32))
            .await
            .is_err());

        let queued = jobs
            .submit("raito", &staged.id, 2, &"dd".repeat(32))
            .await
            .unwrap();
        let completed = timeout(Duration::from_secs(6), async {
            loop {
                let record = jobs.status(&queued.id).await.unwrap();
                if !matches!(record.status, JobStatus::Queued | JobStatus::Running) {
                    break record;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(completed.status, JobStatus::CompletedUnverified);
        assert_eq!(completed.result_sha256, Some(hash_bytes(content)));
        assert_eq!(completed.result_bytes, Some(content.len() as u64));
        let index_path = jobs.root.join(format!("{}.chunks", queued.id));
        let original_index = fs::read(&index_path).unwrap();
        assert_eq!(original_index.len(), 32);
        assert_eq!(
            completed.result_chunk_index_sha256,
            Some(hash_bytes(&original_index))
        );

        let first = jobs.result_chunk(&queued.id, 0, 8).await.unwrap();
        assert_eq!(first["proof_verified"], false);
        assert!(jobs.verified_receipt(&queued.id).await.is_err());
        assert_eq!(
            hex::decode(first["data_hex"].as_str().unwrap()).unwrap(),
            content[..8]
        );
        assert_eq!(first["next_offset"], 8);
        assert_eq!(first["complete"], false);
        let final_chunk = jobs
            .result_chunk(&queued.id, 8, MAX_RESULT_CHUNK_BYTES)
            .await
            .unwrap();
        assert_eq!(
            hex::decode(final_chunk["data_hex"].as_str().unwrap()).unwrap(),
            content[8..]
        );
        assert_eq!(final_chunk["complete"], true);
        assert!(jobs
            .result_chunk(&queued.id, 0, MAX_RESULT_CHUNK_BYTES + 1)
            .await
            .is_err());
        assert!(jobs
            .result_chunk(&queued.id, content.len() as u64 + 1, 16)
            .await
            .is_err());

        fs::write(&index_path, b"corrupted-index").unwrap();
        assert!(jobs.result_chunk(&queued.id, 0, 10).await.is_err());
        fs::write(&index_path, original_index).unwrap();

        let result_path = jobs.root.join(format!("{}.output", queued.id));
        fs::write(&result_path, b"tampered-result").unwrap();
        assert!(jobs.result_chunk(&queued.id, 0, 10).await.is_err());
        fs::write(&result_path, content).unwrap();

        active_hash.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(jobs.check_chain(&completed).await.is_err());

        let restarted = JobManager::new(
            directory.join("jobs"),
            Arc::new(ArtifactStore::new(directory.join("artifacts"), 4096).unwrap()),
            CoreRpc::new(&rpc_url, "unit".into(), "test".into()).unwrap(),
            Arc::new(ChainTracker::new(false)),
            WorkerPrograms::default(),
            2,
            1,
        )
        .unwrap();
        assert_eq!(
            restarted.status(&queued.id).await.unwrap().status,
            JobStatus::CompletedUnverified
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
