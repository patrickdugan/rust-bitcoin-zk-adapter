//! Durable, admission-controlled proving dispatch to operator-configured workers.
//!
//! The RPC client cannot choose commands or read arbitrary files. A job's
//! memory estimate is an *admission reservation*, not an operating-system RSS
//! limit. Configure cgroups/containers around approved prover binaries.

use bitcoin::hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
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

use crate::{cache::ArtifactStore, chain::ChainTracker, CoreRpc};

pub const MAX_PENDING_JOBS: usize = 16;
pub const MAX_JOB_HISTORY: usize = 128;
pub const MAX_ESTIMATED_MEMORY_MIB: u32 = 32 * 1024;
pub const MAX_WORKER_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
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
    pub status: JobStatus,
    pub result_sha256: Option<String>,
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

pub struct JobManager {
    root: PathBuf,
    artifacts: Arc<ArtifactStore>,
    core: CoreRpc,
    chain: Arc<ChainTracker>,
    workers: WorkerPrograms,
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
            if name.contains(".tmp-") {
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
            }
        }
        Ok(Arc::new(Self {
            root,
            artifacts,
            core,
            chain,
            workers,
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
            "shinigami_worker_configured":self.workers.enabled(&JobKind::Shinigami),
            "max_pending":MAX_PENDING_JOBS,
            "max_worker_count":self.worker_count,
            "memory_admission_budget_mib":self.memory_budget_mib,
            "hard_os_memory_limit_enforced":false,
            "max_worker_time_seconds":MAX_WORKER_DURATION.as_secs()
        })
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
        if actual.as_str() != Some(record.block_hash.as_str())
            || self.chain.epoch().await != record.chain_epoch
        {
            return Err("job's block was disconnected or chain changed".into());
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
        let kind = JobKind::from_name(backend)?;
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
            status: JobStatus::Queued,
            result_sha256: None,
            error: None,
            submitted_unix: unix_time(),
            finished_unix: None,
        };
        self.check_chain(&record).await?;
        {
            let mut state = self.records.lock().await;
            if state.len() >= MAX_JOB_HISTORY {
                let oldest_done = state
                    .iter()
                    .filter(|(_, record)| {
                        !matches!(record.status, JobStatus::Queued | JobStatus::Running)
                    })
                    .min_by_key(|(_, record)| record.submitted_unix)
                    .map(|(id, _)| id.clone());
                if let Some(old_id) = oldest_done {
                    state.remove(&old_id);
                    let _ = fs::remove_file(self.root.join(format!("{old_id}.json")));
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
        error: Option<String>,
    ) {
        let mut records = self.records.lock().await;
        if let Some(record) = records.get_mut(id) {
            record.status = status.clone();
            record.result_sha256 = digest;
            record.error = error;
            if !matches!(status, JobStatus::Queued | JobStatus::Running) {
                record.finished_unix = Some(unix_time());
            }
            if let Err(err) = atomic_json(&self.root, record) {
                eprintln!("Could not persist proof job status: {err}");
            }
        }
    }

    async fn run(self: Arc<Self>, id: String, _queue_permit: OwnedSemaphorePermit) {
        let Some(record) = self.records.lock().await.get(&id).cloned() else {
            return;
        };
        let result: Result<String, String> = async {
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
            self.set_status(&id, JobStatus::Running, None, None).await;

            let worker = self
                .workers
                .executable(&record.kind)
                .ok_or("configured worker disappeared")?;
            let input = self.root.join(format!("{id}.input"));
            let output = self.root.join(format!("{id}.output"));
            fs::write(&input, data).map_err(|err| err.to_string())?;

            // Only the operator chooses executable paths. No shell is used,
            // and no RPC field can become part of the executable filename.
            let mut cmd = Command::new(worker);
            cmd.arg("--input")
                .arg(&input)
                .arg("--output")
                .arg(&output)
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

            let status = timeout(MAX_WORKER_DURATION, cmd.status())
                .await
                .map_err(|_| "worker runtime budget exceeded")?
                .map_err(|err| err.to_string())?;
            let _ = fs::remove_file(input);
            if !status.success() {
                let _ = fs::remove_file(&output);
                return Err(format!("approved worker exited with status {status}"));
            }
            self.check_chain(&record).await?;
            let meta = fs::symlink_metadata(&output).map_err(|err| err.to_string())?;
            if !meta.file_type().is_file()
                || meta.len() == 0
                || meta.len() > MAX_WORKER_OUTPUT_BYTES
            {
                return Err("worker output missing, unsafe or above size cap".into());
            }
            let data = fs::read(&output).map_err(|err| err.to_string())?;
            Ok(hash_bytes(&data))
        }
        .await;
        match result {
            Ok(sha) => {
                self.set_status(&id, JobStatus::CompletedUnverified, Some(sha), None)
                    .await;
            }
            Err(err) => {
                self.set_status(&id, JobStatus::Failed, None, Some(err))
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
            status: JobStatus::Running,
            result_sha256: None,
            error: None,
            submitted_unix: 1,
            finished_unix: None,
        };
        atomic_json(&jobs.root, &record).unwrap();
        let restarted = manager(&dir);
        let status = restarted.status(&record.id).await.unwrap();
        assert_eq!(status.status, JobStatus::Interrupted);
        fs::remove_dir_all(dir).unwrap();
    }
}
