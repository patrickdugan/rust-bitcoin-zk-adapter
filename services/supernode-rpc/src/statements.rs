//! Client-submitted Bitcoin statement proofs, checked by operator-pinned
//! external verifiers and then bound to Bitcoin Core's active chain.
//!
//! Proving happens off the gateway. A client submits a small proof bundle
//! inline:
//! - `nova_header_chain_v1`: an NHC1 bundle (about 13.5 KB) proving a
//!   header chain from an operator-pinned checkpoint;
//! - `sp1_btc_payment_v1`: a BPG1 bundle (709 bytes) proving a payment
//!   output's inclusion under a proven header chain;
//! - `nova_spv_payment_v1`: an NSP1 bundle with two chained Nova proofs
//!   (pinned checkpoint to block B, then B to the tip) plus a plain SPV
//!   Merkle branch and the raw transaction. Every part is cheap to prove
//!   (1.4 GB); the Merkle part needs no proof system.
//!
//! A receipt is returned only when all of the following hold:
//! 1. the pinned verifier executable accepts the bundle;
//! 2. its typed receipt binds the submitted bytes and the pinned keys;
//! 3. every chain claim (height, hash and chainwork) matches Core at lookup.
//!
//! The pinned executables run either as gateway children (`Direct`, for
//! tests and development) or behind the separate-UID statement verifier
//! broker (`Isolated`), which holds no Core credentials. Either way the
//! gateway checks the receipt and binds it to Core itself.
use crate::{verification::file_digest, CoreRpc, RpcError};
use bitcoin::hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{process::Command, sync::Semaphore};

pub const NOVA_STATEMENT: &str = "btc_header_chain_v1";
pub const NOVA_VERIFIER: &str = "nova-snark 0.76.0 pallas/vesta ipa, spartan compressed";
pub const PAYMENT_STATEMENT: &str = "btc_payment_v1";
pub const PAYMENT_VERIFIER: &str = "sp1-verifier 6.9.0 groth16 bn254";
/// NHC1 header: magic, step count, fold width, 17 checkpoint field elements.
const NHC1_HEADER_BYTES: usize = 12 + 17 * 32;
pub const MAX_NOVA_BUNDLE_BYTES: usize = 24 * 1024;
pub const PAYMENT_BUNDLE_BYTES: usize = 709;
pub const SPV_PAYMENT_STATEMENT: &str = "btc_nova_spv_payment_v1";
pub const MAX_SPV_BUNDLE_BYTES: usize = 30 * 1024;
const MAX_SPV_TX_BYTES: usize = 4096;
const MAX_RECEIPT_BYTES: u64 = 8192;
const VERIFY_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementKind {
    NovaHeaders,
    Sp1Payment,
    NovaSpvPayment,
}

impl StatementKind {
    pub fn from_name(name: &str) -> Result<Self, String> {
        match name {
            "nova_header_chain_v1" => Ok(Self::NovaHeaders),
            "sp1_btc_payment_v1" => Ok(Self::Sp1Payment),
            "nova_spv_payment_v1" => Ok(Self::NovaSpvPayment),
            _ => Err("unsupported statement kind".into()),
        }
    }
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn sha_hex(bytes: &[u8]) -> String {
    sha256::Hash::hash(bytes).to_string()
}

/// A verifier executable the operator pinned by SHA-256.
#[derive(Clone, Debug)]
pub struct PinnedProgram {
    pub executable: PathBuf,
    pub binary_sha256: String,
}

impl PinnedProgram {
    fn validate(&self) -> Result<(), String> {
        if !self.executable.is_absolute() || !valid_hash(&self.binary_sha256) {
            return Err("statement verifier requires an absolute path and SHA-256 pin".into());
        }
        if file_digest(&self.executable)? != self.binary_sha256 {
            return Err("statement verifier executable differs from its SHA-256 pin".into());
        }
        Ok(())
    }
}

/// Header-chain policy: the Nova verifier key and the checkpoints a proof
/// may start from. A checkpoint is authenticated by the operator, not the
/// proof, so only pinned checkpoint states are accepted.
#[derive(Clone, Debug)]
pub struct NovaPolicy {
    pub vk_sha256: String,
    /// SHA-256 of the 17 checkpoint field elements (`checkpoint_state_sha256`).
    pub checkpoints: Vec<String>,
}

/// Payment policy: the SP1 payment program key and the header-chain program
/// identities its statement must commit.
#[derive(Clone, Debug)]
pub struct PaymentPolicy {
    /// `0x`-prefixed bytes32 key of the payment program.
    pub pay_vkey: String,
    pub node_program_words: String,
    pub leaf_program_words: String,
    pub segment_program_words: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ChainPoint {
    pub height: u32,
    pub tip_hash: String,
    /// `0x`-prefixed big-endian hex.
    pub chainwork: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NovaHeaderReceipt {
    pub statement: String,
    pub verifier: String,
    pub vk_sha256: String,
    pub proof_sha256: String,
    pub checkpoint_state_sha256: String,
    /// SHA-256 of the 17 end-state field elements: a later proof starting
    /// here has this as its `checkpoint_state_sha256`.
    pub end_state_sha256: String,
    pub checkpoint: ChainPoint,
    pub end: ChainPoint,
    pub headers: u64,
    pub verify_seconds: f64,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PaymentReceipt {
    pub statement: String,
    pub verifier: String,
    pub groth16_vk_sha256: String,
    pub pay_vkey: String,
    pub node_program_words: String,
    pub leaf_program_words: String,
    pub segment_program_words: String,
    pub proof_sha256: String,
    pub statement_sha256: String,
    pub start_is_genesis: bool,
    pub tip_height: u32,
    pub tip_hash: String,
    /// Big-endian hex, 64 digits.
    pub tip_chainwork: String,
    pub block_height: u32,
    pub block_hash: String,
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub script_sha256: String,
    pub confirmations: u32,
    pub verified: bool,
}

/// A payment proven by chained Nova header proofs plus an SPV Merkle branch.
/// Assembled by the gateway from two verifier receipts and its own checks.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SpvPaymentReceipt {
    pub statement: String,
    pub checkpoint_state_sha256: String,
    pub chain_to_block: NovaHeaderReceipt,
    pub chain_to_tip: Option<NovaHeaderReceipt>,
    pub block_height: u32,
    pub block_hash: String,
    pub tip_height: u32,
    pub tip_hash: String,
    pub tip_chainwork: String,
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub script_sha256: String,
    pub confirmations: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StatementReceipt {
    NovaHeaders(NovaHeaderReceipt),
    Sp1Payment(PaymentReceipt),
    NovaSpvPayment(Box<SpvPaymentReceipt>),
}

/// One proven output, whichever payment kind proved it.
#[derive(Debug, Clone, PartialEq)]
pub struct ProvenOutput {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub script_sha256: String,
    pub block_height: u32,
}

impl StatementReceipt {
    pub fn proven_output(&self) -> Option<ProvenOutput> {
        match self {
            Self::NovaHeaders(_) => None,
            Self::Sp1Payment(r) => Some(ProvenOutput {
                txid: r.txid.clone(),
                vout: r.vout,
                value_sats: r.value_sats,
                script_sha256: r.script_sha256.clone(),
                block_height: r.block_height,
            }),
            Self::NovaSpvPayment(r) => Some(ProvenOutput {
                txid: r.txid.clone(),
                vout: r.vout,
                value_sats: r.value_sats,
                script_sha256: r.script_sha256.clone(),
                block_height: r.block_height,
            }),
        }
    }
}

impl NovaHeaderReceipt {
    /// `checkpoints` are the accepted start states: the operator's pins, or
    /// the end state of the proof this one continues.
    pub fn validate(
        &self,
        vk_sha256: &str,
        checkpoints: &[String],
        bundle: &[u8],
    ) -> Result<(), String> {
        let headers_ok = u64::from(self.end.height)
            .checked_sub(u64::from(self.checkpoint.height))
            .is_some_and(|n| n == self.headers && n > 0);
        if !self.verified
            || self.statement != NOVA_STATEMENT
            || self.verifier != NOVA_VERIFIER
            || self.vk_sha256 != vk_sha256
            || bundle.len() <= NHC1_HEADER_BYTES
            || self.proof_sha256 != sha_hex(&bundle[NHC1_HEADER_BYTES..])
            || self.checkpoint_state_sha256 != sha_hex(&bundle[12..NHC1_HEADER_BYTES])
            || !checkpoints.contains(&self.checkpoint_state_sha256)
            || !valid_hash(&self.end_state_sha256)
            || !headers_ok
            || !valid_hash(&self.checkpoint.tip_hash)
            || !valid_hash(&self.end.tip_hash)
        {
            return Err("header-chain receipt does not bind the bundle, key and checkpoint".into());
        }
        Ok(())
    }
}

impl PaymentReceipt {
    pub fn validate(&self, policy: &PaymentPolicy, bundle: &[u8]) -> Result<(), String> {
        if !self.verified
            || self.statement != PAYMENT_STATEMENT
            || self.verifier != PAYMENT_VERIFIER
            || self.pay_vkey != policy.pay_vkey
            || self.node_program_words != policy.node_program_words
            || self.leaf_program_words != policy.leaf_program_words
            || self.segment_program_words != policy.segment_program_words
            || self.proof_sha256 != sha_hex(bundle)
            || bundle.len() != PAYMENT_BUNDLE_BYTES
            || self.statement_sha256 != sha_hex(&bundle[4 + 356..])
            || self.block_height > self.tip_height
            || self.confirmations != self.tip_height - self.block_height + 1
            || ![
                &self.tip_hash,
                &self.block_hash,
                &self.txid,
                &self.tip_chainwork,
            ]
            .iter()
            .all(|h| valid_hash(h))
        {
            return Err("payment receipt does not bind the bundle and pinned programs".into());
        }
        Ok(())
    }
}

/// The Nova verifier executable and the key file it loads.
#[derive(Clone, Debug)]
pub struct NovaProgram {
    pub program: PinnedProgram,
    pub vk_path: PathBuf,
}

/// How a bundle reaches its pinned verifier executable.
pub enum StatementRunner {
    /// Child processes of the gateway, under its UID: tests and development.
    Direct {
        work_dir: PathBuf,
        nova: Option<NovaProgram>,
        payment: Option<PinnedProgram>,
    },
    /// The separate-UID statement verifier broker, which owns the
    /// executables, the Nova key file and the payment program key.
    #[cfg(unix)]
    Isolated(crate::statement_broker::IsolatedStatementRunner),
}

/// What one verifier run produced.
struct RunOutput {
    success: bool,
    status: String,
    stdout: Vec<u8>,
}

/// Verifiers configured by the operator; at most one verification runs at a
/// time per gateway, since a Nova check loads a ~250 MB verifier key.
pub struct StatementVerifiers {
    runner: StatementRunner,
    nova: Option<NovaPolicy>,
    payment: Option<PaymentPolicy>,
    slots: Semaphore,
    counter: AtomicU64,
}

impl StatementVerifiers {
    pub fn new(
        runner: StatementRunner,
        nova: Option<NovaPolicy>,
        payment: Option<PaymentPolicy>,
    ) -> Result<Self, String> {
        // On non-Unix targets Direct is the only runner.
        #[allow(irrefutable_let_patterns)]
        if let StatementRunner::Direct {
            work_dir,
            nova: nova_program,
            payment: payment_program,
        } = &runner
        {
            if !work_dir.is_absolute() {
                return Err("statement work directory must be absolute".into());
            }
            fs::create_dir_all(work_dir).map_err(|e| e.to_string())?;
            if nova.is_some() != nova_program.is_some()
                || payment.is_some() != payment_program.is_some()
            {
                return Err("each statement policy needs exactly one verifier program".into());
            }
            if let (Some(p), Some(n)) = (&nova, nova_program) {
                n.program.validate()?;
                if !n.vk_path.is_absolute() || file_digest_any(&n.vk_path)? != p.vk_sha256 {
                    return Err("Nova verifier key differs from its SHA-256 pin".into());
                }
            }
            if let Some(p) = payment_program {
                p.validate()?;
            }
        }
        if let Some(ref p) = nova {
            if !valid_hash(&p.vk_sha256)
                || p.checkpoints.is_empty()
                || !p.checkpoints.iter().all(|c| valid_hash(c))
            {
                return Err("Nova policy requires at least one pinned checkpoint digest".into());
            }
        }
        if let Some(ref p) = payment {
            let key_ok = p.pay_vkey.len() == 66
                && p.pay_vkey.starts_with("0x")
                && valid_hash(&p.pay_vkey[2..]);
            if !key_ok
                || ![
                    &p.node_program_words,
                    &p.leaf_program_words,
                    &p.segment_program_words,
                ]
                .iter()
                .all(|w| valid_hash(w))
            {
                return Err("payment policy requires a bytes32 key and three program words".into());
            }
        }
        if nova.is_none() && payment.is_none() {
            return Err("no statement verifier configured".into());
        }
        Ok(Self {
            runner,
            nova,
            payment,
            slots: Semaphore::new(1),
            counter: AtomicU64::new(0),
        })
    }

    pub fn capabilities(&self) -> Value {
        json!({
            "nova_header_chain_v1": self.nova.as_ref().map(|p| json!({
                "vk_sha256":p.vk_sha256, "pinned_checkpoints":p.checkpoints.len()
            })),
            "sp1_btc_payment_v1": self.payment.as_ref().map(|p| json!({"pay_vkey":p.pay_vkey})),
            "nova_spv_payment_v1": self.nova.is_some(),
            "separate_uid_verifier": !matches!(self.runner, StatementRunner::Direct { .. }),
            "max_nova_bundle_bytes":MAX_NOVA_BUNDLE_BYTES,
            "payment_bundle_bytes":PAYMENT_BUNDLE_BYTES
        })
    }

    /// Run the pinned verifier for `kind` on `bundle` and validate its receipt.
    /// Chain binding is separate (`bind_active_chain`).
    pub async fn verify(
        &self,
        kind: StatementKind,
        bundle: &[u8],
    ) -> Result<StatementReceipt, String> {
        let _slot = self
            .slots
            .try_acquire()
            .map_err(|_| "a statement verification is already running")?;
        match kind {
            StatementKind::NovaHeaders => {
                let policy = self
                    .nova
                    .as_ref()
                    .ok_or("Nova verifier is not configured")?;
                self.verify_nova(policy, bundle, &policy.checkpoints)
                    .await
                    .map(StatementReceipt::NovaHeaders)
            }
            StatementKind::NovaSpvPayment => self
                .verify_spv(bundle)
                .await
                .map(|r| StatementReceipt::NovaSpvPayment(Box::new(r))),
            StatementKind::Sp1Payment => {
                let policy = self
                    .payment
                    .as_ref()
                    .ok_or("payment verifier is not configured")?;
                if bundle.len() != PAYMENT_BUNDLE_BYTES {
                    return Err("BPG1 bundle must be 709 bytes".into());
                }
                let bytes = self.run(StatementKind::Sp1Payment, bundle).await?;
                let receipt: PaymentReceipt =
                    serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                receipt.validate(policy, bundle)?;
                Ok(StatementReceipt::Sp1Payment(receipt))
            }
        }
    }

    async fn verify_nova(
        &self,
        policy: &NovaPolicy,
        bundle: &[u8],
        checkpoints: &[String],
    ) -> Result<NovaHeaderReceipt, String> {
        if bundle.len() > MAX_NOVA_BUNDLE_BYTES || bundle.len() <= NHC1_HEADER_BYTES {
            return Err("NHC1 bundle size out of range".into());
        }
        let bytes = self.run(StatementKind::NovaHeaders, bundle).await?;
        let receipt: NovaHeaderReceipt =
            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        receipt.validate(&policy.vk_sha256, checkpoints, bundle)?;
        Ok(receipt)
    }

    /// NSP1: b"NSP1" | vout u32 | then four u32-length-prefixed parts: the
    /// NHC1 proof from a pinned checkpoint to block B, the NHC1 proof from B
    /// to the tip (may be empty: the tip is B), a `gettxoutproof` MerkleBlock
    /// and the raw transaction. All integers are little-endian.
    async fn verify_spv(&self, bundle: &[u8]) -> Result<SpvPaymentReceipt, String> {
        use bitcoin::consensus::deserialize;
        let policy = self
            .nova
            .as_ref()
            .ok_or("Nova verifier is not configured")?;
        let (vout, to_block, to_tip, merkle, raw_tx) = split_nsp1(bundle)?;
        let chain_to_block = self
            .verify_nova(policy, to_block, &policy.checkpoints)
            .await?;
        let chain_to_tip = if to_tip.is_empty() {
            None
        } else {
            let next = [chain_to_block.end_state_sha256.clone()];
            Some(self.verify_nova(policy, to_tip, &next).await?)
        };

        let merkle: bitcoin::MerkleBlock =
            deserialize(merkle).map_err(|_| "MerkleBlock cannot be decoded")?;
        if merkle.header.block_hash().to_string() != chain_to_block.end.tip_hash {
            return Err("MerkleBlock header is not the proven block".into());
        }
        let tx: bitcoin::Transaction =
            deserialize(raw_tx).map_err(|_| "transaction cannot be decoded")?;
        // A 64-byte transaction can masquerade as an inner Merkle node.
        if tx.base_size() == 64 {
            return Err("64-byte transactions are refused (Merkle ambiguity)".into());
        }
        let txid = tx.compute_txid();
        let (mut matches, mut positions) = (Vec::new(), Vec::new());
        merkle
            .extract_matches(&mut matches, &mut positions)
            .map_err(|_| "Merkle branch does not reach the header's root")?;
        if matches != [txid] {
            return Err("Merkle branch does not bind exactly this transaction".into());
        }
        let output = tx
            .output
            .get(vout as usize)
            .ok_or("output index out of range")?;
        let tip = chain_to_tip.as_ref().unwrap_or(&chain_to_block).end.clone();
        Ok(SpvPaymentReceipt {
            statement: SPV_PAYMENT_STATEMENT.into(),
            checkpoint_state_sha256: chain_to_block.checkpoint_state_sha256.clone(),
            block_height: chain_to_block.end.height,
            block_hash: chain_to_block.end.tip_hash.clone(),
            tip_height: tip.height,
            tip_hash: tip.tip_hash,
            tip_chainwork: tip.chainwork,
            txid: txid.to_string(),
            vout,
            value_sats: output.value.to_sat(),
            script_sha256: sha_hex(output.script_pubkey.as_bytes()),
            confirmations: tip.height - chain_to_block.end.height + 1,
            chain_to_block,
            chain_to_tip,
        })
    }

    /// Run the pinned verifier for `kind` (directly or through the broker)
    /// and return the bounded stdout of an accepting run.
    async fn run(&self, kind: StatementKind, bundle: &[u8]) -> Result<Vec<u8>, String> {
        let out = match &self.runner {
            StatementRunner::Direct {
                work_dir,
                nova,
                payment,
            } => match kind {
                StatementKind::NovaHeaders => {
                    let n = nova.as_ref().ok_or("Nova verifier is not configured")?;
                    n.program.validate()?;
                    self.run_direct(work_dir, &n.program, bundle, |path| {
                        vec![
                            "verify-bundle".into(),
                            path.as_os_str().to_owned(),
                            "--vk".into(),
                            n.vk_path.as_os_str().to_owned(),
                        ]
                    })
                    .await?
                }
                StatementKind::Sp1Payment => {
                    let (program, policy) = payment
                        .as_ref()
                        .zip(self.payment.as_ref())
                        .ok_or("payment verifier is not configured")?;
                    program.validate()?;
                    self.run_direct(work_dir, program, bundle, |path| {
                        vec![path.as_os_str().to_owned(), policy.pay_vkey.clone().into()]
                    })
                    .await?
                }
                StatementKind::NovaSpvPayment => {
                    return Err("NSP1 bundles are verified in parts".into())
                }
            },
            #[cfg(unix)]
            StatementRunner::Isolated(broker) => {
                let name = match kind {
                    StatementKind::NovaHeaders => "nova_header_chain_v1",
                    StatementKind::Sp1Payment => "sp1_btc_payment_v1",
                    StatementKind::NovaSpvPayment => {
                        return Err("NSP1 bundles are verified in parts".into())
                    }
                };
                let (success, status, stdout) = broker.run(name, bundle).await?;
                RunOutput {
                    success,
                    status,
                    stdout,
                }
            }
        };
        if out.stdout.len() as u64 > MAX_RECEIPT_BYTES {
            return Err("statement verifier receipt exceeds size limit".into());
        }
        if !out.success {
            let reason = serde_json::from_slice::<Value>(&out.stdout)
                .ok()
                .and_then(|v| v["error"].as_str().map(|s| s.chars().take(200).collect()))
                .unwrap_or(out.status);
            return Err(format!("proof rejected: {reason}"));
        }
        Ok(out.stdout)
    }

    /// Write the bundle to a fresh file and run the verifier as a gateway
    /// child with stdout to a fresh file.
    async fn run_direct(
        &self,
        work_dir: &Path,
        program: &PinnedProgram,
        bundle: &[u8],
        args: impl FnOnce(&Path) -> Vec<std::ffi::OsString>,
    ) -> Result<RunOutput, String> {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let stem = format!("{}-{}-{n}", sha_hex(bundle), std::process::id());
        let input = work_dir.join(format!("{stem}.bundle"));
        let output = work_dir.join(format!("{stem}.receipt"));
        let result = async {
            let create = |p: &Path| {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(p)
                    .map_err(|e| e.to_string())
            };
            create(&input)?
                .write_all(bundle)
                .map_err(|e| e.to_string())?;
            let stdout = create(&output)?;
            let mut command = Command::new(&program.executable);
            command
                .args(args(&input))
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::null());
            if let Some(path) = std::env::var_os("SystemRoot") {
                // Windows processes need SystemRoot to initialise.
                command.env("SystemRoot", path);
            }
            let status = crate::process::run_supervised(command, VERIFY_TIMEOUT)
                .await
                .map_err(|e| format!("statement verifier: {e}"))?;
            let mut bytes = Vec::new();
            File::open(&output)
                .map_err(|e| e.to_string())?
                .take(MAX_RECEIPT_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            Ok(RunOutput {
                success: status.success(),
                status: status.to_string(),
                stdout: bytes,
            })
        }
        .await;
        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
        result
    }
}

type Nsp1Parts<'a> = (u32, &'a [u8], &'a [u8], &'a [u8], &'a [u8]);

fn split_nsp1(b: &[u8]) -> Result<Nsp1Parts<'_>, String> {
    if b.len() > MAX_SPV_BUNDLE_BYTES || b.len() < 8 || &b[..4] != b"NSP1" {
        return Err("not an NSP1 bundle".into());
    }
    let vout = u32::from_le_bytes(b[4..8].try_into().unwrap());
    let mut rest = &b[8..];
    let mut take = || -> Result<&[u8], String> {
        if rest.len() < 4 {
            return Err("truncated NSP1 bundle".into());
        }
        let n = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
        if rest.len() - 4 < n {
            return Err("truncated NSP1 bundle".into());
        }
        let part = &rest[4..4 + n];
        rest = &rest[4 + n..];
        Ok(part)
    };
    let parts = (vout, take()?, take()?, take()?, take()?);
    if !rest.is_empty() || parts.4.len() > MAX_SPV_TX_BYTES {
        return Err("NSP1 bundle has trailing bytes or an oversized transaction".into());
    }
    Ok(parts)
}

/// SHA-256 of any regular file (the verifier key is far larger than a binary).
fn file_digest_any(path: &Path) -> Result<String, String> {
    use bitcoin::hashes::HashEngine;
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.file_type().is_file() {
        return Err("pinned file is absent or not a regular file".into());
    }
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut engine = sha256::Hash::engine();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        engine.input(&buffer[..n]);
    }
    Ok(sha256::Hash::from_engine(engine).to_string())
}

/// Compare chainwork values written with or without `0x` and zero padding.
fn same_work(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        let s = s.strip_prefix("0x").unwrap_or(s).trim_start_matches('0');
        s.to_ascii_lowercase()
    };
    norm(a) == norm(b) && !norm(a).is_empty()
}

/// Check one claimed (height, hash, chainwork) against Core's active chain.
async fn check_point(
    core: &CoreRpc,
    height: u32,
    hash: &str,
    chainwork: &str,
) -> Result<Value, RpcError> {
    let active = core.call("getblockhash", json!([height])).await?;
    if active.as_str() != Some(hash) {
        return Err(RpcError::new(
            -32050,
            format!("height {height}: proven hash is not on Core's active chain"),
        ));
    }
    let header = core.call("getblockheader", json!([hash, true])).await?;
    let core_work = header["chainwork"].as_str().unwrap_or("");
    if !same_work(core_work, chainwork) {
        return Err(RpcError::new(
            -32051,
            format!("height {height}: proven chainwork differs from Core"),
        ));
    }
    Ok(header)
}

/// Bind a verified receipt to Core's active chain now. For a payment, the
/// caller may also require the TXID and output index it expects.
pub async fn bind_active_chain(
    core: &CoreRpc,
    receipt: &StatementReceipt,
    expected_txid: Option<&str>,
    expected_vout: Option<u32>,
) -> Result<Value, RpcError> {
    match receipt {
        StatementReceipt::NovaHeaders(r) => {
            check_point(
                core,
                r.checkpoint.height,
                &r.checkpoint.tip_hash,
                &r.checkpoint.chainwork,
            )
            .await?;
            let end = check_point(core, r.end.height, &r.end.tip_hash, &r.end.chainwork).await?;
            Ok(json!({
                "statement_kind":"nova_header_chain_v1",
                "proof_verified":true,
                "active_chain_at_lookup":true,
                "core_confirmations_of_end":end["confirmations"],
                "verified_statement":r,
                "not_claimed":["checkpoint authenticity beyond the operator pin",
                               "best-chain selection (compare chainwork with Core)",
                               "the future-time rule"]
            }))
        }
        StatementReceipt::Sp1Payment(r) => {
            if expected_txid.is_some_and(|t| t != r.txid)
                || expected_vout.is_some_and(|v| v != r.vout)
            {
                return Err(RpcError::new(
                    -32052,
                    "proven output is not the expected one",
                ));
            }
            check_point(core, r.tip_height, &r.tip_hash, &r.tip_chainwork).await?;
            let active = core.call("getblockhash", json!([r.block_height])).await?;
            if active.as_str() != Some(r.block_hash.as_str()) {
                return Err(RpcError::new(
                    -32050,
                    "proven payment block is not on Core's active chain",
                ));
            }
            let block = core
                .call("getblockheader", json!([r.block_hash, true]))
                .await?;
            let unspent = unspent_at_lookup(core, &receipt.proven_output().unwrap()).await?;
            Ok(json!({
                "statement_kind":"sp1_btc_payment_v1",
                "proof_verified":true,
                "active_chain_at_lookup":true,
                "core_confirmations":block["confirmations"],
                "unspent_at_lookup":unspent,
                "unspent_source":"bitcoin_core_gettxout_including_mempool",
                "verified_statement":r,
                "not_claimed":["unspentness is proven (it is Bitcoin Core's view at lookup)",
                               "program keys are audited (they are pinned candidates)"]
            }))
        }
        StatementReceipt::NovaSpvPayment(r) => {
            if expected_txid.is_some_and(|t| t != r.txid)
                || expected_vout.is_some_and(|v| v != r.vout)
            {
                return Err(RpcError::new(
                    -32052,
                    "proven output is not the expected one",
                ));
            }
            let first = &r.chain_to_block;
            check_point(
                core,
                first.checkpoint.height,
                &first.checkpoint.tip_hash,
                &first.checkpoint.chainwork,
            )
            .await?;
            let block = check_point(
                core,
                first.end.height,
                &first.end.tip_hash,
                &first.end.chainwork,
            )
            .await?;
            if r.chain_to_tip.is_some() {
                check_point(core, r.tip_height, &r.tip_hash, &r.tip_chainwork).await?;
            }
            let unspent = unspent_at_lookup(core, &receipt.proven_output().unwrap()).await?;
            Ok(json!({
                "statement_kind":"nova_spv_payment_v1",
                "proof_verified":true,
                "active_chain_at_lookup":true,
                "core_confirmations":block["confirmations"],
                "unspent_at_lookup":unspent,
                "unspent_source":"bitcoin_core_gettxout_including_mempool",
                "verified_statement":r,
                "not_claimed":["unspentness is proven (it is Bitcoin Core's view at lookup)",
                               "checkpoint authenticity beyond the operator pin",
                               "the verifier key is audited (it is a pinned candidate)"]
            }))
        }
    }
}

/// Bitcoin Core's view of the proven output. A spend in the mempool counts as
/// spent. When the output is unspent, its value and script must equal the
/// proven ones, or Core and the proof disagree.
async fn unspent_at_lookup(core: &CoreRpc, r: &ProvenOutput) -> Result<bool, RpcError> {
    let out = core.call("gettxout", json!([r.txid, r.vout, true])).await?;
    if out.is_null() {
        return Ok(false);
    }
    let sats = out["value"]
        .as_f64()
        .map(|btc| (btc * 100_000_000.0).round() as u64);
    let script = out["scriptPubKey"]["hex"]
        .as_str()
        .and_then(|h| hex::decode(h).ok())
        .map(|s| sha_hex(&s));
    if sats != Some(r.value_sats) || script.as_deref() != Some(r.script_sha256.as_str()) {
        return Err(RpcError::new(
            -32054,
            "Bitcoin Core's unspent output differs from the proven one",
        ));
    }
    Ok(true)
}

/// Sum several verified payment receipts to one script: everything proven
/// received, and the part Core reports unspent now. This is a lower bound on
/// the script's balance; no proof shows that other outputs do not exist.
pub fn proven_balance(entries: &[(ProvenOutput, bool)]) -> Result<Value, String> {
    let first = entries.first().ok_or("no payment proofs")?;
    let script = &first.0.script_sha256;
    let mut seen = std::collections::BTreeSet::new();
    let (mut received, mut unspent) = (0u64, 0u64);
    for (r, is_unspent) in entries {
        if &r.script_sha256 != script {
            return Err("payment proofs pay different scripts".into());
        }
        if !seen.insert((r.txid.clone(), r.vout)) {
            return Err("duplicate outpoint".into());
        }
        received = received.checked_add(r.value_sats).ok_or("value overflow")?;
        if *is_unspent {
            unspent += r.value_sats;
        }
    }
    Ok(json!({
        "script_sha256":script,
        "proven_outputs":entries.len(),
        "proven_received_sats":received,
        "proven_and_unspent_at_lookup_sats":unspent,
        "outputs":entries.iter().map(|(r, u)| json!({
            "txid":r.txid,"vout":r.vout,"value_sats":r.value_sats,
            "block_height":r.block_height,"unspent_at_lookup":u
        })).collect::<Vec<_>>(),
        "not_claimed":["completeness: other outputs to this script may exist",
                       "unspentness is proven (it is Bitcoin Core's view at lookup)"]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) const NOVA_RECEIPT: &str = include_str!("../tests/fixtures/nova100_receipt.json");
    pub(crate) const PAYMENT_RECEIPT: &str = include_str!("../tests/fixtures/payment_receipt.json");
    const NOVA_BUNDLE: &[u8] =
        include_bytes!("../../../integrations/nova-header-chain/fixtures/nova100.nhc1");
    const PAYMENT_BUNDLE: &[u8] =
        include_bytes!("../../../integrations/sp1-btc-payment/fixtures/payment.bpg1");

    pub(crate) fn nova_policy() -> NovaPolicy {
        NovaPolicy {
            vk_sha256: "e46bb06929d701f1986d320e004e8ed744b0e5f74eb9f5e9c9bd0e2fe6ad1698".into(),
            checkpoints: vec![
                "3e53c33057b13ffecca476024bc78962b624814f41ac9d39e127e8f5a51a507e".into(),
            ],
        }
    }

    pub(crate) fn payment_policy() -> PaymentPolicy {
        PaymentPolicy {
            pay_vkey: "0x00de861a80542b3089fed26b37ac4e1f4bb8664dcddadb3a6de5ae7205751e75".into(),
            node_program_words: "a95b1a6090a64052fb6c2c12a0c5c861843a8b04b68e2218f77c9c4693510d76"
                .into(),
            leaf_program_words: "12c6f307aff4045af93b5a1d0221eb303955312728625960efa42d592e843701"
                .into(),
            segment_program_words:
                "99dedc0b1be5794d932fb94e6d90030e663383572f25bb5161e7347ab0fc4550".into(),
        }
    }

    #[test]
    fn real_nova_receipt_binds_bundle_key_and_checkpoint() {
        let receipt: NovaHeaderReceipt = serde_json::from_str(NOVA_RECEIPT).unwrap();
        let policy = nova_policy();
        receipt
            .validate(&policy.vk_sha256, &policy.checkpoints, NOVA_BUNDLE)
            .unwrap();

        let mut other = NOVA_BUNDLE.to_vec();
        let n = other.len();
        other[n - 1] ^= 1;
        assert!(
            receipt
                .validate(&policy.vk_sha256, &policy.checkpoints, &other)
                .is_err(),
            "proof bytes"
        );
        let mut unpinned = policy.clone();
        unpinned.checkpoints = vec!["ab".repeat(32)];
        assert!(
            receipt
                .validate(&unpinned.vk_sha256, &unpinned.checkpoints, NOVA_BUNDLE)
                .is_err(),
            "checkpoint pin"
        );
        let mut wrong_key = policy.clone();
        wrong_key.vk_sha256 = "cd".repeat(32);
        assert!(
            receipt
                .validate(&wrong_key.vk_sha256, &wrong_key.checkpoints, NOVA_BUNDLE)
                .is_err(),
            "vk pin"
        );
        let mut lie = receipt.clone();
        lie.headers = 99;
        assert!(
            lie.validate(&policy.vk_sha256, &policy.checkpoints, NOVA_BUNDLE)
                .is_err(),
            "header count"
        );
        let mut rejected = receipt;
        rejected.verified = false;
        assert!(rejected
            .validate(&policy.vk_sha256, &policy.checkpoints, NOVA_BUNDLE)
            .is_err());
    }

    #[test]
    fn real_payment_receipt_binds_bundle_and_program_pins() {
        let receipt: PaymentReceipt = serde_json::from_str(PAYMENT_RECEIPT).unwrap();
        let policy = payment_policy();
        receipt.validate(&policy, PAYMENT_BUNDLE).unwrap();

        let mut other = PAYMENT_BUNDLE.to_vec();
        other[100] ^= 1;
        assert!(receipt.validate(&policy, &other).is_err());
        for field in 0..4 {
            let mut p = policy.clone();
            let slot = match field {
                0 => &mut p.pay_vkey,
                1 => &mut p.node_program_words,
                2 => &mut p.leaf_program_words,
                _ => &mut p.segment_program_words,
            };
            slot.replace_range(slot.len() - 2.., "ff");
            assert!(receipt.validate(&p, PAYMENT_BUNDLE).is_err(), "pin {field}");
        }
        let mut lie = receipt;
        lie.confirmations = 12;
        assert!(lie.validate(&policy, PAYMENT_BUNDLE).is_err());
    }

    #[test]
    fn nsp1_framing_is_strict() {
        let part = |b: &[u8]| [&(b.len() as u32).to_le_bytes()[..], b].concat();
        let good = [
            b"NSP1".as_slice(),
            &7u32.to_le_bytes(),
            &part(b"aa"),
            &part(b""),
            &part(b"mb"),
            &part(b"tx"),
        ]
        .concat();
        let (vout, a, b, m, t) = split_nsp1(&good).unwrap();
        assert_eq!(
            (vout, a, b, m, t),
            (7, &b"aa"[..], &b""[..], &b"mb"[..], &b"tx"[..])
        );
        assert!(split_nsp1(&good[..good.len() - 1]).is_err(), "truncated");
        assert!(
            split_nsp1(&[good.as_slice(), b"x"].concat()).is_err(),
            "trailing"
        );
        let mut magic = good.clone();
        magic[0] = b'X';
        assert!(split_nsp1(&magic).is_err());
        let mut huge = good.clone();
        huge[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(split_nsp1(&huge).is_err(), "length overflow");
    }

    #[test]
    fn balance_is_a_lower_bound_over_one_script() {
        let receipt: PaymentReceipt = serde_json::from_str(PAYMENT_RECEIPT).unwrap();
        let r = StatementReceipt::Sp1Payment(receipt)
            .proven_output()
            .unwrap();
        let mut second = r.clone();
        second.vout = 1;
        second.value_sats = 5;
        let b = proven_balance(&[(r.clone(), true), (second.clone(), false)]).unwrap();
        assert_eq!(b["proven_received_sats"], 2_010_005);
        assert_eq!(b["proven_and_unspent_at_lookup_sats"], 2_010_000);
        let mut other_script = second;
        other_script.script_sha256 = "00".repeat(32);
        assert!(proven_balance(&[(r.clone(), true), (other_script, true)]).is_err());
        assert!(proven_balance(&[(r.clone(), true), (r, true)]).is_err());
        assert!(proven_balance(&[]).is_err());
    }

    #[test]
    fn receipts_reject_unknown_fields_and_kinds_are_named() {
        let mut v: Value = serde_json::from_str(PAYMENT_RECEIPT).unwrap();
        v["unspent"] = json!(true);
        assert!(serde_json::from_value::<PaymentReceipt>(v).is_err());
        assert_eq!(
            StatementKind::from_name("sp1_btc_payment_v1"),
            Ok(StatementKind::Sp1Payment)
        );
        assert!(StatementKind::from_name("raito").is_err());
        assert!(same_work("0x44d044d044d", "00000000044d044d044d"));
        assert!(!same_work("0x0", "0000"));
    }
}
