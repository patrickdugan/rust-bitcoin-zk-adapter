//! Client-submitted Bitcoin statement proofs, checked by operator-pinned
//! external verifiers and then bound to Bitcoin Core's active chain.
//!
//! Proving happens off the gateway. A client submits a small proof bundle
//! inline:
//! - `nova_header_chain_v1`: an NHC1 bundle (about 13.5 KB) proving a
//!   header chain from an operator-pinned checkpoint;
//! - `sp1_btc_payment_v1`: a BPG1 bundle (709 bytes) proving a payment
//!   output's inclusion under a proven header chain.
//!
//! A receipt is returned only when all of the following hold:
//! 1. the pinned verifier executable accepts the bundle;
//! 2. its typed receipt binds the submitted bytes and the pinned keys;
//! 3. every chain claim (height, hash and chainwork) matches Core at lookup.
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
const MAX_RECEIPT_BYTES: u64 = 8192;
const VERIFY_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementKind {
    NovaHeaders,
    Sp1Payment,
}

impl StatementKind {
    pub fn from_name(name: &str) -> Result<Self, String> {
        match name {
            "nova_header_chain_v1" => Ok(Self::NovaHeaders),
            "sp1_btc_payment_v1" => Ok(Self::Sp1Payment),
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
    pub program: PinnedProgram,
    pub vk_path: PathBuf,
    pub vk_sha256: String,
    /// SHA-256 of the 17 checkpoint field elements (`checkpoint_state_sha256`).
    pub checkpoints: Vec<String>,
}

/// Payment policy: the SP1 payment program key and the header-chain program
/// identities its statement must commit.
#[derive(Clone, Debug)]
pub struct PaymentPolicy {
    pub program: PinnedProgram,
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

#[derive(Debug, Clone, PartialEq)]
pub enum StatementReceipt {
    NovaHeaders(NovaHeaderReceipt),
    Sp1Payment(PaymentReceipt),
}

impl NovaHeaderReceipt {
    pub fn validate(&self, policy: &NovaPolicy, bundle: &[u8]) -> Result<(), String> {
        let headers_ok = u64::from(self.end.height)
            .checked_sub(u64::from(self.checkpoint.height))
            .is_some_and(|n| n == self.headers && n > 0);
        if !self.verified
            || self.statement != NOVA_STATEMENT
            || self.verifier != NOVA_VERIFIER
            || self.vk_sha256 != policy.vk_sha256
            || bundle.len() <= NHC1_HEADER_BYTES
            || self.proof_sha256 != sha_hex(&bundle[NHC1_HEADER_BYTES..])
            || self.checkpoint_state_sha256 != sha_hex(&bundle[12..NHC1_HEADER_BYTES])
            || !policy.checkpoints.contains(&self.checkpoint_state_sha256)
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

/// Verifiers configured by the operator; at most one verification runs at a
/// time per gateway, since a Nova check loads a ~250 MB verifier key.
pub struct StatementVerifiers {
    work_dir: PathBuf,
    nova: Option<NovaPolicy>,
    payment: Option<PaymentPolicy>,
    slots: Semaphore,
    counter: AtomicU64,
}

impl StatementVerifiers {
    pub fn new(
        work_dir: PathBuf,
        nova: Option<NovaPolicy>,
        payment: Option<PaymentPolicy>,
    ) -> Result<Self, String> {
        if !work_dir.is_absolute() {
            return Err("statement work directory must be absolute".into());
        }
        fs::create_dir_all(&work_dir).map_err(|e| e.to_string())?;
        if let Some(ref p) = nova {
            p.program.validate()?;
            if !p.vk_path.is_absolute() || file_digest_any(&p.vk_path)? != p.vk_sha256 {
                return Err("Nova verifier key differs from its SHA-256 pin".into());
            }
            if p.checkpoints.is_empty() || !p.checkpoints.iter().all(|c| valid_hash(c)) {
                return Err("Nova policy requires at least one pinned checkpoint digest".into());
            }
        }
        if let Some(ref p) = payment {
            p.program.validate()?;
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
            work_dir,
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
                if bundle.len() > MAX_NOVA_BUNDLE_BYTES || bundle.len() <= NHC1_HEADER_BYTES {
                    return Err("NHC1 bundle size out of range".into());
                }
                policy.program.validate()?;
                let bytes = self
                    .run(&policy.program, bundle, |path| {
                        vec![
                            "verify-bundle".into(),
                            path.as_os_str().to_owned(),
                            "--vk".into(),
                            policy.vk_path.as_os_str().to_owned(),
                        ]
                    })
                    .await?;
                let receipt: NovaHeaderReceipt =
                    serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                receipt.validate(policy, bundle)?;
                Ok(StatementReceipt::NovaHeaders(receipt))
            }
            StatementKind::Sp1Payment => {
                let policy = self
                    .payment
                    .as_ref()
                    .ok_or("payment verifier is not configured")?;
                if bundle.len() != PAYMENT_BUNDLE_BYTES {
                    return Err("BPG1 bundle must be 709 bytes".into());
                }
                policy.program.validate()?;
                let bytes = self
                    .run(&policy.program, bundle, |path| {
                        vec![path.as_os_str().to_owned(), policy.pay_vkey.clone().into()]
                    })
                    .await?;
                let receipt: PaymentReceipt =
                    serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                receipt.validate(policy, bundle)?;
                Ok(StatementReceipt::Sp1Payment(receipt))
            }
        }
    }

    /// Write the bundle to a fresh file, run the verifier with stdout to a
    /// fresh file, and return the bounded stdout of an accepting run.
    async fn run(
        &self,
        program: &PinnedProgram,
        bundle: &[u8],
        args: impl FnOnce(&Path) -> Vec<std::ffi::OsString>,
    ) -> Result<Vec<u8>, String> {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let stem = format!("{}-{}-{n}", sha_hex(bundle), std::process::id());
        let input = self.work_dir.join(format!("{stem}.bundle"));
        let output = self.work_dir.join(format!("{stem}.receipt"));
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
            if bytes.len() as u64 > MAX_RECEIPT_BYTES {
                return Err("statement verifier receipt exceeds size limit".into());
            }
            if !status.success() {
                let reason = serde_json::from_slice::<Value>(&bytes)
                    .ok()
                    .and_then(|v| v["error"].as_str().map(|s| s.chars().take(200).collect()))
                    .unwrap_or_else(|| status.to_string());
                return Err(format!("proof rejected: {reason}"));
            }
            Ok(bytes)
        }
        .await;
        let _ = fs::remove_file(&input);
        let _ = fs::remove_file(&output);
        result
    }
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
            Ok(json!({
                "statement_kind":"sp1_btc_payment_v1",
                "proof_verified":true,
                "active_chain_at_lookup":true,
                "core_confirmations":block["confirmations"],
                "verified_statement":r,
                "not_claimed":["the output is unspent",
                               "program keys are audited (they are pinned candidates)"]
            }))
        }
    }
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

    fn program() -> PinnedProgram {
        PinnedProgram {
            executable: PathBuf::from("/unused"),
            binary_sha256: "00".repeat(32),
        }
    }

    pub(crate) fn nova_policy() -> NovaPolicy {
        NovaPolicy {
            program: program(),
            vk_path: PathBuf::from("/unused"),
            vk_sha256: "e46bb06929d701f1986d320e004e8ed744b0e5f74eb9f5e9c9bd0e2fe6ad1698".into(),
            checkpoints: vec![
                "3e53c33057b13ffecca476024bc78962b624814f41ac9d39e127e8f5a51a507e".into(),
            ],
        }
    }

    pub(crate) fn payment_policy() -> PaymentPolicy {
        PaymentPolicy {
            program: program(),
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
        receipt.validate(&policy, NOVA_BUNDLE).unwrap();

        let mut other = NOVA_BUNDLE.to_vec();
        let n = other.len();
        other[n - 1] ^= 1;
        assert!(receipt.validate(&policy, &other).is_err(), "proof bytes");
        let mut unpinned = policy.clone();
        unpinned.checkpoints = vec!["ab".repeat(32)];
        assert!(
            receipt.validate(&unpinned, NOVA_BUNDLE).is_err(),
            "checkpoint pin"
        );
        let mut wrong_key = policy.clone();
        wrong_key.vk_sha256 = "cd".repeat(32);
        assert!(receipt.validate(&wrong_key, NOVA_BUNDLE).is_err(), "vk pin");
        let mut lie = receipt.clone();
        lie.headers = 99;
        assert!(lie.validate(&policy, NOVA_BUNDLE).is_err(), "header count");
        let mut rejected = receipt;
        rejected.verified = false;
        assert!(rejected.validate(&policy, NOVA_BUNDLE).is_err());
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
