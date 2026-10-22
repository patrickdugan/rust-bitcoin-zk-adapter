//! Heavy optional Raito STARK verifier; never part of default sidecar builds.
//! Reuses the real Raito verifier and binds it to an expected Bitcoin TXID.

use anyhow::{bail, ensure, Context, Result};
use bincode::Options;
use bitcoin::consensus;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{BlockHash, MerkleBlock, Transaction, Txid};
use bzip2::read::BzDecoder;
use raito_spv_verify::{verify_proof, CompressedSpvProof, VerifierConfig};
use rust_bitcoin_zk_adapter::{extract_transaction_candidates, Candidate};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

pub const MAX_COMPRESSED_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_DECOMPRESSED_BYTES: u64 = 128 * 1024 * 1024;

/// Bitcoin transaction checked under a specific Raito proof policy.
/// This does not independently select Bitcoin's canonical chain.
#[derive(Debug, Clone)]
pub struct RaitoCheckedTransaction {
    transaction: Transaction,
    txid: Txid,
    block_hash: BlockHash,
    block_height: u32,
    proven_tip_height: u32,
    tx_index: u32,
    candidates: Vec<Candidate>,
    proof_sha256: String,
}

impl RaitoCheckedTransaction {
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }
    pub fn txid(&self) -> Txid {
        self.txid
    }
    pub fn block_hash(&self) -> BlockHash {
        self.block_hash
    }
    pub fn block_height(&self) -> u32 {
        self.block_height
    }
    pub fn proven_tip_height(&self) -> u32 {
        self.proven_tip_height
    }
    pub fn tx_index(&self) -> u32 {
        self.tx_index
    }
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }
    /// SHA-256 of the exact compressed bytes decoded and STARK-verified.
    pub fn proof_sha256(&self) -> &str {
        &self.proof_sha256
    }
}

/// Bounded bzip2/bincode decoder for the upstream Raito proof format.
fn load_bounded_proof(path: &Path) -> Result<(CompressedSpvProof, String)> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("proof path {} could not be inspected", path.display()))?;
    ensure!(meta.file_type().is_file(), "proof must be a regular file");
    ensure!(meta.len() <= MAX_COMPRESSED_BYTES, "compressed proof exceeds limit");

    // Hash the same compressed byte buffer that is decompressed and verified.
    // This prevents proof-file replacement between separate hashing and parsing.
    let mut compressed = Vec::with_capacity(meta.len() as usize);
    File::open(path)?
        .take(MAX_COMPRESSED_BYTES + 1)
        .read_to_end(&mut compressed)?;
    ensure!(
        compressed.len() as u64 <= MAX_COMPRESSED_BYTES,
        "compressed proof exceeds limit"
    );
    let digest = sha256::Hash::hash(&compressed).to_string();

    let mut decoded = Vec::new();
    BzDecoder::new(&compressed[..])
        .take(MAX_DECOMPRESSED_BYTES + 1)
        .read_to_end(&mut decoded)?;
    ensure!(
        decoded.len() as u64 <= MAX_DECOMPRESSED_BYTES,
        "decompressed proof exceeds limit"
    );
    let options = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_DECOMPRESSED_BYTES)
        .reject_trailing_bytes();
    let proof = options
        .deserialize(&decoded)
        .context("malformed Raito compressed SPV proof")?;
    Ok((proof, digest))
}

/// Full Raito STARK+MMR+transaction verification in non-development mode.
///
/// Caller controls expected_txid, minimum proven height and the pinned
/// VerifierConfig, including bootloader hashes and work threshold.
pub async fn verify_raito_proof(
    path: &Path,
    expected_txid: Txid,
    min_proven_height: u32,
    config: &VerifierConfig,
) -> Result<RaitoCheckedTransaction> {
    let (proof, proof_sha256) = load_bounded_proof(path)?;
    let found_txid = proof.transaction.compute_txid();
    ensure!(
        found_txid == expected_txid,
        "proof TXID does not match request"
    );

    let tip_height = proof.chain_state.block_height;
    ensure!(
        tip_height >= min_proven_height,
        "proof tip below required height"
    );
    let block_height = u32::try_from(proof.block_header_proof.leaf_index)
        .context("block height outside u32 range")?;
    ensure!(
        block_height <= tip_height,
        "block height exceeds proven tip"
    );

    let block_hash = proof.block_header.block_hash();
    let transaction = proof.transaction.clone();

    // The MerkleTree itself tells us the inclusion position; there is no
    // independent, user-controlled transaction index in this interface.
    let merkle = MerkleBlock {
        header: proof.block_header,
        txn: consensus::deserialize(&proof.transaction_proof)?,
    };
    let mut matched = Vec::new();
    let mut indexes = Vec::new();
    merkle.extract_matches(&mut matched, &mut indexes)?;
    if matched.len() != 1 || indexes.len() != 1 || matched[0] != expected_txid {
        bail!("partial Merkle tree fails to bind the expected TXID");
    }
    let tx_index = indexes[0];

    // Reuses Raito's Cairo STARK proof validation, MMR inclusion and
    // cumulative-work policy with security checks enabled (dev=false).
    verify_proof(proof, config, false)
        .await
        .context("Raito proof validation failed")?;

    let candidates = extract_transaction_candidates(&transaction, tx_index);
    Ok(RaitoCheckedTransaction {
        transaction,
        txid: found_txid,
        block_hash,
        block_height,
        proven_tip_height: tip_height,
        tx_index,
        candidates,
        proof_sha256,
    })
}
