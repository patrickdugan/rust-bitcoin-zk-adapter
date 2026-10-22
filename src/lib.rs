//! A small independent adjunct to rust-bitcoin.
//!
//! The native verifier below is NOT a zero-knowledge proof system. It supplies
//! deterministic semantics and public-input boundaries for a future zkVM guest.
//! The caller is responsible for canonical-chain verification and prevout data.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Block, Txid};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub txid: Txid,
    pub tx_index: u32,
    pub vout: u32,
    /// Complete script bytes; OP_RETURN payload parsing is protocol/version specific.
    pub script: Vec<u8>,
}

/// Extracts potential overlay events in canonical transaction/output order.
/// This step deliberately does not assert that any event belongs to TradeLayer.
pub fn extract_candidates(block: &Block) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    for (tx_index, tx) in block.txdata.iter().enumerate() {
        for (vout, output) in tx.output.iter().enumerate() {
            if output.script_pubkey.is_op_return() {
                candidates.push(Candidate {
                    txid: tx.compute_txid(),
                    tx_index: tx_index as u32,
                    vout: vout as u32,
                    script: output.script_pubkey.as_bytes().to_vec(),
                });
            }
        }
    }
    candidates
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInputs {
    pub chain_id: u32,
    pub block_height: u64,
    /// Externally established Bitcoin block hash, not verified by this library.
    pub block_hash: [u8; 32],
    pub prior_state_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub input_commitment: [u8; 32],
    pub candidate_count: u64,
}

/// Deterministic domain-separated commitment to public inputs and extracted
/// candidate scripts. This is a native receipt, NOT a cryptographic ZK proof.
pub fn commit_candidates(inputs: &PublicInputs, events: &[Candidate]) -> Receipt {
    let mut bytes = b"RTG-BTC-ZK-ADJUNCT-CANDIDATES-V1".to_vec();
    bytes.extend_from_slice(&inputs.chain_id.to_be_bytes());
    bytes.extend_from_slice(&inputs.block_height.to_be_bytes());
    bytes.extend_from_slice(&inputs.block_hash);
    bytes.extend_from_slice(&inputs.prior_state_root);
    bytes.extend_from_slice(&(events.len() as u64).to_be_bytes());
    for e in events {
        bytes.extend_from_slice(&e.txid.to_byte_array());
        bytes.extend_from_slice(&e.tx_index.to_be_bytes());
        bytes.extend_from_slice(&e.vout.to_be_bytes());
        bytes.extend_from_slice(&(e.script.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&e.script);
    }
    Receipt {
        input_commitment: sha256::Hash::hash(&bytes).to_byte_array(),
        candidate_count: events.len() as u64,
    }
}

/// A recomputation check. This authenticates no external Bitcoin data and
/// provides no ZK soundness or privacy guarantees.
pub fn verify_native(inputs: &PublicInputs, events: &[Candidate], receipt: &Receipt) -> bool {
    commit_candidates(inputs, events) == *receipt
}
