//! Independent Bitcoin application sidecar built atop rust-bitcoin.
//!
//! Deterministic transaction and OP_RETURN utilities live here. Consensus
//! validation and STARK verification belong to specialized upstream engines.
//! Raito integration is kept optional to avoid a heavy default dependency tree.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Block, Transaction, Txid};

pub mod merkle;
pub mod op_return;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub txid: Txid,
    pub tx_index: u32,
    pub vout: u32,
    /// Original output script, without application-specific interpretation.
    pub script: Vec<u8>,
}

/// Collect OP_RETURN outputs from one Bitcoin transaction, preserving vout
/// positions. The caller must authenticate the transaction and its position.
pub fn extract_transaction_candidates(tx: &Transaction, tx_index: u32) -> Vec<Candidate> {
    let txid = tx.compute_txid();
    tx.output
        .iter()
        .enumerate()
        .filter(|(_, output)| output.script_pubkey.is_op_return())
        .map(|(vout, output)| Candidate {
            txid,
            tx_index,
            vout: vout as u32,
            script: output.script_pubkey.as_bytes().to_vec(),
        })
        .collect()
}

/// Collect OP_RETURN candidates in block transaction/output order. This
/// performs NO Bitcoin consensus validation of the supplied block.
pub fn extract_candidates(block: &Block) -> Vec<Candidate> {
    block
        .txdata
        .iter()
        .enumerate()
        .flat_map(|(tx_index, tx)| extract_transaction_candidates(tx, tx_index as u32))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInputs {
    pub chain_id: u32,
    pub block_height: u64,
    /// Claimed block hash supplied by the caller.
    pub block_hash: [u8; 32],
    /// Arbitrary app-defined prior-state commitment, NOT checked here.
    pub prior_state_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub input_commitment: [u8; 32],
    pub candidate_count: u64,
}

/// Deterministic native hash receipt over supplied candidates. This is neither
/// a STARK proof nor evidence that the candidates belong to a valid chain.
pub fn commit_candidates(inputs: &PublicInputs, events: &[Candidate]) -> Receipt {
    let mut bytes = b"RUST-BITCOIN-ZK-SIDECAR-CANDIDATES-V1".to_vec();
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

/// Recompute a native commitment from inputs. A true proof must be checked
/// through an external verifier such as Raito.
pub fn verify_native(inputs: &PublicInputs, events: &[Candidate], receipt: &Receipt) -> bool {
    commit_candidates(inputs, events) == *receipt
}
