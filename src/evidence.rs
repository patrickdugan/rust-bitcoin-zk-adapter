//! Offline Litecoin testnet transaction-inclusion evidence verification.
//!
//! Scope: classic base-layer Litecoin transaction serialization, the standard
//! 80-byte header and Bitcoin-style transaction Merkle commitments. This
//! performs neither Litecoin Scrypt proof-of-work nor chain validation. The
//! source node and its canonical-chain view remain external trust assumptions.

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::{block::Header, BlockHash, Transaction, TxMerkleNode, Txid};
use serde::Deserialize;
use std::str::FromStr;

use crate::merkle::verify_tx_in_header;

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_TRANSACTION_BYTES: usize = 4_000_000;
pub const LITECOIN_TESTNET_GENESIS: &str =
    "4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0";

/// V1 accepts Litecoin testnet explicitly; mainnet evidence needs a separate
/// network anchor and additional test coverage before being enabled.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceChain {
    Litecoin,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceNetwork {
    Testnet,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionClaim {
    pub schema_version: u32,
    pub chain: EvidenceChain,
    pub network: EvidenceNetwork,
    pub genesis_hash: String,
    pub block_height: u64,
    pub block_hash: String,
    pub block_header_hex: String,
    pub txid: String,
    pub raw_transaction_hex: String,
    pub tx_index: u32,
    pub transaction_count: u32,
    pub merkle_siblings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedInclusion {
    pub txid: Txid,
    pub block_hash: BlockHash,
    pub block_height: u64,
    pub tx_index: u32,
    pub op_return_outputs: Vec<u32>,
}

/// Decode bounded, exact, ASCII hex without permissive truncation.
pub fn decode_hex_exact(hex: &str, limit: usize) -> Result<Vec<u8>, String> {
    if !hex.is_ascii() || hex.len() > limit.saturating_mul(2) {
        return Err("hex data is non-ASCII or exceeds size limit".into());
    }
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err("odd hex digit count".into());
    }
    let mut output = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let text = std::str::from_utf8(pair).map_err(|_| "invalid ASCII")?;
        let value = u8::from_str_radix(text, 16).map_err(|_| "invalid hex digit")?;
        output.push(value);
    }
    Ok(output)
}

/// Check that the supplied transaction is bound to the specified header root.
///
/// Success proves only internal consistency of the claim. In particular,
/// genesis_hash is checked against Litecoin Core's testnet genesis constant,
/// but no path from the supplied header to that genesis is verified here.
/// The exporter is responsible for obtaining the block from a trusted node.
pub fn verify_litecoin_testnet_claim(claim: &InclusionClaim) -> Result<VerifiedInclusion, String> {
    if claim.schema_version != SCHEMA_VERSION {
        return Err("unsupported evidence schema version".into());
    }
    if claim.chain != EvidenceChain::Litecoin || claim.network != EvidenceNetwork::Testnet {
        return Err("unsupported evidence chain/network".into());
    }
    let genesis = BlockHash::from_str(&claim.genesis_hash)
        .map_err(|error| format!("bad genesis hash: {error}"))?;
    let expected_genesis = BlockHash::from_str(LITECOIN_TESTNET_GENESIS)
        .map_err(|error| format!("internal testnet anchor error: {error}"))?;
    if genesis != expected_genesis {
        return Err("Litecoin testnet genesis mismatch".into());
    }

    let raw = decode_hex_exact(&claim.raw_transaction_hex, MAX_TRANSACTION_BYTES)?;
    let transaction: Transaction =
        deserialize(&raw).map_err(|error| format!("transaction decode: {error}"))?;
    let actual_txid = transaction.compute_txid();
    let declared_txid =
        Txid::from_str(&claim.txid).map_err(|error| format!("bad txid: {error}"))?;
    if actual_txid != declared_txid {
        return Err("transaction bytes do not match declared txid".into());
    }

    let header_bytes = decode_hex_exact(&claim.block_header_hex, 80)?;
    if header_bytes.len() != 80 {
        return Err("expected 80-byte Litecoin base block header".into());
    }
    let header: Header =
        deserialize(&header_bytes).map_err(|error| format!("header decode: {error}"))?;
    let actual_block_hash = header.block_hash();
    let declared_block_hash = BlockHash::from_str(&claim.block_hash)
        .map_err(|error| format!("bad block hash: {error}"))?;
    if actual_block_hash != declared_block_hash {
        return Err("header bytes do not match declared block hash".into());
    }

    if claim.transaction_count == 0 || claim.merkle_siblings.len() > 32 {
        return Err("invalid block transaction count or branch depth".into());
    }
    let siblings = claim
        .merkle_siblings
        .iter()
        .map(|value| {
            TxMerkleNode::from_str(value).map_err(|error| format!("bad Merkle sibling: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    verify_tx_in_header(
        &header,
        actual_txid,
        claim.tx_index,
        claim.transaction_count,
        &siblings,
    )
    .map_err(|error| format!("transaction inclusion: {error}"))?;

    let op_return_outputs = transaction
        .output
        .iter()
        .enumerate()
        .filter_map(|(vout, output)| output.script_pubkey.is_op_return().then_some(vout as u32))
        .collect();

    Ok(VerifiedInclusion {
        txid: actual_txid,
        block_hash: actual_block_hash,
        block_height: claim.block_height,
        tx_index: claim.tx_index,
        op_return_outputs,
    })
}
