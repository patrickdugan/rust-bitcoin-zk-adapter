//! Inclusion verification against a supplied Bitcoin transaction Merkle root.
//! The caller must authenticate the header with Bitcoin Core and establish
//! canonical chain membership separately; no Bitcoin consensus is checked here.

use bitcoin::hashes::Hash;
use bitcoin::{block::Header, TxMerkleNode, Txid};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkleError {
    InvalidPosition,
    MissingSibling,
    ExtraSibling,
    InvalidOddDuplication,
    MutatedPair,
    RootMismatch,
}
impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for MerkleError {}

fn parent(left: TxMerkleNode, right: TxMerkleNode) -> TxMerkleNode {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&left.to_byte_array());
    bytes[32..].copy_from_slice(&right.to_byte_array());
    TxMerkleNode::hash(&bytes)
}

/// Verify tx inclusion against the supplied root. The branch contains the
/// duplicated sibling for the final leaf of each odd-width Merkle level.
/// The count constrains path length, padding positions, and tree shape.
pub fn verify_tx_merkle_root(
    txid: Txid,
    position: u32,
    transaction_count: u32,
    siblings: &[TxMerkleNode],
    expected_root: TxMerkleNode,
) -> Result<(), MerkleError> {
    if transaction_count == 0 || position >= transaction_count {
        return Err(MerkleError::InvalidPosition);
    }
    let mut node = TxMerkleNode::from_byte_array(txid.to_byte_array());
    let mut index = position;
    let mut width = transaction_count;
    let mut used = 0usize;

    while width > 1 {
        let sibling = *siblings.get(used).ok_or(MerkleError::MissingSibling)?;
        used += 1;
        let odd_last = width % 2 == 1 && index == width - 1;
        if odd_last {
            if sibling != node {
                return Err(MerkleError::InvalidOddDuplication);
            }
        } else if sibling == node {
            return Err(MerkleError::MutatedPair);
        }
        node = if index % 2 == 0 {
            parent(node, sibling)
        } else {
            parent(sibling, node)
        };
        index /= 2;
        width = width / 2 + width % 2;
    }

    if used != siblings.len() {
        return Err(MerkleError::ExtraSibling);
    }
    if node != expected_root {
        return Err(MerkleError::RootMismatch);
    }
    Ok(())
}

/// Check the transaction Merkle path against an externally supplied header.
/// The header itself must be separately authenticated by the caller.
pub fn verify_tx_in_header(
    header: &Header,
    txid: Txid,
    position: u32,
    transaction_count: u32,
    siblings: &[TxMerkleNode],
) -> Result<(), MerkleError> {
    verify_tx_merkle_root(
        txid,
        position,
        transaction_count,
        siblings,
        header.merkle_root,
    )
}
