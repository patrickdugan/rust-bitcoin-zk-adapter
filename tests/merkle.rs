use bitcoin::hashes::Hash;
use bitcoin::{constants::genesis_block, Network, TxMerkleNode, Txid};
use rust_bitcoin_zk_adapter::merkle::{verify_tx_in_header, verify_tx_merkle_root, MerkleError};

fn tid(v: u8) -> Txid {
    Txid::from_byte_array([v; 32])
}
fn leaf(id: Txid) -> TxMerkleNode {
    TxMerkleNode::from_byte_array(id.to_byte_array())
}
fn pair(a: TxMerkleNode, b: TxMerkleNode) -> TxMerkleNode {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(&a.to_byte_array());
    data[32..].copy_from_slice(&b.to_byte_array());
    TxMerkleNode::hash(&data)
}
#[test]
fn genesis_single_transaction_inclusion() {
    let block = genesis_block(Network::Bitcoin);
    assert_eq!(block.txdata.len(), 1);
    let id = block.txdata[0].compute_txid();
    assert_eq!(
        id.to_string(),
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    );
    assert_eq!(verify_tx_in_header(&block.header, id, 0, 1, &[]), Ok(()));
    assert_eq!(
        verify_tx_in_header(&block.header, id, 1, 1, &[]),
        Err(MerkleError::InvalidPosition)
    );
}
#[test]
fn two_leaves_and_root_mismatch() {
    let a = tid(1);
    let b = tid(2);
    let root = pair(leaf(a), leaf(b));
    assert_eq!(verify_tx_merkle_root(a, 0, 2, &[leaf(b)], root), Ok(()));
    assert_eq!(verify_tx_merkle_root(b, 1, 2, &[leaf(a)], root), Ok(()));
    assert_eq!(
        verify_tx_merkle_root(a, 0, 2, &[leaf(b)], leaf(a)),
        Err(MerkleError::RootMismatch)
    );
}
#[test]
fn odd_width_padding_is_bound() {
    let a = tid(1);
    let b = tid(2);
    let c = tid(3);
    let ab = pair(leaf(a), leaf(b));
    let cc = pair(leaf(c), leaf(c));
    let root = pair(ab, cc);
    assert_eq!(verify_tx_merkle_root(c, 2, 3, &[leaf(c), ab], root), Ok(()));
    assert_eq!(verify_tx_merkle_root(a, 0, 3, &[leaf(b), cc], root), Ok(()));
    assert_eq!(
        verify_tx_merkle_root(c, 2, 3, &[leaf(b), ab], root),
        Err(MerkleError::InvalidOddDuplication)
    );
}
#[test]
fn malformed_branches_fail_closed() {
    let a = tid(1);
    let b = tid(2);
    let root = pair(leaf(a), leaf(b));
    assert_eq!(
        verify_tx_merkle_root(a, 0, 0, &[leaf(b)], root),
        Err(MerkleError::InvalidPosition)
    );
    assert_eq!(
        verify_tx_merkle_root(a, 2, 2, &[leaf(b)], root),
        Err(MerkleError::InvalidPosition)
    );
    assert_eq!(
        verify_tx_merkle_root(a, 0, 2, &[], root),
        Err(MerkleError::MissingSibling)
    );
    assert_eq!(
        verify_tx_merkle_root(a, 0, 2, &[leaf(b), leaf(b)], root),
        Err(MerkleError::ExtraSibling)
    );
    assert_eq!(
        verify_tx_merkle_root(a, 0, 2, &[leaf(a)], pair(leaf(a), leaf(a))),
        Err(MerkleError::MutatedPair)
    );
}
