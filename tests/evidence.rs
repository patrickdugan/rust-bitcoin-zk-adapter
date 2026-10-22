use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::{block::Header, Transaction, TxMerkleNode};
use rust_bitcoin_zk_adapter::evidence::{
    decode_hex_exact, verify_litecoin_testnet_claim, EvidenceChain, EvidenceNetwork,
    InclusionClaim, LITECOIN_TESTNET_GENESIS,
};

const GENESIS_HEADER: &str = include_str!("../fixtures/litecoin_testnet/genesis_header.hex");
const TX_HEX: &str = include_str!(
    "../fixtures/mainnet/2033435de7ce307341231e818ed937cd3a5e8597381fd83a7e5b0234f61b38d3.hex"
);

/// A synthetic claim using a Bitcoin transaction and an altered Litecoin
/// testnet genesis header. This deliberately claims NO real Litecoin block.
fn synthetic_claim() -> InclusionClaim {
    let raw_tx = decode_hex_exact(TX_HEX.trim(), 4_000_000).unwrap();
    let tx: Transaction = deserialize(&raw_tx).unwrap();
    let bytes = decode_hex_exact(GENESIS_HEADER.trim(), 80).unwrap();
    let mut header: Header = deserialize(&bytes).unwrap();
    header.merkle_root = TxMerkleNode::from_byte_array(tx.compute_txid().to_byte_array());

    let hex = bitcoin::consensus::encode::serialize_hex(&header);
    InclusionClaim {
        schema_version: 1,
        chain: EvidenceChain::Litecoin,
        network: EvidenceNetwork::Testnet,
        genesis_hash: LITECOIN_TESTNET_GENESIS.into(),
        block_height: 9_999_999,
        block_hash: header.block_hash().to_string(),
        block_header_hex: hex,
        txid: tx.compute_txid().to_string(),
        raw_transaction_hex: TX_HEX.trim().into(),
        tx_index: 0,
        transaction_count: 1,
        merkle_siblings: vec![],
    }
}

#[test]
fn litecoin_testnet_genesis_header_is_independently_anchored() {
    let raw = decode_hex_exact(GENESIS_HEADER.trim(), 80).unwrap();
    assert_eq!(raw.len(), 80);
    let header: Header = deserialize(&raw).unwrap();
    assert_eq!(header.block_hash().to_string(), LITECOIN_TESTNET_GENESIS);
}

#[test]
fn constructed_proof_is_internally_consistent() {
    let claim = synthetic_claim();
    let result = verify_litecoin_testnet_claim(&claim).unwrap();
    assert_eq!(result.txid.to_string(), claim.txid);
    assert_eq!(result.tx_index, 0);
    assert_eq!(result.op_return_outputs, vec![1]);
}

#[test]
fn rejects_a_different_genesis_or_network() {
    let mut claim = synthetic_claim();
    claim.genesis_hash = "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2".into();
    assert!(verify_litecoin_testnet_claim(&claim).is_err());

    assert!(serde_json::from_str::<InclusionClaim>(r#"{"network":"mainnet"}"#).is_err());
}

#[test]
fn rejects_transaction_and_merkle_tampering() {
    let mut claim = synthetic_claim();
    claim.txid = "0".repeat(64);
    assert!(verify_litecoin_testnet_claim(&claim).is_err());
    let mut claim = synthetic_claim();
    claim.block_hash = "0".repeat(64);
    assert!(verify_litecoin_testnet_claim(&claim).is_err());
    let mut claim = synthetic_claim();
    claim.tx_index = 1;
    assert!(verify_litecoin_testnet_claim(&claim).is_err());
    let mut claim = synthetic_claim();
    claim.transaction_count = 2;
    assert!(verify_litecoin_testnet_claim(&claim).is_err());
    let mut claim = synthetic_claim();
    claim.merkle_siblings.push("0".repeat(64));
    assert!(verify_litecoin_testnet_claim(&claim).is_err());
}

#[test]
fn rejects_invalid_transaction_bytes() {
    let mut claim = synthetic_claim();
    claim.raw_transaction_hex.push('g');
    assert!(verify_litecoin_testnet_claim(&claim).is_err());
    assert!(decode_hex_exact("abc", 10).is_err());
    assert!(decode_hex_exact("zz", 10).is_err());
    assert!(decode_hex_exact("ab", 0).is_err());
}


#[test]
fn evidence_observes_non_tradelayer_mainnet_transaction_only_as_synthetic() {
    let observation =
        rust_bitcoin_zk_adapter::evidence::observe_litecoin_testnet_claim(&synthetic_claim())
            .unwrap();
    assert_eq!(observation.outputs.len(), 1);
    assert_eq!(observation.outputs[0].vout, 1);
    assert_eq!(
        observation.outputs[0].strict,
        rust_bitcoin_zk_adapter::replay::StrictOutcome::Ignored
    );
    assert_eq!(
        observation.outputs[0].legacy,
        rust_bitcoin_zk_adapter::replay::LegacyOutcome::Ignored
    );
}

#[test]
fn synthetic_trade_layer_output_is_bound_to_merkle_inclusion() {
    use rust_bitcoin_zk_adapter::evidence::observe_litecoin_testnet_claim;
    use rust_bitcoin_zk_adapter::replay::{LegacyOutcome, StrictOutcome};
    let mut claim = synthetic_claim();
    let raw = decode_hex_exact(&claim.raw_transaction_hex, 4_000_000).unwrap();
    let mut tx: Transaction = deserialize(&raw).unwrap();
    tx.output[1].script_pubkey =
        bitcoin::ScriptBuf::from_bytes(vec![0x6a, 5, b't', b'l', b'2', b'0', b'z']);
    claim.raw_transaction_hex = bitcoin::consensus::encode::serialize_hex(&tx);
    claim.txid = tx.compute_txid().to_string();

    let header_bytes = decode_hex_exact(&claim.block_header_hex, 80).unwrap();
    let mut header: Header = deserialize(&header_bytes).unwrap();
    header.merkle_root = TxMerkleNode::from_byte_array(tx.compute_txid().to_byte_array());
    claim.block_hash = header.block_hash().to_string();
    claim.block_header_hex = bitcoin::consensus::encode::serialize_hex(&header);

    let output = observe_litecoin_testnet_claim(&claim).unwrap().outputs.remove(0);
    assert_eq!(
        output.strict,
        StrictOutcome::Envelope {
            tx_type: 2,
            body: "0z".to_owned(),
        }
    );
    assert_eq!(
        output.legacy,
        LegacyOutcome::Payload {
            payload: "20z".to_owned(),
        }
    );

    // The transaction cannot retain its old inclusion evidence after mutation.
    claim.txid = "00".repeat(32);
    assert!(observe_litecoin_testnet_claim(&claim).is_err());
}
