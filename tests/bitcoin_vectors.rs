use bitcoin::consensus::deserialize;
use bitcoin::Transaction;
use rust_bitcoin_zk_adapter::op_return::{decode_op_return, decode_tradelayer_envelope};

fn hex_bytes(source: &str) -> Vec<u8> {
    let hex: String = source
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn bitcoin_mainnet_real_tx_matches_txid_and_script() {
    // On-chain block 900044, original 275-byte raw transaction.
    let raw = hex_bytes(include_str!(
        "../fixtures/mainnet/2033435de7ce307341231e818ed937cd3a5e8597381fd83a7e5b0234f61b38d3.hex"
    ));
    assert_eq!(raw.len(), 275);
    let tx: Transaction = deserialize(&raw).unwrap();
    assert_eq!(
        tx.compute_txid().to_string(),
        "2033435de7ce307341231e818ed937cd3a5e8597381fd83a7e5b0234f61b38d3"
    );
    assert_eq!(tx.output.len(), 2);
    assert!(tx.output[1].script_pubkey.is_op_return());
    assert_eq!(tx.output[1].value.to_sat(), 0);
    let data = decode_op_return(tx.output[1].script_pubkey.as_bytes()).unwrap();
    assert_eq!(data.len(), 75);
    assert!(data.iter().take(60).all(|byte| *byte == 0));
    assert_eq!(&data[60..], b"learnmeabitcoin");
    assert_eq!(decode_tradelayer_envelope(&data).unwrap(), None);
}
#[test]
fn bitcoin_core_regtest_segwit_example() {
    // Published Bitcoin Core decoderawtransaction example (regtest, NOT mainnet).
    let raw = hex_bytes(include_str!(
        "../fixtures/regtest/00fddd900b735a88ab0ef5eeaa3efbc869d4e52493da8a9467ec782355cb39ff.hex"
    ));
    assert_eq!(raw.len(), 246);
    let tx: Transaction = deserialize(&raw).unwrap();
    assert_eq!(
        tx.compute_txid().to_string(),
        "00fddd900b735a88ab0ef5eeaa3efbc869d4e52493da8a9467ec782355cb39ff"
    );
    let data = decode_op_return(tx.output[0].script_pubkey.as_bytes()).unwrap();
    assert_eq!(data.len(), 73);
    assert!(data.starts_with(b"Europe is tired"));
    assert_eq!(decode_tradelayer_envelope(&data).unwrap(), None);
}
#[test]
fn real_mainnet_scripts_cover_direct_and_pushdata1() {
    let direct = hex_bytes(include_str!("../fixtures/mainnet/b6abffe30b0edef88c796d0a21118046874b55c9c3b98adfb17aa6d9699e679d-vout2.script.hex"));
    assert_eq!(
        decode_op_return(&direct).unwrap(),
        b"I cant see u but I still love you lili"
    );
    let pd1 = hex_bytes(include_str!("../fixtures/mainnet/c89bebdcaf9ee70d0dbb5d8e5e94349ff4446a396097716cb1bdd4ccd29f7208.script.hex"));
    assert_eq!(&pd1[..3], &[0x6a, 0x4c, 0x50]);
    assert_eq!(decode_op_return(&pd1).unwrap().len(), 80);
}
