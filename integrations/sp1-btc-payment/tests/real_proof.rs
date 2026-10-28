//! The real mainnet payment proof (tx fd2fdd44, output 0, block 959,984, tip
//! 959,994) from the SP1 demo run, wrapped to Groth16 by `pay-wrap`.
use sp1_btc_payment::{pack, parse_statement, verify_bundle};

const PAY_VKEY: &str = "0x00de861a80542b3089fed26b37ac4e1f4bb8664dcddadb3a6de5ae7205751e75";

fn hex_fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name);
    hex::decode(std::fs::read_to_string(path).unwrap().trim()).unwrap()
}

fn bundle() -> Vec<u8> {
    pack(
        &hex_fixture("groth16.proof.hex"),
        &hex_fixture("public_values.hex"),
    )
    .unwrap()
}

#[test]
fn real_payment_proof_verifies() {
    let receipt = verify_bundle(&bundle(), PAY_VKEY).unwrap();
    for want in [
        "\"statement\":\"btc_payment_v1\"",
        "\"tip_height\":959994",
        "\"tip_hash\":\"00000000000000000000cf210e0b55fa90e51720f52df6fed15f9909388d79b5\"",
        "\"block_height\":959984",
        "\"block_hash\":\"000000000000000000000b99348eebd2f4863aa49a0d2fb2203c549e7b16372b\"",
        "\"txid\":\"fd2fdd448e15a74e661b7b058bf7ffba0a1a575aca7da75d1358a2c31217daa6\"",
        "\"vout\":0",
        "\"value_sats\":2010000",
        "\"confirmations\":11",
        "\"tip_chainwork\":\"00000000000000000000000000000000000000013b1e621775d64a9ec241fdcd\"",
        "\"verified\":true",
    ] {
        assert!(receipt.contains(want), "missing {want} in {receipt}");
    }
}

#[test]
fn every_statement_field_and_the_proof_are_bound() {
    let good = bundle();
    let s = 4 + 356;
    // proof body; node words; top digest; tip height; tip hash; block height;
    // txid; value; script hash; confirmations (kept consistent below)
    for at in [
        14,
        s + 40,
        s + 140,
        s + 166,
        s + 230,
        s + 270,
        s + 302,
        s + 320,
    ] {
        let mut bad = good.clone();
        bad[at] ^= 1;
        assert!(
            verify_bundle(&bad, PAY_VKEY).is_err(),
            "byte {at} not bound"
        );
    }
    let other_key = format!("0x01{}", &PAY_VKEY[4..]);
    assert!(verify_bundle(&good, &other_key).is_err());
    assert!(verify_bundle(&good[..good.len() - 1], PAY_VKEY).is_err());
}

#[test]
fn inconsistent_confirmations_are_rejected_before_pairing() {
    let mut bad = bundle();
    bad[4 + 356 + 345] ^= 1;
    let err = verify_bundle(&bad, PAY_VKEY).unwrap_err();
    assert!(err.contains("confirmations"), "{err}");
}

#[test]
fn statement_parser_rejects_other_domains() {
    let mut st = hex_fixture("public_values.hex");
    assert_eq!(parse_statement(&st).unwrap().vout, 0);
    st[0] = b'X';
    assert!(parse_statement(&st).is_err());
}
