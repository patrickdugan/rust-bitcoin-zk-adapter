use bitcoin::hashes::Hash;
use bitcoin::Txid;
use rust_bitcoin_zk_adapter::{
    commit_candidates, verify_native, Candidate, PublicInputs,
};

fn fixture() -> PublicInputs {
    PublicInputs {
        chain_id: 0,
        block_height: 840_000,
        block_hash: [1; 32],
        prior_state_root: [2; 32],
    }
}

fn candidate(value: u8) -> Candidate {
    Candidate {
        txid: Txid::from_byte_array([value; 32]),
        tx_index: value as u32,
        vout: 0,
        script: vec![0x6a, 0x01, value],
    }
}

#[test]
fn native_receipt_round_trip() {
    let inputs = fixture();
    let receipt = commit_candidates(&inputs, &[]);
    assert_eq!(receipt.candidate_count, 0);
    assert!(verify_native(&inputs, &[], &receipt));
}

#[test]
fn changing_public_inputs_invalidates_receipt() {
    let inputs = fixture();
    let receipt = commit_candidates(&inputs, &[]);
    let mut modified = inputs.clone();
    modified.block_height += 1;
    assert!(!verify_native(&modified, &[], &receipt));
}

#[test]
fn commitment_is_deterministic() {
    let inputs = fixture();
    assert_eq!(
        commit_candidates(&inputs, &[]),
        commit_candidates(&inputs, &[])
    );
}

#[test]
fn scripts_are_bound_to_receipt() {
    let inputs = fixture();
    let original = vec![candidate(42)];
    let receipt = commit_candidates(&inputs, &original);
    assert!(verify_native(&inputs, &original, &receipt));

    let mut altered = original;
    altered[0].script[2] ^= 1;
    assert!(!verify_native(&inputs, &altered, &receipt));
}

#[test]
fn candidate_order_changes_commitment() {
    let inputs = fixture();
    let original = vec![candidate(1), candidate(2)];
    let receipt = commit_candidates(&inputs, &original);
    let reversed = vec![candidate(2), candidate(1)];
    assert!(!verify_native(&inputs, &reversed, &receipt));
}
