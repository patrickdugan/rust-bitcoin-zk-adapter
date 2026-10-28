//! A Bitcoin payment-inclusion proof from the SP1 payment program, wrapped as
//! a Groth16 (BN254) proof so it is small enough to submit inline (709 bytes).
//!
//! Bundle (`BPG1`): b"BPG1" | 356-byte SP1 Groth16 proof | 349-byte statement.
//!
//! The statement is the payment program's public values (layout in
//! Raito-Scrypt `docs/LIGHTO_P1_PAYMENT.md`). Inside SP1 the payment program
//! verified a top node proof over the checkpointed header chain. The node,
//! leaf-aggregator and segment program identities it accepted are committed
//! in the statement, so the caller pins those words as well as the payment
//! program key.
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 4] = b"BPG1";
pub const PROOF_LEN: usize = 356;
pub const STATEMENT_LEN: usize = 349;
pub const BUNDLE_LEN: usize = 4 + PROOF_LEN + STATEMENT_LEN;
pub const DOMAIN_PREFIX: &[u8] = b"LIGHTO-BTC-PAYMENT-v1";
pub const STATEMENT: &str = "btc_payment_v1";
pub const VERIFIER: &str = "sp1-verifier 6.9.0 groth16 bn254";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payment {
    pub node_program_words: [u8; 32],
    pub leaf_program_words: [u8; 32],
    pub segment_program_words: [u8; 32],
    pub top_digest: [u8; 32],
    pub start_is_genesis: bool,
    pub tip_height: u32,
    /// Display (RPC) byte order, as are the other hashes below.
    pub tip_hash: String,
    /// Big-endian hex, 64 digits.
    pub tip_chainwork: String,
    pub block_height: u32,
    pub block_hash: String,
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub script_len: u32,
    pub script_sha256: String,
    pub confirmations: u32,
}

fn u32_at(v: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(v[at..at + 4].try_into().unwrap())
}

fn display(bytes: &[u8]) -> String {
    hex::encode(bytes.iter().rev().copied().collect::<Vec<u8>>())
}

fn word(v: &[u8], at: usize) -> [u8; 32] {
    v[at..at + 32].try_into().unwrap()
}

/// Decode the statement; rejects a wrong length, domain or flag byte.
pub fn parse_statement(v: &[u8]) -> Result<Payment, String> {
    if v.len() != STATEMENT_LEN {
        return Err("statement must be 349 bytes".into());
    }
    let mut domain = [0u8; 32];
    domain[..DOMAIN_PREFIX.len()].copy_from_slice(DOMAIN_PREFIX);
    if v[..32] != domain {
        return Err("not a LIGHTO-BTC-PAYMENT-v1 statement".into());
    }
    if v[160] > 1 {
        return Err("invalid genesis flag".into());
    }
    Ok(Payment {
        node_program_words: word(v, 32),
        leaf_program_words: word(v, 64),
        segment_program_words: word(v, 96),
        top_digest: word(v, 128),
        start_is_genesis: v[160] == 1,
        tip_height: u32_at(v, 161),
        tip_hash: display(&v[165..197]),
        tip_chainwork: display(&v[197..229]),
        block_height: u32_at(v, 229),
        block_hash: display(&v[233..265]),
        txid: display(&v[265..297]),
        vout: u32_at(v, 297),
        value_sats: u64::from_le_bytes(v[301..309].try_into().unwrap()),
        script_len: u32_at(v, 309),
        script_sha256: hex::encode(&v[313..345]),
        confirmations: u32_at(v, 345),
    })
}

pub fn pack(proof: &[u8], statement: &[u8]) -> Result<Vec<u8>, String> {
    if proof.len() != PROOF_LEN || statement.len() != STATEMENT_LEN {
        return Err("proof must be 356 bytes and statement 349 bytes".into());
    }
    Ok([MAGIC.as_slice(), proof, statement].concat())
}

/// Verify the Groth16 proof for `pay_vkey` (the payment program's bytes32
/// key, `0x`-prefixed) and return the receipt as JSON.
pub fn verify_bundle(bundle: &[u8], pay_vkey: &str) -> Result<String, String> {
    if bundle.len() != BUNDLE_LEN || &bundle[..4] != MAGIC {
        return Err("not a BPG1 bundle".into());
    }
    let (proof, statement) = bundle[4..].split_at(PROOF_LEN);
    let p = parse_statement(statement)?;
    if p.block_height > p.tip_height || p.confirmations != p.tip_height - p.block_height + 1 {
        return Err("statement confirmations disagree with its heights".into());
    }
    sp1_verifier::Groth16Verifier::verify(
        proof,
        statement,
        pay_vkey,
        &sp1_verifier::GROTH16_VK_BYTES,
    )
    .map_err(|e| format!("Groth16 verification failed: {e:?}"))?;
    let sha = |b: &[u8]| hex::encode(Sha256::digest(b));
    Ok(format!(
        concat!(
            "{{\"statement\":\"{}\",\"verifier\":\"{}\",\"groth16_vk_sha256\":\"{}\",\"pay_vkey\":\"{}\",",
            "\"node_program_words\":\"{}\",\"leaf_program_words\":\"{}\",\"segment_program_words\":\"{}\",",
            "\"proof_sha256\":\"{}\",\"statement_sha256\":\"{}\",\"start_is_genesis\":{},",
            "\"tip_height\":{},\"tip_hash\":\"{}\",\"tip_chainwork\":\"{}\",\"block_height\":{},\"block_hash\":\"{}\",",
            "\"txid\":\"{}\",\"vout\":{},\"value_sats\":{},\"script_sha256\":\"{}\",\"confirmations\":{},\"verified\":true}}"
        ),
        STATEMENT,
        VERIFIER,
        sha(&sp1_verifier::GROTH16_VK_BYTES),
        pay_vkey,
        hex::encode(p.node_program_words),
        hex::encode(p.leaf_program_words),
        hex::encode(p.segment_program_words),
        sha(bundle),
        sha(statement),
        p.start_is_genesis,
        p.tip_height,
        p.tip_hash,
        p.tip_chainwork,
        p.block_height,
        p.block_hash,
        p.txid,
        p.vout,
        p.value_sats,
        p.script_sha256,
        p.confirmations
    ))
}
