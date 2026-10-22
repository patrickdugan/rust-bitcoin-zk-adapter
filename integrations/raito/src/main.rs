//! Offline Raito verifier and machine-readable gateway verifier.
use bitcoin::{
    hashes::{sha256, Hash},
    BlockHash, Txid,
};
use raito_spv_verify::VerifierConfig;
use rust_bitcoin_raito_sidecar::verify_raito_proof;
use std::{
    env,
    error::Error,
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    str::FromStr,
};

const VERIFIER_ID: &str = "raito-spv-verify/48c237ac941d8061a857ecd111d7e81107912556";
const STATEMENT: &str = "raito_spv_transaction_inclusion_v1";

/// Machine mode is invoked only by an operator-configured gateway. Its
/// report is emitted after real Cairo/STWO verification with dev=false.
async fn gateway(args: &mut impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    let path = PathBuf::from(args.next().ok_or("missing proof path")?);
    let expected_txid = Txid::from_str(&args.next().ok_or("missing TXID")?)?;
    let expected_block_hash = BlockHash::from_str(&args.next().ok_or("missing block hash")?)?;
    let expected_height: u32 = args.next().ok_or("missing block height")?.parse()?;
    let submitted_policy = args.next().ok_or("missing policy SHA-256")?;
    let receipt_path = PathBuf::from(args.next().ok_or("missing receipt path")?);
    if args.next().is_some() {
        return Err("unexpected gateway verifier argument".into());
    }

    // The policy digest binds all default verifier settings, including
    // bootloader/task program hashes and the minimum cumulative-work bound.
    // A job's user-provided policy hash is never sufficient by itself.
    let config = VerifierConfig::default();
    let policy_sha256 = sha256::Hash::hash(&serde_json::to_vec(&config)?).to_string();
    if submitted_policy != policy_sha256 {
        return Err("submitted policy differs from the pinned Raito configuration".into());
    }

    let checked = verify_raito_proof(&path, expected_txid, expected_height, &config).await?;
    if checked.block_hash() != expected_block_hash || checked.block_height() != expected_height {
        return Err("verified transaction belongs to a different Bitcoin block".into());
    }
    let receipt = serde_json::json!({
        "statement": STATEMENT,
        "verifier": VERIFIER_ID,
        "txid": checked.txid().to_string(),
        "block_hash": checked.block_hash().to_string(),
        "block_height": checked.block_height(),
        "proven_tip_height": checked.proven_tip_height(),
        "tx_index": checked.tx_index(),
        "proof_sha256": checked.proof_sha256(),
        "policy_sha256": policy_sha256
    });
    let mut out = OpenOptions::new().write(true).create_new(true).open(receipt_path)?;
    out.write_all(&serde_json::to_vec(&receipt)?)?;
    out.sync_all()?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let first = args.next().ok_or(
        "usage: raito-verify PROOF_FILE EXPECTED_TXID MIN_PROVEN_HEIGHT; or --gateway PROOF_FILE EXPECTED_TXID BLOCKHASH BLOCKHEIGHT POLICY_SHA256 RECEIPT",
    )?;
    if first == "--gateway" {
        return gateway(&mut args).await;
    }

    let path = PathBuf::from(first);
    let expected = Txid::from_str(&args.next().ok_or("missing expected txid")?)?;
    let minimum: u32 = args
        .next()
        .ok_or("missing minimum proven chain height")?
        .parse()?;
    if args.next().is_some() {
        return Err("unexpected extra argument".into());
    }
    let config = VerifierConfig::default();
    let checked = verify_raito_proof(&path, expected, minimum, &config).await?;
    println!("Raito proof checked for {}", checked.txid());
    println!("block hash: {}", checked.block_hash());
    println!("block height: {}", checked.block_height());
    println!("proven chain height: {}", checked.proven_tip_height());
    println!("transaction position: {}", checked.tx_index());
    println!("proof sha256: {}", checked.proof_sha256());
    println!("OP_RETURN outputs: {}", checked.candidates().len());
    Ok(())
}
