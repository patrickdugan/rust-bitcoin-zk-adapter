//! Offline proof verification against a caller-selected TXID and height floor.
use bitcoin::Txid;
use raito_spv_verify::VerifierConfig;
use rust_bitcoin_raito_sidecar::verify_raito_proof;
use std::{env, error::Error, path::PathBuf, str::FromStr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let path = PathBuf::from(
        args.next()
            .ok_or("usage: raito-verify PROOF_FILE EXPECTED_TXID MIN_PROVEN_HEIGHT")?,
    );
    let expected = Txid::from_str(&args.next().ok_or("missing expected txid")?)?;
    let minimum: u32 = args
        .next()
        .ok_or("missing minimum proven chain height")?
        .parse()?;
    if args.next().is_some() {
        return Err("unexpected extra argument".into());
    }

    // Inspect this upstream default policy carefully before production use.
    let config = VerifierConfig::default();
    let checked = verify_raito_proof(&path, expected, minimum, &config).await?;
    println!("Raito proof checked for {}", checked.txid());
    println!("block hash: {}", checked.block_hash());
    println!("block height: {}", checked.block_height());
    println!("proven chain height: {}", checked.proven_tip_height());
    println!("transaction position: {}", checked.tx_index());
    println!("OP_RETURN outputs: {}", checked.candidates().len());
    Ok(())
}
