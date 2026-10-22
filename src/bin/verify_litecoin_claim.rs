//! Offline Litecoin testnet inclusion-claim consistency verifier.
//! Canonical-chain authority still comes from a trusted Litecoin Core node.

use rust_bitcoin_zk_adapter::evidence::{observe_litecoin_testnet_claim, InclusionClaim};
use std::{env, error::Error, fs};

const MAX_MANIFEST_BYTES: u64 = 8_500_000;

fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: verify_litecoin_claim PATH_TO_JSON")?;
    if fs::metadata(&path)?.len() > MAX_MANIFEST_BYTES {
        return Err("claim manifest exceeds size limit".into());
    }
    let claim: InclusionClaim = serde_json::from_str(&fs::read_to_string(path)?)?;
    let observation = observe_litecoin_testnet_claim(&claim)?;
    let result = observation.binding;
    println!("claim self-consistency: OK (canonical chain status unverified)");
    println!("Litecoin testnet txid: {}", result.txid);
    println!(
        "Supplied block: {} at height {}",
        result.block_hash, result.block_height
    );
    println!("Transaction index: {}", result.tx_index);
    println!("OP_RETURN vouts: {:?}", result.op_return_outputs);
    for output in observation.outputs {
        println!("  vout {} strict: {:?}", output.vout, output.strict);
        println!("  vout {} legacy: {:?}", output.vout, output.legacy);
    }
    Ok(())
}
