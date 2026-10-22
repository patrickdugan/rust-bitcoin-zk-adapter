//! Offline raw-transaction inspector. No network calls or signing.
use bitcoin::consensus::deserialize;
use bitcoin::Transaction;
use rust_bitcoin_zk_adapter::op_return::{decode_op_return, decode_tradelayer_envelope};
use std::{env, error::Error, fs, io};

const MAX_INPUT_HEX_BYTES: u64 = 8_000_000;
fn parse_hex(source: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let hex: String = source
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if !hex.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    hex.as_bytes()
        .as_chunks::<2>().0.iter()
        .map(|chunk| {
            let ascii = std::str::from_utf8(chunk)?;
            Ok(u8::from_str_radix(ascii, 16)?)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()
}
fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: inspect_tx PATH_TO_RAW_TX_HEX")?;
    if fs::metadata(&path)?.len() > MAX_INPUT_HEX_BYTES {
        return Err("transaction hex file exceeds inspection size limit".into());
    }
    let raw = parse_hex(&fs::read_to_string(path)?)?;
    let tx: Transaction = deserialize(&raw)?;
    println!("txid: {}", tx.compute_txid());
    let mut found = 0;
    for (vout, output) in tx.output.iter().enumerate() {
        if output.script_pubkey.is_op_return() {
            found += 1;
            let data = decode_op_return(output.script_pubkey.as_bytes())?;
            println!("  vout {vout}: OP_RETURN, {} payload bytes", data.len());
            match decode_tradelayer_envelope(&data)? {
                Some(tl) => println!(
                    "    TradeLayer syntax: type={}, body={:?}",
                    tl.tx_type, tl.body
                ),
                None => println!("    different or unknown protocol"),
            }
        }
    }
    if found == 0 {
        return Err(io::Error::other("transaction has no OP_RETURN outputs").into());
    }
    Ok(())
}
