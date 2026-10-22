//! Offline Bitcoin transaction inspector. Never accesses the network.
use bitcoin::consensus::deserialize;
use bitcoin::Transaction;
use rust_bitcoin_zk_adapter::op_return::decode_op_return;
use std::{env, error::Error, fs};

const MAX_HEX_FILE_BYTES: u64 = 8_000_000;
fn parse_hex(source: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let hex: String = source
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if !hex.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| {
            let ascii = std::str::from_utf8(chunk)?;
            Ok(u8::from_str_radix(ascii, 16)?)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()
}
fn hex_preview(bytes: &[u8], limit: usize) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut preview = String::with_capacity(bytes.len().min(limit) * 2);
    for &byte in bytes.iter().take(limit) {
        preview.push(char::from(DIGITS[usize::from(byte >> 4)]));
        preview.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    preview
}
fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: inspect_tx PATH_TO_RAW_TX_HEX")?;
    if fs::metadata(&path)?.len() > MAX_HEX_FILE_BYTES {
        return Err("transaction hex file exceeds inspection size limit".into());
    }
    let raw = parse_hex(&fs::read_to_string(path)?)?;
    let tx: Transaction = deserialize(&raw)?;
    println!("txid: {}", tx.compute_txid());
    let mut count = 0usize;
    for (vout, output) in tx.output.iter().enumerate() {
        if output.script_pubkey.is_op_return() {
            count += 1;
            let bytes = decode_op_return(output.script_pubkey.as_bytes())?;
            println!("vout {vout}: OP_RETURN {} payload bytes", bytes.len());
            println!("  hex (first 32 bytes): {}", hex_preview(&bytes, 32));
        }
    }
    println!("OP_RETURN outputs: {count}");
    Ok(())
}
