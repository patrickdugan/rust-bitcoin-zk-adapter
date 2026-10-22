//! Test-only observation of historical TradeLayer.js txIndex.js.
use crate::op_return::MAX_SCRIPT_BYTES;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Replays the legacy ASCII marker search over serialized OP_RETURN script hex.
/// This is an observation helper, not a consensus parser.
pub fn legacy_txindex_payload(script: &[u8]) -> Option<String> {
    if script.first() != Some(&0x6a) || script.len() > MAX_SCRIPT_BYTES {
        return None;
    }
    let mut hex = String::with_capacity(script.len() * 2);
    for &byte in script {
        hex.push(char::from(HEX[usize::from(byte >> 4)]));
        hex.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    let position = hex.find("746c")?;
    if position > 6 {
        return None;
    }
    let start = if hex.get(4..8) == Some("746c") {
        8
    } else if hex.get(5..9) == Some("746c") {
        9
    } else if hex.get(6..10) == Some("746c") {
        10
    } else {
        position + 4
    };
    let payload_hex = hex.get(start..)?;
    let data = payload_hex.as_bytes();
    let mut decoded = Vec::with_capacity(data.len() / 2);
    for index in (0..data.len().saturating_sub(1)).step_by(2) {
        let upper = char::from(data[index]).to_digit(16)? as u8;
        let lower = char::from(data[index + 1]).to_digit(16)? as u8;
        let byte = (upper << 4) | lower;
        if !(0x20..=0x7e).contains(&byte) {
            return None;
        }
        decoded.push(byte);
    }
    String::from_utf8(decoded).ok()
}
