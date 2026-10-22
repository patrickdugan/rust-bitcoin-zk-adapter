//! Strict, bounded OP_RETURN parsing and syntax-only TradeLayer envelope decoding.
//!
//! This adjunct does not establish Bitcoin consensus, historical TradeLayer
//! compatibility, or the validity of any state transition.

use crate::Candidate;
use std::fmt;

/// Application parser guard, NOT a Bitcoin consensus or relay limit.
pub const MAX_SCRIPT_BYTES: usize = 100_000;
pub const MAX_PUSH_OPERATIONS: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    NotOpReturn,
    ScriptTooLarge,
    TooManyPushes,
    TruncatedLength,
    TruncatedData,
    UnsupportedOpcode(u8),
    DataTooLarge,
    MissingTransactionType,
    InvalidTransactionType(u8),
    NonPrintablePayload,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotOpReturn => write!(f, "script must start with OP_RETURN"),
            Self::ScriptTooLarge => write!(f, "script exceeds application length limit"),
            Self::TooManyPushes => write!(f, "too many push operations"),
            Self::TruncatedLength => write!(f, "incomplete PUSHDATA length field"),
            Self::TruncatedData => write!(f, "incomplete pushed data"),
            Self::UnsupportedOpcode(op) => write!(f, "opcode 0x{op:02x} is not a data push"),
            Self::DataTooLarge => write!(f, "extracted data exceeds application length limit"),
            Self::MissingTransactionType => {
                write!(f, "TradeLayer marker is missing transaction type")
            }
            Self::InvalidTransactionType(c) => {
                write!(f, "invalid base36 transaction type byte 0x{c:02x}")
            }
            Self::NonPrintablePayload => {
                write!(f, "TradeLayer envelope body contains non-printable bytes")
            }
        }
    }
}
impl std::error::Error for DecodeError {}

/// Concatenates all push data following an initial OP_RETURN.
///
/// Supports OP_0, direct pushes, OP_PUSHDATA1/2/4. Fails closed on all other
/// opcodes, truncated fields, excessive scripts or excessive push counts.
/// Non-minimal pushes are preserved, leaving policy to a later consensus layer.
pub fn decode_op_return(script: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if script.first() != Some(&0x6a) {
        return Err(DecodeError::NotOpReturn);
    }
    if script.len() > MAX_SCRIPT_BYTES {
        return Err(DecodeError::ScriptTooLarge);
    }
    let mut cursor = 1usize;
    let mut pushes = 0usize;
    let mut data = Vec::new();
    while cursor < script.len() {
        if pushes == MAX_PUSH_OPERATIONS {
            return Err(DecodeError::TooManyPushes);
        }
        pushes += 1;
        let op = script[cursor];
        cursor += 1;
        let len = match op {
            0x00 => 0,
            0x01..=0x4b => usize::from(op),
            0x4c => {
                let length = *script.get(cursor).ok_or(DecodeError::TruncatedLength)?;
                cursor += 1;
                usize::from(length)
            }
            0x4d => {
                let b = script
                    .get(cursor..cursor + 2)
                    .ok_or(DecodeError::TruncatedLength)?;
                cursor += 2;
                usize::from(u16::from_le_bytes([b[0], b[1]]))
            }
            0x4e => {
                let b = script
                    .get(cursor..cursor + 4)
                    .ok_or(DecodeError::TruncatedLength)?;
                cursor += 4;
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
            }
            _ => return Err(DecodeError::UnsupportedOpcode(op)),
        };
        if len > MAX_SCRIPT_BYTES - data.len() {
            return Err(DecodeError::DataTooLarge);
        }
        let end = cursor.checked_add(len).ok_or(DecodeError::TruncatedData)?;
        let pushed = script.get(cursor..end).ok_or(DecodeError::TruncatedData)?;
        data.extend_from_slice(pushed);
        cursor = end;
    }
    Ok(data)
}

/// Pure syntax; every transaction-specific field in body is still opaque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TradeLayerEnvelope {
    pub tx_type: u8,
    pub body: String,
}

/// Recognizes exactly lowercase ASCII "tl" followed by one base36 type byte.
/// Returns None for other protocols, Err for malformed tl-prefixed payloads.
pub fn decode_tradelayer_envelope(data: &[u8]) -> Result<Option<TradeLayerEnvelope>, DecodeError> {
    if !data.starts_with(b"tl") {
        return Ok(None);
    }
    let type_byte = *data.get(2).ok_or(DecodeError::MissingTransactionType)?;
    let tx_type = match type_byte {
        b'0'..=b'9' => type_byte - b'0',
        b'a'..=b'z' => type_byte - b'a' + 10,
        _ => return Err(DecodeError::InvalidTransactionType(type_byte)),
    };
    let body = &data[3..];
    if !body.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
        return Err(DecodeError::NonPrintablePayload);
    }
    let body = String::from_utf8(body.to_vec()).map_err(|_| DecodeError::NonPrintablePayload)?;
    Ok(Some(TradeLayerEnvelope { tx_type, body }))
}

/// Decode a candidate extracted from a transaction or block.
/// Does not validate balances, senders, activation heights, or settlements.
pub fn decode_candidate(candidate: &Candidate) -> Result<Option<TradeLayerEnvelope>, DecodeError> {
    let data = decode_op_return(&candidate.script)?;
    decode_tradelayer_envelope(&data)
}
