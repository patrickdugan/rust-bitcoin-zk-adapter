//! Bounded, protocol-neutral OP_RETURN pushdata extraction.
//!
//! Invalid scripts fail closed. These application limits are not consensus
//! rules, and reading pushed bytes cannot establish transaction validity.

use std::fmt;

/// Maximum output script bytes accepted by this application's decoder.
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
        }
    }
}
impl std::error::Error for DecodeError {}

/// Concatenate pushed bytes following OP_RETURN (OP_0 and PUSHDATA0/1/2/4).
/// Fails on non-push opcodes, truncation, or oversized inputs. A Bitcoin
/// consensus-valid OP_RETURN may contain opcodes rejected by this narrow
/// application decoder, so failure here only rejects payload extraction.
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
