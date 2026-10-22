//! Framed, bounded gateway-to-worker IPC. Worker bytes are untrusted.
//! The socket's kernel peer credentials authenticate the other process;
//! only Raito's independent verifier can authenticate a proof statement.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VERSION: u8 = 1;
pub const MAX_HEADER_BYTES: usize = 4096;
pub const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
pub const TRANSFER_CHUNK_BYTES: usize = 64 * 1024;

pub fn hex_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRequest {
    pub version: u8,
    pub job_id: String,
    pub backend: String,
    pub network: String,
    pub block_hash: String,
    pub block_height: u64,
    pub policy_sha256: String,
    pub expected_txid: Option<String>,
    pub input_bytes: u64,
}

impl RunRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != VERSION
            || !hex_hash(&self.job_id)
            || self.backend != "raito"
            || !matches!(
                self.network.as_str(),
                "main" | "test" | "signet" | "regtest"
            )
            || !hex_hash(&self.block_hash)
            || !hex_hash(&self.policy_sha256)
            || self
                .expected_txid
                .as_deref()
                .is_none_or(|txid| !hex_hash(txid))
            || self.input_bytes == 0
            || self.input_bytes > MAX_INPUT_BYTES as u64
        {
            return Err("invalid or unsupported proof broker request".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunReply {
    pub version: u8,
    pub ok: bool,
    pub output_bytes: u64,
    pub result_sha256: Option<String>,
    pub error: Option<String>,
}

impl RunReply {
    pub fn accepted(&self) -> Result<(u64, &str), String> {
        if self.version != VERSION
            || !self.ok
            || !(1..=MAX_OUTPUT_BYTES).contains(&self.output_bytes)
            || self.error.is_some()
        {
            return Err("broker rejected worker or returned invalid output metadata".into());
        }
        let sha = self
            .result_sha256
            .as_deref()
            .ok_or("broker omitted output SHA-256")?;
        if !hex_hash(sha) {
            return Err("broker returned malformed output digest".into());
        }
        Ok((self.output_bytes, sha))
    }

    pub fn rejected(message: &str) -> Self {
        Self {
            version: VERSION,
            ok: false,
            output_bytes: 0,
            result_sha256: None,
            error: Some(message.chars().take(200).collect()),
        }
    }
}

/// JSON header followed by a single newline; raw bytes follow for transfers.
pub async fn write_header<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<(), String> {
    let body = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if body.len() > MAX_HEADER_BYTES {
        return Err("broker response or request header exceeds limit".into());
    }
    writer.write_all(&body).await.map_err(|e| e.to_string())?;
    writer.write_all(b"\n").await.map_err(|e| e.to_string())
}

pub async fn read_header<R: AsyncRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
) -> Result<T, String> {
    let mut body = Vec::new();
    loop {
        let byte = reader.read_u8().await.map_err(|e| e.to_string())?;
        if byte == b'\n' {
            break;
        }
        if body.len() >= MAX_HEADER_BYTES {
            return Err("proof broker header exceeds byte limit".into());
        }
        body.push(byte);
    }
    serde_json::from_slice(&body).map_err(|_| "invalid or unsupported broker JSON header".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn framing_roundtrip_and_strict_schema() {
        let request = RunRequest {
            version: VERSION,
            job_id: "ab".repeat(32),
            backend: "raito".into(),
            network: "main".into(),
            block_hash: "cd".repeat(32),
            block_height: 900000,
            policy_sha256: "ef".repeat(32),
            expected_txid: Some("12".repeat(32)),
            input_bytes: 5,
        };
        request.validate().unwrap();
        let (mut left, mut right) = tokio::io::duplex(8192);
        write_header(&mut left, &request).await.unwrap();
        let decoded: RunRequest = read_header(&mut right).await.unwrap();
        decoded.validate().unwrap();
        let mut json = serde_json::to_value(&request).unwrap();
        json["arbitrary_program"] = serde_json::json!("/tmp/injected");
        assert!(serde_json::from_value::<RunRequest>(json).is_err());
    }

    #[tokio::test]
    async fn rejects_large_frame_and_forged_verification_claim() {
        let (mut left, mut right) = tokio::io::duplex(8192);
        left.write_all(&vec![b'a'; MAX_HEADER_BYTES + 1])
            .await
            .unwrap();
        let response: Result<RunReply, _> = read_header(&mut right).await;
        assert!(response.is_err());
        let empty = RunReply::rejected("worker failed");
        assert!(empty.accepted().is_err());
        let fake = RunReply {
            version: VERSION,
            ok: true,
            output_bytes: 10,
            result_sha256: Some("ab".repeat(32)),
            error: None,
        };
        assert!(fake.accepted().is_ok());
        // Even a valid response is unverified and contains no boolean that
        // could be mistaken for Raito Cairo/STWO acceptance.
        let value = serde_json::to_value(fake).unwrap();
        assert!(value.get("proof_verified").is_none());
    }
}
