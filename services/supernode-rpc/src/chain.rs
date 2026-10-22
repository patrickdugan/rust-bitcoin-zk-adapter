//! Bitcoin Core \`sequence\` ZMQ messages and conservative chain tracking.
//!
//! The subscriber is an invalidation signal, never a consensus oracle.
//! Missing transport frames, reconnects and block notifications mark the
//! local view dirty until reconciled against Bitcoin Core JSON-RPC.

use crate::CoreRpc;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use zeromq::{Socket, SocketRecv, SubSocket};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SequenceKind {
    BlockConnected,
    BlockDisconnected,
    MempoolAdded(u64),
    MempoolRemoved(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceEvent {
    pub hash: String,
    pub sequence: u32,
    pub kind: SequenceKind,
}

/// The last four bytes are the *ZMQ transport* sequence counter, separate
/// from the 8-byte mempool sequence number carried by A/R messages.
pub fn parse_sequence_frames(frames: &[&[u8]]) -> Result<SequenceEvent, &'static str> {
    if frames.len() != 3 || frames[0] != b"sequence" || frames[2].len() != 4 {
        return Err("expected Bitcoin Core sequence triplet");
    }
    let body = frames[1];
    if !matches!(body.len(), 33 | 41) {
        return Err("invalid sequence message length");
    }
    let kind = match (body[32], body.len()) {
        (b'C', 33) => SequenceKind::BlockConnected,
        (b'D', 33) => SequenceKind::BlockDisconnected,
        (b'A', 41) => SequenceKind::MempoolAdded(u64::from_le_bytes(
            body[33..41]
                .try_into()
                .map_err(|_| "short mempool sequence")?,
        )),
        (b'R', 41) => SequenceKind::MempoolRemoved(u64::from_le_bytes(
            body[33..41]
                .try_into()
                .map_err(|_| "short mempool sequence")?,
        )),
        _ => return Err("unknown sequence event"),
    };
    let hash = hex::encode(body[..32].iter().rev().copied().collect::<Vec<_>>());
    let sequence = u32::from_le_bytes(
        frames[2]
            .try_into()
            .map_err(|_| "invalid sequence counter")?,
    );
    Ok(SequenceEvent {
        hash,
        sequence,
        kind,
    })
}

#[derive(Debug)]
struct ChainState {
    epoch: u64,
    last_sequence: Option<u32>,
    tip_hash: Option<String>,
    tip_height: Option<u64>,
    dirty: bool,
    connected: bool,
    lost_messages: u64,
    block_events: u64,
    mempool_events: u64,
    reconnects: u64,
}

#[derive(Debug)]
pub struct ChainTracker {
    inner: Mutex<ChainState>,
    enabled: bool,
}

impl ChainTracker {
    pub fn new(enabled: bool) -> Self {
        Self {
            inner: Mutex::new(ChainState {
                epoch: 0,
                last_sequence: None,
                tip_hash: None,
                tip_height: None,
                dirty: true,
                connected: false,
                lost_messages: 0,
                block_events: 0,
                mempool_events: 0,
                reconnects: 0,
            }),
            enabled,
        }
    }

    pub async fn reconnect(&self) {
        let mut state = self.inner.lock().await;
        state.epoch = state.epoch.wrapping_add(1);
        state.dirty = true;
        state.last_sequence = None;
        state.connected = false;
        state.reconnects += 1;
    }

    pub async fn set_connected(&self) {
        let mut state = self.inner.lock().await;
        state.connected = true;
        state.dirty = true;
    }

    pub async fn record(&self, event: SequenceEvent) {
        let mut state = self.inner.lock().await;
        if let Some(last) = state.last_sequence {
            if last.wrapping_add(1) != event.sequence {
                state.lost_messages += 1;
                state.epoch = state.epoch.wrapping_add(1);
                state.dirty = true;
            }
        }
        state.last_sequence = Some(event.sequence);
        match event.kind {
            SequenceKind::BlockConnected | SequenceKind::BlockDisconnected => {
                state.epoch = state.epoch.wrapping_add(1);
                state.block_events += 1;
                state.dirty = true;
            }
            SequenceKind::MempoolAdded(_) | SequenceKind::MempoolRemoved(_) => {
                state.mempool_events += 1;
            }
        }
    }

    pub async fn epoch(&self) -> u64 {
        self.inner.lock().await.epoch
    }

    pub async fn is_fresh(&self) -> bool {
        let state = self.inner.lock().await;
        !state.dirty && (!self.enabled || state.connected)
    }

    /// Refresh validated chain state. If ZMQ events arrive during the two
    /// Core reads, leave the view dirty and let the next request retry.
    pub async fn reconcile(&self, core: &CoreRpc) -> Result<Value, String> {
        let prior = self.epoch().await;
        let info = core
            .call("getblockchaininfo", json!([]))
            .await
            .map_err(|err| err.message)?;
        let hash = core
            .call("getbestblockhash", json!([]))
            .await
            .map_err(|err| err.message)?;
        let height = info
            .get("blocks")
            .and_then(Value::as_u64)
            .ok_or("Core chain height missing")?;
        let hash = hash.as_str().ok_or("Core best block hash missing")?;
        let mut state = self.inner.lock().await;
        if state.epoch == prior {
            state.tip_hash = Some(hash.to_owned());
            state.tip_height = Some(height);
            // No ZMQ means a snapshot is useful, but should not be treated
            // as a long-lived cache freshness assertion.
            state.dirty = self.enabled && !state.connected;
        }
        Ok(Self::render(&state, self.enabled))
    }

    fn render(state: &ChainState, enabled: bool) -> Value {
        json!({
            "epoch":state.epoch,
            "dirty":state.dirty,
            "sequence_zmq_enabled":enabled,
            "sequence_connected":state.connected,
            "last_transport_sequence":state.last_sequence,
            "tip_hash_at_reconciliation":state.tip_hash,
            "tip_height_at_reconciliation":state.tip_height,
            "missed_or_out_of_order_frames":state.lost_messages,
            "block_events":state.block_events,
            "mempool_events":state.mempool_events,
            "reconnects":state.reconnects,
            "note":"Bitcoin Core is authoritative; a ZMQ stream can drop events"
        })
    }

    pub async fn snapshot(&self) -> Value {
        let state = self.inner.lock().await;
        Self::render(&state, self.enabled)
    }
}

/// Only trusted local publishers may be used. Bitcoin Core's PUB socket is
/// unauthenticated, and a remote attacker could trigger cache invalidation.
pub fn validate_local_sequence_endpoint(url: &str) -> Result<(), String> {
    let address = url
        .strip_prefix("tcp://")
        .ok_or("ZMQ sequence subscriber currently supports tcp:// only")?;
    let (host, port) = address
        .rsplit_once(':')
        .ok_or("ZMQ sequence publisher port missing")?;
    if !matches!(host, "localhost" | "127.0.0.1" | "[::1]")
        || port.parse::<u16>().ok().filter(|port| *port > 0).is_none()
    {
        return Err("ZMQ publisher must use a loopback TCP host and valid port".into());
    }
    Ok(())
}

/// Reconnect indefinitely while running. The gateway does not trust events
/// following a disconnect until it queries Bitcoin Core again.
pub async fn run_sequence_subscriber(endpoint: String, tracker: Arc<ChainTracker>, core: CoreRpc) {
    if validate_local_sequence_endpoint(&endpoint).is_err() {
        tracker.reconnect().await;
        eprintln!("Bitcoin Core ZMQ sequence endpoint rejected");
        return;
    }
    loop {
        let mut socket = SubSocket::new();
        let status = async {
            socket.connect(&endpoint).await?;
            socket.subscribe("sequence").await?;
            Ok::<(), zeromq::ZmqError>(())
        }
        .await;
        if let Err(error) = status {
            eprintln!("Bitcoin Core sequence ZMQ connection failed: {error}");
            tracker.reconnect().await;
            sleep(Duration::from_secs(3)).await;
            continue;
        }
        tracker.set_connected().await;
        let _ = tracker.reconcile(&core).await;
        loop {
            let message = match socket.recv().await {
                Ok(message) => message,
                Err(error) => {
                    eprintln!("Bitcoin Core ZMQ sequence stream interrupted: {error}");
                    break;
                }
            };
            let frames = message
                .iter()
                .map(|frame| frame.as_ref())
                .collect::<Vec<_>>();
            match parse_sequence_frames(&frames) {
                Ok(event) => {
                    let changed = matches!(
                        event.kind,
                        SequenceKind::BlockConnected | SequenceKind::BlockDisconnected
                    );
                    tracker.record(event).await;
                    if changed {
                        let _ = tracker.reconcile(&core).await;
                    }
                }
                Err(error) => {
                    eprintln!("Bitcoin Core sequence message invalid: {error}");
                    // Malformed frames must not create false freshness.
                    tracker.reconnect().await;
                    break;
                }
            }
        }
        tracker.reconnect().await;
        sleep(Duration::from_secs(3)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(code: u8, seq: u32, mempool: Option<u64>) -> Vec<Vec<u8>> {
        let mut body = vec![0x11; 32];
        body.push(code);
        if let Some(sequence) = mempool {
            body.extend(sequence.to_le_bytes());
        }
        vec![b"sequence".to_vec(), body, seq.to_le_bytes().to_vec()]
    }

    #[test]
    fn bitcoin_core_wire_frames_are_strict() {
        let frames = msg(b'C', 7, None);
        let refs = frames.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let event = parse_sequence_frames(&refs).unwrap();
        assert_eq!(event.sequence, 7);
        assert_eq!(event.hash, "11".repeat(32));
        assert_eq!(event.kind, SequenceKind::BlockConnected);

        let frames = msg(b'A', 8, Some(1234));
        let refs = frames.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let event = parse_sequence_frames(&refs).unwrap();
        assert_eq!(event.kind, SequenceKind::MempoolAdded(1234));
        let bad = msg(b'A', 1, None);
        let refs = bad.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert!(parse_sequence_frames(&refs).is_err());
    }

    #[tokio::test]
    async fn gaps_reorgs_and_reconnects_invalidate_snapshot() {
        let tracker = ChainTracker::new(true);
        tracker.set_connected().await;
        tracker
            .record(SequenceEvent {
                hash: "11".repeat(32),
                sequence: 10,
                kind: SequenceKind::MempoolAdded(2),
            })
            .await;
        assert_eq!(tracker.epoch().await, 0);
        tracker
            .record(SequenceEvent {
                hash: "22".repeat(32),
                sequence: 12,
                kind: SequenceKind::BlockDisconnected,
            })
            .await;
        let status = tracker.snapshot().await;
        assert_eq!(status["missed_or_out_of_order_frames"], 1);
        assert_eq!(status["block_events"], 1);
        assert_eq!(status["dirty"], true);
        let epoch = tracker.epoch().await;
        tracker.reconnect().await;
        assert!(tracker.epoch().await > epoch);
        assert_eq!(tracker.snapshot().await["sequence_connected"], false);
    }

    #[test]
    fn pub_socket_must_be_local() {
        assert!(validate_local_sequence_endpoint("tcp://127.0.0.1:28333").is_ok());
        assert!(validate_local_sequence_endpoint("tcp://[::1]:28333").is_ok());
        assert!(validate_local_sequence_endpoint("tcp://0.0.0.0:28333").is_err());
        assert!(validate_local_sequence_endpoint("tcp://8.8.8.8:28333").is_err());
    }
}
