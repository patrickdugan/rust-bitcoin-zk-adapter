//! Read-only Bitcoin Core RPC superset for proof preparation.
//!
//! Bitcoin Core remains authoritative for chain validation. This gateway
//! locally verifies TXIDs, block-header hashes and transaction Merkle proofs.
//! Neither these checks nor proxying Bitcoin Core RPC creates a STARK proof.

use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use bitcoin::consensus::deserialize;
use bitcoin::{block::Header, BlockHash, MerkleBlock, Transaction, Txid};
use reqwest::{redirect, Client, Url};
use serde_json::{json, Value};
use std::{str::FromStr, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
pub mod cache;
pub mod chain;
pub mod jobs;
pub mod verification;

pub const MAX_RPC_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_RPC_RESPONSE_BYTES: usize = 24 * 1024 * 1024;
pub const MAX_INFLIGHT_REQUESTS: usize = 8;

#[derive(Debug, Clone)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}
impl RpcError {
    fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Clone)]
pub struct CoreRpc {
    client: Client,
    url: Url,
    username: String,
    password: String,
}

impl CoreRpc {
    pub fn new(url: &str, username: String, password: String) -> Result<Self, String> {
        let url = Url::parse(url).map_err(|error| format!("invalid RPC URL: {error}"))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(
                "Bitcoin RPC URL must be HTTP(S) with credentials supplied separately".into(),
            );
        }
        // Sidecar and Core should share a trust boundary. Remote Core can be
        // enabled in a future release using a secure explicit transport policy.
        if !matches!(url.host_str(), Some("127.0.0.1" | "::1" | "localhost")) {
            return Err("Bitcoin RPC endpoint must be loopback".into());
        }
        let client = Client::builder()
            .no_proxy()
            .redirect(redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| format!("RPC HTTP client: {error}"))?;
        Ok(Self {
            client,
            url,
            username,
            password,
        })
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let request = json!({
            "jsonrpc": "1.0",
            "id": "supernode",
            "method": method,
            "params": params
        });
        let mut response = self
            .client
            .post(self.url.clone())
            .basic_auth(&self.username, Some(&self.password))
            .json(&request)
            .send()
            .await
            .map_err(|error| {
                RpcError::new(-32010, format!("Bitcoin Core request failed: {error}"))
            })?;

        if let Some(length) = response.content_length() {
            if length > MAX_RPC_RESPONSE_BYTES as u64 {
                return Err(RpcError::new(
                    -32011,
                    "Bitcoin Core response exceeds size cap",
                ));
            }
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|error| {
            RpcError::new(-32010, format!("Bitcoin Core response failed: {error}"))
        })? {
            if chunk.len() > MAX_RPC_RESPONSE_BYTES.saturating_sub(body.len()) {
                return Err(RpcError::new(
                    -32011,
                    "Bitcoin Core response exceeds size cap",
                ));
            }
            body.extend_from_slice(&chunk);
        }

        let reply: Value = serde_json::from_slice(&body)
            .map_err(|_| RpcError::new(-32012, "Malformed JSON from Bitcoin Core"))?;
        if let Some(error) = reply.get("error").filter(|value| !value.is_null()) {
            let code = error.get("code").and_then(Value::as_i64).unwrap_or(-32010);
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("Bitcoin Core RPC error");
            return Err(RpcError::new(code, message));
        }
        reply
            .get("result")
            .cloned()
            .ok_or_else(|| RpcError::new(-32012, "Bitcoin Core RPC result absent"))
    }
}

#[derive(Clone)]
pub struct Gateway {
    core: CoreRpc,
    gateway_token: String,
    control_token: Option<String>,
    semaphore: Arc<Semaphore>,
    chain: Arc<chain::ChainTracker>,
    artifacts: Option<Arc<cache::ArtifactStore>>,
    jobs: Option<Arc<jobs::JobManager>>,
}

impl Gateway {
    pub fn new(core: CoreRpc, gateway_token: String, max_inflight: usize) -> Result<Self, String> {
        if gateway_token.len() < 16 {
            return Err("gateway token must contain at least 16 characters".into());
        }
        if max_inflight == 0 || max_inflight > MAX_INFLIGHT_REQUESTS {
            return Err("invalid concurrent request limit".into());
        }
        Ok(Self {
            core,
            gateway_token,
            control_token: None,
            semaphore: Arc::new(Semaphore::new(max_inflight)),
            chain: Arc::new(chain::ChainTracker::new(false)),
            artifacts: None,
            jobs: None,
        })
    }

    /// Operator bearer token for local disk writes and prover scheduling.
    /// Read-only Bitcoin Core queries remain accessible to the read token.
    pub fn with_control_token(mut self, token: String) -> Result<Self, String> {
        if token.len() < 24 || constant_time_equal(token.as_bytes(), self.gateway_token.as_bytes())
        {
            return Err(
                "control token must be at least 24 characters and distinct from the read token"
                    .into(),
            );
        }
        self.control_token = Some(token);
        Ok(self)
    }

    pub fn with_job_manager(mut self, manager: Arc<jobs::JobManager>) -> Self {
        self.jobs = Some(manager);
        self
    }

    pub fn with_artifact_store(mut self, store: Arc<cache::ArtifactStore>) -> Self {
        self.artifacts = Some(store);
        self
    }

    pub fn with_chain_tracker(mut self, tracker: Arc<chain::ChainTracker>) -> Self {
        self.chain = tracker;
        self
    }
}

pub fn router(gateway: Gateway) -> Router {
    Router::new()
        .route("/", post(rpc))
        .route(
            "/healthz",
            get(|| async { Json(json!({"status":"alive"})) }),
        )
        .layer(DefaultBodyLimit::max(MAX_RPC_REQUEST_BYTES))
        .with_state(Arc::new(gateway))
}

/// Deliberate read-only subset of Bitcoin Core's standard RPC commands.
/// Wallet, signing, shutdown, broadcasting, mining and expensive mutable
/// scans are outside this v0.1 interface.
pub fn allowed_core_rpc(method: &str) -> bool {
    matches!(
        method,
        "getblockchaininfo"
            | "getblockcount"
            | "getbestblockhash"
            | "getblockhash"
            | "getblockheader"
            | "getblock"
            | "getrawtransaction"
            | "gettxoutproof"
            | "gettxout"
            | "getindexinfo"
            | "getblockfilter"
            | "getrawmempool"
            | "getmempoolentry"
            | "getmempoolinfo"
            | "getchaintips"
    )
}

fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    let mut difference = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        difference |= usize::from(*a.get(i).unwrap_or(&0) ^ *b.get(i).unwrap_or(&0));
    }
    difference == 0
}

/// A read credential never authorizes persistent local writes or launching
/// high-memory proving workers. These methods require the control credential.
pub fn requires_control_token(method: &str) -> bool {
    matches!(method, "zk.artifact.put" | "zk.proof.submit" | "zk.proof.verify")
}

fn error_reply(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": null,
        "error": {"code":code,"message":message.into()}
    })
}
fn success_reply(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result,"error":null})
}

async fn rpc(
    State(state): State<Arc<Gateway>>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let read_authorized = token
        .is_some_and(|token| constant_time_equal(token.as_bytes(), state.gateway_token.as_bytes()));
    let control_authorized = token
        .and_then(|token| {
            state
                .control_token
                .as_deref()
                .map(|control| (token, control))
        })
        .is_some_and(|(token, control)| constant_time_equal(token.as_bytes(), control.as_bytes()));
    if !read_authorized && !control_authorized {
        return (
            StatusCode::UNAUTHORIZED,
            Json(error_reply(
                Value::Null,
                -32001,
                "gateway authorization required",
            )),
        )
            .into_response();
    }

    let id = payload.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = payload.get("method").and_then(Value::as_str) else {
        return Json(error_reply(id, -32600, "missing JSON-RPC method")).into_response();
    };
    if payload.get("id").is_none() || method.len() > 80 {
        return Json(error_reply(
            id,
            -32600,
            "invalid request identifier or method",
        ))
        .into_response();
    }
    if requires_control_token(method) && !control_authorized {
        return (
            StatusCode::FORBIDDEN,
            Json(error_reply(
                id,
                -32002,
                "control authorization required for this method",
            )),
        )
            .into_response();
    }
    let params = payload.get("params").cloned().unwrap_or_else(|| json!([]));
    if !params.is_array() {
        return Json(error_reply(id, -32602, "params must be a JSON array")).into_response();
    }
    if !allowed_core_rpc(method) && !method.starts_with("zk.") {
        return Json(error_reply(
            id,
            -32601,
            "method unavailable in read-only gateway",
        ))
        .into_response();
    }
    let Ok(_permit) = state.semaphore.clone().try_acquire_owned() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(error_reply(
                id,
                -32020,
                "gateway request capacity exhausted",
            )),
        )
            .into_response();
    };
    let result = execute(&state, method, params).await;
    Json(match result {
        Ok(value) => success_reply(id, value),
        Err(error) => error_reply(id, error.code, error.message),
    })
    .into_response()
}

async fn execute(gateway: &Gateway, method: &str, params: Value) -> Result<Value, RpcError> {
    let core = &gateway.core;
    match method {
        "zk.capabilities" => Ok(json!({
            "api":"supernode-rpc/0.1",
            "mode":"read_only",
            "bitcoin_core_proxy":true,
            "auth": {"read_token":true,"separate_control_token_configured":gateway.control_token.is_some()},
            "transaction_context":true,
            "bounded_spend_context":true,
            "content_addressed_artifact_cache":gateway.artifacts.is_some(),
            "proof_jobs":match &gateway.jobs { Some(manager)=>manager.capabilities(), None=>json!({"queue_enabled":false}) },
            "zmq_sequence_tracking":gateway.chain.snapshot().await["sequence_zmq_enabled"],
            "bitcoin_merkle_proof_checked":true,
            "raito": {
                "proof_verifier_connected":gateway.jobs.as_ref().is_some_and(|m| m.raito_verifier_configured()),
                "job_queue_connected":gateway.jobs.as_ref().is_some_and(|m| m.raito_worker_configured())
            },
            "shinigami": {"script_prover_connected":false},
            "ark": {"vtxo_index_connected":false},
            "limits": {"inflight_requests":MAX_INFLIGHT_REQUESTS,
                       "rpc_response_bytes":MAX_RPC_RESPONSE_BYTES}
        })),
        "zk.chainstate" => Ok(gateway.chain.snapshot().await),
        "zk.artifact.stats" => Ok(match &gateway.artifacts {
            Some(store) => store.stats().await,
            None => json!({"enabled":false}),
        }),
        "zk.artifact.put" => put_artifact(gateway, &params).await,
        "zk.artifact.get" => get_artifact(gateway, &params).await,
        "zk.proof.submit" => submit_proof_job(gateway, &params).await,
        "zk.proof.status" => proof_job_status(gateway, &params).await,
        "zk.proof.verify" => proof_job_verify(gateway, &params).await,
        "zk.proof.receipt" => proof_job_receipt(gateway, &params).await,
        "zk.proof.get" => proof_job_get(gateway, &params).await,
        "zk.chain.refresh" => gateway
            .chain
            .reconcile(core)
            .await
            .map_err(|error| RpcError::new(-32010, error)),
        "zk.nodeprofile" => {
            let (chain, indexes, mempool) = tokio::try_join!(
                core.call("getblockchaininfo", json!([])),
                core.call("getindexinfo", json!([])),
                core.call("getmempoolinfo", json!([]))
            )?;
            Ok(json!({"chain":chain,"indexes":indexes,"mempool":mempool}))
        }
        "zk.gettxcontext" => tx_context(core, &params).await,
        "zk.getspendcontext" => spend_context(core, &params).await,
        name if allowed_core_rpc(name) => core.call(name, params).await,
        _ => Err(RpcError::new(-32601, "unknown zk method")),
    }
}

/// Retrieves a Bitcoin Core-confirmed tx by explicit block hash, then binds
/// it to the supplied block header and consensus-encoded PartialMerkleTree.
/// Re-checks the active-chain block hash for the height at response time.
pub async fn tx_context(core: &CoreRpc, params: &Value) -> Result<Value, RpcError> {
    let args = params
        .as_array()
        .ok_or_else(|| RpcError::new(-32602, "expected [txid, blockhash]"))?;
    if args.len() != 2 {
        return Err(RpcError::new(-32602, "expected exactly [txid, blockhash]"));
    }
    let txid_text = args[0]
        .as_str()
        .ok_or_else(|| RpcError::new(-32602, "txid must be a hash string"))?;
    let block_text = args[1]
        .as_str()
        .ok_or_else(|| RpcError::new(-32602, "blockhash must be a hash string"))?;
    let expected_txid =
        Txid::from_str(txid_text).map_err(|_| RpcError::new(-32602, "invalid Bitcoin txid"))?;
    let expected_hash = BlockHash::from_str(block_text)
        .map_err(|_| RpcError::new(-32602, "invalid Bitcoin blockhash"))?;
    let txid_text = expected_txid.to_string();
    let block_text = expected_hash.to_string();

    let (rawtx, proof, header, header_info, chain_info) = tokio::try_join!(
        core.call("getrawtransaction", json!([txid_text, false, block_text])),
        core.call("gettxoutproof", json!([[txid_text], block_text])),
        core.call("getblockheader", json!([block_text, false])),
        core.call("getblockheader", json!([block_text, true])),
        core.call("getblockchaininfo", json!([]))
    )?;
    let rawtx = rawtx
        .as_str()
        .ok_or_else(|| RpcError::new(-32012, "raw transaction missing from Bitcoin Core"))?;
    let proof_hex = proof
        .as_str()
        .ok_or_else(|| RpcError::new(-32012, "Merkle proof missing from Bitcoin Core"))?;
    let header_hex = header
        .as_str()
        .ok_or_else(|| RpcError::new(-32012, "block header missing from Bitcoin Core"))?;
    let decode_hex = |value: &str| {
        hex::decode(value)
            .map_err(|_| RpcError::new(-32013, "invalid hexadecimal Bitcoin Core result"))
    };
    let tx_bytes = decode_hex(rawtx)?;
    let transaction: Transaction = deserialize(&tx_bytes)
        .map_err(|_| RpcError::new(-32013, "Bitcoin Core transaction cannot be decoded"))?;
    if transaction.compute_txid() != expected_txid {
        return Err(RpcError::new(-32013, "raw transaction hash mismatch"));
    }

    let header_bytes = decode_hex(header_hex)?;
    if header_bytes.len() != 80 {
        return Err(RpcError::new(
            -32013,
            "Bitcoin block header must be 80 bytes",
        ));
    }
    let block_header: Header = deserialize(&header_bytes)
        .map_err(|_| RpcError::new(-32013, "Bitcoin block header cannot be decoded"))?;
    if block_header.block_hash() != expected_hash {
        return Err(RpcError::new(-32013, "Bitcoin block header hash mismatch"));
    }

    let proof_bytes = decode_hex(proof_hex)?;
    let merkle: MerkleBlock = deserialize(&proof_bytes)
        .map_err(|_| RpcError::new(-32013, "Bitcoin Merkle proof cannot be decoded"))?;
    if merkle.header != block_header {
        return Err(RpcError::new(-32013, "Merkle proof header mismatch"));
    }
    let mut matches = Vec::new();
    let mut positions = Vec::new();
    merkle
        .extract_matches(&mut matches, &mut positions)
        .map_err(|_| RpcError::new(-32013, "Bitcoin Merkle proof invalid"))?;
    if matches.len() != 1 || positions.len() != 1 || matches[0] != expected_txid {
        return Err(RpcError::new(
            -32013,
            "Merkle proof does not bind exactly the requested TXID",
        ));
    }

    let height = header_info
        .get("height")
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcError::new(-32012, "Bitcoin Core header height missing"))?;
    let confirmations = header_info
        .get("confirmations")
        .and_then(Value::as_i64)
        .ok_or_else(|| RpcError::new(-32012, "Bitcoin Core confirmations missing"))?;
    if confirmations <= 0 {
        return Err(RpcError::new(
            -32014,
            "block is not on Bitcoin Core active chain",
        ));
    }
    let active_hash = core.call("getblockhash", json!([height])).await?;
    if active_hash.as_str() != Some(block_text.as_str()) {
        return Err(RpcError::new(
            -32014,
            "Bitcoin active chain changed while building context",
        ));
    }

    Ok(json!({
        "network":chain_info.get("chain"),
        "txid":txid_text,
        "blockhash":block_text,
        "block_height":height,
        "confirmations_at_lookup":confirmations,
        "transaction_index":positions[0],
        "raw_transaction_hex":rawtx,
        "block_header_hex":header_hex,
        "txoutproof_hex":proof_hex,
        "proof_kind":"bitcoin_partial_merkle_tree",
        "merkle_inclusion_checked":true,
        "core_active_chain_at_lookup":true,
        "raito_stark_proof":null,
        "shinigami_execution_proof":null,
        "canonicality_note":"Bitcoin Core view at lookup time; finality and fresh tip checks belong to consumer"
    }))
}

pub const MAX_SPEND_INPUTS: usize = 256;
type SelectedPrevout = ((Txid, u32), Value);
pub const MAX_PARALLEL_PREVOUT_READS: usize = 4;

/// Decode an independently fetched previous transaction and extract only the
/// requested output positions, discarding other transaction data immediately.
fn verified_parent_outputs(
    raw_hex: &str,
    expected_txid: Txid,
    vouts: &[u32],
) -> Result<Vec<SelectedPrevout>, RpcError> {
    let bytes = hex::decode(raw_hex)
        .map_err(|_| RpcError::new(-32013, "previous transaction is not valid hexadecimal"))?;
    let parent: Transaction = deserialize(&bytes)
        .map_err(|_| RpcError::new(-32013, "previous transaction cannot be decoded"))?;
    if parent.compute_txid() != expected_txid {
        return Err(RpcError::new(-32013, "previous transaction hash mismatch"));
    }
    vouts
        .iter()
        .map(|vout| {
            let output = parent
                .output
                .get(*vout as usize)
                .ok_or_else(|| RpcError::new(-32013, "previous output index out of range"))?;
            Ok((
                (expected_txid, *vout),
                json!({
                    "value_sats":output.value.to_sat(),
                    "script_pubkey_hex":hex::encode(output.script_pubkey.as_bytes())
                }),
            ))
        })
        .collect()
}

/// Bundles proof-checked Bitcoin transaction context with prevout scripts and
/// exact satoshi amounts. Prevout lookup requires Bitcoin Core txindex access
/// unless those parents are retained in Core's mempool. This makes NO claim
/// about Shinigami/Cairo script execution or a separate UTXO validity proof.
pub async fn spend_context(core: &CoreRpc, params: &Value) -> Result<Value, RpcError> {
    let included = tx_context(core, params).await?;
    let raw_hex = included
        .get("raw_transaction_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(-32013, "transaction context lacks raw hex"))?;
    let tx: Transaction = deserialize(
        &hex::decode(raw_hex).map_err(|_| RpcError::new(-32013, "invalid raw transaction hex"))?,
    )
    .map_err(|_| RpcError::new(-32013, "cannot decode spend transaction"))?;
    if tx.input.is_empty() || tx.input.len() > MAX_SPEND_INPUTS {
        return Err(RpcError::new(
            -32602,
            "transaction input count outside bounded spend context limit",
        ));
    }

    let mut needed = std::collections::BTreeMap::<Txid, Vec<u32>>::new();
    for input in &tx.input {
        let prev = input.previous_output;
        if prev.is_null() {
            return Err(RpcError::new(
                -32602,
                "coinbase has no standard prevout spend context",
            ));
        }
        let vouts = needed.entry(prev.txid).or_default();
        if !vouts.contains(&prev.vout) {
            vouts.push(prev.vout);
        }
    }

    // Fetch unique parent transactions with bounded parallelism, and retain
    // only outputs that are actually spent. This keeps the working set small.
    let mut tasks = tokio::task::JoinSet::new();
    let mut previous = std::collections::BTreeMap::<(Txid, u32), Value>::new();
    for (parent_txid, vouts) in needed {
        let client = core.clone();
        tasks.spawn(async move {
            let response = client
                .call("getrawtransaction", json!([parent_txid.to_string(), false]))
                .await?;
            let raw = response
                .as_str()
                .ok_or_else(|| RpcError::new(-32012, "Bitcoin Core parent transaction missing"))?;
            verified_parent_outputs(raw, parent_txid, &vouts)
        });
        if tasks.len() >= MAX_PARALLEL_PREVOUT_READS {
            let values = tasks
                .join_next()
                .await
                .ok_or_else(|| RpcError::new(-32012, "missing prevout lookup result"))?
                .map_err(|_| RpcError::new(-32012, "prevout lookup worker failed"))??;
            previous.extend(values);
        }
    }
    while let Some(joined) = tasks.join_next().await {
        let values =
            joined.map_err(|_| RpcError::new(-32012, "prevout lookup worker failed"))??;
        previous.extend(values);
    }

    let outputs = tx
        .input
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let prev = input.previous_output;
            let data = previous
                .get(&(prev.txid, prev.vout))
                .ok_or_else(|| RpcError::new(-32013, "prevout was not found"))?;
            Ok(json!({
                "input_index":index,
                "previous_txid":prev.txid.to_string(),
                "previous_vout":prev.vout,
                "value_sats":data["value_sats"],
                "script_pubkey_hex":data["script_pubkey_hex"]
            }))
        })
        .collect::<Result<Vec<_>, RpcError>>()?;

    // Recheck the pinned active-chain block after potentially lengthy
    // prevout retrieval. The consumer still owns its finality policy.
    let height = included["block_height"]
        .as_u64()
        .ok_or_else(|| RpcError::new(-32013, "missing block height"))?;
    let active = core.call("getblockhash", json!([height])).await?;
    if active.as_str() != included["blockhash"].as_str() {
        return Err(RpcError::new(
            -32014,
            "active chain changed while gathering spend context",
        ));
    }

    Ok(json!({
        "tx_context":included,
        "prevouts":outputs,
        "prevout_source":"bitcoin_core_transaction_index",
        "prevout_membership_proofs":false,
        "shinigami_execution_proof":null,
        "active_chain_rechecked":true
    }))
}

/// Store bounded content-addressed, application-neutral input bytes.
/// A new artifact is only accepted for a block in Bitcoin Core's active
/// chain, and the network identity is derived from Bitcoin Core.
async fn put_artifact(gateway: &Gateway, params: &Value) -> Result<Value, RpcError> {
    let store = gateway
        .artifacts
        .as_ref()
        .ok_or_else(|| RpcError::new(-32601, "artifact storage is not configured"))?;
    let a = params
        .as_array()
        .ok_or_else(|| RpcError::new(-32602, "expected [height,blockhash,kind,hexdata]"))?;
    if a.len() != 4 {
        return Err(RpcError::new(
            -32602,
            "expected [height,blockhash,kind,hexdata]",
        ));
    }
    let height = a[0]
        .as_u64()
        .ok_or_else(|| RpcError::new(-32602, "invalid height"))?;
    let hash = BlockHash::from_str(a[1].as_str().unwrap_or(""))
        .map_err(|_| RpcError::new(-32602, "invalid blockhash"))?
        .to_string();
    let kind = a[2]
        .as_str()
        .ok_or_else(|| RpcError::new(-32602, "invalid kind"))?;
    let data = hex::decode(
        a[3].as_str()
            .ok_or_else(|| RpcError::new(-32602, "hex data required"))?,
    )
    .map_err(|_| RpcError::new(-32602, "invalid input hexadecimal"))?;
    let epoch_before = gateway.chain.epoch().await;
    let active = gateway.core.call("getblockhash", json!([height])).await?;
    if active.as_str() != Some(&hash) {
        return Err(RpcError::new(
            -32014,
            "artifact block is not on active chain",
        ));
    }
    let info = gateway.core.call("getblockchaininfo", json!([])).await?;
    let network = info["chain"]
        .as_str()
        .ok_or_else(|| RpcError::new(-32012, "network missing from Bitcoin Core"))?;
    if epoch_before != gateway.chain.epoch().await {
        return Err(RpcError::new(
            -32014,
            "chain changed during artifact staging",
        ));
    }
    let metadata = store
        .put(network, &hash, height, epoch_before, kind, &data)
        .await
        .map_err(|err| RpcError::new(-32030, err))?;
    Ok(json!({"artifact":metadata,"proof_verified":false}))
}

/// Load immutable bytes after rechecking Bitcoin Core's active-chain mapping.
/// Chain event epochs are diagnostic; Core's getblockhash check remains
/// mandatory even if ZMQ is disabled or a sequence notification is lost.
async fn get_artifact(gateway: &Gateway, params: &Value) -> Result<Value, RpcError> {
    let store = gateway
        .artifacts
        .as_ref()
        .ok_or_else(|| RpcError::new(-32601, "artifact storage is not configured"))?;
    let args = params
        .as_array()
        .ok_or_else(|| RpcError::new(-32602, "expected [artifact_id]"))?;
    if args.len() != 1 {
        return Err(RpcError::new(-32602, "expected [artifact_id]"));
    }
    let id = args[0]
        .as_str()
        .ok_or_else(|| RpcError::new(-32602, "invalid artifact id"))?;
    let (meta, data) = store
        .get(id)
        .await
        .map_err(|err| RpcError::new(-32031, err))?;
    let active = gateway
        .core
        .call("getblockhash", json!([meta.block_height]))
        .await?;
    if active.as_str() != Some(meta.block_hash.as_str()) {
        return Err(RpcError::new(
            -32014,
            "artifact block no longer belongs to active chain",
        ));
    }
    let current_network = gateway.core.call("getblockchaininfo", json!([])).await?;
    if current_network["chain"].as_str() != Some(meta.network.as_str()) {
        return Err(RpcError::new(-32014, "artifact network mismatch"));
    }
    let revalidated_after_epoch_change = meta.chain_epoch != gateway.chain.epoch().await;
    Ok(json!({"artifact":meta,"data_hex":hex::encode(&data),
              "core_active_chain_at_lookup":true,
              "revalidated_after_epoch_change":revalidated_after_epoch_change,
              "proof_verified":false}))
}

/// A bounded job request contains only predefined backend names and a
/// pre-staged artifact; arbitrary processes and user-selected paths are
/// never available through the gateway RPC.
async fn submit_proof_job(gateway: &Gateway, params: &Value) -> Result<Value, RpcError> {
    let manager = gateway
        .jobs
        .as_ref()
        .ok_or_else(|| RpcError::new(-32601, "proof job dispatcher not configured"))?;
    let args = params.as_array().ok_or_else(|| {
        RpcError::new(
            -32602,
            "expected [backend,artifact_id,memory_mib,policy_sha256,optional_expected_txid]",
        )
    })?;
    if !(4..=5).contains(&args.len()) {
        return Err(RpcError::new(
            -32602,
            "expected [backend,artifact_id,memory_mib,policy_sha256,optional_expected_txid]",
        ));
    }
    let backend = args[0]
        .as_str()
        .ok_or_else(|| RpcError::new(-32602, "invalid backend"))?;
    let artifact = args[1]
        .as_str()
        .ok_or_else(|| RpcError::new(-32602, "invalid artifact id"))?;
    let memory = args[2]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| RpcError::new(-32602, "invalid memory estimate"))?;
    let policy = args[3]
        .as_str()
        .ok_or_else(|| RpcError::new(-32602, "invalid policy hash"))?;
    let expected_txid = args
        .get(4)
        .map(|v| {
            v.as_str()
                .ok_or_else(|| RpcError::new(-32602, "invalid expected TXID"))
        })
        .transpose()?;
    let record = manager
        .submit_with_txid(backend, artifact, memory, policy, expected_txid)
        .await
        .map_err(|err| RpcError::new(-32040, err))?;
    Ok(json!({"job":record,"note":"Worker completion is not proof verification"}))
}
async fn proof_job_get(gateway: &Gateway, params: &Value) -> Result<Value, RpcError> {
    let manager = gateway
        .jobs
        .as_ref()
        .ok_or_else(|| RpcError::new(-32601, "proof job dispatcher not configured"))?;
    let args = params
        .as_array()
        .ok_or_else(|| RpcError::new(-32602, "expected [job_id,offset,max_bytes]"))?;
    if args.len() != 3 {
        return Err(RpcError::new(-32602, "expected [job_id,offset,max_bytes]"));
    }
    let id = args[0]
        .as_str()
        .ok_or_else(|| RpcError::new(-32602, "invalid job identifier"))?;
    let offset = args[1]
        .as_u64()
        .ok_or_else(|| RpcError::new(-32602, "invalid chunk offset"))?;
    let length = args[2]
        .as_u64()
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or_else(|| RpcError::new(-32602, "invalid chunk size"))?;
    manager
        .result_chunk(id, offset, length)
        .await
        .map_err(|error| RpcError::new(-32042, error))
}

async fn proof_job_verify(gateway: &Gateway, params: &Value) -> Result<Value, RpcError> {
    let manager = gateway
        .jobs
        .as_ref()
        .ok_or_else(|| RpcError::new(-32601, "proof job dispatcher not configured"))?;
    let args = params
        .as_array()
        .ok_or_else(|| RpcError::new(-32602, "expected [job_id]"))?;
    if args.len() != 1 {
        return Err(RpcError::new(-32602, "expected [job_id]"));
    }
    let id = args[0]
        .as_str()
        .ok_or_else(|| RpcError::new(-32602, "invalid job ID"))?;
    let job = manager
        .retry_verification(id)
        .await
        .map_err(|error| RpcError::new(-32044, error))?;
    Ok(json!({"job":job,"note":"Verification scheduled against pinned Raito policy"}))
}

async fn proof_job_receipt(gateway: &Gateway, params: &Value) -> Result<Value, RpcError> {
    let manager = gateway
        .jobs
        .as_ref()
        .ok_or_else(|| RpcError::new(-32601, "proof job dispatcher not configured"))?;
    let args = params
        .as_array()
        .ok_or_else(|| RpcError::new(-32602, "expected [job_id]"))?;
    if args.len() != 1 {
        return Err(RpcError::new(-32602, "expected [job_id]"));
    }
    let id = args[0]
        .as_str()
        .ok_or_else(|| RpcError::new(-32602, "invalid job ID"))?;
    manager
        .verified_receipt(id)
        .await
        .map_err(|error| RpcError::new(-32043, error))
}

async fn proof_job_status(gateway: &Gateway, params: &Value) -> Result<Value, RpcError> {
    let manager = gateway
        .jobs
        .as_ref()
        .ok_or_else(|| RpcError::new(-32601, "proof job dispatcher not configured"))?;
    let args = params
        .as_array()
        .ok_or_else(|| RpcError::new(-32602, "expected [job_id]"))?;
    if args.len() != 1 {
        return Err(RpcError::new(-32602, "expected [job_id]"));
    }
    let id = args[0]
        .as_str()
        .ok_or_else(|| RpcError::new(-32602, "invalid job id"))?;
    let record = manager
        .status(id)
        .await
        .map_err(|err| RpcError::new(-32041, err))?;
    Ok(json!({"job":record}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        constants::genesis_block, hashes::Hash, merkle_tree::PartialMerkleTree, Network,
        TxMerkleNode,
    };
    use tokio::net::TcpListener;

    async fn mock_core() -> (String, String, String) {
        let tx_hex = include_str!("../../../fixtures/mainnet/2033435de7ce307341231e818ed937cd3a5e8597381fd83a7e5b0234f61b38d3.hex").trim().to_owned();
        let tx: Transaction = deserialize(&hex::decode(&tx_hex).unwrap()).unwrap();
        let txid = tx.compute_txid();
        let mut header = genesis_block(Network::Bitcoin).header;
        header.merkle_root = TxMerkleNode::from_byte_array(txid.to_byte_array());
        let hash = header.block_hash().to_string();
        let header_hex = bitcoin::consensus::encode::serialize_hex(&header);
        let proof = MerkleBlock {
            header,
            txn: PartialMerkleTree::from_txids(&[txid], &[true]),
        };
        let proof_hex = bitcoin::consensus::encode::serialize_hex(&proof);
        let txid_string = txid.to_string();
        let block_hash = hash.clone();
        let mock = Router::new().route(
            "/",
            post(move |Json(body): Json<Value>| {
                let rawtx = tx_hex.clone();
                let raw_header = header_hex.clone();
                let raw_proof = proof_hex.clone();
                let hash = block_hash.clone();
                async move {
                    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
                    let result = match method {
                        "getrawtransaction" => json!(rawtx),
                        "gettxoutproof" => json!(raw_proof),
                        "getblockheader" => {
                            if body["params"][1] == false {
                                json!(raw_header)
                            } else {
                                json!({"height":900044,"confirmations":3})
                            }
                        }
                        "getblockhash" => json!(hash),
                        "getblockchaininfo" => {
                            json!({"chain":"regtest","blocks":900046,"initialblockdownload":false})
                        }
                        "getindexinfo" => json!({"txindex":{"synced":true}}),
                        "getmempoolinfo" => json!({"size":0}),
                        _ => Value::Null,
                    };
                    Json(json!({"result":result,"error":null,"id":"supernode"}))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, mock).await.unwrap();
        });
        (format!("http://{address}"), txid_string, hash)
    }

    async fn start_gateway(upstream: &str) -> String {
        let core = CoreRpc::new(upstream, "testuser".into(), "testpass".into()).unwrap();
        let gateway = Gateway::new(core, "0123456789abcdefTEST".into(), 4).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router(gateway)).await.unwrap();
        });
        format!("http://{address}")
    }

    async fn query_with_token(url: &str, method: &str, params: Value, token: &str) -> Value {
        let response = reqwest::Client::new()
            .post(url)
            .bearer_auth(token)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .unwrap();
        response.json().await.unwrap()
    }

    async fn query(url: &str, method: &str, params: Value) -> Value {
        query_with_token(url, method, params, "0123456789abcdefTEST").await
    }

    #[test]
    fn default_read_only_method_policy() {
        for method in [
            "getblock",
            "getrawtransaction",
            "gettxoutproof",
            "getindexinfo",
        ] {
            assert!(allowed_core_rpc(method));
        }
        for method in [
            "sendrawtransaction",
            "stop",
            "dumpprivkey",
            "submitblock",
            "testmempoolaccept",
        ] {
            assert!(!allowed_core_rpc(method));
        }
        assert!(requires_control_token("zk.artifact.put"));
        assert!(requires_control_token("zk.proof.submit"));
        assert!(requires_control_token("zk.proof.verify"));
        assert!(!requires_control_token("zk.proof.get"));
        assert!(!requires_control_token("zk.gettxcontext"));
    }

    #[tokio::test]
    async fn node_profile_and_method_denial() {
        let (upstream, _, _) = mock_core().await;
        let gateway = start_gateway(&upstream).await;
        let profile = query(&gateway, "zk.nodeprofile", json!([])).await;
        assert_eq!(profile["result"]["chain"]["chain"], "regtest");
        let denied = query(&gateway, "sendrawtransaction", json!(["deadbeef"])).await;
        assert_eq!(denied["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn proved_tx_context_requires_consistent_merkle_and_core_chain() {
        let (upstream, txid, hash) = mock_core().await;
        let gateway = start_gateway(&upstream).await;
        let answer = query(&gateway, "zk.gettxcontext", json!([txid, hash])).await;
        assert_eq!(answer["error"], Value::Null);
        assert_eq!(answer["result"]["transaction_index"], 0);
        assert_eq!(answer["result"]["merkle_inclusion_checked"], true);
        assert_eq!(answer["result"]["network"], "regtest");
    }

    #[test]
    fn exact_parent_amounts_and_scripts_are_extracted_by_vout() {
        let genesis = genesis_block(Network::Bitcoin);
        let parent = &genesis.txdata[0];
        let raw = bitcoin::consensus::encode::serialize_hex(parent);
        let outputs = verified_parent_outputs(&raw, parent.compute_txid(), &[0]).unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].1["value_sats"], 5_000_000_000u64);
        assert!(outputs[0].1["script_pubkey_hex"]
            .as_str()
            .unwrap()
            .ends_with("ac"));
        let rejected = verified_parent_outputs(&raw, Txid::from_byte_array([0; 32]), &[0]);
        assert!(rejected.is_err());
        assert!(verified_parent_outputs(&raw, parent.compute_txid(), &[1]).is_err());
    }

    #[tokio::test]
    async fn gateway_artifacts_recheck_core_after_new_chain_epoch() {
        let (upstream, _, blockhash) = mock_core().await;
        let directory = std::env::temp_dir().join(format!(
            "supernode-rpc-artifacts-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = Arc::new(crate::cache::ArtifactStore::new(directory.clone(), 4096).unwrap());
        let tracker = Arc::new(crate::chain::ChainTracker::new(false));
        let core = CoreRpc::new(&upstream, "testuser".into(), "testpass".into()).unwrap();
        let gateway = Gateway::new(core, "0123456789abcdefTEST".into(), 4)
            .unwrap()
            .with_control_token("CONTROL-012345678901234567890".into())
            .unwrap()
            .with_artifact_store(store)
            .with_chain_tracker(tracker.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router(gateway)).await.unwrap() });

        let denied = query(
            &endpoint,
            "zk.artifact.put",
            json!([900044, blockhash, "raito_input", "aabbccdd"]),
        )
        .await;
        assert_eq!(denied["error"]["code"], -32002);
        let put = query_with_token(
            &endpoint,
            "zk.artifact.put",
            json!([900044, blockhash, "raito_input", "aabbccdd"]),
            "CONTROL-012345678901234567890",
        )
        .await;
        assert_eq!(put["error"], Value::Null);
        let id = put["result"]["artifact"]["id"].as_str().unwrap().to_owned();
        let get = query(&endpoint, "zk.artifact.get", json!([id])).await;
        assert_eq!(get["result"]["data_hex"], "aabbccdd");
        assert_eq!(get["result"]["proof_verified"], false);
        assert_eq!(get["result"]["core_active_chain_at_lookup"], true);
        assert_eq!(get["result"]["revalidated_after_epoch_change"], false);

        tracker
            .record(crate::chain::SequenceEvent {
                hash: "ff".repeat(32),
                sequence: 1,
                kind: crate::chain::SequenceKind::BlockConnected,
            })
            .await;
        // An observed tip advance must not invalidate immutable data for a
        // historical block that Bitcoin Core confirms remains active.
        let second = query(&endpoint, "zk.artifact.get", json!([id])).await;
        assert_eq!(second["error"], Value::Null);
        assert_eq!(second["result"]["revalidated_after_epoch_change"], true);

        let rejected = query_with_token(
            &endpoint,
            "zk.artifact.put",
            json!([900044, "00".repeat(32), "raito_input", "aabb"]),
            "CONTROL-012345678901234567890",
        )
        .await;
        assert_eq!(rejected["error"]["code"], -32014);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn control_token_must_not_reuse_read_token() {
        let core = CoreRpc::new("http://127.0.0.1:1", "u".into(), "p".into()).unwrap();
        let gateway = Gateway::new(core, "0123456789abcdefTEST".into(), 2).unwrap();
        assert!(gateway
            .clone()
            .with_control_token("0123456789abcdefTEST".into())
            .is_err());
        assert!(gateway.with_control_token("short".into()).is_err());
    }

    #[tokio::test]
    async fn invalid_context_input_fails_before_rpc_and_gateway_requires_bearer() {
        let (upstream, _, _) = mock_core().await;
        let gateway = start_gateway(&upstream).await;
        let invalid = query(&gateway, "zk.gettxcontext", json!(["bad-txid", "00"])).await;
        assert_eq!(invalid["error"]["code"], -32602);
        let unauth = reqwest::Client::new()
            .post(&gateway)
            .json(&json!({"id":1,"method":"getblockcount","params":[]}))
            .send()
            .await
            .unwrap();
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
    }
}
