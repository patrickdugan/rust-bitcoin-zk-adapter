//! End-to-end `zk.statement.verify`, using the real verifier executables and
//! real mainnet proofs, against a mock Bitcoin Core that serves the proven
//! chain points.
//!
//! The verifiers are built from `integrations/` and located through:
//! - `SUPERNODE_TEST_PAYMENT_VERIFIER`: `btc-pay-verify`;
//! - `SUPERNODE_TEST_NOVA_VERIFIER`: `btc-header-fold`;
//! - `SUPERNODE_TEST_NOVA_VK`: the output of `btc-header-fold vk-export 10`.
//!
//! A test whose variables are unset is skipped (it reports so on stderr).
use axum::{routing::post, Json, Router};
use bitcoin::hashes::{sha256, Hash};
use rust_bitcoin_supernode_rpc::statements::{
    NovaPolicy, PaymentPolicy, PinnedProgram, StatementVerifiers,
};
use rust_bitcoin_supernode_rpc::{router, CoreRpc, Gateway};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;

const READ: &str = "0123456789abcdefTEST";
const CONTROL: &str = "control-0123456789abcdefTEST";
const PAY_VKEY: &str = "0x00de861a80542b3089fed26b37ac4e1f4bb8664dcddadb3a6de5ae7205751e75";
const TXID: &str = "fd2fdd448e15a74e661b7b058bf7ffba0a1a575aca7da75d1358a2c31217daa6";

/// height -> (hash, chainwork). Shared so a test can reorganize it.
type Chain = Arc<Mutex<HashMap<u64, (String, String)>>>;
/// Core's `gettxout` answer for the proven output (null when spent).
type TxOut = Arc<Mutex<Value>>;

fn unspent_txout() -> TxOut {
    Arc::new(Mutex::new(json!({
        "value": 0.0201,
        "scriptPubKey": {"hex": "001401e8110b73ddf764954c0d317ccf29c6d236bc77"}
    })))
}

fn payment_chain() -> Chain {
    Arc::new(Mutex::new(HashMap::from([
        (
            959_994,
            (
                "00000000000000000000cf210e0b55fa90e51720f52df6fed15f9909388d79b5".into(),
                "00000000000000000000000000000000000000013b1e621775d64a9ec241fdcd".into(),
            ),
        ),
        (
            959_984,
            (
                "000000000000000000000b99348eebd2f4863aa49a0d2fb2203c549e7b16372b".into(),
                // Only the block's hash is checked; its chainwork is not used.
                "0".repeat(64),
            ),
        ),
    ])))
}

fn nova_chain() -> Chain {
    Arc::new(Mutex::new(HashMap::from([
        (
            1000,
            (
                "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09".into(),
                "000000000000000000000000000000000000000000000000000003e903e903e9".into(),
            ),
        ),
        (
            1100,
            (
                "000000009cd3f93cd2d843202155561eb773b2a7b7c97561ddef31e707f4eb4b".into(),
                "0000000000000000000000000000000000000000000000000000044d044d044d".into(),
            ),
        ),
    ])))
}

async fn mock_core(chain: Chain, txout: TxOut) -> String {
    let app = Router::new().route(
        "/",
        post(move |Json(body): Json<Value>| {
            let chain = chain.clone();
            let txout = txout.clone();
            async move {
                let chain = chain.lock().unwrap();
                let result = match body["method"].as_str().unwrap_or("") {
                    "getblockhash" => body["params"][0]
                        .as_u64()
                        .and_then(|h| chain.get(&h))
                        .map(|(hash, _)| json!(hash))
                        .unwrap_or(Value::Null),
                    "getblockheader" => chain
                        .iter()
                        .find(|(_, (hash, _))| body["params"][0] == json!(hash))
                        .map(|(h, (_, work))| json!({"height":h,"chainwork":work,"confirmations":13_000}))
                        .unwrap_or(Value::Null),
                    "gettxout" if body["params"][0] == TXID && body["params"][1] == 0 => {
                        txout.lock().unwrap().clone()
                    }
                    _ => Value::Null,
                };
                Json(json!({"result":result,"error":null,"id":"supernode"}))
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}")
}

fn pinned(var: &str) -> Option<PinnedProgram> {
    let path = PathBuf::from(std::env::var(var).ok()?);
    let bytes = std::fs::read(&path).unwrap();
    Some(PinnedProgram {
        executable: std::fs::canonicalize(path).unwrap(),
        binary_sha256: sha256::Hash::hash(&bytes).to_string(),
    })
}

async fn start(
    chain: Chain,
    txout: TxOut,
    nova: Option<NovaPolicy>,
    payment: Option<PaymentPolicy>,
) -> String {
    let core = CoreRpc::new(&mock_core(chain, txout).await, "u".into(), "p".into()).unwrap();
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("statements-{}-{n}", std::process::id()));
    let verifiers = StatementVerifiers::new(dir, nova, payment).unwrap();
    let gateway = Gateway::new(core, READ.into(), 4)
        .unwrap()
        .with_control_token(CONTROL.into())
        .unwrap()
        .with_statement_verifiers(Arc::new(verifiers));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(gateway)).await.unwrap() });
    format!("http://{address}")
}

async fn call(url: &str, token: &str, params: Value) -> Value {
    request(url, token, "zk.statement.verify", params).await
}

async fn call_method(url: &str, method: &str, params: Value) -> Value {
    request(url, CONTROL, method, params).await
}

async fn request(url: &str, token: &str, method: &str, params: Value) -> Value {
    reqwest::Client::new()
        .post(url)
        .bearer_auth(token)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn fixture(path: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../integrations");
    hex::encode(std::fs::read(root.join(path)).unwrap())
}

#[tokio::test]
async fn real_payment_proof_is_verified_and_bound_to_core() {
    let Some(program) = pinned("SUPERNODE_TEST_PAYMENT_VERIFIER") else {
        eprintln!("skipped: SUPERNODE_TEST_PAYMENT_VERIFIER unset");
        return;
    };
    let policy = PaymentPolicy {
        program,
        pay_vkey: PAY_VKEY.into(),
        node_program_words: "a95b1a6090a64052fb6c2c12a0c5c861843a8b04b68e2218f77c9c4693510d76"
            .into(),
        leaf_program_words: "12c6f307aff4045af93b5a1d0221eb303955312728625960efa42d592e843701"
            .into(),
        segment_program_words: "99dedc0b1be5794d932fb94e6d90030e663383572f25bb5161e7347ab0fc4550"
            .into(),
    };
    let chain = payment_chain();
    let txout = unspent_txout();
    let url = start(chain.clone(), txout.clone(), None, Some(policy)).await;
    let bundle = fixture("sp1-btc-payment/fixtures/payment.bpg1");

    let ok = call(
        &url,
        CONTROL,
        json!(["sp1_btc_payment_v1", bundle, TXID, 0]),
    )
    .await;
    let result = &ok["result"];
    assert_eq!(result["proof_verified"], true, "{ok}");
    assert_eq!(result["active_chain_at_lookup"], true);
    assert_eq!(result["verified_statement"]["value_sats"], 2_010_000);
    assert_eq!(result["verified_statement"]["block_height"], 959_984);
    assert_eq!(result["unspent_at_lookup"], true);

    // Lower-bound balance over the proven outputs to one script.
    let balance = call_method(&url, "zk.statement.balance", json!([[bundle]])).await;
    assert_eq!(
        balance["result"]["proven_and_unspent_at_lookup_sats"], 2_010_000,
        "{balance}"
    );
    let twice = call_method(&url, "zk.statement.balance", json!([[bundle, bundle]])).await;
    assert!(
        twice["error"]["message"]
            .as_str()
            .unwrap()
            .contains("duplicate"),
        "{twice}"
    );

    // Spent per Core: still a verified payment, no longer counted as unspent.
    *txout.lock().unwrap() = Value::Null;
    let spent = call(&url, CONTROL, json!(["sp1_btc_payment_v1", bundle])).await;
    assert_eq!(spent["result"]["unspent_at_lookup"], false, "{spent}");
    let none = call_method(&url, "zk.statement.balance", json!([[bundle]])).await;
    assert_eq!(none["result"]["proven_received_sats"], 2_010_000);
    assert_eq!(none["result"]["proven_and_unspent_at_lookup_sats"], 0);

    // Core reporting a different value for the outpoint contradicts the proof.
    *txout.lock().unwrap() = json!({"value":0.0202,"scriptPubKey":{"hex":"001401e8110b73ddf764954c0d317ccf29c6d236bc77"}});
    let clash = call(&url, CONTROL, json!(["sp1_btc_payment_v1", bundle])).await;
    assert_eq!(clash["error"]["code"], -32054, "{clash}");
    *txout.lock().unwrap() = Value::Null;

    // The read token cannot start a verification.
    let forbidden = call(&url, READ, json!(["sp1_btc_payment_v1", bundle])).await;
    assert_eq!(forbidden["error"]["code"], -32002);

    // A different expected output is refused.
    let other = call(
        &url,
        CONTROL,
        json!(["sp1_btc_payment_v1", bundle, TXID, 1]),
    )
    .await;
    assert_eq!(other["error"]["code"], -32052, "{other}");

    // A flipped proof bit is rejected by the verifier itself.
    let mut bad = hex::decode(&bundle).unwrap();
    bad[50] ^= 1;
    let rejected = call(
        &url,
        CONTROL,
        json!(["sp1_btc_payment_v1", hex::encode(bad)]),
    )
    .await;
    assert_eq!(rejected["error"]["code"], -32053, "{rejected}");

    // Core's view wins: a reorganized tip, or different chainwork, is refused.
    chain.lock().unwrap().get_mut(&959_994).unwrap().1 = "00".repeat(31) + "01";
    let work = call(&url, CONTROL, json!(["sp1_btc_payment_v1", bundle])).await;
    assert_eq!(work["error"]["code"], -32051, "{work}");
    chain.lock().unwrap().get_mut(&959_994).unwrap().0 = "11".repeat(32);
    let reorg = call(&url, CONTROL, json!(["sp1_btc_payment_v1", bundle])).await;
    assert_eq!(reorg["error"]["code"], -32050, "{reorg}");
}

#[tokio::test]
async fn real_header_chain_proof_is_verified_and_bound_to_core() {
    let (Some(program), Ok(vk)) = (
        pinned("SUPERNODE_TEST_NOVA_VERIFIER"),
        std::env::var("SUPERNODE_TEST_NOVA_VK"),
    ) else {
        eprintln!("skipped: SUPERNODE_TEST_NOVA_VERIFIER / SUPERNODE_TEST_NOVA_VK unset");
        return;
    };
    let policy = NovaPolicy {
        program,
        vk_path: std::fs::canonicalize(vk).unwrap(),
        vk_sha256: "e46bb06929d701f1986d320e004e8ed744b0e5f74eb9f5e9c9bd0e2fe6ad1698".into(),
        checkpoints: vec![
            "3e53c33057b13ffecca476024bc78962b624814f41ac9d39e127e8f5a51a507e".into(),
        ],
    };
    let chain = nova_chain();
    let url = start(chain.clone(), unspent_txout(), Some(policy), None).await;
    let bundle = fixture("nova-header-chain/fixtures/nova100.nhc1");

    let ok = call(&url, CONTROL, json!(["nova_header_chain_v1", bundle])).await;
    let result = &ok["result"];
    assert_eq!(result["proof_verified"], true, "{ok}");
    assert_eq!(result["verified_statement"]["end"]["height"], 1100);
    assert_eq!(result["verified_statement"]["headers"], 100);

    // Outputs belong to payments only.
    let misuse = call(&url, CONTROL, json!(["nova_header_chain_v1", bundle, TXID])).await;
    assert_eq!(misuse["error"]["code"], -32602);

    // A stale end tip (Core reorganized height 1,100) is refused.
    chain.lock().unwrap().get_mut(&1100).unwrap().0 = "22".repeat(32);
    let stale = call(&url, CONTROL, json!(["nova_header_chain_v1", bundle])).await;
    assert_eq!(stale["error"]["code"], -32050, "{stale}");
}

/// A Nova proof of 1,000 current-difficulty headers (958,994 -> 959,994) and
/// the SP1 payment proof are independent proof systems; both must land on
/// the same tip hash and chainwork.
#[tokio::test]
async fn modern_header_chain_proof_ends_at_the_payment_proof_tip() {
    let (Some(nova_program), Ok(vk), Some(pay_program)) = (
        pinned("SUPERNODE_TEST_NOVA_VERIFIER"),
        std::env::var("SUPERNODE_TEST_NOVA_VK"),
        pinned("SUPERNODE_TEST_PAYMENT_VERIFIER"),
    ) else {
        eprintln!("skipped: verifier variables unset");
        return;
    };
    let nova = NovaPolicy {
        program: nova_program,
        vk_path: std::fs::canonicalize(vk).unwrap(),
        vk_sha256: "e46bb06929d701f1986d320e004e8ed744b0e5f74eb9f5e9c9bd0e2fe6ad1698".into(),
        checkpoints: vec![
            "f6db0a7fc59782567f6e49842cb21d62d4d493a97a13d65ddfca0f0a8503efe2".into(),
        ],
    };
    let payment = PaymentPolicy {
        program: pay_program,
        pay_vkey: PAY_VKEY.into(),
        node_program_words: "a95b1a6090a64052fb6c2c12a0c5c861843a8b04b68e2218f77c9c4693510d76"
            .into(),
        leaf_program_words: "12c6f307aff4045af93b5a1d0221eb303955312728625960efa42d592e843701"
            .into(),
        segment_program_words: "99dedc0b1be5794d932fb94e6d90030e663383572f25bb5161e7347ab0fc4550"
            .into(),
    };
    let chain = payment_chain();
    chain.lock().unwrap().insert(
        958_994,
        (
            "000000000000000000015e344d926094a7a364ff0ec2982fad6004a5584821ce".into(),
            "0x1395bd71adc43a240a19aeb6e".into(),
        ),
    );
    let url = start(chain, unspent_txout(), Some(nova), Some(payment)).await;

    let headers = call(
        &url,
        CONTROL,
        json!([
            "nova_header_chain_v1",
            fixture("nova-header-chain/fixtures/tip959994.nhc1")
        ]),
    )
    .await;
    let pay = call(
        &url,
        CONTROL,
        json!([
            "sp1_btc_payment_v1",
            fixture("sp1-btc-payment/fixtures/payment.bpg1")
        ]),
    )
    .await;
    let h = &headers["result"]["verified_statement"];
    let p = &pay["result"]["verified_statement"];
    assert_eq!(h["headers"], 1000, "{headers}");
    assert_eq!(h["end"]["height"], p["tip_height"]);
    assert_eq!(h["end"]["tip_hash"], p["tip_hash"]);
    let work = |s: &Value| {
        s.as_str()
            .unwrap()
            .trim_start_matches("0x")
            .trim_start_matches('0')
            .to_owned()
    };
    assert_eq!(work(&h["end"]["chainwork"]), work(&p["tip_chainwork"]));
}
