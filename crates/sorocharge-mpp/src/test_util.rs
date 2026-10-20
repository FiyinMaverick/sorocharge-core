//! Test-only doubles shared by the client and server unit tests: an
//! in-process mock Stellar RPC JSON-RPC server and a mock MPP resource
//! server.
//!
//! Both stand in for a real network at the HTTP boundary rather than behind
//! a trait, matching how the crate is actually wired: `MppClient`/`MppServer`
//! take a concrete `stellar_rpc_client::Client`, and the client takes a
//! `reqwest::Client`, so pointing each at a local server exercises the real
//! transport and JSON shapes without an API change.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use serde_json::{json, Value};
use sorocharge_signer::{Address, Signer, SorochargeError};
use stellar_xdr::{
    AccountEntry, AccountId, LedgerEntryData, Limits, PublicKey, ScAddress, SequenceNumber,
    SorobanTransactionData, Uint256, WriteXdr,
};

use crate::header::{build_www_authenticate_header, decode_base64url_json, encode_base64url_jcs};
use crate::types::{ChargeRequest, Credential};

/// A deterministic ed25519 signer whose reported address is derived from its
/// own key, so entries it signs verify against the address it claims.
pub(crate) struct TestSigner {
    signing_key: SigningKey,
    address: Address,
}

impl TestSigner {
    pub(crate) fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let address = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            public_key,
        ))));
        Self {
            signing_key,
            address,
        }
    }
}

impl Signer for TestSigner {
    fn sign_preimage(&self, preimage: &[u8]) -> Result<[u8; 64], SorochargeError> {
        Ok(self.signing_key.sign(preimage).to_bytes())
    }

    fn address(&self) -> Address {
        self.address.clone()
    }
}

/// A signer that always fails to sign, used for testing error paths.
pub(crate) struct FailingSigner {
    address: Address,
    error: SorochargeError,
}

impl FailingSigner {
    pub(crate) fn new(address: Address, error: SorochargeError) -> Self {
        Self { address, error }
    }
}

impl Signer for FailingSigner {
    fn sign_preimage(&self, _preimage: &[u8]) -> Result<[u8; 64], SorochargeError> {
        Err(self.error.clone())
    }

    fn address(&self) -> Address {
        self.address.clone()
    }
}

/// Serves `router` on an ephemeral localhost port; returns its base URL with
/// a trailing slash.
async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral localhost port");
    let addr = listener.local_addr().expect("read the bound address");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("mock server");
    });
    format!("http://{addr}/")
}

/// A mock Stellar RPC endpoint, answering the handful of JSON-RPC methods
/// this crate's flows call.
pub(crate) struct MockRpc {
    pub(crate) url: String,
    pub(crate) state: Arc<MockRpcState>,
}

pub(crate) struct MockRpcState {
    latest_ledger: u32,
    account_seq_num: i64,
    min_resource_fee: u64,
    methods: Mutex<Vec<String>>,
    simulation_events: Mutex<Option<Vec<String>>>,
}

impl MockRpc {
    /// `account_seq_num` is the sequence number `get_account` reports; the
    /// client builds its next transaction with `seq_num + 1`.
    pub(crate) async fn spawn(latest_ledger: u32, account_seq_num: i64) -> Self {
        let state = Arc::new(MockRpcState {
            latest_ledger,
            account_seq_num,
            min_resource_fee: 100,
            methods: Mutex::new(Vec::new()),
            simulation_events: Mutex::new(None),
        });
        let router = Router::new()
            .route("/", post(handle_rpc))
            .with_state(state.clone());
        let url = serve(router).await;
        Self { url, state }
    }

    /// Sets custom simulation events for the next `simulateTransaction` call.
    /// The events should be base64-encoded XDR DiagnosticEvent structures.
    #[allow(dead_code)]
    pub(crate) fn set_simulation_events(&self, events: Vec<String>) {
        *self
            .state
            .simulation_events
            .lock()
            .expect("simulation events lock") = Some(events);
    }

    /// The JSON-RPC methods the client called, in order.
    pub(crate) fn methods(&self) -> Vec<String> {
        self.state.methods.lock().expect("methods lock").clone()
    }
}

async fn handle_rpc(
    State(state): State<Arc<MockRpcState>>,
    Json(request): Json<Value>,
) -> Json<Value> {
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    state
        .methods
        .lock()
        .expect("methods lock")
        .push(method.clone());

    let result = match method.as_str() {
        "getLatestLedger" => json!({
            "id": "mock-ledger",
            "protocolVersion": 28,
            "sequence": state.latest_ledger,
        }),
        "getLedgerEntries" => {
            let account = AccountEntry {
                seq_num: SequenceNumber(state.account_seq_num),
                ..Default::default()
            };
            let xdr = LedgerEntryData::Account(account)
                .to_xdr_base64(Limits::none())
                .expect("encode a ledger entry");
            json!({
                "entries": [{
                    "key": "",
                    "xdr": xdr,
                    "lastModifiedLedgerSeq": state.latest_ledger,
                }],
                "latestLedger": i64::from(state.latest_ledger),
            })
        }
        "simulateTransaction" => {
            let transaction_data = SorobanTransactionData::default()
                .to_xdr_base64(Limits::none())
                .expect("encode transaction data");
            let events = state
                .simulation_events
                .lock()
                .expect("simulation events lock")
                .take()
                .unwrap_or_default();
            json!({
                "minResourceFee": state.min_resource_fee.to_string(),
                "transactionData": transaction_data,
                "latestLedger": state.latest_ledger,
                "events": events,
            })
        }
        other => json!({
            "error": { "code": -32601, "message": format!("mock RPC has no method {other}") }
        }),
    };
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

/// A mock MPP resource server: issues a `WWW-Authenticate: Payment`
/// challenge on a request with no credential, and returns `200` while
/// capturing the credential on a request that carries one.
pub(crate) struct MockResource {
    pub(crate) url: String,
    pub(crate) state: Arc<MockResourceState>,
}

pub(crate) struct MockResourceState {
    charge: ChargeRequest,
    id: String,
    realm: String,
    expires: Option<String>,
    captured: Mutex<Option<Credential>>,
    requests: Mutex<u32>,
}

impl MockResource {
    pub(crate) async fn spawn(charge: ChargeRequest, expires: Option<String>) -> Self {
        let state = Arc::new(MockResourceState {
            charge,
            id: "test-challenge".to_string(),
            realm: "test.example".to_string(),
            expires,
            captured: Mutex::new(None),
            requests: Mutex::new(0),
        });
        let router = Router::new()
            .route("/resource", get(handle_resource))
            .with_state(state.clone());
        let url = format!("{}resource", serve(router).await);
        Self { url, state }
    }

    /// The credential the client sent on its retry.
    pub(crate) fn captured_credential(&self) -> Credential {
        self.state
            .captured
            .lock()
            .expect("credential lock")
            .clone()
            .expect("the client should have sent a credential")
    }

    /// How many requests the resource received (1 = only the challenge).
    pub(crate) fn request_count(&self) -> u32 {
        *self.state.requests.lock().expect("requests lock")
    }
}

async fn handle_resource(
    State(state): State<Arc<MockResourceState>>,
    headers: HeaderMap,
) -> Response {
    *state.requests.lock().expect("requests lock") += 1;

    let credential_header = headers
        .get(header::AUTHORIZATION)
        .or_else(|| headers.get("payment-authorization"));
    let Some(raw) = credential_header else {
        let request_b64 = encode_base64url_jcs(&state.charge).expect("encode the charge request");
        let challenge = build_www_authenticate_header(
            &state.id,
            &state.realm,
            &request_b64,
            state.expires.as_deref(),
        );
        let mut out = HeaderMap::new();
        out.insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_str(&challenge).expect("challenge is a valid header value"),
        );
        return (StatusCode::PAYMENT_REQUIRED, out).into_response();
    };

    let raw = raw.to_str().expect("credential header is ASCII");
    let encoded = raw.strip_prefix("Payment ").expect("Payment auth scheme");
    let credential: Credential =
        decode_base64url_json(encoded).expect("credential base64url-decodes to JSON");
    *state.captured.lock().expect("credential lock") = Some(credential);
    (StatusCode::OK, "paid resource body\n").into_response()
}
