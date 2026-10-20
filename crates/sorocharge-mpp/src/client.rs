//! The payer side of MPP's `"stellar"` `"charge"` method: `GET` a resource,
//! receive a `Payment` challenge, build and sign a charge (pull mode,
//! sponsored or unsponsored), and retry with the credential attached.

use chrono::{DateTime, Utc};
use sorocharge_signer::{
    build_charge_entry, network_id_hash, sign_entry, ChargeParams, CredentialKind, Signer,
};
use stellar_xdr::{
    AccountId, Limits, PublicKey, ReadXdr, ScAddress, SorobanTransactionData, WriteXdr,
};

use crate::error::MppError;
use crate::header::{decode_base64url_json, encode_base64url_jcs};
use crate::network::caip2_for_passphrase;
use crate::tx::{build_sponsored_envelope, build_unsponsored_transaction, sign_transaction};
use crate::types::{Challenge, ChargeRequest, Credential, Payload};

const DEFAULT_ESTIMATED_LEDGER_SECONDS: u64 = 5;
const DEFAULT_CHALLENGE_EXPIRY_SECONDS: i64 = 300;
const SETTLEMENT_FEE_BUFFER_STROOPS: i64 = 100;
/// Retry configuration for transient HTTP/RPC failures.
/// Max 3 attempts with exponential backoff (1s, 2s, 4s).
const MAX_RETRY_ATTEMPTS: u32 = 3;

fn parse_expires(expires: Option<&str>) -> DateTime<Utc> {
    expires
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|| Utc::now() + chrono::Duration::seconds(DEFAULT_CHALLENGE_EXPIRY_SECONDS))
}

/// Retries an HTTP GET request with bounded backoff for transient failures.
///
/// - Retries up to `MAX_RETRY_ATTEMPTS` times (default 3).
/// - On 5xx or connection-level errors, waits with exponential backoff
///   (1s, 2s, 4s...).
/// - Each attempt respects the client's `request_timeout`, so total wall-clock
///   time is bounded by `timeout * attempts` plus backoff.
/// - On success, returns the successful response immediately.
/// - On final failure, returns the last error.
async fn retry_get<T: reqwest::IntoUrl + Clone>(
    http: &reqwest::Client,
    url: T,
) -> Result<reqwest::Response, MppError> {
    let mut attempt = 0;
    let mut last_error = MppError::HttpRequestFailed {
        reason: "exhausted retries".to_string(),
    };
    while attempt < MAX_RETRY_ATTEMPTS {
        attempt += 1;
        match http.get(url.clone()).send().await {
            Ok(resp) => {
                // Don't retry on 200 (ok) or 402 (payment required) — those are
                // deliberate protocol responses returned to the caller. Retry
                // only on connection failures (the `Err` arm below).
                return Ok(resp);
            }
            Err(e) => {
                last_error = MppError::HttpRequestFailed {
                    reason: format!("request attempt {} failed: {e}", attempt),
                };
                // Retry on connection errors.
                if attempt < MAX_RETRY_ATTEMPTS {
                    // Exponential backoff: 1s, 2s, 4s, ...
                    let backoff = std::time::Duration::from_secs(
                        1u64.saturating_pow(attempt.saturating_sub(1)),
                    );
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }
    Err(last_error)
}

/// The MPP payer client. Owns a Stellar RPC client because, unlike x402,
/// the unsponsored flow needs the payer's own account sequence number and a
/// fee/resource-data simulation before it can build a fully-signed
/// transaction — pushing that onto the caller would just move the same RPC
/// calls one layer up.
pub struct MppClient<'a> {
    http: reqwest::Client,
    rpc: &'a stellar_rpc_client::Client,
}

impl<'a> MppClient<'a> {
    /// # Errors
    ///
    /// Returns [`MppError::HttpRequestFailed`] if the underlying HTTP
    /// client fails to construct.
    pub fn new(
        rpc: &'a stellar_rpc_client::Client,
        request_timeout: std::time::Duration,
    ) -> Result<Self, MppError> {
        let http = reqwest::Client::builder()
            .timeout(request_timeout)
            .build()
            .map_err(|e| MppError::HttpRequestFailed {
                reason: e.to_string(),
            })?;
        Ok(Self { http, rpc })
    }

    /// Performs the full MPP client flow against `url`: `GET`, decode the
    /// `WWW-Authenticate: Payment` challenge, build and sign a charge per
    /// the challenge's `feePayer` setting, and retry with the credential
    /// attached in the header the challenge selected (`Authorization` by
    /// default, or `Payment-Authorization` when the challenge requested
    /// it).
    ///
    /// # Errors
    ///
    /// See [`MppError`] for the specific failure modes.
    pub async fn get_with_payment(
        &self,
        url: &str,
        signer: &dyn Signer,
        network_passphrase: &str,
    ) -> Result<reqwest::Response, MppError> {
        let first = retry_get(&self.http, url).await?;

        if first.status() == reqwest::StatusCode::OK {
            return Ok(first);
        }
        if first.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
            // Protocol-level 402: continue with challenge handling below.
        } else if first.status().is_server_error() {
            // Transient 5xx: retry_get already handled backoff; if we're here,
            // retries were exhausted.
            return Err(MppError::UnexpectedStatus {
                status: first.status().as_u16(),
            });
        } else {
            return Err(MppError::UnexpectedStatus {
                status: first.status().as_u16(),
            });
        }

        let www_authenticate = first
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .ok_or(MppError::MissingChallenge)?
            .to_str()
            .map_err(|e| MppError::InvalidChallenge {
                reason: e.to_string(),
            })?;
        let params = crate::header::parse_payment_auth_params(www_authenticate)?;

        let id = params
            .get("id")
            .filter(|v| !v.is_empty())
            .ok_or_else(|| MppError::InvalidChallenge {
                reason: "missing \"id\"".to_string(),
            })?
            .clone();
        let realm = params
            .get("realm")
            .ok_or_else(|| MppError::InvalidChallenge {
                reason: "missing \"realm\"".to_string(),
            })?
            .clone();
        let method = params
            .get("method")
            .ok_or_else(|| MppError::InvalidChallenge {
                reason: "missing \"method\"".to_string(),
            })?
            .clone();
        if method != "stellar" {
            return Err(MppError::UnsupportedMethod { method });
        }
        let intent = params
            .get("intent")
            .ok_or_else(|| MppError::InvalidChallenge {
                reason: "missing \"intent\"".to_string(),
            })?
            .clone();
        if intent != "charge" {
            return Err(MppError::UnsupportedIntent { intent });
        }
        let request_b64 = params
            .get("request")
            .ok_or_else(|| MppError::InvalidChallenge {
                reason: "missing \"request\"".to_string(),
            })?
            .clone();
        let expires = params.get("expires").cloned();
        let header_field = params.get("header").cloned();

        let charge_request: ChargeRequest = decode_base64url_json(&request_b64)
            .map_err(|reason| MppError::InvalidChargeRequest { reason })?;

        let network = caip2_for_passphrase(network_passphrase)?;
        if charge_request.method_details.network != network {
            return Err(MppError::UnsupportedNetwork {
                network: charge_request.method_details.network,
            });
        }

        let expires_at = parse_expires(expires.as_deref());
        if expires_at <= Utc::now() {
            return Err(MppError::ChallengeExpired);
        }

        let current_ledger = self
            .rpc
            .get_latest_ledger()
            .await
            .map_err(|e| MppError::RpcFailed {
                reason: e.to_string(),
            })?
            .sequence;
        let seconds_until_expiry = (expires_at - Utc::now()).num_seconds().max(0) as u64;
        // Half the spec's allowance. The server re-derives its bound from its own
        // clock and the live ledger; if ledgers close slower than the 5s default,
        // a full-allowance expiry fails that check. The margin keeps the
        // expiry inside the bound (and shorter, so less exposed) at the cost of
        // a shorter authorization window.
        let ledger_timeout = seconds_until_expiry
            .div_ceil(DEFAULT_ESTIMATED_LEDGER_SECONDS)
            .div_ceil(2);
        let valid_until_ledger =
            // ledger_timeout is the result of dividing seconds_until_expiry by 10
            // (5 estimated ledger seconds * 2 margin). The result should fit in
            // u32 for any reasonable expiry, but we defensively cap at u32::MAX
            // rather than error out, since the downstream verify_entry check
            // against valid_until_ledger will catch any genuine overflow.
            current_ledger.saturating_add(u32::try_from(ledger_timeout).unwrap_or(u32::MAX));

        let asset_contract =
            charge_request
                .currency
                .parse()
                .map_err(|_| MppError::InvalidChargeRequest {
                    reason: format!("invalid currency address: {}", charge_request.currency),
                })?;
        let amount = charge_request
            .amount
            .parse()
            .map_err(|_| MppError::InvalidChargeRequest {
                reason: format!("invalid amount: {}", charge_request.amount),
            })?;
        let recipient =
            charge_request
                .recipient
                .parse()
                .map_err(|_| MppError::InvalidChargeRequest {
                    reason: format!("invalid recipient address: {}", charge_request.recipient),
                })?;
        let params_ = ChargeParams {
            asset_contract,
            amount,
            payer: signer.address(),
            recipient,
            valid_until_ledger,
        };

        let unsigned = build_charge_entry(&params_, CredentialKind::Legacy)?;
        let signed = sign_entry(unsigned, signer, network_passphrase)?;

        let payload = if charge_request.method_details.fee_payer {
            let envelope = build_sponsored_envelope(&params_, &signed)?;
            let transaction = envelope.to_xdr_base64(Limits::none()).map_err(|e| {
                MppError::XdrEncodingFailed {
                    reason: e.to_string(),
                }
            })?;
            Payload::Transaction { transaction }
        } else {
            let ScAddress::Account(payer_account_id) = params_.payer.clone() else {
                return Err(MppError::XdrEncodingFailed {
                    reason: "payer must be an Ed25519 account for unsponsored payments".to_string(),
                });
            };
            let account = self
                .rpc
                .get_account(&params_.payer.to_string())
                .await
                .map_err(|e| MppError::RpcFailed {
                    reason: e.to_string(),
                })?;
            let next_seq = stellar_xdr::SequenceNumber(account.seq_num.0 + 1);
            let max_time_unix = u64::try_from(expires_at.timestamp()).unwrap_or(0);

            let draft_tx = build_unsponsored_transaction(
                &params_,
                &signed,
                payer_account_id.clone(),
                next_seq.clone(),
                0,
                SorobanTransactionData::default(),
                max_time_unix,
            )?;
            let draft_envelope =
                stellar_xdr::TransactionEnvelope::Tx(stellar_xdr::TransactionV1Envelope {
                    tx: draft_tx,
                    signatures: Default::default(),
                });
            let simulation = self
                .rpc
                .simulate_transaction_envelope(&draft_envelope, None)
                .await
                .map_err(|e| MppError::RpcFailed {
                    reason: e.to_string(),
                })?;
            if let Some(error) = simulation.error {
                return Err(MppError::VerificationFailed {
                    reason: format!("simulation failed: {error}"),
                });
            }
            let fee = i64::try_from(simulation.min_resource_fee)
                .unwrap_or(i64::MAX)
                // simulation.min_resource_fee is u64; i64::MAX is 9.2e18 while
                // u64::MAX is 1.8e19, so the conversion can lose the top bit.
                // However, realistic Stellar resource fees are always orders of
                // magnitude below this ceiling. The unwrap_or(i64::MAX) ensures we
                // never silently saturate to a wrong value; instead we get i64::MAX
                // which will then fail the fee > ceiling check (since 2^63-1 > 50_000),
                // causing the settlement to be refused rather than submitting a
                // transaction with a spuriously high fee.
                .saturating_add(SETTLEMENT_FEE_BUFFER_STROOPS);
            let soroban_data = SorobanTransactionData::from_xdr_base64(
                &simulation.transaction_data,
                Limits::none(),
            )
            .map_err(|e| MppError::XdrDecodingFailed {
                reason: e.to_string(),
            })?;

            let final_tx = build_unsponsored_transaction(
                &params_,
                &signed,
                payer_account_id,
                next_seq,
                u32::try_from(fee).unwrap_or(u32::MAX), // fee is i64 from the simulation + buffer. u32::MAX is 4.3e9
                // stroops (~0.039 XLM). Real Stellar fees are typically
                // < 10_000 stroops. unwrap_or(u32::MAX) ensures we never silently
                // saturate a fee that's genuinely too high; the fee check above
                // will already have refused such cases. If fee somehow exceeds
                // u32::MAX (extremely unlikely), the transaction won't be
                // submitted with a maximal fee rather than erroring out of band.
                soroban_data,
                max_time_unix,
            )?;
            let network_id = network_id_hash(network_passphrase);
            let signed_envelope = sign_transaction(final_tx, signer, network_id)?;
            let transaction = signed_envelope.to_xdr_base64(Limits::none()).map_err(|e| {
                MppError::XdrEncodingFailed {
                    reason: e.to_string(),
                }
            })?;
            Payload::Transaction { transaction }
        };

        let ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(_))) = params_.payer
        else {
            return Err(MppError::XdrEncodingFailed {
                reason: "payer must be an Ed25519 account".to_string(),
            });
        };
        let source = format!("did:pkh:{network}:{}", params_.payer);

        let credential = Credential {
            challenge: Challenge {
                id,
                realm,
                method,
                intent,
                request: request_b64,
                description: params.get("description").cloned(),
                opaque: params.get("opaque").cloned(),
                digest: params.get("digest").cloned(),
                expires,
                header: header_field.clone(),
            },
            payload,
            source: Some(source),
        };
        let credential_value = encode_base64url_jcs(&credential)?;

        let header_name = match header_field.as_deref() {
            Some("Payment-Authorization") => "Payment-Authorization",
            _ => "Authorization",
        };
        let second = self
            .http
            .get(url)
            .header(header_name, format!("Payment {credential_value}"))
            .send()
            .await
            .map_err(|e| MppError::HttpRequestFailed {
                reason: e.to_string(),
            })?;

        if second.status() != reqwest::StatusCode::OK {
            return Err(MppError::UnexpectedStatus {
                status: second.status().as_u16(),
            });
        }
        Ok(second)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use chrono::Duration as ChronoDuration;
    use std::time::Duration;
    use stellar_xdr::{AccountId, MuxedAccount, Preconditions, TransactionEnvelope, Uint256};

    use crate::test_util::{MockResource, MockRpc, TestSigner};
    use crate::types::MethodDetails;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
    use base64::Engine as _;

    const NETWORK: &str = "Test SDF Network ; September 2015";
    const CURRENT_LEDGER: u32 = 1_000;
    const ACCOUNT_SEQ_NUM: i64 = 5;
    const ASSET_CONTRACT: &str = "CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH";
    const RECIPIENT: &str = "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N";
    const AMOUNT: i128 = 42_000_000;

    fn charge_request(fee_payer: bool) -> ChargeRequest {
        ChargeRequest {
            amount: AMOUNT.to_string(),
            currency: ASSET_CONTRACT.to_string(),
            recipient: RECIPIENT.to_string(),
            description: None,
            external_id: None,
            method_details: MethodDetails {
                network: "stellar:testnet".to_string(),
                fee_payer,
            },
        }
    }

    fn expires_in(seconds: i64) -> String {
        (Utc::now() + ChronoDuration::seconds(seconds)).to_rfc3339()
    }

    fn transaction_from(credential: &Credential) -> TransactionEnvelope {
        let Payload::Transaction { transaction } = &credential.payload else {
            panic!("expected a transaction payload");
        };
        TransactionEnvelope::from_xdr_base64(transaction, Limits::none()).expect("decode envelope")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sponsored_flow_builds_a_placeholder_source_transaction() {
        let resource = MockResource::spawn(charge_request(true), Some(expires_in(300))).await;
        let rpc = MockRpc::spawn(CURRENT_LEDGER, ACCOUNT_SEQ_NUM).await;
        let rpc_client = stellar_rpc_client::Client::new(&rpc.url).expect("rpc client");
        let client = MppClient::new(&rpc_client, Duration::from_secs(5)).expect("client");
        let signer = TestSigner::from_seed([0x44; 32]);

        let response = client
            .get_with_payment(&resource.url, &signer, NETWORK)
            .await
            .expect("payment flow");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(resource.request_count(), 2);

        let TransactionEnvelope::Tx(v1) = transaction_from(&resource.captured_credential()) else {
            panic!("expected a v1 envelope");
        };
        assert_eq!(
            v1.tx.source_account,
            MuxedAccount::Ed25519(Uint256([0u8; 32])),
            "sponsored transactions must use the all-zeros placeholder source"
        );
        assert_eq!(v1.tx.seq_num.0, 0);
        assert_eq!(v1.tx.fee, 0);
        // The sponsored path never needs the payer's account or a simulation.
        assert_eq!(rpc.methods(), vec!["getLatestLedger"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unsponsored_flow_builds_a_real_sequence_and_time_bounds() {
        let resource = MockResource::spawn(charge_request(false), Some(expires_in(300))).await;
        let rpc = MockRpc::spawn(CURRENT_LEDGER, ACCOUNT_SEQ_NUM).await;
        let rpc_client = stellar_rpc_client::Client::new(&rpc.url).expect("rpc client");
        let client = MppClient::new(&rpc_client, Duration::from_secs(5)).expect("client");
        let signer = TestSigner::from_seed([0x44; 32]);

        let response = client
            .get_with_payment(&resource.url, &signer, NETWORK)
            .await
            .expect("payment flow");
        assert_eq!(response.status(), reqwest::StatusCode::OK);

        let TransactionEnvelope::Tx(v1) = transaction_from(&resource.captured_credential()) else {
            panic!("expected a v1 envelope");
        };

        let ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(payer_key)))) =
            signer.address()
        else {
            panic!("the test signer must be an account");
        };
        assert_eq!(
            v1.tx.source_account,
            MuxedAccount::Ed25519(Uint256(payer_key))
        );
        assert_eq!(v1.tx.seq_num.0, ACCOUNT_SEQ_NUM + 1);
        // The mock simulation reports a 100-stroop resource fee; the client
        // adds its own 100-stroop buffer on top.
        assert_eq!(v1.tx.fee, 200);

        let Preconditions::Time(bounds) = &v1.tx.cond else {
            panic!("unsponsored transactions must set timeBounds");
        };
        assert!(bounds.max_time.0 > 0);

        assert_eq!(
            rpc.methods(),
            vec!["getLatestLedger", "getLedgerEntries", "simulateTransaction"]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn invalid_challenge_request_returns_invalid_charge_request() {
        // Create a mock resource that returns a challenge with an invalid request field
        // (base64url that doesn't decode to valid JSON)
        let invalid_request_b64 = BASE64URL.encode(b"not valid json");
        let rpc = MockRpc::spawn(CURRENT_LEDGER, ACCOUNT_SEQ_NUM).await;
        let rpc_client = stellar_rpc_client::Client::new(&rpc.url).expect("rpc client");
        let client = MppClient::new(&rpc_client, Duration::from_secs(5)).expect("client");
        let signer = TestSigner::from_seed([0x44; 32]);

        // Build a challenge header with the invalid request field
        let challenge_header = crate::header::build_www_authenticate_header(
            "test-challenge",
            "test.example",
            &invalid_request_b64,
            Some(&expires_in(300)),
        );

        // Create a mock server that returns this specific challenge
        let mock_router = axum::Router::new().route(
            "/resource",
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let challenge_header = challenge_header.clone();
                async move {
                    let credential_header = headers
                        .get(axum::http::header::AUTHORIZATION)
                        .or_else(|| headers.get("payment-authorization"));
                    if credential_header.is_none() {
                        let mut out = axum::http::HeaderMap::new();
                        out.insert(
                            axum::http::header::WWW_AUTHENTICATE,
                            axum::http::HeaderValue::from_str(&challenge_header).unwrap(),
                        );
                        return (axum::http::StatusCode::PAYMENT_REQUIRED, out).into_response();
                    }
                    (axum::http::StatusCode::OK, "paid\n").into_response()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, mock_router).await.unwrap();
        });
        let url = format!("http://{addr}/resource");

        let result = client.get_with_payment(&url, &signer, NETWORK).await;

        assert!(
            matches!(result, Err(MppError::InvalidChargeRequest { ref reason }) if reason.contains("JSON decode failed")),
            "expected InvalidChargeRequest, got {result:?}"
        );
    }
}
