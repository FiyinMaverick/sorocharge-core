//! Parsing and building the `WWW-Authenticate: Payment` challenge,
//! `Authorization: Payment` credential, and `Payment-Receipt` header values
//! defined by `draft-httpauth-payment-01`, plus the JCS + base64url
//! encoding those specs require for the `request` and credential/receipt
//! payloads.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use base64::Engine;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::BTreeMap;

use crate::error::MppError;

/// Splits `s` on `sep`, treating any run between two `"` characters as
/// opaque. This is a deliberate simplification of RFC 9110's full
/// `quoted-string` grammar (no backslash-escape unescaping): every value
/// this protocol actually carries — challenge ids, realms, base64url
/// blobs, RFC 3339 timestamps — contains neither a comma nor an embedded
/// quote, so the simplification never encounters the cases it can't
/// handle.
fn split_respecting_quotes(s: &str, sep: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        if c == '"' {
            in_quotes = !in_quotes;
        } else if c == sep && !in_quotes {
            parts.push(&s[start..i]);
            start = i + 1;
        }
    }
    parts.push(&s[start..]);
    parts
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

/// Parses a `WWW-Authenticate` (or credential) header's `Payment
/// auth-param-list` into a `key -> value` map, with `quoted-string` values
/// unquoted.
pub(crate) fn parse_payment_auth_params(
    header_value: &str,
) -> Result<BTreeMap<String, String>, MppError> {
    let rest = header_value.trim();
    let rest = rest
        .strip_prefix("Payment")
        .ok_or_else(|| MppError::InvalidChallenge {
            reason: "expected the \"Payment\" auth scheme".to_string(),
        })?
        .trim_start();
    let mut params = BTreeMap::new();
    if rest.is_empty() {
        return Ok(params);
    }
    for part in split_respecting_quotes(rest, ',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| MppError::InvalidChallenge {
                reason: format!("malformed auth-param: {part}"),
            })?;
        params.insert(key.trim().to_string(), unquote(value));
    }
    Ok(params)
}

/// Builds a `WWW-Authenticate: Payment ...` header value for a `"stellar"`
/// `"charge"` challenge.
pub(crate) fn build_www_authenticate_header(
    id: &str,
    realm: &str,
    request_b64: &str,
    expires: Option<&str>,
) -> String {
    let mut header = format!(
        "Payment id=\"{id}\", realm=\"{realm}\", method=\"stellar\", intent=\"charge\", request=\"{request_b64}\""
    );
    if let Some(expires) = expires {
        header.push_str(&format!(", expires=\"{expires}\""));
    }
    header
}

/// Encodes `value` per the spec's requirement for the `request` param and
/// the credential/receipt payloads: JSON Canonicalization Scheme (RFC
/// 8785), then base64url without padding.
pub(crate) fn encode_base64url_jcs<T: Serialize>(value: &T) -> Result<String, MppError> {
    let bytes = serde_jcs::to_vec(value).map_err(|e| MppError::InvalidChargeRequest {
        reason: e.to_string(),
    })?;
    Ok(BASE64URL.encode(bytes))
}

/// Decodes a base64url (no padding) JSON value. Accepts ordinary JSON on
/// decode (JCS is a canonical *output* form; any conforming JSON parser
/// reads it back without needing to know it was canonicalized).
pub(crate) fn decode_base64url_json<T: DeserializeOwned>(encoded: &str) -> Result<T, String> {
    let bytes = BASE64URL
        .decode(encoded.trim())
        .map_err(|e| format!("base64url decode failed: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("JSON decode failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim (line-folding joined, as an HTTP client would hand it to
    /// us) from `draft-httpauth-payment-01`'s "Example Challenge".
    const EXAMPLE_CHALLENGE: &str = "Payment id=\"x7Tg2pLqR9mKvNwY3hBcZa\", realm=\"api.example.com\", method=\"example\", intent=\"charge\", expires=\"2025-01-15T12:05:00Z\", request=\"eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiJVU0QiLCJyZWNpcGllbnQiOiJhY2N0XzEyMyJ9\"";

    #[test]
    fn parses_the_spec_example_challenge() {
        let params = parse_payment_auth_params(EXAMPLE_CHALLENGE).unwrap();
        assert_eq!(params.get("id").unwrap(), "x7Tg2pLqR9mKvNwY3hBcZa");
        assert_eq!(params.get("realm").unwrap(), "api.example.com");
        assert_eq!(params.get("method").unwrap(), "example");
        assert_eq!(params.get("intent").unwrap(), "charge");
        assert_eq!(params.get("expires").unwrap(), "2025-01-15T12:05:00Z");
        assert_eq!(
            params.get("request").unwrap(),
            "eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiJVU0QiLCJyZWNpcGllbnQiOiJhY2N0XzEyMyJ9"
        );

        let decoded: serde_json::Value =
            decode_base64url_json(params.get("request").unwrap()).unwrap();
        assert_eq!(decoded["amount"], "1000");
        assert_eq!(decoded["currency"], "USD");
        assert_eq!(decoded["recipient"], "acct_123");
    }

    #[test]
    fn build_then_parse_round_trips_a_challenge_header() {
        let header = build_www_authenticate_header(
            "abc123",
            "api.example.com",
            "eyJhbW91bnQiOiIxMDAwIn0",
            Some("2025-01-15T12:05:00Z"),
        );
        let params = parse_payment_auth_params(&header).unwrap();
        assert_eq!(params.get("id").unwrap(), "abc123");
        assert_eq!(params.get("realm").unwrap(), "api.example.com");
        assert_eq!(params.get("method").unwrap(), "stellar");
        assert_eq!(params.get("intent").unwrap(), "charge");
        assert_eq!(params.get("request").unwrap(), "eyJhbW91bnQiOiIxMDAwIn0");
        assert_eq!(params.get("expires").unwrap(), "2025-01-15T12:05:00Z");
    }

    #[test]
    fn decode_base64url_json_rejects_invalid_base64url() {
        // Not valid base64url (contains invalid chars)
        let result = decode_base64url_json::<serde_json::Value>("!!!invalid!!!");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("base64url decode failed"));
    }

    #[test]
    fn decode_base64url_json_rejects_valid_base64url_but_invalid_json() {
        // Valid base64url encoding of "not json"
        let encoded = BASE64URL.encode(b"not json");
        let result = decode_base64url_json::<serde_json::Value>(&encoded);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("JSON decode failed"));
    }

    #[test]
    fn decode_base64url_json_rejects_valid_json_but_wrong_shape_for_charge_request() {
        // Valid JSON but missing required fields for ChargeRequest
        let encoded = BASE64URL.encode(br#"{"foo": "bar"}"#);
        let result = decode_base64url_json::<crate::types::ChargeRequest>(&encoded);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("JSON decode failed"));
    }
}
