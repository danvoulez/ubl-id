//! PoP (Proof-of-Possession) headers for request signing — RFC-0001 compliant
//!
//! The `X-UBL-POW` header proves that a wallet possesses the private key
//! and authorizes a specific HTTP request.
//!
//! # Wire Format v1 (RFC-0001 §6)
//!
//! ```text
//! X-UBL-POW: <payload_b64>.<signature_b64>.<wallet_did>
//! ```
//!
//! Where:
//! - `payload_b64` = base64url(canonical_json(payload))
//! - `signature_b64` = base64url(Ed25519_sign(payload_bytes))
//! - `wallet_did` = the DID string (e.g., `did:key:z6Mk...`)
//!
//! # Payload Structure v1
//!
//! ```json
//! {
//!   "v": 1,
//!   "m": "POST",
//!   "p": "/t/logline/v1/chip/mint",
//!   "ts": 1704067200,
//!   "ath": "blake3:a1b2c3d4..."  // optional
//! }
//! ```
//!
//! # Token Binding (ath)
//!
//! Optional `ath` = `blake3:<hex>` where hex = blake3(access_token).
//! Binds the PoP to a specific Bearer token, preventing token substitution.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use crate::did::Did;

/// PoP verification errors
#[derive(Debug, Error)]
pub enum PopError {
    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    #[error("missing field: {0}")]
    MissingField(String),
    #[error("unsupported version: {0}")]
    UnsupportedVersion(i32),
    #[error("timestamp skew too large")]
    TimestampSkew,
    #[error("request binding mismatch")]
    RequestMismatch,
    #[error("token binding mismatch")]
    TokenMismatch,
    #[error("signature verification failed")]
    SignatureFailed,
    #[error("invalid wallet DID")]
    InvalidDid,
    #[error("invalid wire format")]
    InvalidWireFormat,
}

/// PoP Payload v1 (the signed portion)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopPayloadV1 {
    /// Version (MUST be 1)
    pub v: i32,
    /// HTTP method (uppercase)
    pub m: String,
    /// Path only (no scheme/host/query)
    pub p: String,
    /// Unix timestamp (seconds)
    pub ts: i64,
    /// Access token hash: blake3:<hex>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
}

/// Proof-of-Possession header (decoded)
#[derive(Debug, Clone)]
pub struct Pop {
    /// The payload that was signed
    pub payload: PopPayloadV1,
    /// The canonical payload bytes (for verification)
    pub payload_bytes: Vec<u8>,
    /// The signature (64 bytes)
    pub signature: [u8; 64],
    /// The wallet DID
    pub wallet_did: String,
}

impl Pop {
    /// Encode as X-UBL-POW header value (RFC-0001 wire format v1)
    ///
    /// Format: `base64url(payload).base64url(sig).wallet_did`
    pub fn encode(&self) -> String {
        format!(
            "{}.{}.{}",
            B64URL.encode(&self.payload_bytes),
            B64URL.encode(self.signature),
            self.wallet_did
        )
    }

    /// Decode from X-UBL-POW header value
    pub fn decode(header: &str) -> Result<Self, PopError> {
        let parts: Vec<&str> = header.split('.').collect();
        if parts.len() != 3 {
            return Err(PopError::InvalidWireFormat);
        }

        // Decode payload
        let payload_bytes = B64URL
            .decode(parts[0].as_bytes())
            .map_err(|_| PopError::InvalidEncoding("payload base64".into()))?;

        let payload: PopPayloadV1 = serde_json::from_slice(&payload_bytes)
            .map_err(|e| PopError::InvalidJson(e.to_string()))?;

        // Check version
        if payload.v != 1 {
            return Err(PopError::UnsupportedVersion(payload.v));
        }

        // Decode signature
        let sig_bytes = B64URL
            .decode(parts[1].as_bytes())
            .map_err(|_| PopError::InvalidEncoding("signature base64".into()))?;

        let signature: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| PopError::InvalidEncoding("signature must be 64 bytes".into()))?;

        // Wallet DID
        let wallet_did = parts[2].to_string();

        Ok(Self {
            payload,
            payload_bytes,
            signature,
            wallet_did,
        })
    }

    /// Verify the PoP against expected values
    ///
    /// # Arguments
    /// - `expected_method`: Expected HTTP method (case-insensitive)
    /// - `expected_path`: Expected path (exact match)
    /// - `max_skew_secs`: Maximum allowed timestamp skew (typically 120)
    /// - `access_token`: If provided, verify ath matches blake3 of token
    pub fn verify(
        &self,
        expected_method: &str,
        expected_path: &str,
        max_skew_secs: i64,
        access_token: Option<&str>,
    ) -> Result<Did, PopError> {
        // Check version
        if self.payload.v != 1 {
            return Err(PopError::UnsupportedVersion(self.payload.v));
        }

        // Check request binding (method case-insensitive, path exact)
        if !self.payload.m.eq_ignore_ascii_case(expected_method) || self.payload.p != expected_path
        {
            return Err(PopError::RequestMismatch);
        }

        // Check timestamp
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if (now - self.payload.ts).abs() > max_skew_secs {
            return Err(PopError::TimestampSkew);
        }

        // Check token binding if present
        if let Some(ath) = &self.payload.ath {
            let token = access_token.ok_or(PopError::TokenMismatch)?;
            let expected_ath = format!("blake3:{}", blake3::hash(token.as_bytes()).to_hex());
            if ath != &expected_ath {
                return Err(PopError::TokenMismatch);
            }
        }

        // Parse wallet DID and extract public key
        let did = Did::parse(&self.wallet_did).map_err(|_| PopError::InvalidDid)?;
        let pk_bytes = did.key_bytes().ok_or(PopError::InvalidDid)?;
        let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| PopError::InvalidDid)?;

        // Verify signature over the canonical payload bytes
        let sig = Signature::from_bytes(&self.signature);
        vk.verify_strict(&self.payload_bytes, &sig)
            .map_err(|_| PopError::SignatureFailed)?;

        Ok(did)
    }

    /// Get the method from payload
    pub fn method(&self) -> &str {
        &self.payload.m
    }

    /// Get the path from payload
    pub fn path(&self) -> &str {
        &self.payload.p
    }

    /// Get the timestamp from payload
    pub fn ts(&self) -> i64 {
        self.payload.ts
    }
}

/// Build X-UBL-POW header value (convenience function)
pub fn build_pop_header(
    method: &str,
    path: &str,
    priv_b64: &str,
    access_token: Option<&str>,
) -> Result<String, PopError> {
    let wallet = crate::wallet::Wallet::from_priv_b64(priv_b64)
        .map_err(|e| PopError::InvalidEncoding(e.to_string()))?;

    let pop = if let Some(token) = access_token {
        wallet
            .sign_pop_with_ath(method, path, token)
            .map_err(|e| PopError::InvalidEncoding(e.to_string()))?
    } else {
        wallet
            .sign_pop(method, path)
            .map_err(|e| PopError::InvalidEncoding(e.to_string()))?
    };

    Ok(pop.encode())
}

/// Verify X-UBL-POW header (convenience function)
pub fn verify_pop(
    header: &str,
    method: &str,
    path: &str,
    max_skew_secs: i64,
    access_token: Option<&str>,
) -> Result<Did, PopError> {
    let pop = Pop::decode(header)?;
    pop.verify(method, path, max_skew_secs, access_token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::Wallet;

    #[test]
    fn test_pop_roundtrip() {
        let w = Wallet::generate();
        let pop = w.sign_pop("GET", "/test").unwrap();

        let encoded = pop.encode();
        println!("Encoded: {}", encoded);

        // Check wire format: 3 parts separated by .
        let parts: Vec<&str> = encoded.split('.').collect();
        assert_eq!(parts.len(), 3, "Wire format must have 3 parts");

        let decoded = Pop::decode(&encoded).unwrap();
        assert_eq!(decoded.wallet_did, w.did().as_str());
        assert_eq!(decoded.payload.m, "GET");
        assert_eq!(decoded.payload.p, "/test");
        assert_eq!(decoded.payload.v, 1);
    }

    #[test]
    fn test_pop_verify() {
        let w = Wallet::generate();
        let pop = w.sign_pop("POST", "/v1/chips/mint").unwrap();

        let result = pop.verify("POST", "/v1/chips/mint", 300, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), w.did().as_str());
    }

    #[test]
    fn test_pop_with_ath() {
        let w = Wallet::generate();
        let token = "Bearer my-access-token";
        let pop = w.sign_pop_with_ath("POST", "/v1/chips/mint", token).unwrap();

        assert!(pop.payload.ath.is_some());
        let ath = pop.payload.ath.as_ref().unwrap();
        assert!(ath.starts_with("blake3:"), "ath must be blake3:<hex> format");
        assert_eq!(ath.len(), 7 + 64, "ath must be blake3: + 64 hex chars");

        // Verify with correct token
        let result = pop.verify("POST", "/v1/chips/mint", 300, Some(token));
        assert!(result.is_ok());

        // Verify with wrong token should fail
        let result2 = pop.verify("POST", "/v1/chips/mint", 300, Some("wrong-token"));
        assert!(matches!(result2, Err(PopError::TokenMismatch)));
    }

    #[test]
    fn test_pop_request_mismatch() {
        let w = Wallet::generate();
        let pop = w.sign_pop("POST", "/v1/chips/mint").unwrap();

        let result = pop.verify("GET", "/v1/chips/mint", 300, None);
        assert!(matches!(result, Err(PopError::RequestMismatch)));
    }

    #[test]
    fn test_pop_wire_format_decode() {
        let w = Wallet::generate();
        let pop = w.sign_pop("POST", "/t/logline/v1/chip/mint").unwrap();
        let encoded = pop.encode();

        // Manually decode parts
        let parts: Vec<&str> = encoded.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Decode payload
        let payload_bytes = B64URL.decode(parts[0]).unwrap();
        let payload: PopPayloadV1 = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload.v, 1);
        assert_eq!(payload.m, "POST");
        assert_eq!(payload.p, "/t/logline/v1/chip/mint");

        // Signature is 64 bytes
        let sig_bytes = B64URL.decode(parts[1]).unwrap();
        assert_eq!(sig_bytes.len(), 64);

        // Wallet DID
        assert!(parts[2].starts_with("did:key:z"));
    }
}
