//! PoP (Proof-of-Possession) headers for request signing
//!
//! The `X-UBL-POW` header proves that a wallet possesses the private key
//! and authorizes a specific HTTP request.
//!
//! # Format
//!
//! Base64url-encoded JSON:
//! ```json
//! {
//!   "wallet_did": "did:key:z...",
//!   "ts": 1704067200,
//!   "method": "POST",
//!   "path": "/v1/chips/mint",
//!   "sig": "<base64url signature>",
//!   "ath": "<base64url hash of access token>" // optional
//! }
//! ```
//!
//! # Signature
//!
//! Signs: `"{METHOD} {PATH}\n{TS}"`
//!
//! # Token Binding (ath)
//!
//! Optional `ath` = base64url(blake3(access_token)) binds the PoP to
//! a specific Bearer token, preventing token substitution attacks.

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
}

/// Proof-of-Possession header content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pop {
    pub wallet_did: String,
    pub ts: i64,
    pub method: String,
    pub path: String,
    pub sig: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
}

impl Pop {
    /// Encode as X-UBL-POW header value
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).unwrap_or_default();
        B64URL.encode(json)
    }

    /// Decode from X-UBL-POW header value
    pub fn decode(header: &str) -> Result<Self, PopError> {
        let bytes = B64URL
            .decode(header.as_bytes())
            .map_err(|_| PopError::InvalidEncoding("base64".into()))?;
        serde_json::from_slice(&bytes).map_err(|e| PopError::InvalidJson(e.to_string()))
    }

    /// Verify the PoP against expected values
    pub fn verify(
        &self,
        expected_method: &str,
        expected_path: &str,
        max_skew_secs: i64,
        access_token: Option<&str>,
    ) -> Result<Did, PopError> {
        // Check request binding
        if self.method != expected_method || self.path != expected_path {
            return Err(PopError::RequestMismatch);
        }

        // Check timestamp
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if (now - self.ts).abs() > max_skew_secs {
            return Err(PopError::TimestampSkew);
        }

        // Check token binding if present
        if let Some(ath) = &self.ath {
            let token = access_token.ok_or(PopError::TokenMismatch)?;
            let expected_ath = B64URL.encode(blake3::hash(token.as_bytes()).as_bytes());
            if ath != &expected_ath {
                return Err(PopError::TokenMismatch);
            }
        }

        // Parse wallet DID and extract public key
        let did = Did::parse(&self.wallet_did).map_err(|_| PopError::InvalidDid)?;
        let pk_bytes = did.key_bytes().ok_or(PopError::InvalidDid)?;
        let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| PopError::InvalidDid)?;

        // Verify signature
        let msg = format!("{} {}\n{}", self.method, self.path, self.ts);
        let sig_bytes = B64URL
            .decode(self.sig.as_bytes())
            .map_err(|_| PopError::InvalidEncoding("sig".into()))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| PopError::InvalidEncoding("sig len".into()))?;
        let sig = Signature::from_bytes(&sig_arr);

        vk.verify_strict(msg.as_bytes(), &sig)
            .map_err(|_| PopError::SignatureFailed)?;

        Ok(did)
    }
}

/// Build X-UBL-POW header value (convenience function)
pub fn build_pop_header(
    method: &str,
    path: &str,
    priv_b64: &str,
    access_token: Option<&str>,
) -> Result<String, PopError> {
    let wallet =
        crate::wallet::Wallet::from_priv_b64(priv_b64).map_err(|e| PopError::InvalidEncoding(e.to_string()))?;

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
        let decoded = Pop::decode(&encoded).unwrap();

        assert_eq!(decoded.wallet_did, pop.wallet_did);
        assert_eq!(decoded.method, "GET");
        assert_eq!(decoded.path, "/test");
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
        let token = "my-access-token";
        let pop = w.sign_pop_with_ath("POST", "/v1/chips/mint", token).unwrap();

        assert!(pop.ath.is_some());

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
}
