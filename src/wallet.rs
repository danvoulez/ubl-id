//! Ephemeral Wallet for session-based signing
//!
//! A wallet is a short-lived Ed25519 keypair that can:
//! - Sign PoP (Proof-of-Possession) headers
//! - Be bound to an owner DID
//! - Expire after a TTL
//!
//! # Use Case
//!
//! ```text
//! 1. User authenticates → Bearer JWT (sub = did:ubl:user:daniel)
//! 2. Client generates wallet → did:key:z... (ephemeral)
//! 3. Register wallet with Directory (binds to owner)
//! 4. Use wallet to sign requests → X-UBL-POW header
//! 5. Server verifies: owner authorized, wallet valid, request signed
//! ```

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use crate::did::Did;
use crate::pop::Pop;

/// Wallet errors
#[derive(Debug, Error)]
pub enum WalletError {
    #[error("invalid key encoding: {0}")]
    InvalidKey(String),
    #[error("expired wallet")]
    Expired,
    #[error("signing error: {0}")]
    SigningError(String),
}

/// Ed25519 JWK public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkPub {
    pub kty: String,
    pub crv: String,
    pub x: String,
}

/// An ephemeral wallet (Ed25519 keypair)
#[derive(Clone)]
pub struct Wallet {
    signing_key: SigningKey,
    did: Did,
    created_at: i64,
    ttl_secs: Option<i64>,
}

impl Wallet {
    /// Generate a new random wallet
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let vk = signing_key.verifying_key();
        let did = Did::key_from_ed25519(&vk.to_bytes());
        Self {
            signing_key,
            did,
            created_at: OffsetDateTime::now_utc().unix_timestamp(),
            ttl_secs: None,
        }
    }

    /// Generate a wallet with TTL
    pub fn generate_with_ttl(ttl_secs: i64) -> Self {
        let mut w = Self::generate();
        w.ttl_secs = Some(ttl_secs);
        w
    }

    /// Restore from base64url-encoded private key
    pub fn from_priv_b64(priv_b64: &str) -> Result<Self, WalletError> {
        let bytes = B64URL
            .decode(priv_b64.as_bytes())
            .map_err(|_| WalletError::InvalidKey("bad base64".into()))?;
        let key_bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| WalletError::InvalidKey("expected 32 bytes".into()))?;
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let vk = signing_key.verifying_key();
        let did = Did::key_from_ed25519(&vk.to_bytes());
        Ok(Self {
            signing_key,
            did,
            created_at: OffsetDateTime::now_utc().unix_timestamp(),
            ttl_secs: None,
        })
    }

    /// Get the wallet's DID
    pub fn did(&self) -> &Did {
        &self.did
    }

    /// Get the public key as JWK
    pub fn jwk_pub(&self) -> JwkPub {
        let vk = self.signing_key.verifying_key();
        JwkPub {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: B64URL.encode(vk.to_bytes()),
        }
    }

    /// Get the private key as base64url (for storage)
    pub fn priv_b64(&self) -> String {
        B64URL.encode(self.signing_key.to_bytes())
    }

    /// Get the public key X coordinate as base64url
    pub fn pub_x_b64(&self) -> String {
        B64URL.encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Check if wallet is expired
    pub fn is_expired(&self) -> bool {
        if let Some(ttl) = self.ttl_secs {
            let now = OffsetDateTime::now_utc().unix_timestamp();
            now > self.created_at + ttl
        } else {
            false
        }
    }

    /// Sign a PoP header for an HTTP request
    pub fn sign_pop(&self, method: &str, path: &str) -> Result<Pop, WalletError> {
        if self.is_expired() {
            return Err(WalletError::Expired);
        }
        self.sign_pop_with_ts(method, path, None, None)
    }

    /// Sign a PoP header with token binding (ath = hash of access token)
    pub fn sign_pop_with_ath(
        &self,
        method: &str,
        path: &str,
        access_token: &str,
    ) -> Result<Pop, WalletError> {
        if self.is_expired() {
            return Err(WalletError::Expired);
        }
        self.sign_pop_with_ts(method, path, Some(access_token), None)
    }

    fn sign_pop_with_ts(
        &self,
        method: &str,
        path: &str,
        access_token: Option<&str>,
        ts_override: Option<i64>,
    ) -> Result<Pop, WalletError> {
        let ts = ts_override.unwrap_or_else(|| OffsetDateTime::now_utc().unix_timestamp());
        let msg = format!("{} {}\n{}", method, path, ts);
        let sig = self.signing_key.sign(msg.as_bytes());
        let sig_b64 = B64URL.encode(sig.to_bytes());

        let ath = access_token.map(|tok| {
            let digest = blake3::hash(tok.as_bytes());
            B64URL.encode(digest.as_bytes())
        });

        Ok(Pop {
            wallet_did: self.did.as_str().to_string(),
            ts,
            method: method.to_string(),
            path: path.to_string(),
            sig: sig_b64,
            ath,
        })
    }

    /// Export wallet as JSON for storage
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "did": self.did.as_str(),
            "jwk_pub": self.jwk_pub(),
            "jwk_priv_b64": self.priv_b64(),
            "created_at": self.created_at,
            "ttl_secs": self.ttl_secs
        })
    }
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("did", &self.did)
            .field("created_at", &self.created_at)
            .field("ttl_secs", &self.ttl_secs)
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_generate() {
        let w = Wallet::generate();
        assert!(w.did().as_str().starts_with("did:key:z"));
        assert!(!w.is_expired());
    }

    #[test]
    fn test_wallet_roundtrip() {
        let w1 = Wallet::generate();
        let priv_b64 = w1.priv_b64();
        let w2 = Wallet::from_priv_b64(&priv_b64).unwrap();
        assert_eq!(w1.did().as_str(), w2.did().as_str());
    }

    #[test]
    fn test_wallet_sign_pop() {
        let w = Wallet::generate();
        let pop = w.sign_pop("POST", "/v1/chips/mint").unwrap();
        assert_eq!(pop.wallet_did, w.did().as_str());
        assert_eq!(pop.method, "POST");
        assert_eq!(pop.path, "/v1/chips/mint");
    }
}
