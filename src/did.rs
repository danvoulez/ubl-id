//! DID (Decentralized Identifier) types and utilities
//!
//! Supports multiple DID methods:
//! - `did:ubl:*` — UBL native identifiers
//! - `did:key:*` — Self-certifying Ed25519 keys
//! - `did:web:*` — Domain-linked identifiers
//!
//! # UBL DID Types
//!
//! ```text
//! did:ubl:user:daniel       — Human user
//! did:ubl:org:logline       — Organization
//! did:ubl:agent:gpt4        — LLM/AI agent
//! did:ubl:app:minicontratos — Application
//! did:ubl:wallet:sess123    — Ephemeral wallet/session
//! did:ubl:service:registry  — System service
//! ```

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// DID parsing/validation errors
#[derive(Debug, Error)]
pub enum DidError {
    #[error("invalid DID format: {0}")]
    InvalidFormat(String),
    #[error("unsupported DID method: {0}")]
    UnsupportedMethod(String),
    #[error("invalid UBL type: {0}")]
    InvalidType(String),
    #[error("invalid key encoding: {0}")]
    InvalidKeyEncoding(String),
}

/// DID method (the second component after `did:`)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DidMethod {
    /// UBL native: `did:ubl:type:id`
    #[default]
    Ubl,
    /// Self-certifying key: `did:key:z...`
    Key,
    /// Domain-linked: `did:web:example.com`
    Web,
}

impl fmt::Display for DidMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DidMethod::Ubl => write!(f, "ubl"),
            DidMethod::Key => write!(f, "key"),
            DidMethod::Web => write!(f, "web"),
        }
    }
}

/// UBL entity type (for `did:ubl:type:id`)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DidType {
    /// Human user
    User,
    /// Organization/company
    Org,
    /// LLM/AI agent
    Agent,
    /// Application
    App,
    /// Ephemeral wallet/session
    Wallet,
    /// System service
    Service,
}

impl fmt::Display for DidType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DidType::User => write!(f, "user"),
            DidType::Org => write!(f, "org"),
            DidType::Agent => write!(f, "agent"),
            DidType::App => write!(f, "app"),
            DidType::Wallet => write!(f, "wallet"),
            DidType::Service => write!(f, "service"),
        }
    }
}

impl FromStr for DidType {
    type Err = DidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(DidType::User),
            "org" => Ok(DidType::Org),
            "agent" => Ok(DidType::Agent),
            "app" => Ok(DidType::App),
            "wallet" => Ok(DidType::Wallet),
            "service" => Ok(DidType::Service),
            _ => Err(DidError::InvalidType(s.to_string())),
        }
    }
}

/// A Decentralized Identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did {
    /// Full DID string
    #[serde(rename = "id")]
    raw: String,
    /// Parsed method
    #[serde(skip)]
    method: DidMethod,
}

impl Did {
    /// Parse a DID string
    pub fn parse(s: &str) -> Result<Self, DidError> {
        if !s.starts_with("did:") {
            return Err(DidError::InvalidFormat("must start with 'did:'".into()));
        }
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        if parts.len() < 3 {
            return Err(DidError::InvalidFormat("missing method or id".into()));
        }
        let method = match parts[1] {
            "ubl" => DidMethod::Ubl,
            "key" => DidMethod::Key,
            "web" => DidMethod::Web,
            m => return Err(DidError::UnsupportedMethod(m.to_string())),
        };
        Ok(Self {
            raw: s.to_string(),
            method,
        })
    }

    /// Create a `did:ubl:type:id`
    pub fn ubl(typ: DidType, id: &str) -> Self {
        Self {
            raw: format!("did:ubl:{}:{}", typ, id),
            method: DidMethod::Ubl,
        }
    }

    /// Create a `did:key:z...` from Ed25519 public key (UBL-compatible format)
    pub fn key_from_ed25519(pk32: &[u8; 32]) -> Self {
        let raw = format!("did:key:z{}", B64URL.encode(pk32));
        Self {
            raw,
            method: DidMethod::Key,
        }
    }

    /// Create a `did:key:z...` from Ed25519 public key (W3C multicodec format)
    pub fn key_from_ed25519_w3c(pk32: &[u8; 32]) -> Self {
        let mut v = vec![0xed, 0x01]; // Ed25519 multicodec prefix
        v.extend_from_slice(pk32);
        let raw = format!("did:key:z{}", bs58::encode(v).into_string());
        Self {
            raw,
            method: DidMethod::Key,
        }
    }

    /// Create a `did:web:domain`
    pub fn web(domain: &str) -> Self {
        Self {
            raw: format!("did:web:{}", domain),
            method: DidMethod::Web,
        }
    }

    /// Get the full DID string
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Get the DID method
    pub fn method(&self) -> &DidMethod {
        &self.method
    }

    /// For `did:ubl:type:id`, get the type
    pub fn ubl_type(&self) -> Option<DidType> {
        if self.method != DidMethod::Ubl {
            return None;
        }
        let parts: Vec<&str> = self.raw.splitn(4, ':').collect();
        if parts.len() >= 3 {
            parts[2].parse().ok()
        } else {
            None
        }
    }

    /// For `did:ubl:type:id`, get the id
    pub fn ubl_id(&self) -> Option<&str> {
        if self.method != DidMethod::Ubl {
            return None;
        }
        let parts: Vec<&str> = self.raw.splitn(4, ':').collect();
        if parts.len() >= 4 {
            Some(parts[3])
        } else {
            None
        }
    }

    /// For `did:key:z...`, extract the Ed25519 public key bytes (UBL format)
    pub fn key_bytes(&self) -> Option<[u8; 32]> {
        if self.method != DidMethod::Key {
            return None;
        }
        let key_part = self.raw.strip_prefix("did:key:z")?;
        let bytes = B64URL.decode(key_part.as_bytes()).ok()?;
        bytes.try_into().ok()
    }

    /// Can this DID sign things? (has associated private key capability)
    pub fn can_sign(&self) -> bool {
        matches!(self.method, DidMethod::Key | DidMethod::Ubl)
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}

impl FromStr for Did {
    type Err = DidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Did::parse(s)
    }
}

impl AsRef<str> for Did {
    fn as_ref(&self) -> &str {
        &self.raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_ubl() {
        let did = Did::ubl(DidType::User, "daniel");
        assert_eq!(did.as_str(), "did:ubl:user:daniel");
        assert_eq!(did.method(), &DidMethod::Ubl);
        assert_eq!(did.ubl_type(), Some(DidType::User));
        assert_eq!(did.ubl_id(), Some("daniel"));
    }

    #[test]
    fn test_did_key() {
        let pk = [1u8; 32];
        let did = Did::key_from_ed25519(&pk);
        assert!(did.as_str().starts_with("did:key:z"));
        assert_eq!(did.method(), &DidMethod::Key);
        assert_eq!(did.key_bytes(), Some(pk));
    }

    #[test]
    fn test_did_parse() {
        let did = Did::parse("did:ubl:agent:gpt4").unwrap();
        assert_eq!(did.ubl_type(), Some(DidType::Agent));
        assert_eq!(did.ubl_id(), Some("gpt4"));
    }
}
