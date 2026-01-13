//! CID (Content Identifier) for content-addressed data
//!
//! Uses BLAKE3 for fast, secure hashing with canonical JSON serialization.
//!
//! # Format
//!
//! ```text
//! cid:blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
//! ```
//!
//! # LLM-First Design
//!
//! Uses `json_atomic::canonize()` for deterministic serialization:
//! - Alphabetically sorted keys
//! - Normalized Unicode (NFC)
//! - No extra whitespace
//!
//! This ensures identical content → identical CID across all platforms.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// CID errors
#[derive(Debug, Error)]
pub enum CidError {
    #[error("invalid CID format: {0}")]
    InvalidFormat(String),
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("invalid hash encoding: {0}")]
    InvalidEncoding(String),
    #[error("json serialization error: {0}")]
    JsonError(String),
}

/// A Content Identifier (hash of canonical content)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cid {
    /// Full CID string: `cid:blake3:<hex>`
    #[serde(rename = "cid")]
    raw: String,
    /// Just the hex hash portion
    #[serde(skip)]
    hash: String,
}

impl Cid {
    /// Create a CID from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let hash = blake3::hash(bytes);
        let hex = hash.to_hex().to_string();
        Self {
            raw: format!("cid:blake3:{}", hex),
            hash: hex,
        }
    }

    /// Create a CID from any serializable value using canonical JSON
    pub fn from_json<T: Serialize>(value: &T) -> Result<Self, CidError> {
        let bytes = json_atomic::canonize(value).map_err(|e| CidError::JsonError(e.to_string()))?;
        Ok(Self::from_bytes(&bytes))
    }

    /// Parse a CID string
    pub fn parse(s: &str) -> Result<Self, CidError> {
        if !s.starts_with("cid:") {
            return Err(CidError::InvalidFormat("must start with 'cid:'".into()));
        }
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(CidError::InvalidFormat("expected cid:algo:hash".into()));
        }
        if parts[1] != "blake3" {
            return Err(CidError::UnsupportedAlgorithm(parts[1].to_string()));
        }
        let hash = parts[2];
        if hash.len() != 64 {
            return Err(CidError::InvalidEncoding("blake3 hash must be 64 hex chars".into()));
        }
        // Validate hex
        if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(CidError::InvalidEncoding("invalid hex characters".into()));
        }
        Ok(Self {
            raw: s.to_string(),
            hash: hash.to_string(),
        })
    }

    /// Get the full CID string
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Get just the hash portion (64 hex chars)
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// Get the hash as bytes
    pub fn hash_bytes(&self) -> Option<[u8; 32]> {
        let bytes: Vec<u8> = (0..64)
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&self.hash[i..i + 2], 16).ok())
            .collect();
        bytes.try_into().ok()
    }

    /// Verify that given bytes match this CID
    pub fn verify(&self, bytes: &[u8]) -> bool {
        let computed = Self::from_bytes(bytes);
        computed.hash == self.hash
    }

    /// Verify that a JSON value matches this CID
    pub fn verify_json<T: Serialize>(&self, value: &T) -> bool {
        match json_atomic::canonize(value) {
            Ok(bytes) => self.verify(&bytes),
            Err(_) => false,
        }
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}

impl FromStr for Cid {
    type Err = CidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Cid::parse(s)
    }
}

impl AsRef<str> for Cid {
    fn as_ref(&self) -> &str {
        &self.raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_cid_from_bytes() {
        let cid = Cid::from_bytes(b"hello world");
        assert!(cid.as_str().starts_with("cid:blake3:"));
        assert_eq!(cid.hash().len(), 64);
    }

    #[test]
    fn test_cid_from_json() {
        let obj = json!({"a": 1, "b": 2});
        let cid = Cid::from_json(&obj).unwrap();
        assert!(cid.as_str().starts_with("cid:blake3:"));
        
        // Same content → same CID
        let obj2 = json!({"b": 2, "a": 1}); // Different key order
        let cid2 = Cid::from_json(&obj2).unwrap();
        assert_eq!(cid.hash(), cid2.hash()); // json_atomic sorts keys!
    }

    #[test]
    fn test_cid_parse() {
        let s = "cid:blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
        let cid = Cid::parse(s).unwrap();
        assert_eq!(cid.as_str(), s);
        assert_eq!(cid.hash().len(), 64);
    }

    #[test]
    fn test_cid_verify() {
        let data = b"test data";
        let cid = Cid::from_bytes(data);
        assert!(cid.verify(data));
        assert!(!cid.verify(b"wrong data"));
    }
}
