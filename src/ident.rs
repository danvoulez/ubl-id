//! Unified identifier type for the UBL ecosystem
//!
//! An `Ident` can be either:
//! - A **DID** (who): `did:ubl:*`, `did:key:*`, `did:web:*`
//! - A **CID** (what): `cid:blake3:*`
//!
//! # Examples
//!
//! ```
//! use ubl_id::Ident;
//!
//! let user = Ident::parse("did:ubl:user:daniel").unwrap();
//! assert!(user.is_did());
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

use crate::cid::{Cid, CidError};
use crate::did::{Did, DidError};

/// Ident parsing errors
#[derive(Debug, Error)]
pub enum IdentError {
    #[error("unknown identifier scheme: {0}")]
    UnknownScheme(String),
    #[error("DID error: {0}")]
    Did(#[from] DidError),
    #[error("CID error: {0}")]
    Cid(#[from] CidError),
}

/// A universal UBL identifier (DID or CID)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Ident {
    /// A decentralized identifier (entity)
    Did(Did),
    /// A content identifier (data)
    Cid(Cid),
}

impl Ident {
    /// Parse any UBL identifier
    pub fn parse(s: &str) -> Result<Self, IdentError> {
        if s.starts_with("did:") {
            Ok(Ident::Did(Did::parse(s)?))
        } else if s.starts_with("cid:") {
            Ok(Ident::Cid(Cid::parse(s)?))
        } else {
            Err(IdentError::UnknownScheme(
                s.split(':').next().unwrap_or("").to_string(),
            ))
        }
    }

    /// Is this a DID?
    pub fn is_did(&self) -> bool {
        matches!(self, Ident::Did(_))
    }

    /// Is this a CID?
    pub fn is_cid(&self) -> bool {
        matches!(self, Ident::Cid(_))
    }

    /// Get as DID if it is one
    pub fn as_did(&self) -> Option<&Did> {
        match self {
            Ident::Did(d) => Some(d),
            _ => None,
        }
    }

    /// Get as CID if it is one
    pub fn as_cid(&self) -> Option<&Cid> {
        match self {
            Ident::Cid(c) => Some(c),
            _ => None,
        }
    }

    /// Get the string representation
    pub fn as_str(&self) -> &str {
        match self {
            Ident::Did(d) => d.as_str(),
            Ident::Cid(c) => c.as_str(),
        }
    }

    /// Can this identifier sign things?
    /// DIDs can (they have keys), CIDs cannot (they're just hashes)
    pub fn can_sign(&self) -> bool {
        match self {
            Ident::Did(d) => d.can_sign(),
            Ident::Cid(_) => false,
        }
    }
}

impl fmt::Display for Ident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Ident {
    type Err = IdentError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ident::parse(s)
    }
}

impl From<Did> for Ident {
    fn from(d: Did) -> Self {
        Ident::Did(d)
    }
}

impl From<Cid> for Ident {
    fn from(c: Cid) -> Self {
        Ident::Cid(c)
    }
}

impl Serialize for Ident {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Ident {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ident::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ident_parse_did() {
        let ident = Ident::parse("did:ubl:user:daniel").unwrap();
        assert!(ident.is_did());
        assert!(!ident.is_cid());
        assert!(ident.can_sign());
    }

    #[test]
    fn test_ident_parse_cid() {
        let ident = Ident::parse(
            "cid:blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        )
        .unwrap();
        assert!(ident.is_cid());
        assert!(!ident.is_did());
        assert!(!ident.can_sign());
    }

    #[test]
    fn test_ident_unknown_scheme() {
        let result = Ident::parse("foo:bar:baz");
        assert!(matches!(result, Err(IdentError::UnknownScheme(_))));
    }

    #[test]
    fn test_ident_serde() {
        let ident = Ident::parse("did:ubl:org:logline").unwrap();
        let json = serde_json::to_string(&ident).unwrap();
        assert_eq!(json, "\"did:ubl:org:logline\"");

        let parsed: Ident = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ident);
    }
}
