#![forbid(unsafe_code)]
//! # ubl-id — Universal Business Ledger Identity Primitives
//!
//! The identity kernel for the UBL ecosystem. Provides:
//! - **DIDs** (`did:ubl:*`, `did:key:*`) for entities (users, orgs, agents, apps, wallets)
//! - **CIDs** (`cid:blake3:*`) for content-addressed data (chips, blueprints, proofs)
//! - **Wallets** for ephemeral session keys with PoP (Proof-of-Possession) headers
//!
//! ## LLM-First Design
//!
//! Uses [`json_atomic`] for canonical JSON serialization, ensuring deterministic
//! hashing across all platforms. When an LLM generates JSON, the server gets
//! identical bytes → identical hash → zero-trust verification works.

pub mod did;
pub mod cid;
pub mod wallet;
pub mod pop;
pub mod ident;

#[cfg(feature = "resolve")]
pub mod resolve;

// Re-exports for convenience
pub use did::{Did, DidMethod, DidType};
pub use cid::Cid;
pub use wallet::Wallet;
pub use pop::{Pop, PopPayloadV1, PopError, build_pop_header, verify_pop};
pub use ident::Ident;

/// Re-export json_atomic for downstream canonical serialization
pub use json_atomic;
