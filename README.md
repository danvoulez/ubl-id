# ubl-id — Universal Business Ledger Identity Primitives

[![Crates.io](https://img.shields.io/crates/v/ubl-id.svg)](https://crates.io/crates/ubl-id)
[![Documentation](https://docs.rs/ubl-id/badge.svg)](https://docs.rs/ubl-id)
[![License](https://img.shields.io/crates/l/ubl-id.svg)](LICENSE-MIT)

> **UBL — Universal Business Ledger and Security OS for Agents**
> 
> Audit-ready, EU-grade privacy standards. RFC-0001 compliant.

The **identity kernel** for the UBL ecosystem. Provides unified primitives for:

- **DIDs** — Decentralized Identifiers for entities (users, orgs, agents, apps, wallets)
- **CIDs** — Content Identifiers for immutable data (chips, blueprints, proofs)
- **Wallets** — Ephemeral Ed25519 keypairs for session-based signing
- **PoP** — Proof-of-Possession headers for request authentication (RFC-0001 §6)

## Installation

```toml
[dependencies]
ubl-id = "0.3"

# With Directory resolution
ubl-id = { version = "0.3", features = ["resolve"] }
```

## Quick Start

```rust,ignore
use ubl_id::{Did, DidType, Cid, Wallet};

// Create DIDs for different entity types
let user = Did::ubl(DidType::User, "daniel");      // Human
let org = Did::ubl(DidType::Org, "logline");       // Company
let agent = Did::ubl(DidType::Agent, "gpt4");      // LLM
let app = Did::ubl(DidType::App, "minicontratos"); // Application

// Create a CID from JSON (canonical serialization)
let data = serde_json::json!({"type": "policy", "version": "1.0"});
let cid = Cid::from_json(&data).unwrap();

// Generate an ephemeral wallet for this session
let wallet = Wallet::generate();

// Sign a PoP header for an HTTP request
let pop = wallet.sign_pop("POST", "/v1/chips/mint").unwrap();
// Wire format: payload.sig.wallet_did (RFC-0001)
println!("X-UBL-POW: {}", pop.encode());
```

## PoP Wire Format v1 (RFC-0001)

```
X-UBL-POW: <payload_b64>.<signature_b64>.<wallet_did>
```

Payload structure:
```json
{"v":1,"m":"POST","p":"/t/tenant/v1/action","ts":1704067200,"ath":"blake3:..."}
```

## DID Types

UBL treats **humans and LLMs as equal citizens**:

| DID | Entity Type | Example |
|-----|-------------|---------|
| `did:ubl:user:*` | Human user | `did:ubl:user:daniel` |
| `did:ubl:org:*` | Organization | `did:ubl:org:logline` |
| `did:ubl:agent:*` | **LLM/AI agent** | `did:ubl:agent:gpt4` |
| `did:ubl:app:*` | Application | `did:ubl:app:minicontratos` |
| `did:ubl:wallet:*` | Ephemeral session | `did:ubl:wallet:sess123` |
| `did:key:z*` | Self-certifying key | `did:key:z6Mk...` |

## CID (Content Identifier)

Content-addressed, immutable identifiers using BLAKE3 + canonical JSON:

- **Alphabetically sorted keys**
- **Normalized Unicode (NFC)**
- **No extra whitespace**

When an LLM generates JSON, the server gets identical bytes → identical hash → **zero-trust verification works**.

## Audit-Ready by Design

Every identity operation produces traceable receipts:

```json
{
  "kind": "chip.mint.v1",
  "tenant": "logline",
  "who": {"did": "did:key:z..."},
  "act": {"did": "did:ubl:user:daniel"},
  "trace": {"trace_id": "01HQXYZ...", "ts": 1704067200}
}
```

## EU-Grade Privacy

- **Self-sovereign identity**: Users control their DIDs
- **Minimal disclosure**: PoP headers prove possession without exposing secrets
- **Ephemeral sessions**: Wallets expire, limiting exposure window
- **Content-addressed**: CIDs are just hashes, no PII embedded

## Related Crates

| Crate | Purpose |
|-------|---------|
| [`ubl-auth`](https://crates.io/crates/ubl-auth) | Ed25519 JWT/JWKS verification |
| [`json_atomic`](https://crates.io/crates/json_atomic) | Canonical JSON serialization |
| [`chip_as_code`](https://crates.io/crates/chip_as_code) | Semantic chips with GateBox |

## License

MIT OR Apache-2.0

---

**UBL** — Making AI agents first-class business citizens, with the same audit trail as humans.
