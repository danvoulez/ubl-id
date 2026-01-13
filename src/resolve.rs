//! DID and alias resolution against a UBL Directory
//!
//! Requires the `resolve` feature:
//! ```toml
//! ubl-id = { version = "0.2", features = ["resolve"] }
//! ```

use serde::{Deserialize, Serialize};

/// Subject information from the Directory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub did: String,
    pub kind: String,
    pub display_name: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Wallet registration in the Directory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    pub did: String,
    pub owner_did: String,
    pub expires_at: Option<i64>,
}

/// Resolve a `namespace/name` alias to a DID
pub fn alias(dir_base: &str, namespace: &str, name: &str) -> Result<Option<String>, String> {
    let url = format!(
        "{}/v1/aliases/{}/{}",
        dir_base.trim_end_matches('/'),
        namespace,
        name
    );
    let resp = ureq::get(&url).call();
    match resp {
        Ok(r) => {
            let v: serde_json::Value = r.into_json().map_err(|e| e.to_string())?;
            Ok(v.get("did").and_then(|s| s.as_str()).map(|s| s.to_string()))
        }
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(e) => Err(format!("{}", e)),
    }
}

/// Resolve a DID to subject information
pub fn subject(dir_base: &str, did: &str) -> Result<Option<Subject>, String> {
    // Simple percent-encoding for DID colons
    let encoded_did = did.replace(':', "%3A");
    let url = format!(
        "{}/v1/subjects/{}",
        dir_base.trim_end_matches('/'),
        encoded_did
    );
    let resp = ureq::get(&url).call();
    match resp {
        Ok(r) => {
            let s: Subject = r.into_json().map_err(|e| e.to_string())?;
            Ok(Some(s))
        }
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(e) => Err(format!("{}", e)),
    }
}

/// Lookup wallet information (owner binding)
pub fn wallet(dir_base: &str, wallet_did: &str) -> Result<Option<WalletInfo>, String> {
    let encoded_did = wallet_did.replace(':', "%3A");
    let url = format!(
        "{}/v1/wallets/{}",
        dir_base.trim_end_matches('/'),
        encoded_did
    );
    let resp = ureq::get(&url).call();
    match resp {
        Ok(r) => {
            let w: WalletInfo = r.into_json().map_err(|e| e.to_string())?;
            Ok(Some(w))
        }
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(e) => Err(format!("{}", e)),
    }
}

/// Register a wallet with the Directory
pub fn register_wallet(
    dir_base: &str,
    bearer_token: &str,
    pub_jwk: &crate::wallet::JwkPub,
    ttl_secs: Option<i64>,
) -> Result<WalletInfo, String> {
    let url = format!("{}/v1/wallets", dir_base.trim_end_matches('/'));
    let body = serde_json::json!({
        "pub_jwk": pub_jwk,
        "ttl_secs": ttl_secs.unwrap_or(3600)
    });
    let resp = ureq::post(&url)
        .set("authorization", &format!("Bearer {}", bearer_token))
        .set("content-type", "application/json")
        .send_json(&body)
        .map_err(|e| format!("request failed: {}", e))?;
    resp.into_json().map_err(|e| format!("json error: {}", e))
}
