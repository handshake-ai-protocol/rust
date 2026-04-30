//! Serde models mirroring the v0.2.3 JSON Schemas under
//! `packages/handshake-spec/schemas/v0.2.3/`. A `tests/schema_consistency.rs`
//! integration test (Phase 1.1) compares each model's JSON Schema export
//! against the on-disk schema file; CI fails on drift.
//!
//! Round-tripping a model through serde and then [`crate::jcs::canonicalize`]
//! produces the byte string EdDSA / ML-DSA-65 signatures cover.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `_common.json#/$defs/signatureAlgorithm`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    #[serde(rename = "EdDSA")]
    EdDsa,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
    #[serde(rename = "Hybrid-EdDSA-MLDSA65")]
    HybridEdDsaMlDsa65,
}

/// `_common.json#/$defs/hashAlgorithm`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    #[serde(rename = "sha-256")]
    Sha256,
    #[serde(rename = "sha3-256")]
    Sha3_256,
}

/// `_common.json#/$defs/hashValue`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashValue {
    pub alg: HashAlgorithm,
    /// lowercase hex
    pub value: String,
}

/// `_common.json#/$defs/capability`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub constraints: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub delegable: Option<bool>,
}

/// `delegation-token.json`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationToken {
    pub version: String,
    pub kind: String,
    pub id: String,
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: String,
    pub nbf: String,
    pub exp: String,
    pub capabilities: Vec<Capability>,
    pub sub_delegation_depth_remaining: u32,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub parent_delegation_id: Option<String>,
    pub alg: SignatureAlgorithm,
    /// base64url-without-padding. Omitted when computing the bytes-to-sign;
    /// see `with_signature_field_omitted` in conformance helpers.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signature: Option<String>,
}

/// `handshake-request.json`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    pub version: String,
    pub kind: String,
    pub id: String,
    pub iss: String,
    pub aud: String,
    pub iat: String,
    pub nonce: String,
    pub agent_attestation: Value,
    pub capability: Capability,
    pub delegation_chain: Vec<DelegationToken>,
    pub alg: SignatureAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signature: Option<String>,
}

/// `receipt.json`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub version: String,
    pub kind: String,
    pub id: String,
    pub handshake_id: String,
    pub iss: String,
    pub sub: String,
    pub action: String,
    pub executed_at: String,
    pub result: ReceiptResult,
    pub result_hash: HashValue,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub result_summary: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub upstream_receipts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub registry_anchor: Option<Value>,
    pub alg: SignatureAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReceiptResult {
    Ok,
    Error,
    Partial,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn delegation_token_round_trip() {
        let raw = json!({
            "version": "0.2.3",
            "kind": "DelegationToken",
            "id": "dt_01HK4ZQ7M3X9R5N2P8V0YJF7B3",
            "iss": "did:hsk:user:alice@example.com",
            "sub": "did:hsk:agent:abc",
            "aud": "did:hsk:agent:abc",
            "iat": "2026-04-29T14:02:11Z",
            "nbf": "2026-04-29T14:02:11Z",
            "exp": "2026-04-29T14:12:11Z",
            "capabilities": [{"name": "billing.invoices.read"}],
            "sub_delegation_depth_remaining": 0,
            "alg": "EdDSA",
            "signature": "AAAA"
        });
        let dt: DelegationToken = serde_json::from_value(raw.clone()).expect("parse");
        let back = serde_json::to_value(&dt).expect("serialize");
        assert_eq!(back["alg"], "EdDSA");
        assert_eq!(back["id"], "dt_01HK4ZQ7M3X9R5N2P8V0YJF7B3");
    }
}
