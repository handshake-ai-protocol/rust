//! Crate-wide error type. Kept narrow so callers can pattern-match on causes
//! (signature failure vs. canonicalization failure vs. malformed key) without
//! needing string parsing.

use thiserror::Error;

/// Errors returned by the handshake crate. Every public function returns
/// `Result<_, Error>` so FFI callers (PyO3 / NAPI-RS) can map cause types
/// to language-native exceptions.
#[derive(Debug, Error)]
pub enum Error {
    /// JCS canonicalization failed (e.g. non-finite number).
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),

    /// Signature did not verify, or had wrong length / encoding.
    #[error("signature invalid: {0}")]
    SignatureInvalid(String),

    /// Public or private key was malformed (wrong length, invalid encoding).
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Schema validation failure for a parsed model.
    #[error("model invalid: {0}")]
    InvalidModel(String),

    /// JSON serialization or deserialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
