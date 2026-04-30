//! Handshake protocol — canonical Rust implementation.
//!
//! This crate ships the cryptographic primitives the entire Handshake stack
//! depends on:
//!
//! * [`jcs::canonicalize`] — RFC 8785 JSON canonicalization. We delegate to the
//!   `serde_jcs` crate (Cisco-maintained, RFC 8785-compliant numbers including
//!   the ECMAScript 6.1.6.1 ToString algorithm). Wrapping it lets us evolve the
//!   API surface without breaking callers if we ever swap implementations.
//! * [`hash::sha256`] / [`hash::sha256_hex`] — the spec-required digest.
//! * [`sign::Keypair`] / [`sign::verify`] / [`sign::verify_b64`] —
//!   Ed25519 (RFC 8032).
//! * [`mldsa::Keypair`] / [`mldsa::verify`] — ML-DSA-65 (FIPS 204), the
//!   post-quantum scheme listed in `_common.json#/$defs/signatureAlgorithm`
//!   alongside EdDSA. Phase 2+ wires it into the protocol negotiation logic.
//! * [`models`] — serde-derived structs mirroring the v0.2.3 JSON Schemas
//!   (`packages/handshake-spec/schemas/v0.2.3/`). Round-tripping a model
//!   through `serde_json` and then `jcs::canonicalize` gives the bytes you
//!   sign over.
//!
//! The Python (PyO3) and TypeScript (NAPI-RS) SDKs in this monorepo are FFI
//! shims that re-export these functions byte-for-byte. The Go SDK is a parallel
//! native implementation tested for byte-equality in `tests/conformance/`.

pub mod error;
pub mod hash;
pub mod jcs;
pub mod mldsa;
pub mod models;
pub mod sign;

pub use error::Error;

/// Spec version this crate implements. Pinned so callers can detect mismatch
/// against the schemas in `packages/handshake-spec/`.
pub const SPEC_VERSION: &str = "0.2.3";
