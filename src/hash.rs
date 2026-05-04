// SPDX-License-Identifier: Apache-2.0
//! SHA-256 wrapper — the digest the spec requires (`_common.json#/$defs/hashAlgorithm`).
//!
//! Thin so callers don't depend on `sha2` directly; lets us add SHA3-256
//! later without a breaking change.

use sha2::{Digest, Sha256};

/// Return the 32-byte SHA-256 digest of `bytes`.
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Return the lowercase-hex SHA-256 digest of `bytes` (the encoding used in
/// `hashValue.value` per the spec's `hex` definition).
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha256(bytes))
}
