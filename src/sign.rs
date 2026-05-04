// SPDX-License-Identifier: Apache-2.0
//! Ed25519 sign and verify, plus base64url helpers used by the rest of the
//! Handshake stack. Keys are 32-byte raw seeds (RFC 8032 §5.1.5);
//! signatures are 64-byte raw byte strings encoded as base64url-without-padding
//! when serialized into protocol messages (see `_common.json#/$defs/base64url`).

use crate::error::Error;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};

/// An Ed25519 signing keypair (private + derived public).
#[derive(Clone)]
pub struct Keypair {
    inner: SigningKey,
}

impl Keypair {
    /// Generate a fresh keypair using the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut seed = [0_u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Construct a keypair from a 32-byte seed (Ed25519 RFC 8032 §5.1.5).
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            inner: SigningKey::from_bytes(seed),
        }
    }

    /// 32-byte private seed.
    #[must_use]
    pub fn seed(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// 32-byte public key (the value normally exposed in a DID Document).
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.inner.verifying_key().to_bytes()
    }

    /// Sign `message` with Ed25519. Returns the raw 64-byte signature.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.inner.sign(message).to_bytes()
    }

    /// Sign and base64url-encode (no padding) — the form used in protocol
    /// messages.
    #[must_use]
    pub fn sign_b64(&self, message: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(self.sign(message))
    }
}

/// Verify a 64-byte raw signature against a 32-byte public key over `message`.
///
/// # Errors
/// Returns [`Error::SignatureInvalid`] when verification fails or when the
/// public key / signature lengths are wrong.
pub fn verify(public_key: &[u8], signature: &[u8], message: &[u8]) -> Result<(), Error> {
    let pk: [u8; 32] = public_key.try_into().map_err(|_| {
        Error::InvalidKey(format!(
            "expected 32-byte public key, got {}",
            public_key.len()
        ))
    })?;
    let sig: [u8; 64] = signature.try_into().map_err(|_| {
        Error::SignatureInvalid(format!(
            "expected 64-byte signature, got {}",
            signature.len()
        ))
    })?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| Error::InvalidKey(e.to_string()))?;
    let signature = Signature::from_bytes(&sig);
    vk.verify(message, &signature)
        .map_err(|e| Error::SignatureInvalid(e.to_string()))
}

/// Verify a base64url-without-padding signature.
///
/// # Errors
/// Same as [`verify`], plus base64 decoding errors are reported as
/// [`Error::SignatureInvalid`].
pub fn verify_b64(public_key: &[u8], signature_b64: &str, message: &[u8]) -> Result<(), Error> {
    let sig = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .map_err(|e| Error::SignatureInvalid(format!("base64url decode: {e}")))?;
    verify(public_key, &sig, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let kp = Keypair::generate();
        let msg = b"handshake protocol payload";
        let sig = kp.sign(msg);
        verify(&kp.public_key(), &sig, msg).expect("signature should verify");
    }

    #[test]
    fn rejects_tampered_message() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"original");
        let res = verify(&kp.public_key(), &sig, b"tampered");
        assert!(matches!(res, Err(Error::SignatureInvalid(_))));
    }
}
