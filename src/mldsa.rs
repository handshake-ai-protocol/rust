//! ML-DSA-65 — FIPS 204 post-quantum digital signatures.
//!
//! ML-DSA-65 is one of the three signature algorithms enumerated by the spec
//! (`_common.json#/$defs/signatureAlgorithm`):
//!
//! ```json
//! "enum": ["EdDSA", "ML-DSA-65", "Hybrid-EdDSA-MLDSA65"]
//! ```
//!
//! v0.2.x messages REQUIRE EdDSA; ML-DSA-65 is RECOMMENDED for negotiation in
//! v0.3+. We ship the primitive in Phase 1 so the negotiation logic in Phase 2
//! has it available and so the post-quantum migration path is exercised by
//! the conformance suite from day one.
//!
//! Wire format (mirrored byte-for-byte by Go via `cloudflare/circl`):
//!
//! | Item        | Bytes |
//! |-------------|-------|
//! | Public key  | 1952  |
//! | Private key | 4032  |
//! | Signature   | 3309  |
//!
//! Signatures are emitted in the spec-required base64url-without-padding form
//! (`_common.json#/$defs/base64url`).
//!
//! Implementation note: we use the RustCrypto `ml-dsa` crate, which exposes
//! both hedged and deterministic signing variants. We pin **deterministic**
//! signing here because conformance demands byte-equal signatures across
//! Rust ↔ Go for the KAT.

use crate::error::Error;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ml_dsa::{signature::Verifier, KeyGen, MlDsa65};
use rand_core::{OsRng, RngCore};

/// Public-key length for ML-DSA-65 (FIPS 204).
pub const PUBLIC_KEY_LEN: usize = 1952;
/// Private-key length for ML-DSA-65 (FIPS 204).
pub const PRIVATE_KEY_LEN: usize = 4032;
/// Signature length for ML-DSA-65 (FIPS 204).
pub const SIGNATURE_LEN: usize = 3309;

/// An ML-DSA-65 keypair. The signing key is held in memory; the verifying key
/// is derived on demand.
pub struct Keypair {
    keypair: ml_dsa::KeyPair<MlDsa65>,
}

impl Keypair {
    /// Generate a fresh keypair using the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut seed = [0_u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Construct a keypair from a 32-byte seed (FIPS 204 ξ).
    ///
    /// Given the same seed, every conforming implementation MUST produce the
    /// same (public, private) pair. Used to seed the ML-DSA-65 KAT in
    /// `tests/conformance/fixtures/jcs.json`.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let arr: ml_dsa::B32 = (*seed).into();
        let keypair = MlDsa65::key_gen_internal(&arr);
        Self { keypair }
    }

    /// Public-key bytes (length [`PUBLIC_KEY_LEN`]).
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        use ml_dsa::EncodedVerifyingKey;
        let encoded: EncodedVerifyingKey<MlDsa65> = self.keypair.verifying_key().encode();
        encoded.to_vec()
    }

    /// Private-key bytes (length [`PRIVATE_KEY_LEN`]).
    #[must_use]
    pub fn private_key(&self) -> Vec<u8> {
        use ml_dsa::EncodedSigningKey;
        let encoded: EncodedSigningKey<MlDsa65> = self.keypair.signing_key().encode();
        encoded.to_vec()
    }

    /// Deterministically sign `message` (FIPS 204 §5.5 deterministic variant
    /// with empty context). Returns the raw signature
    /// (length [`SIGNATURE_LEN`]).
    ///
    /// Determinism is required for the cross-implementation KAT to pass — Go
    /// (`cloudflare/circl`) calls `SignTo(..., randomized=false, ...)` to match.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig = self
            .keypair
            .signing_key()
            .sign_deterministic(message, &[])
            .expect("ML-DSA-65 deterministic signing is infallible for valid keys");
        sig.encode().to_vec()
    }

    /// Sign and base64url-encode (no padding) — the form used in protocol
    /// messages.
    #[must_use]
    pub fn sign_b64(&self, message: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(self.sign(message))
    }
}

/// Verify an ML-DSA-65 signature.
///
/// # Errors
/// Returns [`Error::SignatureInvalid`] for verification failure, malformed
/// signature length, or malformed public key length.
pub fn verify(public_key: &[u8], signature: &[u8], message: &[u8]) -> Result<(), Error> {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, VerifyingKey};

    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(Error::InvalidKey(format!(
            "expected {PUBLIC_KEY_LEN}-byte ML-DSA-65 public key, got {}",
            public_key.len()
        )));
    }
    if signature.len() != SIGNATURE_LEN {
        return Err(Error::SignatureInvalid(format!(
            "expected {SIGNATURE_LEN}-byte ML-DSA-65 signature, got {}",
            signature.len()
        )));
    }
    let pk_bytes: EncodedVerifyingKey<MlDsa65> = <[u8; PUBLIC_KEY_LEN]>::try_from(public_key)
        .map_err(|_| Error::InvalidKey("public key length conversion".into()))?
        .into();
    let vk = VerifyingKey::<MlDsa65>::decode(&pk_bytes);
    let sig_bytes: EncodedSignature<MlDsa65> = <[u8; SIGNATURE_LEN]>::try_from(signature)
        .map_err(|_| Error::SignatureInvalid("signature length conversion".into()))?
        .into();
    let sig = ml_dsa::Signature::<MlDsa65>::decode(&sig_bytes)
        .ok_or_else(|| Error::SignatureInvalid("signature decode failed".into()))?;
    vk.verify(message, &sig)
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
    fn deterministic_keygen_from_seed() {
        let seed = [42_u8; 32];
        let kp1 = Keypair::from_seed(&seed);
        let kp2 = Keypair::from_seed(&seed);
        assert_eq!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn round_trip() {
        let kp = Keypair::generate();
        let msg = b"handshake protocol payload";
        let sig = kp.sign(msg);
        assert_eq!(sig.len(), SIGNATURE_LEN);
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
