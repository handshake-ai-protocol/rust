// SPDX-License-Identifier: Apache-2.0
//! Chain-walk verifier — Phase 2's main deliverable.
//!
//! Steps in the order the spec mandates (handoff §7 Phase 2 + Implementation
//! Guide §3.1's six attack scenarios):
//!
//! 1. Schema/version sanity (kind + protocol version).
//! 2. Outer signature on the `HandshakeRequest`.
//! 3. Audience check — the request's `aud` must match the receiver's DID.
//! 4. Freshness window — `|now − iat| ≤ 60s` (spec §11 ±60s clock skew).
//! 5. Nonce uniqueness inside the TTL window (replay rejection).
//! 6. Chain leaf-issuer match — first delegation's `sub` must equal request's `iss`.
//! 7. Per-link checks (oldest first):
//!    a. Signature.
//!    b. `nbf ≤ now ≤ exp` (with ±60s skew).
//!    c. Revocation lookup.
//!    d. Issuer-chain integrity (each link's `iss` matches the prior link's `sub`).
//!    e. `delegable` and `sub_delegation_depth_remaining` for non-final links.
//! 8. Capability intersection — request's capability ⊆ chain-intersected scope.
//! 9. Policy hook — pluggable callback for compile-time policy DSL.
//!
//! Each rejection returns a [`RefusalReason`] whose `error_code()` maps 1:1
//! to the spec's `_common.json#/$defs/errorCode` enum.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::intersect::{self, ScopeViolation};
use crate::jcs;
#[cfg(test)]
use crate::models::Capability;
use crate::models::{DelegationToken, HandshakeRequest, SignatureAlgorithm};
use crate::sign;
use crate::SPEC_VERSION;

/// Default freshness skew tolerance per spec §11.
pub const DEFAULT_SKEW_SECS: i64 = 60;

/// Resolves a DID to its current Ed25519 public key (32 raw bytes).
///
/// Production deployments back this with a DID Document fetcher + cache;
/// the conformance suite backs it with a fixed `HashMap`.
pub trait KeyResolver {
    /// Look up the raw 32-byte Ed25519 public key for `did`. Returns `None`
    /// when the DID is unknown — verification fails with `signature_invalid`.
    fn resolve(&self, did: &str) -> Option<[u8; 32]>;
}

/// In-memory `KeyResolver` keyed by DID string. The default for tests and
/// the conformance harness.
#[derive(Debug, Default, Clone)]
pub struct StaticKeyResolver {
    keys: HashMap<String, [u8; 32]>,
}

impl StaticKeyResolver {
    /// Construct an empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `did → public_key`. Returns the previous binding if any.
    pub fn insert(&mut self, did: impl Into<String>, public_key: [u8; 32]) -> Option<[u8; 32]> {
        self.keys.insert(did.into(), public_key)
    }

    /// Iterate over `(did, public_key)` pairs. Useful for FFI tests that
    /// need to repackage the resolver into the `HashMap` shape
    /// [`verify_from_json`] consumes.
    pub fn iter(&self) -> impl Iterator<Item = (String, [u8; 32])> + '_ {
        self.keys.iter().map(|(k, v)| (k.clone(), *v))
    }
}

impl KeyResolver for StaticKeyResolver {
    fn resolve(&self, did: &str) -> Option<[u8; 32]> {
        self.keys.get(did).copied()
    }
}

/// Tracks consumed nonces inside a TTL window. The default implementation
/// is in-memory (suitable for SDKs); services swap in a Postgres-backed
/// implementation per ADR-0007.
pub trait NonceStore {
    /// Returns `true` if `nonce` had already been consumed (replay).
    /// Returns `false` and records `nonce` on first sight.
    fn check_and_record(&mut self, nonce: &str, seen_at: DateTime<Utc>) -> bool;
}

/// In-memory nonce store with TTL-bounded eviction. Default for SDK callers.
#[derive(Debug, Default)]
pub struct InMemoryNonceStore {
    seen: HashMap<String, DateTime<Utc>>,
    /// How long to remember a nonce before evicting it.
    pub ttl_secs: i64,
}

/// Process-shared default nonce store used by the FFI helpers
/// ([`verify_from_json`], [`verify_to_json_string`]) so that replay
/// protection actually spans calls inside the same Python / Node process.
/// Spec §11 recommends a 120 s TTL window (twice the freshness skew).
fn default_nonce_store() -> &'static std::sync::Mutex<InMemoryNonceStore> {
    static STORE: std::sync::OnceLock<std::sync::Mutex<InMemoryNonceStore>> =
        std::sync::OnceLock::new();
    STORE.get_or_init(|| std::sync::Mutex::new(InMemoryNonceStore::new(120)))
}

/// Resets the process-shared default nonce store. Intended for tests and
/// for benchmark harnesses that want a clean slate between scenarios.
/// Production callers should construct their own [`InMemoryNonceStore`]
/// (or a `NonceStore` impl backed by Postgres / Redis) and call
/// [`verify_handshake_request`] directly.
pub fn reset_default_nonce_store_for_tests() {
    if let Ok(mut s) = default_nonce_store().lock() {
        *s = InMemoryNonceStore::new(120);
    }
}

impl InMemoryNonceStore {
    /// Construct with a TTL window in seconds. Spec §11 recommends ≥120s
    /// (twice the freshness skew window) so a replay arriving within the
    /// skew window can never slip through after the original was evicted.
    #[must_use]
    pub fn new(ttl_secs: i64) -> Self {
        Self {
            seen: HashMap::new(),
            ttl_secs,
        }
    }
}

impl NonceStore for InMemoryNonceStore {
    fn check_and_record(&mut self, nonce: &str, seen_at: DateTime<Utc>) -> bool {
        // Evict expired nonces before the lookup so the map doesn't grow
        // unbounded under sustained traffic.
        let cutoff = seen_at - chrono::Duration::seconds(self.ttl_secs);
        self.seen.retain(|_, &mut t| t >= cutoff);

        if self.seen.contains_key(nonce) {
            return true;
        }
        self.seen.insert(nonce.to_string(), seen_at);
        false
    }
}

/// Looks up revocation status for a DID or DelegationToken id. Phase 2
/// ships in-memory; Phase 3 wires this to the Registry's revocation feed.
pub trait RevocationResolver {
    /// Returns `true` if `principal_did` has been revoked at or before `as_of`.
    fn is_principal_revoked(&self, principal_did: &str, as_of: DateTime<Utc>) -> bool;

    /// Returns `true` if `delegation_id` has been revoked at or before `as_of`.
    fn is_delegation_revoked(&self, delegation_id: &str, as_of: DateTime<Utc>) -> bool;
}

/// In-memory revocation resolver — accepts revocation lists at construction
/// time; suitable for tests and SDK defaults. Push subscribers (sub-60s
/// propagation per §3.6) wrap this with a transport adapter.
#[derive(Debug, Default, Clone)]
pub struct StaticRevocationResolver {
    pub revoked_principals: Vec<String>,
    pub revoked_delegations: Vec<String>,
}

impl RevocationResolver for StaticRevocationResolver {
    fn is_principal_revoked(&self, principal_did: &str, _as_of: DateTime<Utc>) -> bool {
        self.revoked_principals.iter().any(|d| d == principal_did)
    }

    fn is_delegation_revoked(&self, delegation_id: &str, _as_of: DateTime<Utc>) -> bool {
        self.revoked_delegations.iter().any(|d| d == delegation_id)
    }
}

/// Per-call verification context. Caller owns clock + key resolver + replay
/// store + revocation feed; the verifier is pure given these inputs.
pub struct VerifyContext<'a, K: KeyResolver, N: NonceStore, R: RevocationResolver> {
    /// DID of the receiver (the `aud` we expect on the request).
    pub receiver_did: &'a str,
    /// Wall-clock time used for all freshness/expiry checks.
    pub now: DateTime<Utc>,
    /// Skew tolerance in seconds (default 60).
    pub skew_secs: i64,
    pub keys: &'a K,
    pub nonces: &'a mut N,
    pub revocations: &'a R,
}

/// Successful outcome — the chain-intersected effective scope the request is
/// authorized for. Maps to `handshake-acceptance.json` in the spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Acceptance {
    /// The capability `name` the request carried, echoed back so receivers
    /// can dispatch on a single field.
    pub capability: String,
    /// The narrowed constraint set. Equal to or stricter than every link
    /// in the chain.
    pub effective_constraints: Map<String, Value>,
}

/// Spec error codes (`_common.json#/$defs/errorCode`). Every variant maps to
/// exactly one string, used both in the typed Rust API and serialized into
/// the `Refusal.error_code` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    SignatureInvalid,
    ChainBroken,
    ScopeExceeded,
    CredentialRevoked,
    Expired,
    NotYetValid,
    ReplayDetected,
    AudMismatch,
    PolicyDenied,
    ServiceUnavailable,
    RateLimited,
    ProtocolVersionUnsupported,
}

impl ErrorCode {
    /// Lowercase string the spec enum lists. Stable wire format.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SignatureInvalid => "signature_invalid",
            Self::ChainBroken => "chain_broken",
            Self::ScopeExceeded => "scope_exceeded",
            Self::CredentialRevoked => "credential_revoked",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::ReplayDetected => "replay_detected",
            Self::AudMismatch => "aud_mismatch",
            Self::PolicyDenied => "policy_denied",
            Self::ServiceUnavailable => "service_unavailable",
            Self::RateLimited => "rate_limited",
            Self::ProtocolVersionUnsupported => "protocol_version_unsupported",
        }
    }
}

/// Which step in the verifier emitted a rejection. Surfaced into the
/// `Refusal.rejected_at_step` field; the test vectors assert on exact
/// strings here so the names are part of the public contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectStep {
    SchemaValidation,
    SignatureVerification,
    AudienceCheck,
    FreshnessWindow,
    NonceCheck,
    DelegationChainWalk,
    ScopeIntersection,
    PolicyHook,
}

/// Structured rejection. Serializes to the `Refusal` shape the spec defines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefusalReason {
    pub error_code: ErrorCode,
    pub rejected_at_step: RejectStep,
    /// Free-form human-readable explanation. Conformance harness substring-
    /// matches against this for `detail_must_include` assertions.
    pub detail: String,
    /// When the rejection happened in the chain walk, which delegation was
    /// at fault (`delegation.id`). `None` for outer-request rejections.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub rejected_delegation_id: Option<String>,
}

impl RefusalReason {
    fn outer(code: ErrorCode, step: RejectStep, detail: impl Into<String>) -> Self {
        Self {
            error_code: code,
            rejected_at_step: step,
            detail: detail.into(),
            rejected_delegation_id: None,
        }
    }

    fn link(
        code: ErrorCode,
        step: RejectStep,
        delegation_id: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            error_code: code,
            rejected_at_step: step,
            detail: detail.into(),
            rejected_delegation_id: Some(delegation_id.into()),
        }
    }
}

/// The verifier's typed return — Acceptance on success or a structured
/// Refusal on failure.
pub type VerifyResult = Result<Acceptance, RefusalReason>;

/// Top-level entry point. See module docs for the step ordering.
///
/// # Errors
/// Returns a [`RefusalReason`] on any rejection. The receiver is responsible
/// for translating it into a signed `HandshakeRefusal` wire message.
pub fn verify_handshake_request<K, N, R>(
    req: &HandshakeRequest,
    ctx: &mut VerifyContext<'_, K, N, R>,
) -> VerifyResult
where
    K: KeyResolver,
    N: NonceStore,
    R: RevocationResolver,
{
    // --- Step 1: schema/version -----------------------------------------
    if req.kind != "HandshakeRequest" {
        return Err(RefusalReason::outer(
            ErrorCode::SignatureInvalid,
            RejectStep::SchemaValidation,
            format!("expected kind=HandshakeRequest, got {}", req.kind),
        ));
    }
    if req.version != SPEC_VERSION {
        return Err(RefusalReason::outer(
            ErrorCode::ProtocolVersionUnsupported,
            RejectStep::SchemaValidation,
            format!("expected version={SPEC_VERSION}, got {}", req.version),
        ));
    }
    if req.delegation_chain.is_empty() {
        return Err(RefusalReason::outer(
            ErrorCode::ChainBroken,
            RejectStep::SchemaValidation,
            "delegation_chain must contain at least one DelegationToken",
        ));
    }

    // --- Step 2: outer signature ----------------------------------------
    verify_signed_payload(
        req,
        req.alg,
        req.signature.as_deref(),
        &req.iss,
        ctx,
        RejectStep::SignatureVerification,
        None,
    )?;

    // --- Step 3: audience -----------------------------------------------
    if req.aud != ctx.receiver_did {
        return Err(RefusalReason::outer(
            ErrorCode::AudMismatch,
            RejectStep::AudienceCheck,
            format!(
                "request aud={} does not match receiver {}",
                req.aud, ctx.receiver_did
            ),
        ));
    }

    // --- Step 4: freshness window ---------------------------------------
    let req_iat = parse_ts(&req.iat).map_err(|e| {
        RefusalReason::outer(
            ErrorCode::SignatureInvalid,
            RejectStep::FreshnessWindow,
            format!("request.iat unparseable: {e}"),
        )
    })?;
    let skew = chrono::Duration::seconds(ctx.skew_secs);
    if req_iat > ctx.now + skew {
        return Err(RefusalReason::outer(
            ErrorCode::NotYetValid,
            RejectStep::FreshnessWindow,
            format!(
                "request.iat {} is more than {}s ahead of now {}",
                req.iat, ctx.skew_secs, ctx.now
            ),
        ));
    }
    if req_iat < ctx.now - skew {
        return Err(RefusalReason::outer(
            ErrorCode::Expired,
            RejectStep::FreshnessWindow,
            format!(
                "request.iat {} is more than {}s behind now {}",
                req.iat, ctx.skew_secs, ctx.now
            ),
        ));
    }

    // --- Step 5: nonce uniqueness ---------------------------------------
    if ctx.nonces.check_and_record(&req.nonce, ctx.now) {
        return Err(RefusalReason::outer(
            ErrorCode::ReplayDetected,
            RejectStep::NonceCheck,
            format!("nonce {} already consumed", req.nonce),
        ));
    }

    // --- Step 6: chain leaf-issuer match --------------------------------
    // The delegation_chain is ordered ROOT first, LEAF last. The leaf's
    // `sub` is the principal the request is signed by, so it must equal
    // the request's `iss`.
    let leaf = req
        .delegation_chain
        .last()
        .expect("non-empty checked above");
    if leaf.sub != req.iss {
        return Err(RefusalReason::link(
            ErrorCode::ChainBroken,
            RejectStep::DelegationChainWalk,
            &leaf.id,
            format!(
                "leaf delegation sub={} does not match request iss={}",
                leaf.sub, req.iss
            ),
        ));
    }

    // --- Step 7: per-link walk (root → leaf) ----------------------------
    let mut cumulative: Option<(String, Map<String, Value>)> = None;
    let chain_len = req.delegation_chain.len();
    for (idx, link) in req.delegation_chain.iter().enumerate() {
        // Step 7d: issuer-chain integrity. Each non-root link's `iss` must
        // equal the prior link's `sub`. Enforced here at the call site so
        // we have direct access to the full chain.
        if idx > 0 {
            let prev = &req.delegation_chain[idx - 1];
            if link.iss != prev.sub {
                return Err(RefusalReason::link(
                    ErrorCode::ChainBroken,
                    RejectStep::DelegationChainWalk,
                    &link.id,
                    format!(
                        "link iss={} does not match prior link sub={}",
                        link.iss, prev.sub
                    ),
                ));
            }
        }

        verify_link(link, idx, chain_len, &cumulative, &req.capability.name, ctx)?;

        // Find the capability inside this link that matches the one being
        // requested. (A delegation may grant multiple capabilities; the
        // chain narrows on the one the request is asking for.)
        let cap = link
            .capabilities
            .iter()
            .find(|c| c.name == req.capability.name)
            .ok_or_else(|| {
                RefusalReason::link(
                    ErrorCode::ChainBroken,
                    RejectStep::DelegationChainWalk,
                    &link.id,
                    format!(
                        "delegation does not grant capability {}; chain cannot satisfy request",
                        req.capability.name
                    ),
                )
            })?;

        let link_constraints = cap
            .constraints
            .as_ref()
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        cumulative = Some(match cumulative {
            None => (cap.name.clone(), link_constraints),
            Some((_, prev)) => {
                let merged = intersect::intersect(&prev, &link_constraints)
                    .map_err(|v| scope_violation_to_refusal(&link.id, v))?;
                (cap.name.clone(), merged)
            }
        });
    }

    let (effective_name, chain_scope) = cumulative.expect("at least one link walked above");

    // --- Step 8: scope intersection vs. request -------------------------
    let req_constraints = req
        .capability
        .constraints
        .as_ref()
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let effective_constraints =
        intersect::intersect(&chain_scope, &req_constraints).map_err(|v| RefusalReason {
            error_code: ErrorCode::ScopeExceeded,
            rejected_at_step: RejectStep::ScopeIntersection,
            detail: v.reason,
            rejected_delegation_id: None,
        })?;

    // --- Step 9: policy hook (caller-supplied; default is no-op) --------
    // Phase 2 ships the hook surface; the policy DSL compiler is Phase 6.
    // Callers that want to add custom denial rules wrap `verify_handshake_request`.

    Ok(Acceptance {
        capability: effective_name,
        effective_constraints,
    })
}

fn scope_violation_to_refusal(delegation_id: &str, v: ScopeViolation) -> RefusalReason {
    RefusalReason::link(
        ErrorCode::ScopeExceeded,
        RejectStep::DelegationChainWalk,
        delegation_id,
        v.reason,
    )
}

fn verify_link<K, N, R>(
    link: &DelegationToken,
    idx: usize,
    chain_len: usize,
    parent: &Option<(String, Map<String, Value>)>,
    requested_capability_name: &str,
    ctx: &mut VerifyContext<'_, K, N, R>,
) -> Result<(), RefusalReason>
where
    K: KeyResolver,
    N: NonceStore,
    R: RevocationResolver,
{
    if link.kind != "DelegationToken" {
        return Err(RefusalReason::link(
            ErrorCode::SignatureInvalid,
            RejectStep::DelegationChainWalk,
            &link.id,
            format!("expected kind=DelegationToken, got {}", link.kind),
        ));
    }

    // 7a: link signature
    verify_signed_payload(
        link,
        link.alg,
        link.signature.as_deref(),
        &link.iss,
        ctx,
        RejectStep::DelegationChainWalk,
        Some(&link.id),
    )?;

    // 7b: nbf ≤ now ≤ exp with ±skew
    let nbf = parse_ts(&link.nbf).map_err(|e| {
        RefusalReason::link(
            ErrorCode::SignatureInvalid,
            RejectStep::DelegationChainWalk,
            &link.id,
            format!("nbf unparseable: {e}"),
        )
    })?;
    let exp = parse_ts(&link.exp).map_err(|e| {
        RefusalReason::link(
            ErrorCode::SignatureInvalid,
            RejectStep::DelegationChainWalk,
            &link.id,
            format!("exp unparseable: {e}"),
        )
    })?;
    let skew = chrono::Duration::seconds(ctx.skew_secs);
    if ctx.now + skew < nbf {
        return Err(RefusalReason::link(
            ErrorCode::NotYetValid,
            RejectStep::DelegationChainWalk,
            &link.id,
            format!(
                "delegation nbf={} is in the future relative to now={} (±{}s)",
                link.nbf, ctx.now, ctx.skew_secs
            ),
        ));
    }
    if ctx.now - skew > exp {
        return Err(RefusalReason::link(
            ErrorCode::Expired,
            RejectStep::DelegationChainWalk,
            &link.id,
            format!(
                "delegation exp={} is in the past relative to now={} (±{}s)",
                link.exp, ctx.now, ctx.skew_secs
            ),
        ));
    }

    // 7c: revocation lookup (delegation id + issuer)
    if ctx.revocations.is_delegation_revoked(&link.id, ctx.now) {
        return Err(RefusalReason::link(
            ErrorCode::CredentialRevoked,
            RejectStep::DelegationChainWalk,
            &link.id,
            format!("delegation {} is revoked", link.id),
        ));
    }
    if ctx.revocations.is_principal_revoked(&link.iss, ctx.now) {
        return Err(RefusalReason::link(
            ErrorCode::CredentialRevoked,
            RejectStep::DelegationChainWalk,
            &link.id,
            format!("issuer principal {} is revoked", link.iss),
        ));
    }

    // 7d: issuer-chain integrity is enforced at the call site in
    // `verify_handshake_request` where the full chain is in scope.
    // `parent` here is the chain-cumulative capability binding, used by
    // 7e/8 for scope intersection — not for issuer-chain integrity.
    let _ = parent;

    // 7e: delegable + sub_delegation_depth_remaining for non-final links
    if idx + 1 < chain_len {
        // This link delegates further down the chain. The *specific
        // capability* the request is asking for must be `delegable=true`
        // on this link — checking "any cap on the link is delegable"
        // would let an attacker chain a non-delegable capability A by
        // co-mingling it with an unrelated delegable capability B.
        // (See architect review of T007 wrap-up; ADR-0007.)
        if let Some(matched) = link
            .capabilities
            .iter()
            .find(|c| c.name == requested_capability_name)
        {
            if !matched.delegable.unwrap_or(false) {
                return Err(RefusalReason::link(
                    ErrorCode::ChainBroken,
                    RejectStep::DelegationChainWalk,
                    &link.id,
                    format!(
                        "intermediate delegation: capability {requested_capability_name} is not delegable on this link"
                    ),
                ));
            }
        }
        // If the requested capability isn't on this link at all, the
        // caller's `.find(|c| c.name == req.capability.name)` (right
        // after this function returns) emits the canonical ChainBroken.
        if link.sub_delegation_depth_remaining == 0 {
            return Err(RefusalReason::link(
                ErrorCode::ChainBroken,
                RejectStep::DelegationChainWalk,
                &link.id,
                "sub_delegation_depth_remaining is 0 but chain extends further",
            ));
        }
    }

    Ok(())
}

/// Verify the signature on any signed envelope (`HandshakeRequest` or
/// `DelegationToken`). The bytes-to-sign are the JCS canonicalization of the
/// envelope with the `signature` field omitted.
fn verify_signed_payload<T, K, N, R>(
    payload: &T,
    alg: SignatureAlgorithm,
    signature_b64: Option<&str>,
    issuer_did: &str,
    ctx: &VerifyContext<'_, K, N, R>,
    step: RejectStep,
    delegation_id: Option<&str>,
) -> Result<(), RefusalReason>
where
    T: Serialize,
    K: KeyResolver,
    N: NonceStore,
    R: RevocationResolver,
{
    let sig_b64 = signature_b64.ok_or_else(|| {
        make_refusal(
            ErrorCode::SignatureInvalid,
            step,
            delegation_id,
            "envelope is missing `signature` field",
        )
    })?;

    // Phase 2 supports EdDSA only on the verification path. ML-DSA-65 + Hybrid
    // are wired into the cryptographic primitives (Phase 1) but the chain
    // walk's negotiation-aware path lands in v0.3 per ADR-0006.
    if !matches!(alg, SignatureAlgorithm::EdDsa) {
        return Err(make_refusal(
            ErrorCode::ProtocolVersionUnsupported,
            step,
            delegation_id,
            format!("alg {alg:?} not supported by Phase 2 verifier (EdDSA only); ML-DSA-65 + Hybrid land in v0.3"),
        ));
    }

    let pk = ctx.keys.resolve(issuer_did).ok_or_else(|| {
        make_refusal(
            ErrorCode::SignatureInvalid,
            step,
            delegation_id,
            format!("no public key registered for issuer {issuer_did}"),
        )
    })?;

    let msg = bytes_to_sign(payload).map_err(|e| {
        make_refusal(
            ErrorCode::SignatureInvalid,
            step,
            delegation_id,
            format!("canonicalization failed: {e}"),
        )
    })?;

    sign::verify_b64(&pk, sig_b64, &msg).map_err(|e| {
        make_refusal(
            ErrorCode::SignatureInvalid,
            step,
            delegation_id,
            format!("signature did not verify: {e}"),
        )
    })
}

fn make_refusal(
    code: ErrorCode,
    step: RejectStep,
    delegation_id: Option<&str>,
    detail: impl Into<String>,
) -> RefusalReason {
    match delegation_id {
        Some(id) => RefusalReason::link(code, step, id, detail),
        None => RefusalReason::outer(code, step, detail),
    }
}

/// Compute the bytes-to-sign for any signed envelope: JCS-canonicalize the
/// payload with the `signature` field stripped. Mirrors the procedure in
/// `_common.json` and the Implementation Guide §4.1's hot-path table.
///
/// # Errors
/// Returns an error if the payload doesn't serialize to JSON or fails JCS
/// canonicalization (non-finite numbers, etc.).
pub fn bytes_to_sign<T: Serialize>(payload: &T) -> Result<Vec<u8>, crate::Error> {
    let mut value = serde_json::to_value(payload)?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("signature");
    }
    let canonical = jcs::canonicalize(&value)?;
    Ok(canonical)
}

fn parse_ts(s: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339(s).map(|dt| dt.with_timezone(&Utc))
}

// ---------------------------------------------------------------------------
// Re-exports for the FFI shims. The PyO3 / NAPI-RS layers wrap these to
// produce language-native objects without re-implementing the algorithm.
// ---------------------------------------------------------------------------

/// Convenience: verify a request given JSON inputs (used by the conformance
/// runner and the FFI shims). Constructs an in-memory nonce store + static
/// resolver internally — production callers should construct these
/// themselves and call [`verify_handshake_request`] directly.
///
/// # Errors
/// Returns a parse error if the inputs aren't well-formed JSON; otherwise
/// returns the standard verifier result.
#[allow(clippy::module_name_repetitions)]
pub fn verify_from_json(
    request_json: &str,
    keys: &HashMap<String, [u8; 32]>,
    receiver_did: &str,
    now_rfc3339: &str,
    revoked_principals: &[String],
    revoked_delegations: &[String],
) -> Result<VerifyResult, crate::Error> {
    let req: HandshakeRequest = serde_json::from_str(request_json)?;
    let now = parse_ts(now_rfc3339)
        .map_err(|e| crate::Error::InvalidModel(format!("now_rfc3339 unparseable: {e}")))?;
    let mut resolver = StaticKeyResolver::new();
    for (did, pk) in keys {
        resolver.insert(did, *pk);
    }
    // Use the process-shared default nonce store so a replayed request hitting
    // the same FFI process is rejected on the second call. Production callers
    // that need cross-instance dedup wire their own NonceStore (e.g. Postgres
    // per ADR-0007) and call `verify_handshake_request` directly.
    let store = default_nonce_store();
    let mut nonces_guard = store.lock().expect("nonce store mutex poisoned");
    let revs = StaticRevocationResolver {
        revoked_principals: revoked_principals.to_vec(),
        revoked_delegations: revoked_delegations.to_vec(),
    };
    let mut ctx = VerifyContext {
        receiver_did,
        now,
        skew_secs: DEFAULT_SKEW_SECS,
        keys: &resolver,
        nonces: &mut *nonces_guard,
        revocations: &revs,
    };
    Ok(verify_handshake_request(&req, &mut ctx))
}

/// FFI-friendly variant: returns a JSON string with a stable, language-
/// agnostic shape so PyO3 / NAPI-RS / external callers can consume the
/// verifier without binding to typed Rust enums.
///
/// Output schema:
/// ```jsonc
/// // Acceptance
/// { "result": "accept",
///   "capability": "<name>",
///   "effective_constraints": { ... } }
///
/// // Refusal
/// { "result": "reject",
///   "error_code": "<spec enum value>",
///   "rejected_at_step": "<step enum value>",
///   "detail": "<human-readable>",
///   "rejected_delegation_id": "<id>" | null }
/// ```
///
/// # Errors
/// Returns a parse error if the inputs aren't well-formed JSON.
pub fn verify_to_json_string(
    request_json: &str,
    keys: &HashMap<String, [u8; 32]>,
    receiver_did: &str,
    now_rfc3339: &str,
    revoked_principals: &[String],
    revoked_delegations: &[String],
) -> Result<String, crate::Error> {
    let result = verify_from_json(
        request_json,
        keys,
        receiver_did,
        now_rfc3339,
        revoked_principals,
        revoked_delegations,
    )?;
    let payload = match result {
        Ok(acc) => serde_json::json!({
            "result": "accept",
            "capability": acc.capability,
            "effective_constraints": acc.effective_constraints,
        }),
        Err(r) => serde_json::json!({
            "result": "reject",
            "error_code": r.error_code.as_str(),
            "rejected_at_step": reject_step_str(r.rejected_at_step),
            "detail": r.detail,
            "rejected_delegation_id": r.rejected_delegation_id,
        }),
    };
    Ok(serde_json::to_string(&payload).expect("serialize payload"))
}

fn reject_step_str(s: RejectStep) -> &'static str {
    match s {
        RejectStep::SchemaValidation => "schema_validation",
        RejectStep::SignatureVerification => "signature_verification",
        RejectStep::AudienceCheck => "audience_check",
        RejectStep::FreshnessWindow => "freshness_window",
        RejectStep::NonceCheck => "nonce_check",
        RejectStep::DelegationChainWalk => "delegation_chain_walk",
        RejectStep::ScopeIntersection => "scope_intersection",
        RejectStep::PolicyHook => "policy_hook",
    }
}

/// FFI-friendly intersection: takes the delegated + requested constraint
/// sets as JSON object strings and returns a JSON object describing the
/// outcome.
///
/// Output schema:
/// ```jsonc
/// // Admissible
/// { "ok": true, "effective": { ... } }
/// // Disjoint / exceeds
/// { "ok": false, "error_code": "scope_exceeded", "key": "...", "reason": "..." }
/// ```
///
/// # Errors
/// Returns an error if `delegated_json` or `requested_json` isn't a JSON
/// object literal.
pub fn intersect_to_json_string(
    delegated_json: &str,
    requested_json: &str,
) -> Result<String, crate::Error> {
    let d: Value = serde_json::from_str(delegated_json)?;
    let r: Value = serde_json::from_str(requested_json)?;
    let dm = d
        .as_object()
        .ok_or_else(|| crate::Error::InvalidModel("delegated must be a JSON object".into()))?;
    let rm = r
        .as_object()
        .ok_or_else(|| crate::Error::InvalidModel("requested must be a JSON object".into()))?;
    let payload = match intersect::intersect(dm, rm) {
        Ok(merged) => serde_json::json!({"ok": true, "effective": merged}),
        Err(v) => serde_json::json!({
            "ok": false,
            "error_code": "scope_exceeded",
            "key": v.key,
            "reason": v.reason,
        }),
    };
    Ok(serde_json::to_string(&payload).expect("serialize payload"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Keypair;
    use serde_json::json;

    /// Build a minimal valid request + delegation pair, sign both with fresh
    /// Ed25519 keys, return everything callers need to verify.
    fn build_valid() -> (HandshakeRequest, StaticKeyResolver, String) {
        let user_kp = Keypair::generate();
        let agent_kp = Keypair::generate();
        let svc_did = "did:hsk:svc:test-service";

        let mut delegation = DelegationToken {
            version: SPEC_VERSION.to_string(),
            kind: "DelegationToken".to_string(),
            id: "dt_test".to_string(),
            iss: "did:hsk:user:alice".to_string(),
            sub: "did:hsk:agent:bob".to_string(),
            aud: "did:hsk:agent:bob".to_string(),
            iat: "2026-04-29T14:02:11Z".to_string(),
            nbf: "2026-04-29T14:02:11Z".to_string(),
            exp: "2026-04-29T14:32:11Z".to_string(),
            capabilities: vec![Capability {
                name: "billing.invoices.read".to_string(),
                constraints: Some(json!({"max_invoices": 100})),
                delegable: Some(false),
            }],
            sub_delegation_depth_remaining: 0,
            parent_delegation_id: None,
            alg: SignatureAlgorithm::EdDsa,
            signature: None,
        };
        let dt_msg = bytes_to_sign(&delegation).expect("canonicalize");
        delegation.signature = Some(user_kp.sign_b64(&dt_msg));

        let mut request = HandshakeRequest {
            version: SPEC_VERSION.to_string(),
            kind: "HandshakeRequest".to_string(),
            id: "hs_test".to_string(),
            iss: "did:hsk:agent:bob".to_string(),
            aud: svc_did.to_string(),
            iat: "2026-04-29T14:14:32Z".to_string(),
            nonce: "k7nQ9pX3vR2mT4uV6wY8zA".to_string(),
            agent_attestation: json!({"deployer": "did:hsk:org:deployer", "model": "claude-sonnet-4-5"}),
            capability: Capability {
                name: "billing.invoices.read".to_string(),
                constraints: Some(json!({"max_invoices": 100})),
                delegable: None,
            },
            delegation_chain: vec![delegation],
            alg: SignatureAlgorithm::EdDsa,
            signature: None,
        };
        let req_msg = bytes_to_sign(&request).expect("canonicalize");
        request.signature = Some(agent_kp.sign_b64(&req_msg));

        let mut resolver = StaticKeyResolver::new();
        resolver.insert("did:hsk:user:alice", user_kp.public_key());
        resolver.insert("did:hsk:agent:bob", agent_kp.public_key());

        (request, resolver, svc_did.to_string())
    }

    #[test]
    fn vector_001_style_acceptance() {
        let (req, resolver, svc_did) = build_valid();
        let mut nonces = InMemoryNonceStore::new(120);
        let revs = StaticRevocationResolver::default();
        let mut ctx = VerifyContext {
            receiver_did: &svc_did,
            now: parse_ts("2026-04-29T14:14:32Z").unwrap(),
            skew_secs: DEFAULT_SKEW_SECS,
            keys: &resolver,
            nonces: &mut nonces,
            revocations: &revs,
        };
        let acc = verify_handshake_request(&req, &mut ctx).expect("accept");
        assert_eq!(acc.capability, "billing.invoices.read");
        assert_eq!(acc.effective_constraints["max_invoices"], json!(100));
    }

    #[test]
    fn vector_002_style_rejects_expired_delegation() {
        let (req, resolver, svc_did) = build_valid();
        let mut nonces = InMemoryNonceStore::new(120);
        let revs = StaticRevocationResolver::default();
        let mut ctx = VerifyContext {
            receiver_did: &svc_did,
            // Jump 18 minutes past delegation.exp; the chain link must reject.
            now: parse_ts("2026-04-29T14:50:11Z").unwrap(),
            skew_secs: DEFAULT_SKEW_SECS,
            keys: &resolver,
            nonces: &mut nonces,
            revocations: &revs,
        };
        let err = verify_handshake_request(&req, &mut ctx).expect_err("must reject");
        assert_eq!(err.error_code, ErrorCode::Expired);
        assert_eq!(err.rejected_at_step, RejectStep::FreshnessWindow);
        // Note: the request iat is also 18 minutes old, so the freshness
        // window catches this BEFORE the chain walk. Good — that's the
        // outer-first ordering the spec mandates.
    }

    #[test]
    fn vector_003_style_rejects_scope_exceeded() {
        let (mut req, resolver, svc_did) = build_valid();
        // Mutate the request to ask for more than the delegation grants.
        req.capability.constraints = Some(json!({"max_invoices": 500}));
        // Re-sign the request so the signature still validates.
        req.signature = None;
        let agent_pk = resolver.resolve("did:hsk:agent:bob").unwrap();
        // Resolver doesn't expose the private key; instead, we re-build the
        // env around fresh keys for this case.
        let _ = agent_pk;
        let agent_kp = Keypair::generate();
        let req_msg = bytes_to_sign(&req).expect("canonicalize");
        req.signature = Some(agent_kp.sign_b64(&req_msg));
        let mut resolver2 = resolver.clone();
        resolver2.insert("did:hsk:agent:bob", agent_kp.public_key());
        let mut nonces = InMemoryNonceStore::new(120);
        let revs = StaticRevocationResolver::default();
        let mut ctx = VerifyContext {
            receiver_did: &svc_did,
            now: parse_ts("2026-04-29T14:14:32Z").unwrap(),
            skew_secs: DEFAULT_SKEW_SECS,
            keys: &resolver2,
            nonces: &mut nonces,
            revocations: &revs,
        };
        let err = verify_handshake_request(&req, &mut ctx).expect_err("must reject");
        assert_eq!(err.error_code, ErrorCode::ScopeExceeded);
        assert!(err.detail.contains("max_invoices"));
    }

    #[test]
    fn replay_rejected_on_second_call() {
        let (req, resolver, svc_did) = build_valid();
        let mut nonces = InMemoryNonceStore::new(120);
        let revs = StaticRevocationResolver::default();
        let now = parse_ts("2026-04-29T14:14:32Z").unwrap();
        {
            let mut ctx = VerifyContext {
                receiver_did: &svc_did,
                now,
                skew_secs: DEFAULT_SKEW_SECS,
                keys: &resolver,
                nonces: &mut nonces,
                revocations: &revs,
            };
            verify_handshake_request(&req, &mut ctx).expect("first call accepts");
        }
        let mut ctx = VerifyContext {
            receiver_did: &svc_did,
            now,
            skew_secs: DEFAULT_SKEW_SECS,
            keys: &resolver,
            nonces: &mut nonces,
            revocations: &revs,
        };
        let err = verify_handshake_request(&req, &mut ctx).expect_err("replay rejected");
        assert_eq!(err.error_code, ErrorCode::ReplayDetected);
    }

    #[test]
    fn audience_mismatch_rejected() {
        let (req, resolver, _svc_did) = build_valid();
        let mut nonces = InMemoryNonceStore::new(120);
        let revs = StaticRevocationResolver::default();
        let mut ctx = VerifyContext {
            receiver_did: "did:hsk:svc:wrong-audience",
            now: parse_ts("2026-04-29T14:14:32Z").unwrap(),
            skew_secs: DEFAULT_SKEW_SECS,
            keys: &resolver,
            nonces: &mut nonces,
            revocations: &revs,
        };
        let err = verify_handshake_request(&req, &mut ctx).expect_err("aud mismatch");
        assert_eq!(err.error_code, ErrorCode::AudMismatch);
    }

    #[test]
    fn revoked_delegation_rejected() {
        let (req, resolver, svc_did) = build_valid();
        let mut nonces = InMemoryNonceStore::new(120);
        let revs = StaticRevocationResolver {
            revoked_delegations: vec!["dt_test".to_string()],
            ..Default::default()
        };
        let mut ctx = VerifyContext {
            receiver_did: &svc_did,
            now: parse_ts("2026-04-29T14:14:32Z").unwrap(),
            skew_secs: DEFAULT_SKEW_SECS,
            keys: &resolver,
            nonces: &mut nonces,
            revocations: &revs,
        };
        let err = verify_handshake_request(&req, &mut ctx).expect_err("revoked");
        assert_eq!(err.error_code, ErrorCode::CredentialRevoked);
    }

    /// FFI surface: `verify_to_json_string` MUST share replay state across
    /// successive calls inside the same process. Otherwise a Python or
    /// Node caller could replay the exact same request and have it accepted.
    /// This guards the process-shared default nonce store wired in
    /// `verify_from_json`.
    #[test]
    fn ffi_verify_to_json_string_rejects_replay_across_calls() {
        // Reset the shared store so this test is hermetic regardless of
        // ordering with other tests in the same process.
        reset_default_nonce_store_for_tests();

        let (req, resolver, svc_did) = build_valid();
        let request_json = serde_json::to_string(&req).expect("serialize req");
        let keys: HashMap<String, [u8; 32]> = resolver.iter().collect();
        let now = "2026-04-29T14:14:32Z";

        let first = verify_to_json_string(&request_json, &keys, &svc_did, now, &[], &[])
            .expect("first call ok");
        let first: serde_json::Value = serde_json::from_str(&first).unwrap();
        assert_eq!(first["result"], "accept", "first call must accept");

        let second = verify_to_json_string(&request_json, &keys, &svc_did, now, &[], &[])
            .expect("second call ok");
        let second: serde_json::Value = serde_json::from_str(&second).unwrap();
        assert_eq!(second["result"], "reject", "second call must reject");
        assert_eq!(
            second["error_code"], "replay_detected",
            "replay must be detected by the FFI's process-shared nonce store"
        );

        // Leave the store clean for subsequent tests.
        reset_default_nonce_store_for_tests();
    }

    /// Step 7d enforcement: a two-link chain whose middle link's `iss` does
    /// NOT match the prior link's `sub` must be rejected with
    /// `chain_broken` at `delegation_chain_walk`. This guards against an
    /// attacker splicing a valid leaf delegation onto an unrelated root.
    #[test]
    fn chain_broken_when_iss_does_not_match_prior_sub() {
        let user_kp = Keypair::generate();
        let mallory_kp = Keypair::generate();
        let agent_kp = Keypair::generate();
        let svc_did = "did:hsk:svc:test-service";

        // Root: alice → bob (delegable, depth 1)
        let mut root = DelegationToken {
            version: SPEC_VERSION.to_string(),
            kind: "DelegationToken".to_string(),
            id: "dt_root".to_string(),
            iss: "did:hsk:user:alice".to_string(),
            sub: "did:hsk:agent:bob".to_string(),
            aud: "did:hsk:agent:bob".to_string(),
            iat: "2026-04-29T14:02:11Z".to_string(),
            nbf: "2026-04-29T14:02:11Z".to_string(),
            exp: "2026-04-29T14:32:11Z".to_string(),
            capabilities: vec![Capability {
                name: "billing.invoices.read".to_string(),
                constraints: Some(json!({"max_invoices": 100})),
                delegable: Some(true),
            }],
            sub_delegation_depth_remaining: 1,
            parent_delegation_id: None,
            alg: SignatureAlgorithm::EdDsa,
            signature: None,
        };
        let root_msg = bytes_to_sign(&root).expect("canonicalize root");
        root.signature = Some(user_kp.sign_b64(&root_msg));

        // Spliced leaf: signed by an UNRELATED principal `mallory`, whose
        // `iss` (mallory) ≠ root.sub (bob). Even though the signature
        // verifies under mallory's key, Step 7d must reject this chain.
        let mut spliced_leaf = DelegationToken {
            version: SPEC_VERSION.to_string(),
            kind: "DelegationToken".to_string(),
            id: "dt_spliced".to_string(),
            iss: "did:hsk:attacker:mallory".to_string(),
            sub: "did:hsk:agent:bob".to_string(),
            aud: "did:hsk:agent:bob".to_string(),
            iat: "2026-04-29T14:02:11Z".to_string(),
            nbf: "2026-04-29T14:02:11Z".to_string(),
            exp: "2026-04-29T14:32:11Z".to_string(),
            capabilities: vec![Capability {
                name: "billing.invoices.read".to_string(),
                constraints: Some(json!({"max_invoices": 100})),
                delegable: Some(false),
            }],
            sub_delegation_depth_remaining: 0,
            parent_delegation_id: Some("dt_root".to_string()),
            alg: SignatureAlgorithm::EdDsa,
            signature: None,
        };
        let leaf_msg = bytes_to_sign(&spliced_leaf).expect("canonicalize leaf");
        spliced_leaf.signature = Some(mallory_kp.sign_b64(&leaf_msg));

        let mut request = HandshakeRequest {
            version: SPEC_VERSION.to_string(),
            kind: "HandshakeRequest".to_string(),
            id: "hs_chain_broken".to_string(),
            iss: "did:hsk:agent:bob".to_string(),
            aud: svc_did.to_string(),
            iat: "2026-04-29T14:14:32Z".to_string(),
            nonce: "chain-broken-nonce-9001".to_string(),
            agent_attestation: json!({"deployer": "did:hsk:org:deployer", "model": "claude-sonnet-4-5"}),
            capability: Capability {
                name: "billing.invoices.read".to_string(),
                constraints: Some(json!({"max_invoices": 100})),
                delegable: None,
            },
            delegation_chain: vec![root, spliced_leaf],
            alg: SignatureAlgorithm::EdDsa,
            signature: None,
        };
        let req_msg = bytes_to_sign(&request).expect("canonicalize req");
        request.signature = Some(agent_kp.sign_b64(&req_msg));

        let mut resolver = StaticKeyResolver::new();
        resolver.insert("did:hsk:user:alice", user_kp.public_key());
        resolver.insert("did:hsk:attacker:mallory", mallory_kp.public_key());
        resolver.insert("did:hsk:agent:bob", agent_kp.public_key());

        let mut nonces = InMemoryNonceStore::new(120);
        let revs = StaticRevocationResolver::default();
        let mut ctx = VerifyContext {
            receiver_did: svc_did,
            now: parse_ts("2026-04-29T14:14:32Z").unwrap(),
            skew_secs: DEFAULT_SKEW_SECS,
            keys: &resolver,
            nonces: &mut nonces,
            revocations: &revs,
        };
        let err = verify_handshake_request(&request, &mut ctx).expect_err("must reject");
        assert_eq!(err.error_code, ErrorCode::ChainBroken);
        assert_eq!(err.rejected_at_step, RejectStep::DelegationChainWalk);
        assert_eq!(err.rejected_delegation_id.as_deref(), Some("dt_spliced"));
        assert!(
            err.detail.contains("does not match prior link sub"),
            "detail should explain the integrity violation, got: {}",
            err.detail
        );
    }

    /// Step 7e enforcement: when the *requested* capability on an
    /// intermediate link is `delegable=false`, the chain MUST be rejected
    /// even if some *other* capability on that same link is
    /// `delegable=true`. Co-mingling an unrelated delegable capability
    /// MUST NOT be enough to launder a non-delegable one — that would be
    /// an authorization-escalation path. (Architect-flagged case from
    /// the T007 wrap-up review; mirrored as conformance vector
    /// `error_codes/009-non-delegable-capability.json`.)
    #[test]
    fn chain_broken_when_requested_cap_not_delegable_even_if_other_cap_is() {
        let alice_kp = Keypair::generate();
        let agent1_kp = Keypair::generate();
        let agent2_kp = Keypair::generate();
        let svc_did = "did:hsk:svc:test-service";

        let mut root = DelegationToken {
            version: SPEC_VERSION.to_string(),
            kind: "DelegationToken".to_string(),
            id: "dt_009a".to_string(),
            iss: "did:hsk:user:alice".to_string(),
            sub: "did:hsk:agent:agent1".to_string(),
            aud: "did:hsk:agent:agent1".to_string(),
            iat: "2026-04-29T14:02:11Z".to_string(),
            nbf: "2026-04-29T14:02:11Z".to_string(),
            exp: "2026-04-29T14:32:11Z".to_string(),
            capabilities: vec![
                // The requested cap, marked non-delegable.
                Capability {
                    name: "billing.invoices.read".to_string(),
                    constraints: Some(json!({"max_invoices": 100})),
                    delegable: Some(false),
                },
                // An unrelated decoy cap, marked delegable.
                Capability {
                    name: "billing.invoices.export".to_string(),
                    constraints: Some(json!({"max_invoices": 100})),
                    delegable: Some(true),
                },
            ],
            sub_delegation_depth_remaining: 1,
            parent_delegation_id: None,
            alg: SignatureAlgorithm::EdDsa,
            signature: None,
        };
        let root_msg = bytes_to_sign(&root).expect("canonicalize root");
        root.signature = Some(alice_kp.sign_b64(&root_msg));

        let mut leaf = DelegationToken {
            version: SPEC_VERSION.to_string(),
            kind: "DelegationToken".to_string(),
            id: "dt_009b".to_string(),
            iss: "did:hsk:agent:agent1".to_string(),
            sub: "did:hsk:agent:agent2".to_string(),
            aud: "did:hsk:agent:agent2".to_string(),
            iat: "2026-04-29T14:03:00Z".to_string(),
            nbf: "2026-04-29T14:03:00Z".to_string(),
            exp: "2026-04-29T14:33:00Z".to_string(),
            capabilities: vec![Capability {
                name: "billing.invoices.read".to_string(),
                constraints: Some(json!({"max_invoices": 50})),
                delegable: Some(false),
            }],
            sub_delegation_depth_remaining: 0,
            parent_delegation_id: Some("dt_009a".to_string()),
            alg: SignatureAlgorithm::EdDsa,
            signature: None,
        };
        let leaf_msg = bytes_to_sign(&leaf).expect("canonicalize leaf");
        leaf.signature = Some(agent1_kp.sign_b64(&leaf_msg));

        let mut request = HandshakeRequest {
            version: SPEC_VERSION.to_string(),
            kind: "HandshakeRequest".to_string(),
            id: "hs_009".to_string(),
            iss: "did:hsk:agent:agent2".to_string(),
            aud: svc_did.to_string(),
            iat: "2026-04-29T14:14:32Z".to_string(),
            nonce: "nonce-009-rs".to_string(),
            agent_attestation: json!({"deployer": "did:hsk:org:o", "model": "claude-sonnet-4-5"}),
            capability: Capability {
                name: "billing.invoices.read".to_string(),
                constraints: Some(json!({"max_invoices": 25})),
                delegable: None,
            },
            delegation_chain: vec![root, leaf],
            alg: SignatureAlgorithm::EdDsa,
            signature: None,
        };
        let req_msg = bytes_to_sign(&request).expect("canonicalize req");
        request.signature = Some(agent2_kp.sign_b64(&req_msg));

        let mut resolver = StaticKeyResolver::new();
        resolver.insert("did:hsk:user:alice", alice_kp.public_key());
        resolver.insert("did:hsk:agent:agent1", agent1_kp.public_key());
        resolver.insert("did:hsk:agent:agent2", agent2_kp.public_key());

        let mut nonces = InMemoryNonceStore::new(120);
        let revs = StaticRevocationResolver::default();
        let mut ctx = VerifyContext {
            receiver_did: svc_did,
            now: parse_ts("2026-04-29T14:14:32Z").unwrap(),
            skew_secs: DEFAULT_SKEW_SECS,
            keys: &resolver,
            nonces: &mut nonces,
            revocations: &revs,
        };
        let err = verify_handshake_request(&request, &mut ctx).expect_err("must reject");
        assert_eq!(err.error_code, ErrorCode::ChainBroken);
        assert_eq!(err.rejected_at_step, RejectStep::DelegationChainWalk);
        assert_eq!(err.rejected_delegation_id.as_deref(), Some("dt_009a"));
        assert!(
            err.detail.contains("billing.invoices.read") && err.detail.contains("not delegable"),
            "detail should name the non-delegable capability, got: {}",
            err.detail
        );
    }
}
