//! Rust conformance runner. Reads the shared fixtures + the v0.2.3 core test
//! vectors (001, 002, 003), drives them through the chain-walk verifier, and
//! emits a JSON report on stdout matching the schema consumed by
//! `examples/phase1_demo.sh` (and the Phase 2 demo).
//!
//! Schema (per implementation):
//! ```jsonc
//! {
//!   "implementation": "rust",
//!   "spec_version": "0.2.3",
//!   "jcs_fixtures": [{"name": "...", "sha256": "..."}],
//!   "ed25519_kat":  { "passed": true, ... },
//!   "mldsa65_kat":  { "passed": true, ... },
//!   "vector_001":   { "passed": true, ... },             // back-compat for Phase 1 dashboard
//!   "vectors":      [ { "vector_id": "...", "passed": true, ... }, ... ]
//! }
//! ```

use handshake::sign::Keypair;
use handshake::verify::{
    bytes_to_sign, verify_handshake_request, ErrorCode, InMemoryNonceStore, RejectStep,
    StaticKeyResolver, StaticRevocationResolver, VerifyContext, DEFAULT_SKEW_SECS,
};
use handshake::{hash, jcs, mldsa, sign};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fs;

const REPO_ROOT_FIXTURES: &str = "tests/conformance/fixtures/jcs.json";
const VECTORS_DIR: &str = "packages/handshake-spec/test-vectors/v0.2.3/core";
const ERROR_CODES_DIR: &str = "tests/conformance/error_codes";
const VECTOR_FILES: &[(&str, &str)] = &[
    ("001-valid-handshake", "001-valid-handshake.json"),
    ("002-expired-delegation", "002-expired-delegation.json"),
    ("003-scope-exceeded", "003-scope-exceeded.json"),
];

fn jcs_sha256_hex(v: &Value) -> String {
    let bytes = jcs::canonicalize(v).expect("canonicalize");
    hex::encode(hash::sha256(&bytes))
}

fn run_jcs_fixtures() -> Vec<Value> {
    let raw = fs::read_to_string(REPO_ROOT_FIXTURES).expect("read jcs fixtures");
    let parsed: Value = serde_json::from_str(&raw).expect("parse fixtures");
    let mut out = Vec::new();
    for f in parsed["fixtures"].as_array().expect("fixtures array") {
        let Some(name) = f.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let canonical = jcs::canonicalize(&f["input"]).expect("canonicalize");
        if let Some(expected) = f.get("expected_canonical").and_then(|v| v.as_str()) {
            let actual = std::str::from_utf8(&canonical).expect("utf8");
            assert_eq!(
                actual, expected,
                "fixture {name}: canonical bytes diverge from golden"
            );
        }
        let h = hex::encode(hash::sha256(&canonical));
        out.push(json!({"name": name, "sha256": h}));
    }
    out
}

fn run_ed25519_kat() -> Value {
    let raw = fs::read_to_string(REPO_ROOT_FIXTURES).expect("read jcs fixtures");
    let parsed: Value = serde_json::from_str(&raw).expect("parse fixtures");
    let kat = &parsed["ed25519_kat"];
    let seed = hex::decode(kat["seed_hex"].as_str().unwrap()).unwrap();
    let expected_pub = hex::decode(kat["public_key_hex"].as_str().unwrap()).unwrap();
    let message = hex::decode(kat["message_hex"].as_str().unwrap()).unwrap();
    let expected_sig = hex::decode(kat["signature_hex"].as_str().unwrap()).unwrap();

    let seed: [u8; 32] = seed.try_into().expect("32-byte seed");
    let kp = sign::Keypair::from_seed(&seed);

    let pub_match = kp.public_key().as_slice() == expected_pub.as_slice();
    let sig = kp.sign(&message);
    let sig_match = sig.as_slice() == expected_sig.as_slice();
    let verifies = sign::verify(&kp.public_key(), &sig, &message).is_ok();

    json!({
        "name": kat["name"].as_str().unwrap(),
        "public_key_match": pub_match,
        "signature_match": sig_match,
        "verifies": verifies,
        "passed": pub_match && sig_match && verifies,
    })
}

fn run_mldsa65_kat() -> Value {
    let raw = fs::read_to_string(REPO_ROOT_FIXTURES).expect("read jcs fixtures");
    let parsed: Value = serde_json::from_str(&raw).expect("parse fixtures");
    let kat = &parsed["mldsa65_kat"];
    let seed_hex = kat["seed_hex"].as_str().unwrap();
    let message = kat["message_utf8"].as_str().unwrap().as_bytes();
    let expected_pk_sha = kat["expected_public_key_sha256"].as_str().unwrap();
    let expected_sg_sha = kat["expected_signature_sha256"].as_str().unwrap();

    let seed: [u8; 32] = hex::decode(seed_hex)
        .expect("seed hex")
        .try_into()
        .expect("32-byte seed");
    let kp = mldsa::Keypair::from_seed(&seed);
    let pk = kp.public_key();
    let sig = kp.sign(message);

    let pk_sha = hash::sha256_hex(&pk);
    let sg_sha = hash::sha256_hex(&sig);
    let pk_match = pk_sha == expected_pk_sha;
    let sg_match = sg_sha == expected_sg_sha;
    let verifies = mldsa::verify(&pk, &sig, message).is_ok();

    json!({
        "name": kat["name"].as_str().unwrap(),
        "public_key_size": pk.len(),
        "signature_size": sig.len(),
        "public_key_sha256": pk_sha,
        "signature_sha256": sg_sha,
        "public_key_match": pk_match,
        "signature_match": sg_match,
        "verifies": verifies,
        "passed": pk_match && sg_match && verifies,
    })
}

/// For a given vector, generate a fresh Ed25519 keypair for every DID listed
/// in `context.public_keys` (the PEM-encoded values are spec placeholders;
/// the runner-bound public/private material is what the verifier actually
/// sees). Returns `did -> Keypair` so the caller can sign + register.
fn synthesize_keys(public_keys: &Map<String, Value>) -> HashMap<String, Keypair> {
    let mut out = HashMap::new();
    for did in public_keys.keys() {
        out.insert(did.clone(), Keypair::generate());
    }
    out
}

/// Sign a delegation `link` using the keypair for `link.iss`. Returns the
/// link with a real `signature` field installed (replacing the placeholder).
fn sign_link(mut link: Value, keys: &HashMap<String, Keypair>) -> Value {
    let issuer = link["iss"]
        .as_str()
        .expect("link.iss is a string")
        .to_string();
    let kp = keys
        .get(&issuer)
        .unwrap_or_else(|| panic!("no keypair for issuer {issuer}"));
    link.as_object_mut()
        .expect("link object")
        .remove("signature");
    let canonical = jcs::canonicalize(&link).expect("canon link");
    let sig_b64 = kp.sign_b64(&canonical);
    link.as_object_mut()
        .unwrap()
        .insert("signature".into(), Value::String(sig_b64));
    link
}

/// Sign the outer `HandshakeRequest` using the keypair for `request.iss`,
/// after the delegation chain has already been signed.
fn sign_request(mut req: Value, keys: &HashMap<String, Keypair>) -> Value {
    let issuer = req["iss"]
        .as_str()
        .expect("req.iss is a string")
        .to_string();
    let kp = keys
        .get(&issuer)
        .unwrap_or_else(|| panic!("no keypair for issuer {issuer}"));
    req.as_object_mut()
        .expect("request object")
        .remove("signature");
    let canonical = jcs::canonicalize(&req).expect("canon request");
    let sig_b64 = kp.sign_b64(&canonical);
    req.as_object_mut()
        .unwrap()
        .insert("signature".into(), Value::String(sig_b64));
    req
}

/// Drive a single test vector through the verifier. Returns a result row
/// matching the dashboard schema.
fn run_vector(vector_id: &str, vector_path: &str) -> Value {
    let raw = fs::read_to_string(vector_path).unwrap_or_else(|e| panic!("read {vector_path}: {e}"));
    let v: Value = serde_json::from_str(&raw).expect("parse vector json");

    let context = &v["context"];
    let now_str = context["now"].as_str().expect("context.now").to_string();
    let public_keys = context["public_keys"]
        .as_object()
        .expect("context.public_keys")
        .clone();
    let registry = &context["registry_state"];
    let revoked_principals: Vec<String> = registry["revoked_principals"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let revoked_delegations: Vec<String> = registry["revoked_delegations"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    // Synthesize fresh keypairs for every DID the vector mentions.
    let keys = synthesize_keys(&public_keys);

    // Sign the delegation chain (root → leaf) with each link's issuer key.
    let input = &v["input"];
    let mut signed_chain = Vec::new();
    if let Some(single) = input.get("delegation") {
        signed_chain.push(sign_link(single.clone(), &keys));
    }
    if let Some(arr) = input.get("delegation_chain").and_then(Value::as_array) {
        for link in arr {
            signed_chain.push(sign_link(link.clone(), &keys));
        }
    }

    // Build the request, splice in the signed chain, then sign.
    let mut request = input["request"].clone();
    // Replace any `$ref_vector_local` placeholders in the request's
    // delegation_chain with the freshly-signed delegation objects.
    request.as_object_mut().unwrap().insert(
        "delegation_chain".into(),
        Value::Array(signed_chain.clone()),
    );
    let signed_request = sign_request(request, &keys);

    // Build the resolver and call the verifier.
    let mut resolver = StaticKeyResolver::new();
    for (did, kp) in &keys {
        resolver.insert(did, kp.public_key());
    }
    let mut nonces = InMemoryNonceStore::new(120);
    let revs = StaticRevocationResolver {
        revoked_principals,
        revoked_delegations,
    };

    let req_struct: handshake::models::HandshakeRequest =
        serde_json::from_value(signed_request.clone()).expect("parse signed request");
    // Some error-code vectors (e.g. 004 aud_mismatch) deliberately set
    // request.aud to a DID *different* from the receiver. Honour an explicit
    // `input.receiver_did` override; otherwise default to request.aud.
    let receiver_did = input
        .get("receiver_did")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| req_struct.aud.clone());
    let now = chrono::DateTime::parse_from_rfc3339(&now_str)
        .expect("parse context.now")
        .with_timezone(&chrono::Utc);

    let mut ctx = VerifyContext {
        receiver_did: &receiver_did,
        now,
        skew_secs: DEFAULT_SKEW_SECS,
        keys: &resolver,
        nonces: &mut nonces,
        revocations: &revs,
    };
    let result = verify_handshake_request(&req_struct, &mut ctx);

    let expected = &v["expected"];
    let expected_result = expected["result"].as_str().unwrap_or("accept");

    let (actual_result, actual_code, actual_step, detail, _delegation_id) = match &result {
        Ok(acc) => (
            "accept".to_string(),
            None::<&'static str>,
            None::<&'static str>,
            format!(
                "capability={} effective={}",
                acc.capability,
                serde_json::to_string(&acc.effective_constraints).unwrap()
            ),
            None::<String>,
        ),
        Err(refusal) => (
            "reject".to_string(),
            Some(refusal.error_code.as_str()),
            Some(reject_step_str(refusal.rejected_at_step)),
            refusal.detail.clone(),
            refusal.rejected_delegation_id.clone(),
        ),
    };

    // Score the result against `expected`.
    let mut passed = actual_result == expected_result;
    if let Some(expected_code) = expected.get("error_code").and_then(Value::as_str) {
        passed &= actual_code == Some(expected_code);
    }
    if let Some(expected_step) = expected.get("rejected_at_step").and_then(Value::as_str) {
        passed &= actual_step == Some(expected_step);
    }
    if let Some(must_include) = expected
        .get("detail_must_include")
        .and_then(Value::as_array)
    {
        for needle in must_include.iter().filter_map(Value::as_str) {
            passed &= detail.contains(needle);
        }
    }

    json!({
        "vector_id": vector_id,
        "expected_result": expected_result,
        "expected_error_code": expected.get("error_code").cloned().unwrap_or(Value::Null),
        "actual_result": actual_result,
        "actual_error_code": actual_code,
        "actual_rejected_at_step": actual_step,
        "detail": detail,
        "passed": passed,
    })
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

/// Phase-1 back-compat: produce the unsigned-delegation + unsigned-request
/// SHA-256 digests for vector 001 so the cross-impl JCS byte-equality table
/// in the dashboard keeps working.
fn vector_001_phase1_compat() -> Value {
    let path = format!("{VECTORS_DIR}/001-valid-handshake.json");
    let raw = fs::read_to_string(&path).expect("read vector 001");
    let v: Value = serde_json::from_str(&raw).expect("parse vector 001");

    let mut delegation = v["input"]["delegation"].clone();
    delegation.as_object_mut().unwrap().remove("signature");
    let unsigned_del_sha = jcs_sha256_hex(&delegation);

    let mut request_for_hash = v["input"]["request"].clone();
    request_for_hash
        .as_object_mut()
        .unwrap()
        .remove("signature");
    request_for_hash
        .as_object_mut()
        .unwrap()
        .insert("delegation_chain".into(), Value::Array(vec![delegation]));
    let unsigned_req_sha = jcs_sha256_hex(&request_for_hash);

    json!({
        "passed": true,
        "result": "accept",
        "unsigned_delegation_sha256": unsigned_del_sha,
        "unsigned_request_sha256": unsigned_req_sha,
    })
}

fn run_all_vectors() -> Vec<Value> {
    VECTOR_FILES
        .iter()
        .map(|(id, fname)| run_vector(id, &format!("{VECTORS_DIR}/{fname}")))
        .collect()
}

/// Walk tests/conformance/error_codes/*.json — malformed inputs whose only
/// job is to assert every implementation returns the same errorCode at the
/// same rejected_at_step. The aggregator builds a cross-impl matrix.
fn run_error_code_vectors() -> Vec<Value> {
    let mut out = Vec::new();
    let dir = match fs::read_dir(ERROR_CODES_DIR) {
        Ok(d) => d,
        Err(_) => return out,
    };
    let mut entries: Vec<_> = dir
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let path = entry.path();
        let raw = fs::read_to_string(&path).expect("read error_code vector");
        let v: Value = serde_json::from_str(&raw).expect("parse error_code vector");
        let vid = v
            .get("vector_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| {
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("?")
                    .to_string()
            });
        out.push(run_vector(&vid, path.to_str().expect("path utf8")));
    }
    out
}

/// Cross-call replay protection: verify vector 001 twice in a row sharing
/// a single nonce store. The first call must accept; the second must
/// reject with `replay_detected`. This mirrors what the Py / TS / Go
/// runners do via their FFI's process-shared nonce store.
fn run_replay_check() -> Value {
    let raw =
        fs::read_to_string(format!("{VECTORS_DIR}/001-valid-handshake.json")).expect("read 001");
    let v: Value = serde_json::from_str(&raw).expect("parse vector 001");
    let context = &v["context"];
    let now_str = context["now"].as_str().unwrap().to_string();
    let public_keys = context["public_keys"].as_object().unwrap().clone();
    let keys = synthesize_keys(&public_keys);

    let input = &v["input"];
    let mut signed_chain = Vec::new();
    if let Some(single) = input.get("delegation") {
        signed_chain.push(sign_link(single.clone(), &keys));
    }
    if let Some(arr) = input.get("delegation_chain").and_then(Value::as_array) {
        for link in arr {
            signed_chain.push(sign_link(link.clone(), &keys));
        }
    }
    let mut request = input["request"].clone();
    request
        .as_object_mut()
        .unwrap()
        .insert("delegation_chain".into(), Value::Array(signed_chain));
    let signed_request = sign_request(request, &keys);

    let mut resolver = StaticKeyResolver::new();
    for (did, kp) in &keys {
        resolver.insert(did, kp.public_key());
    }
    // ONE nonce store, TWO verify calls — that's the whole point of this check.
    let mut nonces = InMemoryNonceStore::new(120);
    let revs = StaticRevocationResolver::default();
    let req_struct: handshake::models::HandshakeRequest =
        serde_json::from_value(signed_request).expect("parse signed request");
    let receiver_did = req_struct.aud.clone();
    let now = chrono::DateTime::parse_from_rfc3339(&now_str)
        .unwrap()
        .with_timezone(&chrono::Utc);

    let mut ctx = VerifyContext {
        receiver_did: &receiver_did,
        now,
        skew_secs: DEFAULT_SKEW_SECS,
        keys: &resolver,
        nonces: &mut nonces,
        revocations: &revs,
    };
    let first = verify_handshake_request(&req_struct, &mut ctx);
    let first_result = if first.is_ok() { "accept" } else { "reject" };

    // SECOND call. Same signed request, same nonce store.
    let mut ctx2 = VerifyContext {
        receiver_did: &receiver_did,
        now,
        skew_secs: DEFAULT_SKEW_SECS,
        keys: &resolver,
        nonces: &mut nonces,
        revocations: &revs,
    };
    let second = verify_handshake_request(&req_struct, &mut ctx2);
    let (second_result, second_error_code) = match &second {
        Ok(_) => ("accept", None),
        Err(r) => ("reject", Some(r.error_code.as_str().to_string())),
    };
    let passed = first_result == "accept"
        && second_result == "reject"
        && second_error_code.as_deref() == Some("replay_detected");
    json!({
        "first_result": first_result,
        "second_result": second_result,
        "second_error_code": second_error_code,
        "passed": passed,
    })
}

fn vendor_label() -> &'static str {
    "rust"
}

// Bypass clippy's "unused_imports" gripe when bytes_to_sign isn't reached:
// we re-export it here for the conformance runner's documentation surface.
#[allow(dead_code)]
fn _rexport_assert(_b: fn() -> Result<Vec<u8>, handshake::Error>) {}
fn _check() {
    _rexport_assert(|| bytes_to_sign(&serde_json::Value::Null));
    let _ = ErrorCode::SignatureInvalid;
}

fn main() {
    _check();
    let report = json!({
        "implementation": vendor_label(),
        "spec_version": "0.2.3",
        "jcs_fixtures": run_jcs_fixtures(),
        "ed25519_kat": run_ed25519_kat(),
        "mldsa65_kat": run_mldsa65_kat(),
        "vector_001": vector_001_phase1_compat(),
        "vectors": run_all_vectors(),
        "error_code_vectors": run_error_code_vectors(),
        "replay_check": run_replay_check(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize report")
    );
}
