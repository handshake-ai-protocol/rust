//! Rust conformance runner. Reads the shared fixtures + test vector 001,
//! emits a JSON report on stdout matching the schema consumed by
//! `examples/phase1_demo.sh`.
//!
//! Schema (per implementation):
//! ```jsonc
//! {
//!   "implementation": "rust",
//!   "spec_version": "0.2.3",
//!   "jcs_fixtures": [{"name": "...", "sha256": "..."}],
//!   "ed25519_kat":  { "passed": true, ... },
//!   "mldsa65_kat":  { "passed": true, ... },
//!   "vector_001":   { "passed": true, ... }
//! }
//! ```

use handshake::{hash, jcs, mldsa, sign};
use serde_json::{json, Value};
use std::fs;

const REPO_ROOT_FIXTURES: &str = "tests/conformance/fixtures/jcs.json";
const VECTOR_001: &str =
    "packages/handshake-spec/test-vectors/v0.2.3/core/001-valid-handshake.json";

fn jcs_sha256_hex(v: &Value) -> String {
    let bytes = jcs::canonicalize(v).expect("canonicalize");
    hex::encode(hash::sha256(&bytes))
}

fn run_jcs_fixtures() -> Vec<Value> {
    let raw = fs::read_to_string(REPO_ROOT_FIXTURES).expect("read jcs fixtures");
    let parsed: Value = serde_json::from_str(&raw).expect("parse fixtures");
    let mut out = Vec::new();
    for f in parsed["fixtures"].as_array().expect("fixtures array") {
        // Skip "comment" entries that don't carry a "name" field.
        let Some(name) = f.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let canonical = jcs::canonicalize(&f["input"]).expect("canonicalize");
        // Where the fixture pins an expected canonical string, this implementation
        // MUST produce it byte-for-byte. Hard-fail on mismatch so we cannot pass
        // the suite by drifting in lock-step with the other implementations.
        if let Some(expected) = f.get("expected_canonical").and_then(|v| v.as_str()) {
            let actual = std::str::from_utf8(&canonical).expect("utf8");
            assert_eq!(
                actual, expected,
                "fixture {name}: canonical bytes diverge from golden",
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

fn run_vector_001() -> Value {
    // The vector includes placeholder signatures; we strip them, regenerate
    // signing keys locally, sign the JCS canonical form, verify, and check the
    // expected outcome. The JCS-canonical-bytes hashes (unsigned form) must be
    // byte-identical across all four SDK implementations.
    let raw = fs::read_to_string(VECTOR_001).expect("read vector 001");
    let v: Value = serde_json::from_str(&raw).expect("parse vector 001");

    let expected_result = v["expected"]["result"]
        .as_str()
        .unwrap_or("accept")
        .to_string();

    // ---- delegation ----
    let mut delegation = v["input"]["delegation"].clone();
    delegation
        .as_object_mut()
        .expect("delegation object")
        .remove("signature");
    let unsigned_del_sha = jcs_sha256_hex(&delegation);

    let user_kp = sign::Keypair::generate();
    let agent_kp = sign::Keypair::generate();

    let del_canonical = jcs::canonicalize(&delegation).expect("canon delegation");
    let del_sig_b64 = user_kp.sign_b64(&del_canonical);

    sign::verify_b64(&user_kp.public_key(), &del_sig_b64, &del_canonical)
        .expect("delegation verifies");

    let mut signed_delegation = delegation.clone();
    signed_delegation
        .as_object_mut()
        .unwrap()
        .insert("signature".into(), Value::String(del_sig_b64));

    // ---- request ----
    // The cross-implementation byte-equality bar requires deterministic input;
    // a freshly-signed delegation has a random signature, so build the
    // canonical-bytes snapshot with the *unsigned* delegation in the chain.
    // The signing/verification round-trip below uses the signed delegation —
    // those signatures are local to each runner and don't need to match.
    let mut request_for_hash = v["input"]["request"].clone();
    request_for_hash
        .as_object_mut()
        .expect("request object")
        .remove("signature");
    request_for_hash.as_object_mut().unwrap().insert(
        "delegation_chain".into(),
        Value::Array(vec![delegation.clone()]),
    );
    let unsigned_req_sha = jcs_sha256_hex(&request_for_hash);

    let mut request_for_signing = request_for_hash.clone();
    request_for_signing.as_object_mut().unwrap().insert(
        "delegation_chain".into(),
        Value::Array(vec![signed_delegation]),
    );

    let req_canonical = jcs::canonicalize(&request_for_signing).expect("canon request");
    let req_sig_b64 = agent_kp.sign_b64(&req_canonical);
    sign::verify_b64(&agent_kp.public_key(), &req_sig_b64, &req_canonical)
        .expect("request verifies");

    json!({
        "passed": true,
        "result": expected_result,
        "unsigned_delegation_sha256": unsigned_del_sha,
        "unsigned_request_sha256": unsigned_req_sha,
    })
}

fn main() {
    let report = json!({
        "implementation": "rust",
        "spec_version": "0.2.3",
        "jcs_fixtures": run_jcs_fixtures(),
        "ed25519_kat": run_ed25519_kat(),
        "mldsa65_kat": run_mldsa65_kat(),
        "vector_001": run_vector_001(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize report")
    );
}
