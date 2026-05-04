// SPDX-License-Identifier: Apache-2.0
//! RFC 8785 — JSON Canonicalization Scheme (JCS).
//!
//! Delegates to the `serde_jcs` crate, which implements:
//!
//! * Object keys sorted by UTF-16 code-unit ordering.
//! * No whitespace between tokens.
//! * Minimal RFC 8259 string escaping.
//! * **ECMAScript 6.1.6.1 Number→String** for all numeric values, including
//!   the IEEE-754 edge cases tested in our conformance corpus
//!   (`tests/conformance/fixtures/jcs.json` IEEE-754 block).
//! * Arrays preserve order.
//!
//! We wrap the crate so we can change implementations later without breaking
//! downstream callers (the FFI shims in `handshake-py` and `handshake-ts`,
//! and the conformance runner in `tests/conformance/`).

use crate::error::Error;
use serde::Serialize;

/// Canonicalize any `Serialize` value per RFC 8785 and return the resulting
/// UTF-8 bytes. The output is the unique byte string that EdDSA / ML-DSA-65
/// signatures cover.
///
/// # Errors
/// Returns [`Error::Canonicalization`] if the value contains a non-finite
/// float (NaN / +/-Infinity), which RFC 8785 forbids. Any other failure
/// (which would indicate a serializer bug) is wrapped the same way.
pub fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    serde_jcs::to_vec(value).map_err(|e| Error::Canonicalization(e.to_string()))
}

/// Canonicalize and return a UTF-8 string. Convenience for callers that want
/// to log or hash the canonical form.
pub fn canonicalize_string<T: Serialize>(value: &T) -> Result<String, Error> {
    let bytes = canonicalize(value)?;
    String::from_utf8(bytes).map_err(|e| Error::Canonicalization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canon(v: serde_json::Value) -> String {
        canonicalize_string(&v).unwrap()
    }

    #[test]
    fn keys_are_sorted() {
        assert_eq!(canon(json!({"b": 2, "a": 1})), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn no_whitespace_between_tokens() {
        assert_eq!(canon(json!([1, 2, {"x": "y"}])), r#"[1,2,{"x":"y"}]"#);
    }

    #[test]
    fn nested_objects_recursively_sorted() {
        assert_eq!(
            canon(json!({"z": {"b": 2, "a": 1}, "a": [3, 1, 2]})),
            r#"{"a":[3,1,2],"z":{"a":1,"b":2}}"#
        );
    }

    #[test]
    fn ecmascript_number_canonicalization() {
        // RFC 8785 Appendix B examples — these are the exact strings
        // ECMAScript 6.1.6.1 produces.
        assert_eq!(canon(json!(0)), "0");
        assert_eq!(canon(json!(4.50)), "4.5");
        assert_eq!(canon(json!(0.002)), "0.002");
        assert_eq!(canon(json!(1e30_f64)), "1e+30");
        assert_eq!(canon(json!(1e-7_f64)), "1e-7");
    }

    #[test]
    fn unicode_passes_through() {
        assert_eq!(canon(json!("héllo")), "\"héllo\"");
    }
}
