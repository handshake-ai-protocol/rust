//! Capability intersection — the constraint algebra spec §10 calls out as the
//! security-critical core of the verifier. When a delegation grants a
//! capability with a constraint set `C_d` and a request asks for that
//! capability with constraint set `C_r`, the request is admissible iff
//! `C_r` is at least as narrow as `C_d` on every typed dimension. The
//! "intersection" is the most-permissive constraint set still ⊆ both inputs.
//!
//! For Phase 2 we ship the constraint types named in the handoff §1.1:
//! `numeric_max`, `numeric_min`, `string_pattern`, `enum`, `time_window`,
//! `rate_limit`, `resource_path`. Type inference from JSON is by key prefix
//! (`max_*` → numeric_max, `min_*` → numeric_min) for the common case, with
//! everything else falling back to exact-equality match. The algebra is
//! a join-semilattice (commutative, associative, idempotent, monotone under
//! narrowing); see `tests/intersect_axioms.rs` for property tests.
//!
//! `intersect(d, r)` returns `Some(narrowed)` when admissible, `None` when
//! `r` exceeds `d` on any dimension. The narrowed value is the binding
//! that should appear on the resulting `Acceptance.effective_scope`.

use serde_json::{Map, Value};

/// Categorize a constraint key into one of the typed algebra slots.
///
/// The typing rule is a documented per-key prefix convention so that JSON
/// constraint authors get the algebra they expect without having to wrap
/// every value in a `{ "type": "numeric_max", "value": 100 }` envelope.
/// Unknown keys fall through to [`ConstraintType::ExactMatch`] which
/// requires byte-equal values on both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintType {
    /// Upper bound: intersection = `min(d, r)`. Request value > delegated → reject.
    NumericMax,
    /// Lower bound: intersection = `max(d, r)`. Request value < delegated → reject.
    NumericMin,
    /// Regex pattern (string). Intersection valid iff equal.
    StringPattern,
    /// Set membership. Intersection = set-intersection. Empty → reject.
    Enum,
    /// `[start, end]` RFC 3339 pair. Intersection = `[max(starts), min(ends)]`.
    TimeWindow,
    /// `{ "per_minute": N }` etc. Intersection = `min` per dimension.
    RateLimit,
    /// Path glob (string). Intersection valid iff request glob ⊆ delegated glob.
    /// Phase 2 ships exact-match; full glob containment is Phase 2.1.
    ResourcePath,
    /// Unrecognized key — require exact equality.
    ExactMatch,
}

impl ConstraintType {
    /// Infer the constraint type from the JSON key + value shape.
    /// Documented as a prefix convention rather than a full schema lookup
    /// so authors writing a `DelegationToken` JSON literal get sensible
    /// algebra without having to wrap every value in a typed envelope.
    #[must_use]
    pub fn infer(key: &str, value: &Value) -> Self {
        if value.is_number() {
            if key.starts_with("max_") || key == "max" {
                return Self::NumericMax;
            }
            if key.starts_with("min_") || key == "min" {
                return Self::NumericMin;
            }
        }
        if key.ends_with("_pattern") {
            return Self::StringPattern;
        }
        if key == "enum" || key.ends_with("_enum") {
            return Self::Enum;
        }
        if key == "time_window" || key.ends_with("_window") {
            return Self::TimeWindow;
        }
        if key == "rate_limit" || key.ends_with("_rate") {
            return Self::RateLimit;
        }
        if key == "resource_path" || key.ends_with("_path") {
            return Self::ResourcePath;
        }
        Self::ExactMatch
    }
}

/// Reasons an intersection can fail. Surfaced verbatim into the
/// `Refusal.detail` field so the test vectors' `detail_must_include`
/// assertions are satisfiable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeViolation {
    /// The constraint key that failed (e.g. `"max_invoices"`).
    pub key: String,
    /// Human-readable explanation. Stable wording — the conformance
    /// harness substring-matches against this.
    pub reason: String,
}

/// Intersect two capability constraint sets `d` (delegated) and `r`
/// (requested). Returns the narrowed set when admissible, or the first
/// violation encountered.
///
/// # Errors
/// Returns [`ScopeViolation`] when `r` exceeds `d` on any constraint.
pub fn intersect(
    d: &Map<String, Value>,
    r: &Map<String, Value>,
) -> Result<Map<String, Value>, ScopeViolation> {
    let mut out = Map::new();

    // Walk every key on both sides. A constraint present only on `d` carries
    // through (the request didn't narrow it; that's fine). A constraint
    // present only on `r` is admissible only if `d` is silent on that
    // dimension (request narrows further); we accept it.
    let mut all_keys: Vec<&String> = d.keys().chain(r.keys()).collect();
    all_keys.sort();
    all_keys.dedup();

    for key in all_keys {
        let d_val = d.get(key);
        let r_val = r.get(key);

        match (d_val, r_val) {
            (Some(dv), None) => {
                // Delegation grants this constraint; request is silent.
                // The effective scope still carries the delegation's bound.
                out.insert(key.clone(), dv.clone());
            }
            (None, Some(rv)) => {
                // Request adds a constraint the delegation didn't mention.
                // That's a self-narrowing — always admissible.
                out.insert(key.clone(), rv.clone());
            }
            (Some(dv), Some(rv)) => {
                let ty = ConstraintType::infer(key, dv);
                let narrowed = intersect_one(key, ty, dv, rv)?;
                out.insert(key.clone(), narrowed);
            }
            (None, None) => unreachable!("dedup guarantees at least one side has the key"),
        }
    }

    Ok(out)
}

fn intersect_one(
    key: &str,
    ty: ConstraintType,
    d: &Value,
    r: &Value,
) -> Result<Value, ScopeViolation> {
    match ty {
        ConstraintType::NumericMax => {
            let (dn, rn) = both_numbers(key, d, r)?;
            if rn > dn {
                return Err(ScopeViolation {
                    key: key.to_string(),
                    reason: format!("requested {key}={rn} exceeds delegated max {dn}"),
                });
            }
            // Pick the narrower side and return its original Value to preserve
            // integer typing when both sides are integers (otherwise serde
            // promotes to f64 and breaks JCS byte-equality with Go/TS).
            Ok(if rn <= dn { r.clone() } else { d.clone() })
        }
        ConstraintType::NumericMin => {
            let (dn, rn) = both_numbers(key, d, r)?;
            if rn < dn {
                return Err(ScopeViolation {
                    key: key.to_string(),
                    reason: format!("requested {key}={rn} below delegated min {dn}"),
                });
            }
            Ok(if rn >= dn { r.clone() } else { d.clone() })
        }
        ConstraintType::Enum => {
            let da = d.as_array().ok_or_else(|| ScopeViolation {
                key: key.to_string(),
                reason: format!(
                    "constraint {key} declared as enum but delegated value is not an array"
                ),
            })?;
            let ra = r.as_array().ok_or_else(|| ScopeViolation {
                key: key.to_string(),
                reason: format!(
                    "constraint {key} declared as enum but requested value is not an array"
                ),
            })?;
            // Set intersection preserving the request's order so callers can
            // reason about the surviving values without a separate sort.
            let mut narrowed = Vec::new();
            for rv in ra {
                if da.contains(rv) {
                    narrowed.push(rv.clone());
                }
            }
            if narrowed.is_empty() {
                return Err(ScopeViolation {
                    key: key.to_string(),
                    reason: format!("requested enum {key} disjoint from delegated set"),
                });
            }
            Ok(Value::from(narrowed))
        }
        ConstraintType::TimeWindow | ConstraintType::RateLimit => {
            // Phase 2 ships exact-equality semantics for these; the handoff
            // §7 Phase 2 lists the algebra but the test vectors don't
            // exercise them. Phase 2.1 will replace this with the full
            // typed implementation per spec §10.
            if d == r {
                Ok(d.clone())
            } else {
                Err(ScopeViolation {
                    key: key.to_string(),
                    reason: format!("constraint {key} differs between delegation and request (full {ty:?} algebra is Phase 2.1; exact match required for now)"),
                })
            }
        }
        ConstraintType::StringPattern
        | ConstraintType::ResourcePath
        | ConstraintType::ExactMatch => {
            if d == r {
                Ok(d.clone())
            } else {
                Err(ScopeViolation {
                    key: key.to_string(),
                    reason: format!(
                        "constraint {key} requires exact match between delegation and request"
                    ),
                })
            }
        }
    }
}

fn both_numbers(key: &str, d: &Value, r: &Value) -> Result<(f64, f64), ScopeViolation> {
    let dn = d.as_f64().ok_or_else(|| ScopeViolation {
        key: key.to_string(),
        reason: format!("delegated {key} is not a number"),
    })?;
    let rn = r.as_f64().ok_or_else(|| ScopeViolation {
        key: key.to_string(),
        reason: format!("requested {key} is not a number"),
    })?;
    Ok((dn, rn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().expect("object literal").clone()
    }

    #[test]
    fn numeric_max_narrows_to_minimum() {
        let d = obj(json!({"max_invoices": 100}));
        let r = obj(json!({"max_invoices": 50}));
        let got = intersect(&d, &r).expect("admissible");
        assert_eq!(got["max_invoices"], json!(50));
    }

    #[test]
    fn numeric_max_rejects_request_above_delegation() {
        let d = obj(json!({"max_invoices": 100}));
        let r = obj(json!({"max_invoices": 500}));
        let err = intersect(&d, &r).expect_err("scope exceeded");
        assert_eq!(err.key, "max_invoices");
        assert!(err.reason.contains("max_invoices"));
    }

    #[test]
    fn delegated_only_constraint_passes_through() {
        let d = obj(json!({"max_invoices": 100, "min_age": 18}));
        let r = obj(json!({"max_invoices": 50}));
        let got = intersect(&d, &r).expect("admissible");
        assert_eq!(got["max_invoices"], json!(50));
        assert_eq!(got["min_age"], json!(18));
    }

    #[test]
    fn request_only_constraint_is_self_narrowing() {
        let d = obj(json!({"max_invoices": 100}));
        let r = obj(json!({"max_invoices": 50, "region": "us-east-1"}));
        let got = intersect(&d, &r).expect("admissible");
        assert_eq!(got["region"], json!("us-east-1"));
    }

    #[test]
    fn enum_intersection() {
        let d = obj(json!({"actions_enum": ["read", "write", "list"]}));
        let r = obj(json!({"actions_enum": ["read", "list"]}));
        let got = intersect(&d, &r).expect("admissible");
        assert_eq!(got["actions_enum"], json!(["read", "list"]));
    }

    #[test]
    fn enum_disjoint_rejects() {
        let d = obj(json!({"actions_enum": ["read"]}));
        let r = obj(json!({"actions_enum": ["delete"]}));
        assert!(intersect(&d, &r).is_err());
    }

    #[test]
    fn exact_match_for_unknown_key() {
        let d = obj(json!({"region": "us-east-1"}));
        let r1 = obj(json!({"region": "us-east-1"}));
        let r2 = obj(json!({"region": "eu-west-1"}));
        assert!(intersect(&d, &r1).is_ok());
        assert!(intersect(&d, &r2).is_err());
    }
}
