//! draft-04 §5.5.5 reference-block checks, without resolving cited artifacts.
//! Port of `go/verify/references.go`. CPB owns digest representation and
//! comparison context, so a foreign reference is not held to AAC's SHA-256
//! hex encoding. Log coordinates are recorded claims only; Class 1 never
//! authenticates their inclusion proofs.

use crate::registries::Registries;
use crate::verify::{is_hex64, mkf, Finding};
use serde_json::{Map, Value};

/// String-typed members of a `references[]` entry's `retention` object
/// (§5.5.5), checked in this order within each entry.
const RETENTION_STRING_MEMBERS: [&str; 3] = ["declarant", "retained_until", "not_retained_after"];

/// Check-1 findings for a `references[]` entry's `retention` (§5.5.5), in
/// order: the object itself, its REQUIRED `declarant` (absent or null is
/// missing, as for `disposition.approver`), the type of each member, and at
/// least one bound.
fn retention_findings(raw: &Value, path: &str, findings: &mut Vec<Finding>) {
    let Some(retention) = raw.as_object() else {
        findings.push(mkf(
            "field_not_object",
            &format!("{path} MUST be a JSON object when present (§5.5.5)"),
            Some(1),
            "error",
        ));
        return;
    };
    for field in RETENTION_STRING_MEMBERS {
        match retention.get(field) {
            None | Some(Value::Null) if field == "declarant" => findings.push(mkf(
                "missing_required_field",
                &format!("{path}.declarant is REQUIRED (§5.5.5)"),
                Some(1),
                "error",
            )),
            Some(v) if !v.is_string() => findings.push(mkf(
                "field_not_string",
                &format!("{path}.{field} MUST be a string when present (§5.5.5)"),
                Some(1),
                "error",
            )),
            _ => {}
        }
    }
    if !retention.contains_key("retained_until") && !retention.contains_key("not_retained_after") {
        findings.push(mkf(
            "retention_empty",
            &format!("{path} MUST carry retained_until or not_retained_after (§5.5.5)"),
            Some(1),
            "error",
        ));
    }
}

/// Findings for `references[]`, tagged with checks 1, 6 and 8.
pub(crate) fn reference_findings(capsule: &Map<String, Value>, regs: &Registries) -> Vec<Finding> {
    if !matches!(capsule.get("format_version"), Some(Value::String(v)) if v == "4") {
        return Vec::new();
    }
    let raw = match capsule.get("references") {
        Some(v) => v,
        None => return Vec::new(),
    };
    let mut findings = Vec::new();
    let refs = match raw.as_array() {
        Some(refs) => refs,
        None => {
            findings.push(mkf(
                "references_malformed",
                "references MUST be an array (§5.5.5)",
                Some(1),
                "error",
            ));
            return findings;
        }
    };
    let parent = capsule
        .get("chain")
        .and_then(Value::as_object)
        .and_then(|chain| chain.get("parent_capsule_id"))
        .and_then(Value::as_str);

    for (i, raw_ref) in refs.iter().enumerate() {
        let path = format!("references[{i}]");
        let reference = match raw_ref.as_object() {
            Some(m) => m,
            None => {
                findings.push(mkf(
                    "reference_malformed",
                    &format!("{path} MUST be an object (§5.5.5)"),
                    Some(1),
                    "error",
                ));
                continue;
            }
        };
        for field in ["type", "digest_alg", "digest"] {
            let ok = matches!(reference.get(field), Some(Value::String(s)) if !s.is_empty());
            if !ok {
                findings.push(mkf(
                    "reference_malformed",
                    &format!("{path}.{field} MUST be a non-empty string (§5.5.5)"),
                    Some(1),
                    "error",
                ));
            }
        }
        // Compare only a known AAC identity context, never equal-looking digests
        // belonging to a different artifact type or hash algorithm (CPB §7).
        let digest = reference
            .get("digest")
            .and_then(Value::as_str)
            .unwrap_or("");
        let is_aac_sha256 = matches!(reference.get("type"), Some(Value::String(t)) if t == "agent-action-capsule")
            && matches!(reference.get("digest_alg"), Some(Value::String(a)) if a == "SHA-256");
        if is_aac_sha256 {
            if !digest.is_empty() && !is_hex64(digest) {
                findings.push(mkf(
                    "reference_malformed",
                    &format!("{path}.digest MUST be an AAC Capsule ID for agent-action-capsule/SHA-256 (§5.5.5)"),
                    Some(1),
                    "error",
                ));
            }
            if let Some(parent) = parent {
                if !parent.is_empty() && digest == parent {
                    findings.push(mkf(
                        "reference_duplicates_chain_parent",
                        &format!("{path} duplicates chain.parent_capsule_id (§5.5.5)"),
                        Some(6),
                        "error",
                    ));
                }
            }
        }
        match reference.get("citation_purpose") {
            Some(Value::String(purpose)) if !purpose.is_empty() => {
                if !regs.contains("citation_purpose", purpose) {
                    findings.push(mkf(
                        "unknown_registry_value",
                        &format!("{path}.citation_purpose is not seeded; informational, not rejected (§12)"),
                        Some(8),
                        "info",
                    ));
                }
            }
            Some(_) => findings.push(mkf(
                "reference_malformed",
                &format!("{path}.citation_purpose MUST be a non-empty string (§5.5.5)"),
                Some(1),
                "error",
            )),
            None => {}
        }
        if let Some(retention) = reference.get("retention") {
            retention_findings(retention, &format!("{path}.retention"), &mut findings);
        }
        if let Some(raw_coordinates) = reference.get("log_coordinates") {
            let coordinates = match raw_coordinates.as_object() {
                Some(m) => m,
                None => {
                    findings.push(mkf(
                        "reference_log_coordinates_malformed",
                        &format!("{path}.log_coordinates MUST be an object (§5.5.5)"),
                        Some(1),
                        "error",
                    ));
                    continue;
                }
            };
            for field in ["log_id", "leaf_index", "inclusion_proof"] {
                if !matches!(coordinates.get(field), Some(v) if !v.is_null()) {
                    findings.push(mkf(
                        "reference_log_coordinates_malformed",
                        &format!("{path}.log_coordinates requires {field} (§5.5.5)"),
                        Some(1),
                        "error",
                    ));
                }
            }
        }
    }
    findings
}
