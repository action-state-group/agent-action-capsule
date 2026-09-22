//! draft-04 §5.5.5 reference-block structural checks, without resolving cited
//! artifacts. Byte-for-byte port of the Go/Python/TS siblings' `references`
//! finding logic, minus the `citation_purpose` "known in registry" lookup:
//! that check is `info`-severity only (never gates `ok`) and depends on the
//! REGISTRY.md-derived vocabulary tables, which this crate does not embed
//! (see `verify.rs` module doc for the scope note). Every `error`-severity
//! reference finding is ported in full.

use crate::verify::{is_hex64, mkf, Finding};
use serde_json::{Map, Value};

pub fn reference_findings(capsule: &Map<String, Value>) -> Vec<Finding> {
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
        // citation_purpose registry-membership ("known"/"unknown") is info-only
        // and omitted here (see module doc); a present-but-empty/non-string
        // citation_purpose is still a structural error.
        if let Some(raw_purpose) = reference.get("citation_purpose") {
            let ok = matches!(raw_purpose, Value::String(s) if !s.is_empty());
            if !ok {
                findings.push(mkf(
                    "reference_malformed",
                    &format!("{path}.citation_purpose MUST be a non-empty string (§5.5.5)"),
                    Some(1),
                    "error",
                ));
            }
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
