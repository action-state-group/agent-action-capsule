//! Class 1 verifier (§6) -- the subset `bundle.rs` needs to gate per-record
//! trust, ported from the Go/Python/TS siblings' `verify` module.
//!
//! **Scope note (deliberate, not a silent gap):** the siblings' check 8
//! ("unknown registry value") looks up `verdict_class` / `disposition.decision`
//! / `effect.type` / `irreversibility_class` / `effect_attestation` /
//! `chain.relation` / `references[].citation_purpose` against the vocabulary
//! tables generated from `spec/REGISTRY.md` (plus a vendored CPB provisional
//! snapshot) and reports what it finds -- but every finding check 8 can ever
//! produce is `info`-severity (`unknown_registry_value`,
//! `known_provisional_registry_value`, `effect_attestation_graded_floor`).
//! `info` never gates `ok`, and none of it is part of the recomputed
//! `capsule_id`. Since this crate's only consumer of `Verify` is
//! `bundle::records()`, which uses exactly `ok` and `capsule_id`, check 8 is
//! omitted rather than embedding and re-parsing REGISTRY.md's Markdown tables
//! for output nothing here observes. Every `error`-severity check (1-7) is
//! ported in full, so `ok` and `capsule_id` are bit-exact with the siblings.
//! A future consumer that needs check 8's informational findings should port
//! it then, not stub it now.

use crate::canonical::{compute_capsule_id, float_paths, unsafe_int_paths, CanonicalError};
use crate::references::reference_findings;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn is_hex64_value(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(s)) if is_hex64(s))
}

const REQUIRED_FIELDS: [&str; 8] = [
    "spec_version",
    "format_version",
    "capsule_id",
    "action_id",
    "action_type",
    "operator",
    "developer",
    "timestamp",
];

fn never_dispatch_verdict_class(v: &str) -> bool {
    matches!(
        v,
        "blocked"
            | "hitl_dispatched"
            | "denied"
            | "engine_failure"
            | "deferred"
            | "needs_decision"
            | "expired"
            | "escalated"
            | "resolved"
    )
}

fn valid_approver(v: &str) -> bool {
    matches!(v, "human" | "policy" | "counterparty")
}

fn effect_mode_rank(v: &str) -> Option<i32> {
    match v {
        "not_applicable" | "dispatched_unconfirmed" => Some(0),
        "confirmed" => Some(1),
        _ => None,
    }
}

fn attestation_rank(v: &str) -> Option<i32> {
    match v {
        "self_attested" => Some(0),
        "anchored" => Some(1),
        _ => None,
    }
}

fn ledger_mode_rank(v: &str) -> Option<i32> {
    match v {
        "standalone" => Some(0),
        "chained" => Some(1),
        "anchored" => Some(2),
        _ => None,
    }
}

fn cross_party_rung_rank(v: &str) -> Option<i32> {
    match v {
        "unilateral_fallback" => Some(0),
        "acknowledged_receipt" => Some(1),
        "full_bilateral" => Some(2),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub code: String,
    pub detail: String,
    pub severity: String,
    pub check: Option<i32>,
}

pub fn mkf(code: &str, detail: &str, check: Option<i32>, severity: &str) -> Finding {
    Finding {
        code: code.to_string(),
        detail: detail.to_string(),
        severity: severity.to_string(),
        check,
    }
}

#[derive(Debug, Clone, Default)]
pub struct VerificationResult {
    pub ok: bool,
    pub findings: Vec<Finding>,
    pub assurance: BTreeMap<String, String>,
    pub capsule_id: Option<String>,
}

fn as_map(v: Option<&Value>) -> Option<&Map<String, Value>> {
    v.and_then(Value::as_object)
}

/// Derives `assurance.effect_mode` from the Effect Record (§5.2).
fn derive_effect_mode(effect: Option<&Map<String, Value>>) -> String {
    let effect = match effect {
        Some(e) => e,
        None => return "not_applicable".to_string(),
    };
    match effect.get("status").and_then(Value::as_str) {
        Some("planned") => "not_applicable".to_string(),
        Some("confirmed") => {
            if is_hex64_value(effect.get("response_digest")) {
                "confirmed".to_string()
            } else {
                "dispatched_unconfirmed".to_string()
            }
        }
        _ => "dispatched_unconfirmed".to_string(),
    }
}

/// Derives `assurance.cross_party_rung` (§5.3) from the top-level
/// `cross_party` block alone -- a structural check over the block's own
/// bytes, never a dereference of the digests it cites.
fn derive_cross_party_rung(cross_party: Option<&Map<String, Value>>) -> Option<String> {
    let cross_party = cross_party?;
    let has_ref = is_hex64_value(cross_party.get("counterparty_ref"));
    let correlator = cross_party.get("correlator").and_then(Value::as_str);
    if !has_ref || !matches!(correlator, Some(c) if !c.is_empty()) {
        return Some("unilateral_fallback".to_string());
    }
    if matches!(cross_party.get("substantive"), Some(Value::Bool(true))) {
        return Some("full_bilateral".to_string());
    }
    Some("acknowledged_receipt".to_string())
}

fn store_ids(store: &[Value]) -> std::collections::HashSet<String> {
    let mut ids = std::collections::HashSet::new();
    for item in store {
        match item {
            Value::Object(m) => {
                if let Some(Value::String(id)) = m.get("capsule_id") {
                    ids.insert(id.clone());
                }
            }
            Value::String(id) => {
                ids.insert(id.clone());
            }
            _ => {}
        }
    }
    ids
}

/// Runs Class 1 verification (§6) over a single Capsule. Never panics.
/// `store` is the ledger of capsules for chain-level checks; `None` means
/// store-level checks are skipped (as `bundle::records()` does, matching the
/// Go/Python/TS siblings' `Verify(record, nil, nil)` call site).
pub fn verify(capsule: &Value, store: Option<&[Value]>) -> VerificationResult {
    let capsule_map = match capsule.as_object() {
        Some(m) => m,
        None => {
            return VerificationResult {
                ok: false,
                findings: vec![mkf(
                    "not_an_object",
                    "Capsule is not a JSON object",
                    Some(1),
                    "error",
                )],
                ..Default::default()
            };
        }
    };

    let mut findings = Vec::new();
    let effect = as_map(capsule_map.get("effect"));
    let disposition = as_map(capsule_map.get("disposition"));
    let chain = as_map(capsule_map.get("chain"));
    let cross_party = as_map(capsule_map.get("cross_party"));

    let mut reference_checks: BTreeMap<i32, Vec<Finding>> = BTreeMap::new();
    for finding in reference_findings(capsule_map) {
        if let Some(check) = finding.check {
            reference_checks.entry(check).or_default().push(finding);
        }
    }

    // ---- Check 1: Structural ------------------------------------------------

    for field in REQUIRED_FIELDS {
        match capsule_map.get(field) {
            None => findings.push(mkf(
                "missing_required_field",
                &format!("{field} is REQUIRED (§5.1)"),
                Some(1),
                "error",
            )),
            Some(v) if !v.is_string() => findings.push(mkf(
                "field_not_string",
                &format!("{field} MUST be a string (§5.1)"),
                Some(1),
                "error",
            )),
            _ => {}
        }
    }

    let mut cid_present = matches!(capsule_map.get("capsule_id"), Some(Value::String(_)));
    if let Some(Value::String(cid)) = capsule_map.get("capsule_id") {
        if !is_hex64(cid) {
            findings.push(mkf(
                "capsule_id_malformed",
                "capsule_id MUST be 64 lowercase hex (§5.1)",
                Some(1),
                "error",
            ));
            cid_present = false; // treat as absent for recompute below
        }
    }

    if let Some(Value::String(at)) = capsule_map.get("action_type") {
        if at != "fyi" && at != "decide" {
            findings.push(mkf(
                "action_type_invalid",
                "action_type MUST be 'fyi' or 'decide' (§5.1)",
                Some(1),
                "error",
            ));
        }
    }

    // Format 4 requires declared plain JCS.
    let mut identity_profile_valid = false;
    if let Some(Value::String(fv)) = capsule_map.get("format_version") {
        if fv != "4" {
            findings.push(mkf(
                "unsupported_format_version",
                &format!("format_version {fv:?} is not supported; expected \"4\" (§5.1)"),
                Some(1),
                "error",
            ));
        } else {
            match capsule_map.get("canonicalization_id") {
                None => findings.push(mkf(
                    "canonicalization_id_missing",
                    "format_version \"4\" REQUIRES canonicalization_id=\"jcs\" (§5.1)",
                    Some(1),
                    "error",
                )),
                Some(Value::String(algorithm)) if algorithm == "jcs" => {
                    identity_profile_valid = true;
                }
                Some(Value::String(_)) => findings.push(mkf(
                    "canonicalization_profile_mismatch",
                    "format_version \"4\" REQUIRES canonicalization_id=\"jcs\" (§5.1)",
                    Some(1),
                    "error",
                )),
                Some(_) => findings.push(mkf(
                    "canonicalization_id_not_string",
                    "canonicalization_id MUST be a string (§5.1)",
                    Some(1),
                    "error",
                )),
            }
        }
    }

    for field in ["effect", "assurance", "disposition", "chain", "cross_party"] {
        if let Some(v) = capsule_map.get(field) {
            if !v.is_object() {
                findings.push(mkf(
                    "block_not_object",
                    &format!("{field} MUST be a JSON object when present"),
                    Some(1),
                    "error",
                ));
            }
        }
    }

    if let Some(cv) = capsule_map.get("constraints") {
        if !cv.is_array() {
            findings.push(mkf(
                "constraints_not_array",
                "constraints MUST be an array when present (§8.1)",
                Some(1),
                "error",
            ));
        }
    }

    for p in float_paths(capsule, "") {
        findings.push(mkf(
            "float_in_digest_field",
            &format!("floating-point value at {p}; §5.1 forbids it"),
            Some(1),
            "error",
        ));
    }

    for p in unsafe_int_paths(capsule, "") {
        findings.push(mkf(
            "unsafe_integer_in_digest_field",
            &format!(
                "integer outside the JS-safe range (+/-{}) at {p}; large integers MUST be exact \
                 decimal strings for cross-impl digest reproducibility (impl guard ahead of -00; \
                 see -01 flag)",
                crate::canonical::MAX_SAFE_INTEGER
            ),
            Some(1),
            "error",
        ));
    }

    if let Some(disposition) = disposition {
        let approver = disposition.get("approver").and_then(Value::as_str);
        match approver {
            None => findings.push(mkf(
                "missing_required_field",
                "disposition.approver is REQUIRED (§5.4)",
                Some(1),
                "error",
            )),
            Some(a) if !valid_approver(a) => findings.push(mkf(
                "approver_invalid",
                &format!(
                    "disposition.approver MUST be human|policy|counterparty (§5.4); got {a:?}"
                ),
                Some(1),
                "error",
            )),
            _ => {}
        }
        if disposition.get("decision").is_none() {
            findings.push(mkf(
                "missing_required_field",
                "disposition.decision is REQUIRED (§5.4)",
                Some(1),
                "error",
            ));
        }
        match disposition.get("human_disposed") {
            Some(Value::Bool(hd)) => {
                if *hd && approver != Some("human") {
                    // Defensive honesty check (§6): non-gating warning.
                    findings.push(mkf(
                        "dishonest_human_disposed",
                        "human_disposed=true with a non-human approver (§5.4). Structurally \
                         unconstructable by a conforming producer; reported as a non-gating \
                         defensive warning, not a §6 gating check.",
                        None,
                        "warning",
                    ));
                }
            }
            _ => findings.push(mkf(
                "field_not_bool",
                "disposition.human_disposed is REQUIRED and boolean (§5.4)",
                Some(1),
                "error",
            )),
        }
    }

    if let Some(fs) = reference_checks.get(&1) {
        findings.extend(fs.clone());
    }

    // ---- Check 2: Identity --------------------------------------------------
    let mut recomputed_id: Option<String> = None;
    if cid_present && identity_profile_valid {
        match compute_capsule_id(capsule_map) {
            Ok(computed) => {
                let carried = capsule_map.get("capsule_id").and_then(Value::as_str);
                if Some(computed.as_str()) != carried {
                    findings.push(mkf(
                        "capsule_id_mismatch",
                        &format!("recomputed {computed} != carried {}", carried.unwrap_or("")),
                        Some(2),
                        "error",
                    ));
                }
                recomputed_id = Some(computed);
            }
            Err(CanonicalError::Float(_)) | Err(CanonicalError::UnsafeInt(_)) => {
                // Already reported structurally (check 1); recomputed_id stays None.
            }
            Err(err) => findings.push(mkf(
                "capsule_id_uncomputable",
                &err.to_string(),
                Some(2),
                "error",
            )),
        }
    }

    // ---- Check 3: Confirmed-effect binding ----------------------------------
    if let Some(effect) = effect {
        if matches!(
            effect.get("status").and_then(Value::as_str),
            Some("confirmed")
        ) && !is_hex64_value(effect.get("response_digest"))
        {
            findings.push(mkf(
                "confirmed_without_response",
                "effect.status 'confirmed' requires a 64-hex response_digest (§5.2)",
                Some(3),
                "error",
            ));
        }
    }

    let effect_mode = derive_effect_mode(effect);

    // ---- Check 4: Verdict/effect orthogonality ------------------------------
    let verdict_class = disposition
        .and_then(|d| d.get("verdict_class"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if never_dispatch_verdict_class(verdict_class) && effect_mode != "not_applicable" {
        findings.push(mkf(
            "verdict_effect_conflict",
            &format!(
                "verdict_class {verdict_class:?} never dispatches, but derived effect_mode is \
                 {effect_mode:?} (§5.4.2)"
            ),
            Some(4),
            "error",
        ));
    }

    // ---- Check 5: Effect-attestation matrix ---------------------------------
    let ea = effect.and_then(|e| e.get("effect_attestation"));
    if effect_mode == "confirmed" || effect_mode == "dispatched_unconfirmed" {
        if ea.is_none() {
            findings.push(mkf(
                "effect_attestation_missing",
                &format!("effect_attestation REQUIRED for effect_mode {effect_mode:?} (§5.2)"),
                Some(5),
                "error",
            ));
        }
    } else if ea.is_some() {
        findings.push(mkf(
            "effect_attestation_present",
            "effect_attestation MUST be absent for effect_mode 'not_applicable' (§5.2)",
            Some(5),
            "error",
        ));
    }

    // ---- Check 6: Chain semantics -------------------------------------------
    if let Some(chain) = chain {
        let parent = chain.get("parent_capsule_id");
        if !is_hex64_value(parent) {
            findings.push(mkf(
                "chain_parent_malformed",
                "chain.parent_capsule_id MUST be a 64-hex capsule_id (§5.4.4)",
                Some(6),
                "error",
            ));
        }
        if chain.get("relation").is_none() {
            findings.push(mkf(
                "missing_required_field",
                "chain.relation is REQUIRED when a chain block is present (§5.4.4)",
                Some(6),
                "error",
            ));
        }
        match store {
            None => findings.push(mkf(
                "chain_check_store_level",
                "chain parent-existence and concurrent-supersedes are store-level checks (§6); \
                 not run without a store",
                Some(6),
                "info",
            )),
            Some(store) => {
                let ids = store_ids(store);
                if let Some(Value::String(parent_str)) = parent {
                    if !ids.contains(parent_str) {
                        findings.push(mkf(
                            "chain_parent_missing",
                            &format!("chain parent {parent_str} not found in the store (§6)"),
                            Some(6),
                            "error",
                        ));
                    }
                }
            }
        }
    }

    if let Some(fs) = reference_checks.get(&6) {
        findings.extend(fs.clone());
    }

    // ---- Check 7: Assurance reconciliation ----------------------------------
    let ledger_mode = if chain.is_some() {
        "chained"
    } else {
        "standalone"
    };
    let mut derived: BTreeMap<String, String> = BTreeMap::new();
    derived.insert("effect_mode".to_string(), effect_mode.clone());
    derived.insert("attestation_mode".to_string(), "self_attested".to_string());
    derived.insert("ledger_mode".to_string(), ledger_mode.to_string());
    let derived_cross_party_rung = derive_cross_party_rung(cross_party);
    if cross_party.is_some() {
        if let Some(rung) = &derived_cross_party_rung {
            derived.insert("cross_party_rung".to_string(), rung.clone());
        }
    }

    if let Some(stated) = as_map(capsule_map.get("assurance")) {
        if let Some(sm) = stated.get("effect_mode").and_then(Value::as_str) {
            if let Some(r) = effect_mode_rank(sm) {
                if let Some(dr) = effect_mode_rank(&effect_mode) {
                    if r > dr {
                        findings.push(mkf(
                            "assurance_overclaim",
                            &format!(
                                "claimed effect_mode {sm:?} but verifier derived {effect_mode:?} (§5.3)"
                            ),
                            Some(7),
                            "error",
                        ));
                    }
                }
            }
        }
        if let Some(sa) = stated.get("attestation_mode").and_then(Value::as_str) {
            if let Some(r) = attestation_rank(sa) {
                if r > attestation_rank("self_attested").unwrap_or(0) {
                    findings.push(mkf(
                        "assurance_overclaim",
                        &format!(
                            "claimed attestation_mode {sa:?} but no Receipt verified at this \
                             layer (§5.3)"
                        ),
                        Some(7),
                        "info",
                    ));
                }
            }
        }
        if let Some(sl) = stated.get("ledger_mode").and_then(Value::as_str) {
            if let Some(r) = ledger_mode_rank(sl) {
                if r > ledger_mode_rank(ledger_mode).unwrap_or(0) {
                    findings.push(mkf(
                        "assurance_overclaim",
                        &format!("claimed ledger_mode {sl:?} but verifier derived {ledger_mode:?} (§5.3)"),
                        Some(7),
                        "info",
                    ));
                }
            }
        }
        if let Some(sc) = stated.get("cross_party_rung").and_then(Value::as_str) {
            if let Some(r) = cross_party_rung_rank(sc) {
                let derived_rank = derived_cross_party_rung
                    .as_deref()
                    .and_then(cross_party_rung_rank)
                    .unwrap_or(0);
                if r > derived_rank {
                    findings.push(mkf(
                        "assurance_overclaim",
                        &format!(
                            "claimed cross_party_rung {sc:?} but verifier derived {:?} (§5.3 \
                             Cross-party assurance)",
                            derived_cross_party_rung.as_deref().unwrap_or("")
                        ),
                        Some(7),
                        "info",
                    ));
                }
            }
        }
    }

    // ---- Check 8: Unknown registry values -----------------------------------
    // Deliberately omitted -- info-severity only, see module doc.

    let ok = !findings.iter().any(|f| f.severity == "error");
    VerificationResult {
        ok,
        findings,
        assurance: derived,
        capsule_id: recomputed_id,
    }
}
