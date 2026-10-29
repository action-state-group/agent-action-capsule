//! Class 1 verifier (§6). Port of `go/verify`.
//!
//! A verifier validates a Capsule from its own bytes without trusting the
//! producer. It returns a structured result and never panics (§6). `ok` gates
//! trust in every other reported field; findings are reported in a fixed
//! order. Unknown registry values are informational, never a rejection (§4,
//! §12).
//!
//! This is the Class 1 surface only. COSE_Sign1 signatures over the record,
//! registration and Receipt inclusion proofs belong to the SCITT/COSE
//! substrate (§6); the Producer Envelope is [`crate::envelope`].

use crate::canonical::{
    compute_capsule_id, float_paths_limited, unsafe_int_paths_limited, CanonicalError,
};
use crate::references::reference_findings;
use crate::registries::{provisional_values, Registries};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};

/// True if `s` is 64 lowercase hexadecimal characters.
pub fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn is_hex64_value(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(s)) if is_hex64(s))
}

/// At most this many `float_in_digest_field` (and, separately,
/// `unsafe_integer_in_digest_field`) findings are reported. The verdict needs
/// only one.
const MAX_PATH_FINDINGS: usize = 64;

/// A number finding quotes at most this many characters of its path, then
/// `...`.
const MAX_PATH_CHARS: usize = 256;

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

/// The closed enum for `provenance_mode.mode` (§5.3(bis)).
fn provenance_mode_valid(v: &str) -> bool {
    matches!(v, "contemporaneous" | "backfilled")
}

/// The closed enum for `provenance_mode.time_rung` (§5.3(bis)).
fn time_rung_valid(v: &str) -> bool {
    matches!(v, "self_attested" | "witnessed")
}

/// REQUIRED companions of `provenance_mode.mode = "backfilled"` (§5.3(bis)).
const PROVENANCE_MODE_BACKFILLED_FIELDS: [&str; 4] = [
    "source_ref",
    "source_asserted_at",
    "import_batch",
    "imported_at",
];

/// `(registry, block, member)` in check-8 emission order.
const REGISTRY_FIELDS: [(&str, &str, &str); 6] = [
    ("verdict_class", "disposition", "verdict_class"),
    ("disposition.decision", "disposition", "decision"),
    ("effect.type", "effect", "type"),
    ("irreversibility_class", "effect", "irreversibility_class"),
    ("effect_attestation", "effect", "effect_attestation"),
    ("chain.relation", "chain", "relation"),
];

/// One structured verification finding. `check` is `None` for a finding
/// outside the numbered §6 checks. Severity `"error"` gates `ok`;
/// `"warning"` and `"info"` do not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub code: String,
    pub detail: String,
    pub severity: String,
    pub check: Option<i32>,
}

/// String-typed block members, in check-1 emission order. A value of any
/// other JSON type (a number, a boolean, null, a list, an object) fails check 1
/// ("REQUIRED fields present and typed", §6). The never-reject rule for
/// unregistered values (§4, §12) covers well-typed strings only: a list where a
/// string belongs is a type error, not an unknown value. The top-level
/// `epoch_id` is checked the same way, just before these.
/// `disposition.authority` is not here: §5.4 types it only as "an opaque
/// reference", not as a string.
const STRING_MEMBERS: [(&str, &str); 16] = [
    ("disposition", "decision"),
    ("disposition", "verdict_class"),
    ("effect", "status"),
    ("effect", "type"),
    ("effect", "irreversibility_class"),
    ("effect", "effect_attestation"),
    ("effect", "external_ref"),
    ("chain", "relation"),
    ("cross_party", "correlator"),
    ("assurance", "effect_mode"),
    ("assurance", "attestation_mode"),
    ("assurance", "ledger_mode"),
    ("assurance", "cross_party_rung"),
    ("provenance_mode", "source_asserted_at"),
    ("provenance_mode", "import_batch"),
    ("provenance_mode", "imported_at"),
];

pub(crate) fn mkf(code: &str, detail: &str, check: Option<i32>, severity: &str) -> Finding {
    Finding {
        code: code.to_string(),
        detail: detail.to_string(),
        severity: severity.to_string(),
        check,
    }
}

/// The never-panicking result of [`verify`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerificationResult {
    pub ok: bool,
    pub findings: Vec<Finding>,
    /// Derived assurance: `effect_mode`, `attestation_mode`, `ledger_mode`,
    /// and when applicable `cross_party_rung`, `provenance_mode` and
    /// `provenance_time_rung`.
    pub assurance: BTreeMap<String, String>,
    /// The recomputed `capsule_id`; `None` if it could not be computed.
    pub capsule_id: Option<String>,
}

impl VerificationResult {
    fn internal_error(detail: &str) -> Self {
        VerificationResult {
            ok: false,
            findings: vec![mkf("verifier_internal_error", detail, None, "error")],
            ..Default::default()
        }
    }
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

/// The `capsule_id`s of a store of capsule objects or bare id strings.
fn store_ids(store: &[Value]) -> HashSet<&str> {
    let mut ids = HashSet::new();
    for item in store {
        match item {
            Value::Object(m) => {
                if let Some(Value::String(id)) = m.get("capsule_id") {
                    ids.insert(id.as_str());
                }
            }
            Value::String(id) => {
                ids.insert(id.as_str());
            }
            _ => {}
        }
    }
    ids
}

pub use crate::json::DecodeError;

/// Decodes capsule JSON strictly (RFC 8259). Numbers keep their source text,
/// so a float or an unsafe integer is reported by check 1 rather than lost in
/// conversion. Use this rather than `serde_json::from_slice`, which turns an
/// object holding `serde_json`'s private number token into a number.
pub fn decode_capsule_json(data: &[u8]) -> Result<Value, DecodeError> {
    crate::json::decode(data)
}

/// Runs Class 1 verification (§6) over one Capsule against the authoritative
/// registries. `store` is the ledger for chain-level checks; `None` skips the
/// store-level checks.
pub fn verify(capsule: &Value, store: Option<&[Value]>) -> VerificationResult {
    match Registries::authoritative() {
        Ok(regs) => verify_with(capsule, store, regs),
        Err(e) => VerificationResult::internal_error(&e.to_string()),
    }
}

/// [`verify`] against a caller-supplied registry snapshot.
pub fn verify_with(
    capsule: &Value,
    store: Option<&[Value]>,
    regs: &Registries,
) -> VerificationResult {
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
    for finding in reference_findings(capsule_map, regs) {
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

    // Sub-block type checks, in the Python reference's order. The §-02
    // addendum's self_reported_reasoning block and its scalar domain and
    // provenance members are typed the same way.
    for field in [
        "effect",
        "assurance",
        "disposition",
        "chain",
        "cross_party",
        "self_reported_reasoning",
        "provenance_mode",
    ] {
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

    for field in ["domain", "provenance"] {
        if matches!(capsule_map.get(field), Some(v) if !v.is_string()) {
            findings.push(mkf(
                &format!("{field}_not_string"),
                &format!("{field} MUST be a string when present (§-02)"),
                Some(1),
                "error",
            ));
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

    // One finding of each kind is enough to fail the record; on hostile input
    // the cap and the quoted-path limit keep the result small.
    for p in float_paths_limited(capsule, MAX_PATH_FINDINGS, MAX_PATH_CHARS) {
        findings.push(mkf(
            "float_in_digest_field",
            &format!("floating-point value at {p}; §5.1 forbids it"),
            Some(1),
            "error",
        ));
    }

    for p in unsafe_int_paths_limited(capsule, MAX_PATH_FINDINGS, MAX_PATH_CHARS) {
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
        match disposition.get("approver") {
            None | Some(Value::Null) => findings.push(mkf(
                "missing_required_field",
                "disposition.approver is REQUIRED (§5.4)",
                Some(1),
                "error",
            )),
            Some(Value::String(a)) if !valid_approver(a) => findings.push(mkf(
                "approver_invalid",
                &format!(
                    "disposition.approver MUST be human|policy|counterparty (§5.4); got {a:?}"
                ),
                Some(1),
                "error",
            )),
            Some(Value::String(_)) => {}
            Some(_) => findings.push(mkf(
                "field_not_string",
                "disposition.approver MUST be a string (§5.4)",
                Some(1),
                "error",
            )),
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

    if matches!(capsule_map.get("epoch_id"), Some(v) if !v.is_string()) {
        findings.push(mkf(
            "field_not_string",
            "epoch_id MUST be a string when present (§5.1)",
            Some(1),
            "error",
        ));
    }
    for (block, member) in STRING_MEMBERS {
        if let Some(v) = as_map(capsule_map.get(block)).and_then(|b| b.get(member)) {
            if !v.is_string() {
                findings.push(mkf(
                    "field_not_string",
                    &format!("{block}.{member} MUST be a string when present (§6 check 1)"),
                    Some(1),
                    "error",
                ));
            }
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
    // JSON null counts as absent, as a nil map value does in Go.
    let ea = effect
        .and_then(|e| e.get("effect_attestation"))
        .filter(|v| !v.is_null());
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
                    if !ids.contains(parent_str.as_str()) {
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
    let provisional = match provisional_values() {
        Ok(p) => Some(p),
        Err(e) => {
            findings.push(mkf(
                "registry_snapshot_unavailable",
                &e.to_string(),
                Some(8),
                "warning",
            ));
            None
        }
    };
    for (registry, block, member) in REGISTRY_FIELDS {
        // A non-string value is a type error, reported by check 1.
        let Some(Value::String(value)) = as_map(capsule_map.get(block)).and_then(|b| b.get(member))
        else {
            continue;
        };
        if regs.contains(registry, value) {
            continue;
        }
        if let Some(class) = provisional
            .and_then(|p| p.get(registry))
            .and_then(|values| values.get(value))
        {
            findings.push(mkf(
                "known_provisional_registry_value",
                &format!(
                    "{block}.{member}={value:?} resolves known status 'provisional' via vendored \
                     CPB registry (payload class {class:?}); informational, not rejected (§12)"
                ),
                Some(8),
                "info",
            ));
            continue;
        }
        findings.push(mkf(
            "unknown_registry_value",
            &format!(
                "{block}.{member}={value:?} is not a seeded {registry} value; informational, \
                 not rejected (§12)"
            ),
            Some(8),
            "info",
        ));
        if registry == "effect_attestation" {
            findings.push(mkf(
                "effect_attestation_graded_floor",
                "unknown effect_attestation graded no stronger than 'runtime_claimed' (§5.2)",
                Some(8),
                "info",
            ));
        }
    }

    if let Some(fs) = reference_checks.get(&8) {
        findings.extend(fs.clone());
    }

    // ---- Check 9: Provenance mode -------------------------------------------
    if let Some(pm) = as_map(capsule_map.get("provenance_mode")) {
        provenance_mode_findings(capsule_map, pm, &mut findings, &mut derived);
    }

    let ok = !findings.iter().any(|f| f.severity == "error");
    VerificationResult {
        ok,
        findings,
        assurance: derived,
        capsule_id: recomputed_id,
    }
}

/// Check 9 (§5.3(bis) Provenance mode). A backfilled record's occurrence-time
/// claim is capped at self-attested unless a witnessed reference is cited.
/// Unlike check 7's informational overclaims, a time-rung overclaim and the
/// `imported_at == source_asserted_at` laundering shape gate `ok`: they are
/// falsifiable dishonesty claims, not merely unverifiable ones.
fn provenance_mode_findings(
    capsule: &Map<String, Value>,
    pm: &Map<String, Value>,
    findings: &mut Vec<Finding>,
    derived: &mut BTreeMap<String, String>,
) {
    let mode = pm.get("mode").and_then(Value::as_str);
    match mode {
        Some(m) if provenance_mode_valid(m) => {
            derived.insert("provenance_mode".to_string(), m.to_string());
        }
        _ => findings.push(mkf(
            "provenance_mode_invalid",
            &format!(
                "provenance_mode.mode MUST be one of backfilled|contemporaneous (§5.3(bis) \
                 Provenance mode); got {}",
                pm.get("mode")
                    .map_or("nothing".to_string(), Value::to_string)
            ),
            Some(9),
            "error",
        )),
    }

    match mode {
        Some("backfilled") => {
            for field in PROVENANCE_MODE_BACKFILLED_FIELDS {
                let missing = match pm.get(field) {
                    None | Some(Value::Null) => true,
                    Some(Value::String(s)) => s.is_empty(),
                    Some(_) => false,
                };
                if missing {
                    findings.push(mkf(
                        "provenance_mode_missing_required_field",
                        &format!(
                            "provenance_mode.{field} is REQUIRED when mode='backfilled' \
                             (§5.3(bis) Provenance mode)"
                        ),
                        Some(9),
                        "error",
                    ));
                }
            }

            match pm.get("source_ref") {
                Some(Value::Object(source_ref)) => {
                    for field in ["type", "digest_alg", "digest"] {
                        if !matches!(source_ref.get(field), Some(Value::String(s)) if !s.is_empty())
                        {
                            findings.push(mkf(
                                "provenance_mode_source_ref_malformed",
                                &format!(
                                    "provenance_mode.source_ref.{field} MUST be a non-empty \
                                     string (§5.3(bis) Provenance mode)"
                                ),
                                Some(9),
                                "error",
                            ));
                        }
                    }
                }
                Some(_) => findings.push(mkf(
                    "provenance_mode_source_ref_malformed",
                    "provenance_mode.source_ref MUST be a JSON object when present (§5.3(bis) \
                     Provenance mode)",
                    Some(9),
                    "error",
                )),
                None => {}
            }

            // An equal imported_at/source_asserted_at is exactly the shape that
            // makes a backfilled import look contemporaneous; never corroboration.
            let imported_at = pm.get("imported_at").and_then(Value::as_str);
            let source_asserted_at = pm.get("source_asserted_at").and_then(Value::as_str);
            if imported_at.is_some() && imported_at == source_asserted_at {
                findings.push(mkf(
                    "provenance_time_laundering_shape",
                    "provenance_mode.imported_at equals source_asserted_at on a backfilled \
                     record; this is the shape a laundering producer would construct to make an \
                     import look contemporaneous (§5.3(bis) Provenance mode)",
                    Some(9),
                    "error",
                ));
            }

            let mut time_rung = None;
            match pm.get("time_rung") {
                None | Some(Value::Null) => {}
                Some(Value::String(rung)) if time_rung_valid(rung) => {
                    time_rung = Some(rung.as_str())
                }
                Some(other) => findings.push(mkf(
                    "provenance_mode_invalid",
                    &format!(
                        "provenance_mode.time_rung MUST be one of self_attested|witnessed \
                         (§5.3(bis) Provenance mode); got {other}"
                    ),
                    Some(9),
                    "error",
                )),
            }

            // time_rung="witnessed" REQUIRES a well-formed references[] entry
            // citing corroborates_source_time; the derived rung comes from that
            // evidence, never from the claim.
            let corroborated = capsule
                .get("references")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_object)
                .any(|reference| {
                    let text = |k: &str| reference.get(k).and_then(Value::as_str).unwrap_or("");
                    text("citation_purpose") == "corroborates_source_time"
                        && !text("type").is_empty()
                        && !text("digest_alg").is_empty()
                        && !text("digest").is_empty()
                });
            if time_rung == Some("witnessed") && !corroborated {
                findings.push(mkf(
                    "provenance_time_rung_overclaim",
                    "provenance_mode.time_rung='witnessed' claimed without a well-formed \
                     references[] entry citing citation_purpose='corroborates_source_time' \
                     (§5.3(bis) Provenance mode)",
                    Some(9),
                    "error",
                ));
            }
            derived.insert(
                "provenance_time_rung".to_string(),
                if corroborated {
                    "witnessed"
                } else {
                    "self_attested"
                }
                .to_string(),
            );
        }
        Some("contemporaneous") => {
            let orphaned: Vec<&str> = PROVENANCE_MODE_BACKFILLED_FIELDS
                .iter()
                .copied()
                .chain(["time_rung"])
                .filter(|field| matches!(pm.get(*field), Some(v) if !v.is_null()))
                .collect();
            if !orphaned.is_empty() {
                findings.push(mkf(
                    "provenance_mode_invalid",
                    &format!(
                        "provenance_mode fields {orphaned:?} are meaningful only when \
                         mode='backfilled' (§5.3(bis) Provenance mode)"
                    ),
                    Some(9),
                    "error",
                ));
            }
        }
        _ => {}
    }
}

/// Verifies a ledger of Capsules in order against the authoritative
/// registries, adding the store-level checks of §6 and §5.4.4: parent
/// existence, concurrent supersedes, and duplicates collapse (§5.3(bis)).
pub fn verify_store(capsules: &[Value]) -> Vec<VerificationResult> {
    match Registries::authoritative() {
        Ok(regs) => verify_store_with(capsules, regs),
        Err(e) => vec![VerificationResult::internal_error(&e.to_string()); capsules.len()],
    }
}

/// [`verify_store`] against a caller-supplied registry snapshot.
pub fn verify_store_with(capsules: &[Value], regs: &Registries) -> Vec<VerificationResult> {
    let mut results: Vec<VerificationResult> = capsules
        .iter()
        .map(|c| verify_with(c, Some(capsules), regs))
        .collect();
    let chained = |c: &Value, relation: &str| -> Option<String> {
        let chain = as_map(c.as_object()?.get("chain"))?;
        if chain.get("relation").and_then(Value::as_str) != Some(relation) {
            return None;
        }
        chain
            .get("parent_capsule_id")
            .and_then(Value::as_str)
            .map(str::to_string)
    };

    // Concurrent supersedes (§5.4.4): the earliest supersedes over a parent is
    // authoritative; each later one is reported.
    let mut seen_parents = HashSet::new();
    for (i, c) in capsules.iter().enumerate() {
        let Some(parent) = chained(c, "supersedes").filter(|p| !p.is_empty()) else {
            continue;
        };
        if seen_parents.contains(&parent) {
            results[i].findings.push(mkf(
                "concurrent_supersedes",
                &format!("a later supersedes over parent {parent}; the earliest is authoritative (§5.4.4)"),
                Some(6),
                "info",
            ));
        } else {
            seen_parents.insert(parent);
        }
    }

    // Duplicates (§5.3(bis); REGISTRY.md §6): a duplicates-linked pair counts
    // once, the contemporaneous parent governing. Parent existence is check
    // 6's; this pass records the collapse and flags, informationally, a
    // parent that is itself backfilled.
    let by_id: HashMap<&str, &Map<String, Value>> = capsules
        .iter()
        .filter_map(Value::as_object)
        .filter_map(|m| Some((m.get("capsule_id")?.as_str()?, m)))
        .collect();
    for (i, c) in capsules.iter().enumerate() {
        let Some(parent_id) = chained(c, "duplicates") else {
            continue;
        };
        results[i].findings.push(mkf(
            "duplicate_collapsed",
            &format!(
                "chain.relation='duplicates' over parent {parent_id}; verifiers and downstream \
                 evidence evaluators MUST count this pair once, the contemporaneous parent \
                 governing (§5.3(bis) Provenance mode)"
            ),
            Some(9),
            "info",
        ));
        let parent_backfilled = by_id
            .get(parent_id.as_str())
            .and_then(|parent| as_map(parent.get("provenance_mode")))
            .and_then(|pm| pm.get("mode"))
            .and_then(Value::as_str)
            == Some("backfilled");
        if parent_backfilled {
            results[i].findings.push(mkf(
                "duplicate_parent_not_contemporaneous",
                &format!(
                    "chain.relation='duplicates' parent {parent_id} is itself \
                     provenance_mode.mode='backfilled'; 'duplicates' is defined to cite the \
                     contemporaneous record (§5.3(bis) Provenance mode)"
                ),
                Some(9),
                "info",
            ));
        }
    }
    results
}
