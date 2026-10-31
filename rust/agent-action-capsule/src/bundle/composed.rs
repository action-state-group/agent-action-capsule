//! The `composed/v1` Evidence Bundle extension
//! (`draft-mih-zhang-agent-disclosure-bundle-02`, "The composed/v1
//! Extension"). Port of `go/bundle/composed.go` and `composed_binding.go`,
//! checked against `vectors/bundle/composed/` and
//! `vectors/bundle/composed-controller-binding/`.
//!
//! A `controller_binding` join reads a binding record only through
//! `evidence_request::controller_binding::verify`, the one Controller Binding
//! v0 verifier; this module applies Bundle -02's own rules on top (an empty
//! `nonce` is malformed, `ed25519` is the one key type, and a `sig` under
//! `ed25519` keys is a `sig-hex`) and reads the report for the two root
//! records' timestamps. It reports no binding property.

use super::{
    bundle_digest, is_empty_history, signed_checkpoint, verify_bundle_with_options, BundleOptions,
    VerificationResult,
};
use crate::{canonical, verify};
use evidence_request::controller_binding::{self, PROPERTY_FORM};
use evidence_request::status::Status;
use evidence_request::time::{parse_utc, UtcTime};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};

/// The registered extension kind this module interprets.
pub const COMPOSED_KIND: &str = "composed/v1";

/// Signature states reported on a refusal or response member.
pub const SIGNATURE_VERIFIED: &str = "verified";
pub const SIGNATURE_INVALID: &str = "invalid";
pub const SIGNATURE_UNVERIFIED: &str = "signature_unverified";

/// Checks a carried signed refusal, or an artifact member's signed response
/// envelope, under the deployment's signature profile. It returns
/// [`SIGNATURE_VERIFIED`], [`SIGNATURE_INVALID`] or [`SIGNATURE_UNVERIFIED`].
/// The draft leaves the signature format to the deployment, so the core
/// ships no profile: without a verifier every refusal and response is
/// signature-unverified, which is neither failed nor absent.
pub type SignatureVerifier = dyn Fn(&Map<String, Value>) -> &'static str;

/// What a `composed/v1` block is verified with.
#[derive(Clone, Copy, Default)]
pub struct ComposedOptions<'a> {
    pub refusal_signature: Option<&'a SignatureVerifier>,
    pub response_signature: Option<&'a SignatureVerifier>,
    /// The binding records delivered beside the Bundle, and the revocation
    /// statements, that a `controller_binding` join is derived from. A join
    /// whose record was not delivered is not derivable.
    pub controller_bindings: &'a [Value],
    pub binding_revocations: &'a [Value],
}

/// The recomputed composed digest beside the declared one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposedDigestResult {
    pub declared: String,
    pub recomputed: String,
    pub matches: bool,
}

/// One member: its outcome, whether its body is carried or declared missing,
/// whether the body reproduces its digest, and, for a carried artifact, the
/// member Evidence Bundle's own verification. The member's claims are its
/// own; they are never merged into another member's, the containing
/// Bundle's, or composition closure.
#[derive(Debug, Clone)]
pub struct ComposedMemberResult {
    pub id: String,
    pub observer: String,
    pub outcome: String,
    /// `carried`, `declared_missing` or `absent`.
    pub body: String,
    /// `reproduced`, `mismatch` or `not_shown`.
    pub digest: String,
    pub findings: Vec<String>,
    pub bundle: Option<Box<VerificationResult>>,
    pub refusal_signature: Option<String>,
    pub response_signature: Option<String>,
}

/// The fourth completeness claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositionClosureResult {
    pub status: String,
    pub findings: Vec<String>,
    pub missing: Vec<String>,
}

/// One member's value at a compare pointer.
#[derive(Debug, Clone, PartialEq)]
pub struct JoinValue {
    pub member: String,
    pub resolved: bool,
    pub value: Option<Value>,
}

/// One compare pointer whose values differ on a derived mismatch. No winner
/// is named.
#[derive(Debug, Clone, PartialEq)]
pub struct JoinDifference {
    pub pointer: String,
    pub values: Vec<JoinValue>,
}

/// A join: the declared state, the derived state (`None` when not
/// derivable), and whether they match.
#[derive(Debug, Clone, PartialEq)]
pub struct ComposedJoinResult {
    pub members: [String; 2],
    pub basis: String,
    pub declared: String,
    pub derived: Option<String>,
    /// `derived_matches`, `join_state_mismatch` or `not_derivable`.
    pub result: String,
    pub differences: Vec<JoinDifference>,
}

/// Per join, what a derived agreement is worth. Results are never combined
/// into a count or a score.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorroborationResult {
    pub members: [String; 2],
    /// `corroborating`, `redundant` or `not_applicable`.
    pub result: String,
    pub reason: Option<String>,
    pub reasons: Vec<String>,
    pub report: Option<String>,
    pub qualifier: Option<String>,
}

/// The verification of one `composed/v1` block. `status` is the block's own
/// result: `fail` when the block is malformed, the composed digest does not
/// recompute, a member body fails its checks, composition closure fails or a
/// declared join state does not match its derivation; `withheld` when
/// nothing failed but something is not shown; otherwise `pass`. Member
/// bundles' own claims are reported on each member and do not enter `status`.
#[derive(Debug, Clone)]
pub struct ComposedResult {
    pub status: String,
    pub findings: Vec<String>,
    /// The block violates the draft's block rules; no composition result is
    /// reported from a malformed block.
    pub malformed: bool,
    pub composed_digest: Option<ComposedDigestResult>,
    pub members: Vec<ComposedMemberResult>,
    pub composition_closure: Option<CompositionClosureResult>,
    pub joins: Vec<ComposedJoinResult>,
    pub corroboration: Vec<CorroborationResult>,
}

// ---- the block ----------------------------------------------------------------

struct Member {
    id: String,
    observer: String,
    request_digest: String,
    outcome: String,
    digest: String,
    body: Option<Map<String, Value>>,
    /// An artifact member's signed response envelope without its artifact
    /// bytes, when carried: what binds the artifact to its request.
    response: Option<Map<String, Value>>,
}

struct Observer {
    id: String,
    role: String,
    custody: String,
}

struct Join {
    members: [String; 2],
    basis: String,
    state: String,
    pointer: Option<String>,
    identifier: Option<String>,
    compare: Vec<String>,
    compare_carried: bool,
}

struct Block {
    members: Vec<Member>,
    observers: Vec<Observer>,
    joins: Vec<Join>,
    not_requested: Vec<String>,
    missing: Vec<String>,
    digest: String,
}

fn is_label(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn is_digest(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(s)) if verify::is_hex64(s))
}

fn is_text(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(_)))
}

fn outcome_body_key(outcome: &str) -> Option<&'static str> {
    match outcome {
        "artifact" => Some("bundle"),
        "refusal" => Some("refusal"),
        "absence" => Some("absence"),
        _ => None,
    }
}

fn join_basis(s: &str) -> bool {
    matches!(
        s,
        "pre_agreed_identifier"
            | "shared_artifact_digest"
            | "issued_receipt"
            | "same_interval"
            | "controller_binding"
    )
}

fn join_state(s: &str) -> bool {
    matches!(s, "agree" | "mismatch" | "unjoined" | "one_sided")
}

fn join_key(j: &Join) -> String {
    format!(
        "{}\0{}\0{}\0{}",
        j.members[0],
        j.members[1],
        j.basis,
        j.pointer.as_deref().unwrap_or("")
    )
}

/// An optional array member; `None` when it is present but not an array.
fn optional_array<'a>(value: &'a Map<String, Value>, key: &str) -> Option<&'a [Value]> {
    match value.get(key) {
        None => Some(&[]),
        Some(Value::Array(list)) => Some(list),
        Some(_) => None,
    }
}

fn label_array(value: &Map<String, Value>, key: &str) -> Result<Vec<String>, String> {
    let list = optional_array(value, key).ok_or_else(|| key.to_string())?;
    list.iter()
        .map(|raw| match raw {
            Value::String(s) if is_label(s) => Ok(s.clone()),
            _ => Err(key.to_string()),
        })
        .collect()
}

fn parse_composed(raw: &Value) -> Result<Block, String> {
    let value = raw.as_object().ok_or("not_an_object")?;
    let digest = match value.get("composed_digest") {
        Some(Value::String(s)) if verify::is_hex64(s) => s.clone(),
        _ => return Err("composed_digest".to_string()),
    };

    let observer_list = match value.get("observers") {
        Some(Value::Array(l)) if !l.is_empty() => l,
        _ => return Err("observers".to_string()),
    };
    let mut observer_ids = HashSet::new();
    let mut observers = Vec::new();
    for (i, raw_observer) in observer_list.iter().enumerate() {
        let o = raw_observer.as_object();
        let text = |name: &str| o.and_then(|o| o.get(name)).and_then(Value::as_str);
        let (Some(id), Some(role), Some(custody)) =
            (text("id"), text("role"), text("custody_domain"))
        else {
            return Err(format!("observer:{i}"));
        };
        if !is_label(id) {
            return Err(format!("observer:{i}"));
        }
        if !observer_ids.insert(id.to_string()) {
            return Err(format!("observer_id_duplicate:{id}"));
        }
        observers.push(Observer {
            id: id.to_string(),
            role: role.to_string(),
            custody: custody.to_string(),
        });
    }

    let member_list = match value.get("members") {
        Some(Value::Array(l)) if !l.is_empty() => l,
        _ => return Err("members".to_string()),
    };
    let mut member_ids = HashSet::new();
    let mut members = Vec::new();
    for (i, raw_member) in member_list.iter().enumerate() {
        let m = parse_member(raw_member, &observer_ids).map_err(|r| format!("member:{i}:{r}"))?;
        if !member_ids.insert(m.id.clone()) {
            return Err(format!("member_id_duplicate:{}", m.id));
        }
        members.push(m);
    }

    let join_list = optional_array(value, "joins").ok_or("joins")?;
    let mut seen = HashSet::new();
    let mut joins = Vec::new();
    for (i, raw_join) in join_list.iter().enumerate() {
        let j = parse_join(raw_join, &member_ids).map_err(|r| format!("join:{i}:{r}"))?;
        let mut key = join_key(&j);
        if j.pointer.is_none() {
            key.push_str("\0absent");
        }
        if !seen.insert(key) {
            return Err(format!("join_duplicate:{i}"));
        }
        joins.push(j);
    }

    let not_requested = label_array(value, "not_requested")?;
    if let Some(id) = not_requested.iter().find(|id| member_ids.contains(*id)) {
        return Err(format!("not_requested_is_member:{id}"));
    }
    let missing = label_array(value, "missing")?;
    Ok(Block {
        members,
        observers,
        joins,
        not_requested,
        missing,
        digest,
    })
}

fn parse_member(raw: &Value, observers: &HashSet<String>) -> Result<Member, &'static str> {
    let value = raw.as_object().ok_or("not_an_object")?;
    let text = |name: &str| value.get(name).and_then(Value::as_str);
    let (id, observer, request_digest, outcome, digest) = (
        text("id"),
        text("observer"),
        text("request_digest"),
        text("outcome"),
        text("digest"),
    );
    match id {
        Some(id) if is_label(id) => {}
        _ => return Err("id"),
    }
    match observer {
        Some(o) if is_label(o) => {
            if !observers.contains(o) {
                return Err("observer_undeclared");
            }
        }
        _ => return Err("observer"),
    }
    match request_digest {
        Some(d) if verify::is_hex64(d) => {}
        _ => return Err("request_digest"),
    }
    match digest {
        Some(d) if verify::is_hex64(d) => {}
        _ => return Err("digest"),
    }
    let outcome = outcome.ok_or("outcome")?;
    let body_key = outcome_body_key(outcome).ok_or("outcome")?;
    // A body under another outcome's member name would convert one outcome
    // into another; the outcomes are never converted.
    for other in ["bundle", "refusal", "absence"] {
        if other != body_key && value.contains_key(other) {
            return Err("body_outcome_conflict");
        }
    }
    let mut response = None;
    if let Some(raw_response) = value.get("response") {
        match raw_response.as_object() {
            Some(r)
                if outcome == "artifact"
                    && is_digest(r.get("request_digest"))
                    && is_digest(r.get("artifact_digest")) =>
            {
                response = Some(r.clone());
            }
            _ => return Err("response"),
        }
    }
    let mut member = Member {
        id: id.unwrap_or_default().to_string(),
        observer: observer.unwrap_or_default().to_string(),
        request_digest: request_digest.unwrap_or_default().to_string(),
        outcome: outcome.to_string(),
        digest: digest.unwrap_or_default().to_string(),
        body: None,
        response,
    };
    let Some(raw_body) = value.get(body_key) else {
        return Ok(member);
    };
    let body = raw_body.as_object().ok_or("body")?;
    match outcome {
        "refusal" => {
            if !is_digest(body.get("request_digest"))
                || !is_text(body.get("reason"))
                || !is_text(body.get("issued_at"))
            {
                return Err("refusal_body");
            }
        }
        "absence" => {
            let window = body.get("window").and_then(Value::as_object);
            if !is_digest(body.get("request_digest"))
                || !window.is_some_and(|w| is_text(w.get("from")) && is_text(w.get("to")))
            {
                return Err("absence_body");
            }
            if body.get("route").is_some_and(|r| !is_text(Some(r)))
                || body.get("commitment").is_some_and(|c| !is_digest(Some(c)))
            {
                return Err("absence_body");
            }
        }
        _ => {}
    }
    member.body = Some(body.clone());
    Ok(member)
}

fn parse_join(raw: &Value, members: &HashSet<String>) -> Result<Join, &'static str> {
    let value = raw.as_object().ok_or("not_an_object")?;
    let pair = match value.get("members") {
        Some(Value::Array(p)) if p.len() == 2 => p,
        _ => return Err("members"),
    };
    let mut ids = [String::new(), String::new()];
    for (i, item) in pair.iter().enumerate() {
        match item {
            Value::String(id) if is_label(id) && members.contains(id) => ids[i] = id.clone(),
            _ => return Err("members"),
        }
    }
    if ids[0] >= ids[1] {
        return Err("members_order");
    }
    let basis = match value.get("basis") {
        Some(Value::String(b)) if join_basis(b) => b.clone(),
        _ => return Err("basis"),
    };
    let state = match value.get("state") {
        Some(Value::String(s)) if join_state(s) => s.clone(),
        _ => return Err("state"),
    };
    let mut j = Join {
        members: ids,
        basis,
        state,
        pointer: None,
        identifier: None,
        compare: Vec::new(),
        compare_carried: false,
    };
    if let Some(raw_pointer) = value.get("pointer") {
        match raw_pointer {
            Value::String(p) if valid_pointer(p) => j.pointer = Some(p.clone()),
            _ => return Err("pointer"),
        }
    }
    if let Some(raw_digest) = value.get("identifier_digest") {
        match raw_digest {
            Value::String(d) if verify::is_hex64(d) => j.identifier = Some(d.clone()),
            _ => return Err("identifier_digest"),
        }
    }
    if let Some(raw_compare) = value.get("compare") {
        let list = match raw_compare {
            Value::Array(l) if !l.is_empty() => l,
            _ => return Err("compare"),
        };
        for item in list {
            match item {
                Value::String(p) if valid_pointer(p) => j.compare.push(p.clone()),
                _ => return Err("compare"),
            }
        }
        j.compare_carried = true;
    }
    Ok(j)
}

/// Whether `pointer` is an RFC 6901 JSON Pointer: empty, or `/`-prefixed
/// reference tokens in which `~` appears only as `~0` or `~1`.
fn valid_pointer(pointer: &str) -> bool {
    if pointer.is_empty() {
        return true;
    }
    if !pointer.starts_with('/') {
        return false;
    }
    let b = pointer.as_bytes();
    (0..b.len()).all(|i| b[i] != b'~' || matches!(b.get(i + 1), Some(b'0' | b'1')))
}

/// Evaluates an RFC 6901 JSON Pointer against a decoded JSON value; `None`
/// when any reference token does not resolve.
fn resolve_pointer<'a>(document: &'a Value, pointer: &str) -> Option<&'a Value> {
    if !valid_pointer(pointer) {
        return None;
    }
    if pointer.is_empty() {
        return Some(document);
    }
    let mut current = document;
    for token in pointer[1..].split('/') {
        let token = token.replace("~1", "/").replace("~0", "~");
        current = match current {
            Value::Object(node) => node.get(&token)?,
            Value::Array(node) => {
                if token.is_empty() || (token.len() > 1 && token.starts_with('0')) {
                    return None;
                }
                let index: usize = token.parse().ok()?;
                if index.to_string() != token {
                    return None;
                }
                node.get(index)?
            }
            _ => return None,
        };
    }
    Some(current)
}

// ---- the composed digest --------------------------------------------------------

/// Recomputes a `composed/v1` block's composed digest from its declarations
/// alone: lowercase-hex SHA-256 of the JCS serialization of the digest input
/// D = {kind, members, observers, joins, not_requested}, each array reduced
/// to its declared fields and sorted. Member bodies, `missing` and
/// `composed_digest` are excluded. It fails on a malformed block.
pub fn composed_digest(raw: &Value) -> Result<String, String> {
    let preimage = composed_digest_preimage(raw)?;
    Ok(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
        preimage,
    )))
}

/// The UTF-8 JCS bytes of the digest input D.
pub fn composed_digest_preimage(raw: &Value) -> Result<Vec<u8>, String> {
    let block = parse_composed(raw).map_err(|r| format!("composed/v1 block malformed: {r}"))?;
    digest_input(&block).map_err(|e| e.to_string())
}

fn digest_input(block: &Block) -> Result<Vec<u8>, canonical::CanonicalError> {
    let mut members: Vec<&Member> = block.members.iter().collect();
    members.sort_by(|a, b| a.id.cmp(&b.id));
    let member_values: Vec<Value> = members
        .iter()
        .map(|m| {
            json!({"id": m.id, "observer": m.observer, "request_digest": m.request_digest,
                   "outcome": m.outcome, "digest": m.digest})
        })
        .collect();
    let mut observers: Vec<&Observer> = block.observers.iter().collect();
    observers.sort_by(|a, b| a.id.cmp(&b.id));
    let observer_values: Vec<Value> = observers
        .iter()
        .map(|o| json!({"id": o.id, "role": o.role, "custody_domain": o.custody}))
        .collect();
    let mut joins: Vec<&Join> = block.joins.iter().collect();
    joins.sort_by_key(|j| join_key(j));
    let join_values: Vec<Value> = joins
        .iter()
        .map(|j| {
            let mut value = Map::new();
            value.insert("members".into(), json!([j.members[0], j.members[1]]));
            value.insert("basis".into(), json!(j.basis));
            value.insert("state".into(), json!(j.state));
            if let Some(p) = &j.pointer {
                value.insert("pointer".into(), json!(p));
            }
            if let Some(d) = &j.identifier {
                value.insert("identifier_digest".into(), json!(d));
            }
            if j.compare_carried {
                value.insert("compare".into(), json!(j.compare));
            }
            Value::Object(value)
        })
        .collect();
    let mut not_requested = block.not_requested.clone();
    not_requested.sort();
    canonical::jcs(&json!({
        "kind": COMPOSED_KIND,
        "members": member_values,
        "observers": observer_values,
        "joins": join_values,
        "not_requested": not_requested,
    }))
}

// ---- verification ---------------------------------------------------------------

/// Verifies a `composed/v1` block as carried in a Bundle's extensions.
/// Carried member bundles are verified recursively with `opts`.
pub fn verify_composed(raw: &Value, opts: &BundleOptions) -> ComposedResult {
    let block = match parse_composed(raw) {
        Ok(b) => b,
        Err(reason) => {
            return ComposedResult {
                status: "fail".to_string(),
                findings: vec![format!("composed_block_malformed:{reason}")],
                malformed: true,
                composed_digest: None,
                members: Vec::new(),
                composition_closure: None,
                joins: Vec::new(),
                corroboration: Vec::new(),
            }
        }
    };
    let mut result = ComposedResult {
        status: String::new(),
        findings: Vec::new(),
        malformed: false,
        composed_digest: None,
        members: Vec::new(),
        composition_closure: None,
        joins: Vec::new(),
        corroboration: Vec::new(),
    };
    let mut failed: Vec<String> = Vec::new();
    let mut withheld: Vec<String> = Vec::new();

    let recomputed = digest_input(&block)
        .ok()
        .map(|p| hex::encode(<sha2::Sha256 as sha2::Digest>::digest(p)));
    let matches = recomputed.as_deref() == Some(block.digest.as_str());
    result.composed_digest = Some(ComposedDigestResult {
        declared: block.digest.clone(),
        recomputed: recomputed.unwrap_or_default(),
        matches,
    });
    if !matches {
        failed.push("composed_digest_mismatch".to_string());
    }

    let declared: HashSet<&str> = block.members.iter().map(|m| m.id.as_str()).collect();
    let mut missing: HashSet<String> = HashSet::new();
    let mut closure_findings: Vec<String> = Vec::new();
    for id in &block.missing {
        if !missing.insert(id.clone()) {
            closure_findings.push(format!("missing_duplicate:{id}"));
        }
        if !declared.contains(id.as_str()) {
            closure_findings.push(format!("missing_names_undeclared_member:{id}"));
        }
    }

    let mut by_id: HashMap<&str, &Member> = HashMap::new();
    for m in &block.members {
        by_id.insert(m.id.as_str(), m);
        let (member, member_closure, member_failed, member_withheld) =
            verify_member(m, missing.contains(&m.id), opts);
        result.members.push(member);
        closure_findings.extend(member_closure);
        failed.extend(member_failed);
        withheld.extend(member_withheld);
    }

    let mut unique_missing: Vec<String> = block.missing.clone();
    unique_missing.sort();
    unique_missing.dedup();
    let closure = if !closure_findings.is_empty() {
        failed.push("composition_closure_fail".to_string());
        CompositionClosureResult {
            status: "fail".to_string(),
            findings: closure_findings,
            missing: unique_missing,
        }
    } else if !block.missing.is_empty() {
        withheld.push("declared_incomplete".to_string());
        CompositionClosureResult {
            status: "withheld".to_string(),
            findings: vec!["declared_incomplete".to_string()],
            missing: unique_missing,
        }
    } else {
        CompositionClosureResult {
            status: "pass".to_string(),
            findings: Vec::new(),
            missing: unique_missing,
        }
    };
    result.composition_closure = Some(closure);

    let observers: HashMap<&str, &Observer> =
        block.observers.iter().map(|o| (o.id.as_str(), o)).collect();
    for j in &block.joins {
        let join_result = derive_join(j, &by_id, &missing, opts);
        let pair = format!("{},{}", j.members[0], j.members[1]);
        match join_result.result.as_str() {
            "join_state_mismatch" => failed.push(format!("join_state_mismatch:{pair}")),
            "not_derivable" => withheld.push(format!("join_not_derivable:{pair}")),
            _ => {}
        }
        result.corroboration.push(corroboration(
            j,
            join_result.derived.as_deref(),
            &by_id,
            &observers,
        ));
        result.joins.push(join_result);
    }

    if !failed.is_empty() {
        result.status = "fail".to_string();
        failed.extend(withheld);
        result.findings = failed;
    } else if !withheld.is_empty() {
        result.status = "withheld".to_string();
        result.findings = withheld;
    } else {
        result.status = "pass".to_string();
    }
    result
}

type MemberOutcome = (ComposedMemberResult, Vec<String>, Vec<String>, Vec<String>);

fn verify_member(m: &Member, declared_missing: bool, opts: &BundleOptions) -> MemberOutcome {
    let mut out = ComposedMemberResult {
        id: m.id.clone(),
        observer: m.observer.clone(),
        outcome: m.outcome.clone(),
        body: String::new(),
        digest: "not_shown".to_string(),
        findings: Vec::new(),
        bundle: None,
        refusal_signature: None,
        response_signature: None,
    };
    let (mut closure, mut failed, mut withheld) = (Vec::new(), Vec::new(), Vec::new());
    match (declared_missing, &m.body) {
        (true, Some(_)) => {
            out.body = "carried".to_string();
            closure.push(format!("missing_member_carries_body:{}", m.id));
        }
        (true, None) => {
            out.body = "declared_missing".to_string();
            return (out, Vec::new(), Vec::new(), Vec::new());
        }
        (false, None) => {
            out.body = "absent".to_string();
            closure.push(format!("member_body_absent:{}", m.id));
            out.findings.push("member_body_absent".to_string());
            return (out, closure, Vec::new(), Vec::new());
        }
        (false, Some(_)) => out.body = "carried".to_string(),
    }
    let body = m.body.as_ref().expect("a carried member has a body");
    let body_value = Value::Object(body.clone());

    let computed: Option<String>;
    if m.outcome == "artifact" {
        computed = bundle_digest(&body_value).ok();
        let verification = verify_bundle_with_options(&body_value, opts);
        out.bundle = Some(Box::new(verification));
        // A carried response binds the artifact to the request it answered:
        // the request digest it signs is the member's, and the artifact
        // digest it signs is the member's bundle digest.
        if let Some(response) = &m.response {
            if response.get("request_digest").and_then(Value::as_str) != Some(&m.request_digest) {
                out.findings
                    .push("response_request_digest_mismatch".to_string());
                failed.push(format!("member_response_request_digest_mismatch:{}", m.id));
            }
            if response.get("artifact_digest").and_then(Value::as_str) != Some(&m.digest) {
                out.findings
                    .push("response_artifact_digest_mismatch".to_string());
                failed.push(format!("member_response_artifact_digest_mismatch:{}", m.id));
            }
            let state = signature_state(opts.composed.response_signature, response);
            match state {
                SIGNATURE_INVALID => {
                    out.findings.push("response_signature_invalid".to_string());
                    failed.push(format!("response_signature_invalid:{}", m.id));
                }
                SIGNATURE_UNVERIFIED => {
                    withheld.push(format!("response_signature_unverified:{}", m.id))
                }
                _ => {}
            }
            out.response_signature = Some(state.to_string());
        }
    } else {
        computed = canonical::json_digest(&body_value).ok();
        if body.get("request_digest").and_then(Value::as_str) != Some(&m.request_digest) {
            out.findings.push("request_digest_mismatch".to_string());
            failed.push(format!("member_request_digest_mismatch:{}", m.id));
        }
    }
    if computed.as_deref() == Some(m.digest.as_str()) {
        out.digest = "reproduced".to_string();
    } else {
        out.digest = "mismatch".to_string();
        out.findings.push("member_digest_mismatch".to_string());
        closure.push(format!("member_digest_mismatch:{}", m.id));
    }
    if m.outcome == "refusal" {
        let state = signature_state(opts.composed.refusal_signature, body);
        match state {
            SIGNATURE_INVALID => {
                out.findings.push("refusal_signature_invalid".to_string());
                failed.push(format!("refusal_signature_invalid:{}", m.id));
            }
            SIGNATURE_UNVERIFIED => withheld.push(format!("refusal_signature_unverified:{}", m.id)),
            _ => {}
        }
        out.refusal_signature = Some(state.to_string());
    }
    (out, closure, failed, withheld)
}

/// A verifier's answer, read as the draft's states: anything but `verified`
/// and `invalid` is `signature_unverified`.
fn signature_state(
    verifier: Option<&SignatureVerifier>,
    value: &Map<String, Value>,
) -> &'static str {
    match verifier.map(|v| v(value)) {
        Some(SIGNATURE_VERIFIED) => SIGNATURE_VERIFIED,
        Some(SIGNATURE_INVALID) => SIGNATURE_INVALID,
        _ => SIGNATURE_UNVERIFIED,
    }
}

/// The carried member bundle's root record, or `None`.
fn root_record(m: &Member) -> Option<&Map<String, Value>> {
    let body = m.body.as_ref()?;
    let root = body.get("root")?.as_str()?;
    body.get("records")?
        .as_array()?
        .iter()
        .filter_map(Value::as_object)
        .find(|r| r.get("capsule_id").and_then(Value::as_str) == Some(root))
}

fn derive_join(
    j: &Join,
    by_id: &HashMap<&str, &Member>,
    missing: &HashSet<String>,
    opts: &BundleOptions,
) -> ComposedJoinResult {
    let (derived, differences) = derived_state(j, by_id, missing, opts);
    let result = match &derived {
        None => "not_derivable",
        Some(d) if *d == j.state => "derived_matches",
        Some(_) => "join_state_mismatch",
    };
    ComposedJoinResult {
        members: j.members.clone(),
        basis: j.basis.clone(),
        declared: j.state.clone(),
        derived,
        result: result.to_string(),
        differences,
    }
}

fn derived_state(
    j: &Join,
    by_id: &HashMap<&str, &Member>,
    missing: &HashSet<String>,
    opts: &BundleOptions,
) -> (Option<String>, Vec<JoinDifference>) {
    let a = by_id[j.members[0].as_str()];
    let b = by_id[j.members[1].as_str()];
    // An artifact member counts as having records unless its carried Bundle
    // is an empty-history Bundle, which shows no history.
    let (mut with_records, mut empty) = (Vec::new(), Vec::new());
    for m in [a, b] {
        if m.outcome != "artifact" {
            continue;
        }
        match &m.body {
            Some(body) if !missing.contains(&m.id) && is_empty_history(body) => empty.push(m),
            _ => with_records.push(m),
        }
    }
    let state = |s: &str| (Some(s.to_string()), Vec::new());
    match with_records.len() {
        0 => return state("unjoined"),
        1 => {
            if empty.is_empty() || j.basis != "controller_binding" {
                return state("one_sided");
            }
            // controller_binding still derives against an empty-history
            // member, from the key that signed its checkpoint at that
            // checkpoint's time.
            let full = with_records[0];
            let Some(pointer) = &j.pointer else {
                return (None, Vec::new());
            };
            if missing.contains(&full.id) {
                return (None, Vec::new());
            }
            let (Some(record), Some(side)) = (
                root_record(full),
                empty[0].body.as_ref().and_then(checkpoint_side),
            ) else {
                return (None, Vec::new());
            };
            return match controller_binding_link(j, &record_side(record, pointer), &side, opts) {
                (_, false) => (None, Vec::new()),
                (true, true) => state("one_sided"),
                (false, true) => state("unjoined"),
            };
        }
        _ => {}
    }
    if missing.contains(&a.id) || missing.contains(&b.id) {
        return (None, Vec::new());
    }
    let (Some(ra), Some(rb)) = (root_record(a), root_record(b)) else {
        return (None, Vec::new());
    };
    let (va_doc, vb_doc) = (Value::Object(ra.clone()), Value::Object(rb.clone()));
    let linked = match j.basis.as_str() {
        "pre_agreed_identifier" => match (&j.pointer, &j.identifier) {
            (Some(pointer), Some(identifier)) => {
                identifier_matches(&va_doc, pointer, identifier)
                    && identifier_matches(&vb_doc, pointer, identifier)
            }
            _ => false,
        },
        "shared_artifact_digest" => match &j.pointer {
            Some(pointer) => matches!(
                (resolve_pointer(&va_doc, pointer), resolve_pointer(&vb_doc, pointer)),
                (Some(Value::String(x)), Some(Value::String(y))) if x == y
            ),
            None => false,
        },
        "controller_binding" => {
            let Some(pointer) = &j.pointer else {
                return (None, Vec::new());
            };
            match controller_binding_link(
                j,
                &record_side(ra, pointer),
                &record_side(rb, pointer),
                opts,
            ) {
                (_, false) => return (None, Vec::new()),
                (linked, true) => linked,
            }
        }
        _ => return (None, Vec::new()),
    };
    if !linked {
        return state("unjoined");
    }
    let mut differences = Vec::new();
    for pointer in &j.compare {
        let (va, vb) = (
            resolve_pointer(&va_doc, pointer),
            resolve_pointer(&vb_doc, pointer),
        );
        if let (Some(x), Some(y)) = (va, vb) {
            if let (Ok(jx), Ok(jy)) = (canonical::jcs(x), canonical::jcs(y)) {
                if jx == jy {
                    continue;
                }
            }
        }
        differences.push(JoinDifference {
            pointer: pointer.clone(),
            values: vec![
                JoinValue {
                    member: a.id.clone(),
                    resolved: va.is_some(),
                    value: va.cloned(),
                },
                JoinValue {
                    member: b.id.clone(),
                    resolved: vb.is_some(),
                    value: vb.cloned(),
                },
            ],
        });
    }
    if differences.is_empty() {
        state("agree")
    } else {
        (Some("mismatch".to_string()), differences)
    }
}

fn identifier_matches(record: &Value, pointer: &str, digest: &str) -> bool {
    match resolve_pointer(record, pointer) {
        Some(Value::String(identifier)) => {
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                identifier.as_bytes(),
            )) == digest
        }
        _ => false,
    }
}

fn corroboration(
    j: &Join,
    derived: Option<&str>,
    by_id: &HashMap<&str, &Member>,
    observers: &HashMap<&str, &Observer>,
) -> CorroborationResult {
    let mut out = CorroborationResult {
        members: j.members.clone(),
        result: String::new(),
        reason: None,
        reasons: Vec::new(),
        report: None,
        qualifier: None,
    };
    if derived != Some("agree") {
        out.result = "not_applicable".to_string();
        return out;
    }
    let (a, b) = (by_id[j.members[0].as_str()], by_id[j.members[1].as_str()]);
    if a.observer == b.observer {
        out.reasons.push("same_observer".to_string());
    }
    let custody = |m: &Member| {
        observers
            .get(m.observer.as_str())
            .map(|o| o.custody.as_str())
    };
    if custody(a) == custody(b) {
        out.reasons.push("same_custody_domain".to_string());
    }
    fn key(m: &Member) -> Option<&str> {
        root_record(m)?.get("key_id")?.as_str()
    }
    if let (Some(x), Some(y)) = (key(a), key(b)) {
        if x == y {
            out.reasons.push("same_key_id".to_string());
        }
    }
    // A controller_binding agreement is the bound keys' holders agreeing:
    // their keys are not independent issuers (bundle -02).
    if j.basis == "controller_binding" {
        out.reasons.push("controller_binding".to_string());
    }
    if let Some(first) = out.reasons.first() {
        out.result = "redundant".to_string();
        out.reason = Some(first.clone());
        out.report = Some("redundant, not corroborating".to_string());
        return out;
    }
    out.result = "corroborating".to_string();
    out.qualifier = Some("custody_declared".to_string());
    out
}

// ---- the controller_binding join ------------------------------------------------

/// One member's side of a controller_binding join: the key identifier the
/// binding must name and the time T it must cover.
struct BindingSide {
    key: Option<String>,
    at: Option<UtcTime>,
}

/// Reads a root record's timestamp, which may carry fractional seconds. Times
/// compare as instants; digits beyond nanoseconds are dropped, as Go's
/// `time.Parse` does.
fn record_time(value: &Value) -> Option<UtcTime> {
    let text = value.as_str()?;
    let b = text.as_bytes();
    let digit = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    let shape = b.len() >= 20
        && (0..4).all(digit)
        && b[4] == b'-'
        && (5..7).all(digit)
        && b[7] == b'-'
        && (8..10).all(digit)
        && b[10] == b'T'
        && (11..13).all(digit)
        && b[13] == b':'
        && (14..16).all(digit)
        && b[16] == b':'
        && (17..19).all(digit);
    if !shape {
        return None;
    }
    let rest = &text[19..];
    let zone = rest.strip_suffix('Z')?;
    let normalized = match zone.strip_prefix('.') {
        Some(fraction) if !fraction.is_empty() && fraction.bytes().all(|c| c.is_ascii_digit()) => {
            let kept = &fraction[..fraction.len().min(9)];
            format!("{}.{kept}Z", &text[..19])
        }
        None if zone.is_empty() => text.to_string(),
        _ => return None,
    };
    parse_utc(&normalized)
}

/// A root record's side: the key identifier `pointer` selects, asserted as a
/// string, and the record's timestamp.
fn record_side(record: &Map<String, Value>, pointer: &str) -> BindingSide {
    let document = Value::Object(record.clone());
    BindingSide {
        key: match resolve_pointer(&document, pointer) {
            Some(Value::String(key)) => Some(key.clone()),
            _ => None,
        },
        at: record.get("timestamp").and_then(record_time),
    }
}

/// An empty-history member's side, from its signed checkpoint: the key that
/// signed `checkpoint.cose` and its timestamp. A member without a checkpoint
/// that verifies has no key, so the join is not derivable.
fn checkpoint_side(body: &Map<String, Value>) -> Option<BindingSide> {
    let empty = Map::new();
    let object = |name: &str| body.get(name).and_then(Value::as_object).unwrap_or(&empty);
    let (claim, signed) =
        signed_checkpoint(object("checkpoint"), object("completeness_certificate"));
    let (signed, _) = signed?;
    if claim.status != "pass" {
        return None;
    }
    Some(BindingSide {
        key: Some(signed.key_id),
        at: record_time(&Value::String(signed.timestamp)),
    })
}

/// Whether `record` is a binding record under `ed25519` keys: `key_types` is
/// absent, or names `ed25519` twice. -02 defines no other key type, so a
/// record under one is skipped like a record under an unimplemented method.
fn ed25519_keys(record: &Map<String, Value>) -> bool {
    match record.get("key_types") {
        None => true,
        Some(Value::Array(types)) => {
            types.len() == 2 && types.iter().all(|t| t.as_str() == Some("ed25519"))
        }
        Some(_) => false,
    }
}

fn is_sig_hex(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(s))
        if s.len() == 128 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// Verifies one delivered record through the one binding verifier at the
/// given times. It returns the verifier's report (`None` when the record has
/// no JCS form, so no digest) and whether the record is well formed as -02
/// states it.
///
/// -02 differs from Controller Binding v0 in two places, both applied here
/// and nowhere else: an empty nonce is malformed, and a key type other than
/// `ed25519` is well formed without CB v0's rule for it (the 32-character
/// `bip340` nonce), because -02 does not define that type. A `sig` under
/// `ed25519` keys that is not a `sig-hex` is malformed in -02, where CB v0
/// reads it as a signature that does not verify.
fn binding_report(
    record: &Map<String, Value>,
    times: &[UtcTime],
    statements: &[Vec<u8>],
) -> (Option<controller_binding::Report>, bool) {
    let verify_at = |octets: &[u8], times: &[UtcTime], statements: &[Vec<u8>]| {
        controller_binding::verify(
            octets,
            times,
            &controller_binding::Options {
                revocations: statements.to_vec(),
                ..Default::default()
            },
        )
    };
    let Ok(octets) = canonical::jcs(&Value::Object(record.clone())) else {
        // The digest matched, so only sigs can be unserializable (a float or an
        // integer beyond 2^53 where a sig-hex belongs): malformed under ed25519
        // keys, which -02 holds to sig-hex, and merely not implemented under any
        // other.
        let shaped = record.get("key_types").is_none_or(
            |t| matches!(t, Value::Array(l) if l.len() == 2 && l.iter().all(Value::is_string)),
        );
        if !shaped || ed25519_keys(record) {
            return (None, false);
        }
        // Not implemented, but still held to -02's form: read it with each sig
        // replaced by a string, which no other rule looks at.
        let mut standin = record.clone();
        if let Some(Value::Array(sigs)) = standin.get_mut("sigs") {
            for entry in sigs.iter_mut() {
                if let Some(e) = entry.as_object_mut().filter(|e| e.contains_key("sig")) {
                    e.insert("sig".into(), json!(""));
                }
            }
        }
        if canonical::jcs(&Value::Object(standin.clone())).is_err() {
            return (None, false);
        }
        return binding_report(&standin, times, statements);
    };
    let report = verify_at(&octets, times, statements);
    if let Some(types) = record.get("key_types") {
        let ok = matches!(types, Value::Array(l) if l.len() == 2 && l.iter().all(Value::is_string));
        if !ok {
            return (Some(report), false);
        }
    }
    if record
        .get("nonce")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return (Some(report), false);
    }
    let ed25519 = ed25519_keys(record);
    if let (true, Some(Value::Array(sigs))) = (ed25519, record.get("sigs")) {
        let hex_sigs = sigs.iter().all(|raw| {
            raw.as_object()
                .is_some_and(|entry| is_sig_hex(entry.get("sig")))
        });
        if !hex_sigs {
            return (Some(report), false);
        }
    }
    let form_pass =
        |r: &controller_binding::Report| r.properties.get(PROPERTY_FORM) == Some(&Status::Pass);
    let well_formed = if ed25519 {
        form_pass(&report)
    } else {
        let mut subject = record.clone();
        subject.remove("key_types");
        match canonical::jcs(&Value::Object(subject)) {
            Ok(form_octets) => form_pass(&verify_at(&form_octets, &[], &[])),
            Err(_) => form_pass(&report),
        }
    };
    (Some(report), well_formed)
}

/// Whether this verifier implements the record's method and key types: a
/// method -02 defines for the record's claim, and `ed25519` keys.
fn implemented(record: &Map<String, Value>) -> bool {
    let want =
        if record.get("claim").and_then(Value::as_str) == Some("same_organization_credentialed") {
            "dual_signature_credential/0"
        } else {
            "dual_signature/0"
        };
    record.get("method").and_then(Value::as_str) == Some(want) && ed25519_keys(record)
}

/// -02's binding digest: SHA-256 of the JCS of the record without `sigs`. A
/// join names its record by it, so a record with another digest is skipped
/// before any signature is checked.
fn binding_digest(record: &Map<String, Value>) -> Option<String> {
    let mut rest = record.clone();
    rest.remove("sigs");
    let octets = canonical::jcs(&Value::Object(rest)).ok()?;
    Some(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(octets)))
}

/// Derives the linkage of a `controller_binding` join between two root
/// records: `(linked, derivable)`. Not derivable when no delivered binding
/// record has the join's `identifier_digest`, or when every one that does
/// names a method or key type this verifier does not implement. Otherwise
/// linked when one such record applies: well formed, signed by both bound
/// keys, its keys exactly the two values `pointer` selects, in effect at both
/// root records' timestamps, and revoked by no delivered statement at or
/// before either. A join without `pointer` or `identifier_digest` names no
/// record: not derivable. The record checks are `controller_binding`'s; only
/// the join's reading of its report is here.
fn controller_binding_link(
    j: &Join,
    a: &BindingSide,
    b: &BindingSide,
    opts: &BundleOptions,
) -> (bool, bool) {
    let Some(identifier) = &j.identifier else {
        return (false, false);
    };
    let times: Vec<UtcTime> = match (a.at, b.at) {
        (Some(x), Some(y)) => vec![x, y],
        _ => Vec::new(),
    };
    let statements: Vec<Vec<u8>> = opts
        .composed
        .binding_revocations
        .iter()
        .filter_map(|s| canonical::jcs(s).ok())
        .collect();
    let mut derivable = false;
    for raw in opts.composed.controller_bindings {
        let Some(record) = raw.as_object() else {
            continue;
        };
        if binding_digest(record).as_deref() != Some(identifier.as_str()) {
            continue;
        }
        let (report, well_formed) = binding_report(record, &times, &statements);
        if !well_formed {
            // A malformed record does not apply: the join derives, unjoined.
            derivable = true;
            continue;
        }
        if !implemented(record) {
            continue;
        }
        derivable = true;
        if let (Some(report), Some(x), Some(y)) = (&report, &a.key, &b.key) {
            if report.applies_to(x, y) {
                return (true, true);
            }
        }
    }
    (false, derivable)
}
