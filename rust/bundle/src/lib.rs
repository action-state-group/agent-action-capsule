//! AAC Evidence Bundle v2 codec and verifier -- Rust sibling of `go/bundle`
//! and `ts/bundle`, sharing their conformance vectors (`testdata/vectors.json`
//! is a pinned copy of `vectors/bundle/vectors.json`).
//!
//! The verifier deliberately reports graph closure, interval coverage, and
//! per-record membership separately. The CLL range proof used for interval
//! coverage binds every leaf in the interval (all `body_digests` participate
//! in rebuilding the root, not just the two endpoints); `memberships`
//! separately carries one detached proof per record for the per-record
//! membership property. Keeping those proofs outside the enclosed Capsule is
//! necessary: embedding a proof in a Capsule would change the Capsule ID,
//! which is itself the MMR leaf.
//!
//! **Scope note (deliberate, not a silent gap):** this crate does not depend
//! on `scitt-cose-receipt`. The only checkpoint-authentication member the
//! Go/Python/TS siblings implement -- and the only one the AAC Evidence
//! Bundle draft (-00) defines a wire shape for -- is `checkpoint.cose`, a
//! self-signed CLL COSE checkpoint (see `authenticate_checkpoint`). No
//! Evidence Bundle member for an external SCITT witness receipt is drafted
//! yet, so there is no call site for a receipt verifier here; adding one
//! ahead of a defined wire shape would be inventing spec text, not
//! implementing it. When that member is drafted, wire `scitt-cose-receipt`
//! in as a second, additive authentication path here.

pub mod canonical;
pub mod disclosure;
pub mod references;
pub mod verify;

use base64::Engine as _;
use canonical::CanonicalError;
use cll::mmr;
use cll::range_proof::{self, RangeProof};
use serde::de::Deserialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::fmt;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

// ---- public result types --------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimResult {
    pub status: String,
    pub findings: Vec<String>,
}

impl ClaimResult {
    fn pass() -> Self {
        ClaimResult {
            status: "pass".to_string(),
            findings: Vec::new(),
        }
    }
    fn fail(findings: Vec<String>) -> Self {
        ClaimResult {
            status: "fail".to_string(),
            findings,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureResult {
    pub capsule_id: String,
    pub member: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionResult {
    pub kind: String,
    pub status: String,
    pub integrity_covered: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CountersignatureResult {
    pub value: Value,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProducerSelfReport {
    pub value: Value,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub bundle_digest: Option<String>,
    pub graph_closure: ClaimResult,
    pub interval_coverage: ClaimResult,
    pub per_record_membership: ClaimResult,
    pub disclosures: Vec<DisclosureResult>,
    pub extensions: Vec<ExtensionResult>,
    pub countersignatures: Vec<CountersignatureResult>,
    pub verification: Option<ProducerSelfReport>,
    pub capsule_results: BTreeMap<String, verify::VerificationResult>,
}

#[derive(Debug)]
pub enum BundleError {
    NotAnObject,
    Canonical(CanonicalError),
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BundleError::NotAnObject => write!(f, "bundle must be a JSON object"),
            BundleError::Canonical(e) => write!(f, "{e}"),
        }
    }
}

impl From<CanonicalError> for BundleError {
    fn from(e: CanonicalError) -> Self {
        BundleError::Canonical(e)
    }
}

#[derive(Debug)]
pub enum DecodeError {
    NotBase64Url,
    NotUtf8Json,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::NotBase64Url => write!(f, "fragment must be unpadded base64url"),
            DecodeError::NotUtf8Json => write!(f, "fragment is not UTF-8 JSON"),
        }
    }
}

// ---- fragment codec ---------------------------------------------------------

fn is_b64url(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Encodes a Bundle as unpadded RFC 4648 base64url over UTF-8 JCS bytes.
pub fn encode_fragment(value: &Value) -> Result<String, CanonicalError> {
    let bytes = canonical::jcs(value)?;
    Ok(B64.encode(bytes))
}

/// Decodes an unpadded Evidence Bundle URL fragment. Intentionally
/// transport-only; `verify_bundle` applies the Bundle's semantic checks.
pub fn decode_fragment(fragment: &str) -> Result<Value, DecodeError> {
    if !is_b64url(fragment) {
        return Err(DecodeError::NotBase64Url);
    }
    let raw = B64.decode(fragment).map_err(|_| DecodeError::NotUtf8Json)?;
    let text = std::str::from_utf8(&raw).map_err(|_| DecodeError::NotUtf8Json)?;
    let mut de = serde_json::Deserializer::from_str(text);
    let value = Value::deserialize(&mut de).map_err(|_| DecodeError::NotUtf8Json)?;
    de.end().map_err(|_| DecodeError::NotUtf8Json)?;
    Ok(value)
}

/// Returns the v2 bundle digest, omitting only `countersignatures`.
pub fn bundle_digest(value: &Value) -> Result<String, BundleError> {
    let bundle = value.as_object().ok_or(BundleError::NotAnObject)?;
    let mut canonical_bundle = Map::with_capacity(bundle.len());
    for (k, v) in bundle {
        if k != "countersignatures" {
            canonical_bundle.insert(k.clone(), v.clone());
        }
    }
    Ok(canonical::json_digest(&Value::Object(canonical_bundle))?)
}

// ---- small JSON helpers -----------------------------------------------------

fn is_str(v: Option<&Value>, s: &str) -> bool {
    matches!(v, Some(Value::String(x)) if x == s)
}

/// A JSON integer, decoded or natively constructed, within ±MAX_SAFE_INTEGER.
/// Unlike Go/Python, `serde_json::Value::Number` and `Value::Bool` are
/// distinct enum variants, so (unlike Go's `interface{}` or Python's `bool`
/// subclassing `int`) a boolean can never be mistaken for an integer here.
fn as_bundle_int(v: Option<&Value>) -> Option<i64> {
    let n = match v? {
        Value::Number(n) => n,
        _ => return None,
    };
    if canonical::is_float(n) || canonical::is_unsafe_int(n) {
        return None;
    }
    n.to_string().parse::<i64>().ok()
}

fn hex_list(raw: Option<&Value>) -> Option<Vec<String>> {
    let list = raw?.as_array()?;
    let mut out = Vec::with_capacity(list.len());
    for item in list {
        let s = item.as_str()?;
        if !verify::is_hex64(s) {
            return None;
        }
        out.push(s.to_string());
    }
    Some(out)
}

fn hashes(raw: Option<&Value>) -> Option<Vec<[u8; 32]>> {
    let list = raw?.as_array()?;
    list.iter()
        .map(|item| {
            let s = item.as_str()?;
            if !verify::is_hex64(s) {
                return None;
            }
            hex::decode(s).ok()?.try_into().ok()
        })
        .collect()
}

// ---- records ----------------------------------------------------------------

fn records(
    raw: Option<&Value>,
    results: &mut BTreeMap<String, verify::VerificationResult>,
) -> (BTreeMap<String, Map<String, Value>>, Vec<String>) {
    let mut out = BTreeMap::new();
    let list = match raw.and_then(Value::as_array) {
        Some(l) => l,
        None => return (out, vec!["records_malformed".to_string()]),
    };
    let mut findings = Vec::new();
    for (index, raw_record) in list.iter().enumerate() {
        let record = match raw_record.as_object() {
            Some(r) => r,
            None => {
                findings.push(format!("record_malformed:{index}"));
                continue;
            }
        };
        let id = match record.get("capsule_id").and_then(Value::as_str) {
            Some(id) if verify::is_hex64(id) => id.to_string(),
            _ => {
                findings.push(format!("record_identity_invalid:{index}"));
                continue;
            }
        };
        if out.contains_key(&id) {
            findings.push(format!("record_duplicate:{id}"));
            continue;
        }
        let verification = verify::verify(raw_record, None);
        let matches_id = verification.ok && verification.capsule_id.as_deref() == Some(id.as_str());
        results.insert(id.clone(), verification);
        if !matches_id {
            findings.push(format!("record_identity_invalid:{id}"));
            continue;
        }
        out.insert(id, record.clone());
    }
    (out, findings)
}

// ---- graph closure ------------------------------------------------------------

fn citation_targets(record: &Map<String, Value>) -> Vec<String> {
    let mut targets = Vec::new();
    if let Some(chain) = record.get("chain").and_then(Value::as_object) {
        if let Some(parent) = chain.get("parent_capsule_id").and_then(Value::as_str) {
            targets.push(parent.to_string());
        }
    }
    if let Some(references) = record.get("references").and_then(Value::as_array) {
        for raw in references {
            if let Some(reference) = raw.as_object() {
                let is_aac = matches!(reference.get("type"), Some(Value::String(t)) if t == "agent-action-capsule")
                    && matches!(reference.get("digest_alg"), Some(Value::String(a)) if a == "SHA-256");
                if is_aac {
                    if let Some(digest) = reference.get("digest").and_then(Value::as_str) {
                        targets.push(digest.to_string());
                    }
                }
            }
        }
    }
    targets
}

fn graph(
    bundle: &Map<String, Value>,
    records: &BTreeMap<String, Map<String, Value>>,
    record_findings: &[String],
) -> ClaimResult {
    let mut findings: Vec<String> = record_findings.to_vec();
    if !is_str(bundle.get("bundle_version"), "2")
        || !is_str(bundle.get("bundle_kind"), "evidence-bundle/v2")
    {
        findings.push("bundle_version_or_kind_invalid".to_string());
    }
    let root = match bundle.get("root").and_then(Value::as_str) {
        Some(r) if records.contains_key(r) => r.to_string(),
        _ => {
            findings.push("root_not_supplied_with_matching_identity".to_string());
            return ClaimResult::fail(findings);
        }
    };
    let complete = match bundle.get("completeness").and_then(Value::as_object) {
        Some(c) => c,
        None => {
            findings.push("completeness_malformed".to_string());
            return ClaimResult::fail(findings);
        }
    };
    let depth = match complete.get("closure_depth") {
        None => Some(2i64),
        Some(v) => as_bundle_int(Some(v)),
    };
    let depth = match depth {
        Some(d) if d >= 0 => d,
        _ => {
            findings.push("closure_depth_invalid".to_string());
            return ClaimResult::fail(findings);
        }
    };
    let missing_list: Vec<Value> = match complete.get("missing") {
        None => Vec::new(),
        Some(v) => match v.as_array() {
            Some(l) => l.clone(),
            None => {
                findings.push("missing_malformed".to_string());
                return ClaimResult::fail(findings);
            }
        },
    };
    let mut missing: HashSet<String> = HashSet::new();
    for item in &missing_list {
        let id = match item.as_str() {
            Some(id) if verify::is_hex64(id) => id.to_string(),
            _ => {
                findings.push("missing_malformed".to_string());
                return ClaimResult::fail(findings);
            }
        };
        if missing.contains(&id) {
            findings.push("missing_duplicate".to_string());
        }
        missing.insert(id);
    }
    let expected_mode = if missing.is_empty() {
        "complete"
    } else {
        "declared_incomplete"
    };
    if !is_str(complete.get("records_mode"), expected_mode) {
        findings.push("records_mode_mismatch".to_string());
    }
    let mut frontier = vec![root];
    for _ in 0..depth {
        let mut next = Vec::new();
        for source_id in &frontier {
            if let Some(source) = records.get(source_id) {
                for target in citation_targets(source) {
                    if records.contains_key(&target) {
                        next.push(target);
                    } else if !missing.contains(&target) {
                        findings.push(format!("citation_dangling:{target}"));
                    }
                }
            }
        }
        frontier = next;
    }
    if !findings.is_empty() {
        return ClaimResult::fail(findings);
    }
    if !missing.is_empty() {
        return ClaimResult {
            status: "withheld".to_string(),
            findings: vec!["declared_incomplete".to_string()],
        };
    }
    ClaimResult::pass()
}

// ---- completeness (interval coverage + per-record membership) ---------------

struct RangeProofData {
    from_seq: i64,
    to_seq: i64,
    size: u64,
    proof: RangeProof,
}

fn parse_range_proof(raw: Option<&Value>) -> Option<RangeProofData> {
    let m = raw?.as_object()?;
    let from_seq = as_bundle_int(m.get("from_seq"))?;
    let to_seq = as_bundle_int(m.get("to_seq"))?;
    let size = as_bundle_int(m.get("size"))?;
    let from_index = as_bundle_int(m.get("from_index"))?;
    let to_index = as_bundle_int(m.get("to_index"))?;
    let witness = hex_list(m.get("witness"))?;
    if from_seq < 1 || to_seq < from_seq || size < 0 || from_index < 0 || to_index < from_index {
        return None;
    }
    Some(RangeProofData {
        from_seq,
        to_seq,
        size: size as u64,
        proof: RangeProof {
            v: 1,
            kind: "range".to_string(),
            size: size as u64,
            from_index: from_index as u64,
            to_index: to_index as u64,
            witness,
        },
    })
}

fn parse_inclusion_proof(raw: Option<&Value>) -> Option<mmr::InclusionProof> {
    let m = raw?.as_object()?;
    let v = as_bundle_int(m.get("v"))?;
    let size = as_bundle_int(m.get("size"))?;
    let leaf_index = as_bundle_int(m.get("leaf_index"))?;
    let kind = m.get("kind").and_then(Value::as_str)?;
    let witness = hex_list(m.get("witness"))?;
    let peaks_left = hex_list(m.get("peaks_left"))?;
    let peaks_right = hex_list(m.get("peaks_right"))?;
    if v != 1 || kind != "inclusion" || size < 0 || leaf_index < 0 {
        return None;
    }
    Some(mmr::InclusionProof {
        v: v as u32,
        kind: kind.to_string(),
        size: size as u64,
        leaf_index: leaf_index as u64,
        witness,
        peaks_left,
        peaks_right,
    })
}

fn certificate_data(
    certificate: &Map<String, Value>,
    checkpoint: &Map<String, Value>,
) -> Option<([u8; 32], String, i64, i64, RangeProofData)> {
    let log_id = certificate
        .get("log_id")
        .and_then(Value::as_str)?
        .to_string();
    let root_hex = certificate.get("range_root").and_then(Value::as_str)?;
    let first = as_bundle_int(certificate.get("first_seq"))?;
    let last = as_bundle_int(certificate.get("last_seq"))?;
    if first < 1 || last < first || !verify::is_hex64(root_hex) {
        return None;
    }
    if checkpoint.get("root").and_then(Value::as_str) != Some(root_hex) {
        return None;
    }
    let root: [u8; 32] = hex::decode(root_hex).ok()?.try_into().ok()?;
    let proof = parse_range_proof(certificate.get("range_proof"))?;
    let checkpoint_size = as_bundle_int(checkpoint.get("mmr_size"))?;
    if checkpoint_size < 0 || checkpoint_size as u64 != proof.size {
        return None;
    }
    Some((root, log_id, first, last, proof))
}

/// CLL #13 per-record range membership: every leaf in `[first, last]`
/// participates (via the ordered `body_digests` plus the flat witness), so
/// an altered/deleted/replaced interior leaf is caught here, not only at the
/// two endpoints.
fn verify_range_claim(
    root: &[u8; 32],
    first: i64,
    last: i64,
    certificate: &Map<String, Value>,
    proof: &RangeProofData,
) -> bool {
    if proof.from_seq != first
        || proof.to_seq != last
        || proof.proof.from_index != (first - 1) as u64
        || proof.proof.to_index != (last - 1) as u64
    {
        return false;
    }
    // The interval must end at the checkpointed tip: leaf_count(size) == last.
    // Otherwise a sub-tip range would let records after `last` be silently omitted.
    match mmr::leaf_count(proof.size) {
        Ok(leaves) if leaves == last as u64 => {}
        _ => return false,
    }
    let body_digests_len_ok = matches!(
        certificate.get("body_digests").and_then(Value::as_array),
        Some(l) if l.len() as i64 == last - first + 1
    );
    if !body_digests_len_ok {
        return false;
    }
    let body_digests = match hashes(certificate.get("body_digests")) {
        Some(d) => d,
        None => return false,
    };
    range_proof::verify_range(
        root,
        proof.size,
        proof.proof.from_index,
        proof.proof.to_index,
        &body_digests,
        &proof.proof,
    )
}

fn authenticate_checkpoint(
    checkpoint: &Map<String, Value>,
    log_id: &str,
    root: &[u8; 32],
    size: u64,
) -> &'static str {
    let encoded = match checkpoint.get("cose") {
        None => return "unverified",
        Some(Value::String(s)) => s,
        Some(_) => return "invalid",
    };
    if !is_b64url(encoded) {
        return "invalid";
    }
    let cose = match B64.decode(encoded) {
        Ok(c) => c,
        Err(_) => return "invalid",
    };
    let result = cll::checkpoint::verify_checkpoint_cose_offline(&cose);
    if !result.ok {
        return "invalid";
    }
    match result.decoded {
        Some(decoded)
            if decoded.log_id == log_id
                && decoded.mmr_size == size
                && decoded.root == hex::encode(root) =>
        {
            "verified"
        }
        _ => "invalid",
    }
}

fn verify_memberships(
    root: &[u8; 32],
    log_id: &str,
    first: i64,
    last: i64,
    raw: Option<&Value>,
    records: &BTreeMap<String, Map<String, Value>>,
    completeness: Option<&Value>,
) -> Vec<String> {
    let members = match raw.and_then(Value::as_object) {
        Some(m) => m,
        None => return vec!["memberships_absent".to_string()],
    };
    let mut by_seq: BTreeMap<i64, String> = BTreeMap::new();
    let mut bound_records: HashSet<String> = HashSet::new();
    let mut findings = Vec::new();

    for (id, raw_member) in members {
        let record = records.get(id);
        let member = raw_member.as_object();
        if !verify::is_hex64(id) || record.is_none() || member.is_none() {
            findings.push(format!("membership_record_unknown:{id}"));
            continue;
        }
        let member = member.expect("checked above");
        let coordinates = match member.get("log_coordinates").and_then(Value::as_object) {
            Some(c) => c,
            None => {
                findings.push(format!("membership_coordinates_missing:{id}"));
                continue;
            }
        };
        let seq = as_bundle_int(coordinates.get("seq"));
        let leaf = as_bundle_int(coordinates.get("leaf_index"));
        let log_id_matches =
            matches!(coordinates.get("log_id"), Some(Value::String(l)) if l == log_id);
        let valid = log_id_matches
            && matches!((seq, leaf), (Some(s), Some(l)) if s >= first && s <= last && l == s - 1);
        if !valid {
            findings.push(format!("membership_coordinates_invalid:{id}"));
            continue;
        }
        let seq = seq.expect("validated above");
        let leaf = leaf.expect("validated above");
        if by_seq.contains_key(&seq) {
            findings.push(format!("membership_seq_duplicate:{seq}"));
            continue;
        }
        by_seq.insert(seq, id.clone());
        bound_records.insert(id.clone());

        let proof = parse_inclusion_proof(member.get("inclusion_proof"));
        let body_digest: Option<[u8; 32]> = hex::decode(id).ok().and_then(|b| b.try_into().ok());
        let proof_ok = match (&proof, body_digest) {
            (Some(p), Some(bd)) => mmr::verify_inclusion(root, p.size, leaf as u64, &bd, p),
            _ => false,
        };
        if !proof_ok {
            findings.push(format!("membership_proof_invalid:{id}"));
        }
    }

    for seq in first..=last {
        if !by_seq.contains_key(&seq) {
            findings.push(format!("membership_record_missing:{seq}"));
        }
    }

    let declared_missing: HashSet<String> = completeness
        .and_then(Value::as_object)
        .and_then(|c| c.get("missing"))
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    for id in records.keys() {
        if !bound_records.contains(id) && !declared_missing.contains(id) {
            findings.push(format!("membership_record_unbound:{id}"));
        }
    }
    findings
}

/// `completeness_certificate` and `checkpoint`, when supplied, support three
/// separate claims (this function reports two: interval coverage and
/// per-record membership; `graph()` reports the third). A verifier must
/// report each independently rather than collapsing them into one verdict.
fn completeness(
    bundle: &Map<String, Value>,
    records: &BTreeMap<String, Map<String, Value>>,
) -> (ClaimResult, ClaimResult) {
    let certificate = bundle
        .get("completeness_certificate")
        .and_then(Value::as_object);
    let checkpoint = bundle.get("checkpoint").and_then(Value::as_object);
    let (certificate, checkpoint) = match (certificate, checkpoint) {
        (Some(c), Some(k)) => (c, k),
        _ => {
            let absent = ClaimResult {
                status: "withheld".to_string(),
                findings: vec!["completeness_evidence_absent".to_string()],
            };
            return (absent.clone(), absent);
        }
    };
    let (root, log_id, first, last, proof) = match certificate_data(certificate, checkpoint) {
        Some(data) => data,
        None => {
            let failure = ClaimResult::fail(vec!["completeness_certificate_invalid".to_string()]);
            return (failure.clone(), failure);
        }
    };
    if !verify_range_claim(&root, first, last, certificate, &proof) {
        let failure = ClaimResult::fail(vec!["range_proof_invalid".to_string()]);
        return (failure.clone(), failure);
    }
    let authentication = authenticate_checkpoint(checkpoint, &log_id, &root, proof.size);
    if authentication == "invalid" {
        let failure = ClaimResult::fail(vec!["checkpoint_authentication_invalid".to_string()]);
        return (failure.clone(), failure);
    }
    let membership_findings = verify_memberships(
        &root,
        &log_id,
        first,
        last,
        certificate.get("memberships"),
        records,
        bundle.get("completeness"),
    );
    let mut interval = ClaimResult::pass();
    if authentication != "verified" {
        interval.findings = vec!["checkpoint_unverified".to_string()];
    }
    if !membership_findings.is_empty() {
        return (interval, ClaimResult::fail(membership_findings));
    }
    let mut membership = ClaimResult::pass();
    if authentication != "verified" {
        membership.findings = vec!["checkpoint_unverified".to_string()];
    }
    (interval, membership)
}

// ---- disclosures --------------------------------------------------------------

fn committed_digest(value: &Map<String, Value>, path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = value;
    for part in &parts[..parts.len() - 1] {
        current = current.get(*part)?.as_object()?;
    }
    current
        .get(parts[parts.len() - 1])?
        .as_str()
        .map(String::from)
}

fn disclosures(
    raw: Option<&Value>,
    records: &BTreeMap<String, Map<String, Value>>,
) -> Vec<DisclosureResult> {
    let overlay = match raw.and_then(Value::as_object) {
        Some(o) => o,
        None => {
            return vec![DisclosureResult {
                capsule_id: String::new(),
                member: String::new(),
                status: disclosure::MISMATCH.to_string(),
            }]
        }
    };

    let mut result = Vec::new();
    for (id, record) in records {
        let supplied = match overlay.get(id) {
            None => None,
            Some(v) => match v.as_object() {
                Some(m) => Some(m),
                None => continue,
            },
        };
        for member in disclosure::ELIGIBLE_MEMBERS {
            let exists = supplied.map(|m| m.contains_key(member)).unwrap_or(false);
            if !exists {
                let path = disclosure::disclosure_eligible_field(member).expect("known member");
                if committed_digest(record, path).is_some() {
                    result.push(DisclosureResult {
                        capsule_id: id.clone(),
                        member: member.to_string(),
                        status: "withheld".to_string(),
                    });
                }
            }
        }
    }

    let mut keys: Vec<&String> = overlay.keys().collect();
    keys.sort();
    for id in keys {
        let members = match overlay.get(id).and_then(Value::as_object) {
            Some(m) => m,
            None => {
                result.push(DisclosureResult {
                    capsule_id: id.clone(),
                    member: String::new(),
                    status: disclosure::MISMATCH.to_string(),
                });
                continue;
            }
        };
        let record = match records.get(id) {
            Some(r) => r,
            None => {
                result.push(DisclosureResult {
                    capsule_id: id.clone(),
                    member: String::new(),
                    status: disclosure::MISMATCH.to_string(),
                });
                continue;
            }
        };
        let mut member_names: Vec<&String> = members.keys().collect();
        member_names.sort();
        for member in member_names {
            let path = match disclosure::disclosure_eligible_field(member) {
                Some(p) => p,
                None => {
                    result.push(DisclosureResult {
                        capsule_id: id.clone(),
                        member: member.clone(),
                        status: disclosure::INELIGIBLE.to_string(),
                    });
                    continue;
                }
            };
            let stored = committed_digest(record, path);
            let stored = match &stored {
                Some(s) if verify::is_hex64(s) => s,
                _ => {
                    result.push(DisclosureResult {
                        capsule_id: id.clone(),
                        member: member.clone(),
                        status: disclosure::NO_COMMITTED_DIGEST.to_string(),
                    });
                    continue;
                }
            };
            let status = match canonical::json_digest(&members[member]) {
                Ok(computed) if &computed == stored => disclosure::MATCH,
                _ => disclosure::MISMATCH,
            };
            result.push(DisclosureResult {
                capsule_id: id.clone(),
                member: member.clone(),
                status: status.to_string(),
            });
        }
    }
    result
}

fn extensions(raw: Option<&Value>) -> Vec<ExtensionResult> {
    let values = match raw.and_then(Value::as_object) {
        Some(v) => v,
        None => return Vec::new(),
    };
    let mut kinds: Vec<&String> = values.keys().collect();
    kinds.sort();
    kinds
        .into_iter()
        .map(|kind| ExtensionResult {
            kind: kind.clone(),
            status: "uninterpreted".to_string(),
            integrity_covered: true,
        })
        .collect()
}

// ---- top-level verifier -------------------------------------------------------

/// Verifies an AAC Evidence Bundle using only its supplied evidence.
pub fn verify_bundle(value: &Value) -> VerificationResult {
    let bundle = match value.as_object() {
        Some(b) => b,
        None => {
            let invalid = ClaimResult::fail(vec!["bundle_malformed".to_string()]);
            return VerificationResult {
                bundle_digest: None,
                graph_closure: invalid.clone(),
                interval_coverage: invalid.clone(),
                per_record_membership: invalid,
                disclosures: Vec::new(),
                extensions: Vec::new(),
                countersignatures: Vec::new(),
                verification: None,
                capsule_results: BTreeMap::new(),
            };
        }
    };

    let mut capsule_results = BTreeMap::new();
    let bundle_digest_value = bundle_digest(value).ok();
    let (record_map, record_findings) = records(bundle.get("records"), &mut capsule_results);
    let graph_closure = graph(bundle, &record_map, &record_findings);
    let (interval_coverage, per_record_membership) = completeness(bundle, &record_map);
    let empty_overlay = Value::Object(Map::new());
    let disclosures_result = match bundle.get("disclosures") {
        Some(v) => disclosures(Some(v), &record_map),
        None => disclosures(Some(&empty_overlay), &record_map),
    };
    let extensions_result = extensions(bundle.get("extensions"));
    let countersignatures = match bundle.get("countersignatures").and_then(Value::as_array) {
        Some(list) => list
            .iter()
            .map(|v| CountersignatureResult {
                value: v.clone(),
                status: "unverified".to_string(),
            })
            .collect(),
        None => Vec::new(),
    };
    let verification = bundle.get("verification").map(|v| ProducerSelfReport {
        value: v.clone(),
        status: "producer_self_report".to_string(),
    });

    VerificationResult {
        bundle_digest: bundle_digest_value,
        graph_closure,
        interval_coverage,
        per_record_membership,
        disclosures: disclosures_result,
        extensions: extensions_result,
        countersignatures,
        verification,
        capsule_results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Not exercised by the shared #100 vector matrix (no vector sets
    // `extensions`); covered here directly since it is genuinely untested
    // otherwise.
    #[test]
    fn extensions_reports_every_kind_sorted_and_uninterpreted() {
        let raw = json!({"b/kind": {"x": 1}, "a/kind": {}});
        let result = extensions(Some(&raw));
        assert_eq!(
            result,
            vec![
                ExtensionResult {
                    kind: "a/kind".to_string(),
                    status: "uninterpreted".to_string(),
                    integrity_covered: true,
                },
                ExtensionResult {
                    kind: "b/kind".to_string(),
                    status: "uninterpreted".to_string(),
                    integrity_covered: true,
                },
            ]
        );
        assert_eq!(extensions(None), Vec::new());
        assert_eq!(extensions(Some(&json!("not-an-object"))), Vec::new());
    }
}
