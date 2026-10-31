//! AAC Evidence Bundle v2 codec and verifier. Port of `go/bundle` and the
//! TypeScript `/bundle` export, checked against `vectors/bundle/`.
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
//! [`verify_bundle`] reads only what the Bundle draft defines; the one
//! checkpoint-authentication member it checks is `checkpoint.cose`, a
//! self-signed CLL COSE checkpoint (see `authenticate_checkpoint`). With the
//! `strict` feature, [`verify_bundle_strict`] adds the checks a verifier
//! needs before it tells a person a Bundle is VALID: each record's producer
//! signature, the checkpoint read only from its signed COSE form,
//! producer-selected Bundles, the `disclosures` overlay as one claim, and
//! the witness receipts in `checkpoint.witnesses` ([`crate::witness`]), with
//! a verdict. `completeness.selection` and `checkpoint.witnesses` are not
//! defined by the Bundle draft, so strict mode reads them as verifier
//! extensions (`vectors/bundle/strict/README.md`).
//!
//! The `strict` feature also adds the producer: [`build_evidence_bundle`]
//! assembles a Bundle from a [`ProofSource`] and refuses any result
//! [`verify_bundle_strict`] calls INVALID; [`proof_source_from_cll`] adapts a
//! CLL backend and a [`RecordSource`]; [`build_unproven_bundle`] builds the
//! form with no log proof.

mod category_coverage;
pub use category_coverage::{
    category_coverage_signing_input, check_category_coverage, CategoryCoverage, CategoryInputs,
    CATEGORY_COVERAGE_GATING, CATEGORY_COVERAGE_PROPERTIES, CATEGORY_STATUSES,
};
mod composed;
pub use composed::{
    composed_digest, composed_digest_preimage, verify_composed, ComposedDigestResult,
    ComposedJoinResult, ComposedMemberResult, ComposedOptions, ComposedResult,
    CompositionClosureResult, CorroborationResult, JoinDifference, JoinValue, SignatureVerifier,
    COMPOSED_KIND, SIGNATURE_INVALID, SIGNATURE_UNVERIFIED, SIGNATURE_VERIFIED,
};
#[cfg(feature = "strict")]
mod strict;
#[cfg(feature = "strict")]
pub use strict::{verify_bundle_strict, RecordResult, StrictOptions, StrictVerificationResult};
#[cfg(feature = "strict")]
mod producer;
#[cfg(feature = "strict")]
pub use producer::{
    build_evidence_bundle, build_unproven_bundle, proof_source_from_cll, BuildError, BuildOptions,
    CllProofSource, InclusionProof, Interval, PayloadsMode, ProofSource, RangeProof, RecordSource,
    StoredRecord, UnprovenOptions,
};

use crate::canonical::{self, CanonicalError};
use crate::{disclosure, verify};
use base64::Engine as _;
use cll::mmr;
use cll::range_proof::{self, RangeProof as CllRangeProof};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::fmt;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// `completeness.selection` of a producer-selected Bundle: records the
/// producer picked from its log, each proven on its own, with no claim about
/// the records between them (Bundle -02).
pub const SELECTION_PRODUCER_SELECTED: &str = "producer-selected";

/// The finding for a `completeness.selection` value naming a certificate mode
/// this verifier does not implement (Bundle -02): interval coverage and
/// per-record membership are withheld, never failed.
pub const CERTIFICATE_MODE_UNSUPPORTED: &str = "certificate_mode_unsupported";

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

#[derive(Debug, Clone)]
pub struct ExtensionResult {
    pub kind: String,
    pub status: String,
    pub integrity_covered: bool,
    /// The `composed/v1` block's verification, for that kind only. Its
    /// `status` is this result's `status`.
    pub composed: Option<ComposedResult>,
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

/// What an empty-history Bundle shows (Bundle -02, "Empty-History Bundles"):
/// no history. `state` is `none`; `since` is the timestamp of the signed
/// checkpoint the Bundle carries, when it verifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryResult {
    pub state: String,
    pub since: Option<String>,
}

/// What a Bundle is verified with beyond its own bytes: the inputs for its
/// `category_coverage` member and for a `composed/v1` block.
#[derive(Clone, Copy, Default)]
pub struct BundleOptions<'a> {
    pub category: CategoryInputs<'a>,
    pub composed: ComposedOptions<'a>,
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
    /// The `category_coverage` member's five properties, in report order, or
    /// `None` when the Bundle carries no such member.
    pub category_coverage: Option<CategoryCoverage>,
    /// Set only for a well-formed empty-history Bundle: the member shows no
    /// history.
    pub history: Option<HistoryResult>,
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
    crate::json::decode(&raw).map_err(|_| DecodeError::NotUtf8Json)
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
    // Breadth-first, each target once: a record first reached at its shortest
    // distance already carries the most remaining depth, and the walk stops when
    // no new record is reached, so work is bounded by the supplied records.
    let mut visited: HashSet<String> = HashSet::from([root.clone()]);
    let mut dangling: HashSet<String> = HashSet::new();
    let mut frontier = vec![root];
    let mut level = 0;
    while level < depth && !frontier.is_empty() {
        let mut next = Vec::new();
        for source_id in &frontier {
            if let Some(source) = records.get(source_id) {
                for target in citation_targets(source) {
                    if records.contains_key(&target) {
                        if visited.insert(target.clone()) {
                            next.push(target);
                        }
                    } else if !missing.contains(&target) && dangling.insert(target.clone()) {
                        findings.push(format!("citation_dangling:{target}"));
                    }
                }
            }
        }
        frontier = next;
        level += 1;
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
    proof: CllRangeProof,
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
        proof: CllRangeProof {
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

/// Per-record membership over `[first, last]`: every finding in report
/// order, and whether any of them fails the claim (the others are
/// `non_record_leaf_type_unsupported`, which withhold it). Every seq of the
/// interval is a record's membership, a non-record leaf, or
/// `membership_record_missing`.
fn verify_memberships(
    root: &[u8; 32],
    log_id: &str,
    first: i64,
    last: i64,
    certificate: &Map<String, Value>,
    records: &BTreeMap<String, Map<String, Value>>,
    completeness: Option<&Value>,
) -> (Vec<String>, bool) {
    let members = match certificate.get("memberships").and_then(Value::as_object) {
        Some(m) => m,
        None => return (vec!["memberships_absent".to_string()], true),
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

    let mut leaf_seqs = HashSet::new();
    let mut unsupported = 0;
    if let Some(raw_leaves) = certificate.get("non_record_leaves") {
        let leaf_findings;
        (leaf_findings, leaf_seqs) = non_record_leaves(
            raw_leaves,
            first,
            last,
            certificate.get("body_digests"),
            &stated_seqs(members),
        );
        unsupported = leaf_findings
            .iter()
            .filter(|f| f.starts_with(UNSUPPORTED_LEAF))
            .count();
        findings.extend(leaf_findings);
    }
    for seq in first..=last {
        if !by_seq.contains_key(&seq) && !leaf_seqs.contains(&seq) {
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
    let failed = findings.len() > unsupported;
    (findings, failed)
}

const UNSUPPORTED_LEAF: &str = "non_record_leaf_type_unsupported:";

/// The one non-record leaf type a range can carry (Bundle -02, Evidence Layer
/// padding), and the exact members of its content.
const PADDING: &str = "padding";
const PADDING_MEMBERS: [&str; 4] = ["capsule_id", "epistemic_type", "record_type", "store_nonce"];

/// Every seq a `memberships` entry states in `log_coordinates`, whatever else
/// is wrong with the entry: a non-record leaf may not claim one.
fn stated_seqs(members: &Map<String, Value>) -> HashSet<i64> {
    members
        .values()
        .filter_map(|member| {
            let coordinates = member.get("log_coordinates")?;
            as_bundle_int(coordinates.get("seq"))
        })
        .collect()
}

/// Checks `completeness_certificate.non_record_leaves` (Bundle -02): the
/// findings in element order and the seqs the member accounts for. Every
/// finding fails the claim except `non_record_leaf_type_unsupported:<seq>`.
/// An element whose `seq` is valid accounts for that seq whatever else it
/// fails, so the seq is never also reported missing. `body_digests` has
/// already been checked by the range proof.
fn non_record_leaves(
    raw: &Value,
    first: i64,
    last: i64,
    body_digests: Option<&Value>,
    record_seqs: &HashSet<i64>,
) -> (Vec<String>, HashSet<i64>) {
    let mut accounted = HashSet::new();
    let Some(elements) = raw.as_array() else {
        return (vec!["non_record_leaves_malformed".to_string()], accounted);
    };
    let digests = body_digests.and_then(Value::as_array);
    let mut findings = Vec::new();
    for (index, element) in elements.iter().enumerate() {
        let Some(element) = element.as_object() else {
            findings.push(format!("non_record_leaf_element_invalid:{index}"));
            continue;
        };
        let seq = match as_bundle_int(element.get("seq")) {
            Some(seq)
                if seq >= first
                    && seq <= last
                    && !record_seqs.contains(&seq)
                    && !accounted.contains(&seq) =>
            {
                seq
            }
            _ => {
                findings.push(format!("non_record_leaf_seq_invalid:{index}"));
                continue;
            }
        };
        accounted.insert(seq);
        let content = element.get("content").and_then(Value::as_object);
        let Some((content, record_type)) =
            content.and_then(|c| Some((c, c.get("record_type")?.as_str()?)))
        else {
            // Includes an element that carries a digest in place of content.
            findings.push(format!("non_record_leaf_malformed:{seq}"));
            continue;
        };
        if record_type != PADDING {
            findings.push(format!("{UNSUPPORTED_LEAF}{seq}"));
            continue;
        }
        let shaped = content.len() == PADDING_MEMBERS.len()
            && PADDING_MEMBERS
                .iter()
                .all(|name| content.contains_key(*name))
            && is_str(content.get("epistemic_type"), "producer_claim")
            && content
                .get("store_nonce")
                .and_then(Value::as_str)
                .is_some_and(verify::is_hex64)
            && content
                .get("capsule_id")
                .and_then(Value::as_str)
                .is_some_and(verify::is_hex64);
        if !shaped {
            findings.push(format!("non_record_leaf_malformed:{seq}"));
            continue;
        }
        let body = digests.and_then(|d| d.get((seq - first) as usize));
        match padding_leaf(content) {
            Some(leaf) if is_str(content.get("capsule_id"), &leaf) && is_str(body, &leaf) => {}
            _ => findings.push(format!("non_record_leaf_mismatch:{seq}")),
        }
    }
    (findings, accounted)
}

/// A padding record's leaf: JSON-DIGEST of its content without `capsule_id`.
fn padding_leaf(content: &Map<String, Value>) -> Option<String> {
    let mut preimage = content.clone();
    preimage.remove("capsule_id");
    canonical::json_digest(&Value::Object(preimage)).ok()
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
    if let Some(selection) = bundle
        .get("completeness")
        .and_then(Value::as_object)
        .and_then(|c| c.get("selection"))
    {
        if is_str(Some(selection), SELECTION_PRODUCER_SELECTED) {
            return plain_selected(bundle, checkpoint);
        }
        // A certificate mode this verifier does not implement: not shown, and
        // never a failure (Bundle -02).
        let unsupported = ClaimResult {
            status: "withheld".to_string(),
            findings: vec![CERTIFICATE_MODE_UNSUPPORTED.to_string()],
        };
        return (unsupported.clone(), unsupported);
    }
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
    let (mut findings, failed) = verify_memberships(
        &root,
        &log_id,
        first,
        last,
        certificate,
        records,
        bundle.get("completeness"),
    );
    let qualifier: Vec<String> = if authentication == "verified" {
        Vec::new()
    } else {
        vec!["checkpoint_unverified".to_string()]
    };
    let interval = ClaimResult {
        status: "pass".to_string(),
        findings: qualifier.clone(),
    };
    if failed {
        return (interval, ClaimResult::fail(findings));
    }
    if !findings.is_empty() {
        findings.extend(qualifier);
        let withheld = ClaimResult {
            status: "withheld".to_string(),
            findings,
        };
        return (interval, withheld);
    }
    (interval.clone(), interval)
}

/// A producer-selected Bundle without strict mode: no interval to check;
/// each record's own proof against the stated checkpoint, qualified like a
/// range Bundle's when the checkpoint's COSE form does not authenticate it.
fn plain_selected(
    bundle: &Map<String, Value>,
    checkpoint: &Map<String, Value>,
) -> (ClaimResult, ClaimResult) {
    let interval = ClaimResult {
        status: "withheld".to_string(),
        findings: vec!["selection_not_checkable".to_string()],
    };
    let null = Value::Null;
    let stated = |name: &str| checkpoint.get(name).unwrap_or(&null);
    let membership =
        selected_membership(bundle, stated("root"), stated("mmr_size"), stated("log_id"));
    if membership.status != "pass" {
        return (interval, membership);
    }
    // selected_membership passed, so these are a string, 64 hex digits and a
    // safe integer.
    let log_id = stated("log_id").as_str().unwrap_or_default();
    let root: [u8; 32] = hex::decode(stated("root").as_str().unwrap_or_default())
        .ok()
        .and_then(|r| r.try_into().ok())
        .unwrap_or_default();
    let size = as_bundle_int(Some(stated("mmr_size"))).unwrap_or_default();
    let authentication = match u64::try_from(size) {
        Ok(size) => authenticate_checkpoint(checkpoint, log_id, &root, size),
        Err(_) if !checkpoint.contains_key("cose") => "unverified",
        Err(_) => "invalid",
    };
    let membership = match authentication {
        "invalid" => ClaimResult::fail(vec!["checkpoint_authentication_invalid".to_string()]),
        "verified" => ClaimResult::pass(),
        _ => ClaimResult {
            status: "pass".to_string(),
            findings: vec!["checkpoint_unverified".to_string()],
        },
    };
    (interval, membership)
}

/// Each record's inclusion proof against `root_hex` and `size`, for a
/// producer-selected Bundle. A `non_record_leaves` member makes the
/// certificate invalid: with no range there is no interval for it to cover.
fn selected_membership(
    bundle: &Map<String, Value>,
    root_hex: &Value,
    size: &Value,
    log_id: &Value,
) -> ClaimResult {
    let invalid = || ClaimResult::fail(vec!["completeness_certificate_invalid".to_string()]);
    let Some(certificate) = bundle
        .get("completeness_certificate")
        .and_then(Value::as_object)
    else {
        return invalid();
    };
    let (Some(members), Some(log_id), Some(root_text), Some(size)) = (
        certificate.get("memberships").and_then(Value::as_object),
        log_id.as_str(),
        root_hex.as_str(),
        as_bundle_int(Some(size)),
    ) else {
        return invalid();
    };
    if certificate.contains_key("non_record_leaves")
        || !is_str(certificate.get("range_root"), root_text)
        || !is_str(certificate.get("log_id"), log_id)
        || !verify::is_hex64(root_text)
    {
        return invalid();
    }
    let root: [u8; 32] = match hex::decode(root_text).ok().and_then(|r| r.try_into().ok()) {
        Some(r) => r,
        None => return invalid(),
    };
    let ids: Vec<String> = bundle
        .get("records")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter_map(Value::as_object)
        .map(|r| {
            r.get("capsule_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        })
        .collect();
    let mut findings = Vec::new();
    let mut seen: HashSet<i64> = HashSet::new();
    for cid in &ids {
        let member = members.get(cid).and_then(Value::as_object);
        let coords = match member
            .and_then(|m| m.get("log_coordinates"))
            .and_then(Value::as_object)
        {
            Some(c) => c,
            None => {
                findings.push(format!("membership_record_unbound:{cid}"));
                continue;
            }
        };
        let seq = as_bundle_int(coords.get("seq"));
        let index = as_bundle_int(coords.get("leaf_index"));
        let (seq, index) = match (seq, index) {
            (Some(seq), Some(index))
                if is_str(coords.get("log_id"), log_id)
                    && seq >= 1
                    && index == seq - 1
                    && !seen.contains(&seq) =>
            {
                (seq, index)
            }
            _ => {
                findings.push(format!("membership_coordinates_invalid:{cid}"));
                continue;
            }
        };
        seen.insert(seq);
        let proof = parse_inclusion_proof(member.and_then(|m| m.get("inclusion_proof")));
        let leaf: Option<[u8; 32]> = hex::decode(cid).ok().and_then(|b| b.try_into().ok());
        let proof_ok = match (proof, leaf, u64::try_from(size)) {
            (Some(proof), Some(leaf), Ok(size)) => {
                proof.size == size
                    && mmr::verify_inclusion(&root, size, index as u64, &leaf, &proof)
            }
            _ => false,
        };
        if !proof_ok {
            findings.push(format!("membership_proof_invalid:{cid}"));
        }
    }
    let mut unknown: Vec<&String> = members.keys().filter(|cid| !ids.contains(cid)).collect();
    unknown.sort();
    findings.extend(
        unknown
            .into_iter()
            .map(|cid| format!("membership_record_unknown:{cid}")),
    );
    if findings.is_empty() {
        ClaimResult::pass()
    } else {
        ClaimResult::fail(findings)
    }
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

fn extensions(raw: Option<&Value>, opts: &BundleOptions) -> Vec<ExtensionResult> {
    let values = match raw.and_then(Value::as_object) {
        Some(v) => v,
        None => return Vec::new(),
    };
    let mut kinds: Vec<&String> = values.keys().collect();
    kinds.sort();
    kinds
        .into_iter()
        .map(|kind| {
            let composed = (kind == COMPOSED_KIND).then(|| verify_composed(&values[kind], opts));
            ExtensionResult {
                kind: kind.clone(),
                status: composed
                    .as_ref()
                    .map_or("uninterpreted", |c| c.status.as_str())
                    .to_string(),
                integrity_covered: true,
                composed,
            }
        })
        .collect()
}

// ---- signed checkpoint --------------------------------------------------------

/// The checkpoint fields a signed COSE checkpoint states; the Bundle's JSON
/// copy must match every one it carries.
const SIGNED_CHECKPOINT_FIELDS: [&str; 7] = [
    "log_id",
    "mmr_size",
    "root",
    "key_id",
    "timestamp",
    "prev_size",
    "prev_root",
];

/// JSON equality of a stated checkpoint field with its signed string value.
fn same_string(stated: &Value, signed: &str) -> bool {
    matches!(stated, Value::String(s) if s == signed)
}

/// JSON equality of a stated checkpoint field with its signed integer value:
/// a JSON integer (never a float or a boolean) of the same value.
fn same_integer(stated: &Value, signed: u64) -> bool {
    match stated {
        Value::Number(n) if !canonical::is_float(n) => {
            n.to_string().parse::<i128>().ok() == Some(i128::from(signed))
        }
        _ => false,
    }
}

/// Verifies `checkpoint.cose` and holds the JSON copy, and the completeness
/// certificate's `log_id` when stated, to it. Returns the claim and, when it
/// passed, the signed fields and the COSE bytes.
fn signed_checkpoint(
    stated: &Map<String, Value>,
    certificate: &Map<String, Value>,
) -> (
    ClaimResult,
    Option<(cll::checkpoint::DecodedCheckpointCose, Vec<u8>)>,
) {
    let fail = |finding: &str| (ClaimResult::fail(vec![finding.to_string()]), None);
    let encoded = match stated.get("cose") {
        None | Some(Value::Null) => {
            return (
                ClaimResult {
                    status: "withheld".to_string(),
                    findings: vec!["checkpoint_signature_absent".to_string()],
                },
                None,
            )
        }
        Some(Value::String(s)) if is_b64url(s) => s,
        Some(_) => return fail("checkpoint_signature_malformed"),
    };
    let cose = match B64.decode(encoded) {
        Ok(c) => c,
        Err(_) => return fail("checkpoint_signature_malformed"),
    };
    let verified = cll::checkpoint::verify_checkpoint_cose_offline(&cose);
    let signed = match verified.decoded {
        Some(decoded) if verified.ok => decoded,
        _ => return fail("checkpoint_signature_invalid"),
    };
    let mut findings: Vec<String> = SIGNED_CHECKPOINT_FIELDS
        .iter()
        .filter(|name| {
            // The certificate's log_id is a second stated copy of the signed
            // one (bundle -01 §Completeness): either copy differing is one
            // mismatch.
            let certificate_differs = **name == "log_id"
                && certificate
                    .get("log_id")
                    .is_some_and(|value| !same_string(value, &signed.log_id));
            certificate_differs
                || stated.get(**name).is_some_and(|value| match **name {
                    "log_id" => !same_string(value, &signed.log_id),
                    "mmr_size" => !same_integer(value, signed.mmr_size),
                    "root" => !same_string(value, &signed.root),
                    "key_id" => !same_string(value, &signed.key_id),
                    "timestamp" => !same_string(value, &signed.timestamp),
                    "prev_size" => !same_integer(value, signed.prev_size),
                    _ => !same_string(value, &signed.prev_root),
                })
        })
        .map(|name| format!("checkpoint_field_mismatch:{name}"))
        .collect();
    findings.extend(
        ["log_id", "mmr_size", "root"]
            .iter()
            .filter(|name| !stated.contains_key(**name))
            .map(|name| format!("checkpoint_field_missing:{name}")),
    );
    if !findings.is_empty() {
        return (ClaimResult::fail(findings), None);
    }
    (ClaimResult::pass(), Some((signed, cose)))
}

// ---- top-level verifier -------------------------------------------------------

/// The result for a Bundle that cannot be read: `bundle_malformed` on every
/// claim.
fn malformed_bundle() -> VerificationResult {
    let invalid = ClaimResult::fail(vec!["bundle_malformed".to_string()]);
    VerificationResult {
        bundle_digest: None,
        graph_closure: invalid.clone(),
        interval_coverage: invalid.clone(),
        per_record_membership: invalid,
        disclosures: Vec::new(),
        extensions: Vec::new(),
        countersignatures: Vec::new(),
        verification: None,
        capsule_results: BTreeMap::new(),
        category_coverage: None,
        history: None,
    }
}

/// Verifies an AAC Evidence Bundle using only its supplied evidence.
///
/// A Bundle that is not a JSON object, or that nests arrays and objects
/// deeper than 128 levels (checked iteratively before any recursive work, so
/// a caller-built `Value` cannot overflow the stack), is `bundle_malformed`
/// on every claim.
pub fn verify_bundle(value: &Value) -> VerificationResult {
    verify_bundle_with(value, &CategoryInputs::default())
}

/// [`verify_bundle`] with the inputs a Bundle cannot carry for its
/// `category_coverage` member ([`CategoryInputs`]).
pub fn verify_bundle_with(value: &Value, category: &CategoryInputs) -> VerificationResult {
    verify_bundle_with_options(
        value,
        &BundleOptions {
            category: *category,
            composed: ComposedOptions::default(),
        },
    )
}

/// [`verify_bundle`] with [`BundleOptions`]: the `category_coverage` inputs
/// and the signature verifiers and delivered binding records a `composed/v1`
/// block is checked with. Carried member bundles are verified with the same
/// options.
pub fn verify_bundle_with_options(value: &Value, opts: &BundleOptions) -> VerificationResult {
    let category = &opts.category;
    let bundle = match value.as_object() {
        Some(b) if !crate::json::exceeds_max_depth(value) => b,
        _ => return malformed_bundle(),
    };

    let mut capsule_results = BTreeMap::new();
    let bundle_digest_value = bundle_digest(value).ok();
    let (record_map, record_findings) = records(bundle.get("records"), &mut capsule_results);
    let mut history = None;
    let (graph_closure, interval_coverage, per_record_membership) = if is_empty_history(bundle) {
        let graph_closure = empty_history_form(bundle);
        let no_records = ClaimResult {
            status: "withheld".to_string(),
            findings: vec!["no_records".to_string()],
        };
        if graph_closure.status == "pass" {
            let empty = Map::new();
            let object = |name: &str| {
                bundle
                    .get(name)
                    .and_then(Value::as_object)
                    .unwrap_or(&empty)
            };
            let (claim, signed) =
                signed_checkpoint(object("checkpoint"), object("completeness_certificate"));
            history = Some(HistoryResult {
                state: "none".to_string(),
                since: signed
                    .filter(|_| claim.status == "pass")
                    .map(|(decoded, _)| decoded.timestamp),
            });
        }
        (graph_closure, no_records.clone(), no_records)
    } else {
        let graph_closure = graph(bundle, &record_map, &record_findings);
        let (interval_coverage, per_record_membership) = completeness(bundle, &record_map);
        (graph_closure, interval_coverage, per_record_membership)
    };
    let empty_overlay = Value::Object(Map::new());
    let disclosures_result = match bundle.get("disclosures") {
        Some(v) => disclosures(Some(v), &record_map),
        None => disclosures(Some(&empty_overlay), &record_map),
    };
    let extensions_result = extensions(bundle.get("extensions"), opts);
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
        category_coverage: check_category_coverage(bundle, category),
        history,
    }
}

/// Whether `bundle` has the shape of an empty-history Bundle: an empty
/// `records` array and no `root` member. Whether it is well formed is
/// [`empty_history_form`]'s question.
fn is_empty_history(bundle: &Map<String, Value>) -> bool {
    matches!(bundle.get("records"), Some(Value::Array(l)) if l.is_empty())
        && !bundle.contains_key("root")
}

/// Graph closure for an empty-history Bundle: nothing to close, so it passes
/// when the Bundle is well formed. `records_mode` is `complete`,
/// `payloads_mode` `none`, and no certificate, disclosures or disclosure
/// record is carried.
fn empty_history_form(bundle: &Map<String, Value>) -> ClaimResult {
    let mut findings = Vec::new();
    if !is_str(bundle.get("bundle_version"), "2")
        || !is_str(bundle.get("bundle_kind"), "evidence-bundle/v2")
    {
        findings.push("bundle_version_or_kind_invalid".to_string());
    }
    let complete = bundle.get("completeness").and_then(Value::as_object);
    let missing_ok = match complete.and_then(|c| c.get("missing")) {
        None => true,
        Some(Value::Array(l)) => l.is_empty(),
        Some(_) => false,
    };
    if !complete.is_some_and(|c| {
        is_str(c.get("records_mode"), "complete") && is_str(c.get("payloads_mode"), "none")
    }) || !missing_ok
    {
        findings.push("empty_history_completeness_invalid".to_string());
    }
    for name in [
        "completeness_certificate",
        "disclosures",
        "disclosure_record",
    ] {
        if bundle.contains_key(name) {
            findings.push(format!("empty_history_carries:{name}"));
        }
    }
    if findings.is_empty() {
        ClaimResult::pass()
    } else {
        ClaimResult::fail(findings)
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
    fn a_deeply_nested_bundle_is_malformed_without_recursing() {
        use crate::json::deep;
        for nested in [deep::array(1_000_000), deep::object(129)] {
            let mut record = Map::new();
            record.insert("signature".into(), json!("00"));
            record.insert("key_id".into(), json!("00"));
            record.insert("deep".into(), nested);
            let mut bundle = Map::new();
            bundle.insert("bundle_kind".into(), json!("evidence-bundle/v2"));
            bundle.insert("bundle_version".into(), json!("2"));
            bundle.insert("records".into(), Value::Array(vec![Value::Object(record)]));
            let bundle = Value::Object(bundle);
            let result = verify_bundle(&bundle);
            let malformed = ClaimResult::fail(vec!["bundle_malformed".to_string()]);
            assert_eq!(result.graph_closure, malformed);
            assert_eq!(result.interval_coverage, malformed);
            assert_eq!(result.per_record_membership, malformed);
            assert_eq!(result.bundle_digest, None);
            assert!(result.capsule_results.is_empty());
            crate::json::deep::dismantle(bundle);
        }
    }

    #[test]
    fn extensions_reports_every_kind_sorted_and_uninterpreted() {
        let raw = json!({"b/kind": {"x": 1}, "a/kind": {}});
        let result = extensions(Some(&raw), &BundleOptions::default());
        let shown: Vec<_> = result
            .iter()
            .map(|e| {
                (
                    e.kind.as_str(),
                    e.status.as_str(),
                    e.integrity_covered,
                    e.composed.is_none(),
                )
            })
            .collect();
        assert_eq!(
            shown,
            vec![
                ("a/kind", "uninterpreted", true, true),
                ("b/kind", "uninterpreted", true, true),
            ]
        );
        assert!(extensions(None, &BundleOptions::default()).is_empty());
        assert!(extensions(Some(&json!("not-an-object")), &BundleOptions::default()).is_empty());
    }
}
