//! Strict Evidence Bundle verification (feature `strict`): the checks a
//! verifier needs before it tells a person that a Bundle is VALID. Port of
//! the Python reference's `verify_bundle(..., strict=True)`;
//! `vectors/bundle/strict/README.md` is the normative description.

use super::{as_bundle_int, is_b64url, is_str, parse_inclusion_proof, verify_bundle, ClaimResult};
use super::{VerificationResult, B64};
use crate::disclosure;
use crate::envelope::{self, INVALID, UNCLAIMED};
use crate::witness::{self, SignedCheckpoint, WitnessReceiptResult};
use base64::Engine as _;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};

/// `completeness.selection` of a producer-selected Bundle: records the
/// producer picked from its log, with no claim about the records between
/// them. Not defined by the Bundle draft; read only in strict mode.
pub const SELECTION_PRODUCER_SELECTED: &str = "producer-selected";

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

/// Options of [`verify_bundle_strict`].
#[derive(Debug, Clone, Copy, Default)]
pub struct StrictOptions<'a> {
    /// An unsigned record fails the `signatures` claim instead of leaving it
    /// `withheld`.
    pub require_signature: bool,
    /// The witness directory (a parsed `witnesses.json`, or its row list)
    /// whose keys the witness receipts are checked under. `None` trusts no
    /// witness.
    pub witness_directory: Option<&'a Value>,
}

/// One record of the Bundle's `records` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordResult {
    /// The carried `capsule_id`, or `""` when it is not a string.
    pub capsule_id: String,
    /// The plain verifier verified the record under its carried `capsule_id`.
    pub identity_ok: bool,
    /// [`envelope::AUTHORED`], [`envelope::UNCLAIMED`] or
    /// [`envelope::INVALID`] ([`envelope::verify_record_signature`]).
    pub signature: String,
    pub key_id: Option<String>,
    /// The record's log position, as its membership states it.
    pub seq: Option<i64>,
    /// Why the signature is invalid; not part of any contract.
    pub messages: Vec<String>,
}

/// The result of [`verify_bundle_strict`].
#[derive(Debug, Clone)]
pub struct StrictVerificationResult {
    /// The plain verifier's result ([`verify_bundle`]), unchanged.
    pub base: VerificationResult,
    /// The Bundle is a JSON object of kind `evidence-bundle/v2`, version
    /// `"2"`. When it is not, `records` is the only claim.
    pub kind_ok: bool,
    /// The gating claims, in report order: `records`, `signatures`,
    /// `graph_closure`, `checkpoint`, `interval_coverage`,
    /// `per_record_membership`, then `disclosures` when the Bundle carries
    /// one. `interval_coverage` and `per_record_membership` are the strict
    /// readings.
    pub claims: Vec<(&'static str, ClaimResult)>,
    /// The witness receipts. Never a claim: only a failing receipt gates.
    /// `None` when the Bundle is not an Evidence Bundle v2.
    pub witnesses: Option<ClaimResult>,
    pub witness_receipts: Vec<WitnessReceiptResult>,
    pub records: Vec<RecordResult>,
    /// The signed checkpoint's own fields, when the `checkpoint` claim
    /// passed.
    pub signed_checkpoint: Option<SignedCheckpoint>,
    /// Whether every record's `key_id` is the signed checkpoint's `key_id`,
    /// when the checkpoint is authenticated and there is a record. Reported,
    /// never gating.
    pub signer_matches_checkpoint: Option<bool>,
}

impl StrictVerificationResult {
    /// The named claim, if reported.
    pub fn claim(&self, name: &str) -> Option<&ClaimResult> {
        self.claims
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, claim)| claim)
    }

    /// Nothing failed (`withheld` is not a failure).
    pub fn ok(&self) -> bool {
        self.kind_ok
            && self.claims.iter().all(|(_, c)| c.status != "fail")
            && self.witnesses.as_ref().is_none_or(|w| w.status != "fail")
    }

    /// `VALID` (every claim passed), `INCOMPLETE` (nothing failed, something
    /// is not shown) or `INVALID`.
    pub fn verdict(&self) -> &'static str {
        if !self.ok() {
            "INVALID"
        } else if self.claims.iter().all(|(_, c)| c.status == "pass") {
            "VALID"
        } else {
            "INCOMPLETE"
        }
    }

    /// The `checkpoint` claim passed: the checkpoint is read from its signed
    /// COSE form and the JSON copy agrees with it.
    pub fn checkpoint_authenticated(&self) -> bool {
        self.signed_checkpoint.is_some()
    }
}

fn withheld(findings: Vec<String>) -> ClaimResult {
    ClaimResult {
        status: "withheld".to_string(),
        findings,
    }
}

fn not_v2(base: VerificationResult) -> StrictVerificationResult {
    StrictVerificationResult {
        base,
        kind_ok: false,
        claims: vec![(
            "records",
            ClaimResult::fail(vec!["not_an_evidence_bundle_v2".to_string()]),
        )],
        witnesses: None,
        witness_receipts: Vec::new(),
        records: Vec::new(),
        signed_checkpoint: None,
        signer_matches_checkpoint: None,
    }
}

/// Verifies an Evidence Bundle in strict mode: the plain verifier's results
/// ([`verify_bundle`]) plus each record's producer signature, the checkpoint
/// read only from its signed COSE form, producer-selected Bundles, the
/// `disclosures` overlay as one claim, the witness receipts in
/// `checkpoint.witnesses` under `options.witness_directory`, and a verdict.
///
/// `completeness.selection: "producer-selected"` and `checkpoint.witnesses`
/// are not defined by the Bundle draft; strict mode reads them as verifier
/// extensions. See `vectors/bundle/strict/README.md`.
pub fn verify_bundle_strict(value: &Value, options: &StrictOptions) -> StrictVerificationResult {
    let base = verify_bundle(value);
    let bundle = match value.as_object() {
        Some(b)
            if is_str(b.get("bundle_kind"), "evidence-bundle/v2")
                && is_str(b.get("bundle_version"), "2") =>
        {
            b
        }
        _ => return not_v2(base),
    };

    let raw_records: &[Value] = bundle
        .get("records")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice);
    let seqs = membership_seqs(bundle);
    let mut records = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for record in raw_records {
        let map = match record.as_object() {
            Some(m) => m,
            None => continue,
        };
        let cid = map
            .get("capsule_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let (verdict, messages) = envelope::verify_record_signature(record);
        // A repeated capsule_id is a second record the plain verifier
        // skipped: its identity does not hold.
        let first = seen.insert(cid.clone());
        let identity_ok = first
            && base
                .capsule_results
                .get(&cid)
                .is_some_and(|aac| aac.ok && aac.capsule_id.as_deref() == Some(cid.as_str()));
        records.push(RecordResult {
            seq: seqs.get(&cid).copied(),
            key_id: map.get("key_id").and_then(Value::as_str).map(String::from),
            capsule_id: cid,
            identity_ok,
            signature: verdict.to_string(),
            messages,
        });
    }

    let identity_findings: Vec<String> = if records.is_empty() {
        vec!["no_records".to_string()]
    } else {
        records
            .iter()
            .filter(|r| !r.identity_ok)
            .map(|r| format!("record_identity_invalid:{}", r.capsule_id))
            .collect()
    };
    let record_identity = ClaimResult {
        status: if !records.is_empty() && records.iter().all(|r| r.identity_ok) {
            "pass"
        } else {
            "fail"
        }
        .to_string(),
        findings: identity_findings,
    };

    let invalid = records.iter().filter(|r| r.signature == INVALID);
    let unclaimed: Vec<&RecordResult> = records
        .iter()
        .filter(|r| r.signature == UNCLAIMED)
        .collect();
    let signature_findings: Vec<String> = invalid
        .clone()
        .map(|r| format!("producer_signature_invalid:{}", r.capsule_id))
        .chain(
            unclaimed
                .iter()
                .map(|r| format!("producer_signature_unclaimed:{}", r.capsule_id)),
        )
        .collect();
    let signatures = if invalid.count() > 0
        || (!unclaimed.is_empty() && options.require_signature)
        || records.is_empty()
    {
        ClaimResult::fail(signature_findings)
    } else {
        ClaimResult {
            status: if unclaimed.is_empty() {
                "pass"
            } else {
                "withheld"
            }
            .to_string(),
            findings: signature_findings,
        }
    };

    let empty = Map::new();
    let stated = bundle
        .get("checkpoint")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let (checkpoint, signed) = strict_checkpoint(stated);

    let mut interval = base.interval_coverage.clone();
    let mut membership = base.per_record_membership.clone();
    if producer_selected(bundle) {
        // The certificate binds the producer's selection, not an interval:
        // the interval proof cannot be read, each record's own proof still can.
        interval = withheld(vec!["selection_not_checkable".to_string()]);
        membership = selected_membership(bundle, signed.as_ref().map(|(s, _)| s));
    }
    if signed.is_none() {
        interval = unanchored(interval);
        membership = unanchored(membership);
    }

    let mut claims = vec![
        ("records", record_identity),
        ("signatures", signatures),
        ("graph_closure", base.graph_closure.clone()),
        ("checkpoint", checkpoint),
        ("interval_coverage", interval),
        ("per_record_membership", membership),
    ];
    if bundle.contains_key("disclosures") {
        let failed: Vec<String> = base
            .disclosures
            .iter()
            .filter(|d| d.status != disclosure::MATCH && d.status != "withheld")
            .map(|d| format!("{}:{}:{}", d.status, d.capsule_id, d.member))
            .collect();
        claims.push((
            "disclosures",
            if failed.is_empty() {
                ClaimResult::pass()
            } else {
                ClaimResult::fail(failed)
            },
        ));
    }

    let report = witness::verify_witness_receipts(
        stated.get("witnesses"),
        signed.as_ref().map(|(s, _)| s),
        signed.as_ref().map(|(_, cose)| cose.as_slice()),
        options.witness_directory,
    );
    let signer_matches_checkpoint = match &signed {
        Some((s, _)) if !s.key_id.is_empty() && !records.is_empty() => Some(
            records
                .iter()
                .all(|r| r.key_id.as_deref() == Some(s.key_id.as_str())),
        ),
        _ => None,
    };

    StrictVerificationResult {
        base,
        kind_ok: true,
        claims,
        witnesses: Some(ClaimResult {
            status: report.status,
            findings: report.findings,
        }),
        witness_receipts: report.receipts,
        records,
        signed_checkpoint: signed.map(|(s, _)| s),
        signer_matches_checkpoint,
    }
}

/// JSON equality of a stated checkpoint field with its signed string value.
fn same_string(stated: &Value, signed: &str) -> bool {
    matches!(stated, Value::String(s) if s == signed)
}

/// JSON equality of a stated checkpoint field with its signed integer value:
/// a JSON integer (never a float or a boolean) of the same value.
fn same_integer(stated: &Value, signed: u64) -> bool {
    match stated {
        Value::Number(n) if !crate::canonical::is_float(n) => {
            n.to_string().parse::<i128>().ok() == Some(i128::from(signed))
        }
        _ => false,
    }
}

/// Verifies `checkpoint.cose` and holds the JSON copy to it. Returns the
/// claim and, when it passed, the signed fields and the COSE bytes.
fn strict_checkpoint(
    stated: &Map<String, Value>,
) -> (ClaimResult, Option<(SignedCheckpoint, Vec<u8>)>) {
    let fail = |finding: &str| (ClaimResult::fail(vec![finding.to_string()]), None);
    let encoded = match stated.get("cose") {
        None | Some(Value::Null) => {
            return (
                withheld(vec!["checkpoint_signature_absent".to_string()]),
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
        Some(decoded) if verified.ok => SignedCheckpoint::from(&decoded),
        _ => return fail("checkpoint_signature_invalid"),
    };
    let mut findings: Vec<String> = SIGNED_CHECKPOINT_FIELDS
        .iter()
        .filter(|name| {
            stated.get(**name).is_some_and(|value| match **name {
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

/// A proof claim with no signed checkpoint behind it: a failure stays a
/// failure; anything else is not shown.
fn unanchored(claim: ClaimResult) -> ClaimResult {
    if claim.status == "fail" {
        return claim;
    }
    let mut findings = claim.findings;
    if !findings.iter().any(|f| f == "checkpoint_unverified") {
        findings.push("checkpoint_unverified".to_string());
    }
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert(f.clone()));
    withheld(findings)
}

fn producer_selected(bundle: &Map<String, Value>) -> bool {
    bundle
        .get("completeness")
        .and_then(Value::as_object)
        .is_some_and(|c| is_str(c.get("selection"), SELECTION_PRODUCER_SELECTED))
}

fn memberships(bundle: &Map<String, Value>) -> Option<&Map<String, Value>> {
    bundle
        .get("completeness_certificate")
        .and_then(Value::as_object)?
        .get("memberships")
        .and_then(Value::as_object)
}

/// Each record's `seq` as its membership's `log_coordinates` state it.
fn membership_seqs(bundle: &Map<String, Value>) -> HashMap<String, i64> {
    let mut out = HashMap::new();
    if let Some(members) = memberships(bundle) {
        for (cid, member) in members {
            let seq = member
                .as_object()
                .and_then(|m| m.get("log_coordinates"))
                .and_then(Value::as_object)
                .and_then(|c| as_bundle_int(c.get("seq")));
            if let Some(seq) = seq {
                out.insert(cid.clone(), seq);
            }
        }
    }
    out
}

/// Each record's inclusion proof against the signed checkpoint's root and
/// size, for a producer-selected Bundle. With no signed checkpoint nothing is
/// shown.
fn selected_membership(
    bundle: &Map<String, Value>,
    signed: Option<&SignedCheckpoint>,
) -> ClaimResult {
    let signed = match signed {
        Some(s) => s,
        None => return withheld(vec!["checkpoint_unverified".to_string()]),
    };
    let invalid = || ClaimResult::fail(vec!["completeness_certificate_invalid".to_string()]);
    let certificate = match bundle
        .get("completeness_certificate")
        .and_then(Value::as_object)
    {
        Some(c) => c,
        None => return invalid(),
    };
    let members = match certificate.get("memberships").and_then(Value::as_object) {
        Some(m) if is_str(certificate.get("range_root"), &signed.root) => m,
        _ => return invalid(),
    };
    let root: [u8; 32] = match hex::decode(&signed.root)
        .ok()
        .and_then(|r| r.try_into().ok())
    {
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
                if is_str(coords.get("log_id"), &signed.log_id)
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
        let proof_ok = match (proof, leaf) {
            (Some(proof), Some(leaf)) => {
                proof.size == signed.mmr_size
                    && cll::mmr::verify_inclusion(
                        &root,
                        signed.mmr_size,
                        index as u64,
                        &leaf,
                        &proof,
                    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_non_object_bundle_is_invalid() {
        let result = verify_bundle_strict(&json!([1]), &StrictOptions::default());
        assert!(!result.kind_ok);
        assert_eq!(result.verdict(), "INVALID");
        assert_eq!(result.claims.len(), 1);
        assert_eq!(result.witnesses, None);
    }

    #[test]
    fn unanchored_keeps_a_failure_and_withholds_the_rest_once() {
        let failed = ClaimResult::fail(vec!["x".to_string()]);
        assert_eq!(unanchored(failed.clone()), failed);
        let passed = ClaimResult {
            status: "pass".to_string(),
            findings: vec!["checkpoint_unverified".to_string()],
        };
        assert_eq!(
            unanchored(passed),
            withheld(vec!["checkpoint_unverified".to_string()])
        );
        assert_eq!(
            unanchored(withheld(vec!["selection_not_checkable".to_string()])).findings,
            vec!["selection_not_checkable", "checkpoint_unverified"]
        );
    }

    #[test]
    fn stated_integers_keep_their_json_type() {
        assert!(same_integer(&json!(3), 3));
        assert!(!same_integer(&json!(3.0), 3));
        assert!(!same_integer(&json!(true), 1));
        assert!(!same_integer(&json!("3"), 3));
        assert!(!same_string(&json!(3), "3"));
    }
}
