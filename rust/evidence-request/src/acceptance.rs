//! Acceptance records, receipts and the acceptance finding of the interop
//! profile (`evidence-interop/0` §11.1).
//!
//! Given the contract version evaluated, the transaction, the two parties'
//! keys and every acceptance record, acceptance receipt and execution record
//! the verifier holds, [`evaluate`] reports the §11.1.7 properties of each
//! candidate and each receipt and the §11.1.8 finding. It is a port of the
//! profile's Python verifier (`agent_action_capsule.interop_profile.acceptance`)
//! and is checked against the same conformance vectors.
//!
//! Trust in a key is "as of evaluation" (§11.1.7): the caller's evaluation
//! time, never the clock. A record's own `issued_at` is the signer's claim
//! and never shows when it was signed (§11.1.5).
//!
//! Records and receipts are read as JSON, refusing duplicate member names and
//! any number outside 0 to 2^53 − 1 ([`parse`]), so that two parties compute
//! the same record digest from the same octets. A record that asserts
//! `authority` is labelled `agent_origin_assertion` (§11.1.6): no cited
//! authorization is checked. The optional acceptance of a key retired after
//! an earlier ordering point (§11.1.7, a MAY) is not implemented.
//!
//! How an execution record is read is the caller's: [`evaluate`] takes a
//! reader, and [`read_fixture_execution_record`] reads the format §11.5
//! fixes for the conformance vectors only. Choosing which execution records
//! belong to the exchange evaluated is the caller's too: pass only that
//! exchange's.
//!
//! The statuses, findings and claim fields are the result; each report's
//! `method` and `detail` texts are informative and are not compared with
//! another implementation's.
//!
//! One known difference from the Python verifier: this crate refuses a
//! record nested deeper than 128 levels, which the Python verifier reads up
//! to its recursion limit. The profile states no bound.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::jcs::{self, JcsError};
use crate::registry::is_digest;
use crate::status::Status;
use crate::time::{parse_rfc3339, UtcTime};

/// The profile identifier the records and receipts carry.
pub const PROFILE_ID: &str = "evidence-interop/0";

/// The §11.1.7 properties of a candidate, in report order.
pub const CANDIDATE_PROPERTIES: [&str; 8] = [
    "acceptance_form",
    "acceptance_signature",
    "acceptance_signer_trust",
    "acceptance_binding",
    "proposal_binding",
    "acceptance_unique",
    "execution_cites_acceptance",
    "acceptance_ordering",
];

const STATES: [&str; 4] = ["proposed", "accepted", "declined", "countered"];
const DECIDING: [&str; 5] = [
    "acceptance_form",
    "acceptance_signature",
    "acceptance_signer_trust",
    "acceptance_binding",
    "proposal_binding",
];
const MAX_INTEGER: u64 = (1 << 53) - 1;

/// The §11.1.8 finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Finding {
    // Declared in rank order: the best finding first (§11.1.8).
    AcceptedBeforeAction,
    AcceptedExecutionCites,
    AcceptedNotCited,
    NotAccepted,
    AcceptedAfterAction,
}

impl Finding {
    /// The finding as the profile writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            Finding::AcceptedBeforeAction => "accepted_before_action",
            Finding::AcceptedExecutionCites => "accepted_execution_cites",
            Finding::AcceptedNotCited => "accepted_not_cited",
            Finding::NotAccepted => "not_accepted",
            Finding::AcceptedAfterAction => "accepted_after_action",
        }
    }
}

/// One checked property: `{property, status, method}` and an optional
/// `detail` (§7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyReport {
    pub property: &'static str,
    pub status: Status,
    pub method: String,
    pub detail: Option<String>,
}

fn report(
    property: &'static str,
    status: Status,
    method: impl Into<String>,
    detail: Option<String>,
) -> PropertyReport {
    PropertyReport {
        property,
        status,
        method: method.into(),
        detail,
    }
}

/// The relying party's key-to-party map (§11.1.7), the part of its trust
/// policy this check reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustPolicy {
    /// Key (64 hex) to the party the relying party maps it to. A key absent
    /// from the map is not accepted.
    pub parties: BTreeMap<String, String>,
    /// Optional validity windows `(not_before, not_after)` by key: a key
    /// outside its window is not accepted at that instant.
    pub key_validity: BTreeMap<String, (Option<UtcTime>, Option<UtcTime>)>,
    /// §11.1.5 rule 3: the policy requires a time for the action from a
    /// party other than the acceptor.
    pub require_action_time_from_other_party: bool,
}

/// Why a `trust_policy` pin could not be read.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PinError {
    #[error("parties is not a map of key to party name")]
    Parties,
    #[error("key validity window is not RFC 3339")]
    KeyValidity,
    #[error("require_action_time_from_other_party is not a boolean")]
    RequireOtherParty,
}

impl TrustPolicy {
    /// The part of a `trust_policy` pin (the conformance vectors' form,
    /// §11.5) this check reads: `parties`, the optional `key_validity`
    /// (`{key: {not_before?, not_after?}}`) and
    /// `require_action_time_from_other_party`. Absent members are empty or
    /// false; other members are ignored.
    pub fn from_pin(pin: &Value) -> Result<TrustPolicy, PinError> {
        let mut policy = TrustPolicy::default();
        if let Some(parties) = pin.get("parties") {
            for (key, party) in parties.as_object().ok_or(PinError::Parties)? {
                let party = party.as_str().ok_or(PinError::Parties)?;
                policy.parties.insert(key.clone(), party.to_string());
            }
        }
        if let Some(windows) = pin.get("key_validity") {
            for (key, window) in windows.as_object().ok_or(PinError::KeyValidity)? {
                let window = window.as_object().ok_or(PinError::KeyValidity)?;
                // An absent or null end is unbounded, as in the Python verifier.
                let at = |name: &str| match window.get(name) {
                    None | Some(Value::Null) => Ok(None),
                    Some(t) => t
                        .as_str()
                        .and_then(parse_rfc3339)
                        .map(Some)
                        .ok_or(PinError::KeyValidity),
                };
                policy
                    .key_validity
                    .insert(key.clone(), (at("not_before")?, at("not_after")?));
            }
        }
        if let Some(flag) = pin.get("require_action_time_from_other_party") {
            policy.require_action_time_from_other_party =
                flag.as_bool().ok_or(PinError::RequireOtherParty)?;
        }
        Ok(policy)
    }

    fn valid_at(&self, key: &str, at: &str) -> Status {
        let Some((not_before, not_after)) = self.key_validity.get(key) else {
            return Status::Pass;
        };
        let Some(moment) = parse_rfc3339(at) else {
            return Status::Inconclusive;
        };
        if not_before.is_some_and(|nb| moment < nb) || not_after.is_some_and(|na| moment > na) {
            return Status::Fail;
        }
        Status::Pass
    }

    /// The status of trusting `key` at `at`, and the party it maps to when
    /// trusted.
    pub fn party_of(&self, key: Option<&str>, at: &str) -> (Status, Option<&str>) {
        let Some((key, party)) = key.and_then(|k| self.parties.get_key_value(k)) else {
            return (Status::Fail, None);
        };
        let status = self.valid_at(key, at);
        (status, (status == Status::Pass).then_some(party.as_str()))
    }

    /// §11.1.7 "accepts a key as the proposer/acceptor": the policy trusts
    /// `key`, maps it to a party, and that party is not the one it maps
    /// `counterpart` to.
    pub fn accepts_in_role(
        &self,
        key: Option<&str>,
        counterpart: Option<&str>,
        at: &str,
    ) -> Status {
        let (status, party) = self.party_of(key, at);
        if status != Status::Pass {
            return status;
        }
        let other = counterpart
            .and_then(|c| self.parties.get(c))
            .map(String::as_str);
        if party == other {
            Status::Fail
        } else {
            Status::Pass
        }
    }
}

/// What the verifier reads from one execution record: its verified issuer
/// (`None` when its signature does not verify), the time it claims for the
/// action, the digests it cites, the transaction it names, and the method
/// used to read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionRecord {
    pub issuer: Option<String>,
    pub action_at: Option<String>,
    pub cites: BTreeSet<String>,
    pub transaction: Option<Value>,
    pub method: String,
}

/// The execution record format §11.5 fixes for the conformance vectors only
/// (not registered): `action_at`, `issuer`, `links` (EL link shape, type
/// `cites`), `transaction`, `sig`; `sig` is Ed25519 by `issuer` over UTF-8
/// of JCS of the other members.
pub fn read_fixture_execution_record(octets: &[u8]) -> Option<ExecutionRecord> {
    let Value::Object(rec) = parse(octets)? else {
        return None;
    };
    let verified = verifies(text(&rec, "issuer"), text(&rec, "sig"), &rec);
    let cites = match rec.get("links") {
        Some(Value::Array(links)) => links
            .iter()
            .filter_map(|link| {
                let link = link.as_object()?;
                let target = link.get("target")?.as_str()?;
                (link.get("type") == Some(&Value::from("cites")) && is_digest(target))
                    .then(|| target.to_string())
            })
            .collect(),
        _ => BTreeSet::new(),
    };
    Some(ExecutionRecord {
        issuer: if verified {
            text(&rec, "issuer").map(String::from)
        } else {
            None
        },
        action_at: text(&rec, "action_at").map(String::from),
        cites,
        transaction: rec.get("transaction").cloned(),
        method: "§11.5 fixture execution record: Ed25519 over JCS; EL cites link".into(),
    })
}

/// The properties of one held receipt for a candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptResult {
    pub receipt_digest: String,
    pub acceptance_digest: String,
    pub properties: Vec<PropertyReport>,
}

impl ReceiptResult {
    /// The status reported for `property`, if reported.
    pub fn status(&self, property: &str) -> Option<Status> {
        status_of(&self.properties, property)
    }
}

/// One candidate acceptance and its properties.
#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    pub record_digest: String,
    pub record: Map<String, Value>,
    pub properties: Vec<PropertyReport>,
    pub finding: Finding,
    /// The receipts the finding relies on, by digest (`accepted_before_action`).
    pub relied_receipts: Vec<String>,
}

impl Candidate {
    /// The status reported for `property`, if reported.
    pub fn status(&self, property: &str) -> Option<Status> {
        status_of(&self.properties, property)
    }
}

/// The result for one contract version and one transaction.
#[derive(Clone, Debug, PartialEq)]
pub struct AcceptanceResult {
    pub finding: Finding,
    pub candidates: Vec<Candidate>,
    pub receipts: Vec<ReceiptResult>,
    /// Where the finding is not `not_accepted`: the accepted record's
    /// `contract_ref`, which each claim carries (§11.1.8).
    pub contract_ref: Option<String>,
    /// Where the finding is not `not_accepted`: the digests each claim's
    /// `evidence[]` lists, the accepted record and every receipt relied on.
    pub evidence: Vec<String>,
    /// How many held items could not be read at all.
    pub unreadable: usize,
}

/// Why [`evaluate`] evaluated nothing.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AcceptanceError {
    #[error("evaluation_time must be an RFC 3339 time; the verifier never reads the clock")]
    EvaluationTime,
    #[error("the contract carries a value JCS cannot represent, or a number outside 0 to 2^53 - 1; no contract_digest (§11.3.7)")]
    ContractDigest,
    #[error("two requirements share one id; the contract version is not evaluated (§11.3.7)")]
    DuplicateRequirement,
    #[error(
        "the contract's id or version is not text, or its requirements are not an array (§11.3.7)"
    )]
    ContractForm,
}

/// What [`evaluate`] is given.
pub struct Inputs<'a> {
    /// The contract version evaluated, as a JSON value.
    pub contract: &'a Value,
    /// The transaction, or with `session` the session, the candidates name.
    pub transaction: &'a Value,
    pub proposer: &'a str,
    pub acceptor: &'a str,
    /// Acceptance records, as held octets.
    pub records: &'a [&'a [u8]],
    /// Execution records, as held octets, read by the reader passed to
    /// [`evaluate`].
    pub execution_records: &'a [&'a [u8]],
    /// Acceptance receipts, as held octets.
    pub receipts: &'a [&'a [u8]],
    pub trust: &'a TrustPolicy,
    /// RFC 3339; trust is decided as of this time.
    pub evaluation_time: &'a str,
    /// The candidates are session acceptances whose window covers every
    /// time held for the exchange (§11.1.3, §11.1.8).
    pub session: bool,
    /// How many form (ii) objects are held (§11.1.5). No mechanism is named
    /// for them, so they are never checked (`NOT_CHECKED`).
    pub form_ii_objects: usize,
    /// The profiles the verifier implements.
    pub profiles_implemented: &'a [&'a str],
}

/// The §11.1.8 finding for one contract version and one transaction.
pub fn evaluate(
    inputs: &Inputs<'_>,
    read_execution_record: impl Fn(&[u8]) -> Option<ExecutionRecord>,
) -> Result<AcceptanceResult, AcceptanceError> {
    let eval = inputs.evaluation_time;
    if parse_rfc3339(eval).is_none() {
        return Err(AcceptanceError::EvaluationTime);
    }
    let contract_digest = (numbers_in_domain(inputs.contract, 0))
        .then(|| value_digest(inputs.contract).ok())
        .flatten()
        .ok_or(AcceptanceError::ContractDigest)?;
    let contract_ref = contract_ref_of(inputs.contract).ok_or(AcceptanceError::ContractForm)?;
    let ids: Vec<String> = match inputs.contract.get("requirements") {
        Some(Value::Array(reqs)) => reqs
            .iter()
            .map(|q| value_digest(q.get("id").unwrap_or(&Value::Null)).unwrap_or_default())
            .collect(),
        None => Vec::new(),
        Some(_) => return Err(AcceptanceError::ContractForm),
    };
    if ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err(AcceptanceError::DuplicateRequirement);
    }
    let implemented = inputs.profiles_implemented.contains(&PROFILE_ID);
    let trust = inputs.trust;
    let session = inputs.session;

    // By record digest: two copies of one record are one record.
    let mut held: Vec<(String, Map<String, Value>)> = Vec::new();
    let mut unreadable = 0;
    for octets in inputs.records {
        match parse_object(octets) {
            Some((digest, record)) => {
                if !held.iter().any(|(d, _)| *d == digest) {
                    held.push((digest, record));
                }
            }
            None => unreadable += 1,
        }
    }
    let mut receipt_objs: Vec<(String, Map<String, Value>)> = Vec::new();
    for octets in inputs.receipts {
        match parse_object(octets) {
            Some(pair) => receipt_objs.push(pair),
            None => unreadable += 1,
        }
    }
    let mut execs = Vec::new();
    for octets in inputs.execution_records {
        match read_execution_record(octets) {
            Some(e) => execs.push(e),
            None => unreadable += 1,
        }
    }
    let sig_ok = |r: &Map<String, Value>| verifies(signer(r), text(r, "sig"), r);
    let role_trust = |r: &Map<String, Value>| {
        let counterpart = if text(r, "state") == Some("proposed") {
            text(r, "acceptor")
        } else {
            text(r, "proposer")
        };
        trust.accepts_in_role(signer(r), counterpart, eval)
    };

    // Sort what is held (§11.1.5, §11.1.7). A record whose signature
    // verifies under the acceptor key, or under a key the trust policy maps
    // to the acceptor's party, is the acceptor's own execution record. One
    // verified under a trusted key of another party is that party's
    // attestation of the action: a time for it, never an execution record.
    // Anything else is held as an execution record not attributed to the
    // acceptor.
    let acceptor_party = trust.parties.get(inputs.acceptor).map(String::as_str);
    let party_now = |key: Option<&str>| match trust.party_of(key, eval) {
        (Status::Pass, party) => party,
        _ => None,
    };
    // `party_now(key) == acceptor_party` holds when both are absent, as in
    // the reference verifier.
    let attributed = |key: &str| key == inputs.acceptor || party_now(Some(key)) == acceptor_party;
    let mut own_records: Vec<&ExecutionRecord> = Vec::new();
    let mut attestations: Vec<&ExecutionRecord> = Vec::new();
    for e in &execs {
        let party = e.issuer.as_deref().and_then(|k| party_now(Some(k)));
        if e.issuer.as_deref() == Some(inputs.acceptor)
            || (party.is_some() && party == acceptor_party)
        {
            own_records.push(e);
        } else if party.is_some() {
            attestations.push(e);
        } else {
            own_records.push(e);
        }
    }
    let times = |records: &[&ExecutionRecord]| -> Vec<UtcTime> {
        records
            .iter()
            .filter(|e| e.issuer.is_some())
            .filter(|e| session || e.transaction.as_ref() == Some(inputs.transaction))
            .filter_map(|e| e.action_at.as_deref().and_then(parse_rfc3339))
            .map(floor_seconds)
            .collect()
    };
    let own_verified: Vec<&ExecutionRecord> = own_records
        .iter()
        .copied()
        .filter(|e| e.issuer.as_deref().is_some_and(attributed))
        .collect();
    let other_times = times(&attestations);
    let mut action_times = times(&own_verified);
    action_times.extend(other_times.iter().copied());
    let all_action_at: Vec<Option<&str>> = own_records
        .iter()
        .chain(&attestations)
        .map(|e| e.action_at.as_deref())
        .collect();

    let mut candidates: Vec<Candidate> = Vec::new();
    let mut out_receipts: Vec<ReceiptResult> = Vec::new();
    for (digest, r) in &held {
        if !(text(r, "state") == Some("accepted")
            && text(r, "contract_digest") == Some(contract_digest.as_str())
            && text(r, "proposer") == Some(inputs.proposer)
            && text(r, "acceptor") == Some(inputs.acceptor)
            && r.get("transaction") == Some(inputs.transaction)
            && r.contains_key("session") == session)
        {
            continue;
        }
        if session && !in_window(r, &all_action_at) {
            continue;
        }
        let mut cand = Candidate {
            record_digest: digest.clone(),
            record: r.clone(),
            properties: Vec::new(),
            finding: Finding::NotAccepted,
            relied_receipts: Vec::new(),
        };
        if text(r, "profile") != Some(PROFILE_ID) || !implemented {
            let detail = format!("profile {} is not implemented", repr(r.get("profile")));
            cand.properties = CANDIDATE_PROPERTIES
                .iter()
                .map(|p| {
                    report(
                        p,
                        Status::NotChecked,
                        "not run (§11.1.7, §3.3 step 5)",
                        Some(detail.clone()),
                    )
                })
                .collect();
            candidates.push(cand);
            continue;
        }
        let mut p: BTreeMap<&'static str, PropertyReport> = BTreeMap::new();
        let problems = form_problems(r);
        p.insert(
            "acceptance_form",
            report(
                "acceptance_form",
                pass_if(problems.is_empty()),
                "§11.1.2 members and forms",
                (!problems.is_empty()).then(|| problems.join("; ")),
            ),
        );
        p.insert(
            "acceptance_signature",
            report(
                "acceptance_signature",
                pass_if(sig_ok(r)),
                "Ed25519 by the key the state names, over JCS of every member but sig (§11.1.2)",
                None,
            ),
        );
        p.insert(
            "acceptance_signer_trust",
            report(
                "acceptance_signer_trust",
                role_trust(r),
                format!("trust policy, as the acceptor, as of {eval}"),
                None,
            ),
        );
        let binding_ok = text(r, "contract_digest") == Some(contract_digest.as_str())
            && text(r, "contract_ref") == Some(contract_ref.as_str());
        p.insert(
            "acceptance_binding",
            report(
                "acceptance_binding",
                pass_if(binding_ok),
                "contract_digest against the contract evaluated; contract_ref against its id@version (§11.1.2)",
                // §11.1.6: no cited authorization is checked here, so asserted
                // authority is labelled as the agent's own assertion.
                r.contains_key("authority")
                    .then(|| "agent_origin_assertion".to_string()),
            ),
        );
        p.insert(
            "proposal_binding",
            proposal_binding(r, &held, &sig_ok, &role_trust),
        );
        // Answers are held by record digest, so each is a distinct answer:
        // two of them is the equivocation of §11.1.1.
        let answers = held
            .iter()
            .filter(|(_, a)| {
                matches!(
                    text(a, "state"),
                    Some("accepted" | "declined" | "countered")
                ) && a.get("proposal_digest") == r.get("proposal_digest")
                    && a.get("acceptor") == r.get("acceptor")
                    && sig_ok(a)
                    && role_trust(a) == Status::Pass
            })
            .count();
        let method = "one record digest among verified answers to one proposal (§11.1.1)";
        p.insert(
            "acceptance_unique",
            if answers < 2 {
                report(
                    "acceptance_unique",
                    Status::NotChecked,
                    method,
                    Some("fewer than two verified answers are held".into()),
                )
            } else {
                report(
                    "acceptance_unique",
                    Status::Fail,
                    method,
                    Some(format!("{answers} different answers to one proposal")),
                )
            },
        );
        p.insert(
            "execution_cites_acceptance",
            execution_cites(r, digest, &own_records, session, &attributed),
        );
        // Receipts for this record (§11.1.4) and the ordering (§11.1.5).
        let mut rps: Vec<(&Map<String, Value>, ReceiptResult)> = Vec::new();
        for (rdigest, rc) in &receipt_objs {
            if text(rc, "acceptance_digest") != Some(digest.as_str()) {
                continue;
            }
            let rr = ReceiptResult {
                receipt_digest: rdigest.clone(),
                acceptance_digest: digest.clone(),
                properties: receipt_properties(rc, r, trust, eval, implemented),
            };
            out_receipts.push(rr.clone());
            rps.push((rc, rr));
        }
        let (order, relied) = ordering(
            r,
            &rps,
            &action_times,
            &other_times,
            trust,
            inputs.form_ii_objects,
        );
        let order_status = order.status;
        p.insert("acceptance_ordering", order);
        let status = |name: &str| p.get(name).map(|r| r.status);
        cand.finding = if DECIDING.iter().any(|k| status(k) != Some(Status::Pass))
            || status("acceptance_unique") == Some(Status::Fail)
        {
            Finding::NotAccepted
        } else if order_status == Status::Fail {
            Finding::AcceptedAfterAction
        } else if status("execution_cites_acceptance") != Some(Status::Pass) {
            Finding::AcceptedNotCited
        } else if order_status == Status::Pass {
            cand.relied_receipts = relied;
            Finding::AcceptedBeforeAction
        } else {
            Finding::AcceptedExecutionCites
        };
        cand.properties = CANDIDATE_PROPERTIES
            .iter()
            .filter_map(|k| p.remove(k))
            .collect();
        candidates.push(cand);
    }

    let finding = if candidates.is_empty()
        || candidates
            .iter()
            .any(|c| c.status("acceptance_unique") == Some(Status::Fail))
    {
        Finding::NotAccepted
    } else if candidates
        .iter()
        .any(|c| c.finding == Finding::AcceptedAfterAction)
    {
        Finding::AcceptedAfterAction
    } else {
        candidates
            .iter()
            .map(|c| c.finding)
            .min()
            .unwrap_or(Finding::NotAccepted)
    };
    let mut result = AcceptanceResult {
        finding,
        candidates,
        receipts: out_receipts,
        contract_ref: None,
        evidence: Vec::new(),
        unreadable,
    };
    if finding != Finding::NotAccepted {
        if let Some(best) = result.candidates.iter().find(|c| c.finding == finding) {
            result.contract_ref = text(&best.record, "contract_ref").map(String::from);
            result.evidence = std::iter::once(best.record_digest.clone())
                .chain(best.relied_receipts.iter().cloned())
                .collect();
        }
    }
    Ok(result)
}

fn proposal_binding(
    r: &Map<String, Value>,
    held: &[(String, Map<String, Value>)],
    sig_ok: &dyn Fn(&Map<String, Value>) -> bool,
    role_trust: &dyn Fn(&Map<String, Value>) -> Status,
) -> PropertyReport {
    let method =
        "the proposed record answered: signature, proposer trust, and the §11.1.2 equality rule";
    let prop = text(r, "proposal_digest")
        .filter(|d| is_digest(d))
        .and_then(|d| held.iter().find(|(h, _)| h == d).map(|(_, r)| r));
    let Some(prop) = prop else {
        return report(
            "proposal_binding",
            Status::NotPresent,
            method,
            Some("the proposed record is not held".into()),
        );
    };
    let mut problems: Vec<String> = Vec::new();
    if text(prop, "state") != Some("proposed") {
        problems.push("the record named is not a proposed record".into());
    }
    if !sig_ok(prop) {
        problems.push("its signature does not verify".into());
    }
    let trust_status = role_trust(prop);
    const UNTRUSTED: &str = "the policy does not accept its signer as the proposer";
    if trust_status != Status::Pass {
        problems.push(UNTRUSTED.into());
    }
    for k in [
        "contract_ref",
        "contract_digest",
        "transaction",
        "proposer",
        "acceptor",
        "session",
    ] {
        if prop.get(k) != r.get(k) {
            problems.push(format!("{k} differs from the proposal"));
        }
    }
    if problems.is_empty() {
        return report("proposal_binding", Status::Pass, method, None);
    }
    let status = if problems == [UNTRUSTED] && trust_status == Status::Inconclusive {
        Status::Inconclusive
    } else {
        Status::Fail
    };
    report(
        "proposal_binding",
        status,
        method,
        Some(problems.join("; ")),
    )
}

fn execution_cites(
    r: &Map<String, Value>,
    digest: &str,
    execs: &[&ExecutionRecord],
    session: bool,
    attributed: &dyn Fn(&str) -> bool,
) -> PropertyReport {
    let mut method = format!(
        "each execution record: verified under the acceptor key or a key the policy maps to its party, \
         an EL cites link to the record digest, {}",
        if session {
            "within the session window"
        } else {
            "naming the record's transaction"
        }
    );
    let Some(first) = execs.first() else {
        return report(
            "execution_cites_acceptance",
            Status::NotPresent,
            method,
            Some("no execution record is held".into()),
        );
    };
    let mut problems: Vec<&str> = Vec::new();
    for e in execs {
        if !e.issuer.as_deref().is_some_and(attributed) {
            problems.push("an execution record is not attributed to the acceptor");
        } else if !e.cites.contains(digest) {
            problems.push("an execution record does not cite the accepted record");
        } else if !session && e.transaction.as_ref() != r.get("transaction") {
            problems.push("an execution record names another transaction");
        } else if session && !in_window(r, &[e.action_at.as_deref()]) {
            problems.push("an execution record lies outside the session window");
        }
    }
    method = format!("{method}; read by {}", first.method);
    report(
        "execution_cites_acceptance",
        pass_if(problems.is_empty()),
        method,
        (!problems.is_empty()).then(|| problems.join("; ")),
    )
}

fn receipt_properties(
    rc: &Map<String, Value>,
    record: &Map<String, Value>,
    trust: &TrustPolicy,
    eval: &str,
    implemented: bool,
) -> Vec<PropertyReport> {
    if text(rc, "profile") != Some(PROFILE_ID) || !implemented {
        let detail = format!("profile {} is not implemented", repr(rc.get("profile")));
        return ["receipt_signature", "receipt_signer"]
            .into_iter()
            .map(|p| {
                report(
                    p,
                    Status::NotChecked,
                    "not run (§11.1.7)",
                    Some(detail.clone()),
                )
            })
            .collect();
    }
    let members_ok = rc.len() == 5
        && [
            "profile",
            "acceptance_digest",
            "received_at",
            "receiver",
            "sig",
        ]
        .iter()
        .all(|k| rc.contains_key(*k));
    let sig = members_ok && verifies(text(rc, "receiver"), text(rc, "sig"), rc);
    let receiver = text(rc, "receiver");
    let signer_status = if receiver.is_none()
        || receiver != text(record, "proposer")
        || receiver == text(record, "acceptor")
    {
        Status::Fail
    } else {
        trust.accepts_in_role(receiver, text(record, "acceptor"), eval)
    };
    vec![
        report(
            "receipt_signature",
            pass_if(sig),
            "Ed25519 by receiver over JCS of the other four members (§11.1.4)",
            (!members_ok).then(|| "members are not exactly those of §11.1.4".into()),
        ),
        report(
            "receipt_signer",
            signer_status,
            format!(
                "receiver is the proposer, not the acceptor, and accepted as the proposer as of {eval} (§11.1.7)"
            ),
            None,
        ),
    ]
}

/// `acceptance_ordering` (§11.1.5): the first rule that applies decides.
fn ordering(
    r: &Map<String, Value>,
    rps: &[(&Map<String, Value>, ReceiptResult)],
    action_times: &[UtcTime],
    other_times: &[UtcTime],
    trust: &TrustPolicy,
    form_ii: usize,
) -> (PropertyReport, Vec<String>) {
    let method = "§11.1.5: form (i) receipts against the earliest time held for the action";
    let order = |status, detail: &str| {
        report(
            "acceptance_ordering",
            status,
            method,
            Some(detail.to_string()),
        )
    };
    let Some(reference) = action_times.iter().min().copied() else {
        return (
            order(Status::NotPresent, "rule 1: no time for the action"),
            Vec::new(),
        );
    };
    if let Some(issued) = text(r, "issued_at").and_then(parse_rfc3339) {
        if action_times.iter().any(|t| issued >= *t) {
            return (
                order(
                    Status::Fail,
                    "rule 2: the record's own issued_at is not earlier than a time held for the action",
                ),
                Vec::new(),
            );
        }
    }
    if trust.require_action_time_from_other_party && other_times.is_empty() {
        return (
            order(
                Status::NotPresent,
                "rule 3: the policy requires a time for the action from another party; none held",
            ),
            Vec::new(),
        );
    }
    let mut counted: Vec<(UtcTime, &str)> = Vec::new();
    let mut unresolved = false;
    for (rc, rr) in rps {
        let statuses = (rr.status("receipt_signature"), rr.status("receipt_signer"));
        let point = text(rc, "received_at").and_then(parse_rfc3339);
        match (statuses, point) {
            ((Some(Status::Pass), Some(Status::Pass)), Some(point)) => {
                // An ordering point rounds up.
                counted.push((ceil_seconds(point), rr.receipt_digest.as_str()));
            }
            ((Some(Status::Pass), Some(Status::Inconclusive)), _) => unresolved = true,
            _ => {}
        }
    }
    let earlier: Vec<String> = counted
        .iter()
        .filter(|(point, _)| *point < reference)
        .map(|(_, d)| d.to_string())
        .collect();
    if !earlier.is_empty() {
        return (
            order(
                Status::Pass,
                "rule 4: a counterparty receipt is earlier than the action reference point",
            ),
            earlier,
        );
    }
    if !counted.is_empty() || unresolved {
        let why = if !counted.is_empty() {
            "rule 5: no counted receipt is earlier than the action"
        } else {
            "rule 5: a receipt signer is unresolved"
        };
        return (order(Status::Inconclusive, why), Vec::new());
    }
    if form_ii > 0 {
        return (
            order(
                Status::NotChecked,
                "rule 6: only form (ii) objects are held, and no mechanism is implemented (P-13)",
            ),
            Vec::new(),
        );
    }
    (
        order(Status::NotPresent, "rule 7: no ordering evidence counts"),
        Vec::new(),
    )
}

/// §11.1.2 and §11.1.3, as `acceptance_form` checks them.
fn form_problems(r: &Map<String, Value>) -> Vec<&'static str> {
    let mut out = Vec::new();
    let state = text(r, "state");
    let digest_at = |k: &str| text(r, k).is_some_and(is_digest);
    if text(r, "profile") != Some(PROFILE_ID) {
        out.push("profile is not evidence-interop/0");
    }
    if !state.is_some_and(|s| STATES.contains(&s)) {
        out.push("state is not one of the four tokens, exact case");
    }
    if text(r, "contract_ref").is_none() {
        out.push("contract_ref is not text");
    }
    if !digest_at("contract_digest") {
        out.push("contract_digest is not a digest");
    }
    if !digest_at("proposer") {
        out.push("proposer is not a key identifier");
    }
    if !digest_at("acceptor") {
        out.push("acceptor is not a key identifier");
    }
    let transaction_ok = match r.get("transaction") {
        Some(Value::Object(t)) => {
            t.len() == 2
                && t.contains_key("scheme")
                && t.contains_key("id")
                && t.values().all(Value::is_string)
        }
        _ => false,
    };
    if !transaction_ok {
        out.push("transaction is not {scheme, id} of text");
    }
    if !text(r, "issued_at").is_some_and(is_profile_time) {
        out.push("issued_at is not in the §5.2 form");
    }
    if !text(r, "sig").is_some_and(is_signature) {
        out.push("sig is not an Ed25519 signature");
    }
    if state == Some("proposed") && r.contains_key("proposal_digest") {
        out.push("proposal_digest is present in a proposed record");
    }
    if matches!(state, Some("accepted" | "declined" | "countered")) && !digest_at("proposal_digest")
    {
        out.push("proposal_digest is absent or not a digest");
    }
    if state == Some("countered") && !digest_at("counter_contract_digest") {
        out.push("counter_contract_digest is absent or not a digest");
    }
    if state != Some("countered") && r.contains_key("counter_contract_digest") {
        out.push("counter_contract_digest is present outside countered");
    }
    if let Some(s) = r.get("session") {
        let ok = match s {
            Value::Object(s) => {
                let window = |k: &str| {
                    s.get(k)
                        .and_then(Value::as_str)
                        .filter(|t| is_profile_time(t))
                };
                s.keys()
                    .all(|k| matches!(k.as_str(), "not_before" | "not_after" | "policy" | "terms"))
                    && match (window("not_before"), window("not_after")) {
                        (Some(nb), Some(na)) => na >= nb,
                        _ => false,
                    }
                    && ["policy", "terms"]
                        .iter()
                        .all(|k| s.get(*k).is_none_or(|v| v.as_str().is_some_and(is_digest)))
            }
            _ => false,
        };
        if !ok {
            out.push("session is not a valid window (§11.1.3)");
        }
    }
    if let Some(a) = r.get("authority") {
        let ok = matches!(a, Value::Array(items) if items.iter().all(|i| i.as_str().is_some_and(is_digest)));
        if !ok {
            out.push("authority is not an array of digests");
        }
    }
    out
}

/// Every time held lies in the record's session window. A time that is not
/// RFC 3339 is skipped; a record with no window covers nothing.
fn in_window(r: &Map<String, Value>, times: &[Option<&str>]) -> bool {
    let Some(Value::Object(s)) = r.get("session") else {
        return false;
    };
    let bound = |k: &str| s.get(k).and_then(Value::as_str).and_then(parse_rfc3339);
    times
        .iter()
        .filter_map(|t| t.and_then(parse_rfc3339))
        .all(|t| match (bound("not_before"), bound("not_after")) {
            (Some(nb), Some(na)) => nb <= t && t <= na,
            _ => false,
        })
}

fn signer(r: &Map<String, Value>) -> Option<&str> {
    if text(r, "state") == Some("proposed") {
        text(r, "proposer")
    } else {
        text(r, "acceptor")
    }
}

/// Ed25519 by `key` over UTF-8 of JCS of every member of `record` but
/// `sig`, both in the §5.2 hex forms.
fn verifies(key: Option<&str>, sig: Option<&str>, record: &Map<String, Value>) -> bool {
    let (Some(key), Some(sig)) = (key, sig) else {
        return false;
    };
    if !is_digest(key) || !is_signature(sig) {
        return false;
    }
    let (Ok(key), Ok(sig)) = (hex::decode(key), hex::decode(sig)) else {
        return false;
    };
    let (Ok(key), Ok(sig)) = (<[u8; 32]>::try_from(key), <[u8; 64]>::try_from(sig)) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key) else {
        return false;
    };
    let Ok(body) = signing_input(record) else {
        return false;
    };
    key.verify_strict(body.as_bytes(), &Signature::from_bytes(&sig))
        .is_ok()
}

/// The signing input of a record or receipt (§11.1.2, §11.1.4): JCS of
/// every member but `sig`.
pub fn signing_input(record: &Map<String, Value>) -> Result<String, JcsError> {
    let unsigned: Map<String, Value> = record
        .iter()
        .filter(|(k, _)| k.as_str() != "sig")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    jcs::to_string(&Value::Object(unsigned))
}

/// Sign a record or a receipt: `unsigned` holds every member but `sig`, and
/// `key` is the signer its state names (the proposer for `proposed`, the
/// acceptor for an answer, the receiver for a receipt). Returns the record
/// with `sig` added.
pub fn sign(
    mut unsigned: Map<String, Value>,
    key: &SigningKey,
) -> Result<Map<String, Value>, JcsError> {
    unsigned.remove("sig");
    let body = signing_input(&unsigned)?;
    let sig = key.sign(body.as_bytes());
    unsigned.insert("sig".into(), Value::from(hex::encode(sig.to_bytes())));
    Ok(unsigned)
}

/// The record digest (§11.1.2): SHA-256 over UTF-8 of JCS of the whole
/// record, `sig` included, as 64 lowercase hex.
pub fn record_digest(record: &Value) -> Result<String, JcsError> {
    value_digest(record)
}

/// Read JSON octets in the profile's data model (§5.2): `None` when they
/// are not JSON, hold a duplicate member name or an unpaired surrogate
/// escape, nest deeper than 128, or hold a number that is not an integer
/// from 0 to 2^53 − 1 written as digits alone. Both parties read records
/// this way, so the same octets give the same record digest.
pub fn parse(octets: &[u8]) -> Option<Value> {
    crate::strict_json::decode(octets)
}

fn parse_object(octets: &[u8]) -> Option<(String, Map<String, Value>)> {
    let value = parse(octets)?;
    let digest = value_digest(&value).ok()?;
    match value {
        Value::Object(map) => Some((digest, map)),
        _ => None,
    }
}

fn value_digest(value: &Value) -> Result<String, JcsError> {
    Ok(hex::encode(Sha256::digest(
        jcs::to_string(value)?.as_bytes(),
    )))
}

fn numbers_in_domain(value: &Value, depth: usize) -> bool {
    if depth > 64 {
        return false;
    }
    match value {
        Value::Number(n) => n.as_u64().is_some_and(|u| u <= MAX_INTEGER),
        Value::Array(items) => items.iter().all(|v| numbers_in_domain(v, depth + 1)),
        Value::Object(map) => map.values().all(|v| numbers_in_domain(v, depth + 1)),
        _ => true,
    }
}

/// `id`, `@`, `version`, built from the contract held (§11.3.7); never
/// split. `None` when either is not text.
fn contract_ref_of(contract: &Value) -> Option<String> {
    let part = |k: &str| contract.get(k).and_then(Value::as_str);
    Some(format!("{}@{}", part("id")?, part("version")?))
}

/// The §5.2 time form, `YYYY-MM-DDTHH:MM:SSZ`, naming a real instant.
fn is_profile_time(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 20
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            13 | 16 => *c == b':',
            19 => *c == b'Z',
            _ => c.is_ascii_digit(),
        })
        && parse_rfc3339(s).is_some()
}

fn is_signature(s: &str) -> bool {
    s.len() == 128
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn text<'a>(r: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    r.get(key).and_then(Value::as_str)
}

fn pass_if(ok: bool) -> Status {
    if ok {
        Status::Pass
    } else {
        Status::Fail
    }
}

/// A held value as JSON text, for a detail; `absent` when there is none.
fn repr(v: Option<&Value>) -> String {
    v.map_or_else(|| "absent".to_string(), Value::to_string)
}

fn status_of(properties: &[PropertyReport], property: &str) -> Option<Status> {
    properties
        .iter()
        .find(|r| r.property == property)
        .map(|r| r.status)
}

fn floor_seconds(t: UtcTime) -> UtcTime {
    UtcTime {
        seconds: t.seconds,
        nanos: 0,
    }
}

fn ceil_seconds(t: UtcTime) -> UtcTime {
    UtcTime {
        seconds: t.seconds + i64::from(t.nanos > 0),
        nanos: 0,
    }
}
