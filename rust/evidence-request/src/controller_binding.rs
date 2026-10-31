//! Controller Binding v0 (`spec/controller-binding-v0.md`, cited as CB): a
//! binding record's form (§3.1, §3.2), both signatures over the one signing
//! input, each by its key's type (§3.3, §4, §4.1), its window, the
//! revocation statements the caller received (§5), a revocation list a
//! using profile declared complete (§5.1), and, for
//! `same_organization_credentialed`, a credential through a verifier the
//! caller passes. [`verify`] reports the binding properties of §6.1 in the
//! interop profile's §7.1 vocabulary and what the binding proves (§7 item 2);
//! [`Report::applies_to`] says whether it applies to a pair of keys (§6.2),
//! and [`pair_independence`] gives the `issuer_independence` that follows
//! (§7 item 4, IP §6.7.4).
//!
//! A binding shows only that whoever held each private key signed the
//! record. Nothing here establishes who controls a key. The module ships no
//! trust anchors, accepted credential issuers or credential verifier: no
//! credential format is registered (CB-3), and accepting an issuer is the
//! caller's trust policy.
//!
//! An `ed25519` key verifies with `verify_strict`. A `bip340` (Nostr) key
//! verifies the BIP-340 signature over the id of its NIP-01 signing event
//! (§4.1), with k256.
//!
//! Records, statements and lists are read with a strict decoder: a
//! duplicate member name, invalid UTF-8 or an unpaired surrogate makes them
//! unreadable. Numbers are read as JSON numbers, so a `created_at` of `-1`
//! is a signature that fails, not a record that cannot be read. A number
//! that is not an integer has no RFC 8785 form here (`jcs`), so a record
//! with one outside `sigs`, which is malformed anyway, reports no binding
//! digest; Go's `controllerbinding` reports one.
//!
//! The conformance vectors in `vectors/controller-binding-v0/` are the
//! module's tests (`tests/controller_binding_vectors.rs`).

use std::collections::BTreeMap;

use ed25519_dalek::{Signature as EdSignature, VerifyingKey as EdKey};
use k256::schnorr::{Signature as SchnorrSignature, VerifyingKey as SchnorrKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::envelope::is_profile_time;
use crate::jcs;
use crate::status::Status;
use crate::strict_json::decode_json_numbers;
use crate::time::{parse_utc, UtcTime};

/// The `binding_version` of a binding record (CB §3.1).
pub const VERSION: &str = "controller-binding/0";
/// The `revocation_version` of a revocation statement (CB §5).
pub const REVOCATION_VERSION: &str = "controller-binding-revocation/0";
/// The one revocation method this revision defines (CB §3.1).
pub const REVOCATION_METHOD: &str = "revocation_statement/0";

/// The claim types of CB §3.2.
pub const CLAIM_SAME_CONTROLLER: &str = "same_controller_asserted";
pub const CLAIM_DELEGATED_BY: &str = "delegated_by";
pub const CLAIM_SAME_ORGANIZATION: &str = "same_organization_credentialed";
/// The verification methods of CB §3.2, both implemented here.
pub const METHOD_DUAL_SIGNATURE: &str = "dual_signature/0";
pub const METHOD_DUAL_SIGNATURE_CREDENTIAL: &str = "dual_signature_credential/0";

/// The key types of CB §3.3.
pub const KEY_ED25519: &str = "ed25519";
pub const KEY_BIP340: &str = "bip340";
/// The kind of the Nostr event a `bip340` key signs with (CB §4.1),
/// provisional under CB-8.
pub const NOSTR_KIND: u32 = 3374;

/// The binding properties of CB §6.1.
pub const PROPERTY_FORM: &str = "controller_binding_form";
pub const PROPERTY_SIGNATURES: &str = "controller_binding_signatures";
pub const PROPERTY_WINDOW: &str = "controller_binding_window";
pub const PROPERTY_REVOCATION: &str = "controller_binding_revocation";
pub const PROPERTY_CREDENTIAL: &str = "controller_binding_credential";

/// What a binding proves (CB §7 item 2), in the vectors' words.
pub const PROVES_CONTROL: &str = "control of both keys at the ceremony";
pub const PROVES_CREDENTIALED: &str =
    "a trusted issuer key states that both keys are held within one organization";

/// The largest `created_at` and `max_age` (CB §4.1, §5.1): 2^53 − 1.
const MAX_INTEGER: u64 = (1 << 53) - 1;

const COMMON: [&str; 10] = [
    "binding_version",
    "claim",
    "method",
    "keys",
    "issued_at",
    "not_before",
    "not_after",
    "revocation",
    "nonce",
    "sigs",
];
const REVOCATION_MEMBERS: [&str; 5] = [
    "revocation_version",
    "binding",
    "key_id",
    "revoked_at",
    "sig",
];
const DECLARATION_MEMBERS: [&str; 6] = [
    "profile",
    "asserted_by",
    "binding",
    "list_digest",
    "as_of",
    "max_age",
];

/// A claim type's method, the member it adds and what both key holders
/// state (CB §3.2, §7 item 2).
struct ClaimSpec {
    claim: &'static str,
    method: &'static str,
    added: Option<&'static str>,
    states: &'static str,
}

const CLAIMS: [ClaimSpec; 3] = [
    ClaimSpec {
        claim: CLAIM_SAME_CONTROLLER,
        method: METHOD_DUAL_SIGNATURE,
        added: None,
        states: "both key holders state that one controller holds both keys",
    },
    ClaimSpec {
        claim: CLAIM_DELEGATED_BY,
        method: METHOD_DUAL_SIGNATURE,
        added: Some("delegator"),
        states: "both key holders state that the delegator delegated to the other key",
    },
    ClaimSpec {
        claim: CLAIM_SAME_ORGANIZATION,
        method: METHOD_DUAL_SIGNATURE_CREDENTIAL,
        added: Some("credential"),
        states: "both key holders state that both keys are held within one organization",
    },
];

fn claim_spec(claim: &str) -> Option<&'static ClaimSpec> {
    CLAIMS.iter().find(|c| c.claim == claim)
}

/// The `credential` member of a `same_organization_credentialed` record
/// (CB §3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub issuer: String,
    pub method: String,
    pub digest: String,
}

/// Checks a delivered credential, given as the octets transmitted, against
/// the record's `credential` member and its two bound keys. It owns the
/// credential's native method and the caller's trust policy, and returns a
/// §7.1 status: `Pass` only when the credential verifies under
/// `credential.issuer`, the trust policy accepts that issuer and the
/// credential names both keys; `Fail` when any of these fails;
/// `Inconclusive` when the trust policy cannot decide. Any other status is
/// read as `Fail`. [`verify`] has already checked the digest.
pub type CredentialVerifier = Box<dyn Fn(&[u8], &Credential, &[String; 2]) -> Status + Send + Sync>;

/// What a using profile gives the verifier beside a revocation list it
/// declares complete (CB §5.1). It is the asserting party's statement, not
/// a finding: under one that counts, `controller_binding_revocation` is
/// `PASS`, meaning only that no statement in the list applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declaration {
    /// The using profile that names the list.
    pub profile: String,
    /// The party the profile names as asserting completeness.
    pub asserted_by: String,
    /// The binding digest of the binding the list is for.
    pub binding: String,
    /// The SHA-256 of the list's octets as transmitted.
    pub list_digest: String,
    /// The time up to which the list is asserted complete.
    pub as_of: String,
    /// The profile's freshness bound, in seconds.
    pub max_age: u64,
}

/// Why a declaration is not in its form (CB §5.1). A declaration that is
/// not does not count, and the list's entries are still read.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeclarationError {
    #[error("the declaration is not one JSON value")]
    NotJson,
    #[error("the declaration is not a JSON object")]
    NotObject,
    #[error("the declaration does not have exactly profile, asserted_by, binding, list_digest, as_of and max_age")]
    Members,
    #[error("profile or asserted_by is not a text string")]
    Text,
    #[error("binding or list_digest is not 64 lowercase hex characters")]
    Digest,
    #[error("as_of is not a time")]
    Time,
    #[error("max_age is not an integer from 0 to 2^53 - 1")]
    MaxAge,
}

/// Read a declaration (CB §5.1) from its JSON object as received: exactly
/// the six members, each in its form.
pub fn parse_declaration(octets: &[u8]) -> Result<Declaration, DeclarationError> {
    let (declaration, form) = read_declaration(octets);
    form.map(|()| declaration)
}

/// The declaration, and whether it is in its form. When it is not, the
/// declaration still holds `profile`, `asserted_by` and `as_of` where each
/// is a text string, so it can be reported as delivered.
fn read_declaration(octets: &[u8]) -> (Declaration, Result<(), DeclarationError>) {
    let mut d = Declaration {
        profile: String::new(),
        asserted_by: String::new(),
        binding: String::new(),
        list_digest: String::new(),
        as_of: String::new(),
        max_age: 0,
    };
    let Some(value) = decode_json_numbers(octets) else {
        return (d, Err(DeclarationError::NotJson));
    };
    let Some(m) = value.as_object() else {
        return (d, Err(DeclarationError::NotObject));
    };
    let text = |name: &str| m.get(name).and_then(Value::as_str).map(str::to_owned);
    d.profile = text("profile").unwrap_or_default();
    d.asserted_by = text("asserted_by").unwrap_or_default();
    d.as_of = text("as_of").unwrap_or_default();
    if !has_members(m, &DECLARATION_MEMBERS) {
        return (d, Err(DeclarationError::Members));
    }
    if text("profile").is_none() || text("asserted_by").is_none() {
        return (d, Err(DeclarationError::Text));
    }
    d.binding = text("binding").unwrap_or_default();
    d.list_digest = text("list_digest").unwrap_or_default();
    if !is_digest(&d.binding) || !is_digest(&d.list_digest) {
        return (d, Err(DeclarationError::Digest));
    }
    // A §5.2 time naming a real calendar instant: 2026-02-30 is not one.
    if instant(Some(&d.as_of)).is_none() {
        return (d, Err(DeclarationError::Time));
    }
    // An integer token: a fraction, an exponent, a sign or text is not one.
    match m["max_age"].as_u64().filter(|n| *n <= MAX_INTEGER) {
        Some(max_age) => d.max_age = max_age,
        None => return (d, Err(DeclarationError::MaxAge)),
    }
    (d, Ok(()))
}

/// A revocation list (a JSON array of revocation statements) with the
/// declaration a using profile gave beside it (CB §5.1). The caller takes
/// the declaration only through the using profile's own channel, never
/// from the party presenting the evidence: it is unsigned, and
/// `asserted_by` is reported as delivered, not as authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationList {
    /// The declaration's JSON object as received. One that is not in its
    /// form does not count, and the list's entries are still read.
    pub declaration: Vec<u8>,
    /// The list's octets as transmitted.
    pub list: Vec<u8>,
    /// The evaluation time E the freshness bound is checked at: the
    /// verifier's current time, unless the using profile pins it.
    pub evaluated_at: UtcTime,
}

/// How a verifier reports a declaration (CB §6.1): the method of a
/// revocation `PASS`, which it presents as `asserted_by`'s statement under
/// `profile` that the list with `list_digest` was complete as of `as_of`.
/// `list_digest` is the digest of the octets received, not the declared
/// one; `profile`, `asserted_by` and `as_of` are as delivered, empty when
/// not a text string. `counts` says whether the declaration counts for this
/// binding at the times asked about, and `reason`, when it does not, why.
/// `reason` is a diagnostic, as Go's `ListReport.Reason` is, and not part of
/// the vectors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListReport {
    pub profile: String,
    pub asserted_by: String,
    pub list_digest: String,
    pub as_of: String,
    pub counts: bool,
    pub reason: Option<String>,
}

/// What the caller received beside the binding record, and how it checks a
/// credential.
#[derive(Default)]
pub struct Options {
    /// Revocation statements as received (CB §5). One that does not apply
    /// to this binding is ignored.
    pub revocations: Vec<Vec<u8>>,
    /// A revocation list a using profile declared complete (CB §5.1). Its
    /// entries are received statements whether or not the declaration
    /// counts.
    pub revocation_list: Option<RevocationList>,
    /// The credential as transmitted, or `None` when none was delivered.
    pub credential: Option<Vec<u8>>,
    /// Credential checks by `credential.method`. A method with no entry is
    /// not implemented: `NOT_CHECKED`.
    pub credential_verifiers: BTreeMap<String, CredentialVerifier>,
}

/// What a verifier reports for one binding record (CB §7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The record's `claim`, when it is text.
    pub claim: Option<String>,
    /// The two keys the record names, reported even when it is malformed,
    /// so a pair can be told it is named by a binding that does not apply.
    pub keys: Option<[String; 2]>,
    /// The `delegator` of a well-formed `delegated_by` record.
    pub delegator: Option<String>,
    /// The window of a well-formed record.
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    /// The binding digest (CB §4), when the record is a JSON object with an
    /// RFC 8785 form.
    pub binding_digest: Option<String>,
    /// The properties of CB §6.1 that apply. Only `controller_binding_form`
    /// is reported when it is `FAIL`.
    pub properties: BTreeMap<&'static str, Status>,
    /// What the binding proves (CB §7 item 2): empty unless the form and
    /// signatures pass.
    pub proves: Vec<&'static str>,
    /// The declaration's report, when a revocation list was given and the
    /// record is well formed.
    pub revocation_list: Option<ListReport>,
}

impl Report {
    fn property(&self, name: &str) -> Option<Status> {
        self.properties.get(name).copied()
    }

    /// Whether the binding applies to the pair of its own two keys (CB
    /// §6.2): form, signatures and window `PASS`, and revocation not
    /// `FAIL`. The credential never decides it.
    pub fn applies(&self) -> bool {
        self.property(PROPERTY_FORM) == Some(Status::Pass)
            && self.property(PROPERTY_SIGNATURES) == Some(Status::Pass)
            && self.property(PROPERTY_WINDOW) == Some(Status::Pass)
            && self.property(PROPERTY_REVOCATION) != Some(Status::Fail)
    }

    /// Whether `key` is one of the two keys the record names. It gives no
    /// role: a caller that needs the direction reads `claim` and
    /// `delegator`.
    pub fn binds(&self, key: &str) -> bool {
        self.keys
            .as_ref()
            .is_some_and(|k| k.iter().any(|x| x == key))
    }

    /// Whether the record's two keys are exactly `a` and `b`, in either
    /// order (CB §6.2).
    pub fn binds_pair(&self, a: &str, b: &str) -> bool {
        self.keys
            .as_ref()
            .is_some_and(|[x, y]| (x == a && y == b) || (x == b && y == a))
    }

    /// Whether the binding applies to the pair of keys `a` and `b` (CB
    /// §6.2). The report must have been made at the pair's times.
    pub fn applies_to(&self, a: &str, b: &str) -> bool {
        self.binds_pair(a, b) && self.applies()
    }
}

/// The `issuer_independence` a pair gets (CB §7 item 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerIndependence {
    pub status: Status,
    pub shown_as: &'static str,
    /// `same key`, or the applying binding's claim type and digest.
    pub reason: Option<String>,
}

/// The `issuer_independence` of a pair signed under keys `a` and `b`, given
/// every binding report the verifier received for it (CB §9.1). A binding
/// never gives `PASS` (§6.2): one that applies gives `FAIL`, and with none
/// the pair is `NOT_CHECKED`, "not corroborating".
pub fn pair_independence(a: &str, b: &str, reports: &[Report]) -> IssuerIndependence {
    const REDUNDANT: &str = "redundant, not corroborating";
    if a == b {
        return IssuerIndependence {
            status: Status::Fail,
            shown_as: REDUNDANT,
            reason: Some("same key".to_owned()),
        };
    }
    for r in reports {
        if r.applies_to(a, b) {
            return IssuerIndependence {
                status: Status::Fail,
                shown_as: REDUNDANT,
                reason: Some(format!(
                    "controller binding {} {}",
                    r.claim.as_deref().unwrap_or_default(),
                    r.binding_digest.as_deref().unwrap_or_default()
                )),
            };
        }
    }
    IssuerIndependence {
        status: Status::NotChecked,
        shown_as: "not corroborating",
        reason: None,
    }
}

/// Check one binding record, given as the octets received, at the times
/// `times`: for a pair under IP §6.7.4, each member's `issued_at`. With no
/// time the window is `NOT_CHECKED`, so the binding does not apply.
pub fn verify(record: &[u8], times: &[UtcTime], opts: &Options) -> Report {
    let mut report = Report {
        claim: None,
        keys: None,
        delegator: None,
        not_before: None,
        not_after: None,
        binding_digest: None,
        properties: BTreeMap::new(),
        proves: Vec::new(),
        revocation_list: None,
    };
    let Some(Value::Object(r)) = decode_json_numbers(record) else {
        report.properties.insert(PROPERTY_FORM, Status::Fail);
        return report;
    };
    let signing_input = jcs::to_string(&Value::Object(without(&r, "sigs"))).ok();
    report.binding_digest = signing_input.as_deref().map(sha256_hex);
    report.claim = r.get("claim").and_then(Value::as_str).map(str::to_owned);
    if let Some([Value::String(first), Value::String(second)]) =
        r.get("keys").and_then(Value::as_array).map(Vec::as_slice)
    {
        report.keys = Some([first.clone(), second.clone()]);
    }
    if !well_formed(&r) {
        report.properties.insert(PROPERTY_FORM, Status::Fail);
        return report;
    }
    report.properties.insert(PROPERTY_FORM, Status::Pass);
    let keys = report
        .keys
        .clone()
        .expect("a well-formed record names two keys");
    let digest = report.binding_digest.clone().unwrap_or_default();
    let text = |name: &str| r.get(name).and_then(Value::as_str).map(str::to_owned);
    report.delegator = text("delegator");
    report.not_before = text("not_before");
    report.not_after = text("not_after");

    let types = key_types(&r);
    report.properties.insert(
        PROPERTY_SIGNATURES,
        signatures(&r, &keys, &types, signing_input.as_deref()),
    );

    let not_before = instant(report.not_before.as_deref());
    let not_after = instant(report.not_after.as_deref());
    let window = match (times.is_empty(), not_before, not_after) {
        (true, _, _) => Status::NotChecked,
        (false, Some(nb), Some(na)) if times.iter().all(|t| nb <= *t && *t < na) => Status::Pass,
        _ => Status::Fail,
    };
    report.properties.insert(PROPERTY_WINDOW, window);

    let mut statements: Vec<Value> = opts
        .revocations
        .iter()
        .filter_map(|o| decode_json_numbers(o))
        .collect();
    if let Some(list) = &opts.revocation_list {
        statements.extend(list_entries(&list.list).unwrap_or_default());
    }
    let mut revocation = revocation_status(&digest, &keys, &types, times, &statements);
    if let Some(list) = &opts.revocation_list {
        let list_report = list_report(list, &digest, times);
        if list_report.counts && revocation != Status::Fail {
            revocation = Status::Pass;
        }
        report.revocation_list = Some(list_report);
    }
    report.properties.insert(PROPERTY_REVOCATION, revocation);

    let claim = report.claim.clone().unwrap_or_default();
    if claim == CLAIM_SAME_ORGANIZATION {
        report.properties.insert(
            PROPERTY_CREDENTIAL,
            credential_status(&credential_of(&r), &keys, opts),
        );
    }
    if report.property(PROPERTY_SIGNATURES) == Some(Status::Pass) {
        let spec = claim_spec(&claim).expect("a well-formed record has a known claim");
        report.proves.extend([PROVES_CONTROL, spec.states]);
        if report.property(PROPERTY_CREDENTIAL) == Some(Status::Pass) {
            report.proves.push(PROVES_CREDENTIALED);
        }
    }
    report
}

fn sha256_hex(octets: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(octets.as_ref()))
}

fn without(m: &Map<String, Value>, name: &str) -> Map<String, Value> {
    m.iter()
        .filter(|(k, _)| k.as_str() != name)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn has_members(m: &Map<String, Value>, names: &[&str]) -> bool {
    m.len() == names.len() && names.iter().all(|n| m.contains_key(*n))
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_digest(s: &str) -> bool {
    is_lower_hex(s, 64)
}

fn is_key(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(is_digest)
}

/// A §5.2 time naming a real calendar instant.
fn instant(s: Option<&str>) -> Option<UtcTime> {
    s.filter(|s| is_profile_time(s)).and_then(parse_utc)
}

fn instant_of(v: Option<&Value>) -> Option<UtcTime> {
    instant(v.and_then(Value::as_str))
}

/// `controller_binding_form` (CB §3.1, §3.2).
fn well_formed(r: &Map<String, Value>) -> bool {
    let Some(spec) = r.get("claim").and_then(Value::as_str).and_then(claim_spec) else {
        return false;
    };
    let mut names: Vec<&str> = COMMON.to_vec();
    names.extend(spec.added);
    if r.contains_key("key_types") {
        names.push("key_types"); // OPTIONAL (§3.1)
    }
    if !has_members(r, &names) || r["binding_version"] != VERSION {
        return false;
    }
    // A method §3.2 defines for another claim type is malformed; one it does
    // not define at all is well formed and NOT_CHECKED.
    let Some(method) = r["method"].as_str() else {
        return false;
    };
    if CLAIMS.iter().any(|c| c.method == method) && method != spec.method {
        return false;
    }
    let keys = match r["keys"].as_array().map(Vec::as_slice) {
        Some([a, b]) if is_key(Some(a)) && is_key(Some(b)) => {
            [a.as_str().unwrap(), b.as_str().unwrap()]
        }
        _ => return false,
    };
    // Ascending, so also distinct: a key bound to itself states nothing.
    if keys[0] >= keys[1] {
        return false;
    }
    let (Some(issued), Some(not_before), Some(not_after)) = (
        instant_of(r.get("issued_at")),
        instant_of(r.get("not_before")),
        instant_of(r.get("not_after")),
    ) else {
        return false;
    };
    if not_before > issued || issued >= not_after {
        return false;
    }
    if r["revocation"] != REVOCATION_METHOD {
        return false;
    }
    let Some(nonce) = r["nonce"].as_str() else {
        return false;
    };
    if let Some(types) = r.get("key_types") {
        let Some(list) = types.as_array() else {
            return false;
        };
        if list.len() != 2 || !list.iter().all(Value::is_string) {
            return false;
        }
        // A bip340 key is often a public Nostr identity, so the nonce alone
        // keeps a listed binding digest from being matched to guessed keys
        // (§9.3).
        let nonce_ok = nonce.len() >= 32
            && nonce
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if list.iter().any(|t| t == KEY_BIP340) && !nonce_ok {
            return false;
        }
    }
    let Some(sigs) = r["sigs"].as_array() else {
        return false;
    };
    if !sigs.iter().all(|s| {
        s.as_object()
            .is_some_and(|e| has_members(e, &["key_id", "sig"]))
    }) {
        return false;
    }
    match spec.added {
        Some("delegator") => keys.iter().any(|k| r["delegator"] == *k),
        Some("credential") => r["credential"].as_object().is_some_and(|c| {
            has_members(c, &["issuer", "method", "digest"])
                && is_key(c.get("issuer"))
                && c["method"].is_string()
                && is_key(c.get("digest"))
        }),
        _ => true,
    }
}

/// Each key's type, in the order of `keys` (CB §3.1): both `ed25519` when
/// `key_types` is absent. The record is well formed.
fn key_types(r: &Map<String, Value>) -> [String; 2] {
    match r
        .get("key_types")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
    {
        Some([Value::String(a), Value::String(b)]) => [a.clone(), b.clone()],
        _ => [KEY_ED25519.to_owned(), KEY_ED25519.to_owned()],
    }
}

/// `controller_binding_signatures` (CB §4): exactly two entries, naming
/// `keys` in order, each verifying over the one signing input by its key's
/// type (§4.1).
fn signatures(
    r: &Map<String, Value>,
    keys: &[String; 2],
    types: &[String; 2],
    signing_input: Option<&str>,
) -> Status {
    let spec = r["claim"]
        .as_str()
        .and_then(claim_spec)
        .expect("well formed");
    if r["method"].as_str() != Some(spec.method) {
        return Status::NotChecked; // a method this revision does not define
    }
    if !types.iter().all(|t| t == KEY_ED25519 || t == KEY_BIP340) {
        return Status::NotChecked; // a key type §3.3 does not list
    }
    let sigs = r["sigs"].as_array().expect("well formed");
    let Some(signing_input) = signing_input else {
        return Status::Fail;
    };
    if sigs.len() != 2 {
        return Status::Fail;
    }
    let all = sigs
        .iter()
        .zip(keys)
        .zip(types)
        .all(|((entry, key), key_type)| {
            entry["key_id"] == **key
                && verify_sig(
                    key,
                    key_type,
                    &entry["sig"],
                    VERSION,
                    signing_input.as_bytes(),
                )
        });
    if all {
        Status::Pass
    } else {
        Status::Fail
    }
}

/// Check `sig` by `key`, of type `key_type`, over the signed octets of an
/// object of the given version (CB §4.1). A key type §3.3 does not list
/// never verifies.
fn verify_sig(key: &str, key_type: &str, sig: &Value, version: &str, signed: &[u8]) -> bool {
    match key_type {
        KEY_ED25519 => verify_ed25519(key, sig, signed),
        KEY_BIP340 => verify_nostr(key, sig, version, signed),
        _ => false,
    }
}

/// Ed25519 under `verify_strict`: a small-order key or a non-canonical `R`
/// does not verify.
fn verify_ed25519(key: &str, sig: &Value, message: &[u8]) -> bool {
    let Some(sig) = sig.as_str().filter(|s| is_lower_hex(s, 128)) else {
        return false;
    };
    let mut raw_key = [0u8; 32];
    let mut raw_sig = [0u8; 64];
    if hex::decode_to_slice(key, &mut raw_key).is_err()
        || hex::decode_to_slice(sig, &mut raw_sig).is_err()
    {
        return false;
    }
    EdKey::from_bytes(&raw_key).is_ok_and(|k| {
        k.verify_strict(message, &EdSignature::from_bytes(&raw_sig))
            .is_ok()
    })
}

/// A `bip340` key's `sig`, `{created_at, sig}`: the BIP-340 signature over
/// the id of the Nostr event (NIP-01) of kind 3374, no tags, and content
/// `<version>:<SHA-256 of signed>` (CB §4.1).
fn verify_nostr(key: &str, sig: &Value, version: &str, signed: &[u8]) -> bool {
    let Some(s) = sig
        .as_object()
        .filter(|s| has_members(s, &["created_at", "sig"]))
    else {
        return false;
    };
    let Some(signature) = s["sig"].as_str().filter(|t| is_lower_hex(t, 128)) else {
        return false;
    };
    // An integer token in 0..=2^53-1: a fraction, an exponent, a negative
    // number or text is not one.
    let Some(created_at) = s["created_at"].as_u64().filter(|n| *n <= MAX_INTEGER) else {
        return false;
    };
    // key is 64 lowercase hex characters, and version and the digest are
    // ASCII with nothing JSON escapes, so this is NIP-01's serialization.
    let event = format!(
        "[0,\"{key}\",{created_at},{NOSTR_KIND},[],\"{version}:{}\"]",
        sha256_hex(signed)
    );
    let id = Sha256::digest(event.as_bytes());
    let (Ok(raw_key), Ok(raw_sig)) = (hex::decode(key), hex::decode(signature)) else {
        return false;
    };
    let (Ok(public), Ok(parsed)) = (
        SchnorrKey::from_bytes(&raw_key),
        SchnorrSignature::try_from(raw_sig.as_slice()),
    ) else {
        return false;
    };
    public.verify_raw(&id, &parsed).is_ok()
}

/// `controller_binding_revocation` before any declaration (CB §5, §6.1):
/// `FAIL` when a received statement applies with `revoked_at` at or before
/// some T, otherwise `NOT_CHECKED`, since a statement not received cannot be
/// excluded (CB-1). [`verify`] raises `NOT_CHECKED` to `PASS` under a
/// declaration that counts (§5.1).
fn revocation_status(
    digest: &str,
    keys: &[String; 2],
    types: &[String; 2],
    times: &[UtcTime],
    statements: &[Value],
) -> Status {
    for statement in statements {
        let Some(s) = statement.as_object() else {
            continue;
        };
        if !has_members(s, &REVOCATION_MEMBERS)
            || s["revocation_version"] != REVOCATION_VERSION
            || s["binding"] != digest
        {
            continue;
        }
        let Some(index) = keys.iter().position(|k| s["key_id"] == *k) else {
            continue; // only a bound key revokes
        };
        let Ok(signed) = jcs::to_string(&Value::Object(without(s, "sig"))) else {
            continue;
        };
        if !verify_sig(
            &keys[index],
            &types[index],
            &s["sig"],
            REVOCATION_VERSION,
            signed.as_bytes(),
        ) {
            continue;
        }
        let Some(revoked_at) = instant_of(s.get("revoked_at")) else {
            continue;
        };
        if times.iter().any(|t| revoked_at <= *t) {
            return Status::Fail;
        }
    }
    Status::NotChecked
}

/// A revocation list's entries, or `None` when its octets are not a JSON
/// array (CB §5.1). An entry that is not an object is no statement, and
/// [`revocation_status`] skips it.
fn list_entries(list: &[u8]) -> Option<Vec<Value>> {
    match decode_json_numbers(list) {
        Some(Value::Array(items)) => Some(items),
        _ => None,
    }
}

/// The declaration's report, and whether it counts for the binding with
/// this digest at the times `times` and the list's evaluation time (CB
/// §5.1).
fn list_report(l: &RevocationList, digest: &str, times: &[UtcTime]) -> ListReport {
    let (d, form) = read_declaration(&l.declaration);
    let received = sha256_hex(&l.list);
    let reason = why_not(&d, form, &received, l, digest, times);
    ListReport {
        profile: d.profile,
        asserted_by: d.asserted_by,
        list_digest: received,
        as_of: d.as_of,
        counts: reason.is_none(),
        reason,
    }
}

/// Why a declaration does not count (CB §5.1), or `None` when it counts.
fn why_not(
    d: &Declaration,
    form: Result<(), DeclarationError>,
    received: &str,
    l: &RevocationList,
    digest: &str,
    times: &[UtcTime],
) -> Option<String> {
    let why = |s: &str| Some(s.to_owned());
    if let Err(e) = form {
        return Some(e.to_string());
    }
    if d.binding != digest {
        return why("the declaration names another binding");
    }
    if d.list_digest != received {
        return why("list_digest is not the digest of the list received");
    }
    if list_entries(&l.list).is_none() {
        return why("the list is not a JSON array");
    }
    if times.is_empty() {
        return why("no time T was asked about");
    }
    let Some(as_of) = instant(Some(&d.as_of)) else {
        return why("as_of is not a time");
    };
    // The list covers a statement dated at or before T only when as_of is
    // not earlier than T.
    if times.iter().any(|t| as_of < *t) {
        return why("as_of is earlier than a time asked about");
    }
    if as_of > l.evaluated_at {
        return why("as_of is later than the evaluation time");
    }
    // In whole seconds (CB §5.1). E is not before as_of here and max_age is
    // at most 2^53 - 1, so neither side overflows an i64.
    if l.evaluated_at.seconds - as_of.seconds > d.max_age as i64 {
        return why("the evaluation time is more than max_age after as_of");
    }
    None
}

fn credential_of(r: &Map<String, Value>) -> Credential {
    let c = &r["credential"];
    let text = |name: &str| c[name].as_str().unwrap_or_default().to_owned();
    Credential {
        issuer: text("issuer"),
        method: text("method"),
        digest: text("digest"),
    }
}

/// `controller_binding_credential` (CB §6.1).
fn credential_status(c: &Credential, keys: &[String; 2], opts: &Options) -> Status {
    let Some(octets) = &opts.credential else {
        return Status::NotPresent;
    };
    let Some(check) = opts.credential_verifiers.get(&c.method) else {
        return Status::NotChecked;
    };
    if sha256_hex(octets) != c.digest {
        return Status::Fail;
    }
    match check(octets, c, keys) {
        status @ (Status::Pass | Status::Fail | Status::Inconclusive) => status,
        // A verifier that returns no verdict vouches for nothing.
        _ => Status::Fail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_that_is_not_an_object_is_malformed() {
        for record in [&b"[]"[..], b"{\"a\":1,\"a\":1}", b"not json"] {
            let report = verify(record, &[], &Options::default());
            assert_eq!(report.properties.len(), 1);
            assert_eq!(report.properties[PROPERTY_FORM], Status::Fail);
            assert!(report.proves.is_empty() && !report.applies());
        }
    }

    #[test]
    fn declarations_parse_strictly() {
        let good = r#"{"profile":"p","asserted_by":"a","binding":"0000000000000000000000000000000000000000000000000000000000000000","list_digest":"1111111111111111111111111111111111111111111111111111111111111111","as_of":"2026-10-19T00:00:00Z","max_age":86400}"#;
        assert_eq!(parse_declaration(good.as_bytes()).unwrap().max_age, 86400);
        for (from, to, want) in [
            ("86400", "-1", DeclarationError::MaxAge),
            ("86400", "1.0", DeclarationError::MaxAge),
            ("86400", "\"86400\"", DeclarationError::MaxAge),
            ("86400", "9007199254740992", DeclarationError::MaxAge),
            (
                "2026-10-19T00:00:00Z",
                "2026-10-19T00:00:00.5Z",
                DeclarationError::Time,
            ),
            ("\"p\"", "1", DeclarationError::Text),
            (
                "0000000000000000",
                "000000000000000A",
                DeclarationError::Digest,
            ),
            (
                "\"max_age\"",
                "\"max_age\":1,\"max_age\"",
                DeclarationError::NotJson,
            ),
            (",\"max_age\":86400", "", DeclarationError::Members),
            ("2026-10-19", "2026-02-30", DeclarationError::Time),
        ] {
            let bad = good.replacen(from, to, 1);
            assert_eq!(parse_declaration(bad.as_bytes()), Err(want), "{bad}");
        }
        assert_eq!(parse_declaration(b"[]"), Err(DeclarationError::NotObject));
        // A malformed declaration is still reported as delivered.
        let (d, form) = read_declaration(good.replacen("86400", "-1", 1).as_bytes());
        assert_eq!(form, Err(DeclarationError::MaxAge));
        assert_eq!((d.profile.as_str(), d.asserted_by.as_str()), ("p", "a"));
        assert_eq!(d.as_of, "2026-10-19T00:00:00Z");
    }

    fn declared(max_age: u64, evaluated_at: &str) -> RevocationList {
        RevocationList {
            declaration: format!(
                r#"{{"profile":"p","asserted_by":"a","binding":"{}","list_digest":"{}","as_of":"2026-10-19T00:00:00Z","max_age":{max_age}}}"#,
                "0".repeat(64),
                sha256_hex(b"[]")
            )
            .into_bytes(),
            list: b"[]".to_vec(),
            evaluated_at: parse_utc(evaluated_at).unwrap(),
        }
    }

    #[test]
    fn with_no_time_no_declaration_counts() {
        let list = declared(86400, "2026-10-19T01:00:00Z");
        let digest = "0".repeat(64);
        let report = list_report(&list, &digest, &[]);
        assert!(!report.counts);
        assert_eq!(report.reason.as_deref(), Some("no time T was asked about"));
        let t = parse_utc("2026-10-18T00:00:00Z").unwrap();
        let report = list_report(&list, &digest, &[t]);
        assert!(report.counts && report.reason.is_none());
        assert!(!list_report(&list, &"1".repeat(64), &[t]).counts);
    }

    #[test]
    fn max_age_is_compared_in_whole_seconds_without_overflow() {
        let digest = "0".repeat(64);
        let t = parse_utc("2026-10-18T00:00:00Z").unwrap();
        // Exactly max_age after as_of counts; a fraction of a second later
        // is still the same whole second; one second later does not.
        assert!(list_report(&declared(3600, "2026-10-19T01:00:00Z"), &digest, &[t]).counts);
        assert!(list_report(&declared(3600, "2026-10-19T01:00:00.9Z"), &digest, &[t]).counts);
        assert!(!list_report(&declared(3600, "2026-10-19T01:00:01Z"), &digest, &[t]).counts);
        // A max_age far beyond any Duration of nanoseconds.
        for (max_age, e) in [
            (10_000_000_000, "2026-10-22T00:00:00Z"),
            (MAX_INTEGER, "9999-12-31T23:59:59Z"),
        ] {
            assert!(list_report(&declared(max_age, e), &digest, &[t]).counts);
        }
        assert!(
            !list_report(
                &declared(10_000_000_000, "9999-12-31T23:59:59Z"),
                &digest,
                &[t]
            )
            .counts
        );
    }
}
