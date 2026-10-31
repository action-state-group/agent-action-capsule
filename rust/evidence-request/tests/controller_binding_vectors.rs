//! The Controller Binding v0 conformance vectors
//! (`vectors/controller-binding-v0/vectors.json`, all 42 cases), read in
//! place and checked against the directory's `SHA256SUMS` first.
//!
//! Every case runs from its inputs alone, and every member of its
//! `expected` block is compared: the binding block whole (no member is
//! skipped, and none goes unread), `issuer_independence`, and `fails`. The
//! halves' signatures and agreement, and `satisfied_becomes`, belong to the
//! interop profile verifier, not to `controller_binding`; this test checks
//! them itself (IP §11.5, §6.7.4) so that no expected member goes unchecked.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use ed25519_dalek::{Signature, VerifyingKey};
use evidence_request::controller_binding::{
    pair_independence, parse_declaration, verify, Credential, CredentialVerifier, Options, Report,
    RevocationList, PROPERTY_CREDENTIAL,
};
use evidence_request::jcs;
use evidence_request::status::Status;
use evidence_request::time::{parse_utc, UtcTime};
use serde_json::Value;
use sha2::{Digest, Sha256};

const CASES: usize = 42;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/controller-binding-v0")
}

fn verify_pinned_checksums() {
    let sums = std::fs::read_to_string(dir().join("SHA256SUMS")).expect("SHA256SUMS");
    let mut checked = 0;
    for line in sums.lines().filter(|l| !l.trim().is_empty()) {
        let (want, name) = line.split_once("  ").expect("sha256sum line");
        let got = hex::encode(Sha256::digest(
            std::fs::read(dir().join(name.trim())).expect("pinned file"),
        ));
        assert_eq!(got, want, "{name} does not match its pinned checksum");
        checked += 1;
    }
    assert_eq!(checked, 3, "README.md, manifest.json and vectors.json");
}

fn corpus() -> Value {
    verify_pinned_checksums();
    let bytes = std::fs::read(dir().join("vectors.json")).expect("vectors.json");
    let corpus: Value = serde_json::from_slice(&bytes).expect("vectors.json is JSON");
    let cases = corpus["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), CASES);
    assert_eq!(corpus["count"].as_u64(), Some(CASES as u64));
    corpus
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not text in {v}"))
}

fn octets(v: &Value) -> Vec<u8> {
    text(v, "octets_text").as_bytes().to_vec()
}

fn status(s: &str) -> Status {
    match s {
        "PASS" => Status::Pass,
        "FAIL" => Status::Fail,
        "NOT_CHECKED" => Status::NotChecked,
        "NOT_PRESENT" => Status::NotPresent,
        "INCONCLUSIVE" => Status::Inconclusive,
        other => panic!("not a §7.1 status: {other}"),
    }
}

fn ed25519_ok(key: &str, sig: &str, message: &[u8]) -> bool {
    let (Ok(key), Ok(sig)) = (hex::decode(key), hex::decode(sig)) else {
        return false;
    };
    let (Ok(key), Ok(sig)) = (<[u8; 32]>::try_from(key), <[u8; 64]>::try_from(sig)) else {
        return false;
    };
    VerifyingKey::from_bytes(&key).is_ok_and(|k| {
        k.verify_strict(message, &Signature::from_bytes(&sig))
            .is_ok()
    })
}

fn jcs_without(o: &Value, name: &str) -> Vec<u8> {
    let mut o = o.as_object().expect("an object").clone();
    o.remove(name);
    jcs::to_string(&Value::Object(o)).expect("JCS").into_bytes()
}

/// The credential format the vectors fix for themselves (CB §10), checked
/// under the case's pinned credential issuers. It is test code: the crate
/// ships no credential verifier.
fn vector_credential(issuers: Vec<String>) -> CredentialVerifier {
    Box::new(move |octets: &[u8], c: &Credential, keys: &[String; 2]| {
        let Ok(Value::Object(o)) = serde_json::from_slice::<Value>(octets) else {
            return Status::Fail;
        };
        let members: BTreeSet<&str> = o.keys().map(String::as_str).collect();
        let named = o["keys"]
            .as_array()
            .map(|k| k.iter().filter_map(Value::as_str).collect::<Vec<_>>());
        let good = members
            == BTreeSet::from(["issued_at", "issuer", "keys", "organization", "sig"])
            && o["issuer"] == *c.issuer
            && issuers.contains(&c.issuer)
            && o["issued_at"].is_string()
            && o["organization"].is_string()
            && named == Some(vec![keys[0].as_str(), keys[1].as_str()])
            && o["sig"].as_str().is_some_and(|sig| {
                ed25519_ok(
                    &c.issuer,
                    sig,
                    &jcs_without(&Value::Object(o.clone()), "sig"),
                )
            });
        if good {
            Status::Pass
        } else {
            Status::Fail
        }
    })
}

struct Run {
    report: Report,
    keys: [String; 2],
    halves: Vec<Value>,
}

fn run(case: &Value, credential_method: &str) -> Run {
    let pins = &case["pins"];
    let inputs = &case["inputs"];
    let halves: Vec<Value> = inputs["halves"]
        .as_array()
        .expect("halves")
        .iter()
        .map(|h| serde_json::from_slice(&octets(h)).expect("a half is JSON"))
        .collect();
    assert_eq!(halves.len(), 2);
    let keys = [
        text(&halves[0], "producer").to_owned(),
        text(&halves[1], "producer").to_owned(),
    ];
    let times: Vec<UtcTime> = halves
        .iter()
        .map(|h| parse_utc(text(h, "issued_at")).expect("issued_at"))
        .collect();

    let mut opts = Options::default();
    for r in inputs["revocations"].as_array().into_iter().flatten() {
        opts.revocations.push(octets(r));
    }
    if !inputs["credential"].is_null() {
        opts.credential = Some(octets(&inputs["credential"]));
    }
    if let Some(l) = inputs.get("revocation_list") {
        // The declaration as received, malformed or not (CB §5.1).
        opts.revocation_list = Some(RevocationList {
            declaration: serde_json::to_vec(&l["declaration"]).expect("declaration"),
            list: octets(l),
            evaluated_at: parse_utc(text(pins, "evaluation_time")).expect("evaluation_time"),
        });
    }
    let issuers: Vec<String> = pins["trust_policy"]["credential_issuers"]
        .as_array()
        .expect("credential_issuers")
        .iter()
        .map(|i| i.as_str().expect("an issuer key").to_owned())
        .collect();
    for m in pins["verification_policy"]["credential_methods_implemented"]
        .as_array()
        .expect("credential_methods_implemented")
    {
        assert_eq!(
            m, credential_method,
            "the vectors define one credential method"
        );
        opts.credential_verifiers.insert(
            credential_method.to_owned(),
            vector_credential(issuers.clone()),
        );
    }
    let report = verify(&octets(&inputs["binding"]), &times, &opts);
    Run {
        report,
        keys,
        halves,
    }
}

/// The report's binding block in the vectors' form.
fn binding_block(r: &Report, keys: &[String; 2]) -> Value {
    let properties: BTreeMap<&str, &str> =
        r.properties.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let mut block = serde_json::json!({
        "claim": r.claim,
        "binding_digest": r.binding_digest,
        "properties": properties,
        "binds_pair": r.binds_pair(&keys[0], &keys[1]),
        "applies": r.applies_to(&keys[0], &keys[1]),
        "proves": r.proves,
    });
    if let Some(l) = &r.revocation_list {
        // `reason` is a diagnostic, not in the vectors: it is there exactly
        // when the declaration does not count.
        assert_eq!(l.reason.is_none(), l.counts, "{:?}", l.reason);
        block["revocation_list"] = serde_json::json!({
            "profile": l.profile,
            "asserted_by": l.asserted_by,
            "list_digest": l.list_digest,
            "as_of": l.as_of,
            "counts": l.counts,
        });
    }
    block
}

#[test]
fn pinned_files_match_the_source_checksums() {
    verify_pinned_checksums();
}

#[test]
fn every_case_gives_its_whole_expected_block() {
    let corpus = corpus();
    let credential_method = text(&corpus, "credential_method");
    let mut passed = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let id = text(case, "id");
        let expected = &case["expected"];
        let members: BTreeSet<&str> = expected
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            members,
            BTreeSet::from(["halves", "binding", "issuer_independence", "fails"]),
            "{id}: every expected member is checked below"
        );
        let Run {
            report,
            keys,
            halves,
        } = run(case, credential_method);

        // The binding block, whole: an extra or missing member fails.
        assert_eq!(
            binding_block(&report, &keys),
            expected["binding"],
            "{id}: binding"
        );

        // issuer_independence (CB §7 item 4), and what IP §6.7.4 turns a
        // SATISFIED r-corroborated into under it.
        let ii = pair_independence(&keys[0], &keys[1], std::slice::from_ref(&report));
        let want = &expected["issuer_independence"];
        assert_eq!(ii.status, status(text(want, "status")), "{id}: status");
        assert_eq!(ii.shown_as, text(want, "shown_as"), "{id}: shown_as");
        assert_eq!(
            ii.reason.as_deref(),
            want["reason"].as_str(),
            "{id}: reason"
        );
        let becomes = match ii.status {
            Status::Fail => "INSUFFICIENT",
            Status::NotChecked => "UNKNOWN",
            other => panic!("{id}: a binding never gives {other:?}"),
        };
        assert_eq!(
            want["satisfied_becomes"],
            serde_json::json!({"r-corroborated": becomes}),
            "{id}: satisfied_becomes"
        );
        assert_eq!(
            want.as_object().unwrap().len(),
            4,
            "{id}: status, shown_as, reason and satisfied_becomes"
        );

        // fails: the properties that are FAIL.
        let failed: BTreeSet<&str> = report
            .properties
            .iter()
            .filter(|(_, s)| **s == Status::Fail)
            .map(|(p, _)| *p)
            .collect();
        let want_fails: BTreeSet<&str> = expected["fails"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f.as_str().unwrap())
            .collect();
        assert_eq!(failed, want_fails, "{id}: fails");

        // The halves (IP §11.5): each signed by a pinned producer key over
        // JCS of its other members, and agreeing on the claim.
        let trusted: Vec<&str> = case["pins"]["trust_policy"]["foreign_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k.as_str().unwrap())
            .collect();
        let sigs: Vec<&str> = halves
            .iter()
            .map(|h| {
                let producer = text(h, "producer");
                let ok = trusted.contains(&producer)
                    && ed25519_ok(producer, text(h, "sig"), &jcs_without(h, "sig"));
                if ok {
                    "PASS"
                } else {
                    "FAIL"
                }
            })
            .collect();
        assert_eq!(
            expected["halves"],
            serde_json::json!({"signatures": sigs, "agree": halves[0]["claim"] == halves[1]["claim"]}),
            "{id}: halves"
        );
        passed += 1;
    }
    assert_eq!(passed, CASES);
}

/// With no credential verifier passed, a delivered credential is
/// `NOT_CHECKED`, never `PASS`: the crate trusts no issuer of its own. The
/// credential never decides whether the binding applies (CB §6.2).
#[test]
fn no_credential_verifier_is_not_checked() {
    let corpus = corpus();
    let mut seen = 0;
    for case in corpus["cases"].as_array().unwrap() {
        if case["inputs"]["credential"].is_null() {
            continue;
        }
        seen += 1;
        let Run { report: full, .. } = run(case, text(&corpus, "credential_method"));
        let times: Vec<UtcTime> = case["inputs"]["halves"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| {
                let h: Value = serde_json::from_slice(&octets(h)).unwrap();
                parse_utc(text(&h, "issued_at")).unwrap()
            })
            .collect();
        let opts = Options {
            credential: Some(octets(&case["inputs"]["credential"])),
            ..Options::default()
        };
        let report = verify(&octets(&case["inputs"]["binding"]), &times, &opts);
        assert_eq!(
            report.properties[PROPERTY_CREDENTIAL],
            Status::NotChecked,
            "{}",
            text(case, "id")
        );
        assert_eq!(report.applies(), full.applies(), "{}", text(case, "id"));
    }
    assert!(seen >= 3, "the credentialed cases");
}

/// A revocation list that does not count, or cannot be read, never gives
/// `FAIL` (CB §9.4), and with no time asked about no declaration counts.
#[test]
fn a_list_that_cannot_be_read_or_has_no_time_never_fails() {
    let corpus = corpus();
    let case = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "complete-list")
        .expect("complete-list");
    let mut opts = Options::default();
    let l = &case["inputs"]["revocation_list"];
    let declaration = serde_json::to_vec(&l["declaration"]).unwrap();
    assert!(parse_declaration(&declaration).is_ok());
    let evaluated_at = parse_utc(text(&case["pins"], "evaluation_time")).unwrap();
    let binding = octets(&case["inputs"]["binding"]);
    let t = parse_utc("2026-10-15T00:00:20Z").unwrap();
    for list in [&b"[1,"[..], b"{\"a\":1,\"a\":2}", b"null"] {
        opts.revocation_list = Some(RevocationList {
            declaration: declaration.clone(),
            list: list.to_vec(),
            evaluated_at,
        });
        let report = verify(&binding, &[t], &opts);
        assert_eq!(
            report.properties["controller_binding_revocation"],
            Status::NotChecked
        );
        assert!(!report.revocation_list.unwrap().counts);
    }
    opts.revocation_list = Some(RevocationList {
        declaration,
        list: octets(l),
        evaluated_at,
    });
    let report = verify(&binding, &[], &opts);
    assert_eq!(
        report.properties["controller_binding_window"],
        Status::NotChecked
    );
    assert_eq!(
        report.properties["controller_binding_revocation"],
        Status::NotChecked
    );
    assert!(!report.applies());
    assert!(!report.revocation_list.unwrap().counts);
}
