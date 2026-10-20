// SPDX-License-Identifier: BSD-3-Clause
//! Runs `vectors/bundle/strict/vectors.json`: every `cases` entry through
//! `verify_bundle_strict`, compared as `vectors/bundle/strict/README.md`
//! ("How to consume them") says, and every `record_signatures` entry through
//! `envelope::verify_record_signature`.

use agent_action_capsule::bundle::{verify_bundle, verify_bundle_strict, StrictOptions};
use agent_action_capsule::envelope::{verify_record_signature, INVALID};
use agent_action_capsule::verify::decode_capsule_json;
use agent_action_capsule::witness::{
    binding_of, endpoint_of, row_for, row_public_keys, verify_receipt, verify_scrapi_receipt,
    verify_witness_receipts, SignedCheckpoint,
};
use serde_json::{json, Value};

fn vectors() -> Value {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/bundle/strict/vectors.json"
    ))
    .expect("vectors/bundle/strict/vectors.json");
    decode_capsule_json(&data).expect("valid JSON")
}

fn observed(bundle: &Value, options: &StrictOptions) -> Value {
    let result = verify_bundle_strict(bundle, options);
    let witnesses = result.witnesses.as_ref().map(|w| {
        json!({
            "status": w.status,
            "findings": w.findings,
            "receipts": result.witness_receipts.iter().map(|r| json!({
                "ts_url": r.ts_url, "binding": r.binding, "status": r.status, "grade": r.grade,
            })).collect::<Vec<_>>(),
        })
    });
    json!({
        "verdict": result.verdict(),
        "kind_ok": result.kind_ok,
        "claims": result.claims.iter().map(|(name, c)| json!({
            "name": name, "status": c.status, "findings": c.findings,
        })).collect::<Vec<_>>(),
        "witnesses": witnesses,
        "records": result.records.iter().map(|r| json!({
            "capsule_id": r.capsule_id, "identity_ok": r.identity_ok, "signature": r.signature,
            "key_id": r.key_id, "seq": r.seq,
        })).collect::<Vec<_>>(),
        "checkpoint_authenticated": result.checkpoint_authenticated(),
        "signer_matches_checkpoint": result.signer_matches_checkpoint,
    })
}

#[test]
fn every_strict_case_matches() {
    let vectors = vectors();
    let directory = &vectors["witness_directory"];
    let cases = vectors["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 56);
    let mut failures = Vec::new();
    for case in cases {
        let options = StrictOptions {
            require_signature: case["options"]["require_signature"] == json!(true),
            witness_directory: (case["options"]["witness_directory"] == json!(true))
                .then_some(directory),
            ..StrictOptions::default()
        };
        let mut expect = json!({"kind_ok": true});
        for (k, v) in case["expect"].as_object().expect("expect") {
            expect[k] = v.clone();
        }
        // Compare through the canonical text so number spellings agree.
        let got = observed(&case["bundle"], &options);
        let (got_text, want_text) = (got.to_string(), expect.to_string());
        let got_back: Value = serde_json::from_str(&got_text).unwrap();
        let want_back: Value = serde_json::from_str(&want_text).unwrap();
        if got_back != want_back {
            failures.push(format!(
                "{}:\n  got  {got_text}\n  want {want_text}",
                case["id"]
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn every_record_signature_matches() {
    let vectors = vectors();
    let cases = vectors["record_signatures"]
        .as_array()
        .expect("record_signatures");
    assert_eq!(cases.len(), 9);
    for case in cases {
        let (verdict, messages) = verify_record_signature(&case["record"]);
        assert_eq!(json!(verdict), case["expect"], "{}", case["id"]);
        assert_eq!(!messages.is_empty(), verdict == INVALID, "{}", case["id"]);
    }
}

#[test]
fn the_plain_verifier_is_unchanged() {
    let vectors = vectors();
    let bundle = &vectors["cases"][0]["bundle"];
    let plain = verify_bundle(bundle);
    let strict = verify_bundle_strict(bundle, &StrictOptions::default());
    assert_eq!(plain.graph_closure, strict.base.graph_closure);
    assert_eq!(plain.interval_coverage, strict.base.interval_coverage);
    assert_eq!(
        plain.per_record_membership,
        strict.base.per_record_membership
    );
}

/// The vdp inclusion-proof byte string is decoded leniently, as scitt-cose
/// does: `[1, 0, []]` written with non-shortest integer heads
/// (`831801180080` for `83010080`) still verifies. The proof sits in the
/// unprotected header and the signature covers only the protected header and
/// the rebuilt root, so no re-signing is needed.
#[test]
fn a_non_shortest_inclusion_proof_still_verifies() {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let vectors = vectors();
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "pos-witness-cll")
        .unwrap();
    let mut bundle = case["bundle"].clone();
    let receipt_b64 = &mut bundle["checkpoint"]["witnesses"][0]["receipt_b64"];
    let receipt = hex::encode(b64.decode(receipt_b64.as_str().unwrap()).unwrap());
    // bstr(4) [1, 0, []] -> bstr(6) [1, 0, []] with one-byte integer heads.
    assert_eq!(receipt.matches("4483010080").count(), 1);
    let lenient = receipt.replace("4483010080", "46831801180080");
    *receipt_b64 = json!(b64.encode(hex::decode(lenient).unwrap()));

    let options = StrictOptions {
        require_signature: false,
        witness_directory: Some(&vectors["witness_directory"]),
        ..StrictOptions::default()
    };
    let result = verify_bundle_strict(&bundle, &options);
    let witnesses = result.witnesses.as_ref().unwrap();
    assert_eq!(witnesses.status, "pass", "{:?}", result.witness_receipts);
    assert_eq!(
        result.witness_receipts[0].grade.as_deref(),
        Some("mmr-verified")
    );
    assert_eq!(result.verdict(), "VALID");
}

#[test]
fn a_repeated_record_is_not_a_second_identity() {
    let vectors = vectors();
    let mut bundle = vectors["cases"][0]["bundle"].clone();
    let records = bundle["records"].as_array_mut().unwrap();
    let first = records[0].clone();
    records.push(first.clone());
    let cid = first["capsule_id"].as_str().unwrap();
    let result = verify_bundle_strict(&bundle, &StrictOptions::default());
    assert_eq!(result.records.len(), 4);
    assert!(result.records[0].identity_ok);
    assert!(!result.records[3].identity_ok);
    let claim = result.claim("records").unwrap();
    assert_eq!(claim.status, "fail");
    assert_eq!(claim.findings, [format!("record_identity_invalid:{cid}")]);
    assert_eq!(result.verdict(), "INVALID");
}

#[test]
fn a_non_object_bundle_is_invalid_in_strict_mode() {
    let result = verify_bundle_strict(&json!([1]), &StrictOptions::default());
    assert_eq!(result.verdict(), "INVALID");
    assert!(!result.kind_ok);
    assert_eq!(result.claims[0].1.findings, ["not_an_evidence_bundle_v2"]);
}

// ---- witness edges the vectors do not reach (Python test_witness.py) --------

fn signed() -> SignedCheckpoint {
    SignedCheckpoint {
        log_id: "l".into(),
        mmr_size: 1,
        root: "00".repeat(32),
        key_id: "11".repeat(32),
        timestamp: "2026-10-15T00:00:00Z".into(),
        prev_size: 0,
        prev_root: String::new(),
    }
}

#[test]
fn bindings_and_endpoints_come_from_the_url_scheme() {
    assert_eq!(binding_of("https://w.example/"), "cll");
    assert_eq!(binding_of("REKOR+https://r.example"), "rekor");
    assert_eq!(binding_of("scrapi+https://s.example"), "scrapi");
    assert_eq!(binding_of("not a url"), "cll");
    assert_eq!(
        endpoint_of("scrapi+https://s.example/"),
        "https://s.example"
    );
}

#[test]
fn row_lookup_ignores_other_bindings_and_malformed_rows() {
    let directory = json!({"witnesses": ["junk", {"endpoint": "https://s.example/", "binding": "scrapi", "key_ids": []}]});
    assert!(row_for(Some(&directory), "https://s.example").is_none());
    assert!(row_for(Some(&directory), "scrapi+https://s.example").is_some());
    assert!(row_for(None, "https://s.example").is_none());
    let rows = json!([{"endpoint": "https://s.example"}]);
    assert!(row_for(Some(&rows), "https://s.example/").is_some());
}

#[test]
fn a_rekor_row_key_id_without_its_public_key_is_refused() {
    let rekor = json!({"name": "r", "binding": "rekor", "key_ids": ["22".repeat(32)]});
    assert!(row_public_keys(rekor.as_object().unwrap()).is_err());
    let cll = json!({"key_ids": ["22".repeat(32)]});
    assert_eq!(row_public_keys(cll.as_object().unwrap()).unwrap().len(), 1);
    let bad = json!({"key_ids": ["not hex"]});
    assert!(row_public_keys(bad.as_object().unwrap()).is_err());
}

#[test]
fn rekor_and_scrapi_receipts_need_the_checkpoint_cose() {
    let record = json!({"ts_url": "rekor+https://r.example", "receipt_b64": "", "entry_hash": "", "leaf_index": 0, "tree_size": 1});
    let check = verify_receipt(&signed(), record.as_object().unwrap(), &[], None);
    assert!(!check.ok);
    assert_eq!(
        check.reason,
        "not checked: checkpoint COSE statement not available"
    );
    assert_eq!(check.grade, None);
}

#[test]
fn scrapi_without_a_pinned_key_checks_nothing() {
    assert!(!verify_scrapi_receipt(&[], b"x", None).ok);
}

#[test]
fn unreadable_receipts_fail_and_never_panic() {
    let directory = json!({"witnesses": [{"endpoint": "https://r.example", "binding": "rekor",
        "key_ids": ["22".repeat(32)], "public_keys": ["not base64!"]}]});
    let record = json!({"ts_url": "rekor+https://r.example", "receipt_b64": "%%%",
        "entry_hash": "", "leaf_index": 0, "tree_size": 1});
    let report = verify_witness_receipts(
        Some(&json!([record])),
        Some(&signed()),
        Some(b"cose"),
        Some(&directory),
    );
    assert_eq!(report.status, "withheld");
    assert!(report.receipts[0]
        .reason
        .starts_with("not checked: unusable key"));

    // A cll row with a usable key and garbage receipts: each fails.
    let directory = json!([{"endpoint": "https://w.example", "key_ids": ["22".repeat(32)]}]);
    for receipt in ["%%%", "AAAA", ""] {
        let record = json!({"ts_url": "https://w.example", "receipt_b64": receipt,
            "entry_hash": "00", "leaf_index": 0, "tree_size": 1});
        let report = verify_witness_receipts(
            Some(&json!([record])),
            Some(&signed()),
            Some(b"cose"),
            Some(&directory),
        );
        assert_eq!(report.status, "fail", "{receipt}");
    }
}

#[test]
fn malformed_and_stub_entries() {
    let directory = json!([]);
    let entries = json!([
        {"ts_url": "https://w.example"},
        {"ts_url": "https://w.example", "receipt_b64": "", "entry_hash": "", "leaf_index": 0,
         "tree_size": 1, "is_stub": true},
    ]);
    let report = verify_witness_receipts(
        Some(&entries),
        Some(&signed()),
        Some(b"c"),
        Some(&directory),
    );
    assert_eq!(report.status, "fail");
    assert_eq!(
        report.findings,
        [
            "witness_receipt_malformed:0",
            "witness_unverified:https://w.example"
        ]
    );
    let none = verify_witness_receipts(Some(&json!([])), Some(&signed()), Some(b"c"), None);
    assert_eq!(none.findings, ["witness_receipt_absent"]);
    let unsigned = verify_witness_receipts(Some(&entries), None, None, None);
    assert_eq!(unsigned.findings, ["checkpoint_unverified"]);
}
