// SPDX-License-Identifier: BSD-3-Clause
//! Evidence Bundle -02: `vectors/bundle/non-record-leaves`,
//! `vectors/bundle/certificate-mode` and `vectors/bundle/category-coverage`
//! through `verify_bundle_strict`, compared as
//! `python/tests/test_bundle_02_vectors.py` does, and the plain verifier's
//! readings of certificate modes as `python/tests/test_bundle_certificate_modes.py`
//! checks them.

use agent_action_capsule::bundle::{
    verify_bundle, verify_bundle_strict, verify_bundle_with, CategoryInputs, ClaimResult,
    StrictOptions, CATEGORY_COVERAGE_PROPERTIES, CERTIFICATE_MODE_UNSUPPORTED,
};
use agent_action_capsule::verify::decode_capsule_json;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

fn cases(directory: &str) -> Vec<Value> {
    let path = format!(
        "{}/../../vectors/bundle/{directory}/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let data = std::fs::read(&path).expect("vectors.json");
    let vectors = decode_capsule_json(&data).expect("valid JSON");
    let manifest_path = format!(
        "{}/../../vectors/bundle/{directory}/manifest.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(manifest_path).expect("manifest")).unwrap();
    let cases = vectors["cases"].as_array().expect("cases").clone();
    assert_eq!(json!(cases.len()), manifest["case_count"], "{directory}");
    cases
}

fn bundle_of(directory: &str, id: &str) -> Value {
    cases(directory)
        .into_iter()
        .find(|c| c["id"] == json!(id))
        .expect("case")["bundle"]
        .clone()
}

/// Compare through the canonical text so number spellings agree.
fn same(got: &Value, want: &Value) -> bool {
    let got: Value = serde_json::from_str(&got.to_string()).unwrap();
    let want: Value = serde_json::from_str(&want.to_string()).unwrap();
    got == want
}

fn observed(bundle: &Value, options: &StrictOptions) -> Value {
    let result = verify_bundle_strict(bundle, options);
    json!({
        "verdict": result.verdict(),
        "kind_ok": result.kind_ok,
        "claims": result.claims.iter().map(|(name, c)| json!({
            "name": name, "status": c.status, "findings": c.findings,
        })).collect::<Vec<_>>(),
        "witnesses": result.witnesses.as_ref().map(|w| json!({
            "status": w.status, "findings": w.findings, "receipts": [],
        })),
        "records": result.records.iter().map(|r| json!({
            "capsule_id": r.capsule_id, "identity_ok": r.identity_ok, "signature": r.signature,
            "key_id": r.key_id, "seq": r.seq,
        })).collect::<Vec<_>>(),
        "checkpoint_authenticated": result.checkpoint_authenticated(),
        "signer_matches_checkpoint": result.signer_matches_checkpoint,
    })
}

#[test]
fn every_certificate_case_matches() {
    let mut failures = Vec::new();
    let mut count = 0;
    for directory in ["non-record-leaves", "certificate-mode"] {
        for case in cases(directory) {
            count += 1;
            assert_eq!(
                case["options"],
                json!({"require_signature": false, "witness_directory": false})
            );
            let mut expect = json!({"kind_ok": true});
            for (k, v) in case["expect"].as_object().expect("expect") {
                expect[k] = v.clone();
            }
            let got = observed(&case["bundle"], &StrictOptions::default());
            if !same(&got, &expect) {
                failures.push(format!(
                    "{directory}/{}:\n  got  {got}\n  want {expect}",
                    case["id"]
                ));
            }
        }
    }
    assert_eq!(count, 34);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

struct Inputs {
    sets: Option<BTreeMap<String, Vec<String>>>,
    request: Option<Vec<u8>>,
    assigned: Option<BTreeMap<String, Option<String>>>,
}

impl Inputs {
    fn of(options: &Value) -> Self {
        Inputs {
            sets: options["category_sets"].as_object().map(|sets| {
                sets.iter()
                    .map(|(set, names)| {
                        let names = names.as_array().unwrap();
                        (
                            set.clone(),
                            names
                                .iter()
                                .map(|n| n.as_str().unwrap().to_string())
                                .collect(),
                        )
                    })
                    .collect()
            }),
            request: options["category_request"]
                .as_str()
                .map(|text| text.as_bytes().to_vec()),
            assigned: options["record_categories"].as_object().map(|assigned| {
                assigned
                    .iter()
                    .map(|(id, category)| (id.clone(), category.as_str().map(String::from)))
                    .collect()
            }),
        }
    }
    fn inputs(&self) -> CategoryInputs<'_> {
        CategoryInputs {
            category_sets: self.sets.as_ref(),
            category_request: self.request.as_deref(),
            record_categories: self.assigned.as_ref(),
        }
    }
}

fn coverage_value(coverage: &Option<Vec<(&'static str, &'static str)>>) -> Value {
    match coverage {
        None => Value::Null,
        Some(properties) => Value::Object(
            properties
                .iter()
                .map(|(name, value)| (name.to_string(), json!(value)))
                .collect::<Map<_, _>>(),
        ),
    }
}

#[test]
fn every_category_coverage_case_matches() {
    let mut failures = Vec::new();
    let all = cases("category-coverage");
    assert_eq!(all.len(), 32);
    for case in all {
        let inputs = Inputs::of(&case["options"]);
        let options = StrictOptions {
            category: inputs.inputs(),
            ..StrictOptions::default()
        };
        let result = verify_bundle_strict(&case["bundle"], &options);
        let got = json!({
            "verdict": result.verdict(),
            "category_coverage": coverage_value(&result.base.category_coverage),
        });
        if !same(&got, &case["expect"]) {
            failures.push(format!(
                "{}:\n  got  {got}\n  want {}",
                case["id"], case["expect"]
            ));
        }
        // The claims are the base Bundle's: the member changes none of them.
        assert!(
            result.claims.iter().all(|(_, c)| c.status == "pass"),
            "{}",
            case["id"]
        );
        if let Some(properties) = &result.base.category_coverage {
            let names: Vec<&str> = properties.iter().map(|(name, _)| *name).collect();
            assert_eq!(names, CATEGORY_COVERAGE_PROPERTIES, "report order");
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn property(bundle: &Value, inputs: &CategoryInputs, name: &str) -> &'static str {
    verify_bundle_with(bundle, inputs)
        .category_coverage
        .expect("member")
        .into_iter()
        .find(|(n, _)| *n == name)
        .expect("property")
        .1
}

#[test]
fn category_coverage_is_reported_in_plain_mode() {
    let case = cases("category-coverage")
        .into_iter()
        .find(|c| c["id"] == json!("neg-consistency-absent-with-record"))
        .unwrap();
    let inputs = Inputs::of(&case["options"]);
    let result = verify_bundle_with(&case["bundle"], &inputs.inputs());
    assert!(same(
        &coverage_value(&result.category_coverage),
        &case["expect"]["category_coverage"]
    ));
}

#[test]
fn a_non_canonical_root_fails_the_signature() {
    for root in ["1.5", "1152921504606846976"] {
        let mut bundle = bundle_of("category-coverage", "pos-all-six-statuses");
        bundle["root"] = serde_json::from_str(root).unwrap();
        assert_eq!(
            property(
                &bundle,
                &CategoryInputs::default(),
                "category_coverage_signature"
            ),
            "FAIL"
        );
        let strict = verify_bundle_strict(&bundle, &StrictOptions::default());
        assert_eq!(strict.verdict(), "INVALID");
    }
}

#[test]
fn an_ignored_member_does_not_fail_the_form() {
    let mut bundle = bundle_of("category-coverage", "unsigned-member");
    bundle["category_coverage"]["x-note"] = serde_json::from_str(r#"{"weight": 0.5}"#).unwrap();
    assert_eq!(
        property(
            &bundle,
            &CategoryInputs::default(),
            "category_coverage_form"
        ),
        "PASS"
    );
}

#[test]
fn the_request_is_read_strictly() {
    let bundle = bundle_of("category-coverage", "request-without-categories");
    let request = |octets: &[u8]| {
        let inputs = CategoryInputs {
            category_request: Some(octets),
            ..CategoryInputs::default()
        };
        property(&bundle, &inputs, "category_coverage_request")
    };
    for text in [
        r#"{"categories": NaN}"#,
        r#"{"categories": Infinity}"#,
        r#"{"a": {"b": 1, "b": 2}}"#,
        r#"[{"x": 1, "x": 1}]"#,
        r#"{"categories": {"set": "example-set", "names": ["messages"]}} {}"#,
        "[]",
        "",
        r#"{"categories": {"set": "example-set", "names": ["messages", "messages"]}}"#,
        r#"{"categories": {"set": "example-set", "names": []}}"#,
        r#"{"categories": {"set": 1, "names": ["messages"]}}"#,
    ] {
        assert_eq!(request(text.as_bytes()), "NOT_CHECKED", "{text}");
    }
    assert_eq!(request(b"{\"categories\": \"\xff\"}"), "NOT_CHECKED");
    assert_eq!(request(b"\xef\xbb\xbf{}"), "NOT_CHECKED");
    assert_eq!(request(b"{}"), "NOT_PRESENT");
    // The same member name in two objects is no repeat.
    assert_eq!(
        request(br#"{"a": {"x": 1}, "b": {"x": [{"x": 2}]}, "x": 3}"#),
        "NOT_PRESENT"
    );
}

#[test]
fn a_small_order_signer_key_is_refused() {
    // The identity point: it "verifies" a signature whose R is the identity
    // and S is zero over any message, in a verifier with no small-order check.
    let mut bundle = bundle_of("category-coverage", "pos-no-inputs");
    bundle["category_coverage"]["signer"] = json!({"key_id": format!("01{}", "00".repeat(31))});
    bundle["category_coverage"]["signature"] = json!(format!("01{}", "00".repeat(63)));
    assert_eq!(
        property(
            &bundle,
            &CategoryInputs::default(),
            "category_coverage_signature"
        ),
        "FAIL"
    );
}

fn claim(status: &str, findings: &[&str]) -> ClaimResult {
    ClaimResult {
        status: status.to_string(),
        findings: findings.iter().map(|f| f.to_string()).collect(),
    }
}

fn plain(bundle: &Value) -> (ClaimResult, ClaimResult) {
    let result = verify_bundle(bundle);
    (result.interval_coverage, result.per_record_membership)
}

fn selected() -> Value {
    bundle_of(
        "certificate-mode",
        "incomplete-producer-selected-padded-log",
    )
}

#[test]
fn a_plain_producer_selected_bundle_is_not_a_failure() {
    let not_checkable = claim("withheld", &["selection_not_checkable"]);
    assert_eq!(plain(&selected()), (not_checkable, claim("pass", &[])));

    let mut unsigned = selected();
    unsigned["checkpoint"]
        .as_object_mut()
        .unwrap()
        .remove("cose");
    assert_eq!(
        plain(&unsigned).1,
        claim("pass", &["checkpoint_unverified"])
    );

    let mut bad = selected();
    let cose = bad["checkpoint"]["cose"].as_str().unwrap().to_string();
    bad["checkpoint"]["cose"] = json!(format!("{}AAAA", &cose[..cose.len() - 4]));
    assert_eq!(
        plain(&bad).1,
        claim("fail", &["checkpoint_authentication_invalid"])
    );

    let tampered = bundle_of(
        "certificate-mode",
        "neg-producer-selected-padded-log-tampered",
    );
    let finding = format!(
        "membership_proof_invalid:{}",
        tampered["root"].as_str().unwrap()
    );
    assert_eq!(plain(&tampered).1, claim("fail", &[&finding]));
}

#[test]
fn the_plain_producer_selected_root_and_log_id_are_the_checkpoints() {
    let invalid = claim("fail", &["completeness_certificate_invalid"]);
    let mut other_root = selected();
    other_root["checkpoint"]
        .as_object_mut()
        .unwrap()
        .remove("cose");
    other_root["checkpoint"]["root"] = json!("00".repeat(32));
    assert_eq!(plain(&other_root).1, invalid);

    let mut no_log_id = selected();
    no_log_id["checkpoint"]
        .as_object_mut()
        .unwrap()
        .remove("cose");
    no_log_id["completeness_certificate"]
        .as_object_mut()
        .unwrap()
        .remove("log_id");
    assert_eq!(plain(&no_log_id).1, invalid);

    let mut object_root = selected();
    object_root["checkpoint"]["root"] = json!({});
    object_root["completeness_certificate"]["range_root"] = json!({});
    assert_eq!(plain(&object_root).1, invalid);

    let mut negative = selected();
    negative["checkpoint"]
        .as_object_mut()
        .unwrap()
        .remove("cose");
    negative["checkpoint"]["mmr_size"] = json!(-1);
    assert_eq!(plain(&negative).1.status, "fail");
}

#[test]
fn an_unknown_mode_is_withheld() {
    let unsupported = claim("withheld", &[CERTIFICATE_MODE_UNSUPPORTED]);
    for value in [
        json!("x-sampled"),
        json!(7),
        json!(""),
        json!({"mode": "producer-selected"}),
        Value::Null,
    ] {
        let mut bundle = selected();
        bundle["completeness"]["selection"] = value.clone();
        assert_eq!(
            plain(&bundle),
            (unsupported.clone(), unsupported.clone()),
            "{value}"
        );
    }
    let mut null = bundle_of("certificate-mode", "incomplete-certificate-mode-null");
    assert_eq!(plain(&null), (unsupported.clone(), unsupported));
    null["completeness"]
        .as_object_mut()
        .unwrap()
        .remove("selection");
    assert_eq!(plain(&null), (claim("pass", &[]), claim("pass", &[])));
}

#[test]
fn a_plain_padded_range_passes_and_an_unknown_type_withholds() {
    assert_eq!(
        plain(&bundle_of("non-record-leaves", "pos-padded-whole-log")),
        (claim("pass", &[]), claim("pass", &[]))
    );
    let mut unknown = bundle_of("non-record-leaves", "incomplete-unknown-leaf-type");
    assert_eq!(
        plain(&unknown).1,
        claim("withheld", &["non_record_leaf_type_unsupported:20"])
    );
    unknown["checkpoint"]
        .as_object_mut()
        .unwrap()
        .remove("cose");
    assert_eq!(
        plain(&unknown).1,
        claim(
            "withheld",
            &[
                "non_record_leaf_type_unsupported:20",
                "checkpoint_unverified"
            ]
        )
    );
}

#[test]
fn the_member_on_a_producer_selected_bundle_is_invalid_signed_or_not() {
    let invalid = claim("fail", &["completeness_certificate_invalid"]);
    let mut bundle = bundle_of(
        "non-record-leaves",
        "neg-non-record-leaves-on-producer-selected",
    );
    assert_eq!(plain(&bundle).1, invalid);
    bundle["checkpoint"].as_object_mut().unwrap().remove("cose");
    let strict = verify_bundle_strict(&bundle, &StrictOptions::default());
    assert_eq!(strict.claim("per_record_membership"), Some(&invalid));
    assert_eq!(strict.verdict(), "INVALID");
}

#[test]
fn unknown_certificate_members_are_ignored() {
    let mut bundle = bundle_of("non-record-leaves", "pos-padded-whole-log");
    bundle["completeness_certificate"]["x-note"] = json!({"anything": [1, 2]});
    bundle["completeness_certificate"]["non_record_leaves"][0]["x-note"] = json!("ignored");
    assert_eq!(
        verify_bundle_strict(&bundle, &StrictOptions::default()).verdict(),
        "VALID"
    );
}

// Cases the vectors leave out, each pinned to what the Python reference
// reports for the same edit.

#[test]
fn a_non_record_leaf_below_the_interval_is_a_seq_invalid() {
    let mut bundle = bundle_of("non-record-leaves", "pos-padded-suffix");
    let leaves = bundle["completeness_certificate"]["non_record_leaves"]
        .as_array_mut()
        .unwrap();
    let content = leaves[0]["content"].clone();
    leaves.push(json!({"seq": 5, "content": content}));
    let strict = verify_bundle_strict(&bundle, &StrictOptions::default());
    assert_eq!(
        strict.claim("per_record_membership"),
        Some(&claim("fail", &["non_record_leaf_seq_invalid:56"]))
    );
}

#[test]
fn a_padding_capsule_id_in_uppercase_is_malformed() {
    let mut bundle = bundle_of("non-record-leaves", "pos-padded-whole-log");
    let content = &mut bundle["completeness_certificate"]["non_record_leaves"][0]["content"];
    content["capsule_id"] = json!(content["capsule_id"].as_str().unwrap().to_uppercase());
    let strict = verify_bundle_strict(&bundle, &StrictOptions::default());
    assert_eq!(
        strict.claim("per_record_membership"),
        Some(&claim("fail", &["non_record_leaf_malformed:6"]))
    );
}

/// A named edit of a `category_coverage` member.
type Edit = (&'static str, fn(&mut Value));

#[test]
fn the_category_coverage_form_edges_fail() {
    let edits: [Edit; 6] = [
        ("empty set", |m| m["set"] = json!("")),
        ("empty name", |m| {
            m["categories"][""] = json!({"status": "AVAILABLE"});
        }),
        ("policy_uri not a string", |m| {
            m["categories"]["messages"]["policy_uri"] = json!(["https://example.com/policy"]);
        }),
        ("key_id in uppercase", |m| {
            let upper = m["signer"]["key_id"].as_str().unwrap().to_uppercase();
            m["signer"]["key_id"] = json!(upper);
        }),
        ("signature without signer", |m| {
            m.as_object_mut().unwrap().remove("signer");
        }),
        ("signature one digit short", |m| {
            let short = m["signature"].as_str().unwrap()[1..].to_string();
            m["signature"] = json!(short);
        }),
    ];
    for (name, edit) in edits {
        let mut bundle = bundle_of("category-coverage", "pos-no-inputs");
        edit(&mut bundle["category_coverage"]);
        assert_eq!(
            property(
                &bundle,
                &CategoryInputs::default(),
                "category_coverage_form"
            ),
            "FAIL",
            "{name}"
        );
    }
}

#[test]
fn a_requested_name_that_is_not_utf8_is_not_read() {
    let bundle = bundle_of("category-coverage", "request-without-categories");
    let request = |octets: &[u8]| {
        let inputs = CategoryInputs {
            category_request: Some(octets),
            ..CategoryInputs::default()
        };
        property(&bundle, &inputs, "category_coverage_request")
    };
    assert_eq!(
        request(b"{\"categories\": {\"set\": \"example-set\", \"names\": [\"\xff\"]}}"),
        "NOT_CHECKED"
    );
    assert_eq!(
        request(br#"{"categories": {"set": "example-set", "names": ["nope"]}}"#),
        "FAIL"
    );
}

#[test]
fn a_fifth_content_member_is_malformed_whatever_its_name() {
    let mut bundle = bundle_of("non-record-leaves", "pos-padded-whole-log");
    // "zz" sorts after every padding member.
    bundle["completeness_certificate"]["non_record_leaves"][0]["content"]["zz"] = json!(1);
    let strict = verify_bundle_strict(&bundle, &StrictOptions::default());
    assert_eq!(
        strict.claim("per_record_membership"),
        Some(&claim("fail", &["non_record_leaf_malformed:6"]))
    );
}

#[test]
fn a_record_type_that_is_not_a_string_is_malformed() {
    let mut bundle = bundle_of("non-record-leaves", "pos-padded-whole-log");
    bundle["completeness_certificate"]["non_record_leaves"][0]["content"]["record_type"] = json!(7);
    let strict = verify_bundle_strict(&bundle, &StrictOptions::default());
    assert_eq!(
        strict.claim("per_record_membership"),
        Some(&claim("fail", &["non_record_leaf_malformed:6"]))
    );
}
