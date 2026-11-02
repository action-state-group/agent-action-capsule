// SPDX-License-Identifier: BSD-3-Clause
//! Runs `vectors/bundle/parent-log-witness/vectors.json`: every case through
//! `verify_bundle_strict`, compared as
//! `vectors/bundle/parent-log-witness/README.md` ("How to consume them")
//! says.

use agent_action_capsule::bundle::{
    verify_bundle, verify_bundle_strict, StrictOptions, PARENT_LOG_WITNESS_KIND,
};
use agent_action_capsule::verify::decode_capsule_json;
use serde_json::{json, Value};

fn vectors() -> Value {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/bundle/parent-log-witness/vectors.json"
    ))
    .expect("vectors/bundle/parent-log-witness/vectors.json");
    decode_capsule_json(&data).expect("valid JSON")
}

/// The observed result, restricted to the members the case's `expect` names.
fn observed(bundle: &Value, options: &StrictOptions, expect: &Value) -> Value {
    let result = verify_bundle_strict(bundle, options);
    let parent_witness = result.parent_witness.as_ref().map(|p| {
        json!({
            "status": p.status,
            "findings": p.findings,
            "extent": p.extent.map(|e| json!({"entries": e.entries, "of": e.of})),
            "receipts": p.receipts.iter().map(|r| json!({
                "ts_url": r.ts_url, "binding": r.binding, "status": r.status, "grade": r.grade,
                "key_id": r.key_id, "registration_time": r.registration_time,
                "registration_time_reason": r.registration_time_reason,
            })).collect::<Vec<_>>(),
        })
    });
    let mut got = json!({"verdict": result.verdict(), "parent_witness": parent_witness});
    if expect.get("extension_status").is_some() {
        got["extension_status"] = result
            .base
            .extensions
            .iter()
            .find(|e| e.kind == PARENT_LOG_WITNESS_KIND)
            .map_or(Value::Null, |e| json!(e.status));
    }
    if expect.get("witnesses").is_some() {
        got["witnesses"] = result.witnesses.as_ref().map_or(
            Value::Null,
            |w| json!({"status": w.status, "findings": w.findings}),
        );
    }
    got
}

#[test]
fn every_parent_witness_case_matches() {
    let vectors = vectors();
    let directory = &vectors["witness_directory"];
    let cases = vectors["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 36);
    let mut failures = Vec::new();
    for case in cases {
        let options = StrictOptions {
            witness_directory: (case["options"]["witness_directory"] == json!(true))
                .then_some(directory),
            ..StrictOptions::default()
        };
        let expect = &case["expect"];
        // Compare through the canonical text so number spellings agree.
        let got = observed(&case["bundle"], &options, expect);
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
fn plain_mode_leaves_the_extension_uninterpreted() {
    let vectors = vectors();
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "pos-witnessed-whole")
        .expect("pos-witnessed-whole");
    let plain = verify_bundle(&case["bundle"]);
    let extension = plain
        .extensions
        .iter()
        .find(|e| e.kind == PARENT_LOG_WITNESS_KIND)
        .expect("the extension is reported");
    assert_eq!(extension.status, "uninterpreted");
}
