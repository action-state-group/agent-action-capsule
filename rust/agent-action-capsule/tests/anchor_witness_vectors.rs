// SPDX-License-Identifier: BSD-3-Clause
//! Runs `vectors/anchor-witness-v1/vectors.json` (profile v1 §6.2.2) through
//! `witness::check_anchor_witnessed`, as Python, Go and TypeScript do.

use agent_action_capsule::witness::check_anchor_witnessed;
use serde_json::{json, Value};

#[test]
fn anchor_witness_vectors() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/anchor-witness-v1/vectors.json"
    ))
    .expect("vectors/anchor-witness-v1/vectors.json");
    let corpus: Value = serde_json::from_slice(&data).expect("valid JSON");
    let cases = corpus["cases"].as_array().expect("cases");
    assert!(!cases.is_empty());
    for case in cases {
        let policy = match &case["policy"] {
            Value::String(name) => &corpus["policies"][name.as_str()],
            inline => inline,
        };
        let receipts: Vec<Vec<u8>> = case["receipts"]
            .as_array()
            .expect("receipts")
            .iter()
            .map(|r| hex::decode(r.as_str().expect("hex")).expect("hex"))
            .collect();
        let report =
            check_anchor_witnessed(case["anchor"].as_str().expect("anchor"), &receipts, policy);
        let observed = json!({
            "status": report.status,
            "receipts": report.receipts.iter().map(|r| json!({
                "status": r.status,
                "witness": r.witness,
                "registration_time": r.registration_time,
            })).collect::<Vec<_>>(),
            "witness": report.witness,
            "witnessed_time": report.witnessed_time,
        });
        // Compare as plain JSON values: arbitrary_precision keeps number text.
        let expected: Value =
            serde_json::from_str(&case["expected"].to_string()).expect("expected");
        let observed: Value = serde_json::from_str(&observed.to_string()).expect("observed");
        assert_eq!(observed, expected, "{}", case["name"]);
    }
}
