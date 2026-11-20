// SPDX-License-Identifier: BSD-3-Clause
//! Runs `vectors/card-registration-v0/vectors.json` (standard-history-v0
//! §13) through `witness::check_card_registered`, as Python does.

use agent_action_capsule::witness::{
    check_card_registered, check_card_statement, CARD_REGISTERED_METHOD,
};
use serde_json::{json, Value};

fn hex_field(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex string")).expect("hex")
}

fn corpus() -> Value {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/card-registration-v0/vectors.json"
    ))
    .expect("vectors/card-registration-v0/vectors.json");
    serde_json::from_slice(&data).expect("valid JSON")
}

#[test]
fn card_registration_vectors() {
    let corpus = corpus();
    let cases = corpus["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 49);
    for case in cases {
        let policy = match &case["policy"] {
            Value::String(name) => &corpus["policies"][name.as_str()],
            inline => inline,
        };
        let statements: Vec<Vec<u8>> = case["statements"]
            .as_array()
            .expect("statements")
            .iter()
            .map(hex_field)
            .collect();
        let report = check_card_registered(
            &hex_field(&case["card"]),
            case["holder"].as_str().expect("holder"),
            case["anchor"].as_str().expect("anchor"),
            &statements,
            policy,
        );
        assert_eq!(report.method, CARD_REGISTERED_METHOD);
        let observed = json!({
            "status": report.status,
            "statements": report.statements.iter().map(|r| json!({
                "status": r.status,
                "service": r.service,
                "registration_time": r.registration_time,
            })).collect::<Vec<_>>(),
            "service": report.service,
            "registration_time": report.registration_time,
        });
        // Compare as plain JSON values: arbitrary_precision keeps number text.
        let expected: Value =
            serde_json::from_str(&case["expected"].to_string()).expect("expected");
        let observed: Value = serde_json::from_str(&observed.to_string()).expect("observed");
        assert_eq!(observed, expected, "{}", case["name"]);
    }
}

/// Step 2 of §13.3: a statement whose `sub` is not the envelope's
/// `anchor.digest` fails, though it passes under the right anchor.
#[test]
fn card_statement_under_another_anchor_fails() {
    let corpus = corpus();
    let case = corpus["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["name"] == "pass-eddsa-time")
        .expect("pass-eddsa-time");
    let policy = &corpus["policies"]["default"];
    let card = hex_field(&case["card"]);
    let holder = case["holder"].as_str().expect("holder");
    let anchor = case["anchor"].as_str().expect("anchor");
    let statement = hex_field(&case["statements"][0]);
    assert_eq!(
        check_card_statement(&card, holder, anchor, &statement, policy).status,
        "PASS"
    );
    let other = format!(
        "{}{}",
        if anchor.starts_with('0') { "1" } else { "0" },
        &anchor[1..]
    );
    assert_eq!(
        check_card_statement(&card, holder, &other, &statement, policy).status,
        "FAIL"
    );
    let report = check_card_registered(&card, holder, &other, &[statement], policy);
    assert_eq!(report.status, "FAIL");
    assert_eq!(report.service, None);
    assert_eq!(report.registration_time, None);
}
