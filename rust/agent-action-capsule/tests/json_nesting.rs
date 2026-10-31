//! `vectors/json-nesting/`: the decoder reads objects and arrays nested up to
//! 128 levels deep and refuses deeper text, JCS refuses a deeper value, and
//! Class 1 verification refuses a deeper Capsule with only
//! `verifier_internal_error`, as Go, Python and TypeScript do.

use agent_action_capsule::canonical::{jcs, CanonicalError};
use agent_action_capsule::verify::{decode_capsule_json, verify};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

fn cases() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/json-nesting/cases.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// `value` inside one more container of the kind `text` opens with: an array,
/// or an object whose one member is `a`.
fn wrap(text: &str, value: Value) -> Value {
    if text.starts_with('[') {
        Value::Array(vec![value])
    } else {
        Value::Object(Map::from_iter([("a".to_string(), value)]))
    }
}

#[test]
fn json_nesting_vectors() {
    let doc = cases();
    assert_eq!(doc["max_nesting_depth"], 128);
    let all = doc["cases"].as_array().unwrap();
    assert_eq!(all.len(), 9);
    for case in all {
        let id = case["id"].as_str().unwrap();
        let text = case["json"].as_str().unwrap();
        let decoded = decode_capsule_json(text.as_bytes());
        if case["accept"].as_bool().unwrap() {
            let value = decoded.unwrap_or_else(|e| panic!("{id}: {e}"));
            let canonical = jcs(&value).unwrap();
            assert_eq!(
                hex::encode(Sha256::digest(&canonical)),
                case["jcs_sha256"].as_str().unwrap(),
                "{id}"
            );
        } else {
            assert!(decoded.is_err(), "{id} was read");
            let twin = all
                .iter()
                .find(|c| c["id"] == case["wraps"])
                .unwrap_or_else(|| panic!("{id}: no wrapped case"));
            let inner = decode_capsule_json(twin["json"].as_str().unwrap().as_bytes()).unwrap();
            let deeper = wrap(text, inner);
            assert_eq!(jcs(&deeper), Err(CanonicalError::TooDeep), "{id}");
            let result = verify(&json!({ "deep": deeper }), None);
            assert!(!result.ok, "{id}");
            let codes: Vec<&str> = result.findings.iter().map(|f| f.code.as_str()).collect();
            assert_eq!(codes, ["verifier_internal_error"], "{id}");
        }
    }
}

#[test]
fn a_capsule_at_the_limit_is_verified() {
    // `{"deep": <127 levels>}` nests 128 levels: verified as usual, so the
    // findings are the ordinary ones, not verifier_internal_error.
    let doc = cases();
    let text = doc["cases"][0]["json"].as_str().unwrap();
    let inner = decode_capsule_json(&text.as_bytes()[1..text.len() - 1]).unwrap();
    let result = verify(&json!({ "deep": inner }), None);
    assert!(result
        .findings
        .iter()
        .all(|f| f.code != "verifier_internal_error"));
}
