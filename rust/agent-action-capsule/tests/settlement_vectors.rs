// SPDX-License-Identifier: BSD-3-Clause
//! Runs `settlement::verify_settlements` on every case of
//! `vectors/settlement/cases.json`, comparing everything in `expect`, as the
//! Python reference's `test_settlement_library.py` does.

use agent_action_capsule::settlement::{
    verify_settlements, Failure, SettlementOptions, DELIVERY_DIRECTIONS, LEGS, MEMBERS,
    PAYMENT_REF_TYPES, ROLES, SETTLEMENT_VERSION, STATUSES, WRAPPED_TYPES,
};
use agent_action_capsule::verify::decode_capsule_json;
use base64::Engine as _;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};

fn load(name: &str) -> Value {
    let path = format!(
        "{}/../../vectors/settlement/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    decode_capsule_json(&std::fs::read(&path).expect(name)).expect("valid JSON")
}

#[test]
fn tables_match_the_draft_registry() {
    let registry = load("registry.json");
    assert_eq!(registry["settlement_version"], json!(SETTLEMENT_VERSION));
    assert_eq!(registry["legs"], json!(LEGS));
    assert_eq!(registry["sealer_roles"], json!(ROLES));
    assert_eq!(registry["statuses"], json!(STATUSES));
    let directions: Map<String, Value> = DELIVERY_DIRECTIONS
        .iter()
        .map(|(d, r)| (d.to_string(), json!(r)))
        .collect();
    assert_eq!(registry["delivery_directions"], Value::Object(directions));
    let wrapped: Map<String, Value> = WRAPPED_TYPES
        .iter()
        .map(|(t, issuer)| (t.to_string(), json!(issuer)))
        .collect();
    assert_eq!(registry["wrapped_types"], Value::Object(wrapped));
    let types = registry["payment_ref_types"].as_object().unwrap();
    assert_eq!(types.len(), PAYMENT_REF_TYPES.len());
    for t in PAYMENT_REF_TYPES {
        assert_eq!(
            types[t.name]["qualifiers"],
            json!(t.qualifiers),
            "{}",
            t.name
        );
        assert_eq!(
            types[t.name]["receive_fee"],
            json!(t.receive_fee),
            "{}",
            t.name
        );
    }
    let members = registry["settlement_members"].as_object().unwrap();
    assert_eq!(members.len(), MEMBERS.len());
    for m in MEMBERS {
        assert_eq!(members[m.leg]["required"], json!(m.required), "{}", m.leg);
        assert_eq!(members[m.leg]["optional"], json!(m.optional), "{}", m.leg);
    }
}

fn run(case: &Value) -> Value {
    let mut capsules = Vec::new();
    let mut labels: HashMap<Option<String>, String> = HashMap::new();
    for record in case["records"].as_array().unwrap() {
        let mut capsule = record["capsule"].clone();
        if record["envelope_hex"]
            .as_str()
            .is_some_and(|h| !h.is_empty())
        {
            capsule["signature"] = record["envelope_hex"].clone();
            capsule["key_id"] = record["envelope_kid"].clone();
        }
        capsules.push(capsule);
        labels.insert(
            record["capsule_id"].as_str().map(String::from),
            record["label"].as_str().unwrap().to_string(),
        );
    }
    let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let wrapped_objects: BTreeMap<String, Vec<u8>> = case["wrapped_objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| {
            (
                w["digest"].as_str().unwrap().to_string(),
                b64u.decode(w["octets_b64u"].as_str().unwrap()).unwrap(),
            )
        })
        .collect();
    let key_policy = case["key_policy"].as_object().map(|p| {
        p.iter()
            .map(|(role, keys)| {
                let keys = match keys {
                    Value::String(k) => vec![k.clone()],
                    other => other
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|k| k.as_str().unwrap().to_string())
                        .collect(),
                };
                (role.clone(), keys)
            })
            .collect()
    });
    let report = verify_settlements(
        &capsules,
        &SettlementOptions {
            key_policy,
            wrapped_objects,
        },
    );
    let relabel = |entries: &[Failure]| -> Vec<Value> {
        entries
            .iter()
            .map(|e| {
                let records: Vec<Value> = e
                    .records
                    .iter()
                    .map(|c| match labels.get(c) {
                        Some(label) => json!(label),
                        None => json!(c),
                    })
                    .collect();
                json!({"records": records, "code": e.code})
            })
            .collect()
    };
    let settlements: Vec<Value> = report
        .settlements
        .iter()
        .map(|s| {
            let mut s = s.to_json();
            let map = s.as_object_mut().unwrap();
            map.remove("iso20022"); // not carried by the vectors
            let terms = map["terms"].as_str().unwrap().to_string();
            map.insert("terms".into(), json!(labels[&Some(terms)]));
            s
        })
        .collect();
    json!({
        "conforming": report.conforming,
        "failures": relabel(&report.failures),
        "findings": relabel(&report.findings),
        "settlements": settlements,
    })
}

#[test]
fn every_case_matches_its_expect() {
    let cases = load("cases.json");
    let list = cases["cases"].as_array().unwrap();
    assert_eq!(list.len(), 24);
    assert_eq!(cases["count"], json!(24));
    let mut failures = Vec::new();
    for case in list {
        let got = run(case);
        if got != case["expect"] {
            failures.push(format!(
                "{}:\n  got  {got}\n  want {}",
                case["id"], case["expect"]
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
