//! `vectors/evidence-request/history-card-2.json` (ER -03 §8.1.2): the
//! positions P(n, W), and `cll_material::check_history_card_2` on every
//! card.

use evidence_request::cll_material::check_history_card_2;
use evidence_request::history_card::{positions, FINDINGS, MAX_WINDOW};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;

fn corpus() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/evidence-request/history-card-2.json");
    serde_json::from_slice(&std::fs::read(path).expect("read")).expect("parse")
}

#[test]
fn header_and_positions() {
    let c = corpus();
    assert_eq!(c["draft"], "draft-mih-agent-evidence-request-03");
    assert_eq!(c["max_window"].as_u64(), Some(MAX_WINDOW));
    let findings: Vec<&str> = c["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert_eq!(findings, FINDINGS);
    let rows = c["positions"].as_array().unwrap();
    assert!(!rows.is_empty());
    for row in rows {
        let (n, w) = (row["n"].as_u64().unwrap(), row["window"].as_u64().unwrap());
        let want: Vec<u64> = row["positions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_u64().unwrap())
            .collect();
        assert_eq!(positions(n, w), want, "n {n} window {w}");
    }
}

#[test]
fn every_card() {
    let c = corpus();
    let keys: Vec<String> = c["log_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();
    let cases = c["cases"].as_array().unwrap();
    assert_eq!(c["count"].as_u64(), Some(cases.len() as u64));
    let mut seen = BTreeSet::new();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let got = check_history_card_2(&case["card"], case["anchor"].as_str().unwrap(), &keys);
        let want = case["expect"]["finding"].as_str();
        assert_eq!(got, want, "{id}");
        assert_eq!(
            got.is_none(),
            case["expect"]["valid"] == Value::Bool(true),
            "{id}"
        );
        if let Some(f) = got {
            seen.insert(f);
        }
    }
    assert_eq!(
        seen,
        FINDINGS.into_iter().collect(),
        "a case for every finding"
    );
}
