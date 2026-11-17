//! The cases of `vectors/inference-service-history-verdicts-v0` (the verdict counts member,
//! ISH §4.3, §5.3) over `agent_action_capsule::inference_history`: each case's definition and
//! History are checked, and a rejected one fails the one History property the case names.

use agent_action_capsule::inference_history::{check_artifact, Cut, Definition};
use base64::Engine;
use serde_json::{Map, Value};

fn cases() -> Vec<Value> {
    let path = format!(
        "{}/../../vectors/inference-service-history-verdicts-v0/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let corpus: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(
        corpus["count"].as_u64().unwrap() as usize,
        corpus["cases"].as_array().unwrap().len()
    );
    corpus["cases"].as_array().unwrap().clone()
}

fn octets(part: &Value) -> Value {
    serde_json::from_str(part["octets_text"].as_str().unwrap()).unwrap()
}

fn artifact(reply: &Value) -> Map<String, Value> {
    let envelope = octets(reply);
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(envelope["artifact"].as_str().unwrap().trim_end_matches('='))
        .unwrap();
    serde_json::from_slice::<Value>(&bytes)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

#[test]
fn every_case_is_checked_as_its_expected_block_says() {
    let all = cases();
    assert!(all.len() >= 13);
    let mut accepted = 0;
    for case in &all {
        let id = case["id"].as_str().unwrap();
        let def = Definition::from_document(&case["inputs"]["definition"])
            .unwrap_or_else(|e| panic!("{id}: the definition does not conform: {e}"));
        assert!(def.has_verdict_counts(), "{id}");
        let art = artifact(&case["inputs"]["reply"]);
        let history = art["history_card"]["history"].as_array().unwrap();
        let chain: Vec<Cut> = history
            .iter()
            .map(|h| Cut {
                timestamp: h["checkpoint"]["timestamp"].as_str().unwrap(),
                leaves: h["checkpoint"]["log_size"].as_u64().unwrap(),
            })
            .collect();
        let result = check_artifact(
            &def,
            &art,
            &chain,
            art["anchor"].as_str().unwrap(),
            art["evidence_stream"].as_str().unwrap(),
        );
        let fails: Vec<&str> = case["expected"]["fails"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f.as_str().unwrap())
            .collect();
        match (result, fails.as_slice()) {
            (Ok(counts), []) => {
                accepted += 1;
                assert!(counts.verdicts.is_some(), "{id}");
            }
            (Err(why), [property]) => {
                assert_eq!(why.split(':').next().unwrap(), *property, "{id}: {why}");
            }
            (other, expected) => panic!("{id}: expected {expected:?}, got {other:?}"),
        }
    }
    assert_eq!(accepted, 1, "one positive case");
}

#[test]
fn the_positive_case_counts_what_it_states() {
    let case = &cases()[0];
    assert_eq!(case["id"], "verdict-counts-held");
    let def = Definition::from_document(&case["inputs"]["definition"]).unwrap();
    let art = artifact(&case["inputs"]["reply"]);
    let history = art["history_card"]["history"].as_array().unwrap();
    let chain: Vec<Cut> = history
        .iter()
        .map(|h| Cut {
            timestamp: h["checkpoint"]["timestamp"].as_str().unwrap(),
            leaves: h["checkpoint"]["log_size"].as_u64().unwrap(),
        })
        .collect();
    let counts = check_artifact(
        &def,
        &art,
        &chain,
        art["anchor"].as_str().unwrap(),
        art["evidence_stream"].as_str().unwrap(),
    )
    .unwrap();
    let verdicts = counts.verdicts.unwrap();
    assert_eq!(verdicts.len(), 3);
    // Period 1: nine of H1 and six of H2 corroborated: a total of 15, published.
    let total = |period: usize, result: &str| {
        verdicts[period]
            .cells
            .iter()
            .find(|c| c.result == result && c.model_hash.is_none())
            .unwrap()
            .value
            .clone()
    };
    assert_eq!(total(0, "corroborated"), Ok(15));
    // Three contradicted is under the floor: withheld, never a count of 3.
    assert_eq!(total(0, "contradicted"), Err("below_floor".to_string()));
    // Period 2: 7 and 2 contradicted: the total of 9 is published, the 2 withheld, and the 7 with it.
    assert_eq!(total(1, "contradicted"), Ok(9));
    let mut reasons: Vec<String> = verdicts[1]
        .cells
        .iter()
        .filter(|c| c.result == "contradicted" && c.model_hash.is_some())
        .map(|c| c.value.clone().unwrap_err())
        .collect();
    reasons.sort();
    assert_eq!(reasons, ["below_floor", "complementary"]);
}
