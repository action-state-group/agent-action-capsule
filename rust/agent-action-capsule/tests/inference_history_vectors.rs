//! The Standard cases of `vectors/inference-service-history-v0` and
//! `vectors/inference-service-history-v0-interop-v1` over
//! `agent_action_capsule::inference_history`.
//!
//! Each case's `period_policy` is taken from the definition the case hands
//! over. 13 History cases and the 3 pairs run per set; the 7 Detailed-level
//! History cases and the Detailed refusal are listed by id, not run, since
//! this module is the Standard level. `period_fixed` over a pair is evaluated
//! here from two checked [`Counts`], as the module leaves it to its caller.

use agent_action_capsule::inference_history::{Counts, Definition};
use base64::Engine;
use serde_json::{json, Map, Value};

const SETS: [&str; 2] = [
    "inference-service-history-v0",
    "inference-service-history-v0-interop-v1",
];

fn cases(set: &str) -> Vec<Value> {
    let path = format!(
        "{}/../../vectors/{set}/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let corpus: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(
        corpus["count"].as_u64().unwrap() as usize,
        corpus["cases"].as_array().unwrap().len()
    );
    corpus["cases"].as_array().unwrap().clone()
}

fn id(case: &Value) -> &str {
    case["id"].as_str().unwrap()
}

/// The JSON a case carries as octets.
fn octets(part: &Value) -> Value {
    serde_json::from_str(part["octets_text"].as_str().unwrap()).unwrap()
}

/// The artifact of a case's reply envelope.
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

/// The property a failed check names: the word before the first `:`.
fn failed_property(why: &str) -> &str {
    why.split(':').next().unwrap()
}

/// Check one History as the case hands it over: its definition's policy,
/// then every rule over its artifact.
fn check_history(definition: &Value, reply: &Value) -> Result<Counts, String> {
    let def = Definition::from_document(definition)?;
    let art = artifact(reply);
    let history = art["history_card"]["history"].as_array().unwrap();
    let times: Vec<&str> = history
        .iter()
        .map(|h| h["checkpoint"]["timestamp"].as_str().unwrap())
        .collect();
    let log_size = history.last().unwrap()["checkpoint"]["log_size"]
        .as_u64()
        .unwrap();
    assert_eq!(
        art["derivation"],
        json!(def.digest()),
        "a reply names its definition by digest"
    );
    agent_action_capsule::inference_history::check_artifact(
        &def,
        &art,
        &times,
        art["anchor"].as_str().unwrap(),
        art["evidence_stream"].as_str().unwrap(),
        log_size,
    )
}

/// `period_fixed` (ISH §6.1 item 4, §8.3) over two Histories of one node,
/// the earlier first: every period of the earlier is in the later, with the
/// same cells.
fn period_fixed(earlier: &Counts, later: &Counts) -> bool {
    earlier
        .periods
        .iter()
        .all(|p| later.periods.iter().any(|q| q == p))
}

fn expected_failure(expected: &Value) -> Option<&str> {
    let fails = expected["fails"].as_array().unwrap();
    assert!(fails.len() <= 1, "a case fails one property");
    fails.first().map(|f| f.as_str().unwrap())
}

fn is_standard(case: &Value) -> bool {
    case["inputs"]["definition"]["level"] == json!("standard")
}

#[test]
fn the_standard_histories_check_as_the_vectors_expect() {
    for set in SETS {
        let mut run = 0;
        for case in cases(set)
            .iter()
            .filter(|c| c["kind"] == json!("history") && is_standard(c))
        {
            let got = check_history(&case["inputs"]["definition"], &case["inputs"]["reply"]);
            // `definition_form` and `definition_binding` pass in every case.
            match (expected_failure(&case["expected"]), got) {
                (None, Ok(_)) => {}
                (Some(want), Err(why)) => {
                    assert_eq!(failed_property(&why), want, "{set} {}: {why}", id(case))
                }
                (want, got) => panic!("{set} {}: expected {want:?}, got {got:?}", id(case)),
            }
            run += 1;
        }
        assert_eq!(run, 13, "{set}");
    }
}

#[test]
fn the_periods_of_a_pair_are_fixed_as_the_vectors_expect() {
    for set in SETS {
        let mut run = 0;
        for case in cases(set).iter().filter(|c| c["kind"] == json!("pair")) {
            let histories = case["inputs"]["histories"].as_array().unwrap();
            assert_eq!(histories.len(), 2, "{}: not two Histories", id(case));
            let checked: Vec<Result<Counts, String>> = histories
                .iter()
                .map(|h| check_history(&h["definition"], &h["reply"]))
                .collect();
            let want = case["expected"]["period_fixed"].as_str().unwrap();
            let fixed = match (&checked[0], &checked[1]) {
                (Ok(earlier), Ok(later)) => period_fixed(earlier, later),
                // A period dropped at the later anchor leaves that History's
                // periods short of the closed ones: the check refuses it as
                // `period_alignment` before the pair is compared, which is
                // `period_fixed` failing all the same.
                (Ok(_), Err(why)) => {
                    assert_eq!(failed_property(why), "period_alignment", "{}", id(case));
                    false
                }
                (earlier, later) => panic!("{}: {earlier:?} {later:?}", id(case)),
            };
            assert_eq!(fixed, want == "PASS", "{set} {}", id(case));
            run += 1;
        }
        assert_eq!(run, 3, "{set}");
    }
}

/// The time of the checkpoint a pin names, in any case's card: the pin is
/// the digest of the checkpoint (README, "history card").
fn pinned_time(cases: &[Value], pin: &str) -> String {
    use sha2::{Digest, Sha256};
    for case in cases {
        let replies: Vec<Value> = match case["kind"].as_str().unwrap() {
            "pair" => case["inputs"]["histories"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| h["reply"].clone())
                .collect(),
            _ => vec![case["inputs"]["reply"].clone()],
        };
        for reply in replies {
            if octets(&reply).get("artifact").is_none() {
                continue;
            }
            for entry in artifact(&reply)["history_card"]["history"]
                .as_array()
                .unwrap()
            {
                let text = String::from_utf8(
                    agent_action_capsule::canonical::jcs(&entry["checkpoint"]).unwrap(),
                )
                .unwrap();
                if hex::encode(Sha256::digest(text.as_bytes())) == pin {
                    return entry["checkpoint"]["timestamp"]
                        .as_str()
                        .unwrap()
                        .to_string();
                }
            }
        }
    }
    panic!("no case holds the checkpoint {pin}");
}

/// A Standard History is a run of whole closed periods at one pinned anchor:
/// any other subject or coverage is declined, and so is a pin off a period
/// boundary, each `policy_declined` the same for every requester (ISH §6.1
/// items 2 and 5). The Detailed refusal is not this level's.
#[test]
fn the_standard_refusals_are_policy_declined() {
    for set in SETS {
        let all = cases(set);
        let mut run = 0;
        for case in all.iter().filter(|c| {
            // `capacity_exceeded` is a node's own load, which no derivation here decides.
            c["kind"] == json!("refusal")
                && c["inputs"]["definition"]["level"] == json!("standard")
                && c["expected"]["reason"] == json!("policy_declined")
        }) {
            let def = Definition::from_document(&case["inputs"]["definition"]).unwrap();
            let request = octets(&case["inputs"]["request"]);
            assert_eq!(request["derivation"], json!(def.digest()));
            let pin = request["coverage"]["expected_pin"].as_str();
            let whole_run = request["subject"] == json!({"full_history": null}) && pin.is_some();
            let declined = !whole_run || def.declines_anchor(&pinned_time(&all, pin.unwrap()));
            assert!(declined, "{set} {}", id(case));
            run += 1;
        }
        assert_eq!(run, 3, "{set}");
    }
}

#[test]
fn a_definition_that_is_not_the_profiles_is_refused() {
    let case = &cases(SETS[0])
        .into_iter()
        .find(is_standard)
        .expect("a Standard case");
    let good = case["inputs"]["definition"].clone();
    assert!(Definition::from_document(&good).is_ok());
    for (member, value) in [
        ("level", json!("detailed")),
        ("embeds", json!([])),
        ("name", json!("Service-History")),
        ("reads", json!(["a field no member reads"])),
        ("extra", json!(1)),
    ] {
        let mut bad = good.clone();
        bad[member] = value;
        let why = Definition::from_document(&bad).unwrap_err();
        assert!(why.starts_with("definition_form:"), "{member}: {why}");
    }
    for (member, value) in [
        ("length_s", json!(3600)),
        ("floor", json!(0)),
        ("epoch", json!("2026-10-01T00:00:00.5Z")),
        ("suppression", json!("none")),
    ] {
        let mut bad = good.clone();
        bad["period_policy"][member] = value;
        let why = Definition::from_document(&bad).unwrap_err();
        assert!(why.starts_with("definition_form:"), "{member}: {why}");
    }
    let mut missing = good;
    missing["period_policy"]
        .as_object_mut()
        .unwrap()
        .remove("floor");
    assert!(Definition::from_document(&missing).is_err());
}
