//! SH-8 for `period_counts` (agent-action-capsule#616): under
//! `inference-service-history/1` a total that fixes two or more models
//! withheld under the floor is withheld with them as `complementary`, and a
//! checker rejects it published; under the frozen `/0` both stay as they
//! were. Each case derives and checks the same records under both versions.

use agent_action_capsule::canonical::jcs;
use agent_action_capsule::inference_history::{
    artifact, check_artifact, period_counts, Cut, Definition, PROFILE_V0, PROFILE_V1,
};
use serde_json::{json, Map, Value};

/// Mondays, 00:00 UTC: the policy's boundaries.
const WEEK_1: &str = "2026-01-12T00:00:00Z";
const STREAM: &str = "stream-a";

/// The vectors' Standard definition under a weekly policy (floor 5), naming
/// `profile`.
fn definition(profile: &str) -> Definition {
    let path = format!(
        "{}/../../vectors/inference-service-history-v0/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let corpus: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mut document = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["inputs"]["definition"]["level"] == json!("standard"))
        .unwrap()["inputs"]["definition"]
        .clone();
    document["profile"] = json!(profile);
    document["period_policy"] = json!({"epoch": "2026-01-05T00:00:00Z", "length_s": 604800,
        "min_length_s": 86400, "floor": 5, "suppression": "complementary"});
    Definition::from_document(&document).unwrap()
}

/// One week's records: `served` gives each model's count.
fn leaves(served: &[(&'static str, u64)]) -> Vec<Option<&'static str>> {
    served
        .iter()
        .flat_map(|&(m, n)| std::iter::repeat_n(Some(m), n as usize))
        .collect()
}

fn chain(n: u64) -> Vec<Cut<'static>> {
    vec![
        Cut {
            timestamp: "2026-01-07T10:00:00Z",
            leaves: n,
        },
        Cut {
            timestamp: WEEK_1,
            leaves: n,
        },
    ]
}

/// The one week's cells `def` derives for `served`.
fn derived(def: &Definition, served: &[(&'static str, u64)]) -> Value {
    let list = leaves(served);
    let model = |i: u64| list.get(i as usize).copied().flatten().map(str::to_string);
    period_counts(def, &chain(list.len() as u64), &model).unwrap()["periods"][0]["cells"].clone()
}

/// The artifact `def` builds over `served`, as a checker is handed it.
fn built(def: &Definition, served: &[(&'static str, u64)]) -> (Map<String, Value>, String) {
    let list = leaves(served);
    let n = list.len() as u64;
    let anchor = "ab".repeat(32);
    let card = json!({
        "anchor": anchor,
        "derivation": "history_card/1",
        "evidence_stream": STREAM,
        "history": chain(n).iter().map(|c| json!({"checkpoint": {"timestamp": c.timestamp, "log_size": c.leaves}})).collect::<Vec<_>>(),
        "subject": {"full_history": null},
    });
    let model = |i: u64| list.get(i as usize).copied().flatten().map(str::to_string);
    let counts = period_counts(def, &chain(n), &model).unwrap();
    let octets = artifact(def, &jcs(&card).unwrap(), counts, &anchor, STREAM, n).unwrap();
    let art: Value = serde_json::from_slice(&octets).unwrap();
    (art.as_object().unwrap().clone(), anchor)
}

fn check(def: &Definition, art: &Map<String, Value>, anchor: &str) -> Result<(), String> {
    let n = art["history_card"]["history"][0]["checkpoint"]["log_size"]
        .as_u64()
        .unwrap();
    check_artifact(def, art, &chain(n), anchor, STREAM).map(|_| ())
}

/// The total cell of the week, last.
fn total(cells: &Value) -> &Value {
    cells.as_array().unwrap().last().unwrap()
}

/// The cases of the issue (floor 5) and their neighbours: whether the total
/// fixes every withheld model.
const PINNED: [&[(&str, u64)]; 3] = [
    // Two models of 4: the total 8 is 2 × (floor − 1).
    &[("a", 4), ("b", 4)],
    // Five models of 1: the total 5 is 1 each.
    &[("a", 1), ("b", 1), ("c", 1), ("d", 1), ("e", 1)],
    // A published 9 beside two of 4: the rest 8 fixes both.
    &[("a", 9), ("b", 4), ("c", 4)],
];
const NOT_PINNED: [&[(&str, u64)]; 3] = [
    // Two models of 4 and 3: 7 is neither 2 nor 8.
    &[("a", 4), ("b", 3)],
    // Three models of 2: 6 is neither 3 nor 12.
    &[("a", 2), ("b", 2), ("c", 2)],
    // A published 9 beside two of 4 and 2: the rest 6 is neither 2 nor 8.
    &[("a", 9), ("b", 4), ("c", 2)],
];

#[test]
fn the_profile_versions_are_told_apart() {
    assert!(!definition(PROFILE_V0).strict_counts());
    assert!(definition(PROFILE_V1).strict_counts());
}

#[test]
fn under_v1_a_total_that_fixes_the_withheld_models_is_withheld() {
    for served in PINNED {
        let cells = derived(&definition(PROFILE_V1), served);
        assert_eq!(
            total(&cells)["suppressed"],
            json!("complementary"),
            "{served:?}"
        );
        assert_eq!(total(&cells)["value"], Value::Null, "{served:?}");
        // The models withheld under the floor stay `below_floor`; a published
        // model stays published.
        for c in &cells.as_array().unwrap()[..served.len()] {
            let n = served
                .iter()
                .find(|(m, _)| json!(m) == c["dimension"]["model"])
                .unwrap()
                .1;
            if n < 5 {
                assert_eq!(c["suppressed"], json!("below_floor"), "{served:?}");
            } else {
                assert_eq!(c["value"], json!(n), "{served:?}");
            }
        }
    }
}

#[test]
fn under_v1_a_total_that_does_not_fix_them_stays_published() {
    for served in NOT_PINNED {
        let cells = derived(&definition(PROFILE_V1), served);
        let sum: u64 = served.iter().map(|(_, n)| n).sum();
        assert_eq!(total(&cells)["value"], json!(sum), "{served:?}");
        assert!(total(&cells).get("suppressed").is_none(), "{served:?}");
    }
}

#[test]
fn under_v0_every_total_stays_as_it_was() {
    for served in PINNED.iter().chain(NOT_PINNED.iter()) {
        let cells = derived(&definition(PROFILE_V0), served);
        let sum: u64 = served.iter().map(|(_, n)| n).sum();
        assert_eq!(total(&cells)["value"], json!(sum), "{served:?}");
    }
}

#[test]
fn a_v1_artifact_checks_under_v1() {
    let v1 = definition(PROFILE_V1);
    for served in PINNED.iter().chain(NOT_PINNED.iter()) {
        let (art, anchor) = built(&v1, served);
        assert_eq!(check(&v1, &art, &anchor), Ok(()), "{served:?}");
    }
}

#[test]
fn under_v1_a_published_total_that_fixes_them_does_not_check() {
    let (v0, v1) = (definition(PROFILE_V0), definition(PROFILE_V1));
    for served in PINNED {
        // Built as /0 would (the total published), checked as /1: the
        // artifact's `derivation` names the /0 digest, so swap it for /1's.
        let (mut art, anchor) = built(&v0, served);
        art["derivation"] = json!(v1.digest());
        let err = check(&v1, &art, &anchor).unwrap_err();
        assert!(err.starts_with("period_floor:"), "{served:?}: {err}");
        // The same table is what /0 publishes, and /0 accepts it.
        let (art, anchor) = built(&v0, served);
        assert_eq!(check(&v0, &art, &anchor), Ok(()), "{served:?}");
    }
}

#[test]
fn under_v0_a_total_withheld_as_v1_does_still_checks() {
    // /0 never asked for the total to go, but withholding it is no break of
    // /0's rule either: a suppressed total is a suppressed cell.
    let (v0, v1) = (definition(PROFILE_V0), definition(PROFILE_V1));
    let (mut art, anchor) = built(&v1, PINNED[0]);
    art["derivation"] = json!(v0.digest());
    assert_eq!(check(&v0, &art, &anchor), Ok(()));
}
