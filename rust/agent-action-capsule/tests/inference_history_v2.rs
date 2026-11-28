//! `inference-service-history/2` (ISH §6.2 item 6, SH-8): beside one model
//! withheld under the floor and its `complementary` partner, a total whose
//! bounds leave one value for the withheld model is withheld `complementary`
//! too, and a checker refuses a published one, or one no counts can match.
//! `/1` keeps its rule.

use agent_action_capsule::canonical::jcs;
use agent_action_capsule::inference_history::{
    artifact, artifact_with_verdicts, check_artifact, period_counts, verdict_counts, Cut,
    Definition, PROFILE_1, PROFILE_2,
};
use serde_json::{json, Map, Value};

const STREAM: &str = "stream-a";
const OPEN: &str = "2026-01-07T10:00:00Z";
const WEEK_1: &str = "2026-01-12T00:00:00Z";

/// The vectors' Standard definition under a weekly policy with `floor`,
/// naming `profile`, with or without the verdict counts member.
fn document(profile: &str, floor: u64, with_verdicts: bool) -> Value {
    let path = format!(
        "{}/../../vectors/inference-service-history-v0/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let corpus: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mut d = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["inputs"]["definition"]["level"] == json!("standard"))
        .unwrap()["inputs"]["definition"]
        .clone();
    d["profile"] = json!(profile);
    d["period_policy"] = json!({"epoch": "2026-01-05T00:00:00Z", "length_s": 604800,
        "min_length_s": 86400, "floor": floor, "suppression": "complementary"});
    if with_verdicts {
        let reads = json!(["record: verdict held"]);
        d["members"].as_array_mut().unwrap().push(json!({
            "name": "verdict_counts", "required": true, "reads": reads,
            "units": [{"where": "periods[].cells[]", "unit": "referee_verdicts"}],
        }));
        d["reads"].as_array_mut().unwrap().push(reads[0].clone());
    }
    d
}

fn def(profile: &str, floor: u64) -> Definition {
    Definition::from_document(&document(profile, floor, false)).unwrap()
}

/// One closed week whose records are `counts` exchanges per model, in model
/// order, then the anchor at its end.
fn chain(counts: &[u64]) -> Vec<Cut<'static>> {
    let n = counts.iter().sum();
    vec![
        Cut {
            timestamp: OPEN,
            leaves: n,
        },
        Cut {
            timestamp: WEEK_1,
            leaves: n,
        },
    ]
}

/// The model the record at `leaf` served: `counts[i]` records for model
/// `m{i}`, one after another.
fn model_of(counts: &[u64]) -> impl Fn(u64) -> Option<String> + '_ {
    move |leaf| {
        let mut end = 0;
        for (i, n) in counts.iter().enumerate() {
            end += n;
            if leaf < end {
                return Some(format!("m{i}"));
            }
        }
        None
    }
}

/// The one period's cells as `(value, reason)`, models in order and the
/// total last.
fn derived(profile: &str, floor: u64, counts: &[u64]) -> Vec<(Option<u64>, Option<String>)> {
    let member = period_counts(&def(profile, floor), &chain(counts), &model_of(counts)).unwrap();
    member["periods"][0]["cells"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["value"].as_u64(),
                c.get("suppressed")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            )
        })
        .collect()
}

fn reasons(profile: &str, floor: u64, counts: &[u64]) -> Vec<Option<String>> {
    derived(profile, floor, counts)
        .into_iter()
        .map(|(_, why)| why)
        .collect()
}

fn s(why: &str) -> Option<String> {
    Some(why.to_string())
}

/// The artifact of one week with `counts`, built and checked under `def`.
fn built(def: &Definition, counts: &[u64]) -> Map<String, Value> {
    let anchor = "ab".repeat(32);
    let chain = chain(counts);
    let card = json!({
        "anchor": anchor, "derivation": "history_card/1", "evidence_stream": STREAM,
        "history": chain.iter().map(|c| json!({"checkpoint": {"timestamp": c.timestamp, "log_size": c.leaves}})).collect::<Vec<_>>(),
        "subject": {"full_history": null},
    });
    let member = period_counts(def, &chain, &model_of(counts)).unwrap();
    let total: u64 = counts.iter().sum();
    let octets = artifact(def, &jcs(&card).unwrap(), member, &anchor, STREAM, total).unwrap();
    serde_json::from_slice::<Value>(&octets)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

fn check(def: &Definition, art: &Map<String, Value>, counts: &[u64]) -> Result<(), String> {
    let anchor = "ab".repeat(32);
    check_artifact(def, art, &chain(counts), &anchor, STREAM).map(|_| ())
}

/// `art` with the one period's cells replaced by `cells`.
fn with_cells(art: &Map<String, Value>, cells: Value) -> Map<String, Value> {
    let mut a = art.clone();
    a["period_counts"]["periods"][0]["cells"] = cells;
    a
}

fn cell(model: Option<&str>, value: Option<u64>, why: Option<&str>) -> Value {
    let mut c = json!({
        "dimension": model.map(|m| json!({"model": m})).unwrap_or(Value::Null),
        "label": "self_reported", "unit": "exchanges_served",
        "value": value,
    });
    if let Some(why) = why {
        c["suppressed"] = json!(why);
    }
    c
}

#[test]
fn the_definition_names_its_revision() {
    assert_eq!(def(PROFILE_2, 5).profile(), PROFILE_2);
}

/// Models in order, then the total, as `(value, reason)` under `/2` at floor 5.
fn cells2(counts: &[u64]) -> Vec<(Option<u64>, Option<String>)> {
    derived(PROFILE_2, 5, counts)
}

#[test]
fn a_total_whose_bounds_leave_one_value_is_withheld() {
    let c = s("complementary");
    let b = s("below_floor");
    // 1, 5, 9: the rest of 6 can only be 1 and 5.
    assert_eq!(
        cells2(&[1, 5, 9]),
        vec![
            (None, b.clone()),
            (None, c.clone()),
            (Some(9), None),
            (None, c.clone())
        ]
    );
    // 4, 6, 6: the rest of 10 can only be 4 and 6.
    assert_eq!(
        reasons(PROFILE_2, 5, &[4, 6, 6]),
        vec![b.clone(), c.clone(), None, c.clone()]
    );
    // 3, 5, 5: the partner lies between 5 and 5.
    assert_eq!(
        reasons(PROFILE_2, 5, &[3, 5, 5]),
        vec![b.clone(), c.clone(), None, c.clone()]
    );
    // 1, 5 with nothing published: the rest of 6 can only be 1 and 5.
    assert_eq!(
        reasons(PROFILE_2, 5, &[1, 5]),
        vec![b.clone(), c.clone(), c.clone()]
    );
    // /1 publishes each of those totals.
    for counts in [&[1, 5, 9][..], &[4, 6, 6], &[3, 5, 5], &[1, 5]] {
        assert_eq!(
            reasons(PROFILE_1, 5, counts).last().unwrap(),
            &None,
            "{counts:?}"
        );
    }
}

#[test]
fn a_total_whose_bounds_leave_two_or_more_values_stays() {
    // 3, 6, 6: 3 or 4. 3, 7: 1 to 4. 9, 3: 1 to 4. 4, 5, 6, 6: 3 or 4.
    assert_eq!(cells2(&[3, 6, 6]).last().unwrap(), &(Some(15), None));
    assert_eq!(cells2(&[3, 7]).last().unwrap(), &(Some(10), None));
    assert_eq!(cells2(&[9, 3]).last().unwrap(), &(Some(12), None));
    assert_eq!(cells2(&[4, 5, 6, 6]).last().unwrap(), &(Some(21), None));
}

#[test]
fn every_derived_table_checks_under_2() {
    for floor in [1, 2, 3, 5] {
        for counts in [
            &[4, 4][..],
            &[1, 1, 1, 1, 1],
            &[1, 1],
            &[3, 4],
            &[10, 4, 4],
            &[9, 3],
            &[3],
            &[1, 1, 7],
            &[1, 5, 9],
            &[4, 6, 6],
            &[3, 5, 5],
            &[3, 6, 6],
            &[1, 5],
            &[3, 7],
            &[2, 3, 3, 8],
        ] {
            let d = def(PROFILE_2, floor);
            let art = built(&d, counts);
            assert_eq!(check(&d, &art, counts), Ok(()), "floor {floor} {counts:?}");
        }
    }
}

#[test]
fn a_published_total_that_leaves_one_value_is_refused_under_2() {
    let d2 = def(PROFILE_2, 5);
    let d1 = def(PROFILE_1, 5);
    for (counts, total) in [
        (&[1u64, 5, 9][..], 15u64),
        (&[4, 6, 6], 16),
        (&[3, 5, 5], 13),
    ] {
        let leak = json!([
            cell(Some("m0"), None, Some("below_floor")),
            cell(Some("m1"), None, Some("complementary")),
            cell(Some("m2"), Some(counts[2]), None),
            cell(None, Some(total), None),
        ]);
        let base = built(&d2, counts);
        let why = check(&d2, &with_cells(&base, leak.clone()), counts).unwrap_err();
        assert_eq!(
            why, "period_floor: a suppressed cell can be derived from the total",
            "{counts:?}"
        );
        // /1 publishes it.
        let base1 = built(&d1, counts);
        assert_eq!(
            check(&d1, &with_cells(&base1, leak), counts),
            Ok(()),
            "{counts:?}"
        );
    }
    let leak = json!([
        cell(Some("m0"), None, Some("below_floor")),
        cell(Some("m1"), None, Some("complementary")),
        cell(None, Some(6), None),
    ]);
    let base = built(&d2, &[1, 5]);
    assert!(check(&d2, &with_cells(&base, leak), &[1, 5])
        .unwrap_err()
        .starts_with("period_floor"));
}

#[test]
fn a_published_total_that_leaves_no_value_does_not_add_up_under_2() {
    let d2 = def(PROFILE_2, 5);
    let base = built(&d2, &[1, 5, 9]);
    for total in [14, 23] {
        let bad = json!([
            cell(Some("m0"), None, Some("below_floor")),
            cell(Some("m1"), None, Some("complementary")),
            cell(Some("m2"), Some(9), None),
            cell(None, Some(total), None),
        ]);
        assert_eq!(
            check(&d2, &with_cells(&base, bad), &[1, 5, 9]).unwrap_err(),
            "period_floor: the models do not add up to the total",
            "{total}"
        );
    }
}

#[test]
fn a_total_withheld_complementary_needs_item_5_or_item_6s_shape_under_2() {
    let d2 = def(PROFILE_2, 5);
    let base = built(&d2, &[9, 3]);
    // One under the floor, its partner and the total: item 6's shape, accepted
    // (a verifier cannot see that the bounds left 1 to 4).
    let shape = json!([
        cell(Some("m0"), None, Some("complementary")),
        cell(Some("m1"), None, Some("below_floor")),
        cell(None, None, Some("complementary")),
    ]);
    assert_eq!(
        check(&d2, &with_cells(&base, shape.clone()), &[9, 3]),
        Ok(())
    );
    // /1 refuses it.
    let d1 = def(PROFILE_1, 5);
    let base1 = built(&d1, &[9, 3]);
    assert!(check(&d1, &with_cells(&base1, shape), &[9, 3]).is_err());
    // No partner: refused under /2.
    let alone = json!([
        cell(Some("m0"), Some(9), None),
        cell(Some("m1"), None, Some("below_floor")),
        cell(None, None, Some("complementary")),
    ]);
    assert!(check(&d2, &with_cells(&base, alone), &[9, 3])
        .unwrap_err()
        .starts_with("period_floor"));
    // Two partners: refused under /2.
    let base3 = built(&d2, &[3, 6, 6]);
    let two = json!([
        cell(Some("m0"), None, Some("below_floor")),
        cell(Some("m1"), None, Some("complementary")),
        cell(Some("m2"), None, Some("complementary")),
        cell(None, None, Some("complementary")),
    ]);
    assert!(check(&d2, &with_cells(&base3, two), &[3, 6, 6])
        .unwrap_err()
        .starts_with("period_floor"));
}

#[test]
fn a_total_alone_is_summed_under_1_and_not_under_2() {
    let alone = json!([cell(None, Some(9), None)]);
    for (profile, ok) in [(PROFILE_1, false), (PROFILE_2, true)] {
        let d = def(profile, 5);
        let base = built(&d, &[9]);
        assert_eq!(
            check(&d, &with_cells(&base, alone.clone()), &[9]).is_ok(),
            ok,
            "{profile}"
        );
    }
}

#[test]
fn a_verdict_table_follows_item_6_under_2() {
    // 1 and 5 contradicted, nothing else: the result's total goes under /2.
    let verdict = |leaf: u64| {
        Some((
            if leaf < 1 { "h1" } else { "h2" }.to_string(),
            "contradicted".to_string(),
        ))
    };
    for (profile, want) in [
        (PROFILE_1, Value::Null),
        (PROFILE_2, json!("complementary")),
    ] {
        let d = Definition::from_document(&document(profile, 5, true)).unwrap();
        let member = verdict_counts(&d, &chain(&[1, 5]), &verdict).unwrap();
        let total = member["periods"][0]["cells"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["dimension"] == json!({"result": "contradicted"}))
            .unwrap()
            .clone();
        assert_eq!(
            total.get("suppressed").cloned().unwrap_or(Value::Null),
            want,
            "{profile}"
        );
        let anchor = "ab".repeat(32);
        let chain = chain(&[1, 5]);
        let card = json!({
            "anchor": anchor, "derivation": "history_card/1", "evidence_stream": STREAM,
            "history": chain.iter().map(|c| json!({"checkpoint": {"timestamp": c.timestamp, "log_size": c.leaves}})).collect::<Vec<_>>(),
            "subject": {"full_history": null},
        });
        let pc = period_counts(&d, &chain, &model_of(&[1, 5])).unwrap();
        let octets =
            artifact_with_verdicts(&d, &jcs(&card).unwrap(), pc, member, &anchor, STREAM, 6)
                .unwrap();
        let art: Value = serde_json::from_slice(&octets).unwrap();
        assert!(
            check_artifact(&d, art.as_object().unwrap(), &chain, &anchor, STREAM).is_ok(),
            "{profile}"
        );
    }
}
