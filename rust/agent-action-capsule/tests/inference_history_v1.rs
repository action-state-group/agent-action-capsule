//! `inference-service-history/1` (ISH §6.2 item 4, SH-8): a total that pins
//! two or more models withheld under the floor is withheld `complementary`,
//! even when it is under the floor itself, and a checker refuses a published
//! total that pins them. `/0` keeps its rule.

use agent_action_capsule::canonical::jcs;
use agent_action_capsule::inference_history::{
    artifact, artifact_with_verdicts, check_artifact, period_counts, verdict_counts, Cut,
    Definition, PROFILE_0, PROFILE_1,
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
    assert_eq!(def(PROFILE_0, 5).profile(), PROFILE_0);
    assert_eq!(def(PROFILE_1, 5).profile(), PROFILE_1);
    let other = document("inference-service-history/2", 5, false);
    assert!(Definition::from_document(&other)
        .unwrap_err()
        .starts_with("definition_form"));
}

#[test]
fn a_total_that_pins_two_models_under_the_floor_is_withheld() {
    // Floor 5: 4 and 4 with a total of 8 fixes both; /0 publishes it.
    assert_eq!(
        reasons(PROFILE_1, 5, &[4, 4]),
        [s("below_floor"), s("below_floor"), s("complementary")]
    );
    assert_eq!(
        derived(PROFILE_0, 5, &[4, 4]),
        [
            (None, s("below_floor")),
            (None, s("below_floor")),
            (Some(8), None)
        ]
    );
    // Five models of 1 each, total 5.
    let ones = reasons(PROFILE_1, 5, &[1, 1, 1, 1, 1]);
    assert_eq!(ones.last().unwrap(), &s("complementary"));
    assert!(ones[..5].iter().all(|w| w == &s("below_floor")));
}

#[test]
fn a_pinned_total_under_the_floor_is_withheld_complementary_too() {
    // Floor 5: 1 and 1, total 2, is under the floor. Were it `below_floor`,
    // a `complementary` total of 4 and 4 would say "at least 5", so 8.
    assert_eq!(
        reasons(PROFILE_1, 5, &[1, 1]),
        [s("below_floor"), s("below_floor"), s("complementary")]
    );
    assert_eq!(
        reasons(PROFILE_0, 5, &[1, 1]),
        [s("below_floor"), s("below_floor"), s("below_floor")]
    );
}

#[test]
fn a_total_that_pins_nothing_stays() {
    // 3 and 4, total 7: 3+4 or 4+3. Published under both revisions.
    assert_eq!(
        derived(PROFILE_1, 5, &[3, 4]),
        [
            (None, s("below_floor")),
            (None, s("below_floor")),
            (Some(7), None)
        ]
    );
    // 1 and 2, total 3, under the floor and pinning nothing: below_floor.
    assert_eq!(
        reasons(PROFILE_1, 5, &[1, 2]),
        [s("below_floor"), s("below_floor"), s("below_floor")]
    );
}

#[test]
fn a_published_model_beside_two_withheld_ones_that_the_rest_pins() {
    // 10 published, 4 and 4 withheld: the rest of 18 is 8.
    assert_eq!(
        reasons(PROFILE_1, 5, &[10, 4, 4]),
        [None, s("below_floor"), s("below_floor"), s("complementary")]
    );
    // 10, 3, 4: the rest 7 pins nothing.
    assert_eq!(
        reasons(PROFILE_1, 5, &[10, 3, 4]),
        [None, s("below_floor"), s("below_floor"), None]
    );
}

#[test]
fn the_one_withheld_model_rule_is_kept() {
    for profile in [PROFILE_0, PROFILE_1] {
        assert_eq!(
            reasons(profile, 5, &[9, 3]),
            [s("complementary"), s("below_floor"), None],
            "{profile}"
        );
    }
}

#[test]
fn edge_floors_and_tables() {
    // Floor 1: nothing is under it, nothing is withheld.
    assert_eq!(reasons(PROFILE_1, 1, &[1, 1]), [None, None, None]);
    // Floor 2: two models under it hold 1 each, which every sum pins.
    assert_eq!(
        reasons(PROFILE_1, 2, &[1, 1, 7]),
        [s("below_floor"), s("below_floor"), None, s("complementary")]
    );
    // One model under the floor and no other: it and its total withheld.
    assert_eq!(
        reasons(PROFILE_1, 5, &[3]),
        [s("below_floor"), s("below_floor")]
    );
}

#[test]
fn every_derived_table_checks_under_its_revision() {
    for profile in [PROFILE_0, PROFILE_1] {
        for floor in [1, 2, 5] {
            for counts in [
                &[4, 4][..],
                &[1, 1, 1, 1, 1],
                &[1, 1],
                &[3, 4],
                &[10, 4, 4],
                &[9, 3],
                &[3],
                &[1, 1, 7],
            ] {
                let d = def(profile, floor);
                let art = built(&d, counts);
                assert_eq!(
                    check(&d, &art, counts),
                    Ok(()),
                    "{profile} floor {floor} {counts:?}"
                );
            }
        }
    }
}

#[test]
fn a_published_total_that_pins_withheld_models_is_refused_under_1() {
    let d1 = def(PROFILE_1, 5);
    let d0 = def(PROFILE_0, 5);
    let base = built(&d1, &[4, 4]);
    let leak = json!([
        cell(Some("m0"), None, Some("below_floor")),
        cell(Some("m1"), None, Some("below_floor")),
        cell(None, Some(8), None),
    ]);
    let why = check(&d1, &with_cells(&base, leak.clone()), &[4, 4]).unwrap_err();
    assert!(why.starts_with("period_floor"), "{why}");
    // /0 checks only its "at the least" minimum.
    let base0 = built(&d0, &[4, 4]);
    assert_eq!(check(&d0, &with_cells(&base0, leak), &[4, 4]), Ok(()));

    let ones: Vec<Value> = (0..5)
        .map(|i| cell(Some(&format!("m{i}")), None, Some("below_floor")))
        .chain([cell(None, Some(5), None)])
        .collect();
    let base = built(&d1, &[1, 1, 1, 1, 1]);
    let why = check(&d1, &with_cells(&base, json!(ones)), &[1, 1, 1, 1, 1]).unwrap_err();
    assert!(why.starts_with("period_floor"), "{why}");

    let beside = json!([
        cell(Some("m0"), Some(10), None),
        cell(Some("m1"), None, Some("below_floor")),
        cell(Some("m2"), None, Some("below_floor")),
        cell(None, Some(18), None),
    ]);
    let base = built(&d1, &[10, 4, 4]);
    let why = check(&d1, &with_cells(&base, beside), &[10, 4, 4]).unwrap_err();
    assert!(why.starts_with("period_floor"), "{why}");
}

#[test]
fn a_rest_smaller_than_the_withheld_models_does_not_add_up_under_1() {
    // Three withheld models hold at least 1 each; a rest of 2 cannot be.
    let d1 = def(PROFILE_1, 5);
    let base = built(&d1, &[10, 1, 1, 1]);
    let short = json!([
        cell(Some("m0"), Some(10), None),
        cell(Some("m1"), None, Some("below_floor")),
        cell(Some("m2"), None, Some("below_floor")),
        cell(Some("m3"), None, Some("below_floor")),
        cell(None, Some(12), None),
    ]);
    let why = check(&d1, &with_cells(&base, short), &[10, 1, 1, 1]).unwrap_err();
    assert!(why.contains("do not add up"), "{why}");
}

#[test]
fn a_rest_beyond_what_cells_under_the_floor_hold_does_not_add_up_under_1() {
    // Two withheld under a floor of 5 hold at most 8; a rest of 9 cannot be.
    let d1 = def(PROFILE_1, 5);
    let base = built(&d1, &[10, 4, 4]);
    let beyond = json!([
        cell(Some("m0"), Some(10), None),
        cell(Some("m1"), None, Some("below_floor")),
        cell(Some("m2"), None, Some("below_floor")),
        cell(None, Some(19), None),
    ]);
    let why = check(&d1, &with_cells(&base, beyond), &[10, 4, 4]).unwrap_err();
    assert!(why.contains("do not add up"), "{why}");
    // Floor 2: two withheld hold 1 each; a published total of 3 cannot be.
    let d2 = def(PROFILE_1, 2);
    let base = built(&d2, &[1, 1]);
    let three = json!([
        cell(Some("m0"), None, Some("below_floor")),
        cell(Some("m1"), None, Some("below_floor")),
        cell(None, Some(3), None),
    ]);
    let why = check(&d2, &with_cells(&base, three), &[1, 1]).unwrap_err();
    assert!(why.contains("do not add up"), "{why}");
}

#[test]
fn nothing_is_withheld_under_a_floor_of_1_under_1() {
    let d1 = def(PROFILE_1, 1);
    let base = built(&d1, &[1, 1]);
    for total_why in ["complementary", "below_floor"] {
        let cells = json!([
            cell(Some("m0"), None, Some("below_floor")),
            cell(Some("m1"), None, Some("below_floor")),
            cell(None, None, Some(total_why)),
        ]);
        let why = check(&d1, &with_cells(&base, cells), &[1, 1]).unwrap_err();
        assert!(why.starts_with("period_floor"), "{total_why}: {why}");
    }
}

#[test]
fn a_total_withheld_complementary_needs_two_models_under_the_floor() {
    let d1 = def(PROFILE_1, 5);
    let base = built(&d1, &[9, 3]);
    // One model withheld under the floor, its partner and the total too.
    let over = json!([
        cell(Some("m0"), None, Some("complementary")),
        cell(Some("m1"), None, Some("below_floor")),
        cell(None, None, Some("complementary")),
    ]);
    let why = check(&d1, &with_cells(&base, over.clone()), &[9, 3]).unwrap_err();
    assert!(why.starts_with("period_floor"), "{why}");
    // /0 has no such rule for a withheld total.
    let d0 = def(PROFILE_0, 5);
    let base0 = built(&d0, &[9, 3]);
    assert_eq!(check(&d0, &with_cells(&base0, over), &[9, 3]), Ok(()));
}

#[test]
fn a_verdict_table_follows_the_same_rule_under_1() {
    // Two hashes, each 4 contradicted: the result's total goes, as
    // `complementary`, under /1; under /0 (#615) it goes too.
    let verdict = |leaf: u64| {
        Some((
            if leaf < 4 { "h1" } else { "h2" }.to_string(),
            "contradicted".to_string(),
        ))
    };
    let counts = [4, 4];
    for profile in [PROFILE_0, PROFILE_1] {
        let d = Definition::from_document(&document(profile, 5, true)).unwrap();
        let member = verdict_counts(&d, &chain(&counts), &verdict).unwrap();
        let total = member["periods"][0]["cells"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["dimension"] == json!({"result": "contradicted"}))
            .unwrap()
            .clone();
        assert_eq!(total["suppressed"], json!("complementary"), "{profile}");
        let anchor = "ab".repeat(32);
        let chain = chain(&counts);
        let card = json!({
            "anchor": anchor, "derivation": "history_card/1", "evidence_stream": STREAM,
            "history": chain.iter().map(|c| json!({"checkpoint": {"timestamp": c.timestamp, "log_size": c.leaves}})).collect::<Vec<_>>(),
            "subject": {"full_history": null},
        });
        let pc = period_counts(&d, &chain, &model_of(&counts)).unwrap();
        let octets =
            artifact_with_verdicts(&d, &jcs(&card).unwrap(), pc, member, &anchor, STREAM, 8)
                .unwrap();
        let art: Value = serde_json::from_slice(&octets).unwrap();
        assert!(check_artifact(&d, art.as_object().unwrap(), &chain, &anchor, STREAM).is_ok());
    }
    // 1 and 1 contradicted: the total of 2 is under the floor. /1 withholds
    // it `complementary`; /0 leaves it `below_floor`.
    let ones = |leaf: u64| {
        Some((
            if leaf < 1 { "h1" } else { "h2" }.to_string(),
            "contradicted".to_string(),
        ))
    };
    for (profile, want) in [(PROFILE_0, "below_floor"), (PROFILE_1, "complementary")] {
        let d = Definition::from_document(&document(profile, 5, true)).unwrap();
        let member = verdict_counts(&d, &chain(&[1, 1]), &ones).unwrap();
        let total = member["periods"][0]["cells"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["dimension"] == json!({"result": "contradicted"}))
            .unwrap()
            .clone();
        assert_eq!(total["suppressed"], json!(want), "{profile}");
    }
}
