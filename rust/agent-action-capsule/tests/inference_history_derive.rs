//! The Standard derivation and checks of `inference_history` over a weekly
//! period policy (epoch Monday 2026-01-05, floor 5): the counts a stream's
//! checkpoints give, the artifact built from them, and the rules a checker
//! rejects one at a time.

use agent_action_capsule::canonical::jcs;
use agent_action_capsule::inference_history::{
    artifact, check_artifact, period_counts, Cell, Counts, Cut, Definition, Refusal,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// Mondays, 00:00 UTC: the policy's boundaries.
const WEEK_1: &str = "2026-01-12T00:00:00Z";
const WEEK_2: &str = "2026-01-19T00:00:00Z";
const WEEK_3: &str = "2026-01-26T00:00:00Z";
const STREAM: &str = "stream-a";

/// A Standard definition from the vectors' example, under a weekly policy.
fn definition() -> Definition {
    let mut document = definition_document();
    document["period_policy"] = json!({"epoch": "2026-01-05T00:00:00Z", "length_s": 604800,
        "min_length_s": 86400, "floor": 5, "suppression": "complementary"});
    Definition::from_document(&document).unwrap()
}

/// The vectors' Standard definition.
fn definition_document() -> Value {
    let path = format!(
        "{}/../../vectors/inference-service-history-v0/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let corpus: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["inputs"]["definition"]["level"] == json!("standard"))
        .unwrap()["inputs"]["definition"]
        .clone()
}

fn digest_of(v: &Value) -> String {
    hex::encode(Sha256::digest(jcs(v).unwrap()))
}

#[test]
fn the_digests_are_those_of_the_definition_document() {
    let def = definition();
    assert_eq!(def.policy().length_s, 604800);
    assert_ne!(def.digest(), def.policy_digest());
    assert!(def.policy().is_boundary(WEEK_1));
    assert!(def.policy().is_boundary("2025-12-29T00:00:00Z"));
    assert!(!def.policy().is_boundary("2026-01-12T00:01:00Z"));
    assert!(!def.policy().is_boundary("2026-01-13T00:00:00Z"));
    assert!(!def.policy().is_boundary("2026-01-12T00:00:00.5Z"));
    assert!(!def.policy().is_boundary("not a time"));
    assert_eq!(
        def.next_boundary_after(
            agent_action_capsule::inference_history::unix_time(WEEK_1).unwrap()
        ),
        agent_action_capsule::inference_history::unix_time(WEEK_2)
    );
}

/// A model per leaf, from a list.
fn models<'a>(list: &'a [Option<&'a str>]) -> impl Fn(u64) -> Option<String> + 'a {
    move |i| list.get(i as usize).copied().flatten().map(str::to_string)
}

fn cuts<'a>(list: &[(&'a str, u64)]) -> Vec<Cut<'a>> {
    list.iter()
        .map(|&(timestamp, leaves)| Cut { timestamp, leaves })
        .collect()
}

fn cell(model: Option<&str>, value: Result<u64, &str>) -> Value {
    let mut c = json!({
        "dimension": model.map(|m| json!({"model": m})),
        "label": "self_reported",
        "unit": "exchanges_served",
        "value": value.ok(),
    });
    if let Err(why) = value {
        c["suppressed"] = json!(why);
    }
    c
}

/// ISH §9.1's day two, by the week: a's 9 and b's 3 under a total of 12.
#[test]
fn a_model_a_published_total_gives_away_is_withheld_with_it() {
    let mut list = vec![Some("a"); 9];
    list.extend([Some("b"); 3]);
    let counts = period_counts(
        &definition(),
        &cuts(&[("2026-01-06T09:00:00Z", 12), (WEEK_1, 12)]),
        &models(&list),
    )
    .unwrap();
    assert_eq!(
        counts["periods"][0]["cells"],
        json!([
            cell(Some("a"), Err("complementary")),
            cell(Some("b"), Err("below_floor")),
            cell(None, Ok(12)),
        ])
    );
}

#[test]
fn every_closed_period_is_counted_in_order_and_the_open_one_never() {
    let def = definition();
    // Week 0 (from the epoch): 6 a and 5 b. Week 1: 7 a, committed by the
    // checkpoint that closes it. Week 2: none.
    let mut list = vec![Some("a"); 6];
    list.extend([Some("b"); 5]);
    list.push(None); // not a served exchange
    list.extend([Some("a"); 7]);
    let counts = period_counts(
        &def,
        &cuts(&[("2026-01-07T12:00:00Z", 12), (WEEK_2, 19), (WEEK_3, 19)]),
        &models(&list),
    )
    .unwrap();
    assert_eq!(counts["policy"], json!(def.policy_digest()));
    assert_eq!(
        counts["periods"],
        json!([
            {"from": "2026-01-05T00:00:00Z", "to": WEEK_1, "cells": [
                cell(Some("a"), Ok(6)), cell(Some("b"), Ok(5)), cell(None, Ok(11))]},
            {"from": WEEK_1, "to": WEEK_2, "cells": [cell(Some("a"), Ok(7)), cell(None, Ok(7))]},
            {"from": WEEK_2, "to": WEEK_3, "cells": [cell(None, Err("below_floor"))]},
        ])
    );
    // At the week-2 anchor, week 2 is open and not listed.
    let earlier = period_counts(
        &def,
        &cuts(&[("2026-01-07T12:00:00Z", 12), (WEEK_2, 19)]),
        &models(&list),
    )
    .unwrap();
    assert_eq!(earlier["periods"].as_array().unwrap().len(), 2);
    // ... and the weeks both list are the same cells (ISH §6.1 item 4).
    assert_eq!(
        earlier["periods"].as_array().unwrap()[..],
        counts["periods"].as_array().unwrap()[..2]
    );
}

#[test]
fn a_checkpoint_time_that_goes_back_never_adds_to_a_closed_period() {
    let def = definition();
    let list = vec![Some("a"); 12];
    let at_week_1 = period_counts(
        &def,
        &cuts(&[("2026-01-07T00:00:00Z", 6), (WEEK_1, 6)]),
        &models(&list),
    )
    .unwrap();
    let later = period_counts(
        &def,
        &cuts(&[
            ("2026-01-07T00:00:00Z", 6),
            (WEEK_1, 6),
            ("2026-01-08T00:00:00Z", 12),
            (WEEK_2, 12),
        ]),
        &models(&list),
    )
    .unwrap();
    assert_eq!(at_week_1["periods"][0], later["periods"][0]);
    assert_eq!(later["periods"][1]["cells"][1], cell(None, Ok(6)));
}

#[test]
fn an_anchor_off_a_boundary_is_declined() {
    for anchor in ["2026-01-12T00:01:00Z", "2026-01-13T00:00:00Z", "garbage"] {
        assert_eq!(
            period_counts(&definition(), &cuts(&[(anchor, 1)]), &models(&[])),
            Err(Refusal::PolicyDeclined),
            "{anchor}"
        );
    }
    assert_eq!(
        period_counts(&definition(), &[], &models(&[])),
        Err(Refusal::CapacityExceeded)
    );
}

/// A stream whose first checkpoint is at a boundary: that checkpoint closes
/// the period before it, and its records are in it.
#[test]
fn a_first_checkpoint_at_a_boundary_closes_the_period_before_it() {
    let counts = period_counts(
        &definition(),
        &cuts(&[(WEEK_1, 3)]),
        &models(&[Some("a"); 3]),
    )
    .unwrap();
    assert_eq!(
        counts["periods"],
        json!([{"from": "2026-01-05T00:00:00Z", "to": WEEK_1, "cells": [
            cell(Some("a"), Err("below_floor")), cell(None, Err("below_floor"))]}])
    );
}

/// A second checkpoint at the same boundary commits into the period that
/// boundary opens, never the one the first closed.
#[test]
fn a_second_checkpoint_at_a_boundary_never_reopens_the_period_closed() {
    let def = definition();
    let list = vec![Some("a"); 12];
    let first = period_counts(
        &def,
        &cuts(&[("2026-01-07T00:00:00Z", 2), (WEEK_1, 6)]),
        &models(&list),
    )
    .unwrap();
    let both = period_counts(
        &def,
        &cuts(&[("2026-01-07T00:00:00Z", 2), (WEEK_1, 6), (WEEK_1, 12)]),
        &models(&list),
    )
    .unwrap();
    assert_eq!(first, both);
    assert_eq!(first["periods"][0]["cells"][1], cell(None, Ok(6)));
}

#[test]
fn a_stream_older_than_the_most_periods_is_refused_not_answered_in_part() {
    // The first checkpoint 10,000 weeks before the anchor.
    let counts = period_counts(
        &definition(),
        &cuts(&[("2026-01-07T00:00:00Z", 1), ("2217-09-08T00:00:00Z", 1)]),
        &models(&[Some("a")]),
    );
    assert_eq!(counts, Err(Refusal::CapacityExceeded));
}

// ---------------------------------------------------------------------
// The artifact, and what a checker rejects one rule at a time
// ---------------------------------------------------------------------

/// 30 records: 9 of model a and 3 of b in week 0, then 6 of a and 12 of b in
/// week 1; checkpoints inside week 0, at week 1's start, inside week 1 and at
/// week 2's start.
const CHECKPOINTS: [(&str, u64); 4] = [
    ("2026-01-07T10:00:00Z", 6),
    (WEEK_1, 12),
    ("2026-01-14T08:00:00Z", 20),
    (WEEK_2, 30),
];

fn ledger_models() -> Vec<Option<&'static str>> {
    let mut list = vec![Some("a"); 9];
    list.extend([Some("b"); 3]);
    list.extend([Some("a"); 6]);
    list.extend([Some("b"); 12]);
    list
}

/// The built artifact, its parts a checker is handed, and the anchor.
fn built() -> (Map<String, Value>, Vec<Cut<'static>>, String) {
    let def = definition();
    let anchor = "ab".repeat(32);
    let card = json!({
        "anchor": anchor,
        "derivation": "history_card/1",
        "evidence_stream": STREAM,
        "history": CHECKPOINTS.iter().map(|(t, n)| json!({"checkpoint": {"timestamp": t, "log_size": n}})).collect::<Vec<_>>(),
        "subject": {"full_history": null},
    });
    let list = ledger_models();
    let chain: Vec<Cut> = CHECKPOINTS
        .iter()
        .map(|&(timestamp, leaves)| Cut { timestamp, leaves })
        .collect();
    let counts = period_counts(&def, &chain, &models(&list)).unwrap();
    let octets = artifact(&def, &jcs(&card).unwrap(), counts, &anchor, STREAM, 30).unwrap();
    // The octets are RFC 8785 of the object.
    let art: Value = serde_json::from_slice(&octets).unwrap();
    assert_eq!(jcs(&art).unwrap(), octets);
    (art.as_object().unwrap().clone(), chain, anchor)
}

fn check(art: &Map<String, Value>, chain: &[Cut<'_>], anchor: &str) -> Result<Counts, String> {
    check_artifact(&definition(), art, chain, anchor, STREAM, 30)
}

#[test]
fn the_built_artifact_checks_and_names_its_parts() {
    let (art, chain, anchor) = built();
    let def = definition();
    assert_eq!(art["derivation"], json!(def.digest()));
    assert_eq!(art["declared"], json!(["history_card", "period_counts"]));
    assert_eq!(art["subject"], json!({"full_history": null}));
    assert_eq!(
        art["history_card_digest"],
        json!(digest_of(&art["history_card"]))
    );
    let counts = check(&art, &chain, &anchor).unwrap();
    assert_eq!(counts.periods.len(), 2);
    assert_eq!(
        counts.periods[0].cells[0].value,
        Err("complementary".into())
    );
    assert_eq!(
        counts.periods[1].cells[1],
        Cell {
            model: Some("b".into()),
            value: Ok(12)
        }
    );
}

#[test]
fn a_card_that_is_not_canonical_is_not_embedded() {
    let def = definition();
    let (art, _, anchor) = built();
    let counts = art["period_counts"].clone();
    let pretty = serde_json::to_vec_pretty(&art["history_card"]).unwrap();
    assert_eq!(
        artifact(&def, &pretty, counts, &anchor, STREAM, 30),
        Err(Refusal::CapacityExceeded)
    );
}

/// The periods of a History artifact.
fn periods(a: &mut Map<String, Value>) -> &mut Vec<Value> {
    a.get_mut("period_counts").unwrap()["periods"]
        .as_array_mut()
        .unwrap()
}

/// One change to a History artifact.
type Tamper = Box<dyn Fn(&mut Map<String, Value>)>;

#[test]
fn a_tampered_history_does_not_check() {
    let (art, chain, anchor) = built();
    let cases: Vec<(&str, Tamper)> = vec![
        (
            "a closed period dropped",
            Box::new(|a| {
                periods(a).remove(0);
            }),
        ),
        (
            "the last closed period dropped",
            Box::new(|a| {
                periods(a).pop();
            }),
        ),
        ("no period listed", Box::new(|a| periods(a).clear())),
        (
            "a period twice",
            Box::new(|a| {
                let p = periods(a)[1].clone();
                periods(a).push(p);
            }),
        ),
        (
            "the open period counted",
            Box::new(|a| {
                periods(a).push(json!({"from": WEEK_2, "to": WEEK_3, "cells": [cell(None, Err("below_floor"))]}));
            }),
        ),
        (
            "a start in another time form",
            Box::new(|a| {
                periods(a)[0]["from"] = json!("2026-01-05T00:00:00+00:00");
            }),
        ),
        (
            "a cell below the floor published",
            Box::new(|a| {
                periods(a)[0]["cells"][1] = cell(Some("b"), Ok(3));
            }),
        ),
        (
            "the complementary cell published",
            Box::new(|a| {
                periods(a)[0]["cells"][0] = cell(Some("a"), Ok(9));
            }),
        ),
        (
            "a cell twice",
            Box::new(|a| {
                let c = periods(a)[1]["cells"][0].clone();
                periods(a)[1]["cells"].as_array_mut().unwrap().insert(0, c);
            }),
        ),
        (
            "two totals",
            Box::new(|a| {
                periods(a)[1]["cells"]
                    .as_array_mut()
                    .unwrap()
                    .push(cell(None, Err("below_floor")));
            }),
        ),
        (
            "models that do not add up",
            Box::new(|a| {
                periods(a)[1]["cells"][2] = cell(None, Ok(19));
            }),
        ),
        (
            "a sum past u64",
            Box::new(|a| {
                periods(a)[1]["cells"][0] = cell(Some("a"), Ok(u64::MAX));
            }),
        ),
        (
            "a count labelled peer_confirmed",
            Box::new(|a| {
                periods(a)[1]["cells"][2]["label"] = json!("peer_confirmed");
            }),
        ),
        (
            "served and requested counted together",
            Box::new(|a| {
                periods(a)[1]["cells"][2]["unit"] = json!("exchanges");
            }),
        ),
        (
            "another policy",
            Box::new(|a| {
                a.get_mut("period_counts").unwrap()["policy"] = json!("00".repeat(32));
            }),
        ),
        (
            "a wrong live-set count",
            Box::new(|a| {
                a.get_mut("coverage_declaration").unwrap()["live_set"][0]["count"] = json!(29);
            }),
        ),
        (
            "an interval that starts later",
            Box::new(|a| {
                a.get_mut("coverage_declaration").unwrap()["interval"]["from"] =
                    json!("00".repeat(32));
            }),
        ),
        (
            "the card for another subject",
            Box::new(|a| {
                a.get_mut("history_card").unwrap()["subject"] = json!({"checkpoints": null});
            }),
        ),
        (
            "a member the definition does not list",
            Box::new(|a| {
                a.insert("served_summary".into(), json!({}));
            }),
        ),
        (
            "another derivation",
            Box::new(|a| {
                a.insert("derivation".into(), json!("00".repeat(32)));
            }),
        ),
        (
            "another subject",
            Box::new(|a| {
                a.get_mut("history_card").unwrap()["subject"] = json!({"checkpoints": null});
                a.insert("subject".into(), json!({"checkpoints": null}));
            }),
        ),
        (
            "a member dropped",
            Box::new(|a| {
                a.remove("period_counts");
            }),
        ),
    ];
    for (name, change) in cases {
        let mut tampered = art.clone();
        change(&mut tampered);
        // Keep the card digest true to the card, so the change itself is
        // what fails.
        tampered.insert(
            "history_card_digest".into(),
            json!(digest_of(&tampered["history_card"])),
        );
        assert!(check(&tampered, &chain, &anchor).is_err(), "{name}");
    }
}

#[test]
fn an_anchor_off_a_boundary_does_not_check() {
    let (art, mut chain, anchor) = built();
    chain.last_mut().unwrap().timestamp = "2026-01-19T00:01:00Z";
    let why = check(&art, &chain, &anchor).unwrap_err();
    assert!(why.starts_with("period_anchor"), "{why}");
}

#[test]
fn a_card_digest_that_is_not_the_card_does_not_check() {
    let (mut art, chain, anchor) = built();
    art.insert("history_card_digest".into(), json!("00".repeat(32)));
    assert!(check(&art, &chain, &anchor).is_err());
}

/// Two models withheld and one published above the total: not the
/// complementary rule, the sum.
#[test]
fn a_published_model_above_the_total_does_not_check() {
    let (mut art, chain, anchor) = built();
    periods(&mut art)[1]["cells"] = json!([
        cell(Some("a"), Err("below_floor")),
        cell(Some("b"), Err("below_floor")),
        cell(Some("c"), Ok(20)),
        cell(None, Ok(12)),
    ]);
    let why = check(&art, &chain, &anchor).unwrap_err();
    assert!(why.contains("do not add up"), "{why}");
}

/// The first period is the one that holds the stream's first record, and a
/// stream with no record lists none (ISH §6.1 item 3, §6.3).
#[test]
fn periods_start_at_the_first_record_and_an_empty_stream_lists_none() {
    let def = definition();
    let list = vec![Some("a"); 6];
    // Two empty checkpoints, then the first record in week 1.
    let chain = cuts(&[
        ("2026-01-06T00:00:00Z", 0),
        ("2026-01-07T00:00:00Z", 0),
        ("2026-01-13T00:00:00Z", 6),
        (WEEK_2, 6),
    ]);
    let counts = period_counts(&def, &chain, &models(&list)).unwrap();
    assert_eq!(counts["periods"].as_array().unwrap().len(), 1);
    assert_eq!(counts["periods"][0]["from"], json!(WEEK_1));
    let empty = cuts(&[("2026-01-06T00:00:00Z", 0), (WEEK_2, 0)]);
    let none = period_counts(&def, &empty, &models(&[])).unwrap();
    assert_eq!(none["periods"], json!([]));
    // A checker holds the same expectation.
    let pin = "ab".repeat(32);
    let card = json!({"anchor": pin, "derivation": "history_card/1",
        "evidence_stream": STREAM, "subject": {"full_history": null}, "history": []});
    let octets = artifact(&def, &jcs(&card).unwrap(), none, &pin, STREAM, 0).unwrap();
    let art = serde_json::from_slice::<Value>(&octets).unwrap();
    let art = art.as_object().unwrap();
    let checked = check_artifact(&def, art, &empty, &pin, STREAM, 0).unwrap();
    assert!(checked.periods.is_empty());
    let full = cuts(&[("2026-01-06T00:00:00Z", 1), (WEEK_2, 1)]);
    assert!(check_artifact(&def, art, &full, &pin, STREAM, 0).is_err());
}

/// A period index no Unix time can hold gives no start, not a wrap or a
/// panic (`jcs` already refuses a `length_s` past 2^53).
#[test]
fn a_period_past_a_unix_time_has_no_start() {
    let def = definition();
    assert_eq!(def.policy().start_of(i64::MAX / 2), None);
    assert!(def.policy().start_of(-1).is_some());
}
