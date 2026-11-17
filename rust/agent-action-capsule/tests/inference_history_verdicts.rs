//! The optional `verdict_counts` member (ISH §4.3, §5.3): derived over the
//! same periods as `period_counts`, each result its own floor table, checked
//! by `check_artifact`, and the rules a checker rejects one at a time.

use agent_action_capsule::canonical::jcs;
use agent_action_capsule::inference_history::{
    artifact, artifact_with_verdicts, check_artifact, period_counts, verdict_counts, Counts, Cut,
    Definition, Refusal,
};
use serde_json::{json, Map, Value};

const WEEK_1: &str = "2026-01-12T00:00:00Z";
const WEEK_2: &str = "2026-01-19T00:00:00Z";
const STREAM: &str = "stream-a";
const CHECKPOINTS: [(&str, u64); 4] = [
    ("2026-01-07T10:00:00Z", 6),
    (WEEK_1, 12),
    ("2026-01-14T08:00:00Z", 20),
    (WEEK_2, 30),
];

/// The vectors' Standard definition under a weekly policy, with or without
/// the verdict counts member.
fn document(with_verdicts: bool) -> Value {
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
    d["period_policy"] = json!({"epoch": "2026-01-05T00:00:00Z", "length_s": 604800,
        "min_length_s": 86400, "floor": 5, "suppression": "complementary"});
    if with_verdicts {
        let reads = json!([
            "record: adjudication_received.verdict",
            "record: adjudication_received.model_hash"
        ]);
        d["members"].as_array_mut().unwrap().push(json!({
            "name": "verdict_counts", "required": true, "reads": reads,
            "units": [{"where": "periods[].cells[]", "unit": "referee_verdicts"}],
        }));
        for r in reads.as_array().unwrap() {
            d["reads"].as_array_mut().unwrap().push(r.clone());
        }
    }
    d
}

fn def() -> Definition {
    Definition::from_document(&document(true)).unwrap()
}

/// Period one (leaves 0..12): model h1 has 7 corroborated and 5
/// contradicted; period two (12..30): h1 6 corroborated, h2 6 corroborated,
/// h2 2 inconclusive, and one record that is no verdict.
fn verdict(leaf: u64) -> Option<(String, String)> {
    let (m, r) = match leaf {
        0..=6 => ("h1", "corroborated"),
        7..=11 => ("h1", "contradicted"),
        12..=17 => ("h1", "corroborated"),
        18..=23 => ("h2", "corroborated"),
        24..=25 => ("h2", "inconclusive"),
        26 => return None,
        _ => ("h2", "not_a_result"),
    };
    Some((m.into(), r.into()))
}

fn chain() -> Vec<Cut<'static>> {
    CHECKPOINTS
        .iter()
        .map(|&(timestamp, leaves)| Cut { timestamp, leaves })
        .collect()
}

fn built() -> (Map<String, Value>, Vec<Cut<'static>>, String) {
    let d = def();
    let anchor = "ab".repeat(32);
    let card = json!({
        "anchor": anchor, "derivation": "history_card/1", "evidence_stream": STREAM,
        "history": CHECKPOINTS.iter().map(|(t, n)| json!({"checkpoint": {"timestamp": t, "log_size": n}})).collect::<Vec<_>>(),
        "subject": {"full_history": null},
    });
    let chain = chain();
    let counts = period_counts(&d, &chain, &|_| Some("a".to_string())).unwrap();
    let verdicts = verdict_counts(&d, &chain, &verdict).unwrap();
    let octets = artifact_with_verdicts(
        &d,
        &jcs(&card).unwrap(),
        counts,
        verdicts,
        &anchor,
        STREAM,
        30,
    )
    .unwrap();
    let art: Value = serde_json::from_slice(&octets).unwrap();
    assert_eq!(jcs(&art).unwrap(), octets);
    (art.as_object().unwrap().clone(), chain, anchor)
}

fn check(art: &Map<String, Value>, chain: &[Cut<'_>], anchor: &str) -> Result<Counts, String> {
    check_artifact(&def(), art, chain, anchor, STREAM)
}

fn cell<'a>(period: &'a Value, result: &str, hash: Option<&str>) -> &'a Value {
    period["cells"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["dimension"]["result"] == json!(result)
                && c["dimension"].get("model_hash").and_then(Value::as_str) == hash
        })
        .unwrap()
}

#[test]
fn each_result_is_its_own_floor_table_over_the_same_periods() {
    let (art, chain, anchor) = built();
    let v = &art["verdict_counts"];
    assert_eq!(v["check"], json!("referee_verdict"));
    assert_eq!(v["signed_by"], json!("checker"));
    assert_eq!(
        art["declared"],
        json!(["history_card", "period_counts", "verdict_counts"])
    );
    let p = v["periods"].as_array().unwrap();
    assert_eq!(p.len(), 2);
    assert_eq!(p[0]["from"], art["period_counts"]["periods"][0]["from"]);
    // Period one: 7 corroborated, 5 contradicted, none else: totals at the
    // floor publish, the two empty results are withheld.
    assert_eq!(cell(&p[0], "corroborated", None)["value"], json!(7));
    assert_eq!(cell(&p[0], "corroborated", Some("h1"))["value"], json!(7));
    assert_eq!(cell(&p[0], "contradicted", None)["value"], json!(5));
    assert_eq!(
        cell(&p[0], "inconclusive", None)["suppressed"],
        json!("below_floor")
    );
    assert_eq!(cell(&p[0], "not_comparable", None)["value"], Value::Null);
    // Period two: h2 has 2 inconclusive (below the floor, total withheld),
    // and a record naming another result counts nowhere.
    assert_eq!(cell(&p[1], "corroborated", None)["value"], json!(12));
    assert_eq!(
        cell(&p[1], "inconclusive", Some("h2"))["suppressed"],
        json!("below_floor")
    );
    let counts = check(&art, &chain, &anchor).unwrap();
    let verdicts = counts.verdicts.unwrap();
    assert_eq!(verdicts.len(), 2);
    assert_eq!(verdicts[0].cells.len(), 6); // two results with h1 and a total, two with a total
}

#[test]
fn a_one_suppressed_model_beside_a_published_total_is_withheld_with_its_neighbour() {
    // h1 has 3 and h2 has 6 contradicted in one period: the total 9 is
    // published, so h2 (the smallest published other) goes with h1.
    let d = def();
    let chain = vec![
        Cut {
            timestamp: "2026-01-07T10:00:00Z",
            leaves: 9,
        },
        Cut {
            timestamp: WEEK_1,
            leaves: 9,
        },
    ];
    let v = verdict_counts(&d, &chain, &|i| {
        Some((
            if i < 3 { "h1" } else { "h2" }.into(),
            "contradicted".into(),
        ))
    })
    .unwrap();
    let p = &v["periods"][0];
    assert_eq!(
        cell(p, "contradicted", Some("h1"))["suppressed"],
        json!("below_floor")
    );
    assert_eq!(
        cell(p, "contradicted", Some("h2"))["suppressed"],
        json!("complementary")
    );
    assert_eq!(cell(p, "contradicted", None)["value"], json!(9));
}

#[test]
fn an_anchor_off_a_boundary_is_declined() {
    let d = def();
    let chain = vec![Cut {
        timestamp: "2026-01-13T00:00:00Z",
        leaves: 3,
    }];
    assert_eq!(
        verdict_counts(&d, &chain, &verdict).unwrap_err(),
        Refusal::PolicyDeclined
    );
}

#[test]
fn a_definition_and_an_artifact_agree_on_whether_there_are_verdict_counts() {
    let plain = Definition::from_document(&document(false)).unwrap();
    assert!(!plain.has_verdict_counts());
    assert!(def().has_verdict_counts());
    assert_ne!(plain.digest(), def().digest());
    let (art, chain, anchor) = built();
    // A definition without the member refuses that artifact, and the other way.
    assert!(check_artifact(&plain, &art, &chain, &anchor, STREAM).is_err());
    let d = def();
    let card = serde_json::to_vec(&art["history_card"]).unwrap();
    let counts = art["period_counts"].clone();
    assert!(artifact(
        &d,
        &jcs(&serde_json::from_slice::<Value>(&card).unwrap()).unwrap(),
        counts.clone(),
        &anchor,
        STREAM,
        30
    )
    .is_err());
    assert!(artifact_with_verdicts(&plain, &card, counts, json!({}), &anchor, STREAM, 30).is_err());
    // Other members of the definition's member list are refused.
    let mut bad = document(true);
    bad["members"][2]["units"] =
        json!([{"where": "periods[].cells[]", "unit": "exchanges_served"}]);
    assert!(Definition::from_document(&bad).is_err());
    let mut bad = document(true);
    bad["members"][2]["required"] = json!(false);
    assert!(Definition::from_document(&bad).is_err());
}

type Tamper = Box<dyn Fn(&mut Map<String, Value>)>;

fn vperiods(a: &mut Map<String, Value>) -> &mut Vec<Value> {
    a.get_mut("verdict_counts").unwrap()["periods"]
        .as_array_mut()
        .unwrap()
}

#[test]
fn a_tampered_verdict_member_does_not_check() {
    let (art, chain, anchor) = built();
    let cases: Vec<(&str, Tamper)> = vec![
        (
            "member missing",
            Box::new(|a| {
                a.remove("verdict_counts");
            }),
        ),
        (
            "declared without it",
            Box::new(|a| {
                a.insert("declared".into(), json!(["history_card", "period_counts"]));
            }),
        ),
        (
            "another check",
            Box::new(|a| {
                a.get_mut("verdict_counts").unwrap()["check"] = json!("audit_result");
            }),
        ),
        (
            "signed by the node",
            Box::new(|a| {
                a.get_mut("verdict_counts").unwrap()["signed_by"] = json!("node");
            }),
        ),
        (
            "another policy",
            Box::new(|a| {
                a.get_mut("verdict_counts").unwrap()["policy"] = json!("00");
            }),
        ),
        (
            "a period dropped",
            Box::new(|a| {
                vperiods(a).remove(0);
            }),
        ),
        (
            "an extra member",
            Box::new(|a| {
                a.get_mut("verdict_counts").unwrap()["extra"] = json!(1);
            }),
        ),
        (
            "a published value under the floor",
            Box::new(|a| {
                let c = &mut vperiods(a)[0]["cells"][0];
                c["value"] = json!(2);
            }),
        ),
        (
            "a cell of another unit",
            Box::new(|a| {
                vperiods(a)[0]["cells"][0]["unit"] = json!("exchanges_served");
            }),
        ),
        (
            "a cell of a result no verdict has",
            Box::new(|a| {
                vperiods(a)[0]["cells"][0]["dimension"]["result"] = json!("guilty");
            }),
        ),
        (
            "a cell with no result",
            Box::new(|a| {
                vperiods(a)[0]["cells"][0]["dimension"] = json!({"model_hash": "h1"});
            }),
        ),
        (
            "a cell twice",
            Box::new(|a| {
                let c = vperiods(a)[0]["cells"][0].clone();
                vperiods(a)[0]["cells"].as_array_mut().unwrap().insert(1, c);
            }),
        ),
        (
            "the cells out of order",
            Box::new(|a| {
                vperiods(a)[0]["cells"].as_array_mut().unwrap().reverse();
            }),
        ),
        (
            "a result's total dropped",
            Box::new(|a| {
                let cells = vperiods(a)[0]["cells"].as_array_mut().unwrap();
                let i = cells
                    .iter()
                    .position(|c| c["dimension"]["result"] == json!("not_comparable"))
                    .unwrap();
                cells.remove(i);
            }),
        ),
        (
            "a cell labelled as another label",
            Box::new(|a| {
                vperiods(a)[0]["cells"][0]["label"] = json!("verified");
            }),
        ),
    ];
    for (what, tamper) in cases {
        let mut a = art.clone();
        tamper(&mut a);
        assert!(check(&a, &chain, &anchor).is_err(), "{what} must not check");
    }
    assert!(check(&art, &chain, &anchor).is_ok());
}
