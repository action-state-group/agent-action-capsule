//! The interop profile's acceptance cases (`vectors/interop-profile-v0/`,
//! the `acceptance-*` cases), and session-scoped cases frozen from the
//! profile's Python verifier (`tests/vectors/acceptance-session.json`, made by
//! `tests/scripts/acceptance_session_cases.py`): for every case, the finding,
//! each candidate's and each receipt's property statuses, and the claim
//! fields the expected report states.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use evidence_request::acceptance::{
    self, read_fixture_execution_record, AcceptanceResult, Finding, Inputs, TrustPolicy,
};
use evidence_request::time::parse_rfc3339;
use serde_json::{json, Map, Value};

fn load(path: &str) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap()
}

fn as_slices(v: &[Vec<u8>]) -> Vec<&[u8]> {
    v.iter().map(Vec::as_slice).collect()
}

fn trust_of(pin: &Value) -> TrustPolicy {
    let parties = pin["parties"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                .collect()
        })
        .unwrap_or_default();
    let key_validity = pin
        .get("key_validity")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, w)| {
                    let at = |n: &str| {
                        w.get(n)
                            .and_then(Value::as_str)
                            .map(|t| parse_rfc3339(t).unwrap())
                    };
                    (k.clone(), (at("not_before"), at("not_after")))
                })
                .collect()
        })
        .unwrap_or_default();
    TrustPolicy {
        parties,
        key_validity,
        require_action_time_from_other_party: pin["require_action_time_from_other_party"]
            .as_bool()
            .unwrap_or(false),
    }
}

fn texts(v: &Value) -> Vec<Vec<u8>> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|t| t.as_str().unwrap().as_bytes().to_vec())
                .collect()
        })
        .unwrap_or_default()
}

/// The report in the vectors' shape.
fn shape(res: &AcceptanceResult) -> Value {
    let props = |ps: &[acceptance::PropertyReport]| -> Map<String, Value> {
        ps.iter()
            .map(|p| (p.property.to_string(), Value::from(p.status.as_str())))
            .collect()
    };
    let mut out = json!({
        "finding": res.finding.as_str(),
        "candidates": res.candidates.iter().map(|c| json!({
            "record_digest": c.record_digest, "properties": props(&c.properties)})).collect::<Vec<_>>(),
        "receipts": res.receipts.iter().map(|r| json!({
            "receipt_digest": r.receipt_digest, "properties": props(&r.properties)})).collect::<Vec<_>>(),
    });
    if res.finding != Finding::NotAccepted {
        out["claim"] = json!({
            "contract_ref": res.contract_ref,
            "evidence_includes": res.evidence.iter()
                .map(|d| json!({"digest_alg": "SHA-256", "digest": d})).collect::<Vec<_>>(),
        });
    }
    out
}

fn run(case: &Value, contract: &Value, session: bool) -> Value {
    let pins = &case["pins"];
    let inp = &case["inputs"];
    let trust = trust_of(&pins["trust_policy"]);
    let (records, execs, receipts) = (
        texts(&inp["acceptance_records"]),
        texts(&inp["execution_records"]),
        texts(&inp["acceptance_receipts"]),
    );
    let (records, execs, receipts) = (as_slices(&records), as_slices(&execs), as_slices(&receipts));
    let implemented: Vec<&str> = pins["verification_policy"]["profiles_implemented"]
        .as_array()
        .map(|a| a.iter().map(|p| p.as_str().unwrap()).collect())
        .unwrap_or_else(|| vec![acceptance::PROFILE_ID]);
    let res = acceptance::evaluate(
        &Inputs {
            contract,
            transaction: &inp["transaction"],
            proposer: inp["proposer"].as_str().unwrap(),
            acceptor: inp["acceptor"].as_str().unwrap(),
            records: &records,
            execution_records: &execs,
            receipts: &receipts,
            trust: &trust,
            evaluation_time: pins["evaluation_time"].as_str().unwrap(),
            session,
            form_ii_objects: 0,
            profiles_implemented: &implemented,
        },
        read_fixture_execution_record,
    )
    .unwrap();
    shape(&res)
}

#[test]
fn every_corpus_acceptance_case_gives_the_expected_report() {
    let corpus = load(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/interop-profile-v0/vectors.json"
    ));
    let contract = &corpus["contract"]["document"];
    let mut ran = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        if !id.starts_with("acceptance-") {
            continue;
        }
        assert_eq!(
            case["pins"]["contract_digest"],
            json!(acceptance::record_digest(contract).unwrap()),
            "{id}: the corpus contract"
        );
        assert_eq!(run(case, contract, false), case["expected"], "{id}");
        ran += 1;
    }
    assert_eq!(ran, 9, "the corpus has nine acceptance cases");
}

#[test]
fn every_session_case_gives_the_reference_verifiers_report() {
    let cases = load(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/acceptance-session.json"
    ));
    let contract = &cases["contract"];
    let mut ran = 0;
    for case in cases["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        assert_eq!(run(case, contract, true), case["expected"], "{id}");
        ran += 1;
    }
    assert!(ran >= 6, "{ran} session cases");
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn hex_key(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().to_bytes())
}

fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => unreachable!(),
    }
}

/// A proposal, its acceptance, the requester's receipt and one execution
/// record citing the acceptance, all signed by this crate: the finding is
/// `accepted_before_action`, and each object is read back exactly.
#[test]
fn records_this_crate_signs_verify_and_order() {
    let (p, q) = (key(1), key(2));
    let (pk, qk) = (hex_key(&p), hex_key(&q));
    let contract = json!({"id": "C", "version": "1", "requirements": [{"id": "r"}]});
    let contract_digest = acceptance::record_digest(&contract).unwrap();
    let transaction = json!({"scheme": "x-test/session", "id": "s1"});
    let session =
        json!({"not_before": "2026-10-12T00:00:00Z", "not_after": "2026-10-12T01:00:00Z"});
    let common = |state: &str, at: &str| {
        obj(json!({
            "profile": "evidence-interop/0", "state": state, "contract_ref": "C@1",
            "contract_digest": contract_digest, "transaction": transaction,
            "proposer": pk, "acceptor": qk, "issued_at": at, "session": session,
        }))
    };
    let proposed =
        Value::Object(acceptance::sign(common("proposed", "2026-10-12T00:00:00Z"), &p).unwrap());
    let mut answer = common("accepted", "2026-10-12T00:05:00Z");
    answer.insert(
        "proposal_digest".into(),
        acceptance::record_digest(&proposed).unwrap().into(),
    );
    let accepted = Value::Object(acceptance::sign(answer, &q).unwrap());
    let acceptance_digest = acceptance::record_digest(&accepted).unwrap();
    let receipt = Value::Object(
        acceptance::sign(
            obj(
                json!({"profile": "evidence-interop/0", "acceptance_digest": acceptance_digest,
                       "received_at": "2026-10-12T00:06:00Z", "receiver": pk}),
            ),
            &p,
        )
        .unwrap(),
    );
    let exec = Value::Object(
        acceptance::sign(
            obj(json!({"action_at": "2026-10-12T00:10:00Z", "issuer": qk,
                       "links": [{"type": "cites", "target": acceptance_digest}],
                       "transaction": transaction})),
            &q,
        )
        .unwrap(),
    );
    let octets = |v: &Value| serde_json::to_vec(v).unwrap();
    for v in [&proposed, &accepted, &receipt] {
        assert_eq!(
            acceptance::parse(&octets(v)).as_ref(),
            Some(v),
            "read back exactly"
        );
    }
    let trust = TrustPolicy {
        parties: BTreeMap::from([(pk.clone(), "P".into()), (qk.clone(), "Q".into())]),
        ..TrustPolicy::default()
    };
    let (records, execs, receipts) = (
        [octets(&proposed), octets(&accepted)],
        [octets(&exec)],
        [octets(&receipt)],
    );
    let evaluate = |receipts: &[&[u8]], execs: &[&[u8]]| {
        acceptance::evaluate(
            &Inputs {
                contract: &contract,
                transaction: &transaction,
                proposer: &pk,
                acceptor: &qk,
                records: &[&records[0], &records[1]],
                execution_records: execs,
                receipts,
                trust: &trust,
                evaluation_time: "2026-10-12T02:00:00Z",
                session: true,
                form_ii_objects: 0,
                profiles_implemented: &[acceptance::PROFILE_ID],
            },
            read_fixture_execution_record,
        )
        .unwrap()
    };
    let res = evaluate(&[&receipts[0]], &[&execs[0]]);
    assert_eq!(res.finding, Finding::AcceptedBeforeAction);
    assert_eq!(res.evidence.len(), 2, "the record and the receipt");
    // Without the receipt the citation alone is not ordering evidence (P-28).
    let res = evaluate(&[], &[&execs[0]]);
    assert_eq!(res.finding, Finding::AcceptedExecutionCites);
}

#[test]
fn the_parse_refuses_a_duplicate_member_name() {
    assert!(acceptance::parse(br#"{"a":"x","b":{"c":1,"c":2}}"#).is_none());
    assert!(acceptance::parse(br#"{"a":"x","a":"x"}"#).is_none());
    assert!(acceptance::parse(br#"{"a":"x","b":{"c":1}}"#).is_some());
}

#[test]
fn the_parse_refuses_a_number_outside_the_profile_integers() {
    for text in [
        r#"{"n":1.0}"#,
        r#"{"n":1e3}"#,
        r#"{"n":-1}"#,
        r#"{"n":9007199254740992}"#,
    ] {
        assert!(acceptance::parse(text.as_bytes()).is_none(), "{text}");
    }
    assert!(acceptance::parse(br#"{"n":9007199254740991}"#).is_some());
}

#[test]
fn a_duplicated_record_is_unreadable_not_a_candidate() {
    let corpus = load(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/interop-profile-v0/vectors.json"
    ));
    let contract = &corpus["contract"]["document"];
    let mut case = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "acceptance-backdated-E-control")
        .unwrap()
        .clone();
    let before = run(&case, contract, false);
    assert_ne!(before["finding"], json!("not_accepted"));
    // The same accepted record with one member written twice.
    let records = case["inputs"]["acceptance_records"].as_array_mut().unwrap();
    for r in records.iter_mut() {
        let text = r.as_str().unwrap().to_string();
        if text.contains(r#""state":"accepted""#) {
            *r = Value::from(text.replacen(
                r#""state":"accepted""#,
                r#""state":"accepted","state":"accepted""#,
                1,
            ));
        }
    }
    assert_eq!(
        run(&case, contract, false)["finding"],
        json!("not_accepted")
    );
}
