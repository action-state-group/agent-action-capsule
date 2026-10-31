// SPDX-License-Identifier: BSD-3-Clause
//! The `composed/v1` Evidence Bundle extension: `vectors/bundle/composed/`
//! and `vectors/bundle/composed-controller-binding/`, read as
//! `go/bundle/composed_test.go` and `composed_binding_test.go` read them.

use agent_action_capsule::bundle::{
    composed_digest, composed_digest_preimage, verify_bundle_strict, verify_bundle_with_options,
    BundleOptions, ComposedOptions, ComposedResult, StrictOptions, VerificationResult,
    COMPOSED_KIND,
};
use agent_action_capsule::verify::decode_capsule_json;
use serde_json::{json, Map, Value};

fn cases(directory: &str, count: usize) -> Vec<Value> {
    let path = format!(
        "{}/../../vectors/bundle/{directory}/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let data = std::fs::read(&path).expect("vectors.json");
    let vectors = decode_capsule_json(&data).expect("valid JSON");
    let cases = vectors["cases"].as_array().expect("cases").clone();
    assert_eq!(cases.len(), count, "{directory}");
    assert_eq!(vectors["count"], json!(count), "{directory}");
    cases
}

/// Compare through the canonical text so number spellings agree.
fn same(got: &Value, want: &Value) -> bool {
    let got: Value = serde_json::from_str(&got.to_string()).unwrap();
    let want: Value = serde_json::from_str(&want.to_string()).unwrap();
    got == want
}

fn block_of(container: &Value) -> &Value {
    &container["extensions"][COMPOSED_KIND]
}

fn composed_of(result: &VerificationResult) -> &ComposedResult {
    assert_eq!(result.extensions.len(), 1);
    let extension = &result.extensions[0];
    assert_eq!(extension.kind, COMPOSED_KIND);
    assert!(extension.integrity_covered);
    let composed = extension.composed.as_ref().expect("a composed result");
    assert_eq!(composed.status, extension.status);
    composed
}

/// A composed result in the vectors' `expect` vocabulary.
fn expect_shape(result: &ComposedResult) -> Value {
    let mut members = Map::new();
    for m in &result.members {
        let claims = m.bundle.as_ref().map(|b| {
            json!({
                "graph_closure": b.graph_closure.status,
                "interval_coverage": b.interval_coverage.status,
                "per_record_membership": b.per_record_membership.status,
            })
        });
        let mut member = json!({
            "outcome": m.outcome, "body": m.body, "digest": m.digest, "claims": claims,
        });
        if let Some(history) = m.bundle.as_ref().and_then(|b| b.history.as_ref()) {
            member["history"] = json!({"state": history.state, "since": history.since});
        }
        if let Some(signature) = &m.response_signature {
            let binding = |finding: &str| {
                if m.findings.iter().any(|f| f == finding) {
                    "mismatch"
                } else {
                    "matches"
                }
            };
            member["response"] = json!({
                "request_digest": binding("response_request_digest_mismatch"),
                "artifact_digest": binding("response_artifact_digest_mismatch"),
                "signature": signature,
            });
        }
        members.insert(m.id.clone(), member);
    }
    let closure = result.composition_closure.as_ref().unwrap();
    let mut closure_value = json!({"status": closure.status, "missing": closure.missing});
    if closure.status == "withheld" {
        closure_value["finding"] = json!(closure.findings[0]);
    }
    let joins: Vec<Value> = result
        .joins
        .iter()
        .map(|j| {
            json!({
                "members": j.members, "declared": j.declared,
                "derived": j.derived, "result": j.result,
            })
        })
        .collect();
    let corroboration: Vec<Value> = result
        .corroboration
        .iter()
        .map(|c| {
            let mut value = json!({"members": c.members, "result": c.result});
            for (key, field) in [
                ("reason", &c.reason),
                ("report", &c.report),
                ("qualifier", &c.qualifier),
            ] {
                if let Some(field) = field {
                    value[key] = json!(field);
                }
            }
            value
        })
        .collect();
    json!({
        "composed_digest": result.composed_digest.as_ref().unwrap().recomputed,
        "status": result.status,
        "members": members,
        "composition_closure": closure_value,
        "joins": joins,
        "corroboration": corroboration,
    })
}

fn expectation(expect: &Value, skip: &[&str]) -> Value {
    let mut want = expect.as_object().unwrap().clone();
    for key in skip {
        want.remove(*key);
    }
    Value::Object(want)
}

fn options_of<'a>(case: &'a Value) -> BundleOptions<'a> {
    let list = |name: &str| -> &'a [Value] {
        case.get(name)
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice)
    };
    BundleOptions {
        composed: ComposedOptions {
            controller_bindings: list("controller_bindings"),
            binding_revocations: list("binding_revocations"),
            ..ComposedOptions::default()
        },
        ..BundleOptions::default()
    }
}

fn member_bundle<'a>(block: &'a Value, id: &str) -> &'a Value {
    block["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == json!(id))
        .map(|m| &m["bundle"])
        .expect("member")
}

#[test]
fn composed_vectors() {
    let cases = cases("composed", 6);
    let by_id = |id: &str| cases.iter().find(|c| c["id"] == json!(id)).unwrap();
    for case in &cases {
        let id = case["id"].as_str().unwrap();
        let container = &case["container"];
        let expect = &case["expect"];
        let block = block_of(container);
        let preimage = composed_digest_preimage(block).expect("preimage");
        assert_eq!(
            expect["canonical_preimage"].as_str().unwrap().as_bytes(),
            preimage.as_slice(),
            "{id}"
        );
        let digest = composed_digest(block).expect("digest");
        assert_eq!(expect["composed_digest"], json!(digest), "{id}");
        assert_eq!(block["composed_digest"], json!(digest), "{id}");

        let result = verify_bundle_with_options(container, &options_of(case));
        assert_eq!(result.graph_closure.status, "pass", "{id}");
        let composed = composed_of(&result);
        assert_eq!(
            expect["status"],
            json!(composed.status),
            "{id}: {:?}",
            composed.findings
        );
        assert!(composed.composed_digest.as_ref().unwrap().matches, "{id}");
        assert_ne!(
            result.bundle_digest.as_deref(),
            Some(
                composed
                    .composed_digest
                    .as_ref()
                    .unwrap()
                    .recomputed
                    .as_str()
            ),
            "{id}"
        );
        let want = expectation(
            expect,
            &[
                "canonical_preimage",
                "composed_digest_equals_case",
                "strict",
                "verdict",
            ],
        );
        assert!(
            same(&expect_shape(composed), &want),
            "{id}: {}",
            expect_shape(composed)
        );

        for member in &composed.members {
            if let Some(carried) = &member.bundle {
                let declared = block["members"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|m| m["id"] == json!(member.id))
                    .map(|m| m["digest"].as_str().unwrap());
                assert_eq!(declared, carried.bundle_digest.as_deref(), "{id}");
            }
        }

        // The strict verdicts of the container and each carried member
        // Bundle, and the full verdict: VALID only when every strict verdict
        // is and the block passes.
        let strict = |bundle: &Value| verify_bundle_strict(bundle, &StrictOptions::default());
        let container_verdict = strict(container).verdict();
        let mut members = Map::new();
        let mut full = container_verdict == "VALID" && composed.status == "pass";
        for member in &composed.members {
            if member.bundle.is_some() {
                let verdict = strict(member_bundle(block, &member.id)).verdict();
                members.insert(member.id.clone(), json!(verdict));
                full = full && verdict == "VALID";
            }
        }
        if let Some(want) = expect.get("strict") {
            assert_eq!(
                want,
                &json!({"container": container_verdict, "members": members}),
                "{id}"
            );
            assert_eq!(
                expect["verdict"],
                json!(if full { "VALID" } else { "INCOMPLETE" }),
                "{id}"
            );
        } else {
            assert!(
                !full,
                "{id}: only a case that states its verdict reaches VALID"
            );
        }
    }
    let agree = &by_id("agree")["expect"]["composed_digest"];
    for id in [
        "one-member-missing",
        "artifact-response-bound",
        "artifact-response-other-request",
    ] {
        assert_eq!(agree, &by_id(id)["expect"]["composed_digest"], "{id}");
        assert_eq!(
            by_id(id)["expect"]["composed_digest_equals_case"],
            json!("agree")
        );
    }
}

#[test]
fn composed_controller_binding_vectors() {
    for case in cases("composed-controller-binding", 14) {
        let id = case["id"].as_str().unwrap();
        let container = &case["container"];
        let expect = &case["expect"];
        let preimage = composed_digest_preimage(block_of(container)).expect("preimage");
        assert_eq!(
            expect["canonical_preimage"].as_str().unwrap().as_bytes(),
            preimage.as_slice(),
            "{id}"
        );
        let result = verify_bundle_with_options(container, &options_of(&case));
        let composed = composed_of(&result);
        assert_eq!(
            expect["status"],
            json!(composed.status),
            "{id}: {:?}",
            composed.findings
        );
        let want = expectation(expect, &["canonical_preimage"]);
        assert!(
            same(&expect_shape(composed), &want),
            "{id}: {}",
            expect_shape(composed)
        );
    }
}

/// Without the delivered records, every controller_binding join is not
/// derivable: the basis never derives from the block alone.
#[test]
fn controller_binding_needs_the_delivered_record() {
    for case in cases("composed-controller-binding", 14) {
        let id = case["id"].as_str().unwrap();
        let result = verify_bundle_with_options(&case["container"], &BundleOptions::default());
        let composed = composed_of(&result);
        assert_eq!(composed.joins[0].result, "not_derivable", "{id}");
        assert_eq!(composed.corroboration[0].result, "not_applicable", "{id}");
    }
}

/// A malformed block reports no composition.
#[test]
fn a_malformed_block_reports_no_composition() {
    let case = cases("composed", 6).remove(0);
    let mut container = case["container"].clone();
    container["extensions"][COMPOSED_KIND]["observers"] = json!([]);
    let result = verify_bundle_with_options(&container, &BundleOptions::default());
    let composed = composed_of(&result);
    assert!(composed.malformed);
    assert_eq!(composed.status, "fail");
    assert!(composed.composed_digest.is_none() && composed.members.is_empty());
}

fn linked_case() -> Value {
    cases("composed-controller-binding", 14)
        .into_iter()
        .find(|c| c["id"] == json!("controller-binding-linked"))
        .unwrap()
}

/// Verify the linked case with `record` delivered in place of its binding,
/// the join pointed at the record's digest and the block resealed. Returns
/// the join's derived state, its result and the corroboration result.
fn derive_with(record: &Value) -> (Option<String>, String, String) {
    let case = linked_case();
    let mut container = case["container"].clone();
    let mut unsigned = record.as_object().unwrap().clone();
    unsigned.remove("sigs");
    let digest = agent_action_capsule::canonical::json_digest(&Value::Object(unsigned)).unwrap();
    let block = &mut container["extensions"][COMPOSED_KIND];
    block["joins"][0]["identifier_digest"] = json!(digest);
    let resealed = composed_digest(block).unwrap();
    block["composed_digest"] = json!(resealed);
    let bindings = [record.clone()];
    let options = BundleOptions {
        composed: ComposedOptions {
            controller_bindings: &bindings,
            ..ComposedOptions::default()
        },
        ..BundleOptions::default()
    };
    let result = verify_bundle_with_options(&container, &options);
    let composed = composed_of(&result);
    (
        composed.joins[0].derived.clone(),
        composed.joins[0].result.clone(),
        composed.corroboration[0].result.clone(),
    )
}

type Mutation = fn(&mut Value);

/// A binding the verifier received but cannot read under the join's keys is
/// unjoined, never corroborating, whichever way its signatures fail.
#[test]
fn controller_binding_signature_failures_never_corroborate() {
    let base = linked_case()["controller_bindings"][0].clone();
    // The unmodified record is the baseline: it links.
    assert_eq!(derive_with(&base).2, "redundant");
    let mutations: [(&str, Mutation); 4] = [
        ("second signature from the first key", |r| {
            r["sigs"][1]["sig"] = r["sigs"][0]["sig"].clone();
        }),
        ("one signature", |r| {
            r["sigs"] = json!([r["sigs"][0].clone()]);
        }),
        ("third signature", |r| {
            let first = r["sigs"][0].clone();
            r["sigs"].as_array_mut().unwrap().push(first);
        }),
        ("sigs out of key order", |r| {
            r["sigs"] = json!([r["sigs"][1].clone(), r["sigs"][0].clone()]);
        }),
    ];
    for (name, mutate) in mutations {
        let mut record = base.clone();
        mutate(&mut record);
        let (derived, result, corroboration) = derive_with(&record);
        assert_eq!(derived.as_deref(), Some("unjoined"), "{name}");
        assert_eq!(result, "join_state_mismatch", "{name}");
        assert_eq!(corroboration, "not_applicable", "{name}");
    }
}

/// The places Bundle -02's form differs from Controller Binding v0, and the
/// key-type restriction.
#[test]
fn controller_binding_bundle_02_form_rules() {
    let base = linked_case()["controller_bindings"][0].clone();
    // Malformed in -02: the join derives, unjoined.
    let malformed: [(&str, Mutation); 3] = [
        ("empty nonce", |r| r["nonce"] = json!("")),
        ("sig under ed25519 keys is not sig-hex", |r| {
            r["sigs"][0]["sig"] = json!("zz");
        }),
        ("key_types not two strings", |r| {
            r["key_types"] = json!(["ed25519", 1]);
        }),
    ];
    for (name, mutate) in malformed {
        let mut record = base.clone();
        mutate(&mut record);
        assert_eq!(
            derive_with(&record).0.as_deref(),
            Some("unjoined"),
            "{name}"
        );
    }
    // Well formed but not implemented: not derivable, even where CB v0's own
    // bip340 nonce rule would call the record malformed.
    let unimplemented: [(&str, Mutation); 3] = [
        ("other key type", |r| {
            r["key_types"] = json!(["ed25519", "x-example-type"]);
            r["sigs"][1]["sig"] = json!({"x": "y"});
        }),
        ("bip340 key with a short nonce", |r| {
            r["key_types"] = json!(["ed25519", "bip340"]);
            r["sigs"][1]["sig"] = json!({"created_at": 1, "sig": "0".repeat(128)});
        }),
        ("undefined method token", |r| {
            r["method"] = json!("x-example-method/0");
        }),
    ];
    for (name, mutate) in unimplemented {
        let mut record = base.clone();
        mutate(&mut record);
        assert_eq!(derive_with(&record).0, None, "{name}");
    }
}
