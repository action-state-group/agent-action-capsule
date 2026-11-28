// SPDX-License-Identifier: BSD-3-Clause
//! The carried signature profiles of `composed/v1` (bundle -03, "Carried
//! Signature Profiles"; #676): `vectors/bundle/composed-signature-profiles/`,
//! read as `go/bundle/carried_signatures_test.go` reads it, and the four
//! strict-Ed25519 cases of `vectors/interop-profile-v1/`.

use agent_action_capsule::bundle::{
    artifact_response_signing_input, carried_refusal_profile, carried_response_profile,
    three_member_refusal_signing_input, verify_bundle_with_options, verify_carried_refusal,
    verify_carried_response, verify_digest_bound_artifact_response, verify_three_member_refusal,
    verify_whole_refusal, BundleOptions, ComposedOptions, COMPOSED_KIND,
    DIGEST_BOUND_ARTIFACT_RESPONSE, SIGNATURE_INVALID, SIGNATURE_UNVERIFIED, THREE_MEMBER_REFUSAL,
    WHOLE_REFUSAL,
};
use agent_action_capsule::verify::decode_capsule_json;
use serde_json::{json, Map, Value};

fn read(path: &str) -> Value {
    let data = std::fs::read(format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"))).expect(path);
    decode_capsule_json(&data).expect("valid JSON")
}

fn vectors() -> Value {
    let file = read("vectors/bundle/composed-signature-profiles/vectors.json");
    assert_eq!(file["count"], json!(50));
    assert_eq!(file["cases"].as_array().unwrap().len(), 45);
    assert_eq!(file["composed_cases"].as_array().unwrap().len(), 5);
    file
}

#[test]
fn object_cases() {
    for case in vectors()["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let object = case["object"].as_object().unwrap();
        let (profile, state) = if case["kind"] == "refusal" {
            (
                carried_refusal_profile(object),
                verify_carried_refusal(object),
            )
        } else {
            (
                carried_response_profile(object),
                verify_carried_response(object),
            )
        };
        assert_eq!(
            profile.map(Value::from).unwrap_or(Value::Null),
            case["expect"]["profile"],
            "{id}"
        );
        assert_eq!(state, case["expect"]["state"], "{id}");
        let Some(want) = case["signing_input_hex"].as_str() else {
            continue;
        };
        let got = match profile {
            Some(THREE_MEMBER_REFUSAL) => three_member_refusal_signing_input(object),
            Some(DIGEST_BOUND_ARTIFACT_RESPONSE) => {
                let s = |name: &str| object[name].as_str().unwrap();
                Some(artifact_response_signing_input(
                    s("request_digest"),
                    s("anchor"),
                    s("artifact_kind"),
                    s("artifact_digest"),
                    s("issued_at"),
                ))
            }
            _ => continue,
        };
        assert_eq!(hex::encode(got.unwrap()), want, "{id}");
    }
}

#[test]
fn per_profile_verifiers() {
    type Verify = fn(&Map<String, Value>) -> &'static str;
    let refusal: [(&str, Verify); 2] = [
        (THREE_MEMBER_REFUSAL, verify_three_member_refusal),
        (WHOLE_REFUSAL, verify_whole_refusal),
    ];
    let response: [(&str, Verify); 1] = [(
        DIGEST_BOUND_ARTIFACT_RESPONSE,
        verify_digest_bound_artifact_response,
    )];
    for case in vectors()["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let object = case["object"].as_object().unwrap();
        let verifiers: &[(&str, Verify)] = if case["kind"] == "refusal" {
            &refusal
        } else {
            &response
        };
        for (profile, verify) in verifiers {
            let want = if case["expect"]["profile"] == *profile {
                case["expect"]["state"].as_str().unwrap()
            } else {
                SIGNATURE_UNVERIFIED
            };
            assert_eq!(verify(object), want, "{id} {profile}");
        }
    }
}

#[test]
fn composed_cases() {
    for case in vectors()["composed_cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let with = BundleOptions {
            composed: ComposedOptions {
                refusal_signature: Some(&verify_carried_refusal),
                response_signature: Some(&verify_carried_response),
                ..ComposedOptions::default()
            },
            ..BundleOptions::default()
        };
        let checked = verify_bundle_with_options(&case["container"], &with);
        let plain = verify_bundle_with_options(&case["container"], &BundleOptions::default());
        let block = |r: &agent_action_capsule::bundle::VerificationResult| {
            r.extensions
                .iter()
                .find_map(|e| e.composed.clone())
                .expect(COMPOSED_KIND)
        };
        let (checked, plain) = (block(&checked), block(&plain));
        assert_eq!(checked.status, case["expect"]["status"], "{id}");
        for (member, states) in case["expect"]["members"].as_object().unwrap() {
            for (name, want) in states.as_object().unwrap() {
                let get = |r: &agent_action_capsule::bundle::ComposedResult| {
                    let m = r.members.iter().find(|m| &m.id == member).unwrap();
                    if name == "refusal_signature" {
                        m.refusal_signature.clone()
                    } else {
                        m.response_signature.clone()
                    }
                };
                assert_eq!(
                    get(&checked).as_deref(),
                    want.as_str(),
                    "{id} {member} {name}"
                );
                assert_eq!(
                    get(&plain).as_deref(),
                    Some(SIGNATURE_UNVERIFIED),
                    "{id} {member} default"
                );
            }
        }
    }
}

#[test]
fn interop_v1_forgeries() {
    let file = read("vectors/interop-profile-v1/vectors.json");
    let reply = |id: &str| -> Map<String, Value> {
        let case = file["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .expect(id);
        let text = case["inputs"]["replies"][0]["octets_text"]
            .as_str()
            .unwrap();
        serde_json::from_str(text).unwrap()
    };
    for id in [
        "forged-refusal-small-order-key",
        "forged-refusal-identity-r",
    ] {
        assert_eq!(
            carried_refusal_profile(&reply(id)),
            Some(THREE_MEMBER_REFUSAL),
            "{id}"
        );
        assert_eq!(
            verify_carried_refusal(&reply(id)),
            SIGNATURE_INVALID,
            "{id}"
        );
    }
    for id in ["envelope-small-order-key", "envelope-identity-r"] {
        let envelope = reply(id);
        assert_eq!(
            verify_carried_response(&envelope),
            SIGNATURE_UNVERIFIED,
            "{id}"
        );
        // Only the small-order key's forgery verifies any message under a
        // lenient verifier; the identity-R signature is over the envelope.
        if id != "envelope-small-order-key" {
            continue;
        }
        let rehomed = json!({
            "request_digest": envelope["request_digest"], "anchor": envelope["anchor"]["digest"],
            "artifact_kind": "evidence-bundle/v2", "artifact_digest": envelope["artifact_digest"],
            "issued_at": envelope["issued_at"], "key_id": envelope["responder"], "sig": envelope["sig"],
        });
        assert_eq!(
            verify_carried_response(rehomed.as_object().unwrap()),
            SIGNATURE_INVALID,
            "{id}"
        );
    }
}
