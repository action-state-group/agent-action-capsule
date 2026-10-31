//! `cll_material::check_anchor_inclusion` and `Envelope::verify` against the
//! interop profile's conformance vectors (`vectors/interop-profile-v0/`):
//! for every envelope reply, the `anchor_inclusion` status the corpus states,
//! and `verify` passing exactly when `envelope_signature`, `artifact_digest`
//! and `verification_binding` all do.

use ed25519_dalek::VerifyingKey;
use evidence_request::cll_material::{check_anchor_inclusion, KeyDecision, LogKeyPolicy, Status};
use evidence_request::envelope::{parse_reply, Binding, Reply};
use serde_json::Value;

/// The case's pinned log keys: (iss, sub, kid hex).
struct Pins(Vec<(String, String, String)>);

impl LogKeyPolicy for Pins {
    fn resolve(&self, iss: &str, sub: &str, kid: &[u8], _issued_at: &str) -> KeyDecision {
        let kid_hex = hex::encode(kid);
        let listed = self
            .0
            .iter()
            .any(|(i, s, k)| i == iss && s == sub && *k == kid_hex);
        match (listed, <[u8; 32]>::try_from(kid)) {
            (true, Ok(raw)) => {
                VerifyingKey::from_bytes(&raw).map_or(KeyDecision::Reject, KeyDecision::Accept)
            }
            _ => KeyDecision::Reject,
        }
    }
}

fn status(name: &str) -> Status {
    match name {
        "PASS" => Status::Pass,
        "FAIL" => Status::Fail,
        "NOT_CHECKED" => Status::NotChecked,
        "NOT_PRESENT" => Status::NotPresent,
        "INCONCLUSIVE" => Status::Inconclusive,
        other => panic!("unknown status {other}"),
    }
}

#[test]
fn anchor_inclusion_matches_the_corpus() {
    anchor_inclusion_matches(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/interop-profile-v0/vectors.json"
    ));
}

#[test]
fn anchor_inclusion_matches_the_v1_corpus() {
    anchor_inclusion_matches(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/interop-profile-v1/vectors.json"
    ));
}

fn anchor_inclusion_matches(path: &str) {
    let corpus: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mut checked = 0;
    let mut passed = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let pins = Pins(
            case["pins"]["trust_policy"]["log_keys"]
                .as_array()
                .map(|keys| {
                    keys.iter()
                        .map(|k| {
                            let t = |n: &str| k[n].as_str().unwrap().to_string();
                            (t("iss"), t("sub"), t("kid"))
                        })
                        .collect()
                })
                .unwrap_or_default(),
        );
        let replies = case["inputs"]["replies"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let expected = case["expected"]["replies"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for (i, (reply, want)) in replies.iter().zip(&expected).enumerate() {
            if want["message_type"] != "envelope" {
                continue;
            }
            let props = &want["properties"];
            let octets = match (reply["octets_text"].as_str(), reply["octets_hex"].as_str()) {
                (Some(text), _) => text.as_bytes().to_vec(),
                (None, Some(h)) => hex::decode(h).unwrap(),
                _ => panic!("{id}: reply {i} has no octets"),
            };
            let binding = if reply["media_type"] == "application/cbor" {
                Binding::Cbor
            } else {
                Binding::Json
            };
            let want_inclusion = status(props["anchor_inclusion"].as_str().unwrap());
            let envelope = match parse_reply(&octets, binding) {
                Ok(Reply::Envelope(e)) => e,
                Ok(Reply::Refusal(_)) => panic!("{id}: reply {i} read as a refusal"),
                Err(e) => {
                    // A reply this crate cannot read is never checked.
                    assert_eq!(want_inclusion, Status::NotChecked, "{id}: reply {i}: {e}");
                    checked += 1;
                    continue;
                }
            };
            let all_bound = [
                "envelope_signature",
                "artifact_digest",
                "verification_binding",
            ]
            .iter()
            .all(|p| props[*p] == "PASS");
            if props["profile_version"] == "PASS" {
                assert_eq!(
                    envelope.verify().is_ok(),
                    all_bound,
                    "{id}: reply {i}: {:?}",
                    envelope.verify()
                );
            }
            let got = check_anchor_inclusion(&envelope, &pins);
            if matches!(
                props["profile_version"].as_str(),
                Some("FAIL" | "NOT_CHECKED")
            ) && evidence_request::envelope::PROFILES.contains(&envelope.profile.as_str())
            {
                // A mismatch with the request, or an identifier the case's
                // policy does not implement (§3.3 step 5), is the verifier's
                // to find; this check sees the envelope alone.
                checked += 1;
                continue;
            }
            assert_eq!(
                got.status, want_inclusion,
                "{id}: reply {i}: {}",
                got.detail
            );
            checked += 1;
            if got.status == Status::Pass {
                passed += 1;
                assert!(got
                    .method
                    .unwrap()
                    .starts_with("CLL-01 checkpoint (Ed25519) + MMR-02 inclusion"));
            }
        }
    }
    assert!(checked >= 17, "only {checked} envelope replies checked");
    assert!(passed >= 10, "only {passed} envelope replies reached PASS");
}
