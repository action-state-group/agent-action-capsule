//! The interop profile's artifact envelope (`envelope`): signing, both
//! bindings, reading replies, and accepting one as an answer.

use ed25519_dalek::SigningKey;
use evidence_request::envelope::{
    parse_reply, sign, Anchor, AnchorFreshness, Binding, Envelope, EnvelopeError, EnvelopeParts,
    Reply, ReplyError, SignError, PROFILE,
};
use evidence_request::request::{Derivation, Subject};
use serde_json::Value;
use sha2::{Digest, Sha256};

const REQUEST: &[u8] = br#"{"coverage":{"expected_pin":"abababababababababababababababababababababababababababababababab"},"nonce":"n-1","subject":{"record":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}}"#;
const ISSUED_AT: &str = "2026-10-15T00:00:00Z";

fn key(label: &str) -> SigningKey {
    SigningKey::from_bytes(&Sha256::digest(label.as_bytes()).into())
}

fn parts() -> EnvelopeParts {
    EnvelopeParts {
        subject: Subject::Record("cd".repeat(32)),
        derivation: None,
        anchor: Anchor {
            digest: "ab".repeat(32),
            freshness: None,
        },
        artifact: br#"{"record":"bytes of the artifact"}"#.to_vec(),
        verification: vec![
            ("cll-checkpoint".into(), b"checkpoint statement".to_vec()),
            ("cll-inclusion-proof".into(), vec![0x82, 0x01, 0x80]),
        ],
        issued_at: ISSUED_AT.into(),
    }
}

fn envelope_of(reply: Result<Reply, ReplyError>) -> Envelope {
    match reply {
        Ok(Reply::Envelope(e)) => *e,
        other => panic!("not an envelope: {other:?}"),
    }
}

#[test]
fn both_bindings_round_trip_and_verify() {
    let k = key("responder");
    let env = sign(REQUEST, parts(), &k).unwrap();
    assert_eq!(env.profile, PROFILE);
    for binding in [Binding::Json, Binding::Cbor] {
        let back = envelope_of(parse_reply(&env.encode(binding), binding));
        assert_eq!(back, env);
        back.verify_for(&k.verifying_key(), REQUEST).unwrap();
    }
    // JSON: RFC 8785 with byte strings as unpadded base64url.
    let json: Value = serde_json::from_slice(&env.encode(Binding::Json)).unwrap();
    assert!(!json["artifact"].as_str().unwrap().contains('='));
    assert_eq!(json["verification_content"].as_array().unwrap().len(), 2);
    assert_eq!(json["verification"][0]["kind"], "cll-checkpoint");
}

#[test]
fn optional_members_appear_only_when_present() {
    let k = key("responder");
    let mut p = parts();
    p.verification.clear();
    let bare = sign(REQUEST, p.clone(), &k).unwrap();
    let signed = bare.signed_members();
    assert!(!signed.contains_key("verification") && !signed.contains_key("derivation"));
    assert!(!String::from_utf8(bare.encode(Binding::Json))
        .unwrap()
        .contains("verification_content"));

    p.subject = Subject::FullHistory;
    p.derivation = Some(Derivation::Token("history_card/1".into()));
    p.anchor.freshness = Some(AnchorFreshness::Size(42));
    let fresh = sign(REQUEST, p.clone(), &k).unwrap();
    let signed = fresh.signed_members();
    assert_eq!(signed["derivation"], "history_card/1");
    assert_eq!(signed["anchor"]["freshness"], 42);
    assert_eq!(signed["subject"], serde_json::json!({"full_history": null}));
    let back = envelope_of(parse_reply(&fresh.encode(Binding::Cbor), Binding::Cbor));
    assert_eq!(back, fresh);
}

#[test]
fn verify_names_what_is_wrong() {
    let k = key("responder");
    let env = sign(REQUEST, parts(), &k).unwrap();

    let mut t = env.clone();
    t.artifact.push(b' ');
    assert_eq!(t.verify(), Err(EnvelopeError::ArtifactDigest));

    let mut t = env.clone();
    t.verification_content[1].push(0);
    assert_eq!(t.verify(), Err(EnvelopeError::VerificationDigest(1)));

    let mut t = env.clone();
    t.verification_content.pop();
    assert_eq!(t.verify(), Err(EnvelopeError::VerificationCount));

    let mut t = env.clone();
    t.issued_at = "2026-10-15T00:00:01Z".into();
    assert_eq!(t.verify(), Err(EnvelopeError::Signature));

    let mut t = env.clone();
    t.sig = t.sig.to_uppercase();
    assert_eq!(t.verify(), Err(EnvelopeError::SignatureForm));

    let other = key("someone else");
    assert_eq!(
        env.verify_for(&other.verifying_key(), REQUEST),
        Err(EnvelopeError::WrongKey)
    );
    assert_eq!(
        env.verify_for(&k.verifying_key(), b"{}"),
        Err(EnvelopeError::WrongRequest)
    );
    let mut t = env.clone();
    t.profile = "evidence-interop/1".into();
    assert_eq!(
        t.verify_for(&k.verifying_key(), REQUEST),
        Err(EnvelopeError::Profile)
    );
}

#[test]
fn sign_refuses_what_the_profile_does_not_allow() {
    let k = key("responder");
    let with = |f: &dyn Fn(&mut EnvelopeParts)| {
        let mut p = parts();
        f(&mut p);
        sign(REQUEST, p, &k)
    };
    assert_eq!(with(&|p| p.artifact.clear()), Err(SignError::EmptyArtifact));
    assert_eq!(
        with(&|p| p.anchor.digest = "AB".repeat(32)),
        Err(SignError::AnchorDigest)
    );
    for when in [
        "yesterday",
        "2026-10-15T00:00:00.5Z",
        "2026-10-15T00:00:00+00:00",
        "2026-02-30T00:00:00Z",
    ] {
        assert_eq!(
            with(&|p| p.issued_at = when.into()),
            Err(SignError::IssuedAt),
            "{when}"
        );
    }
    assert_eq!(
        with(&|p| p.anchor.freshness = Some(AnchorFreshness::Size(1 << 53))),
        Err(SignError::Freshness)
    );
    assert_eq!(
        with(&|p| p.anchor.freshness = Some(AnchorFreshness::Time("2026-10-14T00:00:00.5Z".into()))),
        Err(SignError::Freshness)
    );
    for subject in [
        Subject::Record("XY".into()),
        Subject::Record("AB".repeat(32)),
        Subject::Range(3, 0),
        Subject::Correlation(String::new()),
    ] {
        assert!(
            matches!(
                with(&|p| p.subject = subject.clone()),
                Err(SignError::Subject(_))
            ),
            "{subject:?}"
        );
    }
    for d in [
        Derivation::Token("history_card".into()),
        Derivation::Digest("AB".repeat(32)),
        Derivation::Token(String::new()),
    ] {
        assert!(
            matches!(
                with(&|p| p.derivation = Some(d.clone())),
                Err(SignError::Subject(_))
            ),
            "{d:?}"
        );
    }
    assert_eq!(with(&|p| p.verification[0].0.clear()), Err(SignError::Kind));
}

#[test]
fn parse_reply_reads_only_what_it_can_authenticate() {
    let k = key("responder");
    let env = sign(REQUEST, parts(), &k).unwrap();

    assert_eq!(parse_reply(b"[]", Binding::Json), Err(ReplyError::NotAMap));
    assert_eq!(
        parse_reply(br#"{"x":1}"#, Binding::Json),
        Err(ReplyError::Neither)
    );
    assert_eq!(
        parse_reply(br#"{"artifact_digest":"a","reason":"b"}"#, Binding::Json),
        Err(ReplyError::Both)
    );
    assert!(matches!(
        parse_reply(br#"{"reason":"declined","sig":"00"}"#, Binding::Json),
        Ok(Reply::Refusal(_))
    ));
    // A duplicate member name, at any depth.
    assert!(matches!(
        parse_reply(br#"{"reason":"a","reason":"b"}"#, Binding::Json),
        Err(ReplyError::Encoding(_))
    ));
    assert!(matches!(
        parse_reply(br#"{"reason":"a","x":{"k":1,"k":2}}"#, Binding::Json),
        Err(ReplyError::Encoding(_))
    ));
    // Padded base64 is not the binding's form.
    let mut json: Value = serde_json::from_slice(&env.encode(Binding::Json)).unwrap();
    let artifact = json["artifact"].as_str().unwrap().to_string();
    json["artifact"] = Value::String(format!("{artifact}=="));
    let padded = serde_json::to_vec(&json).unwrap();
    assert_eq!(
        parse_reply(&padded, Binding::Json),
        Err(ReplyError::Member("artifact"))
    );
    // CBOR outside core deterministic encoding.
    let mut cbor = env.encode(Binding::Cbor);
    cbor.push(0);
    assert!(matches!(
        parse_reply(&cbor, Binding::Cbor),
        Err(ReplyError::Encoding(_))
    ));
    // A JSON frame given as CBOR is not read.
    assert!(parse_reply(&env.encode(Binding::Json), Binding::Cbor).is_err());
}

/// Re-signing the corpus's own envelopes with its test responder key gives
/// the corpus octets, in both bindings: the members, their encodings and the
/// signing input are those of `vectors/interop-profile-v0/`.
#[test]
fn reproduces_the_corpus_envelopes_byte_for_byte() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/interop-profile-v0/vectors.json"
    );
    let corpus: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let responder = key(corpus["test_keys"]["keys"]["responder"]["seed_label"]
        .as_str()
        .unwrap());
    let mut reproduced = 0;
    for id in ["valid-exchange", "invariance-two-nonces-two-transports"] {
        let case = corpus["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap();
        let octets_of = |v: &Value| match (v["octets_text"].as_str(), v["octets_hex"].as_str()) {
            (Some(t), _) => t.as_bytes().to_vec(),
            (None, Some(h)) => hex::decode(h).unwrap(),
            _ => panic!("{id}: no octets"),
        };
        let requests: Vec<Vec<u8>> = match case["inputs"]["requests"].as_array() {
            Some(list) => list.iter().map(octets_of).collect(),
            None => vec![octets_of(&case["inputs"]["request"])],
        };
        for reply in case["inputs"]["replies"].as_array().unwrap() {
            let (octets, binding) =
                match (reply["octets_text"].as_str(), reply["octets_hex"].as_str()) {
                    (Some(t), _) => (t.as_bytes().to_vec(), Binding::Json),
                    (None, Some(h)) => (hex::decode(h).unwrap(), Binding::Cbor),
                    _ => unreachable!(),
                };
            let got = envelope_of(parse_reply(&octets, binding));
            let request = requests
                .iter()
                .find(|r| evidence_request::digest::request_digest(r) == got.request_digest)
                .unwrap_or_else(|| panic!("{id}: no request for the reply's digest"));
            let again = sign(
                request,
                EnvelopeParts {
                    subject: got.subject.clone(),
                    derivation: got.derivation.clone(),
                    anchor: got.anchor.clone(),
                    artifact: got.artifact.clone(),
                    verification: got
                        .verification
                        .iter()
                        .map(|e| e.kind.clone())
                        .zip(got.verification_content.iter().cloned())
                        .collect(),
                    issued_at: got.issued_at.clone(),
                },
                &responder,
            )
            .unwrap();
            assert_eq!(again.encode(binding), octets, "{id}");
            reproduced += 1;
        }
    }
    assert!(reproduced >= 3, "only {reproduced} envelopes reproduced");
}

#[test]
fn signed_members_are_never_byte_strings_or_empty_arrays() {
    let k = key("responder");
    let mut p = parts();
    p.subject = Subject::Correlation("YWJj".into());
    let env = sign(REQUEST, p, &k).unwrap();
    // CBOR: the signed subject's text replaced by the bytes its base64url
    // names must not read as that text.
    let mut frame: ciborium::Value =
        ciborium::from_reader(env.encode(Binding::Cbor).as_slice()).unwrap();
    if let ciborium::Value::Map(entries) = &mut frame {
        for (k, v) in entries.iter_mut() {
            if k.as_text() == Some("subject") {
                *v = ciborium::Value::Map(vec![(
                    ciborium::Value::Text("correlation".into()),
                    ciborium::Value::Bytes(b"abc".to_vec()),
                )]);
            }
        }
    }
    let mut octets = Vec::new();
    ciborium::into_writer(&frame, &mut octets).unwrap();
    assert_eq!(
        parse_reply(&octets, Binding::Cbor),
        Err(ReplyError::Member("subject"))
    );
    // A refusal carrying a byte string.
    let refusal = ciborium::Value::Map(vec![(
        ciborium::Value::Text("reason".into()),
        ciborium::Value::Bytes(b"declined".to_vec()),
    )]);
    let mut octets = Vec::new();
    ciborium::into_writer(&refusal, &mut octets).unwrap();
    assert!(matches!(
        parse_reply(&octets, Binding::Cbor),
        Err(ReplyError::Encoding(_))
    ));
    // A byte string in a member no verification reads passes through, as in Go.
    let refusal = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("reason".into()),
            ciborium::Value::Text("declined".into()),
        ),
        (
            ciborium::Value::Text("x".into()),
            ciborium::Value::Bytes(vec![0]),
        ),
    ]);
    let mut octets = Vec::new();
    ciborium::into_writer(&refusal, &mut octets).unwrap();
    assert!(matches!(
        parse_reply(&octets, Binding::Cbor),
        Ok(Reply::Refusal(_))
    ));
    // `verification: []` present: not absence, and not a conforming member.
    let mut bare_parts = parts();
    bare_parts.verification.clear();
    let bare = sign(REQUEST, bare_parts, &k).unwrap();
    let mut json: Value = serde_json::from_slice(&bare.encode(Binding::Json)).unwrap();
    json["verification"] = Value::Array(vec![]);
    let injected = serde_json::to_vec(&json).unwrap();
    assert_eq!(
        parse_reply(&injected, Binding::Json),
        Err(ReplyError::Member("verification"))
    );
}
