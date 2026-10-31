//! Unavailable-window statements (-02 §4.7).
//!
//! A responder that cannot answer for a period may seal a statement that it
//! was unavailable from `start` to `end`, for one reason class from a closed
//! list, signed by its key. A reader recognizes one only when it is well
//! formed, signed by the key the absent request was addressed to, and
//! registered: at least one receipt from a transparency service the reader
//! accepts as independent of the responder attests a time. Which services a
//! reader accepts is reader policy, given here as each receipt's `accepted`.
//!
//! -02 leaves the signature format to the deployment; this crate uses the
//! profile the conformance vectors use (`unavailable-window.json`
//! `signature_profile`): Ed25519 over the RFC 8785 serialization of the
//! object with exactly the members present among `end`, `reason_class` and
//! `start`, with `key_id` the raw public key and `sig` the signature, both
//! lowercase hex. Verification is `verify_strict`.
//!
//! A statement covers a recorded absence when its period, both ends
//! included, shares an instant with the absence's waiting window, both ends
//! included. [`display`] says how a reader shows the absence then: "no
//! answer; holder states unavailability", with each covering statement's
//! class, stated period and registration time, labelled "stated afterwards"
//! when registered after the window closed. A refusal or a pending request
//! has no absence to cover. The absence record and its retention
//! classification ([`crate::retention::classify_absence`]) are unchanged.

use crate::outcome::State;
use crate::time::{parse_utc, UtcTime};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// How a reader shows an absence a statement covers (§4.7 item 1).
pub const SHOWN_AS: &str = "no answer; holder states unavailability";

/// The statement members the signature covers, those of them present.
pub const SIGNED_MEMBERS: [&str; 3] = ["end", "reason_class", "start"];

/// The closed list of reason classes. It changes only with a revision of
/// the draft; it is not a registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReasonClass {
    Flood,
    Maintenance,
    Outage,
    OtherDeclared,
}

impl ReasonClass {
    /// The four classes, in the draft's order.
    pub const ALL: [ReasonClass; 4] = [
        ReasonClass::Flood,
        ReasonClass::Maintenance,
        ReasonClass::Outage,
        ReasonClass::OtherDeclared,
    ];

    pub fn token(self) -> &'static str {
        match self {
            ReasonClass::Flood => "flood",
            ReasonClass::Maintenance => "maintenance",
            ReasonClass::Outage => "outage",
            ReasonClass::OtherDeclared => "other_declared",
        }
    }

    /// The class `token` names exactly, or `None`.
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.token() == token)
    }
}

/// One receipt on a checkpoint whose coverage includes a statement: the
/// time it attests, and whether it comes from a transparency service the
/// reader accepts as independent of the responder. A service the responder
/// operates or controls is never one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationReceipt {
    pub time: String,
    pub accepted: bool,
}

/// Why a reader ignores a statement. It treats an ignored statement as if
/// it did not exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ignored {
    /// `reason_class` is missing or not one of the four tokens, `start` or
    /// `end` is missing or not an RFC 3339 UTC time, or `end` is earlier
    /// than `start`.
    Malformed,
    /// `key_id` is not the responder's key, or `sig` does not verify under it.
    NotSignedByResponder,
    /// No accepted receipt attests a time.
    NotRegistered,
}

impl Ignored {
    /// The name as the vectors spell it.
    pub fn token(self) -> &'static str {
        match self {
            Ignored::Malformed => "malformed",
            Ignored::NotSignedByResponder => "not_signed_by_responder",
            Ignored::NotRegistered => "not_registered",
        }
    }
}

/// A statement a reader recognizes. `registration_time` is the earliest
/// time an accepted receipt attests, as that receipt spells it (the first
/// given, when several attest that instant).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recognized {
    pub reason_class: ReasonClass,
    pub start: String,
    pub end: String,
    pub registration_time: String,
}

/// Read one statement, a JSON object, as a reader holding `receipts` for
/// it, for the responder whose key is `responder_key`. Members other than
/// the signed ones, `key_id` and `sig` are ignored and are never the reason.
pub fn recognize(
    statement: &Value,
    receipts: &[RegistrationReceipt],
    responder_key: &VerifyingKey,
) -> Result<Recognized, Ignored> {
    let map = statement.as_object().ok_or(Ignored::Malformed)?;
    let text = |k: &str| map.get(k).and_then(Value::as_str);
    let reason_class = text("reason_class")
        .and_then(ReasonClass::from_token)
        .ok_or(Ignored::Malformed)?;
    let (start, end) = match (text("start"), text("end")) {
        (Some(start), Some(end)) => (start, end),
        _ => return Err(Ignored::Malformed),
    };
    match (parse_utc(start), parse_utc(end)) {
        (Some(s), Some(e)) if e >= s => {}
        _ => return Err(Ignored::Malformed),
    }
    if !signed_by(map, responder_key) {
        return Err(Ignored::NotSignedByResponder);
    }
    let registration_time = receipts
        .iter()
        .filter(|r| r.accepted)
        .filter_map(|r| parse_utc(&r.time).map(|at| (at, &r.time)))
        .min_by_key(|(at, _)| *at)
        .map(|(_, time)| time.clone())
        .ok_or(Ignored::NotRegistered)?;
    Ok(Recognized {
        reason_class,
        start: start.to_string(),
        end: end.to_string(),
        registration_time,
    })
}

fn signed_by(map: &Map<String, Value>, key: &VerifyingKey) -> bool {
    let text = |k: &str| map.get(k).and_then(Value::as_str);
    if text("key_id") != Some(hex::encode(key.to_bytes()).as_str()) {
        return false;
    }
    let sig = text("sig")
        .filter(|s| {
            s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .and_then(|s| hex::decode(s).ok())
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .map(|b| Signature::from_bytes(&b));
    let body: Map<String, Value> = SIGNED_MEMBERS
        .iter()
        .filter_map(|k| map.get(*k).map(|v| ((*k).to_string(), v.clone())))
        .collect();
    let (Some(sig), Ok(body)) = (sig, crate::jcs::to_string(&Value::Object(body))) else {
        return false;
    };
    key.verify_strict(body.as_bytes(), &sig).is_ok()
}

/// One statement a reader holds, under an id of the reader's choosing, with
/// the receipts it holds for it.
#[derive(Clone, Debug, PartialEq)]
pub struct WindowStatement {
    pub id: String,
    pub statement: Value,
    pub receipts: Vec<RegistrationReceipt>,
}

/// What a reader shows for one statement covering an absence (§4.7 items 1
/// to 3). It is the responder's own statement, never proof that it was
/// attacked, flooded or otherwise unable to answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Label {
    pub reason_class: ReasonClass,
    pub registration_time: String,
    /// Registered later than the close of the absence's waiting window.
    pub stated_afterwards: bool,
    /// From `start` to `end`, so a long stated window does not read like a
    /// short one.
    pub stated_period: (String, String),
}

/// How a reader shows a recorded state beside the statements it holds.
/// `covered_by` lists the ids of the covering statements in the order
/// given; `labels` maps each to its label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbsenceDisplay {
    pub state: State,
    pub shown_as: &'static str,
    pub covered_by: Vec<String>,
    pub labels: BTreeMap<String, Label>,
}

/// A recorded absence whose waiting window is not two RFC 3339 UTC times.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("a recorded absence needs sent_at and closed_at as RFC 3339 UTC times")]
pub struct WindowError;

/// Show the request recorded as `state` beside `statements`, whose ids are
/// distinct. Only [`State::RecordedAbsence`] can be covered: any other
/// state, a refusal or a pending request among them, is shown as itself
/// and no statement covers it. For an absence, `sent_at` and `closed_at`
/// are its waiting window.
pub fn display(
    state: State,
    sent_at: &str,
    closed_at: Option<&str>,
    statements: &[WindowStatement],
    responder_key: &VerifyingKey,
) -> Result<AbsenceDisplay, WindowError> {
    let mut shown = AbsenceDisplay {
        state,
        shown_as: state.token(),
        covered_by: Vec::new(),
        labels: BTreeMap::new(),
    };
    if state != State::RecordedAbsence {
        return Ok(shown);
    }
    let opened = parse_utc(sent_at).ok_or(WindowError)?;
    let closed = closed_at.and_then(parse_utc).ok_or(WindowError)?;
    for s in statements {
        let Ok(r) = recognize(&s.statement, &s.receipts, responder_key) else {
            continue;
        };
        if !overlaps(&r, opened, closed) {
            continue;
        }
        let registered = parse_utc(&r.registration_time).ok_or(WindowError)?;
        shown.covered_by.push(s.id.clone());
        shown.labels.insert(
            s.id.clone(),
            Label {
                reason_class: r.reason_class,
                stated_afterwards: registered > closed,
                stated_period: (r.start, r.end),
                registration_time: r.registration_time,
            },
        );
    }
    if !shown.covered_by.is_empty() {
        shown.shown_as = SHOWN_AS;
    }
    Ok(shown)
}

/// Closed-interval overlap of a recognized statement's period with the
/// window. A recognized statement's times parse.
fn overlaps(r: &Recognized, opened: UtcTime, closed: UtcTime) -> bool {
    match (parse_utc(&r.start), parse_utc(&r.end)) {
        (Some(start), Some(end)) => start <= closed && end >= opened,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// A statement with `members` over the defaults, signed over the signed
    /// members present; a `null` member is left out.
    fn statement(members: Value) -> Value {
        let mut st = json!({"start": "2026-10-29T10:00:00Z", "end": "2026-10-29T10:40:00Z", "reason_class": "flood"});
        for (k, v) in members.as_object().unwrap() {
            if v.is_null() {
                st.as_object_mut().unwrap().remove(k);
            } else {
                st[k] = v.clone();
            }
        }
        let body: Map<String, Value> = SIGNED_MEMBERS
            .iter()
            .filter_map(|k| st.get(*k).map(|v| ((*k).to_string(), v.clone())))
            .collect();
        let body = crate::jcs::to_string(&Value::Object(body)).unwrap();
        st["key_id"] = json!(hex::encode(key().verifying_key().to_bytes()));
        st["sig"] = json!(hex::encode(key().sign(body.as_bytes()).to_bytes()));
        st
    }

    fn accepted(times: &[&str]) -> Vec<RegistrationReceipt> {
        times
            .iter()
            .map(|t| RegistrationReceipt {
                time: (*t).to_string(),
                accepted: true,
            })
            .collect()
    }

    #[test]
    fn a_window_ending_before_it_starts_is_malformed() {
        let st = statement(json!({"start": "2026-10-29T10:40:00Z", "end": "2026-10-29T10:39:59Z"}));
        let got = recognize(
            &st,
            &accepted(&["2026-10-29T10:06:00Z"]),
            &key().verifying_key(),
        );
        assert_eq!(got, Err(Ignored::Malformed));
        // A fraction is the deadline representation too, and orders as an instant.
        let st =
            statement(json!({"start": "2026-10-29T10:00:00.5Z", "end": "2026-10-29T10:00:00.25Z"}));
        let got = recognize(
            &st,
            &accepted(&["2026-10-29T10:06:00Z"]),
            &key().verifying_key(),
        );
        assert_eq!(got, Err(Ignored::Malformed));
    }

    #[test]
    fn a_reason_outside_the_closed_list_is_malformed() {
        for reason in [json!("ddos"), json!("Outage"), json!(""), json!(7)] {
            let st = statement(json!({ "reason_class": reason }));
            let got = recognize(
                &st,
                &accepted(&["2026-10-29T10:06:00Z"]),
                &key().verifying_key(),
            );
            assert_eq!(got, Err(Ignored::Malformed), "{reason}");
        }
        let got = recognize(&json!(["not", "a", "map"]), &[], &key().verifying_key());
        assert_eq!(got, Err(Ignored::Malformed));
    }

    #[test]
    fn only_an_accepted_receipt_that_attests_a_time_registers() {
        let st = statement(json!({}));
        let rejected = RegistrationReceipt {
            time: "2026-10-29T10:06:00Z".into(),
            accepted: false,
        };
        for receipts in [vec![], vec![rejected.clone()], accepted(&["not a time"])] {
            let got = recognize(&st, &receipts, &key().verifying_key());
            assert_eq!(got, Err(Ignored::NotRegistered));
        }
        let mut receipts = vec![RegistrationReceipt {
            time: "2026-10-29T09:00:00Z".into(),
            accepted: false,
        }];
        receipts.extend(accepted(&["2026-10-29T10:30:00Z", "2026-10-29T10:06:00Z"]));
        let got = recognize(&st, &receipts, &key().verifying_key()).unwrap();
        assert_eq!(got.registration_time, "2026-10-29T10:06:00Z");
    }

    #[test]
    fn receipts_at_the_same_instant_give_the_first_ones_registration_time() {
        let st = statement(json!({}));
        for (first, second) in [
            ("2026-10-29T10:06:00Z", "2026-10-29T10:06:00.0Z"),
            ("2026-10-29T10:06:00.0Z", "2026-10-29T10:06:00Z"),
        ] {
            let got = recognize(&st, &accepted(&[first, second]), &key().verifying_key()).unwrap();
            assert_eq!(got.registration_time, first);
        }
    }

    #[test]
    fn a_statement_under_another_key_or_upper_case_hex_is_not_the_responders() {
        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let st = statement(json!({}));
        let got = recognize(&st, &accepted(&["2026-10-29T10:06:00Z"]), &other);
        assert_eq!(got, Err(Ignored::NotSignedByResponder));
        let mut st = statement(json!({}));
        st["sig"] = json!(st["sig"].as_str().unwrap().to_uppercase());
        let got = recognize(
            &st,
            &accepted(&["2026-10-29T10:06:00Z"]),
            &key().verifying_key(),
        );
        assert_eq!(got, Err(Ignored::NotSignedByResponder));
    }

    #[test]
    fn registered_after_the_window_closes_is_stated_afterwards() {
        let statements = [
            WindowStatement {
                id: "late".into(),
                statement: statement(json!({})),
                receipts: accepted(&["2026-10-29T10:20:01Z"]),
            },
            WindowStatement {
                id: "at-close".into(),
                statement: statement(json!({"reason_class": "outage"})),
                receipts: accepted(&["2026-10-29T10:20:00Z"]),
            },
        ];
        let shown = display(
            State::RecordedAbsence,
            "2026-10-29T10:10:00Z",
            Some("2026-10-29T10:20:00Z"),
            &statements,
            &key().verifying_key(),
        )
        .unwrap();
        assert_eq!(shown.shown_as, SHOWN_AS);
        assert_eq!(shown.covered_by, ["late", "at-close"]);
        assert!(shown.labels["late"].stated_afterwards);
        assert!(!shown.labels["at-close"].stated_afterwards);
        assert_eq!(shown.labels["at-close"].reason_class, ReasonClass::Outage);
    }

    #[test]
    fn only_a_recorded_absence_is_covered() {
        let statements = [WindowStatement {
            id: "s1".into(),
            statement: statement(json!({})),
            receipts: accepted(&["2026-10-29T10:06:00Z"]),
        }];
        for state in [
            State::Pending,
            State::Refusal,
            State::RefusalNonconformant,
            State::ArtifactVerified,
        ] {
            let shown = display(
                state,
                "2026-10-29T10:10:00Z",
                Some("2026-10-29T10:20:00Z"),
                &statements,
                &key().verifying_key(),
            )
            .unwrap();
            assert_eq!(shown.shown_as, state.token());
            assert!(shown.covered_by.is_empty() && shown.labels.is_empty());
        }
        let got = display(
            State::RecordedAbsence,
            "2026-10-29T10:10:00Z",
            None,
            &statements,
            &key().verifying_key(),
        );
        assert_eq!(got, Err(WindowError));
    }

    /// checkpointed-local-log's shared strict Ed25519 cases: `verify_strict`,
    /// the check [`recognize`] runs, accepts exactly the valid ones.
    #[test]
    fn verify_strict_matches_the_cll_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/cross-language/cll-ed25519-vectors.json"
        );
        let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let cases = vectors["ed25519_cases"].as_array().unwrap();
        assert_eq!(cases.len(), 54);
        let bytes = |case: &Value, name: &str| hex::decode(case[name].as_str().unwrap()).unwrap();
        for case in cases {
            let key: [u8; 32] = bytes(case, "public_key_hex").try_into().unwrap();
            let signature: [u8; 64] = bytes(case, "signature_hex").try_into().unwrap();
            let verifies = VerifyingKey::from_bytes(&key).is_ok_and(|key| {
                key.verify_strict(
                    &bytes(case, "message_hex"),
                    &Signature::from_bytes(&signature),
                )
                .is_ok()
            });
            assert_eq!(
                verifies,
                case["valid"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
        }
    }
}
