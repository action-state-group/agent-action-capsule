//! The signed refusal (§4.2).
//!
//! A refusal carries the request digest, one registered reason and an
//! issuance time, signed by the responder. -00 leaves member names and the
//! signature format to the deployment; this crate uses the profile the
//! conformance vectors use (A7): Ed25519 over the RFC 8785 serialization of
//! the object with exactly the members `issued_at`, `reason` and
//! `request_digest`; `key_id` is the raw 32-byte public key and `sig` the
//! 64-byte signature, both lowercase hex. In the CBOR binding the same map
//! is the frame; the signature is still over the RFC 8785 body.
//!
//! **To accept a refusal as the answer to your request, use [`verify_for`]**:
//! it requires the signature to come from the responder's key you expected
//! and the refusal to name your request's digest. [`check`] only reports
//! shape and self-consistency: it verifies the signature under the key the
//! refusal itself names, so any key can produce a refusal that `check`
//! calls conformant. It is not authentication.
//!
//! [`check`] keeps three questions apart, as the vectors require:
//! - `signature_valid`: does `sig` verify under `key_id` over the signed
//!   members as they appear (whatever their values)?
//! - `reason_registered`: is `reason` exactly one registered token?
//! - `conformant`: both, and every member §4.2 requires is present and well
//!   formed.
//!
//! A correctly signed object with an unregistered reason is not a conforming
//! refusal, and is still the responder's signed act (A13): see
//! [`crate::outcome`].
//!
//! **`evidence-interop/2`** (`spec/interop-profile-v2.md` §6.3, P-69) adds an
//! optional `policy_digest`, signed when present. A refusal carries no
//! profile, so which members its signature covers is decided by the
//! identifier its request asked for: [`sign_with_profile`],
//! [`check_for_profile`] and [`verify_for_profile`] take it. [`sign`],
//! [`check`] and [`verify_for`] keep the A7 signing input, which is that of
//! `evidence-interop/0` and `/1`: a `policy_digest` beside it binds nothing.

use crate::envelope::{PROFILE, PROFILE_V1, PROFILE_V2};
use crate::registry::{is_digest, Reason};
use crate::time::parse_utc;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{json, Map, Value};

/// The members the signature covers (A7), under every identifier but
/// `evidence-interop/2`.
pub const SIGNED_MEMBERS: [&str; 3] = ["issued_at", "reason", "request_digest"];

/// The members the signature covers under `evidence-interop/2`, each when
/// present: [`SIGNED_MEMBERS`] and `policy_digest` (v2 §6.3). Without a
/// `policy_digest` the signing input is the A7 one, byte for byte.
pub const SIGNED_MEMBERS_V2: [&str; 4] = ["issued_at", "policy_digest", "reason", "request_digest"];

/// The members a refusal's signature covers when its request asked for
/// `profile`: [`SIGNED_MEMBERS_V2`] under `evidence-interop/2`, else
/// [`SIGNED_MEMBERS`].
pub fn signed_members(profile: &str) -> &'static [&'static str] {
    if profile == PROFILE_V2 {
        &SIGNED_MEMBERS_V2
    } else {
        &SIGNED_MEMBERS
    }
}

/// The signed-member sets a refusal answering a request for `profile` is
/// checked under: that identifier's, or, for one this crate does not
/// implement, each one it does, any of which may verify (v2 §6.3).
fn signing_rules(profile: &str) -> &'static [&'static [&'static str]] {
    const A7: &[&str] = &SIGNED_MEMBERS;
    const V2: &[&str] = &SIGNED_MEMBERS_V2;
    match profile {
        PROFILE | PROFILE_V1 => &[A7],
        PROFILE_V2 => &[V2],
        _ => &[A7, V2],
    }
}

/// A refusal as sent: the signed members plus `key_id`, `sig` and an
/// optional `detail`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub request_digest: String,
    pub reason: Reason,
    pub issued_at: String,
    pub key_id: String,
    pub sig: String,
    /// Optional human-readable text (§4.2; profile P-6). It is outside the
    /// signature, so it is not authenticated: the token is the answer, never
    /// the prose. `None` and the empty string are both absent on the wire.
    pub detail: Option<String>,
    /// The SHA-256 of the policy the responder declares, 64 lowercase hex
    /// (v2 §6.3, P-69). [`sign_with_profile`] sets it only under
    /// `evidence-interop/2`, where the signature covers it. `None` is absent
    /// on the wire.
    pub policy_digest: Option<String>,
}

impl Refusal {
    /// The refusal as a JSON object (the JSON binding).
    pub fn to_json(&self) -> Value {
        let mut out = json!({
            "issued_at": self.issued_at,
            "reason": self.reason.token(),
            "request_digest": self.request_digest,
            "key_id": self.key_id,
            "sig": self.sig,
        });
        if let Some(detail) = self.detail.as_deref().filter(|d| !d.is_empty()) {
            out["detail"] = json!(detail);
        }
        if let Some(policy_digest) = &self.policy_digest {
            out["policy_digest"] = json!(policy_digest);
        }
        out
    }

    /// The refusal as a CBOR map (the CBOR binding), deterministically
    /// encoded (RFC 8949 §4.2.1, as §10 requires): the map's keys in the
    /// bytewise order of their encodings, so `sig`, `key_id`, `reason`,
    /// `detail` (when present), `issued_at`, `policy_digest` (when present),
    /// `request_digest`.
    pub fn to_cbor(&self) -> Vec<u8> {
        use ciborium::Value as C;
        let text = |s: &str| C::Text(s.to_string());
        let encoded = |v: &C| {
            let mut out = Vec::new();
            ciborium::into_writer(v, &mut out).expect("writing to a Vec never fails");
            out
        };
        let mut entries = vec![
            (text("issued_at"), text(&self.issued_at)),
            (text("reason"), text(self.reason.token())),
            (text("request_digest"), text(&self.request_digest)),
            (text("key_id"), text(&self.key_id)),
            (text("sig"), text(&self.sig)),
        ];
        if let Some(detail) = self.detail.as_deref().filter(|d| !d.is_empty()) {
            entries.push((text("detail"), text(detail)));
        }
        if let Some(policy_digest) = &self.policy_digest {
            entries.push((text("policy_digest"), text(policy_digest)));
        }
        entries.sort_by_cached_key(|(k, _)| encoded(k));
        encoded(&C::Map(entries))
    }
}

/// The bytes a refusal's signature covers under A7: RFC 8785 of the
/// [`SIGNED_MEMBERS`] present in `object`.
pub fn signing_body(object: &Map<String, Value>) -> Result<String, crate::jcs::JcsError> {
    body_of(object, &SIGNED_MEMBERS)
}

/// The bytes a refusal's signature covers when its request asked for
/// `profile`: RFC 8785 of the [`signed_members`] present in `object`.
pub fn signing_body_for_profile(
    object: &Map<String, Value>,
    profile: &str,
) -> Result<String, crate::jcs::JcsError> {
    body_of(object, signed_members(profile))
}

fn body_of(object: &Map<String, Value>, members: &[&str]) -> Result<String, crate::jcs::JcsError> {
    let body: Map<String, Value> = members
        .iter()
        .filter_map(|k| object.get(*k).map(|v| ((*k).to_string(), v.clone())))
        .collect();
    crate::jcs::to_string(&Value::Object(body))
}

/// Why a refusal cannot be signed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignError {
    #[error("request_digest must be 64 lowercase hex")]
    RequestDigest,
    #[error("issued_at must be an RFC 3339 UTC time")]
    IssuedAt,
    /// A `policy_digest` is signed only under `evidence-interop/2`; under
    /// any other identifier it would ride outside the signature (v2 §6.3).
    #[error("policy_digest is signed only under evidence-interop/2")]
    PolicyDigestProfile,
    #[error("policy_digest must be 64 lowercase hex")]
    PolicyDigest,
}

/// Sign a refusal of the request whose digest is `request_digest`.
pub fn sign(
    request_digest: &str,
    reason: Reason,
    issued_at: &str,
    signing_key: &SigningKey,
) -> Result<Refusal, SignError> {
    sign_with_detail(request_digest, reason, issued_at, None, signing_key)
}

/// [`sign`] with an optional `detail` carried outside the signed members: the
/// signature and the signing body are the same with or without it.
pub fn sign_with_detail(
    request_digest: &str,
    reason: Reason,
    issued_at: &str,
    detail: Option<&str>,
    signing_key: &SigningKey,
) -> Result<Refusal, SignError> {
    sign_with_profile(
        PROFILE,
        request_digest,
        reason,
        issued_at,
        detail,
        None,
        signing_key,
    )
}

/// [`sign_with_detail`] answering a request that asked for `profile`, with
/// an optional `policy_digest`. Under `evidence-interop/2` a `policy_digest`
/// is signed with the A7 members (v2 §6.3); under any other identifier it
/// would ride unsigned and bind nothing, so this refuses it
/// ([`SignError::PolicyDigestProfile`]) instead of building that refusal.
/// Without one, the refusal is the A7 refusal under every identifier.
pub fn sign_with_profile(
    profile: &str,
    request_digest: &str,
    reason: Reason,
    issued_at: &str,
    detail: Option<&str>,
    policy_digest: Option<&str>,
    signing_key: &SigningKey,
) -> Result<Refusal, SignError> {
    if !is_digest(request_digest) {
        return Err(SignError::RequestDigest);
    }
    if parse_utc(issued_at).is_none() {
        return Err(SignError::IssuedAt);
    }
    if let Some(p) = policy_digest {
        if profile != PROFILE_V2 {
            return Err(SignError::PolicyDigestProfile);
        }
        if !is_digest(p) {
            return Err(SignError::PolicyDigest);
        }
    }
    let mut body = Map::new();
    body.insert("issued_at".into(), json!(issued_at));
    body.insert("reason".into(), json!(reason.token()));
    body.insert("request_digest".into(), json!(request_digest));
    if let Some(p) = policy_digest {
        body.insert("policy_digest".into(), json!(p));
    }
    let message = signing_body_for_profile(&body, profile).expect("text members always serialize");
    let sig = signing_key.sign(message.as_bytes());
    Ok(Refusal {
        request_digest: request_digest.to_string(),
        reason,
        issued_at: issued_at.to_string(),
        key_id: hex::encode(signing_key.verifying_key().to_bytes()),
        sig: hex::encode(sig.to_bytes()),
        detail: detail.filter(|d| !d.is_empty()).map(str::to_string),
        policy_digest: policy_digest.map(str::to_string),
    })
}

/// The three answers about a received refusal object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefusalCheck {
    pub signature_valid: bool,
    pub reason_registered: bool,
    pub conformant: bool,
}

/// Check a refusal's **shape and self-consistency only; NOT
/// authentication.** The signature is verified under the refusal's own
/// `key_id`, which anyone can choose, and the request it names is not
/// compared with anything. To accept a refusal as the responder's answer to
/// a request, use [`verify_for`].
///
/// The signing input is A7's, that of `evidence-interop/0` and `/1`: a
/// `policy_digest` the refusal carries is outside it. For a refusal
/// answering a request for `evidence-interop/2`, use [`check_for_profile`].
pub fn check(object: &Value) -> RefusalCheck {
    check_for_profile(object, PROFILE)
}

/// [`check`] for a refusal answering a request that asked for `profile`
/// (v2 §6.3): the signature is checked over that identifier's
/// [`signed_members`], and under `evidence-interop/2` a `policy_digest`
/// present must also be a digest for the refusal to be conformant. For an
/// identifier this crate does not implement, the signature is checked under
/// each one it does, and passes when any verifies. Shape and
/// self-consistency only; NOT authentication (see [`verify_for_profile`]).
pub fn check_for_profile(object: &Value, profile: &str) -> RefusalCheck {
    let Some(map) = object.as_object() else {
        return RefusalCheck {
            signature_valid: false,
            reason_registered: false,
            conformant: false,
        };
    };
    let text = |k: &str| map.get(k).and_then(Value::as_str);
    let key = own_key(map);
    let verifying: Vec<&[&str]> = signing_rules(profile)
        .iter()
        .copied()
        .filter(|members| {
            key.as_ref()
                .is_some_and(|k| signature_verifies_under(map, k, members))
        })
        .collect();
    let signature_valid = !verifying.is_empty();
    let reason_registered = text("reason").and_then(Reason::from_token).is_some();
    let members_well_formed = text("request_digest").is_some_and(is_digest)
        && text("issued_at").is_some_and(|t| parse_utc(t).is_some())
        && text("key_id").is_some_and(|k| is_hex_of_len(k, 32))
        && text("sig").is_some_and(|s| is_hex_of_len(s, 64))
        && verifying
            .iter()
            .any(|members| signed_policy_digest_well_formed(map, members));
    RefusalCheck {
        signature_valid,
        reason_registered,
        conformant: signature_valid && reason_registered && members_well_formed,
    }
}

/// [`check`] for the CBOR binding: shape and self-consistency only; NOT
/// authentication (see [`verify_for_cbor`]).
pub fn check_cbor(frame: &[u8]) -> RefusalCheck {
    check_cbor_for_profile(frame, PROFILE)
}

/// [`check_for_profile`] for the CBOR binding.
pub fn check_cbor_for_profile(frame: &[u8], profile: &str) -> RefusalCheck {
    match decode_cbor_object(frame) {
        Some(object) => check_for_profile(&object, profile),
        None => RefusalCheck {
            signature_valid: false,
            reason_registered: false,
            conformant: false,
        },
    }
}

/// A signed `policy_digest` is a digest (v2 §6.3, §5.2): one that is not is
/// a malformed signed member. Outside the signature its form does not matter.
fn signed_policy_digest_well_formed(map: &Map<String, Value>, members: &[&str]) -> bool {
    !members.contains(&"policy_digest")
        || map
            .get("policy_digest")
            .is_none_or(|p| p.as_str().is_some_and(is_digest))
}

fn decode_cbor_object(frame: &[u8]) -> Option<Value> {
    let mut reader = frame;
    let value = crate::det_cbor::decode_value(&mut reader)?;
    if !reader.is_empty() {
        return None;
    }
    match cbor_to_json(&value)? {
        object @ Value::Object(_) => Some(object),
        _ => None,
    }
}

/// Why [`verify_for`] did not accept a refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// Not a conforming refusal (shape, registry or self-signature).
    #[error("not a conforming refusal")]
    NotConformant,
    /// Conforming, but signed under a key other than the responder's.
    #[error("the refusal is not signed by the expected responder key")]
    WrongKey,
    /// Conforming and from the responder, but about a different request.
    #[error("the refusal names a different request digest")]
    WrongRequest,
}

/// Authenticate a refusal as `responder_key`'s answer to the request whose
/// digest is `request_digest`: it must be conforming ([`check`]), its
/// `key_id` must be `responder_key`, its signature must verify under that key
/// (`verify_strict`: no small-order keys, canonical signatures only), and its
/// `request_digest` must be the one given. Returns the refusal's reason.
///
/// The signing input is A7's, as in [`check`]; for a request that asked for
/// `evidence-interop/2`, use [`verify_for_profile`].
pub fn verify_for(
    object: &Value,
    responder_key: &VerifyingKey,
    request_digest: &str,
) -> Result<Reason, VerifyError> {
    verify_for_profile(object, PROFILE, responder_key, request_digest)
}

/// [`verify_for`] for a refusal answering a request that asked for
/// `profile`, checked as [`check_for_profile`] checks it (v2 §6.3). Under
/// `evidence-interop/2` a `policy_digest` the refusal carries is the
/// responder's signed statement once this returns `Ok`; under any other
/// identifier it binds nothing, and must not be reported as the
/// responder's (P-69).
pub fn verify_for_profile(
    object: &Value,
    profile: &str,
    responder_key: &VerifyingKey,
    request_digest: &str,
) -> Result<Reason, VerifyError> {
    let map = object.as_object().ok_or(VerifyError::NotConformant)?;
    if !check_for_profile(object, profile).conformant {
        return Err(VerifyError::NotConformant);
    }
    let text = |k: &str| map.get(k).and_then(Value::as_str);
    if text("key_id") != Some(hex::encode(responder_key.to_bytes()).as_str()) {
        return Err(VerifyError::WrongKey);
    }
    if !signing_rules(profile).iter().any(|members| {
        signature_verifies_under(map, responder_key, members)
            && signed_policy_digest_well_formed(map, members)
    }) {
        return Err(VerifyError::WrongKey);
    }
    if text("request_digest") != Some(request_digest) {
        return Err(VerifyError::WrongRequest);
    }
    text("reason")
        .and_then(Reason::from_token)
        .ok_or(VerifyError::NotConformant)
}

/// [`verify_for`] for the CBOR binding.
pub fn verify_for_cbor(
    frame: &[u8],
    responder_key: &VerifyingKey,
    request_digest: &str,
) -> Result<Reason, VerifyError> {
    verify_for_profile_cbor(frame, PROFILE, responder_key, request_digest)
}

/// [`verify_for_profile`] for the CBOR binding.
pub fn verify_for_profile_cbor(
    frame: &[u8],
    profile: &str,
    responder_key: &VerifyingKey,
    request_digest: &str,
) -> Result<Reason, VerifyError> {
    let object = decode_cbor_object(frame).ok_or(VerifyError::NotConformant)?;
    verify_for_profile(&object, profile, responder_key, request_digest)
}

fn cbor_to_json(value: &ciborium::Value) -> Option<Value> {
    use ciborium::Value as C;
    Some(match value {
        C::Null => Value::Null,
        C::Bool(b) => json!(b),
        C::Text(s) => json!(s),
        C::Integer(i) => {
            let i = i128::from(*i);
            if let Ok(u) = u64::try_from(i) {
                json!(u)
            } else {
                json!(i64::try_from(i).ok()?)
            }
        }
        C::Array(items) => Value::Array(items.iter().map(cbor_to_json).collect::<Option<_>>()?),
        C::Map(entries) => {
            let mut map = Map::new();
            for (k, v) in entries {
                let C::Text(key) = k else { return None };
                if map.insert(key.clone(), cbor_to_json(v)?).is_some() {
                    return None;
                }
            }
            Value::Object(map)
        }
        _ => return None,
    })
}

fn is_hex_of_len(s: &str, bytes: usize) -> bool {
    s.len() == bytes * 2
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The key the refusal names in `key_id`.
fn own_key(map: &Map<String, Value>) -> Option<VerifyingKey> {
    map.get("key_id")
        .and_then(Value::as_str)
        .and_then(|k| hex::decode(k).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
}

fn signature_verifies_under(
    map: &Map<String, Value>,
    key: &VerifyingKey,
    members: &[&str],
) -> bool {
    let sig = map
        .get("sig")
        .and_then(Value::as_str)
        .and_then(|s| hex::decode(s).ok())
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .map(|b| Signature::from_bytes(&b));
    let (Some(sig), Ok(body)) = (sig, body_of(map, members)) else {
        return false;
    };
    key.verify_strict(body.as_bytes(), &sig).is_ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_cbor_frame_is_read_to_128_levels() {
        // {"x": <arrays n deep around an empty array>}: n + 2 levels.
        let frame = |n: usize| [vec![0xa1u8, 0x61, 0x78], vec![0x81u8; n], vec![0x80]].concat();
        assert!(decode_cbor_object(&frame(126)).is_some());
        assert!(decode_cbor_object(&frame(127)).is_none());
        // A bignum tag is a level too, though ciborium reads it as an integer.
        let bignum = |n: usize| {
            [
                vec![0xa1u8, 0x61, 0x78],
                vec![0x81u8; n],
                vec![0xc2, 0x41, 0x01],
            ]
            .concat()
        };
        assert!(decode_cbor_object(&bignum(126)).is_some());
        assert!(decode_cbor_object(&bignum(127)).is_none());
    }

    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[5u8; 32])
    }

    /// RFC 8949 §3.1 text-string head plus the bytes (lengths under 256 are
    /// all a refusal's members need).
    fn cbor_text(s: &str) -> Vec<u8> {
        let mut out = match s.len() {
            n if n < 24 => vec![0x60 | n as u8],
            n if n < 256 => vec![0x78, n as u8],
            _ => unreachable!(),
        };
        out.extend_from_slice(s.as_bytes());
        out
    }

    #[test]
    fn the_cbor_binding_is_deterministic_on_the_wire() {
        // RFC 8949 §4.2.1: map keys in the bytewise order of their encodings.
        // Text keys sort by encoded length first, then by bytes:
        // sig (3), key_id and reason (6), issued_at (9), request_digest (14).
        let r = sign(
            &"a".repeat(64),
            Reason::NoSuchSubject,
            "2026-09-28T00:00:00Z",
            &key(),
        )
        .unwrap();
        let mut expected = vec![0xa5];
        for (k, v) in [
            ("sig", r.sig.as_str()),
            ("key_id", r.key_id.as_str()),
            ("reason", r.reason.token()),
            ("issued_at", r.issued_at.as_str()),
            ("request_digest", r.request_digest.as_str()),
        ] {
            expected.extend(cbor_text(k));
            expected.extend(cbor_text(v));
        }
        assert_eq!(hex::encode(r.to_cbor()), hex::encode(expected));
    }

    #[test]
    fn a_signed_refusal_checks_conformant_in_both_bindings() {
        let r = sign(
            &"a".repeat(64),
            Reason::NoSuchSubject,
            "2026-09-28T00:00:00Z",
            &key(),
        )
        .unwrap();
        let ok = RefusalCheck {
            signature_valid: true,
            reason_registered: true,
            conformant: true,
        };
        assert_eq!(check(&r.to_json()), ok);
        assert_eq!(check_cbor(&r.to_cbor()), ok);
    }

    #[test]
    fn changing_a_signed_member_breaks_the_signature() {
        let r = sign(
            &"a".repeat(64),
            Reason::NoSuchSubject,
            "2026-09-28T00:00:00Z",
            &key(),
        )
        .unwrap();
        let mut v = r.to_json();
        v["reason"] = json!("policy_declined");
        let c = check(&v);
        assert!(!c.signature_valid && c.reason_registered && !c.conformant);
    }

    #[test]
    fn verify_for_binds_the_responder_key_and_the_request() {
        let responder = key();
        let digest = "a".repeat(64);
        let r = sign(
            &digest,
            Reason::NoSuchSubject,
            "2026-09-28T00:00:00Z",
            &responder,
        )
        .unwrap();

        // The right responder and the right request: accepted.
        assert_eq!(
            verify_for(&r.to_json(), &responder.verifying_key(), &digest),
            Ok(Reason::NoSuchSubject)
        );
        assert_eq!(
            verify_for_cbor(&r.to_cbor(), &responder.verifying_key(), &digest),
            Ok(Reason::NoSuchSubject)
        );
        // Expecting a different responder: refused.
        let other = SigningKey::from_bytes(&[6u8; 32]);
        assert_eq!(
            verify_for(&r.to_json(), &other.verifying_key(), &digest),
            Err(VerifyError::WrongKey)
        );
        // A different request: refused.
        assert_eq!(
            verify_for(&r.to_json(), &responder.verifying_key(), &"b".repeat(64)),
            Err(VerifyError::WrongRequest)
        );
    }

    #[test]
    fn a_refusal_forged_under_any_key_passes_check_but_not_verify_for() {
        // `check` is self-consistency only: an attacker signing with its own
        // key produces a refusal `check` calls conformant.
        let responder = key();
        let attacker = SigningKey::from_bytes(&[66u8; 32]);
        let digest = "a".repeat(64);
        let forged = sign(
            &digest,
            Reason::PolicyDeclined,
            "2026-09-28T00:00:00Z",
            &attacker,
        )
        .unwrap();
        assert!(check(&forged.to_json()).conformant);
        assert_eq!(
            verify_for(&forged.to_json(), &responder.verifying_key(), &digest),
            Err(VerifyError::WrongKey)
        );
        // Swapping in the responder's key_id does not help: the signature no
        // longer verifies, so it is not even conformant.
        let mut relabelled = forged.to_json();
        relabelled["key_id"] = json!(hex::encode(responder.verifying_key().to_bytes()));
        assert_eq!(
            verify_for(&relabelled, &responder.verifying_key(), &digest),
            Err(VerifyError::NotConformant)
        );
    }

    #[test]
    fn verify_for_refuses_non_conforming_refusals() {
        let responder = key();
        let digest = "a".repeat(64);
        let r = sign(
            &digest,
            Reason::NoSuchSubject,
            "2026-09-28T00:00:00Z",
            &responder,
        )
        .unwrap();
        let mut unregistered = r.to_json();
        unregistered["reason"] = json!("no_such_record");
        assert_eq!(
            verify_for(&unregistered, &responder.verifying_key(), &digest),
            Err(VerifyError::NotConformant)
        );
        assert_eq!(
            verify_for_cbor(&[0xff], &responder.verifying_key(), &digest),
            Err(VerifyError::NotConformant)
        );
    }

    #[test]
    fn a_detail_is_outside_the_signature_in_both_bindings() {
        let digest = "a".repeat(64);
        let at = "2026-09-28T00:00:00Z";
        let plain = sign(&digest, Reason::RequestMalformed, at, &key()).unwrap();
        let with = sign_with_detail(
            &digest,
            Reason::RequestMalformed,
            at,
            Some("profiles supported: evidence-interop/0"),
            &key(),
        )
        .unwrap();
        assert_eq!(plain.sig, with.sig);
        assert_eq!(plain.detail, None);
        assert!(plain.to_json().get("detail").is_none());
        assert_eq!(
            with.to_json()["detail"],
            json!("profiles supported: evidence-interop/0")
        );
        let ok = RefusalCheck {
            signature_valid: true,
            reason_registered: true,
            conformant: true,
        };
        assert_eq!(check(&with.to_json()), ok);
        assert_eq!(check_cbor(&with.to_cbor()), ok);
        let responder = key().verifying_key();
        assert_eq!(
            verify_for(&with.to_json(), &responder, &digest),
            Ok(Reason::RequestMalformed)
        );
        assert_eq!(
            verify_for_cbor(&with.to_cbor(), &responder, &digest),
            Ok(Reason::RequestMalformed)
        );
        // Changing the detail does not touch the signature.
        let mut edited = with.to_json();
        edited["detail"] = json!("other prose");
        assert!(check(&edited).conformant);
        // An empty detail is absent, as in the Go signer.
        let empty =
            sign_with_detail(&digest, Reason::RequestMalformed, at, Some(""), &key()).unwrap();
        assert_eq!(empty, plain);
        // Nor does a hand-set empty detail reach the wire in either binding.
        let hand_set = Refusal {
            detail: Some(String::new()),
            ..plain.clone()
        };
        assert_eq!(hand_set.to_json(), plain.to_json());
        assert_eq!(hand_set.to_cbor(), plain.to_cbor());
    }

    #[test]
    fn sign_refuses_malformed_members() {
        assert_eq!(
            sign("abc", Reason::NoSuchSubject, "2026-09-28T00:00:00Z", &key()),
            Err(SignError::RequestDigest)
        );
        assert_eq!(
            sign(&"a".repeat(64), Reason::NoSuchSubject, "now", &key()),
            Err(SignError::IssuedAt)
        );
    }

    const POLICY: &str = "ff551899dc992d7c3e34b239eb3ed1067ef0bb5dbaf219bb1539021c6cedee63";
    const AT: &str = "2026-10-12T00:00:11Z";

    fn v2_with_policy() -> Refusal {
        sign_with_profile(
            PROFILE_V2,
            &"a".repeat(64),
            Reason::NoSuchSubject,
            AT,
            None,
            Some(POLICY),
            &key(),
        )
        .unwrap()
    }

    /// v2 §6.3: a `policy_digest` present is signed, in both bindings.
    #[test]
    fn a_policy_digest_is_signed_under_v2() {
        let r = v2_with_policy();
        assert_eq!(r.policy_digest.as_deref(), Some(POLICY));
        assert_eq!(r.to_json()["policy_digest"], json!(POLICY));
        let ok = RefusalCheck {
            signature_valid: true,
            reason_registered: true,
            conformant: true,
        };
        assert_eq!(check_for_profile(&r.to_json(), PROFILE_V2), ok);
        assert_eq!(check_cbor_for_profile(&r.to_cbor(), PROFILE_V2), ok);
        let digest = "a".repeat(64);
        let responder = key().verifying_key();
        assert_eq!(
            verify_for_profile(&r.to_json(), PROFILE_V2, &responder, &digest),
            Ok(Reason::NoSuchSubject)
        );
        assert_eq!(
            verify_for_profile_cbor(&r.to_cbor(), PROFILE_V2, &responder, &digest),
            Ok(Reason::NoSuchSubject)
        );
        // The signature covers the four members.
        let mut body = r.to_json().as_object().unwrap().clone();
        body.retain(|k, _| SIGNED_MEMBERS_V2.contains(&k.as_str()));
        let message = signing_body_for_profile(&body, PROFILE_V2).unwrap();
        assert!(message.contains("\"policy_digest\""));
        let sig = Signature::from_bytes(&hex::decode(&r.sig).unwrap().try_into().unwrap());
        assert!(responder.verify_strict(message.as_bytes(), &sig).is_ok());
    }

    /// Without a `policy_digest`, the v2 refusal is the A7 refusal, byte for
    /// byte, under every identifier.
    #[test]
    fn without_a_policy_digest_v2_is_the_a7_refusal() {
        let digest = "a".repeat(64);
        let a7 = sign(&digest, Reason::NoSuchSubject, AT, &key()).unwrap();
        for profile in [PROFILE, PROFILE_V1, PROFILE_V2, "evidence-interop/9"] {
            let r = sign_with_profile(
                profile,
                &digest,
                Reason::NoSuchSubject,
                AT,
                None,
                None,
                &key(),
            )
            .unwrap();
            assert_eq!(r, a7, "{profile}");
            assert!(
                check_for_profile(&r.to_json(), profile).conformant,
                "{profile}"
            );
        }
    }

    #[test]
    fn a_policy_digest_replaced_removed_or_added_fails_under_v2() {
        let r = v2_with_policy();
        let mut tampered = r.to_json();
        tampered["policy_digest"] = json!("b".repeat(64));
        let mut stripped = r.to_json();
        stripped.as_object_mut().unwrap().remove("policy_digest");
        let mut unsigned = sign(&"a".repeat(64), Reason::NoSuchSubject, AT, &key())
            .unwrap()
            .to_json();
        unsigned["policy_digest"] = json!(POLICY);
        for v in [&tampered, &stripped, &unsigned] {
            let c = check_for_profile(v, PROFILE_V2);
            assert!(!c.signature_valid && c.reason_registered && !c.conformant);
            assert_eq!(
                verify_for_profile(v, PROFILE_V2, &key().verifying_key(), &"a".repeat(64)),
                Err(VerifyError::NotConformant)
            );
        }
    }

    /// A signed `policy_digest` that is not a digest: the signature verifies,
    /// and the refusal is still not conformant (v2 §6.3).
    #[test]
    fn a_signed_policy_digest_that_is_not_a_digest_is_not_conformant() {
        let mut body = Map::new();
        body.insert("issued_at".into(), json!(AT));
        body.insert("policy_digest".into(), json!(POLICY.to_uppercase()));
        body.insert("reason".into(), json!("no_such_subject"));
        body.insert("request_digest".into(), json!("a".repeat(64)));
        let message = signing_body_for_profile(&body, PROFILE_V2).unwrap();
        body.insert(
            "key_id".into(),
            json!(hex::encode(key().verifying_key().to_bytes())),
        );
        body.insert(
            "sig".into(),
            json!(hex::encode(key().sign(message.as_bytes()).to_bytes())),
        );
        let v = Value::Object(body);
        let c = check_for_profile(&v, PROFILE_V2);
        assert!(c.signature_valid && c.reason_registered && !c.conformant);
        assert_eq!(
            verify_for_profile(&v, PROFILE_V2, &key().verifying_key(), &"a".repeat(64)),
            Err(VerifyError::NotConformant)
        );
        // And this crate does not sign one.
        assert_eq!(
            sign_with_profile(
                PROFILE_V2,
                &"a".repeat(64),
                Reason::NoSuchSubject,
                AT,
                None,
                Some(&POLICY.to_uppercase()),
                &key(),
            ),
            Err(SignError::PolicyDigest)
        );
    }

    /// v2 §6.3: under /0 and /1 the signing input is the three A7 members,
    /// whatever else the refusal carries.
    #[test]
    fn under_v1_a_policy_digest_is_outside_the_signature() {
        let digest = "a".repeat(64);
        let a7 = sign(&digest, Reason::NoSuchSubject, AT, &key()).unwrap();
        let responder = key().verifying_key();
        // An A7 refusal still verifies under /1, with or without an unsigned
        // policy_digest beside it, and so through the A7 entry points.
        let mut unbound = a7.to_json();
        unbound["policy_digest"] = json!(POLICY);
        for v in [&a7.to_json(), &unbound] {
            for profile in [PROFILE, PROFILE_V1] {
                assert!(check_for_profile(v, profile).conformant);
                assert_eq!(
                    verify_for_profile(v, profile, &responder, &digest),
                    Ok(Reason::NoSuchSubject)
                );
            }
            assert!(check(v).conformant);
            assert_eq!(
                verify_for(v, &responder, &digest),
                Ok(Reason::NoSuchSubject)
            );
        }
        // Its form does not matter there: it is not signed.
        unbound["policy_digest"] = json!("not a digest");
        assert!(check_for_profile(&unbound, PROFILE_V1).conformant);
        // A refusal signed with the v2 input fails when its request asked
        // for /1 (or /0).
        let v2 = v2_with_policy().to_json();
        for profile in [PROFILE, PROFILE_V1] {
            assert!(!check_for_profile(&v2, profile).signature_valid);
            assert_eq!(
                verify_for_profile(&v2, profile, &responder, &digest),
                Err(VerifyError::NotConformant)
            );
        }
        assert!(!check(&v2).signature_valid);
    }

    #[test]
    fn a_policy_digest_is_signed_only_under_v2() {
        for profile in [PROFILE, PROFILE_V1, "evidence-interop/9"] {
            assert_eq!(
                sign_with_profile(
                    profile,
                    &"a".repeat(64),
                    Reason::NoSuchSubject,
                    AT,
                    None,
                    Some(POLICY),
                    &key(),
                ),
                Err(SignError::PolicyDigestProfile),
                "{profile}"
            );
        }
    }

    /// v2 §6.3: for an identifier the verifier does not implement, the
    /// signature passes over the signing input of any it does.
    #[test]
    fn an_unknown_identifier_accepts_either_signing_input() {
        let digest = "a".repeat(64);
        let responder = key().verifying_key();
        let a7 = sign(&digest, Reason::NoSuchSubject, AT, &key()).unwrap();
        for v in [a7.to_json(), v2_with_policy().to_json()] {
            assert!(check_for_profile(&v, "evidence-interop/9").conformant);
            assert_eq!(
                verify_for_profile(&v, "evidence-interop/9", &responder, &digest),
                Ok(Reason::NoSuchSubject)
            );
        }
    }

    #[test]
    fn the_cbor_binding_orders_policy_digest_before_request_digest() {
        let r = v2_with_policy();
        let mut expected = vec![0xa6];
        for (k, v) in [
            ("sig", r.sig.as_str()),
            ("key_id", r.key_id.as_str()),
            ("reason", r.reason.token()),
            ("issued_at", r.issued_at.as_str()),
            ("policy_digest", POLICY),
            ("request_digest", r.request_digest.as_str()),
        ] {
            expected.extend(cbor_text(k));
            expected.extend(cbor_text(v));
        }
        assert_eq!(hex::encode(r.to_cbor()), hex::encode(expected));
    }

    #[test]
    fn non_objects_and_bad_frames_fail_every_check() {
        let none = RefusalCheck {
            signature_valid: false,
            reason_registered: false,
            conformant: false,
        };
        assert_eq!(check(&json!("refused")), none);
        assert_eq!(check_cbor(&[0xff]), none);
    }
}
