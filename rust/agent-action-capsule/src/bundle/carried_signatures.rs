//! The carried signature profiles of `composed/v1`
//! (draft-mih-zhang-agent-disclosure-bundle-03, "Carried Signature
//! Profiles"), a port of `go/bundle/carried_signatures.go`: three opt-in
//! profiles in which a verifier checks the signature of a refusal or an
//! artifact response a member carries. Pass [`verify_carried_refusal`] and
//! [`verify_carried_response`] as [`ComposedOptions`](super::ComposedOptions)
//! `refusal_signature` and `response_signature`; without them every carried
//! signature stays signature-unverified.
//!
//! Each check returns [`SIGNATURE_VERIFIED`], [`SIGNATURE_INVALID`] or
//! [`SIGNATURE_UNVERIFIED`]. The state covers the signature alone: no check
//! of a signed value enters it, and it does not compare the key with the
//! member's responder. Ed25519 is strict: a small-order key or R never
//! verifies.

use super::composed::{SIGNATURE_INVALID, SIGNATURE_UNVERIFIED, SIGNATURE_VERIFIED};
use crate::canonical;
use crate::ed25519_strict::strict_ed25519;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::{Map, Value};

/// Signs the refusal's `issued_at`, `reason` and `request_digest` with
/// `sig` under `key_id`.
pub const THREE_MEMBER_REFUSAL: &str = "three-member-refusal/v1";
/// Signs the whole refusal without `signature` with `signature` under
/// `key_id`.
pub const WHOLE_REFUSAL: &str = "whole-refusal/v1";
/// Signs an artifact response's five members, with the type
/// [`ARTIFACT_RESPONSE_TYPE`], with `sig` under `key_id`.
pub const DIGEST_BOUND_ARTIFACT_RESPONSE: &str = "digest-bound-artifact-response/v1";
/// The `type` the verifier supplies to a digest-bound artifact response's
/// signing input; it is never read from the carried object.
pub const ARTIFACT_RESPONSE_TYPE: &str = "evidence-artifact-response/v1";

const REFUSAL_SIGNED: [&str; 3] = ["issued_at", "reason", "request_digest"];
const RESPONSE_SIGNED: [&str; 5] = [
    "request_digest",
    "anchor",
    "artifact_kind",
    "artifact_digest",
    "issued_at",
];

/// The profile a carried refusal is read in: one that carries `sig` and no
/// `signature` is in [`THREE_MEMBER_REFUSAL`], unless it also carries
/// `policy_digest` (an evidence-interop/2 refusal may sign it), in which
/// case it is in none of these profiles (`None`); every other refusal is in
/// [`WHOLE_REFUSAL`]. Presence decides; a `null` member is present.
pub fn carried_refusal_profile(refusal: &Map<String, Value>) -> Option<&'static str> {
    if refusal.contains_key("sig") && !refusal.contains_key("signature") {
        (!refusal.contains_key("policy_digest")).then_some(THREE_MEMBER_REFUSAL)
    } else {
        Some(WHOLE_REFUSAL)
    }
}

/// [`DIGEST_BOUND_ARTIFACT_RESPONSE`] for a carried response that does not
/// carry `responder`; `None` for one that does, which is in none of these
/// profiles.
pub fn carried_response_profile(response: &Map<String, Value>) -> Option<&'static str> {
    (!response.contains_key("responder")).then_some(DIGEST_BOUND_ARTIFACT_RESPONSE)
}

/// A carried refusal's signature in the profile it is read in.
pub fn verify_carried_refusal(refusal: &Map<String, Value>) -> &'static str {
    match carried_refusal_profile(refusal) {
        None => SIGNATURE_UNVERIFIED,
        Some(THREE_MEMBER_REFUSAL) => verify_three_member_refusal(refusal),
        Some(_) => verify_whole_refusal(refusal),
    }
}

/// The response hook: every carried response this module can check.
pub fn verify_carried_response(response: &Map<String, Value>) -> &'static str {
    verify_digest_bound_artifact_response(response)
}

/// The named members, each present and a string.
fn strings(value: &Map<String, Value>, names: &[&str]) -> Option<Map<String, Value>> {
    names
        .iter()
        .map(|name| match value.get(*name) {
            Some(Value::String(s)) => Some((name.to_string(), Value::String(s.clone()))),
            _ => None,
        })
        .collect()
}

fn lower_hex(value: Option<&Value>, len: usize) -> Option<Vec<u8>> {
    let s = value?.as_str()?;
    if s.len() != len
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    hex::decode(s).ok()
}

fn verifies(key: Option<&Value>, sig: Option<&Value>, input: &[u8]) -> &'static str {
    let key: Option<[u8; 32]> = lower_hex(key, 64).and_then(|k| k.try_into().ok());
    let sig: Option<[u8; 64]> = lower_hex(sig, 128).and_then(|s| s.try_into().ok());
    let (Some(key), Some(sig)) = (key, sig) else {
        return SIGNATURE_INVALID;
    };
    let verified = strict_ed25519(&key, &sig)
        && VerifyingKey::from_bytes(&key)
            .is_ok_and(|k| k.verify(input, &Signature::from_bytes(&sig)).is_ok());
    if verified {
        SIGNATURE_VERIFIED
    } else {
        SIGNATURE_INVALID
    }
}

/// The UTF-8 JCS of the refusal's `issued_at`, `reason` and
/// `request_digest`, or `None` when one is absent or not a string.
pub fn three_member_refusal_signing_input(refusal: &Map<String, Value>) -> Option<Vec<u8>> {
    canonical::jcs(&Value::Object(strings(refusal, &REFUSAL_SIGNED)?)).ok()
}

/// The refusal's `sig` under its `key_id` in [`THREE_MEMBER_REFUSAL`]. A
/// refusal in this profile carries `sig`, so it is never signature-unverified.
pub fn verify_three_member_refusal(refusal: &Map<String, Value>) -> &'static str {
    match three_member_refusal_signing_input(refusal) {
        Some(input) => verifies(refusal.get("key_id"), refusal.get("sig"), &input),
        None => SIGNATURE_INVALID,
    }
}

/// The refusal's `signature` under its `key_id` over the JCS of the refusal
/// without `signature`, in [`WHOLE_REFUSAL`].
pub fn verify_whole_refusal(refusal: &Map<String, Value>) -> &'static str {
    if !refusal.contains_key("key_id") && !refusal.contains_key("signature") {
        return SIGNATURE_UNVERIFIED;
    }
    let mut unsigned = refusal.clone();
    unsigned.remove("signature");
    match canonical::jcs(&Value::Object(unsigned)) {
        Ok(input) => verifies(refusal.get("key_id"), refusal.get("signature"), &input),
        Err(_) => SIGNATURE_INVALID,
    }
}

/// The signing input of [`DIGEST_BOUND_ARTIFACT_RESPONSE`]: the UTF-8 JCS of
/// the five members and `type` [`ARTIFACT_RESPONSE_TYPE`].
pub fn artifact_response_signing_input(
    request_digest: &str,
    anchor: &str,
    artifact_kind: &str,
    artifact_digest: &str,
    issued_at: &str,
) -> Vec<u8> {
    let value = serde_json::json!({
        "type": ARTIFACT_RESPONSE_TYPE, "request_digest": request_digest, "anchor": anchor,
        "artifact_kind": artifact_kind, "artifact_digest": artifact_digest, "issued_at": issued_at,
    });
    canonical::jcs(&value).expect("strings only")
}

/// A carried response's `sig` under its `key_id` in
/// [`DIGEST_BOUND_ARTIFACT_RESPONSE`]. A response that carries `responder`
/// is in none of these profiles and is signature-unverified, as is one that
/// carries neither `key_id` nor `sig`.
pub fn verify_digest_bound_artifact_response(response: &Map<String, Value>) -> &'static str {
    if carried_response_profile(response).is_none()
        || (!response.contains_key("key_id") && !response.contains_key("sig"))
    {
        return SIGNATURE_UNVERIFIED;
    }
    let Some(signed) = strings(response, &RESPONSE_SIGNED) else {
        return SIGNATURE_INVALID;
    };
    let get = |name: &str| signed[name].as_str().expect("checked string");
    let input = artifact_response_signing_input(
        get("request_digest"),
        get("anchor"),
        get("artifact_kind"),
        get("artifact_digest"),
        get("issued_at"),
    );
    verifies(response.get("key_id"), response.get("sig"), &input)
}
