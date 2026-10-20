//! The Evidence Bundle `category_coverage` member (Bundle -02).
//!
//! A producer's signed declaration of what it offers in each category of a
//! named category set. It declares; it does not prove. A verifier reports
//! five properties, each on its own, and never combines them:
//!
//! - `category_coverage_form`: the member is well formed;
//! - `category_coverage_signature`: its Ed25519 signature verifies;
//! - `category_coverage_set_registered`: its set, and every name in it, is
//!   known to the verifier;
//! - `category_coverage_request`: it declares every category the Evidence
//!   Request asked for;
//! - `category_coverage_consistency`: no category declared `ABSENT` or
//!   `WITHHELD` has a record in the Bundle.
//!
//! Each property is `PASS`, `FAIL`, `NOT_PRESENT`, `NOT_CHECKED` or
//! `INCONCLUSIVE`.

use crate::{canonical, verify};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fmt;

pub const PASS: &str = "PASS";
pub const FAIL: &str = "FAIL";
pub const NOT_PRESENT: &str = "NOT_PRESENT";
pub const NOT_CHECKED: &str = "NOT_CHECKED";
pub const INCONCLUSIVE: &str = "INCONCLUSIVE";

/// The per-category statuses: the Evidence Layer -00 retention states
/// AVAILABLE, PARTIAL, WITHHELD and DELETED, and UNDISCLOSED and ABSENT,
/// which Bundle -02 defines.
pub const CATEGORY_STATUSES: [&str; 6] = [
    "AVAILABLE",
    "PARTIAL",
    "WITHHELD",
    "DELETED",
    "ABSENT",
    "UNDISCLOSED",
];

/// The five properties, in report order.
pub const CATEGORY_COVERAGE_PROPERTIES: [&str; 5] = [
    "category_coverage_form",
    "category_coverage_signature",
    "category_coverage_set_registered",
    "category_coverage_request",
    "category_coverage_consistency",
];

/// The properties whose `FAIL` makes a strict verdict INVALID.
pub const CATEGORY_COVERAGE_GATING: [&str; 3] = [
    "category_coverage_form",
    "category_coverage_signature",
    "category_coverage_consistency",
];

/// The five properties in report order, each with its value.
pub type CategoryCoverage = Vec<(&'static str, &'static str)>;

/// The inputs a Bundle cannot carry for its `category_coverage` member.
#[derive(Debug, Clone, Copy, Default)]
pub struct CategoryInputs<'a> {
    /// Each category set the caller knows, to its names. A set starting
    /// `x-` is never looked up.
    pub category_sets: Option<&'a BTreeMap<String, Vec<String>>>,
    /// The Evidence Request's octets as received.
    pub category_request: Option<&'a [u8]>,
    /// Each carried record's category by `capsule_id`, as the set's rule
    /// assigns it (`None` for a record in no category). Without it, or when
    /// a carried record is not in it, consistency is `NOT_CHECKED`.
    pub record_categories: Option<&'a BTreeMap<String, Option<String>>>,
}

const PRIVATE_SET: &str = "x-";

/// `UTF8(JCS({"category_coverage": <member without signature>, "root": root}))`.
pub fn category_coverage_signing_input(
    member: &Map<String, Value>,
    root: &Value,
) -> Result<Vec<u8>, canonical::CanonicalError> {
    let mut unsigned = member.clone();
    unsigned.remove("signature");
    let mut input = Map::new();
    input.insert("category_coverage".to_string(), Value::Object(unsigned));
    input.insert("root".to_string(), root.clone());
    canonical::jcs(&Value::Object(input))
}

fn is_hex128(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// RFC 3986 Section 4.3 absolute-URI, checked at the character level: a
/// scheme, ":", then only unreserved, sub-delims, ":", "@", "/", "?" and
/// well-formed percent-encodings. ASCII only; no fragment ("#"), so no
/// relative reference.
fn is_absolute_uri(uri: &str) -> bool {
    let bytes = uri.as_bytes();
    let Some(colon) = bytes.iter().position(|&b| b == b':') else {
        return false;
    };
    let scheme = &bytes[..colon];
    if scheme.is_empty()
        || !scheme[0].is_ascii_alphabetic()
        || !scheme[1..]
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'.' || b == b'-')
    {
        return false;
    }
    let rest = &bytes[colon + 1..];
    let mut i = 0;
    while i < rest.len() {
        let b = rest[i];
        if b == b'%' {
            if rest.len() < i + 3
                || !rest[i + 1].is_ascii_hexdigit()
                || !rest[i + 2].is_ascii_hexdigit()
            {
                return false;
            }
            i += 3;
            continue;
        }
        if !(b.is_ascii_alphanumeric() || b"._~!$&'()*+,;=:@/?-".contains(&b)) {
            return false;
        }
        i += 1;
    }
    true
}

fn well_formed(raw: &Value) -> Option<&Map<String, Value>> {
    let member = raw.as_object()?;
    if !matches!(member.get("set"), Some(Value::String(s)) if !s.is_empty()) {
        return None;
    }
    let categories = member.get("categories")?.as_object()?;
    if categories.is_empty() {
        return None;
    }
    for (name, entry) in categories {
        let entry = entry.as_object()?;
        let status = entry.get("status").and_then(Value::as_str)?;
        if name.is_empty() || !CATEGORY_STATUSES.contains(&status) {
            return None;
        }
        match entry.get("policy_uri") {
            Some(Value::String(uri)) if is_absolute_uri(uri) => {}
            Some(_) => return None,
            None if status == "UNDISCLOSED" => return None,
            None => {}
        }
    }
    if let Some(digest) = member.get("request_digest") {
        if !digest.as_str().is_some_and(verify::is_hex64) {
            return None;
        }
    }
    match (member.get("signer"), member.get("signature")) {
        (None, None) => {}
        (Some(signer), Some(signature)) => {
            let key_id = signer.as_object()?.get("key_id")?.as_str()?;
            if !verify::is_hex64(key_id) || !signature.as_str().is_some_and(is_hex128) {
                return None;
            }
        }
        _ => return None,
    }
    Some(member)
}

fn signature(member: &Map<String, Value>, root: &Value) -> &'static str {
    let Some(signature) = member.get("signature").and_then(Value::as_str) else {
        return NOT_PRESENT;
    };
    let Ok(signing_input) = category_coverage_signing_input(member, root) else {
        return FAIL; // no canonical signing input, so nothing the signature can cover
    };
    // The form check has made both 64 and 128 lowercase hex digits.
    let key_id = member["signer"]["key_id"].as_str().unwrap_or_default();
    let key: Option<[u8; 32]> = hex::decode(key_id).ok().and_then(|k| k.try_into().ok());
    let signature: Option<[u8; 64]> = hex::decode(signature).ok().and_then(|s| s.try_into().ok());
    let (Some(key), Some(signature)) = (key, signature) else {
        return FAIL;
    };
    // A small-order key "verifies" signatures over any message, so it is
    // refused, as strict verification (RFC 8032 with a small-order check) does.
    let verified = VerifyingKey::from_bytes(&key).is_ok_and(|key| {
        !key.is_weak()
            && key
                .verify(&signing_input, &Signature::from_bytes(&signature))
                .is_ok()
    });
    if verified {
        PASS
    } else {
        FAIL
    }
}

fn set_registered(
    member: &Map<String, Value>,
    category_sets: Option<&BTreeMap<String, Vec<String>>>,
) -> &'static str {
    let set = member["set"].as_str().unwrap_or_default();
    if set.starts_with(PRIVATE_SET) {
        return NOT_PRESENT;
    }
    let Some(known) = category_sets.and_then(|sets| sets.get(set)) else {
        return INCONCLUSIVE;
    };
    let categories = member["categories"]
        .as_object()
        .expect("checked by the form");
    if categories.keys().all(|name| known.contains(name)) {
        PASS
    } else {
        FAIL
    }
}

/// Deserializes one JSON value and fails on any object that names a member
/// twice, at any depth. serde_json itself keeps the last value.
struct NoRepeatedMember;

impl<'de> Deserialize<'de> for NoRepeatedMember {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NoRepeatedMemberVisitor)
    }
}

struct NoRepeatedMemberVisitor;

impl<'de> Visitor<'de> for NoRepeatedMemberVisitor {
    type Value = NoRepeatedMember;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(NoRepeatedMember)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(NoRepeatedMember)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(NoRepeatedMember)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(NoRepeatedMember)
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(NoRepeatedMember)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoRepeatedMember)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<NoRepeatedMember>()?.is_some() {}
        Ok(NoRepeatedMember)
    }
    // A number reaches here too: with arbitrary_precision, serde_json hands
    // it over as a one-member map holding its text.
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !seen.insert(name) {
                return Err(de::Error::custom("repeated member name"));
            }
            map.next_value::<NoRepeatedMember>()?;
        }
        Ok(NoRepeatedMember)
    }
}

/// The request octets read strictly: UTF-8 JSON, exactly one value, no
/// repeated member name in any object. serde_json refuses NaN and Infinity.
fn decode_request(octets: &[u8]) -> Option<Value> {
    serde_json::from_slice::<NoRepeatedMember>(octets).ok()?;
    serde_json::from_slice(octets).ok()
}

fn request(member: &Map<String, Value>, octets: Option<&[u8]>) -> &'static str {
    let Some(octets) = octets else {
        return NOT_CHECKED;
    };
    // The digest is over the octets as received, so it is checked before (and
    // whether or not) they parse.
    if let Some(digest) = member.get("request_digest") {
        if digest.as_str() != Some(hex::encode(Sha256::digest(octets)).as_str()) {
            return FAIL;
        }
    }
    let Some(Value::Object(parsed)) = decode_request(octets) else {
        return NOT_CHECKED;
    };
    let Some(asked) = parsed.get("categories") else {
        return NOT_PRESENT;
    };
    let set = asked.get("set").and_then(Value::as_str);
    let names: Option<Vec<&str>> = asked
        .get("names")
        .and_then(Value::as_array)
        .and_then(|names| names.iter().map(Value::as_str).collect());
    let (Some(set), Some(names)) = (set, names) else {
        return NOT_CHECKED; // a malformed request is the requester's to fix, not the producer's failure
    };
    if names.is_empty() || names.iter().collect::<HashSet<_>>().len() != names.len() {
        return NOT_CHECKED;
    }
    if Some(set) != member["set"].as_str() {
        return FAIL;
    }
    let categories = member["categories"]
        .as_object()
        .expect("checked by the form");
    if names.iter().all(|name| categories.contains_key(*name)) {
        PASS
    } else {
        FAIL
    }
}

fn consistency(
    member: &Map<String, Value>,
    record_ids: &[&str],
    record_categories: Option<&BTreeMap<String, Option<String>>>,
) -> &'static str {
    let Some(assigned) = record_categories else {
        return NOT_CHECKED;
    };
    let mut carried = HashSet::new();
    for id in record_ids {
        match assigned.get(*id) {
            // A record the caller could not assign could be in any category.
            None => return NOT_CHECKED,
            Some(category) => {
                carried.insert(category.as_deref());
            }
        }
    }
    let categories = member["categories"]
        .as_object()
        .expect("checked by the form");
    let contradicted = categories.iter().any(|(name, entry)| {
        matches!(
            entry.get("status").and_then(Value::as_str),
            Some("ABSENT" | "WITHHELD")
        ) && carried.contains(&Some(name.as_str()))
    });
    if contradicted {
        FAIL
    } else {
        PASS
    }
}

/// The five properties of `bundle["category_coverage"]`, in report order, or
/// `None` when the Bundle carries no such member. When the member is
/// malformed, every other property is `NOT_CHECKED`.
pub fn check_category_coverage(
    bundle: &Map<String, Value>,
    inputs: &CategoryInputs,
) -> Option<CategoryCoverage> {
    let raw = bundle.get("category_coverage")?;
    let values: [&'static str; 5] = match well_formed(raw) {
        None => [FAIL, NOT_CHECKED, NOT_CHECKED, NOT_CHECKED, NOT_CHECKED],
        Some(member) => {
            let record_ids: Vec<&str> = bundle
                .get("records")
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .filter_map(|record| record.get("capsule_id").and_then(Value::as_str))
                .collect();
            [
                PASS,
                signature(member, bundle.get("root").unwrap_or(&Value::Null)),
                set_registered(member, inputs.category_sets),
                request(member, inputs.category_request),
                consistency(member, &record_ids, inputs.record_categories),
            ]
        }
    };
    Some(
        CATEGORY_COVERAGE_PROPERTIES
            .into_iter()
            .zip(values)
            .collect(),
    )
}

/// Whether a property whose `FAIL` gates the strict verdict failed.
#[cfg(feature = "strict")]
pub(super) fn category_coverage_fails(coverage: Option<&CategoryCoverage>) -> bool {
    coverage.is_some_and(|properties| {
        properties
            .iter()
            .any(|(name, value)| CATEGORY_COVERAGE_GATING.contains(name) && *value == FAIL)
    })
}
