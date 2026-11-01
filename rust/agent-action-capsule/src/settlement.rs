//! Derive settlement states from two parties' leg records (verification
//! only; feature `settlement`). Port of the Python reference's
//! `agent_action_capsule.settlement`, checked against `vectors/settlement/`.
//!
//! Verifier for "Two-Party Settlement Records for Agent Payments",
//! `draft-mih-agent-settlement-records-01`. The payer and the payee are two
//! independent sealers; each seals only what its own system observed, as a
//! Capsule with a top-level `settlement` member:
//!
//! ```text
//! terms  <-terms_ref-  payer_observed, payee_observed, delivered
//! ```
//!
//! [`verify_settlements`] checks each leg record on its own (the Capsule
//! checks, its Producer Envelope, the `settlement` structure and amounts, its
//! wrapped entries and, with a key policy, that its key may seal its role),
//! then groups the legs by `terms_ref` and derives the draft's states:
//! payment `terms_only` / `payer_stated` / `payee_stated` / `agreed` /
//! `mismatch` / `unjoined`, and delivery `none` / `stated` / `matched` /
//! `mismatch`. A pair whose two observed legs share a key is never `agreed`:
//! its state is `None` and `sealer_conflation` is a failure. Whether each key
//! belongs to its party is a separate result (`key_policy_applied`). Building
//! and sealing legs is a producer's job and is not here.
//!
//! Amounts are compared exactly as decimal digit strings, at the largest
//! scale of the amounts compared, so no amount overflows.

use crate::envelope;
use crate::verify::{self, is_hex64};
use base64::Engine as _;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// The Capsule member that carries a leg.
pub const SETTLEMENT_MEMBER: &str = "settlement";
/// The settlement member's `version` for
/// `draft-mih-agent-settlement-records-00` and -01.
pub const SETTLEMENT_VERSION: &str = "0";

pub const LEGS: [&str; 4] = ["terms", "payer_observed", "payee_observed", "delivered"];
pub const ROLES: [&str; 2] = ["payer", "payee"];
pub const STATUSES: [&str; 4] = ["pending", "settled", "failed", "reversed"];
/// `delivery.direction` and the role that seals it.
pub const DELIVERY_DIRECTIONS: [(&str, &str); 2] = [("sent", "payee"), ("received", "payer")];

/// One initial payment reference type: its qualifier members, and whether a
/// receive fee may apply (`may_apply` or `not_applicable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentRefType {
    pub name: &'static str,
    pub qualifiers: &'static [&'static str],
    pub receive_fee: &'static str,
}

const fn ref_type(
    name: &'static str,
    qualifiers: &'static [&'static str],
    receive_fee: &'static str,
) -> PaymentRefType {
    PaymentRefType {
        name,
        qualifiers,
        receive_fee,
    }
}

/// The initial payment reference types. `x402.transaction` is "not
/// applicable" for the x402 `exact` scheme only.
pub const PAYMENT_REF_TYPES: [PaymentRefType; 12] = [
    ref_type("x402.transaction", &["network"], "not_applicable"),
    ref_type("ln.payment_hash", &[], "may_apply"),
    ref_type("bolt12.invoice_payment_hash", &[], "may_apply"),
    ref_type("ap2.transaction_id", &[], "may_apply"),
    ref_type("ap2.payment_id", &[], "may_apply"),
    ref_type("ap2.network_confirmation_id", &[], "may_apply"),
    ref_type("acp.order_id", &[], "may_apply"),
    ref_type("ucp.order_id", &[], "may_apply"),
    ref_type("mpp.reference", &["method"], "may_apply"),
    ref_type("iso20022.uetr", &[], "may_apply"),
    ref_type("iso20022.end_to_end_id", &["debtor_agent"], "may_apply"),
    ref_type("open_payments.incoming_payment", &[], "may_apply"),
];

/// The initial wrapped object types and their issuer under their own
/// specification.
pub const WRAPPED_TYPES: [(&str, &str); 13] = [
    ("x402.offer", "payee"),
    ("x402.receipt", "payee"),
    ("x402.payment-payload", "payer"),
    ("x402.settle-response", "other"),
    ("ap2.checkout-mandate", "payer"),
    ("ap2.payment-mandate", "payer"),
    ("ap2.checkout-receipt", "other"),
    ("ap2.payment-receipt", "other"),
    ("bolt12.invoice", "payee"),
    ("bolt12.payer-proof", "payer"),
    ("mpp.payment-receipt", "payee"),
    ("iso20022.message", "other"),
    ("delivery.proof", "other"),
];

/// The required and optional `settlement` members of one leg. Anything else
/// is `settlement_malformed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegMembers {
    pub leg: &'static str,
    pub required: &'static [&'static str],
    pub optional: &'static [&'static str],
}

pub const MEMBERS: [LegMembers; 4] = [
    LegMembers {
        leg: "terms",
        required: &["version", "leg", "sealer_role", "amount"],
        optional: &["payment_ref", "deliverable", "valid_until", "wrapped"],
    },
    LegMembers {
        leg: "payer_observed",
        required: &[
            "version",
            "leg",
            "sealer_role",
            "terms_ref",
            "amount",
            "payment_ref",
            "status",
            "observed_at",
        ],
        optional: &["routing_fee", "wrapped"],
    },
    LegMembers {
        leg: "payee_observed",
        required: &[
            "version",
            "leg",
            "sealer_role",
            "terms_ref",
            "received",
            "payment_ref",
            "status",
            "observed_at",
        ],
        optional: &["receive_fee", "wrapped"],
    },
    LegMembers {
        leg: "delivered",
        required: &[
            "version",
            "leg",
            "sealer_role",
            "terms_ref",
            "observed_at",
            "delivery",
        ],
        optional: &["wrapped"],
    },
];

/// The ISO 20022 code a reviewer reads for each observed status (pacs.002
/// `TxSts`; a reversal is a pacs.004 return), by leg and status.
pub const ISO20022_STATUS: [(&str, &str, &str); 8] = [
    ("payer_observed", "pending", "PDNG"),
    ("payer_observed", "settled", "ACSC"),
    ("payer_observed", "failed", "RJCT"),
    ("payer_observed", "reversed", "pacs.004"),
    ("payee_observed", "pending", "PDNG"),
    ("payee_observed", "settled", "ACCC"),
    ("payee_observed", "failed", "RJCT"),
    ("payee_observed", "reversed", "pacs.004"),
];

const AMOUNT_MEMBERS: [&str; 4] = ["amount", "routing_fee", "received", "receive_fee"];
const DELIVERY_MEMBERS: [&str; 8] = [
    "direction",
    "content_digest",
    "carrier",
    "tracking_digest",
    "status",
    "shipped_at",
    "delivered_at",
    "address_digest",
];
/// `delivery.status` for physical goods (the draft's "Delivered" section).
pub const DELIVERY_STATUSES: [&str; 5] =
    ["pending", "in_transit", "delivered", "failed", "returned"];
const WRAPPED_MEMBERS: [&str; 4] = ["type", "digest_alg", "digest", "content"];

const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn payment_ref_type(name: &str) -> Option<&'static PaymentRefType> {
    PAYMENT_REF_TYPES.iter().find(|t| t.name == name)
}

fn wrapped_issuer(name: &str) -> Option<&'static str> {
    WRAPPED_TYPES
        .iter()
        .find(|(t, _)| *t == name)
        .map(|(_, issuer)| *issuer)
}

fn delivery_role(direction: &str) -> Option<&'static str> {
    DELIVERY_DIRECTIONS
        .iter()
        .find(|(d, _)| *d == direction)
        .map(|(_, role)| *role)
}

fn iso20022_status(leg: &str, status: &str) -> Option<&'static str> {
    ISO20022_STATUS
        .iter()
        .find(|(l, s, _)| *l == leg && *s == status)
        .map(|(_, _, code)| *code)
}

// ---- patterns (whole-string, ASCII digits) -----------------------------------

/// `0|[1-9][0-9]*`.
fn is_value(s: &str) -> bool {
    match s.as_bytes() {
        [b'0'] => true,
        [first, rest @ ..] => (b'1'..=b'9').contains(first) && rest.iter().all(u8::is_ascii_digit),
        [] => false,
    }
}

/// `[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z`, naming
/// a real instant.
fn is_rfc3339_utc(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = |range: std::ops::Range<usize>| b[range].iter().all(u8::is_ascii_digit);
    if b.len() < 20
        || !digits(0..4)
        || b[4] != b'-'
        || !digits(5..7)
        || b[7] != b'-'
        || !digits(8..10)
        || b[10] != b'T'
        || !digits(11..13)
        || b[13] != b':'
        || !digits(14..16)
        || b[16] != b':'
        || !digits(17..19)
        || b[b.len() - 1] != b'Z'
    {
        return false;
    }
    let fraction_ok = match &b[19..b.len() - 1] {
        [] => true,
        [b'.', rest @ ..] => !rest.is_empty() && rest.iter().all(u8::is_ascii_digit),
        _ => false,
    };
    // A real instant: month 1-12, a day of that month (proleptic Gregorian
    // leap years), hour 0-23, minute 0-59, second 0-59 (no leap second).
    let number = |range: std::ops::Range<usize>| {
        b[range]
            .iter()
            .fold(0u32, |n, d| n * 10 + u32::from(d - b'0'))
    };
    let (year, month, day) = (number(0..4), number(5..7), number(8..10));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    fraction_ok
        && (1..=days).contains(&day)
        && number(11..13) <= 23
        && number(14..16) <= 59
        && number(17..19) <= 59
}

fn is_hex64_value(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(s)) if is_hex64(s))
}

fn is_rfc3339_utc_value(v: &Value) -> bool {
    matches!(v, Value::String(s) if is_rfc3339_utc(s))
}

/// Unpadded canonical base64url.
fn b64u_decode(text: &str) -> Option<Vec<u8>> {
    if !text
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    B64URL.decode(text).ok()
}

// ---- Python equality and text of JSON values ---------------------------------

/// A JSON number (or boolean, as Python's `bool` is an `int`) as a value
/// Python compares numerically: an integer's canonical digits, or a float.
enum PyNumber {
    Int(String),
    Float(f64),
}

fn py_number(value: &Value) -> Option<PyNumber> {
    match value {
        Value::Bool(b) => Some(PyNumber::Int(if *b { "1" } else { "0" }.to_string())),
        Value::Number(n) if crate::canonical::is_float(n) => n.as_f64().map(PyNumber::Float),
        Value::Number(n) => {
            let text = n.to_string();
            Some(PyNumber::Int(if text == "-0" {
                "0".to_string()
            } else {
                text
            }))
        }
        _ => None,
    }
}

/// Python `==` on decoded JSON: `1 == 1.0 == true`, objects compare as sets
/// of members.
fn py_eq(a: &Value, b: &Value) -> bool {
    if let (Some(x), Some(y)) = (py_number(a), py_number(b)) {
        return match (x, y) {
            (PyNumber::Int(x), PyNumber::Int(y)) => x == y,
            (PyNumber::Int(i), PyNumber::Float(f)) | (PyNumber::Float(f), PyNumber::Int(i)) => {
                i.parse::<f64>().ok() == Some(f)
            }
            (PyNumber::Float(x), PyNumber::Float(y)) => x == y,
        };
    }
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| py_eq(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| py_eq(v, w)))
        }
        _ => false,
    }
}

/// Python's `dict.get(name)`: an absent member reads as `None`, like `null`.
fn get_or_null<'a>(map: &'a Map<String, Value>, name: &str) -> &'a Value {
    map.get(name).unwrap_or(&Value::Null)
}

// ---- amounts -------------------------------------------------------------------

/// An exact amount (`value`, `assetCode`, `assetScale`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Amount {
    value: String,
    code: String,
    scale: u32,
}

impl Amount {
    fn read(value: Option<&Value>) -> Option<Amount> {
        let value = value?;
        if !amount_ok(value) {
            return None;
        }
        Some(Amount {
            value: value["value"].as_str()?.to_string(),
            code: value["assetCode"].as_str()?.to_string(),
            scale: value["assetScale"].to_string().parse::<i64>().ok()? as u32,
        })
    }

    /// The value at `scale` (not below this amount's scale), as canonical
    /// decimal digits.
    fn scaled(&self, scale: u32) -> String {
        let zeros = (scale - self.scale) as usize;
        canonical_digits(format!("{}{}", self.value, "0".repeat(zeros)))
    }
}

fn canonical_digits(digits: String) -> String {
    let trimmed = digits.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

/// The sum of two canonical decimal digit strings.
fn add_digits(a: &str, b: &str) -> String {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut out = Vec::with_capacity(a.len().max(b.len()) + 1);
    let mut carry = 0u8;
    for i in 0..a.len().max(b.len()) {
        let x = if i < a.len() {
            a[a.len() - 1 - i] - b'0'
        } else {
            0
        };
        let y = if i < b.len() {
            b[b.len() - 1 - i] - b'0'
        } else {
            0
        };
        let sum = x + y + carry;
        out.push(b'0' + sum % 10);
        carry = sum / 10;
    }
    if carry > 0 {
        out.push(b'0' + carry);
    }
    out.reverse();
    canonical_digits(String::from_utf8(out).expect("ASCII digits"))
}

/// An exact amount: an object of exactly `value` (`0|[1-9][0-9]*`, a
/// string), `assetCode` (a non-empty string) and `assetScale` (an integer
/// from 0 to 255).
pub fn amount_ok(a: &Value) -> bool {
    let a = match a.as_object() {
        Some(a) => a,
        None => return false,
    };
    a.len() == 3
        && matches!(a.get("value"), Some(Value::String(v)) if is_value(v))
        && matches!(a.get("assetCode"), Some(Value::String(c)) if !c.is_empty())
        && matches!(a.get("assetScale"), Some(Value::Number(n))
            if !crate::canonical::is_float(n)
                && n.to_string().parse::<i64>().is_ok_and(|s| (0..=255).contains(&s)))
}

fn amounts_equal(a: &Amount, b: &Amount) -> bool {
    let scale = a.scale.max(b.scale);
    a.code == b.code && a.scaled(scale) == b.scaled(scale)
}

/// `payer.amount == payee.received + payee.receive_fee`, exactly, one asset.
/// Never direct equality.
fn amount_rule_holds(amount: &Amount, received: &Amount, receive_fee: &Amount) -> bool {
    if amount.code != received.code || received.code != receive_fee.code {
        return false;
    }
    let scale = amount.scale.max(received.scale).max(receive_fee.scale);
    amount.scaled(scale) == add_digits(&received.scaled(scale), &receive_fee.scaled(scale))
}

// ---- structure -------------------------------------------------------------------

/// A payment reference as the join compares it: an `x402.transaction` on an
/// `eip155:` network has its `value` lowercased.
pub fn normal_payment_ref(reference: &Map<String, Value>) -> Map<String, Value> {
    let mut out = reference.clone();
    let x402 = matches!(reference.get("type"), Some(Value::String(t)) if t == "x402.transaction");
    let eip155 =
        matches!(reference.get("network"), Some(Value::String(n)) if n.starts_with("eip155:"));
    if x402 && eip155 {
        let value = match reference.get("value") {
            Some(Value::String(v)) => v.clone(),
            None => String::new(),
            Some(other) => other.to_string(),
        };
        out.insert("value".to_string(), Value::String(value.to_lowercase()));
    }
    out
}

fn keys_within(map: &Map<String, Value>, allowed: &[&str]) -> bool {
    map.keys().all(|k| allowed.contains(&k.as_str()))
}

/// The draft's structural failure codes for one `settlement` member (empty
/// if none), each once, in the order found.
pub fn structure_failures(member: &Value) -> Vec<String> {
    let malformed = || vec!["settlement_malformed".to_string()];
    let s = match member.as_object() {
        Some(s) => s,
        None => return malformed(),
    };
    let (leg, role) = match (s.get("leg"), s.get("sealer_role")) {
        (Some(Value::String(leg)), Some(Value::String(role)))
            if matches!(s.get("version"), Some(Value::String(v)) if v == SETTLEMENT_VERSION)
                && LEGS.contains(&leg.as_str())
                && ROLES.contains(&role.as_str()) =>
        {
            (leg.as_str(), role.as_str())
        }
        _ => return malformed(),
    };
    let mut out: Vec<&str> = Vec::new();
    let allowed = MEMBERS
        .iter()
        .find(|m| m.leg == leg)
        .expect("leg is one of LEGS");
    let all: Vec<&str> = allowed
        .required
        .iter()
        .chain(allowed.optional)
        .copied()
        .collect();
    if !allowed.required.iter().all(|m| s.contains_key(*m)) || !keys_within(s, &all) {
        out.push("settlement_malformed");
    }
    if (leg == "payer_observed" && role != "payer") || (leg == "payee_observed" && role != "payee")
    {
        out.push("leg_role_mismatch");
    }
    if AMOUNT_MEMBERS
        .iter()
        .any(|m| s.get(*m).is_some_and(|a| !amount_ok(a)))
    {
        out.push("amount_not_exact");
    }
    if leg.ends_with("_observed")
        && !matches!(s.get("status"), Some(Value::String(st)) if STATUSES.contains(&st.as_str()))
    {
        out.push("settlement_malformed");
    }
    if s.contains_key("terms_ref") && !is_hex64_value(s.get("terms_ref")) {
        out.push("settlement_malformed");
    }
    if s.get("observed_at")
        .is_some_and(|t| !is_rfc3339_utc_value(t))
    {
        out.push("settlement_malformed");
    }
    if leg == "delivered" {
        let ok = s.get("delivery").and_then(Value::as_object).is_some_and(|d| {
            matches!(d.get("direction"), Some(Value::String(dir)) if delivery_role(dir) == Some(role))
                && keys_within(d, &DELIVERY_MEMBERS)
                && (d.contains_key("content_digest") || d.contains_key("carrier"))
                && ["content_digest", "tracking_digest", "address_digest"]
                    .iter()
                    .all(|m| !d.contains_key(*m) || is_hex64_value(d.get(*m)))
                && d.get("carrier").is_none_or(Value::is_string)
                && d.get("status").is_none_or(|st| {
                    matches!(st, Value::String(st) if DELIVERY_STATUSES.contains(&st.as_str()))
                })
                && ["shipped_at", "delivered_at"]
                    .iter()
                    .all(|m| d.get(*m).is_none_or(is_rfc3339_utc_value))
        });
        if !ok {
            out.push("settlement_malformed");
        }
    }
    if s.get("valid_until")
        .is_some_and(|t| !is_rfc3339_utc_value(t))
    {
        out.push("settlement_malformed");
    }
    if leg == "terms" {
        if let Some(dv) = s.get("deliverable") {
            let ok = dv.as_object().is_some_and(|dv| {
                !dv.is_empty()
                    && keys_within(dv, &["content_digest", "description_digest"])
                    && dv.values().all(|v| is_hex64_value(Some(v)))
            });
            if !ok {
                out.push("settlement_malformed");
            }
        }
    }
    if let Some(reference) = s.get("payment_ref") {
        match reference.as_object() {
            Some(r)
                if matches!(r.get("type"), Some(Value::String(_)))
                    && matches!(r.get("value"), Some(Value::String(_))) =>
            {
                if let Some(t) = payment_ref_type(r["type"].as_str().unwrap_or_default()) {
                    let expected: BTreeSet<&str> = ["type", "value"]
                        .into_iter()
                        .chain(t.qualifiers.iter().copied())
                        .collect();
                    let actual: BTreeSet<&str> = r.keys().map(String::as_str).collect();
                    let qualifiers_are_strings = t
                        .qualifiers
                        .iter()
                        .all(|q| r.get(*q).is_some_and(Value::is_string));
                    if actual != expected || !qualifiers_are_strings {
                        out.push("settlement_malformed");
                    }
                }
            }
            _ => out.push("settlement_malformed"),
        }
    }
    let wrapped_ok = match s.get("wrapped") {
        None => true,
        Some(Value::Array(entries)) => entries.iter().all(|w| {
            w.as_object().is_some_and(|w| {
                matches!(w.get("digest_alg"), Some(Value::String(a)) if a == "SHA-256")
                    && matches!(w.get("type"), Some(Value::String(t)) if wrapped_issuer(t).is_some())
                    && is_hex64_value(w.get("digest"))
                    && w.get("content").is_none_or(Value::is_string)
                    && keys_within(w, &WRAPPED_MEMBERS)
            })
        }),
        Some(_) => false,
    };
    if !wrapped_ok {
        out.push("settlement_malformed");
    }
    let mut seen = HashSet::new();
    out.into_iter()
        .filter(|code| seen.insert(*code))
        .map(String::from)
        .collect()
}

// ---- the report ------------------------------------------------------------------

/// A failure or finding: the records it concerns (by `capsule_id`, `None`
/// when a record carries no string `capsule_id`) and its code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub records: Vec<Option<String>>,
    pub code: String,
}

impl Failure {
    fn new(records: Vec<Option<String>>, code: &str) -> Self {
        Failure {
            records,
            code: code.to_string(),
        }
    }
}

/// The states derived for one terms leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    /// The terms leg's `capsule_id`.
    pub terms: String,
    /// `None` only for a conflated pair that otherwise matches: no state of
    /// the draft applies, and `sealer_conflation` is a failure.
    pub payment_state: Option<String>,
    /// The agreed status, when `agreed`.
    pub agreed_status: Option<String>,
    /// `equal` or `differs`: the agreed amount against the terms amount,
    /// when `agreed`.
    pub terms_amount: Option<String>,
    /// What differs (`amount`, `status`, `payment_ref`), when `mismatch`.
    pub differs: Vec<String>,
    /// The ISO 20022 code for each observed side whose heads share one
    /// status, by leg.
    pub iso20022: Vec<(String, String)>,
    pub delivery_state: String,
}

impl Settlement {
    /// The settlement as the Python reference reports it: `terms`,
    /// `payment_state` (possibly `null`), then the members that apply.
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("terms".into(), json!(self.terms));
        out.insert("payment_state".into(), json!(self.payment_state));
        if !self.differs.is_empty() {
            out.insert("differs".into(), json!(self.differs));
        }
        if let Some(status) = &self.agreed_status {
            out.insert("agreed_status".into(), json!(status));
        }
        if let Some(terms_amount) = &self.terms_amount {
            out.insert("terms_amount".into(), json!(terms_amount));
        }
        if !self.iso20022.is_empty() {
            let iso: Map<String, Value> = self
                .iso20022
                .iter()
                .map(|(leg, code)| (leg.clone(), json!(code)))
                .collect();
            out.insert("iso20022".into(), Value::Object(iso));
        }
        out.insert("delivery_state".into(), json!(self.delivery_state));
        Value::Object(out)
    }
}

/// What [`verify_settlements`] derived, in the draft's terms.
///
/// `settlements` has one entry per terms leg, in record order. The key
/// result is separate from the payment state, as the draft asks:
/// `key_policy_applied` says whether a key policy bound each leg's key to
/// its party (`false`: `agreed` means two distinct keys agree, not that the
/// keys belong to the payer and the payee), and `keys` maps each
/// authenticated record (`"<capsule_id>:<key>"`) to its key. `diagnostics`
/// carries what the draft does not make a state, as JSON objects with a
/// `code`: `several_keys_for_role`, `delivery_sealed_under_one_key`,
/// `supersedes_ignored` and `sealer_conflation`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SettlementReport {
    pub conforming: bool,
    pub failures: Vec<Failure>,
    pub findings: Vec<Failure>,
    pub settlements: Vec<Settlement>,
    pub keys: BTreeMap<String, String>,
    pub key_policy_applied: bool,
    pub diagnostics: Vec<Value>,
}

/// Options of [`verify_settlements`].
#[derive(Debug, Clone, Default)]
pub struct SettlementOptions {
    /// Keys (lowercase hex raw Ed25519) accepted for each role (`payer`,
    /// `payee`). `None` applies no key policy.
    pub key_policy: Option<BTreeMap<String, Vec<String>>>,
    /// The octets of wrapped objects the caller holds, by their SHA-256
    /// lowercase hex digest ([`wrapped_objects_by_digest`] builds it).
    pub wrapped_objects: BTreeMap<String, Vec<u8>>,
}

/// Wrapped objects keyed by the SHA-256 of their octets.
pub fn wrapped_objects_by_digest<I: IntoIterator<Item = Vec<u8>>>(
    octets: I,
) -> BTreeMap<String, Vec<u8>> {
    octets
        .into_iter()
        .map(|o| (hex::encode(Sha256::digest(&o)), o))
        .collect()
}

/// One leg record as the derivation reads it.
struct Leg<'a> {
    /// `"<capsule_id>:<key>"`, or `"<capsule_id>:#<n>"` with no key.
    rid: String,
    cid: Option<String>,
    capsule: &'a Map<String, Value>,
    /// The `settlement` member, or empty when it is not an object.
    s: Map<String, Value>,
    kid: Option<String>,
    excluded: bool,
}

impl Leg<'_> {
    fn leg(&self) -> &str {
        self.s.get("leg").and_then(Value::as_str).unwrap_or("")
    }
    fn str_member(&self, name: &str) -> &str {
        self.s.get(name).and_then(Value::as_str).unwrap_or("")
    }
    fn cid_text(&self) -> String {
        self.cid.clone().unwrap_or_default()
    }
}

/// The authenticated key of the capsule's Producer Envelope, or `None`. The
/// envelope `signature` must be hex digit pairs (either case, no
/// whitespace), as a strict record's is.
fn envelope_key(capsule: &Map<String, Value>, cid: &str) -> Option<String> {
    let envelope = capsule
        .get("signature")
        .and_then(Value::as_str)
        .and_then(envelope::hex_pairs)?;
    let result = envelope::verify(cid, &envelope);
    result.ok.then(|| hex::encode(result.public_key))
}

/// Whether `octets` are a JWS in compact form whose EdDSA signature counts as
/// the raw Ed25519 key `public_hex`'s own under the -01 re-signing test
/// (Section "Wrapping Existing Signed Objects", rule 3): [`resigned_by`]. An
/// SD-JWT is the issuer-signed JWS, then `~` and any disclosures: only the
/// part before the first `~` is signed.
fn jws_verifies(octets: &[u8], public_hex: &str) -> bool {
    let issuer = octets.split(|b| *b == b'~').next().unwrap_or_default();
    let parts: Vec<&[u8]> = issuer.split(|b| *b == b'.').collect();
    if parts.len() != 3 {
        return false;
    }
    let key: [u8; 32] = match hex::decode(public_hex).ok().and_then(|k| k.try_into().ok()) {
        Some(k) => k,
        None => return false,
    };
    let signature: [u8; 64] = match std::str::from_utf8(parts[2])
        .ok()
        .filter(|s| s.is_ascii())
        .and_then(b64u_decode)
        .and_then(|s| s.try_into().ok())
    {
        Some(s) => s,
        None => return false,
    };
    resigned_by(&key, &[parts[0], b".", parts[1]].concat(), &signature)
}

/// The -01 re-signing test: A a canonical encoding (RFC 8032 section 5.1.3)
/// of a point not of small order, R a canonical encoding of any point, S
/// below L, and the cofactored equation `[8][S]B = [8]R + [8][k]A`. It is
/// deliberately not strict Ed25519: the check looks for the leg key's own
/// signature, and only that key's holder can make one with a small-order or
/// mixed-order R, so refusing those would let a re-signer evade it.
fn resigned_by(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::IsIdentity;
    use sha2::Sha512;

    // RFC 8032 decoding: dalek also decodes y at or above p and an x of zero
    // with the sign bit set, so the encoding must round-trip.
    let point = |bytes: &[u8]| {
        CompressedEdwardsY::from_slice(bytes)
            .ok()
            .and_then(|c| c.decompress())
            .filter(|p| p.compress().as_bytes() == bytes)
    };
    let (Some(a), Some(r)) = (point(public), point(&signature[..32])) else {
        return false;
    };
    if a.is_small_order() {
        return false;
    }
    let s_bytes: [u8; 32] = signature[32..].try_into().expect("64-octet signature");
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
        return false;
    };
    let k = Scalar::from_bytes_mod_order_wide(
        &Sha512::new()
            .chain_update(&signature[..32])
            .chain_update(public)
            .chain_update(message)
            .finalize()
            .into(),
    );
    // [S]B - [k]A - R, times the cofactor, is the identity.
    (EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &-a, &s) - r)
        .mul_by_cofactor()
        .is_identity()
}

fn wrapped_entries(s: &Map<String, Value>) -> impl Iterator<Item = &Map<String, Value>> {
    s.get("wrapped")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
}

fn wrapped_failures(
    s: &Map<String, Value>,
    kid: Option<&str>,
    objects: &BTreeMap<String, Vec<u8>>,
) -> Vec<&'static str> {
    let role = s.get("sealer_role").and_then(Value::as_str).unwrap_or("");
    let mut out = Vec::new();
    for w in wrapped_entries(s) {
        let digest = w.get("digest").and_then(Value::as_str).unwrap_or("");
        let mut octets = objects.get(digest).cloned();
        if let Some(content) = w.get("content") {
            // Content that does not decode matches no digest, the empty one
            // included.
            match content.as_str().and_then(b64u_decode) {
                Some(content) if hex::encode(Sha256::digest(&content)) == digest => {
                    octets = Some(content);
                }
                _ => {
                    out.push("wrapped_digest_mismatch");
                    continue;
                }
            }
        }
        let issuer = w
            .get("type")
            .and_then(Value::as_str)
            .and_then(wrapped_issuer);
        if let (Some(octets), Some(kid)) = (octets, kid) {
            if issuer != Some(role) && jws_verifies(&octets, kid) {
                out.push("wrapped_resigned");
            }
        }
    }
    out
}

/// Python's `bytes.lstrip()`.
fn trim_start_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !matches!(*b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c))
        .unwrap_or(bytes.len());
    &bytes[start..]
}

/// The `scheme` member of a JSON object member (`{}` when absent), or `None`
/// when that member is not an object.
fn scheme_in(object: &Map<String, Value>, member: &str) -> Option<Value> {
    match object.get(member) {
        None => None,
        Some(Value::Object(inner)) => inner.get("scheme").cloned(),
        Some(_) => None,
    }
}

/// The x402 scheme, from the first wrapped offer or payment payload whose
/// octets are held and readable. `None` when none establishes it.
fn x402_scheme(legs: &[&Map<String, Value>], objects: &BTreeMap<String, Vec<u8>>) -> Option<Value> {
    for s in legs {
        for w in wrapped_entries(s) {
            let digest = w.get("digest").and_then(Value::as_str).unwrap_or("");
            let octets = match w.get("content") {
                Some(content) => match content.as_str().and_then(b64u_decode) {
                    Some(o) => o,
                    None => continue,
                },
                None => match objects.get(digest) {
                    Some(o) => o.clone(),
                    None => continue,
                },
            };
            if hex::encode(Sha256::digest(&octets)) != digest {
                continue;
            }
            let object = |bytes: &[u8]| -> Option<Map<String, Value>> {
                match crate::json::decode(bytes).ok()? {
                    Value::Object(m) => Some(m),
                    _ => None,
                }
            };
            match w.get("type").and_then(Value::as_str) {
                Some("x402.offer") => {
                    let jws = octets.iter().filter(|b| **b == b'.').count() == 2
                        && !trim_start_ascii_whitespace(&octets).starts_with(b"{");
                    if jws {
                        let payload = octets.split(|b| *b == b'.').nth(1).unwrap_or_default();
                        let claims = std::str::from_utf8(payload)
                            .ok()
                            .filter(|p| p.is_ascii())
                            .and_then(b64u_decode)
                            .and_then(|raw| object(&raw));
                        match claims {
                            Some(claims) => return claims.get("scheme").cloned(),
                            None => continue,
                        }
                    }
                    // An EIP-712 envelope: RFC 8785 octets with a `payload`.
                    match object(&octets) {
                        Some(envelope) => return scheme_in(&envelope, "payload"),
                        None => continue,
                    }
                }
                Some("x402.payment-payload") => match object(&octets) {
                    Some(payload) => return scheme_in(&payload, "accepted"),
                    None => continue,
                },
                _ => continue,
            }
        }
    }
    None
}

/// Whether an absent `receive_fee` reads as zero: only for a reference type
/// whose receive fee is "not applicable", and for `x402.transaction` only
/// when the x402 scheme is established as `exact`.
fn receive_fee_not_applicable(
    ref_type: &str,
    terms: &Map<String, Value>,
    payer: &Map<String, Value>,
    objects: &BTreeMap<String, Vec<u8>>,
) -> bool {
    if payment_ref_type(ref_type).map(|t| t.receive_fee) != Some("not_applicable") {
        return false;
    }
    ref_type != "x402.transaction"
        || x402_scheme(&[terms, payer], objects) == Some(Value::String("exact".to_string()))
}

/// Derives settlement states from both parties' leg records, offline.
///
/// Each record is checked on its own: the Capsule checks, its Producer
/// Envelope (the authenticated key, from the capsule's hex `signature`), the
/// `settlement` structure and amounts, its wrapped entries, and, with a key
/// policy, that its key is accepted for its role. A record that fails is
/// reported and takes no part in any state. Records are grouped by
/// `terms_ref`.
///
/// A record is identified by its `capsule_id` AND its authenticated key: the
/// same content signed by another key is a different record (anyone can
/// sign a copy of a genuine leg), and it never stands in for, or excludes,
/// the original.
///
/// The wrapped objects' octets serve the re-signing check and the x402
/// scheme. Receive fees are read as zero only for x402 `exact`, established
/// from such octets; otherwise an absent `receive_fee` leaves the pair
/// `unjoined` (`fee_unstated`).
///
/// A leg record that nests arrays and objects deeper than 128 levels is
/// `capsule_invalid` and takes no part, checked before any recursive work.
pub fn verify_settlements(capsules: &[Value], options: &SettlementOptions) -> SettlementReport {
    let objects = &options.wrapped_objects;
    let policy: Option<HashMap<&str, HashSet<&str>>> = options.key_policy.as_ref().map(|p| {
        p.iter()
            .map(|(role, keys)| (role.as_str(), keys.iter().map(String::as_str).collect()))
            .collect()
    });
    let mut report = SettlementReport {
        conforming: true,
        key_policy_applied: policy.is_some(),
        ..Default::default()
    };
    let mut legs: Vec<Leg> = Vec::new();
    for (n, item) in capsules.iter().enumerate() {
        let capsule = match item.as_object() {
            Some(c) => c,
            None => {
                report
                    .failures
                    .push(Failure::new(vec![None], "capsule_invalid"));
                continue;
            }
        };
        let cid = capsule
            .get("capsule_id")
            .and_then(Value::as_str)
            .map(String::from);
        // A leg nested deeper than 128 levels is refused before any recursive
        // work (the Capsule checks, cloning its member): it takes no part.
        if crate::json::exceeds_max_depth(item) {
            report
                .failures
                .push(Failure::new(vec![cid], "capsule_invalid"));
            continue;
        }
        let mut own: Vec<&str> = Vec::new();
        let mut kid = None;
        match &cid {
            Some(id) if verify::verify(item, None).ok => {
                kid = envelope_key(capsule, id);
                if kid.is_none() {
                    own.push("envelope_invalid");
                }
            }
            _ => own.push("capsule_invalid"),
        }
        let cid_text = cid.clone().unwrap_or_else(|| "None".to_string());
        let rid = match &kid {
            Some(k) => format!("{cid_text}:{k}"),
            None => format!("{cid_text}:#{n}"),
        };
        if kid.is_some() && legs.iter().any(|l| l.rid == rid) {
            continue; // the same capsule under the same key, passed again
        }
        let member = capsule.get(SETTLEMENT_MEMBER).unwrap_or(&Value::Null);
        let structural = structure_failures(member);
        own.extend(structural.iter().map(|code| match code.as_str() {
            "leg_role_mismatch" => "leg_role_mismatch",
            "amount_not_exact" => "amount_not_exact",
            _ => "settlement_malformed",
        }));
        if structural.is_empty() {
            let s = member
                .as_object()
                .expect("a well-formed member is an object");
            own.extend(wrapped_failures(s, kid.as_deref(), objects));
            let role = s.get("sealer_role").and_then(Value::as_str).unwrap_or("");
            if let (Some(policy), Some(k)) = (&policy, &kid) {
                if !policy
                    .get(role)
                    .is_some_and(|keys| keys.contains(k.as_str()))
                {
                    own.push("sealer_not_authorized_for_role");
                }
            }
            if let Some(Value::Object(reference)) = s.get("payment_ref") {
                let known = reference
                    .get("type")
                    .and_then(Value::as_str)
                    .and_then(payment_ref_type)
                    .is_some();
                if !known {
                    report
                        .findings
                        .push(Failure::new(vec![cid.clone()], "payment_ref_type_unknown"));
                }
            }
        }
        if kid.is_none()
            && report
                .failures
                .iter()
                .any(|f| f.records == [cid.clone()] && own.contains(&f.code.as_str()))
        {
            continue; // the same unauthenticated record again: report it once
        }
        for code in &own {
            report.failures.push(Failure::new(vec![cid.clone()], code));
        }
        if let Some(k) = &kid {
            report.keys.insert(rid.clone(), k.clone());
        }
        legs.push(Leg {
            rid,
            cid,
            capsule,
            s: member.as_object().cloned().unwrap_or_default(),
            kid,
            excluded: !own.is_empty(),
        });
    }

    // Distinct keys: a payer-observed and a payee-observed leg for one terms
    // leg under the same key are not two sides. Needs no key policy.
    let observed: Vec<&Leg> = legs
        .iter()
        .filter(|l| l.kid.is_some() && l.leg().ends_with("_observed"))
        .collect();
    for p in &observed {
        for q in &observed {
            if p.leg() == "payer_observed"
                && q.leg() == "payee_observed"
                && p.kid == q.kid
                && py_eq(
                    get_or_null(&p.s, "terms_ref"),
                    get_or_null(&q.s, "terms_ref"),
                )
            {
                report.failures.push(Failure::new(
                    vec![p.cid.clone(), q.cid.clone()],
                    "sealer_conflation",
                ));
            }
        }
    }

    let live: Vec<&Leg> = legs.iter().filter(|l| !l.excluded).collect();
    // A re-signed copy of a terms leg is the same terms.
    let mut terms_by_cid: Vec<(String, &Leg)> = Vec::new();
    for leg in live.iter().filter(|l| l.leg() == "terms") {
        let cid = leg.cid_text();
        if !terms_by_cid.iter().any(|(c, _)| *c == cid) {
            terms_by_cid.push((cid, leg));
        }
    }
    for leg in live.iter().filter(|l| l.leg() != "terms") {
        let terms_ref = leg.str_member("terms_ref");
        if !terms_by_cid.iter().any(|(c, _)| c == terms_ref) {
            report
                .failures
                .push(Failure::new(vec![leg.cid.clone()], "terms_ref_unresolved"));
        }
    }
    let with_policy = policy.is_some();
    for (terms_cid, terms) in &terms_by_cid {
        let answering: Vec<&Leg> = live
            .iter()
            .filter(|l| matches!(l.s.get("terms_ref"), Some(Value::String(r)) if r == terms_cid))
            .copied()
            .collect();
        let settlement = derive(
            terms_cid,
            terms,
            &answering,
            &mut report,
            with_policy,
            objects,
        );
        report.settlements.push(settlement);
    }
    report.conforming = report.failures.is_empty();
    report
}

/// Drops observed legs that a later leg of the same side supersedes. A
/// `supersedes` link counts only when the superseding record is signed by the
/// superseded record's own key: a sealer can replace its own observation,
/// never someone else's. Any other link is ignored and reported.
fn heads<'a>(
    side: Vec<&'a Leg<'a>>,
    report: &mut SettlementReport,
    terms_cid: &str,
) -> Vec<&'a Leg<'a>> {
    let mut superseded: HashSet<&str> = HashSet::new();
    for r in &side {
        let chain = match r.capsule.get("chain") {
            Some(Value::Object(chain)) => chain,
            _ => continue,
        };
        if !matches!(chain.get("relation"), Some(Value::String(rel)) if rel == "supersedes") {
            continue;
        }
        let parent = chain.get("parent_capsule_id");
        let targets: Vec<&&Leg> = side
            .iter()
            .filter(|t| t.rid != r.rid && t.capsule.get("capsule_id") == parent && parent.is_some())
            .collect();
        let own: Vec<&&Leg> = targets
            .iter()
            .copied()
            .filter(|t| r.kid.is_some() && t.kid == r.kid)
            .collect();
        superseded.extend(own.iter().map(|t| t.rid.as_str()));
        if !targets.is_empty() && own.is_empty() {
            report.diagnostics.push(json!({
                "terms": terms_cid,
                "code": "supersedes_ignored",
                "record": r.capsule.get("capsule_id"),
                "key": r.kid,
                "parent": parent,
            }));
        }
    }
    side.into_iter()
        .filter(|l| !superseded.contains(l.rid.as_str()))
        .collect()
}

fn derive(
    terms_cid: &str,
    terms: &Leg,
    legs: &[&Leg],
    report: &mut SettlementReport,
    with_policy: bool,
    objects: &BTreeMap<String, Vec<u8>>,
) -> Settlement {
    let side =
        |leg: &str| -> Vec<&Leg> { legs.iter().copied().filter(|l| l.leg() == leg).collect() };
    let payer = heads(side("payer_observed"), report, terms_cid);
    let payee = heads(side("payee_observed"), report, terms_cid);
    let mut result = Settlement {
        terms: terms_cid.to_string(),
        payment_state: None,
        agreed_status: None,
        terms_amount: None,
        differs: Vec::new(),
        iso20022: Vec::new(),
        delivery_state: String::new(),
    };
    for (role, side) in [("payer", &payer), ("payee", &payee)] {
        let keys: BTreeSet<&str> = side.iter().filter_map(|l| l.kid.as_deref()).collect();
        if keys.len() > 1 {
            report.diagnostics.push(json!({
                "terms": terms_cid,
                "code": "several_keys_for_role",
                "role": role,
                "keys": keys,
                "key_policy_applied": with_policy,
            }));
        }
    }
    if payer.is_empty() && payee.is_empty() {
        result.payment_state = Some("terms_only".to_string());
    } else if payee.is_empty() {
        result.payment_state = Some("payer_stated".to_string());
    } else if payer.is_empty() {
        result.payment_state = Some("payee_stated".to_string());
    } else {
        pair(
            terms_cid,
            &terms.s,
            &payer,
            &payee,
            report,
            objects,
            &mut result,
        );
    }
    for (leg, side) in [("payer_observed", &payer), ("payee_observed", &payee)] {
        let statuses: BTreeSet<&str> = side.iter().map(|l| l.str_member("status")).collect();
        if statuses.len() == 1 {
            let status = statuses.into_iter().next().expect("one status");
            if let Some(code) = iso20022_status(leg, status) {
                result.iso20022.push((leg.to_string(), code.to_string()));
            }
        }
    }

    let pinned = terms
        .s
        .get("deliverable")
        .and_then(Value::as_object)
        .and_then(|d| d.get("content_digest"))
        .and_then(Value::as_str);
    let delivered: Vec<(&Leg, &Map<String, Value>)> = legs
        .iter()
        .copied()
        .filter(|l| l.leg() == "delivered")
        .filter_map(|l| {
            l.s.get("delivery")
                .and_then(Value::as_object)
                .map(|d| (l, d))
        })
        .collect();
    fn direction(d: &Map<String, Value>) -> &str {
        d.get("direction").and_then(Value::as_str).unwrap_or("")
    }
    let with_content: Vec<&(&Leg, &Map<String, Value>)> = delivered
        .iter()
        .filter(|(_, d)| d.contains_key("content_digest"))
        .collect();
    let values: BTreeSet<&str> = with_content
        .iter()
        .filter_map(|(_, d)| d.get("content_digest").and_then(Value::as_str))
        .collect();
    let directions: BTreeSet<&str> = with_content.iter().map(|(_, d)| direction(d)).collect();
    result.delivery_state = if delivered.is_empty() {
        "none"
    } else if pinned.is_some_and(|p| values.iter().any(|v| *v != p)) || values.len() > 1 {
        "mismatch"
    } else if directions == BTreeSet::from(["received", "sent"]) {
        let keys_for = |dir: &str| -> BTreeSet<Option<&str>> {
            delivered
                .iter()
                .filter(|(_, d)| direction(d) == dir)
                .map(|(l, _)| l.kid.as_deref())
                .collect()
        };
        let (sent, received) = (keys_for("sent"), keys_for("received"));
        let shared: Vec<&str> = sent.intersection(&received).copied().flatten().collect();
        if sent.intersection(&received).next().is_some() {
            report.diagnostics.push(json!({
                "terms": terms_cid,
                "code": "delivery_sealed_under_one_key",
                "keys": shared,
            }));
        }
        "matched"
    } else {
        "stated"
    }
    .to_string();
    result
}

fn pair(
    terms_cid: &str,
    terms: &Map<String, Value>,
    payer: &[&Leg],
    payee: &[&Leg],
    report: &mut SettlementReport,
    objects: &BTreeMap<String, Vec<u8>>,
    result: &mut Settlement,
) {
    // The pair the state is derived from: one payer head and one payee head
    // under distinct keys. If every combination shares a key, the pair is
    // conflated.
    let pairs: Vec<(&Leg, &Leg)> = payer
        .iter()
        .flat_map(|p| payee.iter().map(move |q| (*p, *q)))
        .filter(|(p, q)| p.kid != q.kid)
        .collect();
    let conflated = pairs.is_empty();
    let (a, b) = pairs.first().copied().unwrap_or((payer[0], payee[0]));
    let b_id = Some(b.cid_text());
    let ref_of = |leg: &Leg| -> Map<String, Value> {
        leg.s
            .get("payment_ref")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default()
    };
    let type_of = |reference: &Map<String, Value>| -> String {
        reference
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let (a_ref, b_ref) = (ref_of(a), ref_of(b));
    let (a_type, b_type) = (type_of(&a_ref), type_of(&b_ref));
    let received = Amount::read(b.s.get("received")).expect("validated payee_observed leg");
    let mut receive_fee = Amount::read(b.s.get("receive_fee"));
    if receive_fee.is_none() && receive_fee_not_applicable(&b_type, terms, &a.s, objects) {
        receive_fee = Some(Amount {
            value: "0".to_string(),
            code: received.code.clone(),
            scale: received.scale,
        });
    }
    if payment_ref_type(&a_type).is_none()
        || payment_ref_type(&b_type).is_none()
        || a_type != b_type
    {
        result.payment_state = Some("unjoined".to_string());
        return;
    }
    let receive_fee = match receive_fee {
        Some(fee) => fee,
        None => {
            report
                .findings
                .push(Failure::new(vec![b_id], "fee_unstated"));
            result.payment_state = Some("unjoined".to_string());
            return;
        }
    };
    let amount = Amount::read(a.s.get("amount")).expect("validated payer_observed leg");
    let routing_fee = Amount::read(a.s.get("routing_fee"));
    // fee_asset_differs names the leg or legs whose fee is in another asset:
    // the payer leg for routing_fee, the payee leg for receive_fee, payer first.
    let mut differ = Vec::new();
    if routing_fee.is_some_and(|fee| fee.code != amount.code) {
        differ.push(Some(a.cid_text()));
    }
    if receive_fee.code != received.code {
        differ.push(b_id);
    }
    if !differ.is_empty() {
        report
            .findings
            .push(Failure::new(differ, "fee_asset_differs"));
        result.payment_state = Some("unjoined".to_string());
        return;
    }
    let mut differs: Vec<&str> = Vec::new();
    if !amount_rule_holds(&amount, &received, &receive_fee) {
        differs.push("amount");
    }
    if a.str_member("status") != b.str_member("status") {
        differs.push("status");
    }
    let normal = |r: &Map<String, Value>| Value::Object(normal_payment_ref(r));
    if !py_eq(&normal(&a_ref), &normal(&b_ref)) {
        differs.push("payment_ref");
    }
    // More than one head on a side (no supersedes chain between them): each
    // must say the same thing.
    for side in [payer, payee] {
        let first = side[0];
        for other in &side[1..] {
            for name in AMOUNT_MEMBERS {
                // The same amount at another scale is the same amount (§6).
                let same = match (
                    Amount::read(first.s.get(name)),
                    Amount::read(other.s.get(name)),
                ) {
                    (None, None) => true,
                    (Some(x), Some(y)) => amounts_equal(&x, &y),
                    _ => false,
                };
                if !same {
                    differs.push("amount");
                }
            }
            if first.str_member("status") != other.str_member("status") {
                differs.push("status");
            }
            if !py_eq(&normal(&ref_of(other)), &normal(&ref_of(first))) {
                differs.push("payment_ref");
            }
        }
    }
    let mut seen = HashSet::new();
    differs.retain(|d| seen.insert(*d));
    if !differs.is_empty() {
        result.payment_state = Some("mismatch".to_string());
        result.differs = differs.into_iter().map(String::from).collect();
    } else if conflated {
        // The draft: a verifier MUST NOT report agreed for such a pair; it
        // reports sealer_conflation instead. sealer_conflation is a failure
        // code, not a state, and no row of the draft's state table fits a
        // conflated pair that otherwise matches, so no state is reported (an
        // open question for the draft); a diagnostic says why.
        result.payment_state = None;
        report.diagnostics.push(json!({
            "terms": terms_cid,
            "code": "sealer_conflation",
            "note": "agreed withheld; no state of the draft applies",
        }));
    } else {
        let terms_amount = Amount::read(terms.get("amount")).expect("validated terms leg");
        result.payment_state = Some("agreed".to_string());
        result.agreed_status = Some(a.str_member("status").to_string());
        result.terms_amount = Some(
            if amounts_equal(&amount, &terms_amount) {
                "equal"
            } else {
                "differs"
            }
            .to_string(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(overrides: Value) -> Value {
        let mut leg = json!({
            "version": "0", "leg": "payer_observed", "sealer_role": "payer",
            "terms_ref": "0".repeat(64),
            "amount": {"value": "15", "assetCode": "USD", "assetScale": 2},
            "payment_ref": {"type": "acp.order_id", "value": "o-1"}, "status": "settled",
            "observed_at": "2026-10-15T00:00:00Z",
        });
        for (k, v) in overrides.as_object().unwrap() {
            leg[k] = v.clone();
        }
        leg
    }

    #[test]
    fn structure_failures_names_the_draft_codes() {
        assert_eq!(structure_failures(&Value::Null), ["settlement_malformed"]);
        let leg = observed(json!({
            "sealer_role": "payee",
            "amount": {"value": "1.5", "assetCode": "USD", "assetScale": 2},
        }));
        assert_eq!(
            structure_failures(&leg),
            ["leg_role_mismatch", "amount_not_exact"]
        );
        assert!(structure_failures(&observed(json!({}))).is_empty());
    }

    #[test]
    fn patterns_match_the_whole_string_in_ascii() {
        for overrides in [
            json!({"amount": {"value": "15\n", "assetCode": "USD", "assetScale": 2}}),
            json!({"terms_ref": format!("{}\n", "0".repeat(64))}),
            json!({"observed_at": "2026-10-15T00:00:00Z\n"}),
            json!({"observed_at": "２０２6-10-15T00:00:00Z"}),
        ] {
            assert!(
                !structure_failures(&observed(overrides.clone())).is_empty(),
                "{overrides}"
            );
        }
        assert!(is_rfc3339_utc("2026-10-15T00:00:00.123Z"));
        assert!(!is_rfc3339_utc("2026-10-15T00:00:00.Z"));
    }

    #[test]
    fn a_null_payment_ref_is_malformed() {
        assert_eq!(
            structure_failures(&observed(json!({"payment_ref": null}))),
            ["settlement_malformed"]
        );
    }

    #[test]
    fn non_string_members_are_malformed() {
        let leg = json!({
            "version": "0", "leg": "delivered", "sealer_role": "payer",
            "terms_ref": "0".repeat(64), "observed_at": "2026-10-15T00:00:00Z",
            "delivery": {"direction": ["received"]},
        });
        assert_eq!(structure_failures(&leg), ["settlement_malformed"]);
        let wrapped = |w: Value| observed(json!({"wrapped": [w]}));
        assert_eq!(
            structure_failures(&wrapped(json!({
                "type": ["x402.offer"], "digest_alg": "SHA-256", "digest": "0".repeat(64),
            }))),
            ["settlement_malformed"]
        );
        assert_eq!(
            structure_failures(&wrapped(json!({
                "type": "x402.offer", "digest_alg": "SHA-256", "digest": "0".repeat(64), "content": 7,
            }))),
            ["settlement_malformed"]
        );
        assert_eq!(
            structure_failures(&observed(json!({"wrapped": null}))),
            ["settlement_malformed"]
        );
    }

    #[test]
    fn a_deeply_nested_leg_is_capsule_invalid_without_recursing() {
        use crate::json::deep;
        for nested in [deep::array(1_000_000), deep::object(129)] {
            let mut leg = observed(json!({}));
            leg["wrapped"] = Value::Array(vec![nested]);
            let mut capsule = Map::new();
            capsule.insert("capsule_id".into(), json!("c1"));
            capsule.insert("signature".into(), json!("00"));
            capsule.insert(SETTLEMENT_MEMBER.into(), leg);
            let capsules = vec![Value::Object(capsule), json!({"capsule_id": 5})];
            let report = verify_settlements(&capsules, &SettlementOptions::default());
            assert!(!report.conforming);
            assert_eq!(
                report.failures[0],
                Failure::new(vec![Some("c1".to_string())], "capsule_invalid")
            );
            // The deep leg takes no part; the next record is still read.
            assert_eq!(report.failures[1].records, [None]);
            assert!(report.settlements.is_empty());
            for capsule in capsules {
                deep::dismantle(capsule);
            }
        }
    }

    #[test]
    fn non_object_inputs_are_reported() {
        let report = verify_settlements(
            &[Value::Null, json!("x"), json!({"capsule_id": 1})],
            &SettlementOptions::default(),
        );
        assert!(!report.conforming);
        let codes: Vec<&str> = report.failures.iter().map(|f| f.code.as_str()).collect();
        assert_eq!(codes[..2], ["capsule_invalid", "capsule_invalid"]);
        assert_eq!(report.failures[0].records, [None]);
    }

    #[test]
    fn amounts_compare_exactly_at_the_largest_scale() {
        let a = |value: &str, scale: u32| Amount {
            value: value.to_string(),
            code: "USD".to_string(),
            scale,
        };
        assert!(amounts_equal(&a("1500000", 6), &a("150000000", 8)));
        assert!(!amounts_equal(&a("1500000", 6), &a("150000001", 8)));
        assert!(amount_rule_holds(
            &a("123456", 2),
            &a("1234500", 3),
            &a("60", 3)
        ));
        assert!(!amount_rule_holds(
            &a("123456", 2),
            &a("1234501", 3),
            &a("60", 3)
        ));
        assert_eq!(add_digits("999", "1"), "1000");
        assert_eq!(a("0", 0).scaled(255), "0");
        let big = "9".repeat(80);
        assert_eq!(add_digits(&big, "1"), format!("1{}", "0".repeat(80)));
    }

    #[test]
    fn amount_ok_takes_only_exact_amounts() {
        assert!(amount_ok(
            &json!({"value": "0", "assetCode": "X", "assetScale": 0})
        ));
        assert!(amount_ok(
            &json!({"value": "1", "assetCode": "X", "assetScale": 255})
        ));
        for bad in [
            json!({"value": "01", "assetCode": "X", "assetScale": 0}),
            json!({"value": "1", "assetCode": "", "assetScale": 0}),
            json!({"value": "1", "assetCode": "X", "assetScale": 256}),
            json!({"value": "1", "assetCode": "X", "assetScale": 2.0}),
            json!({"value": "1", "assetCode": "X", "assetScale": true}),
            json!({"value": 1, "assetCode": "X", "assetScale": 0}),
            json!({"value": "1", "assetCode": "X", "assetScale": 0, "extra": 1}),
        ] {
            assert!(!amount_ok(&bad), "{bad}");
        }
    }

    #[test]
    fn payment_refs_compare_as_python_does() {
        let a = json!({"type": "x402.transaction", "network": "eip155:8453", "value": "0xABC"});
        let b = json!({"type": "x402.transaction", "network": "eip155:8453", "value": "0xabc"});
        let norm = |v: &Value| Value::Object(normal_payment_ref(v.as_object().unwrap()));
        assert!(py_eq(&norm(&a), &norm(&b)));
        let other = json!({"type": "x402.transaction", "network": "solana", "value": "0xABC"});
        assert_eq!(norm(&other), other);
        assert!(py_eq(&json!({"x": 1}), &json!({"x": 1.0})));
        assert!(py_eq(&json!([true]), &json!([1])));
        assert!(!py_eq(&json!("1"), &json!(1)));
    }

    #[test]
    fn two_heads_stating_one_amount_at_two_scales_agree() {
        let capsule = Map::new();
        let leg = |rid: &str, kid: &str, s: Value| Leg {
            rid: rid.to_string(),
            cid: Some(rid.to_string()),
            capsule: &capsule,
            s: s.as_object().unwrap().clone(),
            kid: Some(kid.to_string()),
            excluded: false,
        };
        let usd = |value: &str, scale: u32| json!({"value": value, "assetCode": "USD", "assetScale": scale});
        let payer = observed(json!({}));
        let mut rescaled = payer.clone();
        rescaled["amount"] = usd("1500", 4);
        let mut payee = observed(json!({"leg": "payee_observed", "sealer_role": "payee"}));
        let payee = payee.as_object_mut().map(|m| {
            m.remove("amount");
            m.insert("received".into(), usd("15", 2));
            m.insert("receive_fee".into(), usd("0", 2));
            Value::Object(m.clone())
        });
        let terms = json!({"amount": usd("15", 2)});
        let (a, b, c) = (
            leg("a", "k1", payer),
            leg("b", "k1", rescaled.clone()),
            leg("c", "k2", payee.unwrap()),
        );
        let mut report = SettlementReport::default();
        let mut result = Settlement {
            terms: "t".into(),
            payment_state: None,
            agreed_status: None,
            terms_amount: None,
            differs: Vec::new(),
            iso20022: Vec::new(),
            delivery_state: String::new(),
        };
        let objects = BTreeMap::new();
        pair(
            "t",
            terms.as_object().unwrap(),
            &[&a, &b],
            &[&c],
            &mut report,
            &objects,
            &mut result,
        );
        assert_eq!(result.payment_state.as_deref(), Some("agreed"));

        rescaled["amount"] = usd("1501", 4);
        let d = leg("d", "k1", rescaled);
        pair(
            "t",
            terms.as_object().unwrap(),
            &[&a, &d],
            &[&c],
            &mut report,
            &objects,
            &mut result,
        );
        assert_eq!(result.payment_state.as_deref(), Some("mismatch"));
        assert_eq!(result.differs, ["amount"]);
    }

    #[test]
    fn the_envelope_signature_is_strict_hex() {
        assert_eq!(envelope::hex_pairs("0aFF"), Some(vec![0x0a, 0xff]));
        for bad in ["", " 0a", "0a ff", "0a\n", "0g", "abc"] {
            assert_eq!(envelope::hex_pairs(bad), None, "{bad:?}");
        }
        // A genuine envelope, signed over the capsule_id, authenticates;
        // the same envelope with whitespace does not.
        use ed25519_dalek::{Signer, SigningKey};
        let cid = "ab".repeat(32);
        let key = SigningKey::from_bytes(&[5; 32]);
        let public = key.verifying_key().to_bytes();
        let mut protected = vec![0xa3, 0x01, 0x27, 0x03, 0x78, 0x23];
        protected.extend_from_slice(envelope::CONTENT_TYPE.as_bytes());
        protected.extend_from_slice(&[0x04, 0x58, 0x20]);
        protected.extend_from_slice(&public);
        let payload = hex::decode(&cid).unwrap();
        let mut tbs = vec![0x84, 0x6a];
        tbs.extend_from_slice(b"Signature1");
        tbs.extend_from_slice(&[0x58, protected.len() as u8]);
        tbs.extend_from_slice(&protected);
        tbs.extend_from_slice(&[0x40, 0x58, 0x20]);
        tbs.extend_from_slice(&payload);
        let signature = key.sign(&tbs).to_bytes();
        let mut sign1 = vec![0xd2, 0x84, 0x58, protected.len() as u8];
        sign1.extend_from_slice(&protected);
        sign1.extend_from_slice(&[0xa0, 0x58, 0x20]);
        sign1.extend_from_slice(&payload);
        sign1.extend_from_slice(&[0x58, 0x40]);
        sign1.extend_from_slice(&signature);
        let hex_envelope = hex::encode(&sign1);
        let capsule = |sig: String| json!({"signature": sig}).as_object().unwrap().clone();
        assert_eq!(
            envelope_key(&capsule(hex_envelope.to_uppercase()), &cid),
            Some(hex::encode(public))
        );
        let spaced = format!("{} {}", &hex_envelope[..2], &hex_envelope[2..]);
        assert_eq!(envelope_key(&capsule(spaced), &cid), None);
        assert_eq!(
            envelope_key(&capsule(format!("{hex_envelope}\n")), &cid),
            None
        );
    }

    #[test]
    fn delivery_members_have_the_draft_types() {
        let delivered = |extra: Value| {
            let mut delivery = json!({"direction": "received", "carrier": "post"});
            for (k, v) in extra.as_object().unwrap() {
                delivery[k] = v.clone();
            }
            json!({
                "version": "0", "leg": "delivered", "sealer_role": "payer",
                "terms_ref": "0".repeat(64), "observed_at": "2026-10-15T00:00:00Z",
                "delivery": delivery,
            })
        };
        let good = json!({
            "tracking_digest": "a".repeat(64), "address_digest": "b".repeat(64),
            "status": "in_transit", "shipped_at": "2026-10-14T00:00:00Z",
            "delivered_at": "2026-10-15T00:00:00.5Z",
        });
        assert!(structure_failures(&delivered(good)).is_empty());
        for status in DELIVERY_STATUSES {
            assert!(structure_failures(&delivered(json!({"status": status}))).is_empty());
        }
        for bad in [
            json!({"carrier": 7}),
            json!({"carrier": null}),
            json!({"tracking_digest": "A".repeat(64)}),
            json!({"tracking_digest": "a".repeat(63)}),
            json!({"address_digest": 1}),
            json!({"status": "lost"}),
            json!({"status": ["pending"]}),
            json!({"status": null}),
            json!({"shipped_at": "2026-10-14"}),
            json!({"delivered_at": "2026-10-15T00:00:00+00:00"}),
            json!({"delivered_at": 1}),
        ] {
            assert_eq!(
                structure_failures(&delivered(bad.clone())),
                ["settlement_malformed"],
                "{bad}"
            );
        }
    }

    #[test]
    fn terms_valid_until_is_rfc3339_utc() {
        let terms = |valid_until: Value| {
            json!({
                "version": "0", "leg": "terms", "sealer_role": "payee",
                "amount": {"value": "15", "assetCode": "USD", "assetScale": 2},
                "valid_until": valid_until,
            })
        };
        assert!(structure_failures(&terms(json!("2026-10-15T00:00:00Z"))).is_empty());
        for bad in [
            json!("2026-10-15"),
            json!("2026-10-15T00:00:00z"),
            json!(null),
            json!(0),
        ] {
            assert_eq!(
                structure_failures(&terms(bad.clone())),
                ["settlement_malformed"],
                "{bad}"
            );
        }
    }

    #[test]
    fn utc_times_name_a_real_instant() {
        for good in [
            "2026-10-15T00:00:00Z",
            "2026-12-31T23:59:59.999Z",
            "2024-02-29T12:00:00Z",
            "2000-02-29T00:00:00Z",
            "0000-02-29T00:00:00Z",
            "2026-04-30T00:00:00Z",
            "2026-01-31T00:00:00Z",
        ] {
            assert!(is_rfc3339_utc(good), "{good}");
        }
        for bad in [
            "2026-00-15T00:00:00Z",
            "2026-13-15T00:00:00Z",
            "2026-10-00T00:00:00Z",
            "2026-10-32T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2026-10-15T24:00:00Z",
            "2026-10-15T00:60:00Z",
            "2026-12-31T23:59:60Z",
        ] {
            assert!(!is_rfc3339_utc(bad), "{bad}");
        }
        // Every member that carries a time is held to it.
        let bad = "2026-02-30T00:00:00Z";
        assert_eq!(
            structure_failures(&observed(json!({"observed_at": bad}))),
            ["settlement_malformed"]
        );
        let terms = json!({
            "version": "0", "leg": "terms", "sealer_role": "payee",
            "amount": {"value": "15", "assetCode": "USD", "assetScale": 2},
            "valid_until": bad,
        });
        assert_eq!(structure_failures(&terms), ["settlement_malformed"]);
        for member in ["shipped_at", "delivered_at"] {
            let leg = json!({
                "version": "0", "leg": "delivered", "sealer_role": "payer",
                "terms_ref": "0".repeat(64), "observed_at": "2026-10-15T00:00:00Z",
                "delivery": {"direction": "received", "carrier": "post", member: bad},
            });
            assert_eq!(
                structure_failures(&leg),
                ["settlement_malformed"],
                "{member}"
            );
        }
    }

    #[test]
    fn deeply_nested_x402_objects_are_skipped_cleanly() {
        let entry = |kind: &str, octets: &[u8]| {
            json!({
                "type": kind, "digest_alg": "SHA-256",
                "digest": hex::encode(Sha256::digest(octets)),
                "content": B64URL.encode(octets),
            })
        };
        for depth in [200usize, 100_000] {
            let deep = format!("{}1{}", "{\"payload\":".repeat(depth), "}".repeat(depth));
            let deep_jws = format!("e30.{}.c2ln", B64URL.encode(&deep));
            let exact = br#"{"accepted":{"scheme":"exact"}}"#;
            let leg = json!({"wrapped": [
                entry("x402.offer", deep.as_bytes()),
                entry("x402.offer", deep_jws.as_bytes()),
                entry("x402.payment-payload", deep.as_bytes()),
                entry("x402.payment-payload", exact),
            ]});
            let leg = leg.as_object().unwrap();
            // The unreadable objects are skipped; the readable one decides.
            assert_eq!(x402_scheme(&[leg], &BTreeMap::new()), Some(json!("exact")));
        }
    }

    #[test]
    fn registered_qualifiers_must_be_strings() {
        let reference = |network: Value| {
            observed(json!({"payment_ref": {
                "type": "x402.transaction", "value": "0xabc", "network": network,
            }}))
        };
        assert!(structure_failures(&reference(json!("eip155:8453"))).is_empty());
        for bad in [json!(8453), json!(null), json!(["eip155:8453"])] {
            assert_eq!(
                structure_failures(&reference(bad.clone())),
                ["settlement_malformed"],
                "{bad}"
            );
        }
        // Unregistered types carry any members.
        let unknown = observed(json!({"payment_ref": {"type": "x-new", "value": "v", "n": 1}}));
        assert!(structure_failures(&unknown).is_empty());
    }

    #[test]
    fn undecodable_wrapped_content_matches_no_digest() {
        let empty_digest = hex::encode(Sha256::digest(b""));
        let leg = |content: &str| {
            let s = observed(json!({"wrapped": [{
                "type": "x402.offer", "digest_alg": "SHA-256",
                "digest": empty_digest, "content": content,
            }]}));
            s.as_object().unwrap().clone()
        };
        let objects = BTreeMap::new();
        assert!(wrapped_failures(&leg(""), None, &objects).is_empty());
        for content in ["%%%", "A", "QR", "AA=="] {
            assert_eq!(
                wrapped_failures(&leg(content), None, &objects),
                ["wrapped_digest_mismatch"],
                "{content}"
            );
        }
        let other = observed(json!({"wrapped": [{
            "type": "x402.offer", "digest_alg": "SHA-256",
            "digest": "0".repeat(64), "content": "AA",
        }]}));
        assert_eq!(
            wrapped_failures(other.as_object().unwrap(), None, &objects),
            ["wrapped_digest_mismatch"]
        );
    }

    #[test]
    fn jws_signatures_verify_under_the_given_key() {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&[7; 32]);
        let input = "eyJhbGciOiJFZERTQSJ9.eyJhIjoxfQ";
        let signature = B64URL.encode(key.sign(input.as_bytes()).to_bytes());
        let jws = format!("{input}.{signature}~");
        let public = hex::encode(key.verifying_key().to_bytes());
        assert!(jws_verifies(jws.as_bytes(), &public));
        // An SD-JWT with a disclosure: only the issuer JWS before the first ~ is signed.
        assert!(jws_verifies(
            format!("{jws}WyJzYWx0IiwiYSIsMV0~").as_bytes(),
            &public
        ));
        assert!(!jws_verifies(input.as_bytes(), &public));
        let other = hex::encode(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes());
        assert!(!jws_verifies(jws.as_bytes(), &other));
    }

    /// `wrapped_resigned` counts a wrapped JWS as the leg key's own under the
    /// cofactored equation with any canonical R (-01 section 8 rule 3). A key
    /// holder's identity-R and mixed-order-R signatures count, though strict
    /// Ed25519 refuses them; the identity key's forgery, which anyone can
    /// make, does not, nor does a non-canonical R or an S at or above L.
    #[test]
    fn jws_signatures_count_under_the_cofactored_equation() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use curve25519_dalek::scalar::Scalar;
        use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as _, VerifyingKey};
        use sha2::Sha512;

        let input = "eyJhbGciOiJFZERTQSJ9.eyJhIjoxfQ";
        let lenient = |key: &[u8; 32], signature: &[u8; 64]| {
            VerifyingKey::from_bytes(key)
                .unwrap()
                .verify(input.as_bytes(), &Signature::from_bytes(signature))
                .is_ok()
        };
        let jws = |signature: &[u8; 64]| format!("{input}.{}", B64URL.encode(signature));
        let counts = |signature: &[u8; 64], key: &[u8; 32]| {
            jws_verifies(jws(signature).as_bytes(), &hex::encode(key))
        };

        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut forged = [0u8; 64];
        forged[0] = 1;
        assert!(lenient(&identity, &forged));
        assert!(!counts(&forged, &identity));

        let key = SigningKey::from_bytes(&[9; 32]);
        let public = key.verifying_key().to_bytes();
        assert!(counts(&key.sign(input.as_bytes()).to_bytes(), &public));
        let other = SigningKey::from_bytes(&[8; 32]);
        assert!(!counts(&other.sign(input.as_bytes()).to_bytes(), &public));

        // S = r + k * a mod L, k = SHA-512(R || A || M), for a chosen R.
        let sign_with = |r_point: [u8; 32], r: Scalar| {
            let k = Scalar::from_bytes_mod_order_wide(
                &Sha512::new()
                    .chain_update(r_point)
                    .chain_update(public)
                    .chain_update(input.as_bytes())
                    .finalize()
                    .into(),
            );
            let mut signature = [0u8; 64];
            signature[..32].copy_from_slice(&r_point);
            signature[32..].copy_from_slice(&(r + k * key.to_scalar()).to_bytes());
            signature
        };
        // R the identity (r = 0): the cofactorless equation holds too.
        let small_r = sign_with(identity, Scalar::ZERO);
        assert!(lenient(&public, &small_r));
        assert!(counts(&small_r, &public));
        // R = [r]B + T, T of order 8: only the cofactored equation holds.
        let torsion = CompressedEdwardsY(
            hex::decode("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .decompress()
        .unwrap();
        let r = Scalar::from(12345u64);
        let mixed_r = sign_with(
            (ED25519_BASEPOINT_POINT * r + torsion)
                .compress()
                .to_bytes(),
            r,
        );
        assert!(!lenient(&public, &mixed_r));
        assert!(counts(&mixed_r, &public));

        // R the identity with the sign bit set, R with y = p + 1, and S + L.
        let mut sign_bit = small_r;
        sign_bit[31] |= 0x80;
        assert!(!counts(&sign_bit, &public));
        let mut above_p = small_r;
        above_p[..32].copy_from_slice(
            &hex::decode("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
                .unwrap(),
        );
        assert!(!counts(&above_p, &public));
        let l = hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
            .unwrap();
        let mut s_plus_l = small_r;
        let mut carry = 0u16;
        for i in 0..32 {
            let v = u16::from(s_plus_l[32 + i]) + u16::from(l[i]) + carry;
            s_plus_l[32 + i] = v as u8;
            carry = v >> 8;
        }
        assert!(!counts(&s_plus_l, &public));
    }
}
