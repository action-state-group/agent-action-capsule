//! The Rust stdin/stdout adapter for `scripts/evidence-request-interlock.sh`.
//! Every command reads one JSON document on stdin and writes one compact,
//! key-sorted JSON document on stdout (RFC 8785, so the key order does not
//! depend on serde_json features), so the outputs of the Python, Go and Rust
//! adapters compare byte for byte.
//!
//! `classify`: `[{id, binding: "json"|"cbor", request_hex}]` to
//! `[{id, reason, request_digest, well_formed}]` (`reason` is null when the
//! request is well formed).
//! `refuse`: `{seed_hex, issued_at, cases: [{id, request_hex, reason}]}` to
//! `[{id, refusal}]`, each refusal signed with the Ed25519 key from
//! `seed_hex`.
//! `verify`: `{public_key_hex, items: [{id, request_digest, refusal}]}` to
//! `[{id, reason}]`; any refusal that does not verify is reported on stderr
//! and the command exits 1.
//! `envelope`: `{seed_hex, issued_at, cases: [{id, binding, request_hex,
//! subject, anchor_digest, artifact_hex, derivation?, freshness?,
//! verification: [{kind, hex}]}]}` to `[{id, reply_hex}]`: the interop
//! profile's envelope (§6.2), signed with the key from `seed_hex`.
//! `check-envelope`: `[{id, binding, reply_hex}]` to `[{id}]`; any reply that
//! is not an envelope verifying under its own key is reported on stderr, as
//! `id: reason`, and the command exits 1.
//! `check-cll` (feature `cll`): `{log_keys: [{iss, sub, kid}], cases: [{id,
//! binding, reply_hex}]}` to `[{id, failed}]`: each reply verified as an
//! envelope, then its Checkpointed Local Log material checked (profile
//! §6.2.1) with only the listed log keys trusted. `failed` is null when both
//! pass, else the first check that did not: `envelope`, `inclusion`,
//! `consistency` or `other`. Each failure's reason goes to stderr as
//! `id: reason`; the command still exits 0.
//! `unavailable`: the cases of `unavailable-window.json` (-02 §4.7) to, per
//! statement case, `{id, recognized, why, registration_time}` and, per
//! display case, `{id, state, shown_as, covered_by, labels}`.

use ed25519_dalek::{SigningKey, VerifyingKey};
use evidence_request::digest::request_digest;
use evidence_request::envelope::{
    parse_reply, Anchor, AnchorFreshness, Binding, EnvelopeParts, Reply,
};
use evidence_request::outcome::{record, Received, Window};
use evidence_request::refusal::{sign, verify_for};
use evidence_request::registry::Reason;
use evidence_request::request::{derivation_from_text, parse_cbor, parse_json, subject_from_value};
use evidence_request::unavailable_window::{
    display, recognize, RegistrationReceipt, WindowStatement,
};
use serde_json::{json, Value};
use std::io::Read;
use std::process::ExitCode;

fn main() -> ExitCode {
    let command = std::env::args().nth(1).unwrap_or_default();
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut input) {
        eprintln!("{e}");
        return ExitCode::from(2);
    }
    let doc: Value = match serde_json::from_slice(&input) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("input is not JSON: {e}");
            return ExitCode::from(2);
        }
    };
    let result = match command.as_str() {
        "classify" => classify(&doc),
        "refuse" => refuse(&doc),
        "verify" => verify(&doc),
        "envelope" => envelope(&doc),
        "check-envelope" => check_envelope(&doc),
        #[cfg(feature = "cll")]
        "check-cll" => check_cll(&doc),
        "unavailable" => unavailable(&doc),
        _ => Err(
            "usage: interlock classify|refuse|verify|envelope|check-envelope|check-cll|unavailable"
                .to_string(),
        ),
    };
    match result {
        Ok(out) => {
            // RFC 8785: sorted keys and no whitespace, whatever map order
            // serde_json was built with.
            match evidence_request::jcs::to_string(&out) {
                Ok(text) => {
                    println!("{text}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::from(1)
                }
            }
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v[key]
        .as_str()
        .ok_or_else(|| format!("{key} missing in {v}"))
}

fn bytes(v: &Value, key: &str) -> Result<Vec<u8>, String> {
    hex::decode(text(v, key)?).map_err(|e| format!("{key}: {e}"))
}

fn array(v: &Value) -> Result<&Vec<Value>, String> {
    v.as_array()
        .ok_or_else(|| "expected a JSON array".to_string())
}

fn classify(doc: &Value) -> Result<Value, String> {
    let mut out = Vec::new();
    for case in array(doc)? {
        let request = bytes(case, "request_hex")?;
        let parsed = match text(case, "binding")? {
            "json" => parse_json(&request),
            "cbor" => parse_cbor(&request),
            other => return Err(format!("unknown binding {other}")),
        };
        let reason = parsed.err().map(|e| e.reason().token());
        out.push(json!({
            "id": text(case, "id")?,
            "request_digest": request_digest(&request),
            "well_formed": reason.is_none(),
            "reason": reason,
        }));
    }
    Ok(Value::Array(out))
}

fn refuse(doc: &Value) -> Result<Value, String> {
    let seed: [u8; 32] = bytes(doc, "seed_hex")?
        .try_into()
        .map_err(|_| "seed_hex must be 32 bytes".to_string())?;
    let key = SigningKey::from_bytes(&seed);
    let issued_at = text(doc, "issued_at")?;
    let mut out = Vec::new();
    for case in array(&doc["cases"])? {
        let reason = Reason::from_token(text(case, "reason")?)
            .ok_or_else(|| format!("unregistered reason in {case}"))?;
        let digest = request_digest(&bytes(case, "request_hex")?);
        let refusal = sign(&digest, reason, issued_at, &key).map_err(|e| e.to_string())?;
        out.push(json!({"id": text(case, "id")?, "refusal": refusal.to_json()}));
    }
    Ok(Value::Array(out))
}

fn verify(doc: &Value) -> Result<Value, String> {
    let public: [u8; 32] = bytes(doc, "public_key_hex")?
        .try_into()
        .map_err(|_| "public_key_hex must be 32 bytes".to_string())?;
    let key = VerifyingKey::from_bytes(&public).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let mut failures = Vec::new();
    for item in array(&doc["items"])? {
        let id = text(item, "id")?;
        match verify_for(&item["refusal"], &key, text(item, "request_digest")?) {
            Ok(reason) => out.push(json!({"id": id, "reason": reason.token()})),
            Err(e) => failures.push(format!("{id}: {e}")),
        }
    }
    if failures.is_empty() {
        Ok(Value::Array(out))
    } else {
        Err(failures.join("\n"))
    }
}

fn binding(v: &Value) -> Result<Binding, String> {
    match text(v, "binding")? {
        "json" => Ok(Binding::Json),
        "cbor" => Ok(Binding::Cbor),
        other => Err(format!("unknown binding {other}")),
    }
}

fn envelope(doc: &Value) -> Result<Value, String> {
    let seed: [u8; 32] = bytes(doc, "seed_hex")?
        .try_into()
        .map_err(|_| "seed_hex must be 32 bytes".to_string())?;
    let key = SigningKey::from_bytes(&seed);
    let mut out = Vec::new();
    for case in array(&doc["cases"])? {
        let id = text(case, "id")?;
        let freshness = match &case["freshness"] {
            Value::Null => None,
            Value::Number(n) => Some(AnchorFreshness::Size(
                n.as_u64().ok_or_else(|| format!("{id}: freshness"))?,
            )),
            Value::String(t) => Some(AnchorFreshness::Time(t.clone())),
            other => return Err(format!("{id}: freshness {other}")),
        };
        let derivation = match case["derivation"].as_str() {
            Some(d) => Some(derivation_from_text(d).map_err(|e| format!("{id}: {e}"))?),
            None => None,
        };
        let verification = match case["verification"].as_array() {
            Some(items) => items
                .iter()
                .map(|v| Ok((text(v, "kind")?.to_string(), bytes(v, "hex")?)))
                .collect::<Result<Vec<_>, String>>()?,
            None => Vec::new(),
        };
        let parts = EnvelopeParts {
            subject: subject_from_value(&case["subject"]).map_err(|e| format!("{id}: {e}"))?,
            derivation,
            anchor: Anchor {
                digest: text(case, "anchor_digest")?.to_string(),
                freshness,
            },
            artifact: bytes(case, "artifact_hex")?,
            verification,
            issued_at: text(doc, "issued_at")?.to_string(),
        };
        let signed = evidence_request::envelope::sign(&bytes(case, "request_hex")?, parts, &key)
            .map_err(|e| format!("{id}: {e}"))?;
        out.push(json!({"id": id, "reply_hex": hex::encode(signed.encode(binding(case)?))}));
    }
    Ok(Value::Array(out))
}

fn check_envelope(doc: &Value) -> Result<Value, String> {
    let mut out = Vec::new();
    let mut failures = Vec::new();
    for item in array(doc)? {
        let id = text(item, "id")?;
        let checked = match parse_reply(&bytes(item, "reply_hex")?, binding(item)?) {
            Ok(Reply::Envelope(e)) => e.verify().map_err(|e| e.to_string()),
            Ok(Reply::Refusal(_)) => Err("the reply is not an envelope".to_string()),
            Err(e) => Err(e.to_string()),
        };
        match checked {
            Ok(()) => out.push(json!({ "id": id })),
            Err(e) => failures.push(format!("{id}: {e}")),
        }
    }
    if failures.is_empty() {
        Ok(Value::Array(out))
    } else {
        Err(failures.join("\n"))
    }
}

/// Trusts exactly the listed (iss, sub, kid) log keys.
#[cfg(feature = "cll")]
struct ListedLogKeys(Vec<(String, String, Vec<u8>)>);

#[cfg(feature = "cll")]
impl evidence_request::cll_material::LogKeyPolicy for ListedLogKeys {
    fn resolve(
        &self,
        iss: &str,
        sub: &str,
        kid: &[u8],
        _issued_at: &str,
    ) -> evidence_request::cll_material::KeyDecision {
        use evidence_request::cll_material::KeyDecision;
        let listed = self
            .0
            .iter()
            .any(|(i, s, k)| i == iss && s == sub && k == kid);
        match <[u8; 32]>::try_from(kid) {
            Ok(raw) if listed => VerifyingKey::from_bytes(&raw)
                .map(KeyDecision::Accept)
                .unwrap_or(KeyDecision::Reject),
            _ => KeyDecision::Reject,
        }
    }
}

#[cfg(feature = "cll")]
fn check_cll(doc: &Value) -> Result<Value, String> {
    use evidence_request::cll_material::{check_anchor_inclusion, Status};
    let keys = array(&doc["log_keys"])?
        .iter()
        .map(|k| {
            Ok((
                text(k, "iss")?.to_string(),
                text(k, "sub")?.to_string(),
                bytes(k, "kid")?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let policy = ListedLogKeys(keys);
    let mut out = Vec::new();
    for case in array(&doc["cases"])? {
        let id = text(case, "id")?;
        let envelope = match parse_reply(&bytes(case, "reply_hex")?, binding(case)?) {
            Ok(Reply::Envelope(e)) => e,
            Ok(Reply::Refusal(_)) => return Err(format!("{id}: the reply is not an envelope")),
            Err(e) => return Err(format!("{id}: {e}")),
        };
        let failed = if let Err(e) = envelope.verify() {
            eprintln!("{id}: {e}");
            Some("envelope")
        } else {
            let report = check_anchor_inclusion(&envelope, &policy);
            if report.status == Status::Pass {
                None
            } else {
                eprintln!("{id}: {:?}: {}", report.status, report.detail);
                Some(match report.detail.split_once(": ") {
                    Some(("inclusion", _)) if report.status == Status::Fail => "inclusion",
                    Some(("consistency", _)) if report.status == Status::Fail => "consistency",
                    _ => "other",
                })
            }
        };
        out.push(json!({"id": id, "failed": failed}));
    }
    Ok(Value::Array(out))
}

fn registration_receipts(receipts: &Value) -> Result<Vec<RegistrationReceipt>, String> {
    array(receipts)?
        .iter()
        .map(|r| {
            Ok(RegistrationReceipt {
                time: text(r, "time")?.to_string(),
                accepted: r["accepted"]
                    .as_bool()
                    .ok_or_else(|| format!("accepted missing in {r}"))?,
            })
        })
        .collect()
}

fn unavailable(doc: &Value) -> Result<Value, String> {
    let mut out = Vec::new();
    for case in array(doc)? {
        let id = text(case, "id")?;
        let public: [u8; 32] = bytes(case, "responder_key")?
            .try_into()
            .map_err(|_| "responder_key must be 32 bytes".to_string())?;
        let key = VerifyingKey::from_bytes(&public).map_err(|e| e.to_string())?;
        if text(case, "kind")? == "statement" {
            let receipts = registration_receipts(&case["receipts"])?;
            let reading = recognize(&case["statement"], &receipts, &key);
            out.push(json!({
                "id": id,
                "recognized": reading.is_ok(),
                "why": reading.as_ref().err().map(|why| why.token()),
                "registration_time": reading.as_ref().ok().map(|r| r.registration_time.clone()),
            }));
            continue;
        }
        let absence = &case["absence"];
        let closed_at = absence["closed_at"].as_str();
        let received = match text(absence, "received")? {
            "nothing" => Received::Nothing,
            "refusal" => Received::Refusal {
                signature_valid: true,
                reason: text(absence, "refusal_reason")?.to_string(),
            },
            other => return Err(format!("{id}: received {other}")),
        };
        let window = if closed_at.is_some() {
            Window::Closed
        } else {
            Window::Open
        };
        let statements = array(&case["statements"])?
            .iter()
            .map(|s| {
                Ok(WindowStatement {
                    id: text(s, "id")?.to_string(),
                    statement: s["statement"].clone(),
                    receipts: registration_receipts(&s["receipts"])?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let shown = display(
            record(&received, window),
            text(absence, "sent_at")?,
            closed_at,
            &statements,
            &key,
        )
        .map_err(|e| format!("{id}: {e}"))?;
        let labels: serde_json::Map<String, Value> = shown
            .labels
            .iter()
            .map(|(sid, l)| {
                (
                    sid.clone(),
                    json!({
                        "reason_class": l.reason_class.token(),
                        "registration_time": l.registration_time,
                        "stated_afterwards": l.stated_afterwards,
                        "stated_period": [l.stated_period.0, l.stated_period.1],
                    }),
                )
            })
            .collect();
        out.push(json!({
            "id": id,
            "state": shown.state.token(),
            "shown_as": shown.shown_as,
            "covered_by": shown.covered_by,
            "labels": labels,
        }));
    }
    Ok(Value::Array(out))
}
