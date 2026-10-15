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

use ed25519_dalek::{SigningKey, VerifyingKey};
use evidence_request::digest::request_digest;
use evidence_request::refusal::{sign, verify_for};
use evidence_request::registry::Reason;
use evidence_request::request::{parse_cbor, parse_json};
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
        _ => Err("usage: interlock classify|refuse|verify".to_string()),
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
