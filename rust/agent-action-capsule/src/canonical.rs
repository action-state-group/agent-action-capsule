//! Canonicalization and JSON-DIGEST (draft-mih-scitt-agent-action-capsule, §2, §5.1).
//!
//! `JSON-DIGEST := HEX(SHA-256(JCS(v)))` using plain RFC 8785 JCS. Byte-for-byte
//! port of the Go/Python/TS siblings' `canonical` module -- same key-ordering
//! rule (RFC 8785 §3.2.3, UTF-16 code-unit comparison), same float/unsafe-integer
//! rejection in every digest-bearing field.
//!
//! `serde_json`'s `arbitrary_precision` feature is required here: it preserves
//! a number's exact source text (as Go's `json.Number` and Python's raw decimal
//! string do), so float-vs-integer and magnitude detection read the literal
//! digits rather than a lossy `f64` round-trip.

use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::fmt;

/// IEEE-754 double `Number.MAX_SAFE_INTEGER` = 2^53 - 1.
pub const MAX_SAFE_INTEGER: i64 = (1i64 << 53) - 1;

/// Selects plain RFC 8785 JCS for new Capsule IDs.
pub const CANONICALIZATION_JCS: &str = "jcs";

/// Producer-envelope bookkeeping fields that are NEVER part of any capsule_id
/// preimage, under any format (mirrors Go's `LocalOnlyFields`).
pub fn is_local_only_field(key: &str) -> bool {
    key == "signature" || key == "key_id"
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    Float(String),
    UnsafeInt(String),
    UnsupportedType,
    NotFormat4,
    CanonicalizationIdMissing,
    CanonicalizationIdNotString,
    UnsupportedCanonicalizationId(String),
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanonicalError::Float(path) => write!(
                f,
                "float at {path}: §5.1 forbids floating-point values in digest-bearing fields"
            ),
            CanonicalError::UnsafeInt(path) => write!(
                f,
                "unsafe integer at {path}: outside ±{MAX_SAFE_INTEGER} (§5.1)"
            ),
            CanonicalError::UnsupportedType => write!(f, "unsupported type in JCS serialization"),
            CanonicalError::NotFormat4 => write!(f, "format_version must be \"4\""),
            CanonicalError::CanonicalizationIdMissing => {
                write!(f, "canonicalization_id is required")
            }
            CanonicalError::CanonicalizationIdNotString => {
                write!(f, "canonicalization_id must be a string")
            }
            CanonicalError::UnsupportedCanonicalizationId(id) => {
                write!(f, "unsupported canonicalization_id {id:?}")
            }
        }
    }
}

/// True if the JSON number's source text denotes a floating-point value
/// (contains `.`, `e`, or `E`) -- mirrors Go's `IsFloat(json.Number)`.
pub fn is_float(n: &Number) -> bool {
    let s = n.to_string();
    s.contains(['.', 'e', 'E'])
}

/// True if the integer's magnitude exceeds `MAX_SAFE_INTEGER`.
/// Precondition: `!is_float(n)`.
pub fn is_unsafe_int(n: &Number) -> bool {
    let s = n.to_string();
    let digits = s.strip_prefix('-').unwrap_or(&s);
    // 9007199254740991 is 16 digits; anything longer is definitely unsafe.
    match digits.len().cmp(&16) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => digits > "9007199254740991",
    }
}

/// RFC 8785 §3.2.3 key-ordering comparison: object members sorted by the
/// UTF-16 code-unit sequence of the member name.
fn compare_utf16(a: &str, b: &str) -> std::cmp::Ordering {
    let au: Vec<u16> = a.encode_utf16().collect();
    let bu: Vec<u16> = b.encode_utf16().collect();
    au.cmp(&bu)
}

fn sorted_keys(m: &Map<String, Value>) -> Vec<&String> {
    let mut keys: Vec<&String> = m.keys().collect();
    keys.sort_by(|a, b| compare_utf16(a, b));
    keys
}

/// RFC 8785 §3.2.2.2 string encoding.
fn jcs_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn jcs_value(v: &Value, out: &mut String) -> Result<(), CanonicalError> {
    match v {
        Value::Null => {
            out.push_str("null");
            Ok(())
        }
        Value::Bool(b) => {
            out.push_str(if *b { "true" } else { "false" });
            Ok(())
        }
        Value::String(s) => {
            jcs_string(s, out);
            Ok(())
        }
        Value::Number(n) => {
            if is_float(n) {
                return Err(CanonicalError::Float(String::new()));
            }
            if is_unsafe_int(n) {
                return Err(CanonicalError::UnsafeInt(String::new()));
            }
            let text = n.to_string();
            // RFC 8785 serializes negative zero as "0" (ECMAScript
            // Number::toString), as go/canonical does.
            out.push_str(if text == "-0" { "0" } else { &text });
            Ok(())
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_value(item, out)?;
            }
            out.push(']');
            Ok(())
        }
        Value::Object(map) => {
            out.push('{');
            for (i, key) in sorted_keys(map).into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_string(key, out);
                out.push(':');
                jcs_value(&map[key], out)?;
            }
            out.push('}');
            Ok(())
        }
    }
}

/// Returns the RFC 8785 JCS serialization of `v` as UTF-8 bytes (no
/// Unicode normalization is performed, matching the Go/Python/TS siblings).
pub fn jcs(v: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut out = String::new();
    jcs_value(v, &mut out)?;
    Ok(out.into_bytes())
}

/// `JSON-DIGEST` (§2): lowercase-hex SHA-256 of plain RFC 8785 JCS.
pub fn json_digest(v: &Value) -> Result<String, CanonicalError> {
    let bytes = jcs(v)?;
    let hash = Sha256::digest(&bytes);
    Ok(hex::encode(hash))
}

/// Absent-field normalization (§2) of the vintage `jcs-n` canonicalization:
/// removes object members whose value is null, an empty array or an empty
/// object, bottom-up, so an object emptied by the removal is itself removed
/// by its parent. Array elements are kept. Format-4 `jcs` does not normalize;
/// this is for reading pre-format-4 `jcs-n` records (Python `normalize`).
pub fn normalize(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (key, value) in map {
                let normalized = normalize(value);
                let empty = match &normalized {
                    Value::Null => true,
                    Value::Array(items) => items.is_empty(),
                    Value::Object(members) => members.is_empty(),
                    _ => false,
                };
                if !empty {
                    out.insert(key.clone(), normalized);
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(normalize).collect()),
        other => other.clone(),
    }
}

/// Recomputes a format-4 Capsule ID with plain RFC 8785 JCS. Excludes
/// `capsule_id` and the local-only producer-envelope fields; `chain`,
/// `references`, and `canonicalization_id` all participate in the preimage.
pub fn compute_capsule_id(capsule: &Map<String, Value>) -> Result<String, CanonicalError> {
    match capsule.get("format_version") {
        Some(Value::String(v)) if v == "4" => {}
        _ => return Err(CanonicalError::NotFormat4),
    }
    let algorithm = match capsule.get("canonicalization_id") {
        None => return Err(CanonicalError::CanonicalizationIdMissing),
        Some(Value::String(s)) => s,
        Some(_) => return Err(CanonicalError::CanonicalizationIdNotString),
    };
    if algorithm != CANONICALIZATION_JCS {
        return Err(CanonicalError::UnsupportedCanonicalizationId(
            algorithm.clone(),
        ));
    }
    let mut canonical = Map::with_capacity(capsule.len());
    for (k, v) in capsule {
        if k == "capsule_id" || is_local_only_field(k) {
            continue;
        }
        canonical.insert(k.clone(), v.clone());
    }
    json_digest(&Value::Object(canonical))
}

/// Every JSON path (dotted for objects, `[i]` for arrays) at which a
/// floating-point number appears in `v`, object members in byte order of
/// their keys (the Go and Python walk order). `path` prefixes every result.
pub fn float_paths(v: &Value, path: &str) -> Vec<String> {
    walk_paths(v, path, is_float)
}

/// Every JSON path at which an integer exceeds ±`MAX_SAFE_INTEGER`.
pub fn unsafe_int_paths(v: &Value, path: &str) -> Vec<String> {
    walk_paths(v, path, |n| !is_float(n) && is_unsafe_int(n))
}

/// One open array or object of the walk: its remaining children, and the
/// path they extend.
struct Frame<'a> {
    path: String,
    children: Children<'a>,
}

enum Children<'a> {
    Object(std::vec::IntoIter<(&'a String, &'a Value)>),
    Array(std::iter::Enumerate<std::slice::Iter<'a, Value>>),
}

/// Depth-first, without recursion: memory grows with nesting depth, not with
/// the input's size, and a path is built only for a number that matches.
fn walk_paths(root: &Value, root_path: &str, matches: impl Fn(&Number) -> bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack: Vec<Frame<'_>> = Vec::new();
    visit(root, root_path.to_string(), &mut stack, &mut out, &matches);
    while let Some(frame) = stack.last_mut() {
        let next = match &mut frame.children {
            Children::Object(members) => members.next().map(|(key, child)| {
                let path = if frame.path.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{key}", frame.path)
                };
                (child, path)
            }),
            Children::Array(items) => items
                .next()
                .map(|(i, child)| (child, format!("{}[{i}]", frame.path))),
        };
        match next {
            Some((child, path)) => visit(child, path, &mut stack, &mut out, &matches),
            None => {
                stack.pop();
            }
        }
    }
    out
}

fn visit<'a>(
    v: &'a Value,
    path: String,
    stack: &mut Vec<Frame<'a>>,
    out: &mut Vec<String>,
    matches: &impl Fn(&Number) -> bool,
) {
    match v {
        Value::Number(n) if matches(n) => out.push(if path.is_empty() {
            "<root>".to_string()
        } else {
            path
        }),
        Value::Object(map) => {
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            members.sort_by(|a, b| a.0.cmp(b.0));
            stack.push(Frame {
                path,
                children: Children::Object(members.into_iter()),
            });
        }
        Value::Array(items) => stack.push(Frame {
            path,
            children: Children::Array(items.iter().enumerate()),
        }),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_removes_absent_members_bottom_up() {
        let raw = json!({
            "a": null, "b": [], "c": {}, "d": {"e": null, "f": {"g": []}},
            "h": [null, {}, []], "i": 0, "j": "", "k": false,
        });
        assert_eq!(
            normalize(&raw),
            json!({"h": [null, {}, []], "i": 0, "j": "", "k": false})
        );
        assert_eq!(normalize(&json!(null)), json!(null));
    }

    /// RFC 8785 §3.2.3: key ordering compares UTF-16 CODE UNIT sequences, not
    /// Unicode scalar values. An astral character (U+10000, encoded as the
    /// surrogate pair 0xD800 0xDC00) must sort BEFORE a BMP character at
    /// U+FFFF, even though U+10000 > U+FFFF as a scalar value -- a naive
    /// `str`/`char` comparison in Rust would get this backwards.
    #[test]
    fn jcs_key_order_uses_utf16_code_units_not_scalar_values() {
        let v = json!({ "\u{ffff}": 1, "\u{10000}": 2 });
        let out = String::from_utf8(jcs(&v).expect("no floats/unsafe ints")).expect("utf8");
        let astral_pos = out.find("\u{10000}").expect("astral key present");
        let bmp_pos = out.find("\u{ffff}").expect("bmp key present");
        assert!(
            astral_pos < bmp_pos,
            "expected {out:?} to order the astral key first"
        );
    }

    #[test]
    fn negative_zero_serializes_as_zero() {
        let v: Value = serde_json::from_str(r#"{"a":-0}"#).expect("json");
        assert_eq!(jcs(&v).expect("jcs"), br#"{"a":0}"#);
    }

    #[test]
    fn number_paths_walk_keys_in_byte_order() {
        let v: Value =
            serde_json::from_str(r#"{"b":[1.5,{"\uffff":1,"\ud800\udc00":2.5}],"a":1e2}"#)
                .expect("json");
        assert_eq!(float_paths(&v, ""), ["a", "b[0]", "b[1].\u{10000}"]);
        assert_eq!(float_paths(&Value::from(1.5), ""), ["<root>"]);
        let big: Value =
            serde_json::from_str("[9007199254740992,-9007199254740991]").expect("json");
        assert_eq!(unsafe_int_paths(&big, ""), ["[0]"]);
    }

    #[test]
    fn is_unsafe_int_boundary() {
        assert!(!is_unsafe_int(&Number::from(9007199254740991i64)));
        assert!(is_unsafe_int(&Number::from(9007199254740992i64)));
        assert!(!is_unsafe_int(&Number::from(-9007199254740991i64)));
    }
}
