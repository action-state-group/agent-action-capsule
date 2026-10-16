//! A strict RFC 8259 JSON decoder into [`serde_json::Value`].
//!
//! `serde_json`'s own decoder cannot be used for capsules: with
//! `arbitrary_precision` it turns the object `{"$serde_json::private::Number":
//! "1"}` into the number `1`, so a capsule carrying that member would get a
//! different preimage, and Capsule ID, in Rust than in every other
//! implementation. This decoder builds objects and arrays itself and hands
//! `serde_json` only the text of each number. With `arbitrary_precision`
//! an integer keeps its exact digits and a float stays a float.
//!
//! Duplicate member names keep the last value, as Go and Python do. Input
//! that is not UTF-8, unpaired surrogate escapes, and nesting deeper than 128
//! are rejected.

use serde_json::{Map, Number, Value};
use std::fmt;

const MAX_DEPTH: usize = 128;

/// Whether `value` nests arrays and objects deeper than the decoder accepts
/// (128 levels). The verifier entry points that take a caller-built
/// [`Value`] check this first: cloning, canonicalizing or normalizing a
/// `Value` recurses once per level, so unbounded nesting would overflow the
/// stack. The walk itself is iterative.
pub(crate) fn exceeds_max_depth(value: &Value) -> bool {
    let mut stack: Vec<(&Value, usize)> = vec![(value, 0)];
    while let Some((value, depth)) = stack.pop() {
        let children: Box<dyn Iterator<Item = &Value>> = match value {
            Value::Array(items) => Box::new(items.iter()),
            Value::Object(members) => Box::new(members.values()),
            _ => continue,
        };
        if depth + 1 > MAX_DEPTH {
            return true;
        }
        stack.extend(children.map(|child| (child, depth + 1)));
    }
    false
}

/// Why bytes are not a JSON value this crate accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    /// Byte offset of the problem.
    pub offset: usize,
    pub message: &'static str,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.message, self.offset)
    }
}

impl std::error::Error for DecodeError {}

/// Decodes one JSON value; only whitespace may follow it.
pub(crate) fn decode(data: &[u8]) -> Result<Value, DecodeError> {
    let text = std::str::from_utf8(data).map_err(|e| DecodeError {
        offset: e.valid_up_to(),
        message: "input is not UTF-8",
    })?;
    let mut parser = Parser {
        text,
        bytes: data,
        pos: 0,
    };
    parser.skip_ws();
    let value = parser.value(0)?;
    parser.skip_ws();
    if parser.pos != data.len() {
        return Err(parser.error("trailing data after the JSON value"));
    }
    Ok(value)
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn error(&self, message: &'static str) -> DecodeError {
        DecodeError {
            offset: self.pos,
            message,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, literal: &str) -> Result<(), DecodeError> {
        if self.text[self.pos..].starts_with(literal) {
            self.pos += literal.len();
            Ok(())
        } else {
            Err(self.error("invalid literal"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, DecodeError> {
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => self.expect("true").map(|()| Value::Bool(true)),
            Some(b'f') => self.expect("false").map(|()| Value::Bool(false)),
            Some(b'n') => self.expect("null").map(|()| Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.error("expected a JSON value")),
            None => Err(self.error("unexpected end of input")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, DecodeError> {
        if depth > MAX_DEPTH {
            return Err(self.error("nesting exceeds 128 levels"));
        }
        self.pos += 1;
        let mut map = Map::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.error("expected an object member name"));
            }
            let key = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(self.error("expected ':'"));
            }
            self.pos += 1;
            self.skip_ws();
            let value = self.value(depth)?;
            map.insert(key, value);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(map));
                }
                _ => return Err(self.error("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, DecodeError> {
        if depth > MAX_DEPTH {
            return Err(self.error("nesting exceeds 128 levels"));
        }
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.error("expected ',' or ']'")),
            }
        }
    }

    fn number(&mut self) -> Result<Value, DecodeError> {
        let start = self.pos;
        let digits = |p: &mut Self| {
            let from = p.pos;
            while matches!(p.peek(), Some(b'0'..=b'9')) {
                p.pos += 1;
            }
            p.pos > from
        };
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                digits(self);
            }
            _ => return Err(self.error("invalid number")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !digits(self) {
                return Err(self.error("invalid number"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !digits(self) {
                return Err(self.error("invalid number"));
            }
        }
        serde_json::from_str::<Number>(&self.text[start..self.pos])
            .map(Value::Number)
            .map_err(|_| DecodeError {
                offset: start,
                message: "invalid number",
            })
    }

    fn string(&mut self) -> Result<String, DecodeError> {
        self.pos += 1; // opening quote
        let mut out = String::new();
        loop {
            let run = self.bytes[self.pos..]
                .iter()
                .position(|b| *b == b'"' || *b == b'\\' || *b < 0x20)
                .ok_or_else(|| self.error("unterminated string"))?;
            out.push_str(&self.text[self.pos..self.pos + run]);
            self.pos += run;
            match self.bytes[self.pos] {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let escape = self
                        .peek()
                        .ok_or_else(|| self.error("unterminated string"))?;
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => return Err(self.error("invalid escape")),
                    }
                }
                _ => return Err(self.error("control character in string")),
            }
        }
    }

    /// The code point of a `\u` escape (just past the `u`), joining a
    /// surrogate pair.
    fn unicode_escape(&mut self) -> Result<char, DecodeError> {
        let high = self.hex4()?;
        let code = match high {
            0xd800..=0xdbff => {
                if !self.text[self.pos..].starts_with("\\u") {
                    return Err(self.error("unpaired surrogate escape"));
                }
                self.pos += 2;
                let low = self.hex4()?;
                if !(0xdc00..=0xdfff).contains(&low) {
                    return Err(self.error("unpaired surrogate escape"));
                }
                0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00)
            }
            0xdc00..=0xdfff => return Err(self.error("unpaired surrogate escape")),
            _ => high,
        };
        char::from_u32(code).ok_or_else(|| self.error("invalid unicode escape"))
    }

    fn hex4(&mut self) -> Result<u32, DecodeError> {
        let digits = self
            .text
            .get(self.pos..self.pos + 4)
            .filter(|d| d.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| self.error("invalid unicode escape"))?;
        self.pos += 4;
        u32::from_str_radix(digits, 16).map_err(|_| self.error("invalid unicode escape"))
    }
}

/// Test support for deeply nested values, built and taken apart without
/// recursion: `serde_json::Value`'s own `Drop` recurses once per level.
#[cfg(test)]
pub(crate) mod deep {
    use serde_json::{Map, Value};

    /// `depth` nested arrays around `null`.
    pub(crate) fn array(depth: usize) -> Value {
        let mut value = Value::Null;
        for _ in 0..depth {
            value = Value::Array(vec![value]);
        }
        value
    }

    /// `depth` nested objects `{"a": ...}` around `null`.
    pub(crate) fn object(depth: usize) -> Value {
        let mut value = Value::Null;
        for _ in 0..depth {
            let mut map = Map::new();
            map.insert("a".to_string(), value);
            value = Value::Object(map);
        }
        value
    }

    /// Drops `value` one level at a time.
    pub(crate) fn dismantle(value: Value) {
        let mut stack = vec![value];
        while let Some(value) = stack.pop() {
            match value {
                Value::Array(items) => stack.extend(items),
                Value::Object(members) => stack.extend(members.into_iter().map(|(_, v)| v)),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exceeds_max_depth_counts_levels_iteratively() {
        for (depth, too_deep) in [(0, false), (1, false), (128, false), (129, true)] {
            for value in [deep::array(depth), deep::object(depth)] {
                assert_eq!(exceeds_max_depth(&value), too_deep, "{depth}");
                deep::dismantle(value);
            }
        }
        // Far past any stack: the walk and the teardown stay iterative.
        let value = deep::array(1_000_000);
        assert!(exceeds_max_depth(&value));
        deep::dismantle(value);
        // Width is not depth.
        let wide = Value::Array(vec![Value::Array(vec![]); 100_000]);
        assert!(!exceeds_max_depth(&wide));
        // The decoder and the walk agree on the limit.
        let text = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(decode(text(128).as_bytes()).is_ok_and(|v| !exceeds_max_depth(&v)));
        assert!(decode(text(129).as_bytes()).is_err());
    }

    #[test]
    fn serde_json_number_token_stays_an_object() {
        let v = decode(br#"{"a":{"$serde_json::private::Number":"1"}}"#).expect("decodes");
        assert!(v["a"].is_object());
    }

    /// Integers keep their exact digits; `serde_json` may respell a float
    /// (`1E400` as `1e+400`) or `-0` as `0`, which changes neither the float
    /// classification nor the JCS output (`-0` serializes as `0`).
    #[test]
    fn integers_keep_their_digits_and_floats_stay_floats() {
        use crate::canonical::{is_float, is_unsafe_int};
        let v = decode(b"[9007199254740993,-9007199254740991,0,-0,1.0,1E400,0.5e-3,1e2]")
            .expect("decodes");
        let numbers: Vec<&Number> = v
            .as_array()
            .expect("array")
            .iter()
            .map(|n| match n {
                Value::Number(n) => n,
                _ => panic!("not a number"),
            })
            .collect();
        let texts: Vec<String> = numbers[..3].iter().map(|n| n.to_string()).collect();
        assert_eq!(texts, ["9007199254740993", "-9007199254740991", "0"]);
        assert!(is_unsafe_int(numbers[0]) && !is_unsafe_int(numbers[1]));
        assert!(!is_float(numbers[3]));
        assert!(numbers[4..].iter().all(|n| is_float(n)));
    }

    #[test]
    fn strings_and_escapes() {
        let v = decode(br#""a\"\\\/\b\f\n\r\t\u00e9\ud83d\ude00""#).expect("decodes");
        assert_eq!(
            v,
            Value::String("a\"\\/\u{8}\u{c}\n\r\t\u{e9}\u{1f600}".into())
        );
    }

    #[test]
    fn duplicate_names_keep_the_last_value() {
        let v = decode(br#"{"a":1,"a":2}"#).expect("decodes");
        assert_eq!(v["a"].to_string(), "2");
    }

    #[test]
    fn rejects_what_rfc_8259_rejects() {
        for bad in [
            &b""[..],
            b"01",
            b"1.",
            b"-",
            b"1e",
            b".5",
            b"+1",
            b"NaN",
            b"[1,]",
            b"{\"a\":1,}",
            b"{a:1}",
            b"\"\x01\"",
            b"\"\\x\"",
            b"\"\\ud800\"",
            b"\"\\udc00\"",
            b"\"\\ud800\\u0041\"",
            b"\xef\xbb\xbf{}",
            b"\"\xff\"",
            b"{} {}",
            b"tru",
        ] {
            assert!(decode(bad).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
        assert!(decode(" \t\n{\"a\":[true,false,null]} \r\n".as_bytes()).is_ok());
    }

    #[test]
    fn nesting_limit() {
        let ok = format!("{}{}", "[".repeat(128), "]".repeat(128));
        assert!(decode(ok.as_bytes()).is_ok());
        let deep = format!("{}{}", "[".repeat(129), "]".repeat(129));
        assert!(decode(deep.as_bytes()).is_err());
    }
}
