//! A strict RFC 8259 JSON decoder for the interop profile's data model
//! (§5.2), into [`serde_json::Value`].
//!
//! It builds every value itself rather than through serde_json's decoder,
//! whose behavior changes with features another crate in the same build may
//! turn on: with `arbitrary_precision`, serde_json turns the object
//! `{"$serde_json::private::Number": "1"}` into the number `1`, and `-0`
//! reaches a visitor as the integer `0`. (agent-action-capsule's `json`
//! module avoids the same collision the same way.)
//!
//! Refused, at any depth: a duplicate member name, a number other than an
//! integer from 0 to 2^53 − 1 written as digits alone (no sign, fraction or
//! exponent), an unpaired surrogate escape, an unescaped control character,
//! nesting deeper than 128, input that is not UTF-8, and anything after the
//! value but whitespace. The profile's Python verifier refuses the same,
//! except that it bounds nesting only by its recursion limit.
//!
//! [`decode_json_numbers`] is the same decoder with every RFC 8259 number
//! accepted, as Go's `evidencerequest.DecodeJSON` reads one. A controller
//! binding needs it: a `bip340` signature whose `created_at` is `-1` is a
//! well-formed record whose signature fails (CB §4.1), not a record that
//! cannot be read. An integer that fits `i64` or `u64` is kept exactly; any
//! other number is kept as an `f64`, which has no RFC 8785 form in this
//! crate (`jcs`). A number beyond f64's range, such as `1e400`, is kept as
//! `±f64::MAX`, so it too is a non-integer and the document stays readable,
//! as it is to Go and Python.

use serde_json::{Map, Number, Value};

const MAX_DEPTH: usize = 128;
const MAX_INTEGER: u64 = (1 << 53) - 1;

/// Which numbers the decoder accepts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Numbers {
    /// Digits alone, 0 to 2^53 − 1 (the profile's integers, §5.2).
    Profile,
    /// Any RFC 8259 number.
    Json,
}

/// The value the octets hold, or `None` when they are refused.
#[cfg_attr(not(feature = "acceptance"), allow(dead_code))]
pub(crate) fn decode(octets: &[u8]) -> Option<Value> {
    decode_with(octets, Numbers::Profile)
}

/// [`decode`], with any RFC 8259 number accepted.
#[cfg_attr(not(feature = "controller-binding"), allow(dead_code))]
pub(crate) fn decode_json_numbers(octets: &[u8]) -> Option<Value> {
    decode_with(octets, Numbers::Json)
}

fn decode_with(octets: &[u8], numbers: Numbers) -> Option<Value> {
    let text = std::str::from_utf8(octets).ok()?;
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
        numbers,
    };
    p.ws();
    let value = p.value(0)?;
    p.ws();
    (p.i == p.s.len()).then_some(value)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    numbers: Numbers,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, b: u8) -> Option<()> {
        (self.peek() == Some(b)).then(|| self.i += 1)
    }

    fn literal(&mut self, word: &[u8], value: Value) -> Option<Value> {
        self.s[self.i..].starts_with(word).then(|| {
            self.i += word.len();
            value
        })
    }

    fn value(&mut self, depth: usize) -> Option<Value> {
        match self.peek()? {
            b'{' => self.object(depth + 1),
            b'[' => self.array(depth + 1),
            b'"' => self.string().map(Value::String),
            b't' => self.literal(b"true", Value::Bool(true)),
            b'f' => self.literal(b"false", Value::Bool(false)),
            b'n' => self.literal(b"null", Value::Null),
            b'0'..=b'9' | b'-' if self.numbers == Numbers::Json => self.json_number(),
            b'0'..=b'9' => self.integer(),
            // A sign, a leading `.` or anything else is not a profile integer.
            _ => None,
        }
    }

    fn object(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.eat(b'{')?;
        let mut out = Map::new();
        self.ws();
        if self.eat(b'}').is_some() {
            return Some(Value::Object(out));
        }
        loop {
            self.ws();
            let key = self.string()?;
            self.ws();
            self.eat(b':')?;
            self.ws();
            let value = self.value(depth)?;
            if out.insert(key, value).is_some() {
                return None;
            }
            self.ws();
            if self.eat(b',').is_some() {
                continue;
            }
            self.eat(b'}')?;
            return Some(Value::Object(out));
        }
    }

    fn array(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.eat(b'[')?;
        let mut out = Vec::new();
        self.ws();
        if self.eat(b']').is_some() {
            return Some(Value::Array(out));
        }
        loop {
            self.ws();
            out.push(self.value(depth)?);
            self.ws();
            if self.eat(b',').is_some() {
                continue;
            }
            self.eat(b']')?;
            return Some(Value::Array(out));
        }
    }

    /// Digits alone, no leading zero but `0` itself, then no fraction or
    /// exponent, at most 2^53 − 1.
    fn integer(&mut self) -> Option<Value> {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        let digits = &self.s[start..self.i];
        if (digits.len() > 1 && digits[0] == b'0')
            || matches!(self.peek(), Some(b'.' | b'e' | b'E'))
            || digits.len() > 16
        {
            return None;
        }
        let n: u64 = std::str::from_utf8(digits).ok()?.parse().ok()?;
        (n <= MAX_INTEGER).then(|| Value::from(n))
    }

    /// An RFC 8259 number: `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`.
    fn json_number(&mut self) -> Option<Value> {
        let start = self.i;
        self.eat(b'-');
        let int_start = self.i;
        let digits = |p: &mut Self| {
            let from = p.i;
            while matches!(p.peek(), Some(b'0'..=b'9')) {
                p.i += 1;
            }
            p.i - from
        };
        let int_digits = digits(self);
        if int_digits == 0 || (int_digits > 1 && self.s[int_start] == b'0') {
            return None;
        }
        let mut integer = true;
        if self.eat(b'.').is_some() {
            integer = false;
            if digits(self) == 0 {
                return None;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            integer = false;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if digits(self) == 0 {
                return None;
            }
        }
        let text = std::str::from_utf8(&self.s[start..self.i]).ok()?;
        if integer {
            if let Ok(n) = text.parse::<i64>() {
                return Some(Value::from(n));
            }
            if let Ok(n) = text.parse::<u64>() {
                return Some(Value::from(n));
            }
        }
        // A token beyond f64's range (`1e400`) is still a number, as Go's
        // UseNumber and Python read it. It parses to an infinity, which
        // serde_json cannot hold, so it is kept as the largest finite f64 of
        // the same sign: still not an integer, and still with no RFC 8785
        // form here.
        let n: f64 = text.parse().ok()?;
        let n = if n.is_finite() {
            n
        } else {
            f64::MAX.copysign(n)
        };
        Number::from_f64(n).map(Value::Number)
    }

    fn string(&mut self) -> Option<String> {
        self.eat(b'"')?;
        let mut out = String::new();
        loop {
            let start = self.i;
            while !matches!(self.peek()?, b'"' | b'\\' | 0x00..=0x1f) {
                self.i += 1;
            }
            // The input is UTF-8 and the run stops only at ASCII bytes, so
            // the run is whole characters.
            out.push_str(std::str::from_utf8(&self.s[start..self.i]).ok()?);
            match self.peek()? {
                b'"' => {
                    self.i += 1;
                    return Some(out);
                }
                b'\\' => {
                    self.i += 1;
                    let escaped = self.peek()?;
                    self.i += 1;
                    out.push(match escaped {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => self.unicode_escape()?,
                        _ => return None,
                    });
                }
                _ => return None, // an unescaped control character
            }
        }
    }

    /// After `\u`: one code point, a surrogate pair as one, an unpaired
    /// surrogate refused.
    fn unicode_escape(&mut self) -> Option<char> {
        let first = self.hex4()?;
        match first {
            0xd800..=0xdbff => {
                self.eat(b'\\')?;
                self.eat(b'u')?;
                let second = self.hex4()?;
                if !(0xdc00..=0xdfff).contains(&second) {
                    return None;
                }
                char::from_u32(0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00))
            }
            0xdc00..=0xdfff => None,
            _ => char::from_u32(first),
        }
    }

    fn hex4(&mut self) -> Option<u32> {
        let digits = self.s.get(self.i..self.i + 4)?;
        let text = std::str::from_utf8(digits).ok()?;
        if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        self.i += 4;
        u32::from_str_radix(text, 16).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::decode;
    use serde_json::json;

    #[test]
    fn reads_the_data_model() {
        assert_eq!(
            decode(br#" {"a":[1,true,false,null,"x\u00e9\ud83d\ude00\n"],"b":{}} "#),
            Some(json!({"a": [1, true, false, null, "xé😀\n"], "b": {}}))
        );
        assert_eq!(
            decode(b"9007199254740991"),
            Some(json!(9007199254740991u64))
        );
        assert_eq!(decode(b"0"), Some(json!(0)));
    }

    #[test]
    fn a_serde_json_number_token_is_an_ordinary_member() {
        assert_eq!(
            decode(br#"{"$serde_json::private::Number":"5"}"#),
            Some(json!({"$serde_json::private::Number": "5"}))
        );
    }

    #[test]
    fn refuses_what_the_profile_refuses() {
        for text in [
            r#"{"a":1,"a":1}"#,
            r#"{"a":{"b":1,"b":2}}"#,
            "-0",
            "-1",
            "1.0",
            "1e3",
            "01",
            "9007199254740992",
            "12345678901234567",
            r#""\ud800""#,
            r#""\udc00x""#,
            "\"a\u{1}\"",
            r#""\x""#,
            "[1,]",
            "{\"a\":1,}",
            "1 2",
            "\u{feff}1",
            "NaN",
            "",
        ] {
            assert_eq!(decode(text.as_bytes()), None, "{text:?}");
        }
        assert_eq!(decode(&[0x22, 0xff, 0x22]), None, "not UTF-8");
    }

    #[test]
    fn json_numbers_reads_every_rfc_8259_number_and_refuses_other_tokens() {
        use super::decode_json_numbers;
        assert_eq!(decode_json_numbers(b"-1"), Some(json!(-1)));
        assert_eq!(
            decode_json_numbers(b"[0,-0,18446744073709551615]"),
            Some(json!([0, 0, 18446744073709551615u64]))
        );
        for text in [
            "1.5",
            "-2e3",
            "1E+2",
            "18446744073709551616",
            "1e400",
            "-1e400",
            "1e-400",
        ] {
            let value = decode_json_numbers(text.as_bytes()).expect(text);
            assert!(
                value.is_number() && value.as_i64().is_none() && value.as_u64().is_none(),
                "{text}"
            );
        }
        // Beyond f64's range: the largest finite f64 of the same sign.
        assert_eq!(
            decode_json_numbers(b"[1e400,-1e400]"),
            Some(json!([f64::MAX, -f64::MAX]))
        );
        for text in ["01", "-", "1.", ".5", "1e", "+1", "--1", r#"{"a":1,"a":2}"#] {
            assert_eq!(decode_json_numbers(text.as_bytes()), None, "{text:?}");
        }
    }

    #[test]
    fn nests_to_128_and_no_deeper() {
        let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(decode(deep(128).as_bytes()).is_some());
        assert!(decode(deep(129).as_bytes()).is_none());
    }
}
