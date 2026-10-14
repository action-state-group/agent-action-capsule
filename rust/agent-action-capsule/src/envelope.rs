//! Producer Envelope verification: a COSE_Sign1 over the raw 32-byte Capsule
//! ID (the draft's Producer Envelope profile). Port of `go/envelope`.
//!
//! The profile is exact: tag 18, a protected header holding only `alg` = EdDSA
//! (-8), content type `application/agent-action-capsule-id` and a raw 32-byte
//! Ed25519 public key as `kid`, an empty unprotected map, the attached
//! Capsule ID as payload, and a 64-byte signature. The CBOR reader below
//! applies the profile's encoding rules: definite lengths, the shortest form
//! of every argument and float, unique map keys, no trailing bytes, and no tag
//! but the outer tag 18. It takes every item at its face value: an untagged
//! map or byte string where the profile names one, so a null, undefined or
//! tagged header or payload is malformed. It also bounds nesting and
//! container sizes, which a conforming envelope never approaches; the finding
//! code for input past those bounds is implementation-defined. Authorizing
//! the key for an operator or developer is a separate policy, outside this
//! module.

use crate::verify::is_hex64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Media type of the envelope's raw 32-byte payload.
pub const CONTENT_TYPE: &str = "application/agent-action-capsule-id";
/// COSE algorithm code point for EdDSA.
pub const COSE_ALGORITHM_EDDSA: i64 = -8;
const MAX_ENVELOPE_BYTES: usize = 4096;
// Decoder bounds, matching go/envelope's CBOR decode options.
const MAX_NESTED_LEVELS: usize = 8;
const MAX_ARRAY_ELEMENTS: u64 = 16;
const MAX_MAP_PAIRS: u64 = 16;

/// One producer-envelope verification failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub code: String,
    pub detail: String,
}

/// The never-panicking result of [`verify`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerificationResult {
    pub ok: bool,
    pub findings: Vec<Finding>,
    pub capsule_id: String,
    /// The authenticated raw Ed25519 public key; empty unless `ok`.
    pub public_key: Vec<u8>,
}

/// Authenticates one producer envelope against a carried lowercase-hex Capsule
/// ID, verifying the Ed25519 signature under the key carried in the protected
/// `kid` header.
pub fn verify(capsule_id: &str, data: &[u8]) -> VerificationResult {
    let result = VerificationResult {
        capsule_id: capsule_id.to_string(),
        ..Default::default()
    };
    let fail = |code: &str, detail: String| VerificationResult {
        findings: vec![Finding {
            code: code.to_string(),
            detail,
        }],
        ..result.clone()
    };
    if !is_hex64(capsule_id) {
        return fail(
            "capsule_id_malformed",
            "capsule_id MUST be 64 lowercase hexadecimal characters".into(),
        );
    }
    let expected_payload = match hex::decode(capsule_id) {
        Ok(bytes) => bytes,
        Err(e) => return fail("capsule_id_malformed", e.to_string()),
    };
    if data.len() > MAX_ENVELOPE_BYTES {
        return fail(
            "envelope_too_large",
            format!(
                "producer envelope is {} bytes; maximum is {MAX_ENVELOPE_BYTES}",
                data.len()
            ),
        );
    }
    let envelope = match decode_envelope(data) {
        Ok(envelope) => envelope,
        Err(detail) => return fail("envelope_malformed", detail),
    };
    let header = |label: i64| {
        envelope
            .protected
            .iter()
            .find(|(key, _)| *key == i128::from(label))
            .map(|(_, value)| value)
    };

    if !matches!(header(1), Some(Item::Int(alg)) if *alg == i128::from(COSE_ALGORITHM_EDDSA)) {
        return fail(
            "envelope_algorithm_mismatch",
            "protected alg (label 1) MUST be EdDSA (-8)".into(),
        );
    }
    if !matches!(header(3), Some(Item::Text(ct)) if ct == CONTENT_TYPE) {
        return fail(
            "envelope_content_type_mismatch",
            format!("protected content type (label 3) MUST be {CONTENT_TYPE:?}"),
        );
    }
    let public_key: [u8; 32] = match header(4) {
        Some(Item::Bytes(kid)) => match kid.as_slice().try_into() {
            Ok(key) => key,
            Err(_) => return fail("envelope_kid_invalid", KID_DETAIL.into()),
        },
        _ => return fail("envelope_kid_invalid", KID_DETAIL.into()),
    };
    if envelope.protected.len() != 3 {
        return fail(
            "envelope_protected_headers_invalid",
            "protected header MUST contain exactly alg, content type, and kid".into(),
        );
    }
    if envelope.payload != expected_payload {
        return fail(
            "envelope_payload_mismatch",
            "attached payload MUST equal the raw 32-byte Capsule ID".into(),
        );
    }
    let signature: [u8; 64] = match envelope.signature.as_slice().try_into() {
        Ok(signature) => signature,
        Err(_) => {
            return fail(
                "envelope_signature_invalid",
                "Ed25519 signature MUST be 64 bytes".into(),
            )
        }
    };

    let to_be_signed = sig_structure(&envelope.protected_raw, &envelope.payload);
    let verified = VerifyingKey::from_bytes(&public_key)
        .map(|key| {
            // RFC 8032 cofactorless verification, as Go's ed25519.Verify.
            key.verify(&to_be_signed, &Signature::from_bytes(&signature))
                .is_ok()
        })
        .unwrap_or(false);
    if !verified {
        return fail(
            "envelope_signature_invalid",
            "Ed25519 signature verification failed".into(),
        );
    }
    VerificationResult {
        ok: true,
        public_key: public_key.to_vec(),
        ..result
    }
}

const KID_DETAIL: &str = "protected kid (label 4) MUST be the raw 32-byte Ed25519 public key";

/// The RFC 9052 `Sig_structure` for COSE_Sign1 with empty external AAD, in
/// deterministic encoding.
fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x84];
    push_head(&mut out, 3, b"Signature1".len() as u64);
    out.extend_from_slice(b"Signature1");
    push_head(&mut out, 2, protected.len() as u64);
    out.extend_from_slice(protected);
    out.push(0x40);
    push_head(&mut out, 2, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

fn push_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

struct Envelope {
    protected_raw: Vec<u8>,
    protected: Vec<(i128, Item)>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

fn decode_envelope(data: &[u8]) -> Result<Envelope, String> {
    let top = decode_all(data).map_err(|e| format!("decoding COSE_Sign1: {e}"))?;
    let Item::Tag(18, content) = top else {
        return Err("top-level CBOR tag MUST be COSE_Sign1 tag 18".into());
    };
    let Item::Array(items) = *content else {
        return Err("decoding COSE_Sign1 array: not an array".into());
    };
    let [protected, unprotected, payload, signature]: [Item; 4] = items
        .try_into()
        .map_err(|_| "COSE_Sign1 MUST contain four array elements".to_string())?;
    let protected_raw = match protected {
        Item::Bytes(b) if !b.is_empty() => b,
        _ => return Err("protected header MUST be a non-empty byte string".into()),
    };
    let protected = match decode_all(&protected_raw) {
        Ok(Item::Map(pairs)) => pairs
            .into_iter()
            .map(|(key, value)| match key {
                Item::Int(label) => Ok((label, value)),
                _ => Err("decoding protected header: labels MUST be integers".to_string()),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Ok(_) => return Err("decoding protected header: not a map".into()),
        Err(e) => return Err(format!("decoding protected header: {e}")),
    };
    match unprotected {
        Item::Map(pairs) if pairs.is_empty() => {}
        Item::Map(_) => return Err("unprotected header MUST be an empty map".into()),
        _ => return Err("decoding unprotected header: not a map".into()),
    }
    let Item::Bytes(payload) = payload else {
        return Err("attached payload MUST be a byte string".into());
    };
    let Item::Bytes(signature) = signature else {
        return Err("signature MUST be a byte string".into());
    };
    Ok(Envelope {
        protected_raw,
        protected,
        payload,
        signature,
    })
}

/// The CBOR data items this profile distinguishes. Floats and simple values
/// are only ever wrong here, so they collapse into `Other`, which keeps the
/// encoded bytes for map-key equality.
#[derive(Debug, PartialEq)]
enum Item {
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Item>),
    Map(Vec<(Item, Item)>),
    Tag(u64, Box<Item>),
    Other(Vec<u8>),
}

fn decode_all(data: &[u8]) -> Result<Item, String> {
    let mut reader = Reader { data, offset: 0 };
    let item = reader.item(0)?;
    if reader.offset != data.len() {
        return Err("trailing CBOR data".into());
    }
    Ok(item)
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: u64) -> Result<&[u8], String> {
        let n = usize::try_from(n).map_err(|_| "CBOR length overflow".to_string())?;
        let end = self
            .offset
            .checked_add(n)
            .filter(|end| *end <= self.data.len())
            .ok_or("truncated CBOR")?;
        let bytes = &self.data[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    /// Reads one initial byte and its argument, rejecting any argument not in
    /// its shortest form. For major type 7 it validates the simple value or
    /// float and returns a zero argument.
    fn head(&mut self) -> Result<(u8, u64), String> {
        let first = self.take(1)?[0];
        let (major, info) = (first >> 5, first & 31);
        let width = match info {
            0..=23 => return Ok((major, u64::from(info))),
            24..=27 => 1usize << (info - 24),
            31 => return Err("indefinite-length CBOR is not allowed".into()),
            _ => return Err("reserved CBOR additional information".into()),
        };
        let arg = self
            .take(width as u64)?
            .iter()
            .fold(0u64, |arg, byte| arg << 8 | u64::from(*byte));
        if major == 7 {
            let shortest = match info {
                24 if arg < 32 => {
                    return Err("CBOR simple value below 32 in the two-byte form".into())
                }
                26 => {
                    let value = f64::from(f32::from_bits(arg as u32));
                    !value.is_nan() && !fits_half(value)
                }
                27 => {
                    let value = f64::from_bits(arg);
                    !value.is_nan() && f64::from(value as f32) != value
                }
                _ => true,
            };
            if !shortest {
                return Err("CBOR float is not in its shortest form".into());
            }
            return Ok((major, 0));
        }
        if arg < [24, 1 << 8, 1 << 16, 1 << 32][usize::from(info - 24)] {
            return Err("CBOR argument is not in its shortest form".into());
        }
        Ok((major, arg))
    }

    fn item(&mut self, depth: usize) -> Result<Item, String> {
        if depth > MAX_NESTED_LEVELS {
            return Err("CBOR nesting exceeds the limit".into());
        }
        let start = self.offset;
        let (major, arg) = self.head()?;
        Ok(match major {
            0 => Item::Int(i128::from(arg)),
            1 => Item::Int(-1 - i128::from(arg)),
            2 => Item::Bytes(self.take(arg)?.to_vec()),
            3 => Item::Text(
                String::from_utf8(self.take(arg)?.to_vec())
                    .map_err(|_| "CBOR text is not UTF-8".to_string())?,
            ),
            4 => {
                if arg > MAX_ARRAY_ELEMENTS {
                    return Err("CBOR array exceeds the element limit".into());
                }
                let mut items = Vec::new();
                for _ in 0..arg {
                    items.push(self.item(depth + 1)?);
                }
                Item::Array(items)
            }
            5 => {
                if arg > MAX_MAP_PAIRS {
                    return Err("CBOR map exceeds the pair limit".into());
                }
                let mut pairs: Vec<(Item, Item)> = Vec::new();
                for _ in 0..arg {
                    let key = self.item(depth + 1)?;
                    if pairs.iter().any(|(k, _)| *k == key) {
                        return Err("duplicate CBOR map key".into());
                    }
                    let value = self.item(depth + 1)?;
                    pairs.push((key, value));
                }
                Item::Map(pairs)
            }
            6 if depth > 0 => return Err("only the outer COSE_Sign1 may carry a CBOR tag".into()),
            6 => Item::Tag(arg, Box::new(self.item(depth + 1)?)),
            // Simple values and floats: `head` already consumed their bytes.
            _ => Item::Other(self.data[start..self.offset].to_vec()),
        })
    }
}

/// Whether `value` is exactly representable as an IEEE 754 half-precision
/// float, so that a wider encoding of it is not the shortest.
fn fits_half(value: f64) -> bool {
    let magnitude = value.abs();
    if value.is_infinite() || magnitude == 0.0 {
        return true;
    }
    if magnitude > 65504.0 {
        return false;
    }
    // Normal halves (at least 2^-14) carry 11 significant bits; subnormals are
    // multiples of 2^-24. Every f32 is a normal f64, so its exponent field is
    // exact.
    let exponent = ((magnitude.to_bits() >> 52) & 0x7ff) as i32 - 1023;
    let scaled = if exponent >= -14 {
        magnitude * 2f64.powi(10 - exponent)
    } else {
        magnitude * 2f64.powi(24)
    };
    scaled == scaled.trunc()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_indefinite_length_and_trailing_data() {
        assert!(decode_all(&[0x9f, 0xff]).is_err());
        assert!(decode_all(&[0x01, 0x02]).is_err());
        assert!(decode_all(&[0xa2, 0x01, 0x01, 0x01, 0x02]).is_err());
    }

    #[test]
    fn fits_half_matches_ieee_half_precision() {
        let p = |e: i32| 2f64.powi(e);
        for (value, want) in [
            (0.0, true),
            (-0.0, true),
            (f64::INFINITY, true),
            (-8.0, true),
            (65504.0, true),
            (65520.0, false),
            (1.0 + p(-10), true),
            (1.0 + p(-11), false),
            (p(-14), true),
            (p(-14) + p(-24), true),
            (p(-24), true),
            (p(-25), false),
            (3.0 * p(-25), false),
            (f64::from(1.1f32), false),
            (-f64::from(f32::MAX), false),
            (f64::from(f32::from_bits(1)), false),
        ] {
            assert_eq!(fits_half(value), want, "{value:e}");
        }
    }

    #[test]
    fn rejects_non_shortest_heads_and_nested_tags() {
        for encoded in [
            &[0x18, 0x17][..],
            &[0x19, 0x00, 0xff],
            &[0x5a, 0, 0, 0xff, 0xff],
            &[0xfa, 0x3f, 0x80, 0, 0],
            &[0xf8, 0x10],
            &[0x81, 0xc6, 0x00],
        ] {
            assert!(decode_all(encoded).is_err(), "{encoded:02x?}");
        }
        for encoded in [
            &[0x18, 0x18][..],
            &[0xf9, 0x3c, 0x00],
            &[0xfa, 0x3f, 0x8c, 0xcc, 0xcd],
            &[0xc6, 0x00],
        ] {
            assert!(decode_all(encoded).is_ok(), "{encoded:02x?}");
        }
    }

    #[test]
    fn rejects_bad_inputs_without_panicking() {
        let id = "00".repeat(32);
        assert_eq!(verify("ABC", &[]).findings[0].code, "capsule_id_malformed");
        assert_eq!(verify(&id, &[0xd2]).findings[0].code, "envelope_malformed");
        assert_eq!(
            verify(&id, &vec![0; 5000]).findings[0].code,
            "envelope_too_large"
        );
        let mut deep = vec![0x81; 20];
        deep.push(0x00);
        assert_eq!(verify(&id, &deep).findings[0].code, "envelope_malformed");
    }
}
