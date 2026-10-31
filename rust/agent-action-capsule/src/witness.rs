//! Offline checks of the witness receipts an Evidence Bundle's checkpoint
//! carries (feature `strict`). Port of the Python reference's
//! `agent_action_capsule.witness`, checked against `vectors/bundle/strict/`.
//!
//! A witness is a transparency service that took a log's signed checkpoint
//! and returned a receipt a verifier can check offline.
//! `checkpoint.witnesses` in an Evidence Bundle lists them as CLL
//! `WitnessRecord` objects (`ts_url`, `entry_hash`, `receipt_b64`,
//! `leaf_index`, `tree_size`, optional `is_stub`). The Bundle draft defines
//! no witness member, so this check is an opt-in verifier extension
//! ([`crate::bundle::verify_bundle_strict`]): only a receipt that fails
//! changes the verdict.
//!
//! No witness is trusted by default. The caller supplies a witness directory
//! (a parsed `witnesses.json`: `{"witnesses": [row, ...]}`, or the row list),
//! and every row is read the same way. A receipt whose witness has no row, or
//! whose row has no usable key, is not checked (`withheld`), never failed.
//!
//! Three bindings, named by the `ts_url` scheme:
//!
//! * `https://host` (`cll`): a COSE Receipt (RFC 9162 inclusion) whose leaf
//!   is `entry_hash`, which must equal SHA-256 of the checkpoint digest.
//! * `rekor+https://host` (`rekor`): a Sigstore Rekor `dsse` entry. Its
//!   Signed Entry Timestamp verifies under the row's ECDSA P-256 key, its
//!   `logID` is that key's RFC 6962 log ID, its `payloadHash` is SHA-256 of
//!   the checkpoint's COSE statement, and its only verifier is the
//!   checkpoint's own key.
//! * `scrapi+https://host` (`scrapi`): a SCITT COSE Receipt (RFC 9162) whose
//!   leaf is SHA-256 of the checkpoint's COSE statement.
//!
//! Every base64 field read here is canonical standard base64 with padding:
//! the decoded bytes must re-encode to the same text.
//! Nothing here panics on malformed input.

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;
use p256::ecdsa::signature::Verifier as _;
use p256::pkcs8::{DecodePublicKey, EncodePublicKey, ObjectIdentifier, SubjectPublicKeyInfoRef};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};

use crate::ed25519_strict::strict_ed25519;

/// The binding of a plain `https://` witness URL: a CLL witness.
pub const BINDING_CLL: &str = "cll";
/// The binding of a `rekor+` witness URL: a Sigstore Rekor log.
pub const BINDING_REKOR: &str = "rekor";
/// The binding of a `scrapi+` witness URL: a SCITT transparency service.
pub const BINDING_SCRAPI: &str = "scrapi";

/// Receipt grade: existence and time only.
pub const GRADE_OBSERVED_ONLY: &str = "observed-only";
/// Receipt grade: MMR consistency checked.
pub const GRADE_MMR_VERIFIED: &str = "mmr-verified";

/// Registration-time reason: the receipt did not pass.
pub const REASON_RECEIPT_NOT_PASSED: &str = "receipt_not_passed";
/// Registration-time reason: the receipt's protected CWT claims carry no `iat`.
pub const REASON_IAT_ABSENT: &str = "iat_absent";
/// Registration-time reason: the protected CWT claims are not a map, or `iat`
/// is not an integer from 0 to 2^53 - 1.
pub const REASON_IAT_INVALID: &str = "iat_invalid";
/// Registration-time reason: the binding (`rekor`) is no COSE Receipt.
pub const REASON_BINDING_WITHOUT_IAT: &str = "binding_without_iat";
const CWT_CLAIMS_LABEL: i64 = 15;
const CWT_IAT: u64 = 6;
const MAX_IAT: u64 = (1 << 53) - 1;

/// Strict standard base64 in its one canonical spelling: padding required,
/// and non-zero trailing bits refused, so the bytes re-encode to the text.
const STANDARD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

const RECORD_FIELDS: [&str; 5] = [
    "ts_url",
    "entry_hash",
    "receipt_b64",
    "leaf_index",
    "tree_size",
];

/// The DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410), before the
/// 32-byte raw key.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// The fields a signed CLL COSE checkpoint states, as its signature covers
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCheckpoint {
    pub log_id: String,
    pub mmr_size: u64,
    pub root: String,
    pub key_id: String,
    pub timestamp: String,
    pub prev_size: u64,
    pub prev_root: String,
}

impl From<&cll::checkpoint::DecodedCheckpointCose> for SignedCheckpoint {
    fn from(decoded: &cll::checkpoint::DecodedCheckpointCose) -> Self {
        SignedCheckpoint {
            log_id: decoded.log_id.clone(),
            mmr_size: decoded.mmr_size,
            root: decoded.root.clone(),
            key_id: decoded.key_id.clone(),
            timestamp: decoded.timestamp.clone(),
            prev_size: decoded.prev_size,
            prev_root: decoded.prev_root.clone(),
        }
    }
}

/// One receipt's outcome: `status` is `pass`, `withheld` or `fail`.
///
/// `reason` is a human-readable explanation and is not part of the
/// cross-language contract; `grade` is the verified receipt grade, or `None`.
/// `key_id` is the directory key id a passing receipt verified under.
/// `registration_time` is the `iat` the witness signed into a passing COSE
/// Receipt's protected header, in seconds since the epoch; when it is `None`,
/// `registration_time_reason` (one of the `REASON_` constants) says why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessReceiptResult {
    pub ts_url: String,
    pub binding: String,
    pub status: String,
    pub reason: String,
    pub grade: Option<String>,
    pub key_id: Option<String>,
    pub registration_time: Option<u64>,
    pub registration_time_reason: Option<String>,
}

/// What [`verify_witness_receipts`] found: the overall `status`, the
/// findings, and one result per well-formed receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessReport {
    pub status: String,
    pub findings: Vec<String>,
    pub receipts: Vec<WitnessReceiptResult>,
}

/// One receipt check: whether it verified, why, the verified grade, and its
/// registration time or the reason it has none. A `reason` starting with
/// `not checked` means nothing was checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptCheck {
    pub ok: bool,
    pub reason: String,
    pub grade: Option<String>,
    pub registration_time: Option<u64>,
    pub registration_time_reason: Option<String>,
}

impl ReceiptCheck {
    fn fail(reason: impl Into<String>) -> Self {
        ReceiptCheck {
            ok: false,
            reason: reason.into(),
            grade: None,
            registration_time: None,
            registration_time_reason: Some(REASON_RECEIPT_NOT_PASSED.to_string()),
        }
    }

    /// A receipt that verified, with the registration time of its protected
    /// header.
    fn verified(reason: &str, grade: Option<String>, receipt: &[u8]) -> Self {
        let (registration_time, registration_time_reason) = match registration_time(receipt) {
            Ok(time) => (Some(time), None),
            Err(reason) => (None, Some(reason.to_string())),
        };
        ReceiptCheck {
            ok: true,
            reason: reason.to_string(),
            grade,
            registration_time,
            registration_time_reason,
        }
    }
}

/// The `iat` (claim 6) of a verified COSE Receipt's protected CWT claims
/// (label 15), or why there is none: absent with no claims map or no `iat`
/// in it, invalid when the claims are not a map or `iat` is not an integer
/// from 0 to 2^53 - 1. Only the protected header is signed.
fn registration_time(receipt: &[u8]) -> Result<u64, &'static str> {
    let headers = decode_receipt(receipt)
        .map_err(|_| REASON_IAT_INVALID)?
        .headers;
    let claims = match headers.get(i128::from(CWT_CLAIMS_LABEL)) {
        None => return Err(REASON_IAT_ABSENT),
        Some(claims @ ReceiptItem::Map(_)) => claims,
        Some(_) => return Err(REASON_IAT_INVALID),
    };
    match claims.get(i128::from(CWT_IAT)) {
        None => Err(REASON_IAT_ABSENT),
        Some(ReceiptItem::Int(seconds)) => u64::try_from(*seconds)
            .ok()
            .filter(|seconds| *seconds <= MAX_IAT)
            .ok_or(REASON_IAT_INVALID),
        Some(_) => Err(REASON_IAT_INVALID),
    }
}

/// The binding a witness URL names: `rekor+...` is `rekor`, `scrapi+...` is
/// `scrapi`, anything else is `cll`.
pub fn binding_of(url: &str) -> &'static str {
    let scheme = match url.split_once("://") {
        Some((scheme, _)) => scheme.to_lowercase(),
        None => String::new(),
    };
    if scheme.starts_with("rekor+") {
        BINDING_REKOR
    } else if scheme.starts_with("scrapi+") {
        BINDING_SCRAPI
    } else {
        BINDING_CLL
    }
}

/// The base URL with any binding prefix removed and no trailing slash.
pub fn endpoint_of(url: &str) -> String {
    let url = if binding_of(url) != BINDING_CLL {
        url.split_once('+').map_or(url, |(_, rest)| rest)
    } else {
        url
    };
    url.trim_end_matches('/').to_string()
}

fn rows(directory: Option<&Value>) -> &[Value] {
    match directory {
        Some(Value::Object(map)) => match map.get("witnesses") {
            Some(Value::Array(rows)) => rows,
            _ => &[],
        },
        Some(Value::Array(rows)) => rows,
        _ => &[],
    }
}

/// The directory row a receipt's witness URL belongs to: the same binding (a
/// row without `binding` is `cll`) and the same endpoint, trailing slash
/// ignored. `None` when no row matches.
pub fn row_for<'a>(directory: Option<&'a Value>, ts_url: &str) -> Option<&'a Map<String, Value>> {
    let binding = binding_of(ts_url);
    let endpoint = endpoint_of(ts_url);
    rows(directory)
        .iter()
        .filter_map(Value::as_object)
        .find(|row| {
            let binding_matches = match row.get("binding") {
                None => binding == BINDING_CLL,
                Some(Value::String(b)) => b == binding,
                Some(_) => false,
            };
            let endpoint_matches = match row.get("endpoint") {
                None => endpoint.is_empty(),
                Some(Value::String(e)) => e.trim_end_matches('/') == endpoint,
                Some(_) => false,
            };
            binding_matches && endpoint_matches
        })
}

fn ed25519_spki(raw: &[u8; 32]) -> Vec<u8> {
    let mut der = ED25519_SPKI_PREFIX.to_vec();
    der.extend_from_slice(raw);
    der
}

/// The raw Ed25519 key of a SubjectPublicKeyInfo, when it is one.
fn raw_ed25519(der: &[u8]) -> Option<[u8; 32]> {
    let spki = SubjectPublicKeyInfoRef::try_from(der).ok()?;
    if spki.algorithm.oid != ED25519_OID || spki.algorithm.parameters.is_some() {
        return None;
    }
    spki.subject_public_key.as_bytes()?.try_into().ok()
}

/// Whether a directory `public_keys` entry counts: a DER
/// SubjectPublicKeyInfo holding an Ed25519 key, or an ECDSA P-256 key whose
/// point is on the curve. Every other entry is skipped: not an SPKI, RSA, an
/// unknown algorithm OID, another curve (secp256k1, P-384, P-521, ...) or a
/// point off the curve.
fn spki_loads(der: &[u8]) -> bool {
    raw_ed25519(der).is_some() || p256::PublicKey::from_public_key_der(der).is_ok()
}

fn pem(der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut out = String::from("-----BEGIN PUBLIC KEY-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END PUBLIC KEY-----\n");
    out
}

/// Python's truthiness of a JSON value: `null`, `false`, `0`, `""`, `[]` and
/// `{}` are false.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_none_or(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Every key a row lists, as DER SubjectPublicKeyInfo, in `key_ids` order:
/// the `public_keys` entry (canonical base64 DER) the key id names, by the
/// SHA-256 of its DER or an Ed25519 key by its raw key, when there is one,
/// else the key id read as a raw Ed25519 key (32 bytes that are not an
/// Ed25519 point are still a key, under which nothing verifies). A
/// `public_keys` entry is skipped unless it is canonical base64 of a DER
/// SubjectPublicKeyInfo holding an Ed25519 key or an ECDSA P-256 key on the
/// curve. In a `rekor` row a key id is an RFC 6962 log
/// ID, so one with no `public_keys` entry makes the row unusable, as does a
/// `key_ids` or `public_keys` that is not a list, or a key id that is not 64
/// lowercase hex characters. An unusable row is an `Err`.
pub fn row_public_keys(row: &Map<String, Value>) -> Result<Vec<Vec<u8>>, String> {
    let list = |name: &str| -> Result<&[Value], String> {
        match row.get(name) {
            None => Ok(&[]),
            Some(Value::Array(items)) => Ok(items),
            Some(_) => Err("key_ids and public_keys must be lists".to_string()),
        }
    };
    let (public_keys, key_ids) = (list("public_keys")?, list("key_ids")?);
    let mut by_id: HashMap<String, Vec<u8>> = HashMap::new();
    for der in public_keys
        .iter()
        .filter_map(Value::as_str)
        .filter_map(|b64| STANDARD.decode(b64).ok())
        // An entry that is not a SubjectPublicKeyInfo is skipped, like one
        // that is not base64.
        .filter(|der| spki_loads(der))
    {
        by_id.insert(hex::encode(Sha256::digest(&der)), der.clone());
        if let Some(raw) = raw_ed25519(&der) {
            by_id.insert(hex::encode(raw), der);
        }
    }
    let rekor = matches!(row.get("binding"), Some(Value::String(b)) if b == BINDING_REKOR);
    let mut keys = Vec::with_capacity(key_ids.len());
    for key_id in key_ids {
        let key_id = match key_id {
            Value::String(id) if crate::verify::is_hex64(id) => id.as_str(),
            _ => return Err("a key id is not 64 lowercase hex characters".to_string()),
        };
        if let Some(der) = by_id.get(key_id) {
            keys.push(der.clone());
        } else if rekor {
            return Err(format!(
                "rekor row: no public key for log ID {}...",
                &key_id[..16]
            ));
        } else {
            let mut raw = [0u8; 32];
            hex::decode_to_slice(key_id, &mut raw).map_err(|e| e.to_string())?;
            keys.push(ed25519_spki(&raw));
        }
    }
    Ok(keys)
}

/// CLL's checkpoint digest: SHA-256 of the checkpoint signing body, the JSON
/// object of `v` (1), `kind` (`mmr_checkpoint`) and the signed fields, keys
/// sorted, no whitespace, non-ASCII escaped as `\uXXXX`.
pub fn checkpoint_digest(signed: &SignedCheckpoint) -> String {
    cll::checkpoint::CheckpointRecord {
        v: 1,
        kind: "mmr_checkpoint".to_string(),
        log_id: signed.log_id.clone(),
        mmr_size: signed.mmr_size,
        root: signed.root.clone(),
        prev_size: signed.prev_size,
        prev_root: signed.prev_root.clone(),
        key_id: signed.key_id.clone(),
        timestamp: signed.timestamp.clone(),
        signature: String::new(),
        witnesses: Vec::new(),
    }
    .digest()
}

/// The two signature algorithms a receipt may declare: COSE `alg` -8 (EdDSA,
/// Ed25519 here) and -7 (ES256).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Algorithm {
    EdDSA,
    ES256,
}

/// An inclusion proof: `tree_size`, `leaf_index` and the audit path.
type InclusionProof = (u64, u64, Vec<Vec<u8>>);

/// A COSE Receipt decoded under the receipt encoding rule of profile v1
/// §6.2.2 (`strict_receipt_item`), which the strict Bundle check shares.
struct DecodedReceipt {
    alg: Algorithm,
    protected: Vec<u8>,
    headers: ReceiptItem,
    unprotected: ReceiptItem,
    signature: Vec<u8>,
}

/// Decodes a receipt as vectors/bundle/strict/README.md "COSE Receipts"
/// reads it: at most 10,485,760 octets, one CBOR item under the receipt
/// encoding rule, a tag-18 COSE_Sign1 with a detached (null) payload, so its
/// signature covers the rebuilt Merkle root, protected `vds` (label 395) 1
/// (RFC9162_SHA256) and `alg` EdDSA (-8) or ES256 (-7). A header label the
/// check does not read is ignored whatever its value.
fn decode_receipt(receipt: &[u8]) -> Result<DecodedReceipt, String> {
    if receipt.is_empty() || receipt.len() > MAX_RECEIPT_OCTETS {
        return Err("receipt size is invalid".into());
    }
    let Some(ReceiptItem::Tag(18, body)) = strict_receipt_item(receipt, true) else {
        return Err("receipt rejected: not a COSE_Sign1 under the receipt encoding rule".into());
    };
    let ReceiptItem::Array(parts) = *body else {
        return Err("receipt is not a COSE_Sign1 message".into());
    };
    let Ok([protected, unprotected, payload, signature]) = <[ReceiptItem; 4]>::try_from(parts)
    else {
        return Err("receipt is not a COSE_Sign1 message".into());
    };
    let ReceiptItem::Bytes(protected) = protected else {
        return Err("receipt is not a COSE_Sign1 message".into());
    };
    if payload != ReceiptItem::Null {
        return Err("receipt payload is attached; a receipt's payload must be detached".into());
    }
    let ReceiptItem::Bytes(signature) = signature else {
        return Err("receipt signature is not a byte string".into());
    };
    let headers =
        if protected.is_empty() {
            ReceiptItem::Map(Vec::new())
        } else {
            match strict_receipt_item(&protected, false) {
                Some(map @ ReceiptItem::Map(_)) => map,
                Some(_) => return Err("protected header is not a map".into()),
                None => return Err(
                    "protected header rejected: not one CBOR item under the receipt encoding rule"
                        .into(),
                ),
            }
        };
    if headers.get(395) != Some(&ReceiptItem::Int(1)) {
        return Err("receipt vds is not RFC9162_SHA256 (1)".into());
    }
    let alg = match headers.get(1) {
        Some(ReceiptItem::Int(-8)) => Algorithm::EdDSA,
        Some(ReceiptItem::Int(-7)) => Algorithm::ES256,
        _ => return Err("receipt alg is not EdDSA (-8) or ES256 (-7)".into()),
    };
    check_critical(&headers)?;
    Ok(DecodedReceipt {
        alg,
        protected,
        headers,
        unprotected,
        signature,
    })
}

/// RFC 9052 section 3.1: a `crit` (2) list must be a non-empty array of
/// labels that are present in the protected header and that this check
/// processes (`alg`, `crit`, CWT_Claims, `vds`).
fn check_critical(headers: &ReceiptItem) -> Result<(), String> {
    let Some(raw) = headers.get(2) else {
        return Ok(());
    };
    let ReceiptItem::Array(labels) = raw else {
        return Err("crit (label 2) must be a non-empty array".into());
    };
    if labels.is_empty() {
        return Err("crit (label 2) must be a non-empty array".into());
    }
    let ReceiptItem::Map(pairs) = headers else {
        return Err("protected header is not a map".into());
    };
    for label in labels {
        if !matches!(label, ReceiptItem::Int(_) | ReceiptItem::Text(_)) {
            return Err("crit lists a label that is not an integer or text".into());
        }
        if !pairs.iter().any(|(key, _)| key == label) {
            return Err("crit lists a header absent from the protected header".into());
        }
        if !matches!(label, ReceiptItem::Int(1 | 2 | 15 | 395)) {
            return Err("crit marks a header this verifier does not understand".into());
        }
    }
    Ok(())
}

/// The inclusion proofs of a receipt's unprotected `vdp` (396) map, under -1:
/// one to 16 byte strings, each CBOR `[tree_size, leaf_index, [path...]]`
/// under the receipt encoding rule. Every entry must decode.
fn inclusion_proofs(unprotected: &ReceiptItem) -> Result<Vec<InclusionProof>, String> {
    if !matches!(unprotected, ReceiptItem::Map(_)) {
        return Err("unprotected header is not a map".into());
    }
    let Some(vdp @ ReceiptItem::Map(_)) = unprotected.get(396) else {
        return Err("unprotected vdp (label 396) missing or not a map".into());
    };
    let Some(ReceiptItem::Array(entries)) = vdp.get(-1) else {
        return Err("vdp has no inclusion proofs (key -1)".into());
    };
    if entries.is_empty() || entries.len() > MAX_RECEIPT_PROOFS {
        return Err("a receipt carries one to 16 inclusion proofs".into());
    }
    let mut proofs = Vec::with_capacity(entries.len());
    for entry in entries {
        let ReceiptItem::Bytes(blob) = entry else {
            return Err("inclusion proof entry is not a byte string".into());
        };
        let Some(ReceiptItem::Array(proof)) = strict_receipt_item(blob, false) else {
            return Err(
                "inclusion proof is not one CBOR array under the receipt encoding rule".into(),
            );
        };
        let [ReceiptItem::Int(size), ReceiptItem::Int(index), ReceiptItem::Array(nodes)] =
            proof.as_slice()
        else {
            return Err("inclusion proof must be [tree_size, leaf_index, [path]]".into());
        };
        let (Ok(size), Ok(index)) = (u64::try_from(*size), u64::try_from(*index)) else {
            return Err("invalid tree size or leaf index".into());
        };
        if index >= size
            || size > MAX_RECEIPT_TREE_SIZE
            || nodes.len() != receipt_path_length(size, index)
        {
            return Err("invalid tree size, leaf index or path length".into());
        }
        let mut path = Vec::with_capacity(nodes.len());
        for node in nodes {
            match node {
                ReceiptItem::Bytes(node) if node.len() == 32 => path.push(node.clone()),
                _ => return Err("inclusion proof path node must be 32 bytes".into()),
            }
        }
        proofs.push((size, index, path));
    }
    Ok(proofs)
}

/// The RFC 9162 root of a tree of `size` leaves rebuilt from `leaf` at
/// `index` and its audit path, outermost sibling last (RFC 6962 section
/// 2.1.1).
fn inclusion_root(leaf: &[u8], index: u64, size: u64, path: &[Vec<u8>]) -> [u8; 32] {
    fn node(left: &[u8], right: &[u8]) -> [u8; 32] {
        Sha256::new()
            .chain_update([1u8])
            .chain_update(left)
            .chain_update(right)
            .finalize()
            .into()
    }
    let mut siblings = path.to_vec();
    fn fold(leaf: &[u8], size: u64, index: u64, siblings: &mut Vec<Vec<u8>>) -> [u8; 32] {
        if size == 1 {
            return Sha256::new()
                .chain_update([0u8])
                .chain_update(leaf)
                .finalize()
                .into();
        }
        let k = 1u64 << (63 - (size - 1).leading_zeros());
        let sibling = siblings
            .pop()
            .expect("path length checked against size and index");
        if index < k {
            node(&fold(leaf, k, index, siblings), &sibling)
        } else {
            node(&sibling, &fold(leaf, size - k, index - k, siblings))
        }
    }
    fold(leaf, size, index, &mut siblings)
}

/// The RFC 9052 `Signature1` Sig_structure with an empty external AAD.
fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    fn head(out: &mut Vec<u8>, major: u8, n: usize) {
        let m = major << 5;
        match n {
            0..=23 => out.push(m | n as u8),
            24..=0xff => out.extend([m | 24, n as u8]),
            0x100..=0xffff => {
                out.push(m | 25);
                out.extend((n as u16).to_be_bytes());
            }
            _ => {
                out.push(m | 26);
                out.extend((n as u32).to_be_bytes());
            }
        }
    }
    let mut out = vec![0x84];
    head(&mut out, 3, 10);
    out.extend(b"Signature1");
    head(&mut out, 2, protected.len());
    out.extend(protected);
    out.push(0x40);
    head(&mut out, 2, payload.len());
    out.extend(payload);
    out
}

/// A receipt's `alg` fixes its key type: ES256 verifies only under an ECDSA
/// P-256 key, EdDSA only under an Ed25519 key.
fn key_fits_alg(alg: Algorithm, key_der: &[u8]) -> bool {
    match alg {
        Algorithm::EdDSA => raw_ed25519(key_der).is_some(),
        Algorithm::ES256 => p256::PublicKey::from_public_key_der(key_der).is_ok(),
    }
}

/// The grade a known grade label names; `countersigned-observed` is the
/// pre-rename spelling of `observed-only`.
fn known_grade(label: Option<&str>) -> Option<&'static str> {
    match label? {
        GRADE_OBSERVED_ONLY | "countersigned-observed" => Some(GRADE_OBSERVED_ONLY),
        GRADE_MMR_VERIFIED => Some(GRADE_MMR_VERIFIED),
        _ => None,
    }
}

/// A COSE Receipt over `leaf` under `key_der`: it decodes as
/// `decode_receipt` says, every inclusion proof decodes, and for some proof
/// the root rebuilt from `leaf` verifies the signature. Returns the text of
/// the protected grade label (-65537), if any.
fn cose_receipt(receipt: &[u8], leaf: &[u8], key_der: &[u8]) -> Result<Option<String>, String> {
    let decoded = decode_receipt(receipt)?;
    let alg = decoded.alg;
    if !key_fits_alg(alg, key_der) {
        return Err(format!(
            "receipt alg {alg:?} does not match the key type (ES256 needs ECDSA P-256, EdDSA Ed25519)"
        ));
    }
    if alg == Algorithm::EdDSA
        && !raw_ed25519(key_der).is_some_and(|key| strict_ed25519(&key, &decoded.signature))
    {
        return Err("receipt EdDSA signature is not strict Ed25519: a non-canonical or small-order key or R, or S >= L".into());
    }
    let proofs = inclusion_proofs(&decoded.unprotected)?;
    // After strict_ed25519, the cofactorless `verify` is the strict check.
    let verifies = |message: &[u8]| match alg {
        Algorithm::EdDSA => raw_ed25519(key_der)
            .and_then(|key| ed25519_dalek::VerifyingKey::from_bytes(&key).ok())
            .zip(<[u8; 64]>::try_from(decoded.signature.as_slice()).ok())
            .is_some_and(|(key, signature)| {
                key.verify(message, &ed25519_dalek::Signature::from_bytes(&signature))
                    .is_ok()
            }),
        _ => p256::ecdsa::VerifyingKey::from_public_key_der(key_der).is_ok_and(|key| {
            p256::ecdsa::Signature::from_slice(&decoded.signature)
                .is_ok_and(|signature| key.verify(message, &signature).is_ok())
        }),
    };
    for (size, index, path) in &proofs {
        let root = inclusion_root(leaf, *index, *size, path);
        if verifies(&sig_structure(&decoded.protected, &root)) {
            return Ok(match decoded.headers.get(-65537) {
                Some(ReceiptItem::Text(grade)) => Some(grade.clone()),
                _ => None,
            });
        }
    }
    Err("receipt signature did not verify over any reconstructed root".into())
}

fn verify_cll(
    signed: &SignedCheckpoint,
    record: &Map<String, Value>,
    key_der: &[u8],
) -> ReceiptCheck {
    let digest = hex::decode(checkpoint_digest(signed)).expect("a SHA-256 hex digest");
    let expected = hex::encode(Sha256::digest(digest));
    if !matches!(record.get("entry_hash"), Some(Value::String(h)) if *h == expected) {
        return ReceiptCheck::fail(
            "witness.entry_hash does not match this checkpoint's digest -- stamp is not bound to this checkpoint",
        );
    }
    let receipt = match record
        .get("receipt_b64")
        .and_then(Value::as_str)
        .and_then(|b64| STANDARD.decode(b64).ok())
    {
        Some(r) => r,
        None => return ReceiptCheck::fail("receipt_b64 is not valid base64"),
    };
    let leaf = hex::decode(&expected).expect("hex digest");
    match cose_receipt(&receipt, &leaf, key_der) {
        Err(reason) => ReceiptCheck::fail(if reason.is_empty() {
            "receipt signature does not verify under the pinned/supplied key".to_string()
        } else {
            reason
        }),
        Ok(label) => {
            let grade = known_grade(label.as_deref());
            ReceiptCheck::verified(
                if grade.is_some() {
                    "ok"
                } else {
                    "ok (receipt carries no grade label)"
                },
                grade.map(str::to_string),
                &receipt,
            )
        }
    }
}

/// Python's `json.dumps` integer text for a JSON integer.
fn integer_text(value: &Value) -> Option<String> {
    match value {
        Value::Number(n) if !crate::canonical::is_float(n) => {
            let text = n.to_string();
            Some(if text == "-0" { "0".to_string() } else { text })
        }
        _ => None,
    }
}

/// Offline check of one Rekor `dsse` entry (a parsed log entry) against the
/// checkpoint it claims: the Signed Entry Timestamp verifies under the
/// ECDSA P-256 key `rekor_key_der` and `logID` is that key's, the entry's
/// `payloadHash` is SHA-256 of `checkpoint_cose`, and its only verifier key
/// is the Ed25519 key `checkpoint_key_id` names. Returns `(ok, reason)`.
pub fn verify_rekor_receipt(
    receipt: &Value,
    checkpoint_cose: &[u8],
    checkpoint_key_id: &str,
    rekor_key_der: &[u8],
) -> (bool, String) {
    match rekor_entry(receipt, checkpoint_cose, checkpoint_key_id, rekor_key_der) {
        Ok(()) => (true, "ok".to_string()),
        Err(reason) => (false, reason),
    }
}

fn rekor_entry(
    receipt: &Value,
    checkpoint_cose: &[u8],
    checkpoint_key_id: &str,
    rekor_key_der: &[u8],
) -> Result<(), String> {
    let unreadable = |what: &str| format!("unreadable receipt: {what}");
    // A caller-built entry is walked iteratively before anything clones it.
    if crate::json::exceeds_max_depth(receipt) {
        return Err(unreadable("nests deeper than 128 levels"));
    }
    let key = p256::ecdsa::VerifyingKey::from_public_key_der(rekor_key_der)
        .map_err(|_| unreadable("the Rekor key is not an ECDSA P-256 key"))?;
    let key_der = key
        .to_public_key_der()
        .map_err(|_| unreadable("the Rekor key does not encode"))?;
    let log_id = hex::encode(Sha256::digest(key_der.as_bytes()));
    let receipt = receipt
        .as_object()
        .ok_or_else(|| unreadable("not an object"))?;
    if !matches!(receipt.get("logID"), Some(Value::String(id)) if *id == log_id) {
        return Err("logID is not the pinned Rekor key".to_string());
    }
    let set_b64 = match receipt.get("verification") {
        Some(Value::Object(v)) => v.get("signedEntryTimestamp"),
        Some(other) if truthy(other) => return Err(unreadable("verification is not an object")),
        _ => None,
    };
    let set_b64 = match set_b64 {
        Some(v) if truthy(v) => v,
        _ => return Err("no signedEntryTimestamp".to_string()),
    };
    let (integrated, index) = match (receipt.get("integratedTime"), receipt.get("logIndex")) {
        (Some(i), Some(x)) => (i, x),
        _ => return Err(unreadable("integratedTime or logIndex is missing")),
    };
    let (integrated, index) = match (integer_text(integrated), integer_text(index)) {
        (Some(i), Some(x)) => (i, x),
        _ => return Err("integratedTime and logIndex must be JSON integers".to_string()),
    };
    let body = match receipt.get("body") {
        Some(Value::String(body)) => body,
        Some(_) => return Err("body must be a string".to_string()),
        None => return Err(unreadable("body is missing")),
    };
    // Rekor's canonical JSON: keys sorted, no whitespace.
    let quoted = |s: &str| serde_json::to_string(s).expect("a string serializes");
    let signed = format!(
        "{{\"body\":{},\"integratedTime\":{integrated},\"logID\":{},\"logIndex\":{index}}}",
        quoted(body),
        quoted(&log_id),
    );
    let set = set_b64
        .as_str()
        .and_then(|b64| STANDARD.decode(b64).ok())
        .ok_or_else(|| unreadable("signedEntryTimestamp is not base64"))?;
    let verified = p256::ecdsa::Signature::from_der(&set)
        .map(|sig| key.verify(signed.as_bytes(), &sig).is_ok())
        .unwrap_or(false);
    if !verified {
        return Err("signedEntryTimestamp does not verify under the pinned Rekor key".to_string());
    }
    let entry = STANDARD
        .decode(body)
        .ok()
        .and_then(|raw| crate::json::decode(&raw).ok())
        .ok_or_else(|| unreadable("body is not base64 JSON"))?;
    let entry = entry
        .as_object()
        .ok_or_else(|| unreadable("body is not an object"))?;
    if !matches!(entry.get("kind"), Some(Value::String(k)) if k == "dsse") {
        return Err("entry kind is not 'dsse'".to_string());
    }
    let member = |parent: &Map<String, Value>,
                  name: &str|
     -> Result<Option<Map<String, Value>>, String> {
        match parent.get(name) {
            Some(Value::Object(m)) => Ok(Some(m.clone())),
            Some(other) if truthy(other) => Err(unreadable(&format!("{name} is not an object"))),
            _ => Ok(None),
        }
    };
    let spec = member(entry, "spec")?.unwrap_or_default();
    let payload_hash = member(&spec, "payloadHash")?.unwrap_or_default();
    let cose_hash = hex::encode(Sha256::digest(checkpoint_cose));
    if !matches!(payload_hash.get("algorithm"), Some(Value::String(a)) if a == "sha256")
        || !matches!(payload_hash.get("value"), Some(Value::String(v)) if *v == cose_hash)
    {
        return Err("entry payloadHash is not this checkpoint's bytes".to_string());
    }
    let signatures: &[Value] = match spec.get("signatures") {
        Some(Value::Array(list)) => list,
        Some(other) if truthy(other) => return Err(unreadable("signatures is not a list")),
        _ => &[],
    };
    let mut verifiers = BTreeSet::new();
    for signature in signatures {
        let signature = signature
            .as_object()
            .ok_or_else(|| unreadable("a signature is not an object"))?;
        let encoded = match signature.get("verifier") {
            None => "",
            Some(Value::String(v)) => v.as_str(),
            Some(_) => return Err(unreadable("verifier is not a string")),
        };
        let mut pem_bytes = STANDARD
            .decode(encoded)
            .map_err(|_| unreadable("verifier is not base64"))?;
        pem_bytes.retain(|b| *b != b'\r');
        verifiers.insert(trim_ascii_whitespace(&pem_bytes).to_vec());
    }
    let checkpoint_key: [u8; 32] = hex::decode(checkpoint_key_id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| unreadable("the checkpoint key_id is not a raw Ed25519 key"))?;
    let expected = pem(&ed25519_spki(&checkpoint_key));
    let expected = trim_ascii_whitespace(expected.as_bytes()).to_vec();
    if verifiers.len() != 1 || !verifiers.contains(&expected) {
        return Err("entry is not signed by the checkpoint's key".to_string());
    }
    Ok(())
}

/// Python's `bytes.strip()`.
fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let ws = |b: &u8| matches!(*b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    let start = bytes.iter().position(|b| !ws(b)).unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|b| !ws(b)).map_or(start, |e| e + 1);
    &bytes[start..end]
}

/// Offline check of a SCRAPI receipt: a SCITT COSE Receipt (RFC 9162) over
/// the leaf SHA-256(`checkpoint_cose`), signed under the pinned key
/// (`service_key_der`, DER SubjectPublicKeyInfo). Without a key nothing is
/// checked. The grade is the receipt's known grade label, else
/// `observed-only`.
pub fn verify_scrapi_receipt(
    receipt: &[u8],
    checkpoint_cose: &[u8],
    service_key_der: Option<&[u8]>,
) -> ReceiptCheck {
    let key = match service_key_der {
        Some(key) => key,
        None => return ReceiptCheck::fail("not checked: no key pinned for this service"),
    };
    let leaf = Sha256::digest(checkpoint_cose);
    match cose_receipt(receipt, &leaf, key) {
        Err(reason) => ReceiptCheck::fail(format!(
            "receipt does not verify for this checkpoint under the pinned key: {reason}"
        )),
        Ok(label) => {
            let grade = known_grade(label.as_deref());
            ReceiptCheck::verified(
                if grade.is_none() && label.is_some() {
                    "ok (unknown grade label ignored)"
                } else {
                    "ok"
                },
                Some(grade.unwrap_or(GRADE_OBSERVED_ONLY).to_string()),
                receipt,
            )
        }
    }
}

/// One receipt (a `WitnessRecord` object) under one key (DER
/// SubjectPublicKeyInfo), for the checkpoint whose signed fields are
/// `signed` and whose COSE statement is `checkpoint_cose`. The binding comes
/// from the record's `ts_url`.
pub fn verify_receipt(
    signed: &SignedCheckpoint,
    record: &Map<String, Value>,
    key_der: &[u8],
    checkpoint_cose: Option<&[u8]>,
) -> ReceiptCheck {
    let ts_url = record.get("ts_url").and_then(Value::as_str).unwrap_or("");
    let binding = binding_of(ts_url);
    if binding == BINDING_CLL {
        return verify_cll(signed, record, key_der);
    }
    let cose = match checkpoint_cose {
        Some(cose) => cose,
        None => return ReceiptCheck::fail("not checked: checkpoint COSE statement not available"),
    };
    let receipt = match record
        .get("receipt_b64")
        .and_then(Value::as_str)
        .and_then(|b64| STANDARD.decode(b64).ok())
    {
        Some(r) => r,
        None => return ReceiptCheck::fail("unreadable receipt: receipt_b64 is not base64"),
    };
    if binding == BINDING_REKOR {
        let entry = match crate::json::decode(&receipt) {
            Ok(entry) => entry,
            Err(_) => return ReceiptCheck::fail("unreadable receipt: not JSON"),
        };
        let (ok, reason) = verify_rekor_receipt(&entry, cose, &signed.key_id, key_der);
        return ReceiptCheck {
            ok,
            reason,
            grade: ok.then(|| GRADE_OBSERVED_ONLY.to_string()),
            registration_time: None,
            registration_time_reason: Some(
                if ok {
                    REASON_BINDING_WITHOUT_IAT
                } else {
                    REASON_RECEIPT_NOT_PASSED
                }
                .to_string(),
            ),
        };
    }
    verify_scrapi_receipt(&receipt, cose, Some(key_der))
}

/// A WitnessRecord: every member present; `ts_url`, `entry_hash` and
/// `receipt_b64` non-empty strings; `receipt_b64` canonical standard base64.
/// Anything else is malformed, never merely not checked.
fn is_record(entry: &Value) -> Option<&Map<String, Value>> {
    let record = entry.as_object()?;
    let text = |field: &str| {
        record
            .get(field)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    };
    (RECORD_FIELDS
        .iter()
        .all(|field| record.contains_key(*field))
        && text("ts_url").is_some()
        && text("entry_hash").is_some()
        && text("receipt_b64").is_some_and(|b64| STANDARD.decode(b64).is_ok()))
    .then_some(record)
}

/// Checks every receipt in `receipts` (a Bundle's `checkpoint.witnesses`)
/// against the SIGNED checkpoint `signed` (its fields as the COSE statement
/// states them; `None` when it did not verify) and its COSE bytes, under the
/// keys of `directory`. `None` trusts no witness.
///
/// The status is `fail` when an entry is malformed or a receipt does not
/// verify, else `pass` when one verifies, else `withheld`.
pub fn verify_witness_receipts(
    receipts: Option<&Value>,
    signed: Option<&SignedCheckpoint>,
    checkpoint_cose: Option<&[u8]>,
    directory: Option<&Value>,
) -> WitnessReport {
    let withheld = |finding: &str| WitnessReport {
        status: "withheld".to_string(),
        findings: vec![finding.to_string()],
        receipts: Vec::new(),
    };
    let entries = match receipts {
        Some(Value::Array(entries)) if !entries.is_empty() => entries,
        _ => return withheld("witness_receipt_absent"),
    };
    let (signed, cose) = match (signed, checkpoint_cose) {
        (Some(signed), Some(cose)) => (signed, cose),
        _ => return withheld("checkpoint_unverified"),
    };
    // Malformed entries are listed first, then one finding per checked receipt.
    let mut findings: Vec<String> = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| is_record(entry).is_none())
        .map(|(index, _)| format!("witness_receipt_malformed:{index}"))
        .collect();
    let malformed = !findings.is_empty();
    let mut results = Vec::new();
    for record in entries.iter().filter_map(is_record) {
        let ts_url = record["ts_url"].as_str().expect("checked by is_record");
        let mut check = ReceiptCheck::fail("");
        let mut key_id = None;
        if record.get("is_stub") == Some(&Value::Bool(true)) {
            check.reason = "stub receipt (never reached a witness)".to_string();
        } else {
            match row_for(directory, ts_url) {
                None => check.reason = "not checked: no directory row for this witness".to_string(),
                Some(row) => match row_public_keys(row) {
                    Err(e) => {
                        check.reason = format!("not checked: unusable key in directory row ({e})")
                    }
                    Ok(keys) => {
                        for (index, key) in keys.iter().enumerate() {
                            check = verify_receipt(signed, record, key, Some(cose));
                            if check.ok {
                                // row_public_keys returns one key per key id, in order.
                                key_id = row["key_ids"][index].as_str().map(str::to_string);
                                break;
                            }
                        }
                    }
                },
            }
        }
        let status = if check.ok {
            "pass"
        } else if check.reason.is_empty()
            || check.reason.starts_with("not checked")
            || check.reason.starts_with("stub receipt")
        {
            if check.reason.is_empty() {
                check.reason =
                    "not checked: no key in the directory row for this witness".to_string();
            }
            findings.push(format!("witness_unverified:{ts_url}"));
            "withheld"
        } else {
            findings.push(format!("witness_receipt_invalid:{ts_url}"));
            "fail"
        };
        results.push(WitnessReceiptResult {
            ts_url: ts_url.to_string(),
            binding: binding_of(ts_url).to_string(),
            status: status.to_string(),
            reason: check.reason,
            grade: if check.ok { check.grade } else { None },
            key_id,
            registration_time: check.registration_time,
            registration_time_reason: check.registration_time_reason,
        });
    }
    let status = if malformed || results.iter().any(|r| r.status == "fail") {
        "fail"
    } else if results.iter().any(|r| r.status == "pass") {
        "pass"
    } else {
        "withheld"
    };
    WitnessReport {
        status: status.to_string(),
        findings,
        receipts: results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::cbor::value::Value as Cbor;
    use serde_json::json;

    fn cbor(value: &Cbor) -> Vec<u8> {
        let mut out = Vec::new();
        coset::cbor::ser::into_writer(value, &mut out).unwrap();
        out
    }

    fn receipt(protected: Vec<(Cbor, Cbor)>, payload: Cbor) -> Vec<u8> {
        cbor(&Cbor::Tag(
            18,
            Box::new(Cbor::Array(vec![
                Cbor::Bytes(cbor(&Cbor::Map(protected))),
                Cbor::Map(vec![]),
                payload,
                Cbor::Bytes(vec![]),
            ])),
        ))
    }

    /// The registration-time edges no shared vector reaches.
    #[test]
    fn registration_time_reads_only_a_whole_iat() {
        let int = |i: i64| Cbor::Integer(i.into());
        let with_claims = |claims: Cbor| {
            receipt(
                vec![(int(1), int(-8)), (int(15), claims), (int(395), int(1))],
                Cbor::Null,
            )
        };
        let iat = |value: Cbor| with_claims(Cbor::Map(vec![(int(6), value)]));
        let plain = receipt(vec![(int(1), int(-8)), (int(395), int(1))], Cbor::Null);
        assert_eq!(registration_time(&plain), Err(REASON_IAT_ABSENT));
        assert_eq!(
            registration_time(&with_claims(Cbor::Map(vec![]))),
            Err(REASON_IAT_ABSENT)
        );
        assert_eq!(
            registration_time(&iat(int(1_792_022_400))),
            Ok(1_792_022_400)
        );
        assert_eq!(registration_time(&iat(int(0))), Ok(0));
        assert_eq!(
            registration_time(&iat(int((1 << 53) - 1))),
            Ok((1 << 53) - 1)
        );
        for invalid in [
            iat(int(1 << 53)),
            iat(int(-1)),
            iat(Cbor::Bool(true)),
            iat(Cbor::Text("1792022400".into())),
            iat(Cbor::Float(1.5)),
            with_claims(Cbor::Array(vec![int(6)])),
        ] {
            assert_eq!(registration_time(&invalid), Err(REASON_IAT_INVALID));
        }
    }

    #[test]
    fn receipt_vds_and_alg_are_integers() {
        let int = |i: i64| Cbor::Integer(i.into());
        for alg in [-8, -7] {
            let good = receipt(vec![(int(1), int(alg)), (int(395), int(1))], Cbor::Null);
            assert!(decode_receipt(&good).is_ok());
        }
        for protected in [
            vec![(int(1), int(-8)), (int(395), Cbor::Bool(true))],
            vec![(int(1), int(-8)), (int(395), Cbor::Float(1.0))],
            vec![(int(1), int(-35)), (int(395), int(1))],
            vec![(int(1), Cbor::Bool(true)), (int(395), int(1))],
            vec![(int(1), int(-8)), (int(395), int(2))],
            vec![(int(1), int(-8))],
        ] {
            let shaped = receipt(protected.clone(), Cbor::Null);
            assert!(decode_receipt(&shaped).is_err(), "{protected:?}");
        }
        let attached = receipt(
            vec![(int(1), int(-8)), (int(395), int(1))],
            Cbor::Bytes(vec![1]),
        );
        assert!(decode_receipt(&attached)
            .err()
            .unwrap()
            .contains("attached"));
        let mut undefined = receipt(vec![(int(1), int(-8)), (int(395), int(1))], Cbor::Null);
        let at = undefined
            .iter()
            .rposition(|b| *b == 0xf6)
            .expect("null payload");
        undefined[at] = 0xf7;
        // Undefined is no simple value the receipt encoding rule allows.
        assert!(decode_receipt(&undefined)
            .err()
            .unwrap()
            .contains("receipt encoding rule"));
        assert!(decode_receipt(b"junk").is_err());
    }

    /// The secp256k1 key of the strict vectors' "K1 witness" row.
    const SECP256K1_SPKI_B64: &str = "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEsh20enXO7lwBD2n2bUjVoBfk4vRrR7SW3fA0mMJuHOwSdZkxjbwL+20/X0kVZza/IUgq+4da0Y129p2RKAXz2g==";

    /// A receipt for `leaf` in a one-leaf tree (RFC 9162: the root is
    /// SHA-256(0x00 || leaf)), signed with `alg` by `sign`.
    fn signed_receipt(alg: Algorithm, leaf: &[u8], sign: impl Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
        use coset::{CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
        let root = Sha256::digest([&[0u8][..], leaf].concat());
        let proof = cbor(&Cbor::Array(vec![
            Cbor::Integer(1.into()),
            Cbor::Integer(0.into()),
            Cbor::Array(vec![]),
        ]));
        let protected = HeaderBuilder::new()
            .algorithm(match alg {
                Algorithm::EdDSA => coset::iana::Algorithm::EdDSA,
                Algorithm::ES256 => coset::iana::Algorithm::ES256,
            })
            .value(395, Cbor::Integer(1.into()))
            .build();
        let unprotected = HeaderBuilder::new()
            .value(
                396,
                Cbor::Map(vec![(
                    Cbor::Integer((-1).into()),
                    Cbor::Array(vec![Cbor::Bytes(proof)]),
                )]),
            )
            .build();
        CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .create_detached_signature(&root, &[], |tbs| sign(tbs))
            .build()
            .to_tagged_vec()
            .unwrap()
    }

    #[test]
    fn a_receipt_alg_fixes_its_key_type() {
        use ed25519_dalek::Signer as _;
        let leaf = b"leaf entry";
        let ed = ed25519_dalek::SigningKey::from_bytes(&[6; 32]);
        let ed_der = ed25519_spki(&ed.verifying_key().to_bytes());
        let ec = p256::ecdsa::SigningKey::from_slice(&[8; 32]).unwrap();
        let ec_der = ec
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let k1_der = STANDARD.decode(SECP256K1_SPKI_B64).unwrap();
        assert!(!spki_loads(&k1_der)); // skipped in a directory row

        let eddsa = signed_receipt(Algorithm::EdDSA, leaf, |tbs| {
            ed.sign(tbs).to_bytes().to_vec()
        });
        let es256 = signed_receipt(Algorithm::ES256, leaf, |tbs| {
            let signature: p256::ecdsa::Signature = ec.sign(tbs);
            signature.to_bytes().to_vec()
        });

        assert!(cose_receipt(&eddsa, leaf, &ed_der).is_ok());
        assert!(cose_receipt(&es256, leaf, &ec_der).is_ok());
        for (receipt, key) in [
            (&eddsa, &ec_der),
            (&eddsa, &k1_der),
            (&es256, &ed_der),
            (&es256, &k1_der),
        ] {
            let err = cose_receipt(receipt, leaf, key).unwrap_err();
            assert!(err.contains("does not match the key type"), "{err}");
        }

        // Through scrapi: the same rule, a failure (never withheld).
        let cose = b"checkpoint cose";
        let scrapi_leaf = Sha256::digest(cose);
        let es256 = signed_receipt(Algorithm::ES256, &scrapi_leaf, |tbs| {
            let signature: p256::ecdsa::Signature = ec.sign(tbs);
            signature.to_bytes().to_vec()
        });
        assert!(verify_scrapi_receipt(&es256, cose, Some(&ec_der)).ok);
        let wrong = verify_scrapi_receipt(&es256, cose, Some(&k1_der));
        assert!(!wrong.ok && !wrong.reason.starts_with("not checked"));
    }

    /// checkpointed-local-log's shared strict Ed25519 cases: the pre-check
    /// followed by dalek's `verify`, as `cose_receipt` runs them, accepts
    /// exactly the valid ones.
    #[test]
    fn strict_ed25519_matches_the_cll_vectors() {
        use ed25519_dalek::Verifier as _;
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/cross-language/cll-ed25519-vectors.json"
        );
        let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let cases = vectors["ed25519_cases"].as_array().unwrap();
        assert_eq!(cases.len(), 54);
        let bytes = |case: &Value, name: &str| hex::decode(case[name].as_str().unwrap()).unwrap();
        for case in cases {
            let key: [u8; 32] = bytes(case, "public_key_hex").try_into().unwrap();
            let signature: [u8; 64] = bytes(case, "signature_hex").try_into().unwrap();
            let message = bytes(case, "message_hex");
            let verifies = strict_ed25519(&key, &signature)
                && ed25519_dalek::VerifyingKey::from_bytes(&key).is_ok_and(|key| {
                    key.verify(&message, &ed25519_dalek::Signature::from_bytes(&signature))
                        .is_ok()
                });
            assert_eq!(
                verifies,
                case["valid"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
        }
    }

    /// The receipt encoding rule limits a map only by the octet limit, and
    /// its repeated-key check stays fast on a large one.
    #[test]
    fn a_map_of_131073_pairs_decodes() {
        let mut map = vec![0xba, 0x00, 0x02, 0x00, 0x01];
        for key in 0u32..131_073 {
            match key {
                0..=23 => map.push(key as u8),
                24..=0xff => map.extend([0x18, key as u8]),
                0x100..=0xffff => map.extend([0x19, (key >> 8) as u8, key as u8]),
                _ => {
                    map.push(0x1a);
                    map.extend(key.to_be_bytes());
                }
            }
            map.push(0);
        }
        let started = std::time::Instant::now();
        assert!(
            matches!(strict_receipt_item(&map, false), Some(ReceiptItem::Map(pairs)) if pairs.len() == 131_073)
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        map.extend([0x00, 0x00]);
        map[4] = 0x02; // 131074 pairs, the last repeating key 0
        assert!(strict_receipt_item(&map, false).is_none());
    }

    /// A receipt over 10,485,760 octets is refused before it is decoded, as
    /// in every language (too large for a shared vector).
    #[test]
    fn an_oversize_receipt_is_refused() {
        let oversize = vec![0u8; MAX_RECEIPT_OCTETS + 1];
        let err = cose_receipt(&oversize, b"leaf", &ed25519_spki(&[9; 32])).unwrap_err();
        assert!(err.contains("size"), "{err}");
    }

    /// A receipt "signed" by the identity key (R the identity, S = 0)
    /// verifies over any root under dalek's `verify`; it must be refused.
    #[test]
    fn small_order_key_receipt_is_refused() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let forged = signed_receipt(Algorithm::EdDSA, b"any leaf", |_| {
            [identity, [0u8; 32]].concat()
        });
        let err = cose_receipt(&forged, b"any leaf", &ed25519_spki(&identity)).unwrap_err();
        assert!(err.contains("strict Ed25519"), "{err}");
    }

    #[test]
    fn row_key_lists_and_ids_are_typed() {
        let row = |v: Value| v.as_object().unwrap().clone();
        let key = "22".repeat(32);
        assert!(row_public_keys(&row(json!({"key_ids": {key.clone(): 1}}))).is_err());
        assert!(row_public_keys(&row(json!({"key_ids": [format!(" {key}")]}))).is_err());
        assert!(row_public_keys(&row(json!({"key_ids": ["AB".repeat(32)]}))).is_err());
        assert!(row_public_keys(&row(json!({"key_ids": [], "public_keys": null}))).is_err());
        assert!(row_public_keys(&row(json!({"key_ids": null}))).is_err());
        let skipped = row(json!({"key_ids": [key], "public_keys": ["not base64!", 7]}));
        assert_eq!(row_public_keys(&skipped).unwrap().len(), 1);
        assert!(row_public_keys(&row(json!({}))).unwrap().is_empty());
    }

    #[test]
    fn a_public_key_is_found_by_its_digest_or_raw_key() {
        let raw = [9u8; 32];
        let der = ed25519_spki(&raw);
        let b64 = STANDARD.encode(&der);
        for id in [hex::encode(Sha256::digest(&der)), hex::encode(raw)] {
            let row = json!({"binding": "rekor", "key_ids": [id], "public_keys": [b64]});
            assert_eq!(
                row_public_keys(row.as_object().unwrap()).unwrap(),
                vec![der.clone()]
            );
        }
        assert_eq!(raw_ed25519(&der), Some(raw));
        assert!(spki_loads(&der));
        assert!(!spki_loads(b"\x30\x00"));
    }

    /// Which base64 member of a Rekor entry to spell non-canonically.
    #[derive(Clone, Copy, PartialEq)]
    enum Spelling {
        Canonical,
        Body,
        Verifier,
        SignedEntryTimestamp,
    }

    /// `text` (padded base64) with non-zero trailing bits: the same bytes to
    /// a lenient decoder, another spelling.
    fn noncanonical(text: &str) -> String {
        const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut chars: Vec<char> = text.chars().collect();
        let last = chars.iter().rposition(|c| *c != '=').unwrap();
        assert!(last + 1 < chars.len(), "needs padding: {text}");
        let index = ALPHABET.find(chars[last]).unwrap();
        chars[last] = ALPHABET.as_bytes()[index + 1] as char;
        chars.into_iter().collect()
    }

    /// Padded base64 of `bytes`, after appending `pad` until the encoding
    /// carries padding (so it has a non-canonical spelling).
    fn padded_b64(mut bytes: Vec<u8>, pad: u8) -> String {
        while bytes.len().is_multiple_of(3) {
            bytes.push(pad);
        }
        STANDARD.encode(bytes)
    }

    /// A Rekor `dsse` entry, logged under a P-256 key and verified by the
    /// Ed25519 checkpoint key `[3; 32]`, with the given `payloadHash`, and
    /// one base64 member spelled as `spelling` says.
    fn rekor_entry(payload_hash: Value, spelling: Spelling) -> (Value, Vec<u8>, String) {
        use p256::ecdsa::signature::Signer as _;
        let rekor = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
        let rekor_der = rekor
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let log_id = hex::encode(Sha256::digest(&rekor_der));
        let checkpoint_key = [3u8; 32];
        // Trailing newlines are stripped before the PEM is compared.
        let mut verifier = padded_b64(pem(&ed25519_spki(&checkpoint_key)).into_bytes(), b'\n');
        if spelling == Spelling::Verifier {
            verifier = noncanonical(&verifier);
        }
        let entry = json!({
            "kind": "dsse",
            "spec": {"payloadHash": payload_hash, "signatures": [{"verifier": verifier}]},
        });
        // Trailing spaces are JSON whitespace.
        let mut body = padded_b64(entry.to_string().into_bytes(), b' ');
        if spelling == Spelling::Body {
            body = noncanonical(&body);
        }
        // A DER signature varies in length; pick an integratedTime whose
        // signature encodes with padding.
        let (integrated, set) = (1..)
            .map(|time: u64| {
                let signed = format!(
                    "{{\"body\":\"{body}\",\"integratedTime\":{time},\"logID\":\"{log_id}\",\"logIndex\":2}}"
                );
                let set: p256::ecdsa::Signature = rekor.sign(signed.as_bytes());
                (time, set.to_der().as_bytes().to_vec())
            })
            .find(|(_, der)| !der.len().is_multiple_of(3))
            .unwrap();
        let mut set = STANDARD.encode(set);
        if spelling == Spelling::SignedEntryTimestamp {
            set = noncanonical(&set);
        }
        let receipt = json!({
            "body": body, "integratedTime": integrated, "logID": log_id, "logIndex": 2,
            "verification": {"signedEntryTimestamp": set},
        });
        (receipt, rekor_der, hex::encode(checkpoint_key))
    }

    fn sha256_payload(cose: &[u8]) -> Value {
        json!({"algorithm": "sha256", "value": hex::encode(Sha256::digest(cose))})
    }

    #[test]
    fn a_rekor_key_must_be_ecdsa_p256() {
        let cose = b"checkpoint cose";
        let (receipt, key, checkpoint_key) = rekor_entry(sha256_payload(cose), Spelling::Canonical);
        assert!(verify_rekor_receipt(&receipt, cose, &checkpoint_key, &key).0);
        for other in [ed25519_spki(&[4; 32]), b"\x30\x00".to_vec(), Vec::new()] {
            let (ok, reason) = verify_rekor_receipt(&receipt, cose, &checkpoint_key, &other);
            assert!(!ok);
            assert!(reason.contains("not an ECDSA P-256 key"), "{reason}");
        }
        // Through the directory: an Ed25519 key in a rekor row fails the
        // receipt (it is checked, so never withheld).
        let raw = [4u8; 32];
        let directory = json!([{
            "endpoint": "https://r.example", "binding": "rekor",
            "key_ids": [hex::encode(raw)],
            "public_keys": [STANDARD.encode(ed25519_spki(&raw))],
        }]);
        let record = json!({
            "ts_url": "rekor+https://r.example",
            "receipt_b64": STANDARD.encode(receipt.to_string()),
            "entry_hash": "", "leaf_index": 0, "tree_size": 1,
        });
        let report = verify_witness_receipts(
            Some(&json!([record])),
            Some(&SignedCheckpoint {
                log_id: "l".into(),
                mmr_size: 1,
                root: "00".repeat(32),
                key_id: checkpoint_key,
                timestamp: "t".into(),
                prev_size: 0,
                prev_root: String::new(),
            }),
            Some(cose),
            Some(&directory),
        );
        assert_eq!(report.status, "fail");
    }

    #[test]
    fn rekor_base64_members_must_be_canonical() {
        let cose = b"checkpoint cose";
        for spelling in [
            Spelling::Body,
            Spelling::Verifier,
            Spelling::SignedEntryTimestamp,
        ] {
            let (receipt, key, checkpoint_key) = rekor_entry(sha256_payload(cose), spelling);
            assert!(!verify_rekor_receipt(&receipt, cose, &checkpoint_key, &key).0);
        }
    }

    #[test]
    fn receipt_b64_and_public_keys_must_be_canonical() {
        let signed = SignedCheckpoint {
            log_id: "l".into(),
            mmr_size: 1,
            root: "00".repeat(32),
            key_id: "11".repeat(32),
            timestamp: "t".into(),
            prev_size: 0,
            prev_root: String::new(),
        };
        let entry_hash = hex::encode(Sha256::digest(
            hex::decode(checkpoint_digest(&signed)).unwrap(),
        ));
        let receipt = padded_b64(b"\xd2\x84\x40\xa0\xf6".to_vec(), 0x40);
        let record = |receipt_b64: String| {
            json!({"ts_url": "https://w.example", "receipt_b64": receipt_b64,
                   "entry_hash": entry_hash, "leaf_index": 0, "tree_size": 1})
        };
        let key = ed25519_spki(&[2; 32]);
        let reason = |receipt_b64: String| {
            verify_receipt(
                &signed,
                record(receipt_b64).as_object().unwrap(),
                &key,
                None,
            )
            .reason
        };
        assert!(!reason(receipt.clone()).contains("base64"));
        assert!(reason(noncanonical(&receipt)).contains("not valid base64"));

        // A non-canonical public_keys entry is skipped: the rekor row then
        // has no key for its log ID.
        let der = p256::ecdsa::SigningKey::from_slice(&[7; 32])
            .unwrap()
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let log_id = hex::encode(Sha256::digest(&der));
        let canonical = STANDARD.encode(&der);
        assert!(canonical.ends_with('='), "{canonical}");
        let row =
            |b64: String| json!({"binding": "rekor", "key_ids": [log_id], "public_keys": [b64]});
        assert_eq!(
            row_public_keys(row(canonical.clone()).as_object().unwrap()).unwrap(),
            vec![der]
        );
        assert!(row_public_keys(row(noncanonical(&canonical)).as_object().unwrap()).is_err());
    }

    #[test]
    fn a_rekor_payload_hash_names_sha256() {
        let cose = b"checkpoint cose";
        let value = hex::encode(Sha256::digest(cose));
        let check = |payload_hash: Value| {
            let (receipt, key, checkpoint_key) = rekor_entry(payload_hash, Spelling::Canonical);
            verify_rekor_receipt(&receipt, cose, &checkpoint_key, &key)
        };
        assert_eq!(
            check(json!({"algorithm": "sha256", "value": value})),
            (true, "ok".to_string())
        );
        for payload_hash in [
            json!({"value": value}),
            json!({"algorithm": "sha512", "value": value}),
            json!({"algorithm": "SHA256", "value": value}),
            json!({"algorithm": null, "value": value}),
            json!({"algorithm": "sha256", "value": "00".repeat(32)}),
        ] {
            let (ok, reason) = check(payload_hash.clone());
            assert!(!ok, "{payload_hash}");
            assert!(reason.contains("payloadHash"), "{payload_hash}: {reason}");
        }
    }

    #[test]
    fn base64_is_strict_with_padding() {
        assert_eq!(STANDARD.decode("QQ==").unwrap(), b"A");
        assert!(STANDARD.decode("QQ").is_err());
        assert!(STANDARD.decode("Q-==").is_err());
        // Non-zero trailing bits: the bytes would not re-encode to the text.
        assert!(STANDARD.decode("QR==").is_err());
        assert_eq!(STANDARD.decode("QUI=").unwrap(), b"AB");
        assert!(STANDARD.decode("QUJ=").is_err());
    }

    fn test_checkpoint() -> SignedCheckpoint {
        SignedCheckpoint {
            log_id: "l".into(),
            mmr_size: 1,
            root: "00".repeat(32),
            key_id: "11".repeat(32),
            timestamp: "t".into(),
            prev_size: 0,
            prev_root: String::new(),
        }
    }

    #[test]
    fn a_public_key_that_is_not_an_spki_is_skipped() {
        let garbage = vec![0u8; 4];
        let garbage_id = hex::encode(Sha256::digest(&garbage));
        let good_raw = [9u8; 32];
        let good = ed25519_spki(&good_raw);
        // In a rekor row the skipped entry leaves its log ID without a key.
        let rekor = json!({"binding": "rekor", "key_ids": [garbage_id],
                           "public_keys": [STANDARD.encode(&garbage), STANDARD.encode(&good)]});
        assert!(row_public_keys(rekor.as_object().unwrap()).is_err());
        // The other entries of the row still serve.
        let row = json!({"binding": "rekor", "key_ids": [hex::encode(good_raw)],
                         "public_keys": [STANDARD.encode(&garbage), STANDARD.encode(&good)]});
        assert_eq!(
            row_public_keys(row.as_object().unwrap()).unwrap(),
            vec![good]
        );
    }

    #[test]
    fn only_ed25519_and_p256_keys_count() {
        // The RSA and unknown-OID keys of the strict vectors' directory.
        let vectors = crate::json::decode(
            &std::fs::read(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../vectors/bundle/strict/vectors.json"
            ))
            .unwrap(),
        )
        .unwrap();
        let directory_key = |name: &str| -> Vec<u8> {
            let row = vectors["witness_directory"]["witnesses"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["name"] == name)
                .unwrap();
            STANDARD
                .decode(row["public_keys"][0].as_str().unwrap())
                .unwrap()
        };
        let p256_der = p256::ecdsa::SigningKey::from_slice(&[7; 32])
            .unwrap()
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let k1_der = STANDARD.decode(SECP256K1_SPKI_B64).unwrap();
        assert!(spki_loads(&ed25519_spki(&[1; 32])));
        assert!(spki_loads(&p256_der));

        let rsa = directory_key("Rekor with an RSA key");
        let unknown = directory_key("Rekor with an unknown key");
        // A P-256 point that is not on the curve: a real key's X with its
        // Y changed in the last bit.
        let mut off_curve = p256_der.clone();
        let last = off_curve.len() - 1;
        off_curve[last] ^= 1;
        // An EC key whose parameters are not a named curve (NULL instead).
        let mut unnamed = p256_der.clone();
        unnamed.splice(13..23, [0x05, 0x00]);
        unnamed[1] -= 8;
        unnamed[3] -= 8;
        for (name, der) in [
            ("rsa", &rsa),
            ("unknown oid", &unknown),
            ("p-256 off curve", &off_curve),
            ("secp256k1, a valid key on another curve", &k1_der),
            ("unnamed curve", &unnamed),
        ] {
            assert!(
                SubjectPublicKeyInfoRef::try_from(der.as_slice()).is_ok(),
                "{name}"
            );
            assert!(!spki_loads(der), "{name}");
        }

        // A rekor row whose log ID names only a skipped entry is unusable.
        for skipped in [&rsa, &unknown, &k1_der] {
            let row = json!({"binding": "rekor",
                             "key_ids": [hex::encode(Sha256::digest(skipped))],
                             "public_keys": [STANDARD.encode(skipped)]});
            assert!(row_public_keys(row.as_object().unwrap()).is_err());
        }
    }

    #[test]
    fn a_raw_key_that_is_not_a_point_fails_the_receipt() {
        use ed25519_dalek::Signer as _;
        let off_curve = (0u8..=255)
            .map(|b| {
                let mut key = [b; 32];
                key[0] = 2;
                key
            })
            .find(|k| ed25519_dalek::VerifyingKey::from_bytes(k).is_err())
            .expect("some 32 bytes are not an Ed25519 point");
        let row = |key: [u8; 32]| json!([{"endpoint": "https://w.example", "key_ids": [hex::encode(key)]}]);
        assert_eq!(
            row_public_keys(row(off_curve)[0].as_object().unwrap())
                .unwrap()
                .len(),
            1
        );

        let signed = test_checkpoint();
        let entry_hash = Sha256::digest(hex::decode(checkpoint_digest(&signed)).unwrap());
        let witness = ed25519_dalek::SigningKey::from_bytes(&[6; 32]);
        let receipt = signed_receipt(Algorithm::EdDSA, &entry_hash, |tbs| {
            witness.sign(tbs).to_bytes().to_vec()
        });
        let entries = json!([{
            "ts_url": "https://w.example", "receipt_b64": STANDARD.encode(&receipt),
            "entry_hash": hex::encode(entry_hash), "leaf_index": 0, "tree_size": 1,
        }]);
        let run = |directory: Value| {
            verify_witness_receipts(Some(&entries), Some(&signed), Some(b"c"), Some(&directory))
        };
        assert_eq!(run(row(witness.verifying_key().to_bytes())).status, "pass");
        let report = run(row(off_curve));
        assert_eq!(report.status, "fail");
        assert_eq!(
            report.findings,
            ["witness_receipt_invalid:https://w.example"]
        );
    }

    #[test]
    fn deeply_nested_rekor_receipts_fail_cleanly() {
        let key = ed25519_spki(&[4; 32]);
        for depth in [129usize, 100_000] {
            for deep in [
                format!("{}{}", "[".repeat(depth), "]".repeat(depth)),
                format!("{}1{}", "{\"a\":".repeat(depth), "}".repeat(depth)),
            ] {
                assert!(crate::json::decode(deep.as_bytes()).is_err());
                let record = json!({
                    "ts_url": "rekor+https://r.example", "receipt_b64": STANDARD.encode(&deep),
                    "entry_hash": "", "leaf_index": 0, "tree_size": 1,
                });
                let check = verify_receipt(
                    &test_checkpoint(),
                    record.as_object().unwrap(),
                    &key,
                    Some(b"c"),
                );
                assert!(!check.ok);
                assert!(
                    check.reason.starts_with("unreadable receipt"),
                    "{}",
                    check.reason
                );
            }
        }
    }

    #[test]
    fn the_checkpoint_digest_escapes_non_ascii() {
        let signed = SignedCheckpoint {
            log_id: "\u{e9}".into(),
            mmr_size: 1,
            root: "00".repeat(32),
            key_id: "11".repeat(32),
            timestamp: "t".into(),
            prev_size: 0,
            prev_root: String::new(),
        };
        let body = format!(
            "{{\"key_id\":\"{}\",\"kind\":\"mmr_checkpoint\",\"log_id\":\"\\u00e9\",\"mmr_size\":1,\
             \"prev_root\":\"\",\"prev_size\":0,\"root\":\"{}\",\"timestamp\":\"t\",\"v\":1}}",
            "11".repeat(32),
            "00".repeat(32)
        );
        assert_eq!(
            checkpoint_digest(&signed),
            hex::encode(Sha256::digest(body.as_bytes()))
        );

        // Every escape class: short escapes, other controls, DEL, BMP and
        // astral characters, and the characters that stay raw.
        let log_id = "\"\\\n\r\t\u{8}\u{c}\u{1}\u{1f}\u{7f}/<>&~\u{e9}\u{2028}\u{1f600}";
        let escaped =
            "\\\"\\\\\\n\\r\\t\\b\\f\\u0001\\u001f\\u007f/<>&~\\u00e9\\u2028\\ud83d\\ude00";
        let signed = SignedCheckpoint {
            log_id: log_id.into(),
            ..signed
        };
        let body = format!(
            "{{\"key_id\":\"{}\",\"kind\":\"mmr_checkpoint\",\"log_id\":\"{escaped}\",\"mmr_size\":1,\
             \"prev_root\":\"\",\"prev_size\":0,\"root\":\"{}\",\"timestamp\":\"t\",\"v\":1}}",
            "11".repeat(32),
            "00".repeat(32)
        );
        assert_eq!(
            checkpoint_digest(&signed),
            hex::encode(Sha256::digest(body.as_bytes()))
        );
    }
}

/// The verification-material kind of a witness Receipt over a Checkpointed
/// Local Log anchor (`spec/interop-profile-v1.md` §6.2.2).
pub const ANCHOR_WITNESS_KIND: &str = "cll-witness-receipt";
/// The check §6.2.2 defines. It is not an envelope property and never enters
/// the profile's §8 mapping.
pub const ANCHOR_WITNESS_PROPERTY: &str = "anchor_witnessed";

/// One Receipt's `anchor_witnessed` result: its status (`PASS`, `FAIL` or
/// `NOT_CHECKED`), its witness's name when it passed, and its registration
/// time (a NumericDate) when it passed with a protected `iat`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorReceiptReport {
    pub status: &'static str,
    pub witness: Option<String>,
    pub registration_time: Option<u64>,
}

/// `anchor_witnessed` over every Receipt for one anchor. `witness` and
/// `witnessed_time` always come from the same Receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorWitnessReport {
    pub status: &'static str,
    pub receipts: Vec<AnchorReceiptReport>,
    pub witness: Option<String>,
    pub witnessed_time: Option<u64>,
}

const ANCHOR_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const ANCHOR_P256_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];
const MAX_RECEIPT_OCTETS: usize = 10 * 1024 * 1024;
const MAX_RECEIPT_PROOFS: usize = 16;
const MAX_RECEIPT_DEPTH: usize = 16;
const MAX_RECEIPT_TREE_SIZE: u64 = 1 << 62;
/// Labels below this are private use (RFC 9052 section 16.4).
const PRIVATE_LABEL: i128 = -65536;

/// The policy's listed keys in order (§6.2.2 step 2), as `(name, alg, DER
/// SubjectPublicKeyInfo)`: lowercase hex of one of two exact shapes. Any
/// other entry lists no key.
fn anchor_policy_keys(policy: &Value) -> Vec<(String, Algorithm, Vec<u8>)> {
    let rows = policy.get("witnesses").and_then(Value::as_array);
    let mut out = Vec::new();
    for row in rows.into_iter().flatten() {
        let (Some(name), Some(keys)) = (
            row.get("name").and_then(Value::as_str),
            row.get("keys").and_then(Value::as_array),
        ) else {
            continue;
        };
        for key in keys.iter().filter_map(Value::as_str) {
            if !key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                continue;
            }
            let Ok(der) = hex::decode(key) else { continue };
            let alg = if der.len() == 44 && der.starts_with(&ANCHOR_ED25519_PREFIX) {
                Algorithm::EdDSA
            } else if der.len() == 91 && der.starts_with(&ANCHOR_P256_PREFIX) {
                Algorithm::ES256
            } else {
                continue;
            };
            out.push((name.to_string(), alg, der));
        }
    }
    out
}

/// A CBOR item under the receipt encoding rule of profile v1 §6.2.2, which
/// the strict Bundle check (`cose_receipt`) and the anchor check share.
#[derive(Debug, PartialEq)]
enum ReceiptItem {
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<ReceiptItem>),
    Map(Vec<(ReceiptItem, ReceiptItem)>),
    Tag(u64, Box<ReceiptItem>),
    Bool(bool),
    Null,
}

impl ReceiptItem {
    fn get(&self, key: i128) -> Option<&ReceiptItem> {
        match self {
            ReceiptItem::Map(pairs) => pairs
                .iter()
                .find(|(k, _)| *k == ReceiptItem::Int(key))
                .map(|(_, v)| v),
            _ => None,
        }
    }
}

struct ReceiptReader<'a> {
    data: &'a [u8],
    offset: usize,
    top_tag: bool,
}

impl ReceiptReader<'_> {
    fn take(&mut self, n: u64) -> Option<&[u8]> {
        let end = self.offset.checked_add(usize::try_from(n).ok()?)?;
        let bytes = self.data.get(self.offset..end)?;
        self.offset = end;
        Some(bytes)
    }

    /// The major type and argument, refusing a longer argument, an
    /// indefinite length and every float.
    fn head(&mut self) -> Option<(u8, u64)> {
        let first = self.take(1)?[0];
        let (major, info) = (first >> 5, first & 31);
        let width = match info {
            0..=23 => return Some((major, u64::from(info))),
            24..=27 if major != 7 => 1usize << (info - 24),
            _ => return None,
        };
        let arg = self
            .take(width as u64)?
            .iter()
            .fold(0u64, |arg, byte| arg << 8 | u64::from(*byte));
        (arg >= [24, 1 << 8, 1 << 16, 1 << 32][usize::from(info - 24)]).then_some((major, arg))
    }

    fn item(&mut self, depth: usize) -> Option<ReceiptItem> {
        if depth > MAX_RECEIPT_DEPTH {
            return None;
        }
        let (major, arg) = self.head()?;
        Some(match major {
            0 => ReceiptItem::Int(i128::from(arg)),
            // §6.2.2 admits no integer below -2^63.
            1 if arg <= i64::MAX as u64 => ReceiptItem::Int(-1 - i128::from(arg)),
            2 => ReceiptItem::Bytes(self.take(arg)?.to_vec()),
            3 => ReceiptItem::Text(String::from_utf8(self.take(arg)?.to_vec()).ok()?),
            4 => {
                let mut items = Vec::new();
                for _ in 0..arg {
                    items.push(self.item(depth + 1)?);
                }
                ReceiptItem::Array(items)
            }
            5 => {
                let mut pairs: Vec<(ReceiptItem, ReceiptItem)> = Vec::new();
                // A set, not a scan of `pairs`: a 10 MiB map holds millions
                // of pairs, and a quadratic check would stall on it.
                let mut seen: BTreeSet<Result<i128, String>> = BTreeSet::new();
                for _ in 0..arg {
                    let key = self.item(depth + 1)?;
                    let fresh = match &key {
                        ReceiptItem::Int(i) => seen.insert(Ok(*i)),
                        ReceiptItem::Text(t) => seen.insert(Err(t.clone())),
                        _ => false,
                    };
                    if !fresh {
                        return None;
                    }
                    let value = self.item(depth + 1)?;
                    pairs.push((key, value));
                }
                ReceiptItem::Map(pairs)
            }
            6 if depth == 0 && self.top_tag && arg == 18 => {
                ReceiptItem::Tag(arg, Box::new(self.item(depth + 1)?))
            }
            7 => match arg {
                20 => ReceiptItem::Bool(false),
                21 => ReceiptItem::Bool(true),
                22 => ReceiptItem::Null,
                _ => return None,
            },
            _ => return None,
        })
    }
}

/// One CBOR item under the receipt encoding rule, with no trailing octet:
/// definite lengths, shortest arguments, no repeated key, integer or text
/// keys, valid UTF-8, no float, no simple value but false, true and null, no
/// tag but an outer 18 when `top_tag`, and at most `MAX_RECEIPT_DEPTH` levels.
fn strict_receipt_item(data: &[u8], top_tag: bool) -> Option<ReceiptItem> {
    let mut reader = ReceiptReader {
        data,
        offset: 0,
        top_tag,
    };
    let item = reader.item(0)?;
    (reader.offset == data.len()).then_some(item)
}

fn receipt_path_length(mut size: u64, mut index: u64) -> usize {
    let mut count = 0;
    while size > 1 {
        let k = 1u64 << (63 - (size - 1).leading_zeros());
        if index < k {
            size = k;
        } else {
            (size, index) = (size - k, index - k);
        }
        count += 1;
    }
    count
}

/// Step 1 of profile v1 §6.2.2: the Receipt's `alg` and registration time,
/// or `None` when the octets are not in the one form.
fn parse_anchor_receipt(receipt: &[u8]) -> Option<(Algorithm, Option<u64>)> {
    if receipt.is_empty() || receipt.len() > MAX_RECEIPT_OCTETS {
        return None;
    }
    let ReceiptItem::Tag(18, body) = strict_receipt_item(receipt, true)? else {
        return None;
    };
    let ReceiptItem::Array(parts) = *body else {
        return None;
    };
    let [ReceiptItem::Bytes(protected), unprotected, ReceiptItem::Null, ReceiptItem::Bytes(signature)] =
        parts.as_slice()
    else {
        return None;
    };
    if protected.is_empty() || signature.len() != 64 {
        return None;
    }
    let headers = strict_receipt_item(protected, false)?;
    let ReceiptItem::Map(pairs) = &headers else {
        return None;
    };
    let mut time = None;
    for (label, value) in pairs {
        let ok = match (label, value) {
            (ReceiptItem::Int(1), ReceiptItem::Int(alg)) => *alg == -8 || *alg == -7,
            (ReceiptItem::Int(395), ReceiptItem::Int(vds)) => *vds == 1,
            (ReceiptItem::Int(4), ReceiptItem::Bytes(_)) => true,
            (ReceiptItem::Int(15), claims @ ReceiptItem::Map(_)) => {
                if let Some(ReceiptItem::Int(iat)) = claims.get(i128::from(CWT_IAT)) {
                    time = u64::try_from(*iat).ok().filter(|t| *t <= MAX_IAT);
                }
                true
            }
            (ReceiptItem::Int(label), _) => *label < PRIVATE_LABEL,
            _ => false,
        };
        if !ok {
            return None;
        }
    }
    let alg = match (headers.get(1)?, headers.get(395)?) {
        (ReceiptItem::Int(-8), _) => Algorithm::EdDSA,
        _ => Algorithm::ES256,
    };
    let ReceiptItem::Map(outer) = unprotected else {
        return None;
    };
    let [(ReceiptItem::Int(396), vdp @ ReceiptItem::Map(vdp_pairs))] = outer.as_slice() else {
        return None;
    };
    if vdp_pairs.len() != 1 {
        return None;
    }
    let ReceiptItem::Array(proofs) = vdp.get(-1)? else {
        return None;
    };
    if proofs.is_empty() || proofs.len() > MAX_RECEIPT_PROOFS {
        return None;
    }
    for blob in proofs {
        let ReceiptItem::Bytes(blob) = blob else {
            return None;
        };
        let ReceiptItem::Array(proof) = strict_receipt_item(blob, false)? else {
            return None;
        };
        let [ReceiptItem::Int(size), ReceiptItem::Int(index), ReceiptItem::Array(path)] =
            proof.as_slice()
        else {
            return None;
        };
        let (Ok(size), Ok(index)) = (u64::try_from(*size), u64::try_from(*index)) else {
            return None;
        };
        if index >= size
            || size > MAX_RECEIPT_TREE_SIZE
            || path.len() != receipt_path_length(size, index)
            || !path
                .iter()
                .all(|node| matches!(node, ReceiptItem::Bytes(n) if n.len() == 32))
        {
            return None;
        }
    }
    Some((alg, time))
}

/// Steps 1 to 5 of profile v1 §6.2.2 for one Receipt over the anchor whose
/// digest is `anchor` (64 lowercase hex characters), under the relying
/// party's witness `policy`. The signature is checked as a `scrapi` Receipt
/// is, with the anchor digest's 32 octets as the leaf entry.
pub fn check_anchor_receipt(anchor: &str, receipt: &[u8], policy: &Value) -> AnchorReceiptReport {
    let report = |status, witness, registration_time| AnchorReceiptReport {
        status,
        witness,
        registration_time,
    };
    let leaf = match hex::decode(anchor) {
        Ok(leaf) if leaf.len() == 32 && !anchor.bytes().any(|b| b.is_ascii_uppercase()) => leaf,
        _ => return report("FAIL", None, None),
    };
    let Some((alg, time)) = parse_anchor_receipt(receipt) else {
        return report("FAIL", None, None);
    };
    let keys: Vec<_> = anchor_policy_keys(policy)
        .into_iter()
        .filter(|(_, key_alg, _)| *key_alg == alg)
        .collect();
    if keys.is_empty() {
        return report("NOT_CHECKED", None, None);
    }
    for (name, _, der) in keys {
        if cose_receipt(receipt, &leaf, &der).is_ok() {
            return report("PASS", Some(name), time);
        }
    }
    report("FAIL", None, None)
}

/// `anchor_witnessed` over `receipts`, in the order received, for the anchor
/// `anchor` under `policy` (profile v1 §6.2.2). The anchor's witnessed time
/// is the earliest registration time of a passing Receipt, with that
/// Receipt's witness; the first received wins a tie. With no timed passing
/// Receipt, the first passing one names the witness.
pub fn check_anchor_witnessed(
    anchor: &str,
    receipts: &[Vec<u8>],
    policy: &Value,
) -> AnchorWitnessReport {
    let reports: Vec<_> = receipts
        .iter()
        .map(|receipt| check_anchor_receipt(anchor, receipt, policy))
        .collect();
    let has = |status| reports.iter().any(|r| r.status == status);
    let status = if reports.is_empty() {
        "NOT_PRESENT"
    } else if has("PASS") {
        "PASS"
    } else if has("FAIL") {
        "FAIL"
    } else {
        "NOT_CHECKED"
    };
    let mut chosen: Option<&AnchorReceiptReport> = None;
    for r in reports.iter().filter(|r| r.status == "PASS") {
        let earlier = match (
            r.registration_time,
            chosen.and_then(|c| c.registration_time),
        ) {
            (Some(time), Some(best)) => time < best,
            (Some(_), None) => true,
            (None, _) => false,
        };
        if chosen.is_none() || earlier {
            chosen = Some(r);
        }
    }
    AnchorWitnessReport {
        status,
        witness: chosen.and_then(|c| c.witness.clone()),
        witnessed_time: chosen.and_then(|c| c.registration_time),
        receipts: reports,
    }
}
