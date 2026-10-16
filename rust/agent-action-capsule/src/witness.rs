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
use coset::iana::Algorithm;
use coset::{CoseSign1, Label, RegisteredLabelWithPrivate, TaggedCborSerializable};
use p256::ecdsa::signature::Verifier as _;
use p256::pkcs8::{DecodePublicKey, EncodePublicKey, ObjectIdentifier, SubjectPublicKeyInfoRef};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessReceiptResult {
    pub ts_url: String,
    pub binding: String,
    pub status: String,
    pub reason: String,
    pub grade: Option<String>,
}

/// What [`verify_witness_receipts`] found: the overall `status`, the
/// findings, and one result per well-formed receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessReport {
    pub status: String,
    pub findings: Vec<String>,
    pub receipts: Vec<WitnessReceiptResult>,
}

/// One receipt check: whether it verified, why, and the verified grade. A
/// `reason` starting with `not checked` means nothing was checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptCheck {
    pub ok: bool,
    pub reason: String,
    pub grade: Option<String>,
}

impl ReceiptCheck {
    fn fail(reason: impl Into<String>) -> Self {
        ReceiptCheck {
            ok: false,
            reason: reason.into(),
            grade: None,
        }
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

/// Refuses what the receipt verifier would read differently from this
/// profile: a receipt must be a tag-18 COSE_Sign1 with a detached (`nil`)
/// payload, so its signature covers the rebuilt Merkle root, its protected
/// `vds` (label 395) must be 1 (RFC9162_SHA256), and its `alg` EdDSA (-8) or
/// ES256 (-7). Returns the receipt's `alg`.
fn receipt_shape(receipt: &[u8]) -> Result<Algorithm, String> {
    let sign1 = CoseSign1::from_tagged_slice(receipt)
        .map_err(|e| format!("receipt could not be decoded: {e:?}"))?;
    if sign1.payload.is_some() {
        return Err("receipt payload is attached; a receipt's payload must be detached".into());
    }
    let header = &sign1.protected.header;
    let vds = header
        .rest
        .iter()
        .find(|(label, _)| *label == Label::Int(395))
        .and_then(|(_, value)| value.as_integer());
    if vds != Some(1.into()) {
        return Err("receipt vds is not RFC9162_SHA256 (1)".into());
    }
    match header.alg {
        Some(RegisteredLabelWithPrivate::Assigned(alg @ (Algorithm::EdDSA | Algorithm::ES256))) => {
            Ok(alg)
        }
        _ => Err("receipt alg is not EdDSA (-8) or ES256 (-7)".into()),
    }
}

/// A receipt's `alg` fixes its key type: ES256 verifies only under an ECDSA
/// P-256 key, EdDSA only under an Ed25519 key.
fn key_fits_alg(alg: Algorithm, key_der: &[u8]) -> bool {
    match alg {
        Algorithm::EdDSA => raw_ed25519(key_der).is_some(),
        Algorithm::ES256 => p256::PublicKey::from_public_key_der(key_der).is_ok(),
        _ => false,
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

/// A COSE Receipt over `leaf` under `key_der`, after the shape check.
fn cose_receipt(
    receipt: &[u8],
    leaf: &[u8],
    key_der: &[u8],
) -> Result<scitt_cose_receipt::ReceiptResult, String> {
    let alg = receipt_shape(receipt)?;
    if !key_fits_alg(alg, key_der) {
        return Err(format!(
            "receipt alg {alg:?} does not match the key type (ES256 needs ECDSA P-256, EdDSA Ed25519)"
        ));
    }
    let result = scitt_cose_receipt::verify_receipt(receipt, leaf, &pem(key_der));
    if !result.ok {
        return Err(result.errors.join("; "));
    }
    Ok(result)
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
        Ok(result) => {
            let grade = known_grade(result.grade.as_deref());
            ReceiptCheck {
                ok: true,
                reason: if grade.is_some() {
                    "ok"
                } else {
                    "ok (receipt carries no grade label)"
                }
                .to_string(),
                grade: grade.map(str::to_string),
            }
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
    if let Err(shape) = receipt_shape(receipt) {
        return ReceiptCheck::fail(format!("unreadable receipt: {shape}"));
    }
    let leaf = Sha256::digest(checkpoint_cose);
    match cose_receipt(receipt, &leaf, key) {
        Err(_) => {
            ReceiptCheck::fail("receipt does not verify for this checkpoint under the pinned key")
        }
        Ok(result) => {
            let grade = known_grade(result.grade.as_deref());
            ReceiptCheck {
                ok: true,
                reason: if grade.is_none() && result.grade.is_some() {
                    "ok (unknown grade label ignored)"
                } else {
                    "ok"
                }
                .to_string(),
                grade: Some(grade.unwrap_or(GRADE_OBSERVED_ONLY).to_string()),
            }
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
        };
    }
    verify_scrapi_receipt(&receipt, cose, Some(key_der))
}

fn is_record(entry: &Value) -> Option<&Map<String, Value>> {
    let record = entry.as_object()?;
    (record.get("ts_url").is_some_and(Value::is_string)
        && RECORD_FIELDS
            .iter()
            .all(|field| record.contains_key(*field)))
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
                        for key in keys {
                            check = verify_receipt(signed, record, &key, Some(cose));
                            if check.ok {
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

    #[test]
    fn receipt_vds_and_alg_are_integers() {
        let int = |i: i64| Cbor::Integer(i.into());
        for alg in [-8, -7] {
            let good = receipt(vec![(int(1), int(alg)), (int(395), int(1))], Cbor::Null);
            assert!(receipt_shape(&good).is_ok());
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
            assert!(receipt_shape(&shaped).is_err(), "{protected:?}");
        }
        let attached = receipt(
            vec![(int(1), int(-8)), (int(395), int(1))],
            Cbor::Bytes(vec![1]),
        );
        assert!(receipt_shape(&attached).unwrap_err().contains("attached"));
        assert!(receipt_shape(b"junk").is_err());
    }

    /// The secp256k1 key of the strict vectors' "K1 witness" row.
    const SECP256K1_SPKI_B64: &str = "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEsh20enXO7lwBD2n2bUjVoBfk4vRrR7SW3fA0mMJuHOwSdZkxjbwL+20/X0kVZza/IUgq+4da0Y129p2RKAXz2g==";

    /// A receipt for `leaf` in a one-leaf tree (RFC 9162: the root is
    /// SHA-256(0x00 || leaf)), signed with `alg` by `sign`.
    fn signed_receipt(alg: Algorithm, leaf: &[u8], sign: impl Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
        use coset::{CoseSign1Builder, HeaderBuilder};
        let root = Sha256::digest([&[0u8][..], leaf].concat());
        let proof = cbor(&Cbor::Array(vec![
            Cbor::Integer(1.into()),
            Cbor::Integer(0.into()),
            Cbor::Array(vec![]),
        ]));
        let protected = HeaderBuilder::new()
            .algorithm(alg)
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
