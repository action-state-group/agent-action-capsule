//! The artifact response in the interop profile's form: the signed envelope
//! of `evidence-interop/0` (the repository's `spec/interop-profile-v0.md`
//! §6.2, identifier [`PROFILE`]).
//!
//! -00 says what an artifact response carries (§4.1) but fixes no members
//! and no signature profile for it (ambiguity A12). The profile fixes them,
//! and this module follows it, as the Go (`go/evidencerequest`) and Python
//! (`agent_action_capsule.evidence_request`) implementations do:
//!
//! - The signed members are `profile`, `request_digest`, `subject`,
//!   `derivation` (when present), `anchor` (`{digest}` and, under
//!   `min_freshness`, `freshness`), `artifact_digest`, `verification` (when
//!   there is material: `{kind, digest}` per item), `responder` and
//!   `issued_at`. `sig` is Ed25519 by `responder` over RFC 8785 of those
//!   members ([`Envelope::signing_body`]), the same bytes in either binding.
//! - `artifact` and `verification_content` travel beside the signed members.
//!   Their SHA-256 digests are what is signed.
//! - In the JSON binding the reply is RFC 8785 JSON with byte strings as
//!   unpadded base64url. In the CBOR binding it is core deterministic CBOR
//!   (RFC 8949 §4.2.1) with byte strings ([`Envelope::encode`]).
//!
//! [`sign`] builds and signs one, refusing an envelope the profile does not
//! allow. [`parse_reply`] reads a reply as carried. [`Envelope::verify`]
//! checks the signature and the digests under the envelope's own key.
//! **To accept an envelope as the answer to your request, use
//! [`Envelope::verify_for`]**: it also requires the responder key you
//! expected, your request's digest and the profile identifier.
//!
//! Checking the verification material itself (the Checkpointed Local Log
//! kinds, profile §6.2.1) is the `cll` feature's
//! [`crate::cll_material`]. Building an artifact from a store or a log is the
//! responder's business, not this crate's.

use crate::digest::request_digest;
use crate::registry::is_digest;
use crate::request::{Derivation, Subject};
use crate::time::parse_utc;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// The profile identifier the envelope carries (profile §3.1).
pub const PROFILE: &str = "evidence-interop/0";

/// The largest integer the profile's data model holds exactly: 2^53 - 1.
const MAX_INTEGER: u64 = (1 << 53) - 1;

/// What the resolved anchor attains, in the type the request's
/// `min_freshness` used (profile §6.2; -00 §4.1 item 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorFreshness {
    /// A log size.
    Size(u64),
    /// A time in the profile's form, `YYYY-MM-DDTHH:MM:SSZ` (§5.2).
    Time(String),
}

/// The resolved coverage anchor an envelope names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    /// SHA-256 of the anchor, 64 lowercase hex.
    pub digest: String,
    /// Present only under `min_freshness`.
    pub freshness: Option<AnchorFreshness>,
}

impl Anchor {
    fn to_value(&self) -> Value {
        let mut out = Map::new();
        out.insert("digest".into(), json!(self.digest));
        match &self.freshness {
            Some(AnchorFreshness::Size(n)) => {
                out.insert("freshness".into(), json!(n));
            }
            Some(AnchorFreshness::Time(t)) => {
                out.insert("freshness".into(), json!(t));
            }
            None => {}
        }
        Value::Object(out)
    }
}

/// One item of verification material, named by its kind and the SHA-256 of
/// its octets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationEntry {
    pub kind: String,
    pub digest: String,
}

/// The signed artifact response (profile §6.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub profile: String,
    pub request_digest: String,
    pub subject: Subject,
    pub derivation: Option<Derivation>,
    pub anchor: Anchor,
    pub artifact_digest: String,
    pub verification: Vec<VerificationEntry>,
    /// The responder's Ed25519 public key, 64 lowercase hex.
    pub responder: String,
    pub issued_at: String,
    /// The signature, 128 lowercase hex.
    pub sig: String,
    pub artifact: Vec<u8>,
    /// The octets of each verification item, in the order of
    /// `verification`.
    pub verification_content: Vec<Vec<u8>>,
}

/// A subject as its wire map (-00 §3.1; A1, A6).
pub fn subject_value(subject: &Subject) -> Value {
    match subject {
        Subject::FullHistory => json!({"full_history": null}),
        Subject::Checkpoints => json!({"checkpoints": null}),
        Subject::Record(d) => json!({ "record": d }),
        Subject::Range(a, b) => json!({ "range": [a, b] }),
        Subject::Correlation(c) => json!({ "correlation": c }),
        Subject::Exchange(d) => json!({ "exchange": d }),
    }
}

fn derivation_text(derivation: &Derivation) -> &str {
    match derivation {
        Derivation::Token(t) | Derivation::Digest(t) => t,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

impl Envelope {
    /// The signed members that are present, as a JSON-model map.
    pub fn signed_members(&self) -> Map<String, Value> {
        let mut out = Map::new();
        out.insert("profile".into(), json!(self.profile));
        out.insert("request_digest".into(), json!(self.request_digest));
        out.insert("subject".into(), subject_value(&self.subject));
        out.insert("anchor".into(), self.anchor.to_value());
        out.insert("artifact_digest".into(), json!(self.artifact_digest));
        out.insert("responder".into(), json!(self.responder));
        out.insert("issued_at".into(), json!(self.issued_at));
        if let Some(d) = &self.derivation {
            out.insert("derivation".into(), json!(derivation_text(d)));
        }
        if !self.verification.is_empty() {
            let entries: Vec<Value> = self
                .verification
                .iter()
                .map(|e| json!({"kind": e.kind, "digest": e.digest}))
                .collect();
            out.insert("verification".into(), Value::Array(entries));
        }
        out
    }

    /// The bytes the signature covers: UTF-8 of RFC 8785 over
    /// [`Envelope::signed_members`], whatever the reply's binding.
    pub fn signing_body(&self) -> Vec<u8> {
        crate::jcs::to_string(&Value::Object(self.signed_members()))
            .expect("the signed members hold only text, maps, arrays and integers")
            .into_bytes()
    }

    /// The reply octets in `binding`.
    pub fn encode(&self, binding: Binding) -> Vec<u8> {
        let mut members: Vec<(String, Item)> = self
            .signed_members()
            .into_iter()
            .map(|(k, v)| (k, Item::from_json(&v)))
            .collect();
        members.push(("sig".into(), Item::Text(self.sig.clone())));
        members.push(("artifact".into(), Item::Bytes(self.artifact.clone())));
        if !self.verification_content.is_empty() {
            let items = self
                .verification_content
                .iter()
                .map(|o| Item::Bytes(o.clone()))
                .collect();
            members.push(("verification_content".into(), Item::Array(items)));
        }
        let root = Item::Map(members);
        match binding {
            Binding::Json => crate::jcs::to_string(&root.to_json())
                .expect("the reply holds only text, maps, arrays and integers")
                .into_bytes(),
            Binding::Cbor => {
                let mut out = Vec::new();
                ciborium::into_writer(&root.to_cbor(), &mut out)
                    .expect("writing to a Vec never fails");
                out
            }
        }
    }

    /// Check the envelope under its own `responder` key: the signature
    /// (strict Ed25519: no small-order keys, canonical signatures only), that
    /// the artifact hashes to `artifact_digest`, and that each verification
    /// item hashes to the digest at its position. It does not decide whether
    /// the key is the one you expected or whether the envelope answers your
    /// request: [`Envelope::verify_for`] does.
    pub fn verify(&self) -> Result<(), EnvelopeError> {
        let key = parse_key(&self.responder).ok_or(EnvelopeError::Key)?;
        let sig = parse_sig(&self.sig).ok_or(EnvelopeError::SignatureForm)?;
        key.verify_strict(&self.signing_body(), &sig)
            .map_err(|_| EnvelopeError::Signature)?;
        if sha256_hex(&self.artifact) != self.artifact_digest {
            return Err(EnvelopeError::ArtifactDigest);
        }
        if self.verification.len() != self.verification_content.len() {
            return Err(EnvelopeError::VerificationCount);
        }
        for (i, (entry, octets)) in self
            .verification
            .iter()
            .zip(&self.verification_content)
            .enumerate()
        {
            if sha256_hex(octets) != entry.digest {
                return Err(EnvelopeError::VerificationDigest(i));
            }
        }
        Ok(())
    }

    /// Accept the envelope as the answer of the responder whose key is
    /// `responder_key` to the request whose octets as sent are
    /// `request_bytes`: the profile, the key and the request digest must be
    /// those, and [`Envelope::verify`] must pass. Whether the artifact is the
    /// answer you wanted (its subject, its anchor, its material) is for you
    /// to judge from the verified members.
    pub fn verify_for(
        &self,
        responder_key: &VerifyingKey,
        request_bytes: &[u8],
    ) -> Result<(), EnvelopeError> {
        if self.profile != PROFILE {
            return Err(EnvelopeError::Profile);
        }
        if self.responder != hex::encode(responder_key.to_bytes()) {
            return Err(EnvelopeError::WrongKey);
        }
        if self.request_digest != request_digest(request_bytes) {
            return Err(EnvelopeError::WrongRequest);
        }
        self.verify()
    }
}

/// Why an envelope does not verify, or cannot be accepted.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("responder is not an Ed25519 public key in 64 lowercase hex")]
    Key,
    #[error("sig is not 128 lowercase hex characters")]
    SignatureForm,
    #[error("the signature does not verify under the responder key")]
    Signature,
    #[error("the artifact does not hash to its signed digest")]
    ArtifactDigest,
    #[error("the number of verification entries and items differ")]
    VerificationCount,
    #[error("verification item {0} does not hash to its signed digest")]
    VerificationDigest(usize),
    #[error("the envelope is not the profile's evidence-interop/0")]
    Profile,
    #[error("the envelope is signed by another key than the responder's")]
    WrongKey,
    #[error("the envelope answers another request")]
    WrongRequest,
}

fn parse_key(hex_key: &str) -> Option<VerifyingKey> {
    let bytes: [u8; 32] = lower_hex(hex_key)?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

fn parse_sig(hex_sig: &str) -> Option<Signature> {
    let bytes: [u8; 64] = lower_hex(hex_sig)?.try_into().ok()?;
    Some(Signature::from_bytes(&bytes))
}

fn lower_hex(s: &str) -> Option<Vec<u8>> {
    if s.bytes().any(|c| c.is_ascii_uppercase()) {
        return None;
    }
    hex::decode(s).ok()
}

/// A reply's binding: the request's own encoding (profile §11.4.1 rule 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    Json,
    Cbor,
}

/// Produces raw Ed25519 signatures over the exact bytes given, never a
/// pre-hash, so any key custodian can sign an envelope: an in-process
/// [`SigningKey`], an HSM, a host's own principal.
pub trait Signer {
    /// The public key, 64 lowercase hex.
    fn key_id(&self) -> String;
    /// The signature over `message`.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], String>;
}

impl Signer for SigningKey {
    fn key_id(&self) -> String {
        hex::encode(self.verifying_key().to_bytes())
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], String> {
        Ok(ed25519_dalek::Signer::sign(self, message).to_bytes())
    }
}

/// What an envelope is built from: everything but the request digest, the
/// responder key and the signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeParts {
    /// The request's subject, by value.
    pub subject: Subject,
    /// The request's derivation, when it had one.
    pub derivation: Option<Derivation>,
    pub anchor: Anchor,
    /// The canonical artifact's octets, the same for every requester
    /// (-00 §5).
    pub artifact: Vec<u8>,
    /// `(kind, octets)` per item of verification material, in order.
    pub verification: Vec<(String, Vec<u8>)>,
    pub issued_at: String,
}

/// Why an envelope is not signed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignError {
    #[error("not an envelope a request could ask for: {0}")]
    Subject(&'static str),
    #[error("anchor digest must be 64 lowercase hex")]
    AnchorDigest,
    #[error("artifact must not be empty (profile §6.2)")]
    EmptyArtifact,
    #[error("issued_at must be YYYY-MM-DDTHH:MM:SSZ (profile §5.2)")]
    IssuedAt,
    #[error("freshness must be a size (0 to 2^53 - 1) or a YYYY-MM-DDTHH:MM:SSZ time")]
    Freshness,
    #[error("a verification kind must be non-empty text")]
    Kind,
    #[error("the signer signed under a key other than its key_id")]
    SignerKey,
    #[error("the signer failed: {0}")]
    Signer(String),
}

/// Build and sign the profile envelope for an artifact served in answer to
/// the request whose octets as received are `request_bytes`. Refuses,
/// before anything is signed, an envelope the profile does not allow: a
/// subject or derivation a request could not carry, an anchor that is not a
/// digest, an empty artifact, an `issued_at` or time freshness outside the
/// §5.2 form, or a size freshness outside the profile's integers.
pub fn sign(
    request_bytes: &[u8],
    parts: EnvelopeParts,
    signer: &dyn Signer,
) -> Result<Envelope, SignError> {
    check_subject(&parts.subject).map_err(SignError::Subject)?;
    if let Some(d) = &parts.derivation {
        check_derivation(d).map_err(SignError::Subject)?;
    }
    if !is_digest(&parts.anchor.digest) {
        return Err(SignError::AnchorDigest);
    }
    if parts.artifact.is_empty() {
        return Err(SignError::EmptyArtifact);
    }
    if !is_profile_time(&parts.issued_at) {
        return Err(SignError::IssuedAt);
    }
    match &parts.anchor.freshness {
        Some(AnchorFreshness::Size(n)) if *n > MAX_INTEGER => return Err(SignError::Freshness),
        Some(AnchorFreshness::Time(t)) if !is_profile_time(t) => return Err(SignError::Freshness),
        _ => {}
    }
    if parts.verification.iter().any(|(kind, _)| kind.is_empty()) {
        return Err(SignError::Kind);
    }
    let mut envelope = Envelope {
        profile: PROFILE.to_string(),
        request_digest: request_digest(request_bytes),
        subject: parts.subject,
        derivation: parts.derivation,
        anchor: parts.anchor,
        artifact_digest: sha256_hex(&parts.artifact),
        verification: parts
            .verification
            .iter()
            .map(|(kind, octets)| VerificationEntry {
                kind: kind.clone(),
                digest: sha256_hex(octets),
            })
            .collect(),
        responder: signer.key_id(),
        issued_at: parts.issued_at,
        sig: String::new(),
        artifact: parts.artifact,
        verification_content: parts.verification.into_iter().map(|(_, o)| o).collect(),
    };
    let sig = signer
        .sign(&envelope.signing_body())
        .map_err(SignError::Signer)?;
    let key = parse_key(&envelope.responder).ok_or(SignError::SignerKey)?;
    if key
        .verify_strict(&envelope.signing_body(), &Signature::from_bytes(&sig))
        .is_err()
    {
        return Err(SignError::SignerKey);
    }
    envelope.sig = hex::encode(sig);
    Ok(envelope)
}

/// The profile's time form (§5.2): `YYYY-MM-DDTHH:MM:SSZ`, naming a real
/// instant, with no fraction.
pub fn is_profile_time(s: &str) -> bool {
    s.len() == 20 && parse_utc(s).is_some()
}

fn check_subject(subject: &Subject) -> Result<(), &'static str> {
    match subject {
        Subject::FullHistory | Subject::Checkpoints => Ok(()),
        Subject::Record(d) | Subject::Exchange(d) if is_digest(d) => Ok(()),
        Subject::Record(_) | Subject::Exchange(_) => Err("subject digest is not 64 lowercase hex"),
        Subject::Range(a, b) if a > b => Err("range start is after its end"),
        Subject::Range(_, b) if *b > MAX_INTEGER => Err("range is not two profile integers"),
        Subject::Range(..) => Ok(()),
        Subject::Correlation(c) if c.is_empty() => Err("correlation is not non-empty text"),
        Subject::Correlation(_) => Ok(()),
    }
}

fn check_derivation(derivation: &Derivation) -> Result<(), &'static str> {
    match crate::request::derivation_from_text(derivation_text(derivation)) {
        Ok(read) if read == *derivation => Ok(()),
        _ => Err("derivation is neither a registered token form nor a digest"),
    }
}

/// A reply as carried: exactly one of an envelope or a refusal (profile §1,
/// "Message type").
#[derive(Clone, Debug, PartialEq)]
pub enum Reply {
    Envelope(Box<Envelope>),
    /// The refusal object in the JSON data model, for
    /// [`crate::refusal::verify_for`].
    Refusal(Value),
}

/// Why reply octets are not a reply this crate can authenticate.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReplyError {
    #[error("the reply is not well formed in its binding: {0}")]
    Encoding(&'static str),
    #[error("the reply is not a map")]
    NotAMap,
    #[error("the reply carries both artifact_digest and reason")]
    Both,
    #[error("the reply is neither an envelope nor a refusal (a transport condition)")]
    Neither,
    #[error("the envelope member {0} is missing or has the wrong type")]
    Member(&'static str),
}

/// Read reply octets as carried in `binding`: a map carrying
/// `artifact_digest` is an envelope, one carrying `reason` a refusal. In the
/// CBOR binding the reply must be in core deterministic encoding; in the
/// JSON binding byte strings are unpadded base64url and a duplicate member
/// name makes the reply unreadable.
pub fn parse_reply(octets: &[u8], binding: Binding) -> Result<Reply, ReplyError> {
    let root = match binding {
        Binding::Json => Item::from_json_octets(octets)?,
        Binding::Cbor => {
            crate::det_cbor::check_reply(octets).map_err(ReplyError::Encoding)?;
            let value: ciborium::Value = ciborium::from_reader(octets)
                .map_err(|_| ReplyError::Encoding("not well-formed CBOR"))?;
            Item::from_cbor(&value).ok_or(ReplyError::Encoding("not the profile's data model"))?
        }
    };
    let Item::Map(members) = root else {
        return Err(ReplyError::NotAMap);
    };
    let get = |name: &str| members.iter().find(|(k, _)| k == name).map(|(_, v)| v);
    match (get("artifact_digest").is_some(), get("reason").is_some()) {
        (true, true) => Err(ReplyError::Both),
        (false, false) => Err(ReplyError::Neither),
        (false, true) => Ok(Reply::Refusal(Item::Map(members).to_json())),
        (true, false) => read_envelope(&members, binding).map(|e| Reply::Envelope(Box::new(e))),
    }
}

fn read_envelope(members: &[(String, Item)], binding: Binding) -> Result<Envelope, ReplyError> {
    let get = |name: &str| members.iter().find(|(k, _)| k == name).map(|(_, v)| v);
    let text = |name: &'static str| match get(name) {
        Some(Item::Text(s)) => Ok(s.clone()),
        _ => Err(ReplyError::Member(name)),
    };
    let bytes = |item: &Item| -> Option<Vec<u8>> {
        match (binding, item) {
            (Binding::Cbor, Item::Bytes(b)) => Some(b.clone()),
            (Binding::Json, Item::Text(s)) => decode_base64url(s),
            _ => None,
        }
    };
    let subject_json = get("subject")
        .ok_or(ReplyError::Member("subject"))?
        .to_json();
    let subject = crate::request::subject_from_value(&subject_json)
        .map_err(|_| ReplyError::Member("subject"))?;
    let derivation = match get("derivation") {
        None => None,
        Some(Item::Text(s)) => Some(
            crate::request::derivation_from_text(s)
                .map_err(|_| ReplyError::Member("derivation"))?,
        ),
        Some(_) => return Err(ReplyError::Member("derivation")),
    };
    let anchor = match get("anchor") {
        Some(Item::Map(a)) => {
            let mut digest = None;
            let mut freshness = None;
            for (k, v) in a {
                match (k.as_str(), v) {
                    ("digest", Item::Text(s)) => digest = Some(s.clone()),
                    ("freshness", Item::UInt(n)) => freshness = Some(AnchorFreshness::Size(*n)),
                    ("freshness", Item::Text(t)) => {
                        freshness = Some(AnchorFreshness::Time(t.clone()))
                    }
                    _ => return Err(ReplyError::Member("anchor")),
                }
            }
            Anchor {
                digest: digest.ok_or(ReplyError::Member("anchor"))?,
                freshness,
            }
        }
        _ => return Err(ReplyError::Member("anchor")),
    };
    let verification = match get("verification") {
        None => Vec::new(),
        Some(Item::Array(entries)) => entries
            .iter()
            .map(|entry| match entry {
                Item::Map(m) if m.len() == 2 => {
                    let field = |n: &str| {
                        m.iter().find(|(k, _)| k == n).and_then(|(_, v)| match v {
                            Item::Text(s) => Some(s.clone()),
                            _ => None,
                        })
                    };
                    Some(VerificationEntry {
                        kind: field("kind")?,
                        digest: field("digest")?,
                    })
                }
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(ReplyError::Member("verification"))?,
        Some(_) => return Err(ReplyError::Member("verification")),
    };
    let artifact = get("artifact")
        .and_then(bytes)
        .ok_or(ReplyError::Member("artifact"))?;
    let verification_content = match get("verification_content") {
        None => Vec::new(),
        Some(Item::Array(items)) => items
            .iter()
            .map(bytes)
            .collect::<Option<Vec<_>>>()
            .ok_or(ReplyError::Member("verification_content"))?,
        Some(_) => return Err(ReplyError::Member("verification_content")),
    };
    Ok(Envelope {
        profile: text("profile")?,
        request_digest: text("request_digest")?,
        subject,
        derivation,
        anchor,
        artifact_digest: text("artifact_digest")?,
        verification,
        responder: text("responder")?,
        issued_at: text("issued_at")?,
        sig: text("sig")?,
        artifact,
        verification_content,
    })
}

fn decode_base64url(s: &str) -> Option<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD.decode(s).ok()?;
    // Only the one canonical form: re-encoding must give the same text.
    (URL_SAFE_NO_PAD.encode(&decoded) == s).then_some(decoded)
}

/// The profile's data model (§4): the JSON model plus byte strings, with
/// maps in member order as read. Integers are unsigned and at most 2^53 - 1.
#[derive(Clone, Debug, PartialEq)]
enum Item {
    Null,
    Bool(bool),
    UInt(u64),
    Text(String),
    Bytes(Vec<u8>),
    Array(Vec<Item>),
    Map(Vec<(String, Item)>),
}

impl Item {
    fn from_json(v: &Value) -> Item {
        match v {
            Value::Null => Item::Null,
            Value::Bool(b) => Item::Bool(*b),
            Value::Number(n) => {
                Item::UInt(n.as_u64().expect("the envelope's integers are unsigned"))
            }
            Value::String(s) => Item::Text(s.clone()),
            Value::Array(a) => Item::Array(a.iter().map(Item::from_json).collect()),
            Value::Object(o) => Item::Map(
                o.iter()
                    .map(|(k, v)| (k.clone(), Item::from_json(v)))
                    .collect(),
            ),
        }
    }

    /// Read JSON octets, refusing a duplicate member name at any depth and
    /// any number that is not a profile integer.
    fn from_json_octets(octets: &[u8]) -> Result<Item, ReplyError> {
        use serde::de::{Deserializer as _, MapAccess, SeqAccess, Visitor};
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Item;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a value in the profile's data model")
            }
            fn visit_unit<E>(self) -> Result<Item, E> {
                Ok(Item::Null)
            }
            fn visit_bool<E>(self, b: bool) -> Result<Item, E> {
                Ok(Item::Bool(b))
            }
            fn visit_u64<E: serde::de::Error>(self, n: u64) -> Result<Item, E> {
                if n > MAX_INTEGER {
                    return Err(E::custom("an integer above 2^53 - 1"));
                }
                Ok(Item::UInt(n))
            }
            fn visit_i64<E: serde::de::Error>(self, n: i64) -> Result<Item, E> {
                u64::try_from(n)
                    .map_err(|_| E::custom("a negative integer"))
                    .and_then(|u| self.visit_u64(u))
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Item, E> {
                Err(E::custom("a number that is not an integer"))
            }
            fn visit_str<E>(self, s: &str) -> Result<Item, E> {
                Ok(Item::Text(s.to_string()))
            }
            fn visit_string<E>(self, s: String) -> Result<Item, E> {
                Ok(Item::Text(s))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Item, A::Error> {
                let mut out = Vec::new();
                while let Some(item) = seq.next_element_seed(Seed)? {
                    out.push(item);
                }
                Ok(Item::Array(out))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Item, A::Error> {
                let mut out: Vec<(String, Item)> = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    if out.iter().any(|(k, _)| *k == key) {
                        return Err(serde::de::Error::custom("a duplicate member name"));
                    }
                    let value = map.next_value_seed(Seed)?;
                    out.push((key, value));
                }
                Ok(Item::Map(out))
            }
        }
        struct Seed;
        impl<'de> serde::de::DeserializeSeed<'de> for Seed {
            type Value = Item;
            fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Item, D::Error> {
                d.deserialize_any(V)
            }
        }
        let mut de = serde_json::Deserializer::from_slice(octets);
        let item = de
            .deserialize_any(V)
            .map_err(|_| ReplyError::Encoding("not JSON in the profile's data model"))?;
        de.end()
            .map_err(|_| ReplyError::Encoding("bytes after the reply"))?;
        Ok(item)
    }

    /// From a decoded CBOR item already checked deterministic: `None` for
    /// anything outside the data model.
    fn from_cbor(v: &ciborium::Value) -> Option<Item> {
        use ciborium::Value as C;
        Some(match v {
            C::Null => Item::Null,
            C::Bool(b) => Item::Bool(*b),
            C::Integer(i) => Item::UInt(u64::try_from(*i).ok()?),
            C::Text(s) => Item::Text(s.clone()),
            C::Bytes(b) => Item::Bytes(b.clone()),
            C::Array(a) => Item::Array(a.iter().map(Item::from_cbor).collect::<Option<_>>()?),
            C::Map(entries) => Item::Map(
                entries
                    .iter()
                    .map(|(k, v)| match k {
                        C::Text(key) => Some((key.clone(), Item::from_cbor(v)?)),
                        _ => None,
                    })
                    .collect::<Option<_>>()?,
            ),
            _ => return None,
        })
    }

    /// The JSON binding's form: byte strings as unpadded base64url.
    fn to_json(&self) -> Value {
        match self {
            Item::Null => Value::Null,
            Item::Bool(b) => json!(b),
            Item::UInt(n) => json!(n),
            Item::Text(s) => json!(s),
            Item::Bytes(b) => json!(URL_SAFE_NO_PAD.encode(b)),
            Item::Array(a) => Value::Array(a.iter().map(Item::to_json).collect()),
            Item::Map(m) => {
                Value::Object(m.iter().map(|(k, v)| (k.clone(), v.to_json())).collect())
            }
        }
    }

    /// The CBOR binding's form, with every map's keys in the bytewise order
    /// of their encodings (RFC 8949 §4.2.1).
    fn to_cbor(&self) -> ciborium::Value {
        use ciborium::Value as C;
        match self {
            Item::Null => C::Null,
            Item::Bool(b) => C::Bool(*b),
            Item::UInt(n) => C::Integer((*n).into()),
            Item::Text(s) => C::Text(s.clone()),
            Item::Bytes(b) => C::Bytes(b.clone()),
            Item::Array(a) => C::Array(a.iter().map(Item::to_cbor).collect()),
            Item::Map(m) => {
                let mut entries: Vec<(Vec<u8>, C, C)> = m
                    .iter()
                    .map(|(k, v)| {
                        let key = C::Text(k.clone());
                        let mut encoded = Vec::new();
                        ciborium::into_writer(&key, &mut encoded)
                            .expect("writing to a Vec never fails");
                        (encoded, key, v.to_cbor())
                    })
                    .collect();
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                C::Map(entries.into_iter().map(|(_, k, v)| (k, v)).collect())
            }
        }
    }
}
