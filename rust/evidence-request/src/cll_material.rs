//! `anchor_inclusion` for Checkpointed Local Log material: the requester's
//! check of the three verification-material kinds of the interop profile
//! (`spec/interop-profile-v0.md` §6.2.1, steps 1 to 14). Feature `cll`.
//!
//! The material proves that an artifact's digest is an entry committed under
//! a signed checkpoint, the envelope's anchor:
//!
//! - `cll-checkpoint`: the checkpoint as a tagged COSE_Sign1 with an empty
//!   unprotected header and an attached CBOR claims map;
//! - `cll-inclusion-proof`: deterministic CBOR of `[index, inclusion-path]`;
//! - `cll-consistency-proof` (optional): deterministic CBOR of
//!   `[tree-size-1, tree-size-2, consistency-paths, right-peaks]`, proving
//!   that the checkpoint's `commitment` extends its own `prev_commitment`.
//!
//! The MMR hashing (a leaf is SHA-256(0x00 || entry), an interior node
//! SHA-256(position || left || right)) and the commitment's peak list come
//! from `checkpointed-local-log`, the reference implementation of the log;
//! the walks of the pinned MMR revision (`included_root`,
//! `consistent_roots`) are written here from that draft, as the Go and
//! Python implementations write them.
//!
//! Which log key is the right one for a log identity is the relying party's
//! policy ([`LogKeyPolicy`]), not the profile's. Building the material from
//! a log is the responder's business, not this crate's.

use crate::envelope::{AnchorFreshness, Envelope};
use crate::request::Subject;
use ciborium::Value as C;
use cll::mmr::{decode_commitment_object, height_at, interior_hash, leaf_hash, Hash};
use ed25519_dalek::{Signature, VerifyingKey};

/// `cll-checkpoint`: CLL's own string for the checkpoint's `kind` claim.
pub const KIND_CHECKPOINT: &str = "cll-checkpoint";
/// `cll-inclusion-proof`: the profile's identifier for an MMR inclusion
/// proof (P-31).
pub const KIND_INCLUSION: &str = "cll-inclusion-proof";
/// `cll-consistency-proof`: the profile's identifier for an MMR consistency
/// proof (P-31).
pub const KIND_CONSISTENCY: &str = "cll-consistency-proof";

pub use crate::status::Status;

/// The outcome of the check: a status, the method when it was checked, and
/// a short reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub status: Status,
    /// The pinned drafts and the checks run, set on `Pass`.
    pub method: Option<String>,
    pub detail: String,
}

fn report(status: Status, detail: impl Into<String>) -> Report {
    Report {
        status,
        method: None,
        detail: detail.into(),
    }
}

/// The relying party's answer for a checkpoint key (step 9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyDecision {
    /// The policy accepts this Ed25519 key for the log identity.
    Accept(VerifyingKey),
    /// The policy rejects the key: `FAIL`.
    Reject,
    /// The policy cannot resolve the key's status: `INCONCLUSIVE`.
    Unknown,
    /// The policy excludes the check: `NOT_CHECKED`.
    Excluded,
}

/// Resolves a checkpoint's (`iss`, `sub`, `kid`) to the key the relying
/// party accepts for that log identity as of the checkpoint's `issued_at`.
pub trait LogKeyPolicy {
    fn resolve(&self, iss: &str, sub: &str, kid: &[u8], issued_at: &str) -> KeyDecision;
}

/// The checkpoint's members the procedure uses, read from a well-formed
/// `cll-checkpoint` item.
struct Checkpoint {
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
    alg: i128,
    crit: bool,
    kid: Vec<u8>,
    iss: String,
    sub: String,
    log_size: u64,
    prev_size: u64,
    issued_at: String,
    commitment: Vec<Hash>,
    prev_commitment: Vec<Hash>,
}

/// Run `anchor_inclusion` (profile §6.2.1, steps 1 to 14) on a parsed
/// envelope. The envelope's own signature and digests are checked first
/// (step 4): material that is not bound to a verified envelope is never
/// checked. Whether the envelope's responder is the one you expected is
/// [`Envelope::verify_for`]'s question, not this one's.
pub fn check_anchor_inclusion(envelope: &Envelope, policy: &dyn LogKeyPolicy) -> Report {
    // An envelope of another profile is not checked under this one (§7.3).
    if envelope.profile != crate::envelope::PROFILE {
        return report(Status::NotChecked, "the envelope is not evidence-interop/0");
    }
    // Step 1.
    let record = match &envelope.subject {
        Subject::Record(d) if envelope.derivation.is_none() => d,
        _ => {
            return report(
                Status::NotChecked,
                "no kind in this revision proves this subject or derivation",
            )
        }
    };
    // Step 2.
    if envelope.verification.is_empty() {
        return report(
            Status::NotPresent,
            "the envelope carries no verification material",
        );
    }
    // Step 3: an unimplemented kind first, then a repeated one.
    let slot = |kind: &str| match kind {
        KIND_CHECKPOINT => Some(0),
        KIND_INCLUSION => Some(1),
        KIND_CONSISTENCY => Some(2),
        _ => None,
    };
    if let Some(entry) = envelope
        .verification
        .iter()
        .find(|e| slot(&e.kind).is_none())
    {
        return report(
            Status::NotChecked,
            format!("kind {:?} is not implemented", entry.kind),
        );
    }
    let mut at = [None, None, None];
    for (i, entry) in envelope.verification.iter().enumerate() {
        let k = slot(&entry.kind).expect("every kind is one of the three");
        if at[k].replace(i).is_some() {
            return report(
                Status::Fail,
                format!("kind {:?} appears more than once", entry.kind),
            );
        }
    }
    let (Some(cp_at), Some(incl_at)) = (at[0], at[1]) else {
        return report(
            Status::NotPresent,
            "no cll-checkpoint or no cll-inclusion-proof entry",
        );
    };
    // Step 4.
    if envelope.verify().is_err() {
        return report(
            Status::NotChecked,
            "the envelope does not verify, so its material is not checked",
        );
    }
    // Step 5.
    if *record != envelope.artifact_digest {
        return report(
            Status::NotChecked,
            "subject.record is not the artifact's own digest",
        );
    }
    // Step 6.
    if envelope.verification[cp_at].digest != envelope.anchor.digest {
        return report(Status::Fail, "the cll-checkpoint entry is not the anchor");
    }
    // Step 7.
    let cp = match read_checkpoint(&envelope.verification_content[cp_at]) {
        Ok(cp) => cp,
        Err(why) => return report(Status::Fail, format!("checkpoint: {why}")),
    };
    // Step 8.
    if cp.alg != -8 || cp.crit {
        return report(
            Status::NotChecked,
            "only Ed25519 checkpoints with no critical extensions are checked",
        );
    }
    // Step 9.
    if cp.kid.len() != 32 {
        return report(Status::Fail, "kid is not a 32-octet Ed25519 public key");
    }
    let key = match policy.resolve(&cp.iss, &cp.sub, &cp.kid, &cp.issued_at) {
        KeyDecision::Accept(key) => key,
        KeyDecision::Reject => {
            return report(Status::Fail, "the policy rejects the checkpoint key")
        }
        KeyDecision::Unknown => {
            return report(
                Status::Inconclusive,
                "the policy cannot resolve the checkpoint key",
            )
        }
        KeyDecision::Excluded => {
            return report(Status::NotChecked, "the policy excludes the check")
        }
    };
    // Step 10.
    let Ok(signature) = <[u8; 64]>::try_from(cp.signature.as_slice()) else {
        return report(Status::Fail, "the checkpoint signature is not 64 octets");
    };
    let to_be_signed = sig_structure(&cp.protected, &cp.payload);
    if key
        .verify_strict(&to_be_signed, &Signature::from_bytes(&signature))
        .is_err()
    {
        return report(Status::Fail, "the checkpoint signature does not verify");
    }
    // Step 11.
    match &envelope.anchor.freshness {
        Some(AnchorFreshness::Size(n)) if *n != cp.log_size => {
            return report(
                Status::Fail,
                "anchor.freshness is not the checkpoint's log_size",
            )
        }
        Some(AnchorFreshness::Time(t))
            if Some(t.as_str()) != utc_seconds(&cp.issued_at).as_deref() =>
        {
            return report(
                Status::Fail,
                "anchor.freshness is not the checkpoint's issued_at",
            )
        }
        _ => {}
    }
    // Step 12.
    let entry: Hash = match hex::decode(&envelope.artifact_digest)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(e) => e,
        None => return report(Status::Fail, "artifact_digest is not a digest"),
    };
    if let Err(why) = check_inclusion(
        &cp.commitment,
        &entry,
        &envelope.verification_content[incl_at],
    ) {
        return report(Status::Fail, format!("inclusion: {why}"));
    }
    let mut method = "CLL-01 checkpoint (Ed25519) + MMR-02 inclusion".to_string();
    // Step 13.
    if let Some(cons_at) = at[2] {
        if cp.prev_size == 0 {
            return report(
                Status::Fail,
                "consistency: the checkpoint extends no earlier commitment",
            );
        }
        if let Err(why) = check_consistency(
            &cp.prev_commitment,
            &cp.commitment,
            &envelope.verification_content[cons_at],
        ) {
            return report(Status::Fail, format!("consistency: {why}"));
        }
        method.push_str(" + MMR-02 consistency");
    }
    // Step 14.
    Report {
        status: Status::Pass,
        method: Some(method),
        detail: "the artifact's digest is committed under the anchor checkpoint".into(),
    }
}

/// The COSE `Signature1` Sig_structure with an empty external AAD
/// (RFC 9052 §4.4).
fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let structure = C::Array(vec![
        C::Text("Signature1".into()),
        C::Bytes(protected.to_vec()),
        C::Bytes(Vec::new()),
        C::Bytes(payload.to_vec()),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&structure, &mut out).expect("writing to a Vec never fails");
    out
}

/// One CBOR item from `bytes`, with nothing after it.
fn one_item(bytes: &[u8]) -> Result<C, &'static str> {
    let mut reader = bytes;
    let value: C = ciborium::from_reader(&mut reader).map_err(|_| "not well-formed CBOR")?;
    if !reader.is_empty() {
        return Err("bytes after the item");
    }
    Ok(value)
}

/// A map's entries. Duplicate keys are refused for the whole item first
/// ([`no_duplicate_keys`]).
fn map_entries(value: &C) -> Result<&[(C, C)], &'static str> {
    match value {
        C::Map(entries) => Ok(entries),
        _ => Err("not a map"),
    }
}

/// The deepest nesting walked for duplicate keys; ciborium's own decoder
/// stops well before this.
const MAX_DEPTH: usize = 256;

/// True when no map at any depth of `value` repeats a key. Keys compare by
/// their encodings, sorted, so a map of n keys costs n log n.
fn no_duplicate_keys(value: &C, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }
    match value {
        C::Map(entries) => {
            let mut keys: Vec<Vec<u8>> = entries
                .iter()
                .map(|(k, _)| {
                    let mut out = Vec::new();
                    ciborium::into_writer(k, &mut out).expect("writing to a Vec never fails");
                    out
                })
                .collect();
            keys.sort_unstable();
            keys.windows(2).all(|w| w[0] != w[1])
                && entries.iter().all(|(k, v)| {
                    no_duplicate_keys(k, depth + 1) && no_duplicate_keys(v, depth + 1)
                })
        }
        C::Array(items) => items.iter().all(|v| no_duplicate_keys(v, depth + 1)),
        C::Tag(_, inner) => no_duplicate_keys(inner, depth + 1),
        _ => true,
    }
}

/// One CBOR item with no duplicate map key at any depth.
fn one_item_unique(bytes: &[u8]) -> Result<C, &'static str> {
    let value = one_item(bytes)?;
    if no_duplicate_keys(&value, 0) {
        Ok(value)
    } else {
        Err("a map with a duplicate key")
    }
}

fn int_key(entries: &[(C, C)], label: i128) -> Option<&C> {
    entries.iter().find_map(|(k, v)| match k {
        C::Integer(i) if i128::from(*i) == label => Some(v),
        _ => None,
    })
}

fn text_key<'a>(entries: &'a [(C, C)], name: &str) -> Option<&'a C> {
    entries.iter().find_map(|(k, v)| match k {
        C::Text(t) if t == name => Some(v),
        _ => None,
    })
}

fn uint(value: Option<&C>) -> Option<u64> {
    match value {
        Some(C::Integer(i)) => u64::try_from(*i).ok(),
        _ => None,
    }
}

/// Step 7: decode a `cll-checkpoint` item, refusing every form the
/// procedure calls `FAIL`.
fn read_checkpoint(octets: &[u8]) -> Result<Checkpoint, &'static str> {
    let C::Tag(18, inner) = one_item_unique(octets)? else {
        return Err("not a tag 18 COSE_Sign1");
    };
    let C::Array(parts) = *inner else {
        return Err("not a four-element array");
    };
    let [C::Bytes(protected), unprotected, payload, C::Bytes(signature)] = parts.as_slice() else {
        return Err("not a four-element array of the COSE_Sign1 types");
    };
    if !map_entries(unprotected)?.is_empty() {
        return Err("the unprotected header is not empty");
    }
    let C::Bytes(payload) = payload else {
        return Err("the payload is detached or not a byte string");
    };
    let header = one_item_unique(protected)?;
    let header = map_entries(&header)?;
    let alg = match int_key(header, 1) {
        Some(C::Integer(i)) => i128::from(*i),
        _ => return Err("the protected header lacks alg"),
    };
    let kid = match int_key(header, 4) {
        Some(C::Bytes(k)) => k.clone(),
        _ => return Err("the protected header lacks kid"),
    };
    let claims = int_key(header, 15).ok_or("the protected header lacks CWT_Claims")?;
    let claims = map_entries(claims)?;
    let (Some(C::Text(iss)), Some(C::Text(sub))) = (int_key(claims, 1), int_key(claims, 2)) else {
        return Err("CWT_Claims lacks iss or sub");
    };
    let body = one_item_unique(payload)?;
    let body = map_entries(&body)?;
    if !matches!(text_key(body, "kind"), Some(C::Text(k)) if k == KIND_CHECKPOINT) {
        return Err("the kind claim is not cll-checkpoint");
    }
    let profile_int = |name: &str| uint(text_key(body, name)).filter(|n| *n <= MAX_INTEGER);
    let log_size = profile_int("log_size").ok_or("log_size is not a profile integer")?;
    let prev_size = profile_int("prev_size").ok_or("prev_size is not a profile integer")?;
    if prev_size > log_size {
        return Err("prev_size exceeds log_size");
    }
    let issued_at = match text_key(body, "issued_at") {
        Some(C::Text(t)) if utc_seconds(t).is_some() => t.clone(),
        _ => return Err("issued_at is not an RFC 3339 text string"),
    };
    let peaks = |name: &str, allow_empty: bool| -> Result<Vec<Hash>, &'static str> {
        let Some(C::Bytes(raw)) = text_key(body, name) else {
            return Err("a commitment is not a byte string");
        };
        if raw.is_empty() && allow_empty {
            return Ok(Vec::new());
        }
        match decode_commitment_object(raw) {
            Ok(list) if !list.is_empty() && list.len() <= MAX_PROOF_NODES => Ok(list),
            _ => Err("a commitment is not the deterministic CBOR of one or more 32-octet peaks"),
        }
    };
    let commitment = peaks("commitment", false)?;
    let prev_commitment = if prev_size == 0 {
        match text_key(body, "prev_commitment") {
            Some(C::Bytes(raw)) if raw.is_empty() => Vec::new(),
            _ => return Err("prev_size is 0 and prev_commitment is not zero-length"),
        }
    } else {
        peaks("prev_commitment", false)?
    };
    Ok(Checkpoint {
        protected: protected.clone(),
        payload: payload.clone(),
        signature: signature.clone(),
        alg,
        crit: int_key(header, 2).is_some(),
        kid,
        iss: iss.clone(),
        sub: sub.clone(),
        log_size,
        prev_size,
        issued_at,
        commitment,
        prev_commitment,
    })
}

/// An RFC 3339 date-time (`date-time` of RFC 3339 §5.6, `T`/`Z` in either
/// case) converted to UTC with any fraction dropped, in the profile's form
/// (`YYYY-MM-DDTHH:MM:SSZ`), or `None` when it is not one. A leap second
/// (`:60`) names the instant after second 59, as the Python reference reads
/// it.
fn utc_seconds(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let digits = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = b.get(range)?;
        if part.is_empty() || !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        part.iter()
            .try_fold(0i64, |n, d| Some(n * 10 + i64::from(d - b'0')))
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let second = digits(17..19)?;
    if second > 60 {
        return None;
    }
    let mut at = 19;
    if b.get(at) == Some(&b'.') {
        let n = b[at + 1..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count();
        if n == 0 {
            return None;
        }
        at += 1 + n;
    }
    let offset_seconds = match &b[at..] {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let (hours, minutes) = (digits(at + 1..at + 3)?, digits(at + 4..at + 6)?);
            if hours > 23 || minutes > 59 {
                return None;
            }
            let magnitude = hours * 3600 + minutes * 60;
            if *sign == b'+' {
                magnitude
            } else {
                -magnitude
            }
        }
        _ => return None,
    };
    let base = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        digits(0..4)?,
        digits(5..7)?,
        digits(8..10)?,
        digits(11..13)?,
        digits(14..16)?,
        second.min(59)
    );
    let instant = crate::time::parse_utc(&base)?;
    format_utc(instant.seconds + i64::from(second == 60) - offset_seconds)
}

/// Seconds since the epoch in the profile's time form.
fn format_utc(seconds: i64) -> Option<String> {
    let days = seconds.div_euclid(86_400);
    let secs = seconds.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    if !(0..=9999).contains(&year) {
        return None;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    ))
}

/// The most nodes any proof list may hold: no MMR the profile can address
/// has more peaks or a longer path.
const MAX_PROOF_NODES: usize = 64;

/// The greatest node height in an MMR whose indices are profile integers
/// (below 2^53). A longer path names no node of such an MMR.
const MAX_MMR_HEIGHT: u64 = 52;

/// The largest profile integer.
const MAX_INTEGER: u64 = (1 << 53) - 1;

fn index_height(index: u64) -> u64 {
    u64::from(height_at(index))
}

fn path_fits(index: u64, len: usize) -> bool {
    index <= MAX_INTEGER && index_height(index) + len as u64 <= MAX_MMR_HEIGHT
}

/// MMR-02 `included_root` (§5.2): the root reached from the node at
/// zero-based `index` by `path`. Callers check [`path_fits`] first.
fn included_root(mut index: u64, node: Hash, path: &[Hash]) -> Hash {
    let mut root = node;
    for (g, sibling) in (index_height(index)..).zip(path) {
        if index_height(index + 1) > g {
            index += 1;
            root = interior_hash(sibling, &root, index);
        } else {
            index += 2 << g;
            root = interior_hash(&root, sibling, index);
        }
    }
    root
}

/// MMR-02 `peaks` (§7.1.1): the zero-based indices of the peaks of the MMR
/// whose last node is at `last`.
fn peak_indices(last: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut peak = 0u64;
    let mut size = last + 1;
    while size > 0 {
        let highest = (1u64 << (63 - (size + 1).leading_zeros())) - 1;
        peak += highest;
        out.push(peak - 1);
        size -= highest;
    }
    out
}

/// The zero-based MMR node index of zero-based leaf `leaf`, or `None` when it
/// is not a profile integer.
fn leaf_node_index(leaf: u64) -> Option<u64> {
    let index = leaf.checked_mul(2)? - u64::from(leaf.count_ones());
    (index <= MAX_INTEGER).then_some(index)
}

fn encode_cbor(value: &C) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("writing to a Vec never fails");
    out
}

fn hash_list(nodes: &[Hash]) -> C {
    C::Array(nodes.iter().map(|n| C::Bytes(n.to_vec())).collect())
}

/// The `cll-inclusion-proof` octets for zero-based leaf `leaf` and its
/// inclusion path (the siblings from the leaf up to its peak): deterministic
/// CBOR of `[MMR node index, inclusion-path]` (profile §6.2.1). This encodes
/// a path a log already computed; computing it is the log's. `None` when the
/// leaf's node index is not a profile integer or the path is longer than any
/// MMR can have.
pub fn encode_inclusion_proof(leaf: u64, path: &[Hash]) -> Option<Vec<u8>> {
    let index = leaf_node_index(leaf)?;
    if !path_fits(index, path.len()) {
        return None;
    }
    Some(encode_cbor(&C::Array(vec![
        C::Integer(index.into()),
        hash_list(path),
    ])))
}

/// The `cll-consistency-proof` octets proving that the MMR of `old_size`
/// nodes, whose peaks are `old_peaks`, extends to the MMR of `new_size` nodes
/// whose peaks are `new_peaks`, given each old peak's path into the new MMR:
/// deterministic CBOR of `[tree-size-1, tree-size-2, consistency-paths,
/// right-peaks]` (profile §6.2.1; MMR §6). `None` when the paths do not
/// reach `new_peaks`, so no such proof exists.
pub fn encode_consistency_proof(
    old_size: u64,
    new_size: u64,
    old_peaks: &[Hash],
    paths: &[Vec<Hash>],
    new_peaks: &[Hash],
) -> Option<Vec<u8>> {
    if old_size == 0
        || old_size > new_size
        || new_size > MAX_INTEGER
        || old_peaks.len() != paths.len()
        || paths.len() > MAX_PROOF_NODES
        || new_peaks.len() > MAX_PROOF_NODES
    {
        return None;
    }
    let mut roots: Vec<Hash> = Vec::new();
    for ((index, path), peak) in peak_indices(old_size - 1)
        .into_iter()
        .zip(paths)
        .zip(old_peaks)
    {
        if !path_fits(index, path.len()) {
            return None;
        }
        let root = included_root(index, *peak, path);
        if roots.last() != Some(&root) {
            roots.push(root);
        }
    }
    if roots.len() > new_peaks.len() || roots[..] != new_peaks[..roots.len()] {
        return None;
    }
    let octets = encode_cbor(&C::Array(vec![
        C::Integer(old_size.into()),
        C::Integer(new_size.into()),
        C::Array(paths.iter().map(|p| hash_list(p)).collect()),
        hash_list(&new_peaks[roots.len()..]),
    ]));
    check_consistency(old_peaks, new_peaks, &octets).ok()?;
    Some(octets)
}

/// A deterministic-CBOR proof's list of 32-octet byte strings.
fn hashes(value: &C) -> Option<Vec<Hash>> {
    let C::Array(items) = value else {
        return None;
    };
    if items.len() > MAX_PROOF_NODES {
        return None;
    }
    items
        .iter()
        .map(|item| match item {
            C::Bytes(b) => <Hash>::try_from(b.as_slice()).ok(),
            _ => None,
        })
        .collect()
}

fn proof_parts(octets: &[u8], n: usize) -> Result<Vec<C>, &'static str> {
    crate::det_cbor::check_reply(octets).map_err(|_| "not deterministic CBOR")?;
    match one_item(octets)? {
        C::Array(parts) if parts.len() == n => Ok(parts),
        _ => Err("not the proof's array"),
    }
}

/// Step 12: `entry` is a leaf whose inclusion path reaches one of `peaks`.
fn check_inclusion(peaks: &[Hash], entry: &Hash, octets: &[u8]) -> Result<(), &'static str> {
    let parts = proof_parts(octets, 2)?;
    let index = uint(Some(&parts[0])).ok_or("malformed")?;
    let path = hashes(&parts[1]).ok_or("malformed")?;
    if index_height(index) != 0 {
        return Err("the index is not a leaf");
    }
    if !path_fits(index, path.len()) {
        return Err("the path is longer than any MMR can have");
    }
    let root = included_root(index, leaf_hash(entry), &path);
    if peaks.contains(&root) {
        Ok(())
    } else {
        Err("the path reaches no peak of the checkpoint")
    }
}

/// Step 13: `new_peaks` extends `old_peaks` by the consistency proof.
fn check_consistency(
    old_peaks: &[Hash],
    new_peaks: &[Hash],
    octets: &[u8],
) -> Result<(), &'static str> {
    let parts = proof_parts(octets, 4)?;
    let size1 = uint(Some(&parts[0])).ok_or("malformed")?;
    let size2 = uint(Some(&parts[1])).ok_or("malformed")?;
    let C::Array(raw_paths) = &parts[2] else {
        return Err("malformed");
    };
    let right = hashes(&parts[3]).ok_or("malformed")?;
    if size1 == 0 || size1 > size2 || size2 > MAX_INTEGER || raw_paths.len() > MAX_PROOF_NODES {
        return Err("malformed");
    }
    let paths = raw_paths
        .iter()
        .map(hashes)
        .collect::<Option<Vec<_>>>()
        .ok_or("malformed")?;
    let old_indices = peak_indices(size1 - 1);
    if old_indices.len() != paths.len() || old_indices.len() != old_peaks.len() {
        return Err("the proof does not match the earlier commitment");
    }
    let mut roots: Vec<Hash> = Vec::new();
    for ((index, path), peak) in old_indices.iter().zip(&paths).zip(old_peaks) {
        if !path_fits(*index, path.len()) {
            return Err("a path is longer than any MMR can have");
        }
        let root = included_root(*index, *peak, path);
        if roots.last() != Some(&root) {
            roots.push(root);
        }
    }
    let new_count = peak_indices(size2 - 1).len();
    if right.len() + roots.len() != new_count {
        return Err("the proof has the wrong number of right peaks");
    }
    roots.extend(right);
    if roots == new_peaks {
        Ok(())
    } else {
        Err("the proof does not reach the checkpoint's commitment")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmr_walks_match_the_pinned_draft() {
        // MMR-02's eleven-node example: peaks of the MMR ending at index 10
        // are 6, 9, 10; index 7 is a leaf, 6 has height 2.
        assert_eq!(peak_indices(10), vec![6, 9, 10]);
        assert_eq!(peak_indices(0), vec![0]);
        assert_eq!(index_height(7), 0);
        assert_eq!(index_height(6), 2);
        assert_eq!(index_height(13), 2);
    }

    #[test]
    fn utc_seconds_normalises_offsets_and_fractions() {
        assert_eq!(
            utc_seconds("2026-10-15T00:00:00Z").as_deref(),
            Some("2026-10-15T00:00:00Z")
        );
        assert_eq!(
            utc_seconds("2026-10-15T00:00:00.999Z").as_deref(),
            Some("2026-10-15T00:00:00Z")
        );
        assert_eq!(
            utc_seconds("2026-10-15T01:30:00+01:30").as_deref(),
            Some("2026-10-15T00:00:00Z")
        );
        assert_eq!(
            utc_seconds("2026-10-14T23:00:00-01:00").as_deref(),
            Some("2026-10-15T00:00:00Z")
        );
        assert_eq!(utc_seconds("2026-10-15 00:00:00Z"), None);
        assert_eq!(utc_seconds("yesterday"), None);
    }
}
