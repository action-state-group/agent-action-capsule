//! The Evidence Bundle producer (feature `strict`): [`build_evidence_bundle`]
//! assembles a Bundle from a [`ProofSource`] and checks the result with
//! [`verify_bundle_strict`] before returning it. Port of the Python
//! reference's `build_evidence_bundle`.
//!
//! The producer holds no key and trusts nothing the source returns: the
//! checkpoint is verified from its COSE form, every claimed producer envelope
//! is verified over its Capsule ID, and every proof and record is checked by
//! the strict verifier.

use super::SELECTION_PRODUCER_SELECTED;
use super::{
    bundle_digest, is_str, padding_leaf, parse_inclusion_proof, parse_range_proof, PADDING,
};
use super::{citation_targets, committed_digest, verify_bundle_strict, StrictOptions, B64};
use crate::canonical::MAX_SAFE_INTEGER;
use crate::disclosure;
use crate::envelope;
use crate::json::{exceeds_depth, MAX_DEPTH};
use crate::verify::decode_capsule_json;
use base64::Engine as _;
use cll::log::{CheckpointStateStore, EntrySource, MAX_SCAN_LIMIT};
use cll::mmr::{self, MemoryNodeStore, NodeAppender};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

const BUNDLE_KIND: &str = "evidence-bundle/v2";

/// Extension kinds this crate owns; [`BuildOptions::extensions`] cannot set
/// them.
const OWNED_EXTENSIONS: [&str; 2] = ["producer-key/v1", "composed/v1"];

type BoxedError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The producer refused to build the Bundle. The message names the refusal;
/// a failure of the source's own store is kept as [`std::error::Error::source`].
#[derive(Debug)]
pub struct BuildError {
    message: String,
    source: Option<BoxedError>,
}

impl BuildError {
    /// A refusal with `message`.
    pub fn new(message: impl Into<String>) -> Self {
        BuildError {
            message: message.into(),
            source: None,
        }
    }

    /// A refusal caused by `source`, for example a store failure.
    pub fn with_source(message: impl Into<String>, source: impl Into<BoxedError>) -> Self {
        BuildError {
            message: message.into(),
            source: Some(source.into()),
        }
    }

    /// The message, without the source.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)?;
        if let Some(source) = &self.source {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

/// A record as a store holds it: the Capsule's JSON bytes and its Producer
/// Envelope bytes (empty when the record is unsigned).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredRecord {
    pub capsule: Vec<u8>,
    pub producer_envelope: Vec<u8>,
}

/// An inclusion proof in the Bundle's `memberships[].inclusion_proof` wire
/// shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub v: u32,
    pub kind: String,
    /// The MMR size the proof is against.
    pub size: u64,
    /// The leaf's 0-based index (`seq - 1`).
    pub leaf_index: u64,
    pub witness: Vec<String>,
    pub peaks_left: Vec<String>,
    pub peaks_right: Vec<String>,
}

impl InclusionProof {
    fn to_value(&self) -> Value {
        json!({
            "v": self.v,
            "kind": self.kind,
            "size": self.size,
            "leaf_index": self.leaf_index,
            "witness": self.witness,
            "peaks_left": self.peaks_left,
            "peaks_right": self.peaks_right,
        })
    }
}

/// A range proof in the Bundle's `completeness_certificate.range_proof` wire
/// shape: leaves `from_seq..=to_seq` (1-based) at MMR `size`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeProof {
    pub from_seq: u64,
    pub to_seq: u64,
    pub size: u64,
    pub from_index: u64,
    pub to_index: u64,
    pub witness: Vec<String>,
}

impl RangeProof {
    fn to_value(&self) -> Value {
        json!({
            "from_seq": self.from_seq,
            "to_seq": self.to_seq,
            "size": self.size,
            "from_index": self.from_index,
            "to_index": self.to_index,
            "witness": self.witness,
        })
    }
}

/// The read-only proof material [`build_evidence_bundle`] reads. Proofs are
/// in the Bundle's own wire shape, so an implementer never handles a CLL
/// type. The producer trusts none of it.
pub trait ProofSource {
    /// The signed CLL COSE checkpoint the Bundle is built against.
    fn checkpoint(&self) -> Result<Vec<u8>, BuildError>;

    /// The 32-byte value of every leaf, seq `1` to `leaf_count(mmr_size)`, in
    /// order; a record's value is its Capsule ID.
    fn leaves(&self) -> Result<Vec<[u8; 32]>, BuildError>;

    /// The stored record, or `None` when the log does not hold that leaf as a
    /// record. Any other failure is an error.
    fn record(&self, capsule_id: &str) -> Result<Option<StoredRecord>, BuildError>;

    /// The inclusion proof for leaf `seq` at the checkpoint's size.
    fn inclusion_proof(&self, seq: u64) -> Result<InclusionProof, BuildError>;

    /// The range proof over `[first_seq, tip]`.
    fn range_proof(&self, first_seq: u64) -> Result<RangeProof, BuildError>;

    /// Optional capability: the content of the leaf at `seq` when it is not a
    /// record (a padding record's four members), or `None` when the source
    /// does not hold it. [`build_evidence_bundle`] reads it only with
    /// [`BuildOptions::carry_non_record_leaves`]; a source that does not
    /// implement it builds exactly as before.
    fn leaf_content(&self, _seq: u64) -> Result<Option<Value>, BuildError> {
        Ok(None)
    }
}

/// A record store [`proof_source_from_cll`] reads records from.
pub trait RecordSource {
    /// The store's failure.
    type Error: std::error::Error + Send + Sync + 'static;

    /// The record with Capsule ID `id`; `Ok(None)` only when the store does
    /// not hold it. Every other failure is an error, which the producer
    /// passes on.
    fn get_record(&self, id: &str) -> Result<Option<StoredRecord>, Self::Error>;
}

impl<R: RecordSource + ?Sized> RecordSource for &R {
    type Error = R::Error;

    fn get_record(&self, id: &str) -> Result<Option<StoredRecord>, Self::Error> {
        (**self).get_record(id)
    }
}

/// The checkpoint a CLL backend's state holds.
struct CllCheckpoint {
    bytes: Vec<u8>,
    size: u64,
}

/// [`proof_source_from_cll`]'s source: a snapshot of a CLL backend's latest
/// checkpoint state and the entries it covers, with records from a
/// [`RecordSource`].
pub struct CllProofSource<R> {
    checkpoint: Option<CllCheckpoint>,
    nodes: MemoryNodeStore,
    entries: Vec<Vec<u8>>,
    records: R,
}

/// A [`ProofSource`] over a CLL backend (`scan_entries` and `load_cll`) and a
/// record store. The backend is read once, here: its latest checkpoint
/// state, and the entries that checkpoint covers, so every proof comes from
/// one consistent snapshot. The proofs are built from the state's MMR nodes
/// at the checkpoint's size. Build a fresh source to prove a later
/// checkpoint. A backend with no checkpoint gives a source the producer
/// refuses.
pub fn proof_source_from_cll<B, R>(backend: &B, records: R) -> Result<CllProofSource<R>, BuildError>
where
    B: EntrySource + CheckpointStateStore + ?Sized,
    R: RecordSource,
{
    let state = backend
        .load_cll()
        .map_err(|e| BuildError::with_source("reading the log's checkpoint state", e))?;
    let mut nodes = MemoryNodeStore::new();
    let mut hashes = Vec::with_capacity(state.nodes.len());
    for node in &state.nodes {
        let hash: mmr::Hash = node
            .as_slice()
            .try_into()
            .map_err(|_| BuildError::new("the log's state holds a node that is not 32 bytes"))?;
        hashes.push(hash);
    }
    nodes.append_nodes(&hashes);
    let covered = state.checkpoint.as_ref().map_or(0, |cp| cp.indexed_seq);
    let mut entries: Vec<Vec<u8>> = Vec::new();
    while (entries.len() as u64) < covered {
        let want = (covered - entries.len() as u64).min(MAX_SCAN_LIMIT as u64) as usize;
        let page = backend
            .scan_entries(entries.len() as u64, want)
            .map_err(|e| BuildError::with_source("reading the log's entries", e))?;
        if page.is_empty() {
            break;
        }
        entries.extend(page.into_iter().map(|entry| entry.value));
    }
    Ok(CllProofSource {
        checkpoint: state.checkpoint.map(|cp| CllCheckpoint {
            bytes: cp.bytes,
            size: cp.size,
        }),
        nodes,
        entries,
        records,
    })
}

impl<R> CllProofSource<R> {
    fn signed_size(&self) -> Result<u64, BuildError> {
        self.checkpoint
            .as_ref()
            .map(|cp| cp.size)
            .ok_or_else(no_checkpoint)
    }
}

fn no_checkpoint() -> BuildError {
    BuildError::new("the log has no checkpoint: nothing can be proven until one is cut")
}

impl<R: RecordSource> ProofSource for CllProofSource<R> {
    fn checkpoint(&self) -> Result<Vec<u8>, BuildError> {
        self.checkpoint
            .as_ref()
            .map(|cp| cp.bytes.clone())
            .ok_or_else(no_checkpoint)
    }

    fn leaves(&self) -> Result<Vec<[u8; 32]>, BuildError> {
        self.entries
            .iter()
            .enumerate()
            .map(|(index, value)| {
                value.as_slice().try_into().map_err(|_| {
                    BuildError::new(format!(
                        "the log's entry at seq {} is not 32 bytes",
                        index + 1
                    ))
                })
            })
            .collect()
    }

    fn record(&self, capsule_id: &str) -> Result<Option<StoredRecord>, BuildError> {
        self.records.get_record(capsule_id).map_err(|e| {
            BuildError::with_source(format!("record {capsule_id}: the record store failed"), e)
        })
    }

    fn inclusion_proof(&self, seq: u64) -> Result<InclusionProof, BuildError> {
        let size = self.signed_size()?;
        let proof = seq
            .checked_sub(1)
            .ok_or_else(|| BuildError::new("seq 0 is not a leaf"))
            .and_then(|index| {
                mmr::inclusion_proof(&self.nodes, index, size).map_err(|e| {
                    BuildError::with_source(format!("inclusion proof for seq {seq}"), e)
                })
            })?;
        Ok(InclusionProof {
            v: proof.v,
            kind: proof.kind,
            size: proof.size,
            leaf_index: proof.leaf_index,
            witness: proof.witness,
            peaks_left: proof.peaks_left,
            peaks_right: proof.peaks_right,
        })
    }

    fn range_proof(&self, first_seq: u64) -> Result<RangeProof, BuildError> {
        let size = self.signed_size()?;
        let fail = |e: mmr::MmrError| {
            BuildError::with_source(format!("range proof from seq {first_seq}"), e)
        };
        let tip = mmr::leaf_count(size).map_err(fail)?;
        if first_seq == 0 || first_seq > tip {
            return Err(BuildError::new(format!(
                "range proof from seq {first_seq}: outside 1..={tip}"
            )));
        }
        let proof = cll::range_proof::range_proof(&self.nodes, first_seq - 1, tip - 1, size)
            .map_err(fail)?;
        Ok(RangeProof {
            from_seq: first_seq,
            to_seq: tip,
            size: proof.size,
            from_index: proof.from_index,
            to_index: proof.to_index,
            witness: proof.witness,
        })
    }
}

/// Where the Bundle's range proof starts. It has no default:
/// [`BuildOptions::new`] takes it, so a caller states either a range or its
/// absence and never hands over the whole log by omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interval {
    /// A range proof from this seq to the checkpoint tip, carrying every
    /// record in `[seq, tip]` and none below it. `From(1)` is the whole log.
    From(u64),
    /// No range proof: only the chosen records, each with its own inclusion
    /// proof, under `completeness.selection: "producer-selected"`, which
    /// strict verification reads as INCOMPLETE.
    ProducerSelected,
}

/// `completeness.payloads_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadsMode {
    All,
    Selected,
}

impl PayloadsMode {
    fn as_str(self) -> &'static str {
        match self {
            PayloadsMode::All => "all",
            PayloadsMode::Selected => "selected",
        }
    }
}

/// Options of [`build_evidence_bundle`]. [`BuildOptions::new`] takes the two
/// required ones; every other field has the draft's default and may be set
/// directly.
#[derive(Debug, Clone, PartialEq)]
pub struct BuildOptions {
    /// The Capsule ID the Bundle is built around.
    pub root: String,
    /// The range proof's first seq, or [`Interval::ProducerSelected`].
    pub interval_from: Interval,
    /// The citation depth from `root`; the draft's default is 2.
    pub closure_depth: u64,
    /// Further records to carry.
    pub include: Vec<String>,
    /// The Bundle-level `disclosures` overlay: Capsule ID to revealed members.
    pub disclosures: BTreeMap<String, Map<String, Value>>,
    /// Disclosure-eligible members declared suppressed.
    pub suppressed_fields: Vec<String>,
    /// Declared `payloads_mode`; `None` derives it from the overlay. A declared
    /// `All` must reveal every committed, unsuppressed member of each record
    /// the overlay discloses.
    pub payloads_mode: Option<PayloadsMode>,
    /// A raw Ed25519 public key, added as `producer-key/v1`.
    pub producer_key: Option<[u8; 32]>,
    /// Extension blocks of any kind except `producer-key/v1` and
    /// `composed/v1`.
    pub extensions: Map<String, Value>,
    /// The producer's self-report (`verification`), carried as given.
    pub verification: Option<Map<String, Value>>,
    /// Lets a range cover a padding leaf: the source's
    /// [`ProofSource::leaf_content`] is carried in
    /// `completeness_certificate.non_record_leaves` (Bundle -02). Off by
    /// default because a verifier that predates -02 reads such a Bundle as
    /// missing those seqs; turn it on only for readers that check the member.
    pub carry_non_record_leaves: bool,
}

impl BuildOptions {
    /// Options for a Bundle around `root` with `interval_from`, and the
    /// defaults for everything else.
    pub fn new(root: impl Into<String>, interval_from: Interval) -> Self {
        BuildOptions {
            root: root.into(),
            interval_from,
            closure_depth: 2,
            include: Vec::new(),
            disclosures: BTreeMap::new(),
            suppressed_fields: Vec::new(),
            payloads_mode: None,
            producer_key: None,
            extensions: Map::new(),
            verification: None,
            carry_non_record_leaves: false,
        }
    }
}

/// Options of [`build_unproven_bundle`].
#[derive(Debug, Clone, PartialEq)]
pub struct UnprovenOptions {
    pub root: String,
    pub closure_depth: u64,
    pub disclosures: BTreeMap<String, Map<String, Value>>,
    pub suppressed_fields: Vec<String>,
}

impl UnprovenOptions {
    /// Options for a Bundle around `root`, with the defaults for everything
    /// else.
    pub fn new(root: impl Into<String>) -> Self {
        UnprovenOptions {
            root: root.into(),
            closure_depth: 2,
            disclosures: BTreeMap::new(),
            suppressed_fields: Vec::new(),
        }
    }
}

fn is_eligible(member: &str) -> bool {
    disclosure::disclosure_eligible_field(member).is_some()
}

/// Whether caller input placed `offset` levels below the Bundle object would
/// take the Bundle past the verifier's depth limit. Checked before any
/// recursive clone of the input.
fn too_deep(value: &Value, offset: usize) -> bool {
    exceeds_depth(value, MAX_DEPTH.saturating_sub(offset))
}

fn deep_input(what: &str) -> BuildError {
    BuildError::new(format!(
        "{what} nests arrays and objects deeper than the Bundle's {MAX_DEPTH}-level limit"
    ))
}

fn check_options(
    closure_depth: u64,
    disclosures: &BTreeMap<String, Map<String, Value>>,
    suppressed_fields: &[String],
    extensions: &Map<String, Value>,
    verification: Option<&Map<String, Value>>,
) -> Result<(), BuildError> {
    if closure_depth > MAX_SAFE_INTEGER as u64 {
        return Err(BuildError::new(format!(
            "closure_depth must be a safe integer (at most {MAX_SAFE_INTEGER})"
        )));
    }
    // bundle > disclosures > capsule ID > member > value
    for (cid, members) in disclosures {
        if members.values().any(|v| too_deep(v, 3)) {
            return Err(deep_input(&format!("disclosures[{cid}]")));
        }
    }
    // bundle > extensions > kind > value
    if let Some(kind) = extensions
        .iter()
        .find(|(_, v)| too_deep(v, 2))
        .map(|(k, _)| k)
    {
        return Err(deep_input(&format!("extensions[{kind}]")));
    }
    // bundle > verification > member > value
    if verification.is_some_and(|v| v.values().any(|v| too_deep(v, 2))) {
        return Err(deep_input("verification"));
    }
    let ineligible: BTreeSet<&str> = suppressed_fields
        .iter()
        .map(String::as_str)
        .filter(|m| !is_eligible(m))
        .collect();
    if !ineligible.is_empty() {
        return Err(BuildError::new(format!(
            "suppressed_fields names members that are not disclosure-eligible: {ineligible:?}"
        )));
    }
    for (cid, members) in disclosures {
        let bad: BTreeSet<&str> = members
            .keys()
            .map(String::as_str)
            .filter(|m| !is_eligible(m))
            .collect();
        if !bad.is_empty() {
            return Err(BuildError::new(format!(
                "disclosures[{cid}] names members that are not disclosure-eligible: {bad:?}"
            )));
        }
        let both: BTreeSet<&str> = members
            .keys()
            .map(String::as_str)
            .filter(|m| suppressed_fields.iter().any(|s| s == m))
            .collect();
        if !both.is_empty() {
            return Err(BuildError::new(format!(
                "disclosures[{cid}] reveals member(s) declared suppressed: {both:?}"
            )));
        }
    }
    let owned: Vec<&str> = OWNED_EXTENSIONS
        .into_iter()
        .filter(|kind| extensions.contains_key(*kind))
        .collect();
    if !owned.is_empty() {
        return Err(BuildError::new(format!(
            "extensions cannot set kinds this producer owns: {owned:?}"
        )));
    }
    Ok(())
}

type Record = Map<String, Value>;

/// Records reached from `root` within `depth` citation edges (root
/// included), and the targets `lookup` does not hold, in first-seen order:
/// the traversal [`super::verify_bundle`] checks graph closure with.
fn closure(
    root: &str,
    depth: u64,
    mut lookup: impl FnMut(&str) -> Result<Option<Record>, BuildError>,
) -> Result<(HashMap<String, Record>, Vec<String>), BuildError> {
    let root_record =
        lookup(root)?.ok_or_else(|| BuildError::new(format!("root {root}: no such record")))?;
    let mut found = HashMap::from([(root.to_string(), root_record)]);
    let mut missing: Vec<String> = Vec::new();
    let mut missing_set: HashSet<String> = HashSet::new();
    let mut frontier = vec![root.to_string()];
    let mut level = 0;
    while level < depth && !frontier.is_empty() {
        let mut next = Vec::new();
        for source in &frontier {
            let targets = citation_targets(&found[source]);
            for target in targets {
                if found.contains_key(&target) || missing_set.contains(&target) {
                    continue;
                }
                match lookup(&target)? {
                    Some(record) => {
                        found.insert(target.clone(), record);
                        next.push(target);
                    }
                    None => {
                        missing_set.insert(target.clone());
                        missing.push(target);
                    }
                }
            }
        }
        frontier = next;
        level += 1;
    }
    Ok((found, missing))
}

fn committed_members(record: &Record) -> BTreeSet<&'static str> {
    disclosure::ELIGIBLE_MEMBERS
        .into_iter()
        .filter(|member| {
            let path = disclosure::disclosure_eligible_field(member).expect("eligible member");
            committed_digest(record, path).is_some()
        })
        .collect()
}

fn completeness(
    records: &[&Record],
    closure_depth: u64,
    missing: &[String],
    disclosures: &BTreeMap<String, Map<String, Value>>,
    suppressed_fields: &[String],
    payloads_mode: Option<PayloadsMode>,
) -> Result<Map<String, Value>, BuildError> {
    let suppressed: BTreeSet<&str> = suppressed_fields.iter().map(String::as_str).collect();
    let mut unrevealed: Vec<(String, &'static str)> = Vec::new();
    for record in records {
        let cid = record
            .get("capsule_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        for member in committed_members(record) {
            let revealed = disclosures
                .get(cid)
                .is_some_and(|members| members.contains_key(member));
            if !suppressed.contains(member) && !revealed {
                unrevealed.push((cid.to_string(), member));
            }
        }
    }
    if payloads_mode == Some(PayloadsMode::All) && !disclosures.is_empty() {
        let gaps: Vec<String> = unrevealed
            .iter()
            .filter(|(cid, _)| disclosures.contains_key(cid))
            .map(|(cid, member)| format!("{cid}:{member}"))
            .collect();
        if !gaps.is_empty() {
            return Err(BuildError::new(format!(
                "payloads_mode all, but the disclosures overlay does not reveal: {gaps:?}"
            )));
        }
    }
    // Vacuously `all` when no carried record commits an unsuppressed member.
    let mode = payloads_mode.unwrap_or(if unrevealed.is_empty() {
        PayloadsMode::All
    } else {
        PayloadsMode::Selected
    });
    let mut out = Map::new();
    out.insert("closure_depth".into(), json!(closure_depth));
    out.insert(
        "records_mode".into(),
        json!(if missing.is_empty() {
            "complete"
        } else {
            "declared_incomplete"
        }),
    );
    out.insert("payloads_mode".into(), json!(mode.as_str()));
    out.insert("suppressed_fields".into(), json!(suppressed));
    out.insert("missing".into(), json!(missing));
    Ok(out)
}

/// The stored record as a Bundle carries it: the Capsule, with any inline
/// `signature` and `key_id` removed and a claimed Producer Envelope
/// re-inlined as those local-only members (both outside the `capsule_id`
/// preimage).
fn decode_record(capsule_id: &str, stored: &StoredRecord) -> Result<Record, BuildError> {
    let capsule = decode_capsule_json(&stored.capsule).map_err(|e| {
        BuildError::new(format!(
            "record {capsule_id}: the stored capsule is not a JSON object ({e:?})"
        ))
    })?;
    let mut capsule = match capsule {
        Value::Object(map) => map,
        _ => {
            return Err(BuildError::new(format!(
                "record {capsule_id}: the stored capsule is not a JSON object"
            )))
        }
    };
    if capsule.get("capsule_id").and_then(Value::as_str) != Some(capsule_id) {
        return Err(BuildError::new(format!(
            "record {capsule_id}: the store returned a different capsule"
        )));
    }
    // The stored envelope alone decides the signature: an inline claim in the
    // stored JSON is dropped, so an empty envelope always reads unsigned.
    capsule.remove("signature");
    capsule.remove("key_id");
    if !stored.producer_envelope.is_empty() {
        let checked = envelope::verify(capsule_id, &stored.producer_envelope);
        if !checked.ok || checked.public_key.is_empty() {
            return Err(BuildError::new(format!(
                "record {capsule_id}: its producer envelope does not verify"
            )));
        }
        capsule.insert(
            "signature".into(),
            json!(hex::encode(&stored.producer_envelope)),
        );
        capsule.insert("key_id".into(), json!(hex::encode(&checked.public_key)));
    }
    Ok(capsule)
}

/// The source's content for the non-record leaf at `seq`, when it is a
/// padding record whose recomputed `capsule_id` is that leaf; `None` when the
/// source holds nothing for `seq`. Any other content is refused by name: the
/// producer carries padding only.
fn padding_content<S: ProofSource + ?Sized>(
    source: &S,
    seq: u64,
    leaf_hex: &str,
) -> Result<Option<Value>, BuildError> {
    let Some(stored) = source.leaf_content(seq)? else {
        return Ok(None);
    };
    let mut content = match stored {
        Value::Object(content) if is_str(content.get("record_type"), PADDING) => content,
        _ => {
            return Err(BuildError::new(format!(
                "seq {seq}: the source's leaf content is not a padding record; a range cannot \
                 cover it"
            )))
        }
    };
    // Local-only producer envelope members are outside the leaf's preimage.
    content.remove("signature");
    content.remove("key_id");
    let leaf = padding_leaf(&content).ok_or_else(|| {
        BuildError::new(format!(
            "seq {seq}: the padding record has no canonical digest"
        ))
    })?;
    if leaf != leaf_hex || !is_str(content.get("capsule_id"), leaf_hex) {
        return Err(BuildError::new(format!(
            "seq {seq}: the padding record does not hash to the leaf"
        )));
    }
    Ok(Some(Value::Object(content)))
}

/// Builds an Evidence Bundle around `options.root` from `source`.
///
/// With [`Interval::From`]`(N)` the Bundle carries every record in
/// `[N, tip]` and none below N, with a range proof ending at the checkpoint
/// tip; with [`Interval::ProducerSelected`] it carries only the chosen
/// records, each proven alone. `closure_depth` is the citation depth from
/// `root`; `include` names further records to carry. A citation the source
/// does not hold is stated in `completeness.missing`, and an empty producer
/// envelope leaves the record unsigned; both read INCOMPLETE, not refused.
///
/// Refuses, by name: a checkpoint that does not verify, a leaf count that
/// disagrees with it, a stored capsule for a different ID, a claimed envelope
/// that does not verify, a range over a leaf that is not a record, a carried
/// record below N, a record past the checkpoint, an overlay for a record not
/// carried, an ineligible or suppressed overlay member, an owned extension
/// kind, a `closure_depth` past 2^53-1, caller input nested past the
/// Bundle's depth limit, a malformed source proof, a Bundle with no
/// canonical digest, and any result [`verify_bundle_strict`] calls INVALID
/// (a wrong proof, a tampered record). An inline `signature`/`key_id` in the
/// stored capsule is dropped: only the stored envelope signs a record. A source's store failure is passed on as the
/// error's source.
pub fn build_evidence_bundle<S: ProofSource + ?Sized>(
    source: &S,
    options: &BuildOptions,
) -> Result<Value, BuildError> {
    let BuildOptions {
        root,
        interval_from,
        closure_depth,
        include,
        disclosures,
        suppressed_fields,
        payloads_mode,
        producer_key,
        extensions,
        verification,
        carry_non_record_leaves,
    } = options;
    check_options(
        *closure_depth,
        disclosures,
        suppressed_fields,
        extensions,
        verification.as_ref(),
    )?;
    let interval_from =
        match *interval_from {
            Interval::From(0) => return Err(BuildError::new(
                "interval_from must be a seq of at least 1, or ProducerSelected for no range proof",
            )),
            Interval::From(n) => Some(n),
            Interval::ProducerSelected => None,
        };

    let cose = source.checkpoint()?;
    let checked = cll::checkpoint::verify_checkpoint_cose_offline(&cose);
    let signed = match checked.decoded {
        Some(decoded) if checked.ok => decoded,
        _ => {
            return Err(BuildError::new(format!(
                "the checkpoint does not verify: {}",
                checked.errors.join("; ")
            )))
        }
    };
    let tip = mmr::leaf_count(signed.mmr_size)
        .map_err(|e| BuildError::with_source("the checkpoint's mmr_size is not an MMR size", e))?;
    let leaves = source.leaves()?;
    if leaves.len() as u64 != tip {
        return Err(BuildError::new(format!(
            "the source gave {} leaves; the checkpoint covers {tip} 32-byte leaves",
            leaves.len()
        )));
    }
    let leaf_hex: Vec<String> = leaves.iter().map(hex::encode).collect();
    let mut seq_of: HashMap<String, u64> = HashMap::new();
    for (index, value) in leaf_hex.iter().enumerate() {
        seq_of.entry(value.clone()).or_insert(index as u64 + 1);
    }

    let lookup = |capsule_id: &str| -> Result<Option<Record>, BuildError> {
        let stored = match source.record(capsule_id)? {
            Some(stored) => stored,
            None => return Ok(None),
        };
        if !seq_of.contains_key(capsule_id) {
            return Err(BuildError::new(format!(
                "record {capsule_id} is not a leaf at or below the checkpoint (not yet covered, or not in this log)"
            )));
        }
        decode_record(capsule_id, &stored).map(Some)
    };

    let (mut carried, missing) = closure(root, *closure_depth, &lookup)?;
    for capsule_id in include {
        if !carried.contains_key(capsule_id) {
            let record = lookup(capsule_id)?
                .ok_or_else(|| BuildError::new(format!("include: no such record: {capsule_id}")))?;
            carried.insert(capsule_id.clone(), record);
        }
    }

    let mut certificate = Map::new();
    certificate.insert("log_id".into(), json!(signed.log_id));
    certificate.insert("range_root".into(), json!(signed.root));
    if let Some(first) = interval_from {
        if first > tip {
            return Err(BuildError::new(format!(
                "interval_from {first} is past the checkpoint tip {tip}"
            )));
        }
        let mut below: Vec<(u64, &String)> = carried
            .keys()
            .map(|cid| (seq_of[cid], cid))
            .filter(|(seq, _)| *seq < first)
            .collect();
        if !below.is_empty() {
            below.sort();
            let named: Vec<String> = below
                .iter()
                .map(|(seq, cid)| format!("{cid} (seq {seq})"))
                .collect();
            return Err(BuildError::new(format!(
                "record(s) below interval_from {first}: {}; lower it or build without a range",
                named.join(", ")
            )));
        }
        let mut non_record = Vec::new();
        for seq in first..=tip {
            let capsule_id = &leaf_hex[(seq - 1) as usize];
            if carried.contains_key(capsule_id) {
                continue;
            }
            let Some(record) = lookup(capsule_id)? else {
                let content = if *carry_non_record_leaves {
                    padding_content(source, seq, capsule_id)?
                } else {
                    None
                };
                let content = content.ok_or_else(|| {
                    BuildError::new(format!(
                        "seq {seq} in the interval is not a record the source holds; a range \
                         cannot cover it: start the interval after it or build without a range"
                    ))
                })?;
                non_record.push(json!({"seq": seq, "content": content}));
                continue;
            };
            carried.insert(capsule_id.clone(), record);
        }
        certificate.insert("first_seq".into(), json!(first));
        certificate.insert("last_seq".into(), json!(tip));
        certificate.insert(
            "body_digests".into(),
            json!(leaf_hex[(first - 1) as usize..]),
        );
        certificate.insert(
            "range_proof".into(),
            normalised_range_proof(first, &source.range_proof(first)?)?,
        );
        if !non_record.is_empty() {
            certificate.insert("non_record_leaves".into(), Value::Array(non_record));
        }
    }

    let mut ordered: Vec<&String> = carried.keys().collect();
    ordered.sort_by_key(|cid| seq_of[*cid]);
    let unknown: Vec<&String> = disclosures
        .keys()
        .filter(|cid| !carried.contains_key(*cid))
        .collect();
    if !unknown.is_empty() {
        return Err(BuildError::new(format!(
            "disclosures given for record(s) the bundle does not carry: {unknown:?}"
        )));
    }
    let mut memberships = Map::new();
    for cid in &ordered {
        let seq = seq_of[*cid];
        memberships.insert(
            (*cid).clone(),
            json!({
                "log_coordinates": {"log_id": signed.log_id, "seq": seq, "leaf_index": seq - 1},
                "inclusion_proof": normalised_inclusion_proof(seq, &source.inclusion_proof(seq)?)?,
            }),
        );
    }
    certificate.insert("memberships".into(), Value::Object(memberships));
    let records: Vec<&Record> = ordered.iter().map(|cid| &carried[*cid]).collect();
    let mut completeness = completeness(
        &records,
        *closure_depth,
        &missing,
        disclosures,
        suppressed_fields,
        *payloads_mode,
    )?;
    if interval_from.is_none() {
        completeness.insert("selection".into(), json!(SELECTION_PRODUCER_SELECTED));
    }

    let mut bundle = Map::new();
    bundle.insert("bundle_version".into(), json!("2"));
    bundle.insert("bundle_kind".into(), json!(BUNDLE_KIND));
    bundle.insert("root".into(), json!(root));
    bundle.insert(
        "records".into(),
        Value::Array(records.into_iter().cloned().map(Value::Object).collect()),
    );
    bundle.insert("completeness".into(), Value::Object(completeness));
    bundle.insert(
        "completeness_certificate".into(),
        Value::Object(certificate),
    );
    bundle.insert(
        "checkpoint".into(),
        json!({
            "log_id": signed.log_id,
            "mmr_size": signed.mmr_size,
            "root": signed.root,
            "prev_size": signed.prev_size,
            "prev_root": signed.prev_root,
            "key_id": signed.key_id,
            "timestamp": signed.timestamp,
            "cose": B64.encode(&cose),
        }),
    );
    if !disclosures.is_empty() {
        bundle.insert("disclosures".into(), json!(disclosures));
    }
    let mut extensions = extensions.clone();
    if let Some(key) = producer_key {
        extensions.insert(
            "producer-key/v1".into(),
            json!({"public_key": hex::encode(key)}),
        );
    }
    if !extensions.is_empty() {
        bundle.insert("extensions".into(), Value::Object(extensions));
    }
    if let Some(verification) = verification {
        bundle.insert("verification".into(), Value::Object(verification.clone()));
    }
    self_checked(Value::Object(bundle))
}

/// The source's inclusion proof as the verifier reads it: parsed by the
/// verifier's own parser, then written back with only the wire members.
fn normalised_inclusion_proof(seq: u64, proof: &InclusionProof) -> Result<Value, BuildError> {
    let parsed = parse_inclusion_proof(Some(&proof.to_value())).ok_or_else(|| {
        BuildError::new(format!(
            "the source's inclusion proof for seq {seq} is malformed"
        ))
    })?;
    Ok(InclusionProof {
        v: parsed.v,
        kind: parsed.kind,
        size: parsed.size,
        leaf_index: parsed.leaf_index,
        witness: parsed.witness,
        peaks_left: parsed.peaks_left,
        peaks_right: parsed.peaks_right,
    }
    .to_value())
}

/// The source's range proof as the verifier reads it, as
/// [`normalised_inclusion_proof`].
fn normalised_range_proof(first_seq: u64, proof: &RangeProof) -> Result<Value, BuildError> {
    let parsed = parse_range_proof(Some(&proof.to_value())).ok_or_else(|| {
        BuildError::new(format!(
            "the source's range proof from seq {first_seq} is malformed"
        ))
    })?;
    Ok(RangeProof {
        from_seq: parsed.from_seq as u64,
        to_seq: parsed.to_seq as u64,
        size: parsed.size,
        from_index: parsed.proof.from_index,
        to_index: parsed.proof.to_index,
        witness: parsed.proof.witness,
    }
    .to_value())
}

/// Refuses a Bundle whose digest cannot be computed (a float or an unsafe
/// integer anywhere, for example in `extensions`), and one
/// [`verify_bundle_strict`] calls INVALID. A declared-
/// incomplete closure or an unsigned record is a legitimate outcome to
/// state: the bar is INVALID, not "not VALID".
fn self_checked(bundle: Value) -> Result<Value, BuildError> {
    if let Err(e) = bundle_digest(&bundle) {
        return Err(BuildError::with_source(
            "the bundle has no canonical digest (JCS refuses it)",
            e.to_string(),
        ));
    }
    let result = verify_bundle_strict(&bundle, &StrictOptions::default());
    if result.verdict() == "INVALID" {
        let failed: Vec<String> = result
            .claims
            .iter()
            .filter(|(_, claim)| claim.status == "fail")
            .map(|(name, claim)| {
                let detail = if claim.findings.is_empty() {
                    claim.status.clone()
                } else {
                    claim.findings.join(", ")
                };
                format!("{name}: {detail}")
            })
            .collect();
        let detail = if failed.is_empty() {
            "not an evidence bundle".to_string()
        } else {
            failed.join("; ")
        };
        return Err(BuildError::new(format!(
            "the bundle does not verify: {detail}"
        )));
    }
    Ok(bundle)
}

/// An Evidence Bundle with no log proof: no checkpoint and no certificate,
/// for Capsules that belong to no log. Every given record is carried; the
/// closure from `options.root` decides `missing`. [`verify_bundle_strict`]
/// reads it as INCOMPLETE.
pub fn build_unproven_bundle(
    records: &[Value],
    options: &UnprovenOptions,
) -> Result<Value, BuildError> {
    let UnprovenOptions {
        root,
        closure_depth,
        disclosures,
        suppressed_fields,
    } = options;
    check_options(
        *closure_depth,
        disclosures,
        suppressed_fields,
        &Map::new(),
        None,
    )?;
    // bundle > records > record
    if records.iter().any(|r| too_deep(r, 2)) {
        return Err(deep_input("a record"));
    }
    let mut ids: Vec<String> = Vec::with_capacity(records.len());
    let mut by_id: HashMap<String, Record> = HashMap::new();
    for record in records {
        let map = record.as_object();
        let cid = match map
            .and_then(|m| m.get("capsule_id"))
            .and_then(Value::as_str)
        {
            Some(cid) => cid.to_string(),
            None => return Err(BuildError::new("every record needs a capsule_id")),
        };
        if by_id.contains_key(&cid) {
            return Err(BuildError::new("duplicate capsule_id among the records"));
        }
        by_id.insert(cid.clone(), map.expect("checked above").clone());
        ids.push(cid);
    }
    if !by_id.contains_key(root) {
        return Err(BuildError::new(format!(
            "root {root} is not among the records"
        )));
    }
    let unknown: Vec<&String> = disclosures
        .keys()
        .filter(|cid| !by_id.contains_key(*cid))
        .collect();
    if !unknown.is_empty() {
        return Err(BuildError::new(format!(
            "disclosures given for record(s) the bundle does not carry: {unknown:?}"
        )));
    }
    let (_, missing) = closure(root, *closure_depth, |cid| Ok(by_id.get(cid).cloned()))?;
    let ordered: Vec<&Record> = ids.iter().map(|cid| &by_id[cid]).collect();
    let completeness = completeness(
        &ordered,
        *closure_depth,
        &missing,
        disclosures,
        suppressed_fields,
        None,
    )?;
    let mut bundle = Map::new();
    bundle.insert("bundle_version".into(), json!("2"));
    bundle.insert("bundle_kind".into(), json!(BUNDLE_KIND));
    bundle.insert("root".into(), json!(root));
    bundle.insert(
        "records".into(),
        Value::Array(ordered.into_iter().cloned().map(Value::Object).collect()),
    );
    bundle.insert("completeness".into(), Value::Object(completeness));
    if !disclosures.is_empty() {
        bundle.insert("disclosures".into(), json!(disclosures));
    }
    self_checked(Value::Object(bundle))
}
