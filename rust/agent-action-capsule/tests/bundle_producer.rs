// SPDX-License-Identifier: BSD-3-Clause
//! The Evidence Bundle producer: `build_evidence_bundle` over a `ProofSource`
//! and `build_unproven_bundle`.
//!
//! Every produced Bundle is read back with `verify_bundle_strict`: a
//! range-proven Bundle of signed records is VALID, a producer-selected one
//! INCOMPLETE, and a one-byte change INVALID. Each refusal is checked by name.

use agent_action_capsule::bundle::{
    build_evidence_bundle, build_unproven_bundle, proof_source_from_cll, verify_bundle_strict,
    BuildError, BuildOptions, CllProofSource, InclusionProof, Interval, PayloadsMode, ProofSource,
    RangeProof, RecordSource, StoredRecord, StrictOptions, UnprovenOptions,
};
use agent_action_capsule::canonical::{compute_capsule_id, jcs, json_digest};
use base64::Engine as _;
use cll::checkpoint::{checkpoint_to_cose, verify_checkpoint_cose_offline, CheckpointRecord};
use cll::log::memory::MemoryStore;
use cll::log::{AppendInput, CheckpointState, CheckpointStateStore, EntryStore, State, Timestamp};
use cll::mmr::{self, MemoryNodeStore, NodeReader};
use coset::{iana, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable as _};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::error::Error as _;
use std::fmt;

const LOG_ID: &str = "log:producer-tests";
const TIMESTAMP: &str = "2026-10-19T00:00:00Z";
const ABSENT: &str = "abababababababababababababababababababababababababababababababab";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn producer() -> SigningKey {
    SigningKey::from_bytes(&[0x0B; 32])
}

fn log_key() -> SigningKey {
    SigningKey::from_bytes(&[0x2C; 32])
}

fn producer_key_hex() -> String {
    hex::encode(producer().verifying_key().to_bytes())
}

#[derive(Default)]
struct CapsuleSpec<'a> {
    parent: Option<&'a str>,
    cites: &'a [&'a str],
    agent_input: Option<Value>,
}

fn capsule(action_id: &str, spec: CapsuleSpec) -> Value {
    let mut record = json!({
        "spec_version": "draft-mih-scitt-agent-action-capsule-04",
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_id": action_id,
        "action_type": "fyi",
        "operator": "ACME-CO",
        "developer": "agent@v1",
        "timestamp": TIMESTAMP,
        "assurance": {"effect_mode": "not_applicable", "attestation_mode": "self_attested", "ledger_mode": "standalone"},
        "disposition": {"verdict_class": "not_applicable", "decision": "report", "approver": "policy", "human_disposed": false},
    });
    let map = record.as_object_mut().unwrap();
    if let Some(parent) = spec.parent {
        map.insert(
            "chain".into(),
            json!({"parent_capsule_id": parent, "relation": "follows"}),
        );
    }
    if !spec.cites.is_empty() {
        let refs: Vec<Value> = spec
            .cites
            .iter()
            .map(|c| json!({"type": "agent-action-capsule", "digest_alg": "SHA-256", "digest": c}))
            .collect();
        map.insert("references".into(), Value::Array(refs));
    }
    if let Some(input) = spec.agent_input {
        map.insert(
            "model_attestation".into(),
            json!({"compute_attestation": {"agent_input_digest": json_digest(&input).unwrap()}}),
        );
    }
    let id = compute_capsule_id(map).unwrap();
    map.insert("capsule_id".into(), json!(id));
    record
}

fn cid(record: &Value) -> String {
    record["capsule_id"].as_str().unwrap().to_string()
}

/// A Producer Envelope: COSE_Sign1 over the raw Capsule ID, signed by
/// `producer()`.
fn envelope(capsule_id: &str) -> Vec<u8> {
    let key = producer();
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .content_type("application/agent-action-capsule-id".to_string())
        .key_id(key.verifying_key().to_bytes().to_vec())
        .build();
    CoseSign1Builder::new()
        .protected(protected)
        .payload(hex::decode(capsule_id).unwrap())
        .create_signature(b"", |tbs| key.sign(tbs).to_bytes().to_vec())
        .build()
        .to_tagged_vec()
        .unwrap()
}

#[derive(Debug)]
struct DiskError;

impl fmt::Display for DiskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("disk")
    }
}

impl std::error::Error for DiskError {}

/// A record store: `get_record` returns capsule and envelope bytes, `None`
/// for a record it does not hold, and fails when `broken`.
#[derive(Default)]
struct Records {
    held: HashMap<String, StoredRecord>,
    broken: bool,
}

impl Records {
    fn put(&mut self, record: &Value, signed: bool) {
        let id = cid(record);
        let producer_envelope = if signed { envelope(&id) } else { Vec::new() };
        self.held.insert(
            id,
            StoredRecord {
                capsule: jcs(record).unwrap(),
                producer_envelope,
            },
        );
    }
}

impl RecordSource for Records {
    type Error = DiskError;

    fn get_record(&self, id: &str) -> Result<Option<StoredRecord>, DiskError> {
        if self.broken {
            return Err(DiskError);
        }
        Ok(self.held.get(id).cloned())
    }
}

/// A CLL memory backend holding `leaves` (hex values), checkpointed after the
/// first `checkpoint_after` leaves (all when `None`).
fn make_backend(leaves: &[String], checkpoint_after: Option<usize>) -> MemoryStore {
    let backend = MemoryStore::new();
    let mut nodes = MemoryNodeStore::new();
    let covered = checkpoint_after.unwrap_or(leaves.len());
    for (index, value) in leaves.iter().enumerate() {
        let raw: [u8; 32] = hex::decode(value).unwrap().try_into().unwrap();
        backend
            .append(&AppendInput {
                value: raw.to_vec(),
                appended_at: Timestamp::from_unix_millis(1_792_368_000_000),
            })
            .unwrap();
        if index < covered {
            mmr::add_leaf(&mut nodes, mmr::leaf_hash(&raw)).unwrap();
        }
    }
    let size = nodes.size();
    let peak_hashes: Vec<mmr::Hash> = mmr::peaks(size)
        .unwrap()
        .into_iter()
        .map(|p| nodes.node(p))
        .collect();
    let key = log_key();
    let cp = CheckpointRecord {
        v: 1,
        kind: "mmr_checkpoint".into(),
        log_id: LOG_ID.into(),
        mmr_size: size,
        root: hex::encode(mmr::root_from_peaks(&peak_hashes)),
        prev_size: 0,
        prev_root: String::new(),
        key_id: hex::encode(key.verifying_key().to_bytes()),
        timestamp: TIMESTAMP.into(),
        signature: String::new(),
        witnesses: Vec::new(),
    };
    let cose = checkpoint_to_cose(&cp, &key, &peak_hashes, None, None, None).unwrap();
    let state = State {
        size,
        nodes: (0..size).map(|i| nodes.node(i).to_vec()).collect(),
        indexed_seq: covered as u64,
        first_pending_at: None,
        checkpoint: Some(CheckpointState {
            bytes: cose,
            size,
            indexed_seq: covered as u64,
            peaks: peak_hashes.iter().map(|p| p.to_vec()).collect(),
        }),
        witnesses: Vec::new(),
    };
    backend.commit_cll(0, None, &state).unwrap();
    backend
}

fn make_log(
    leaves: &[String],
    records: Records,
    checkpoint_after: Option<usize>,
) -> CllProofSource<Records> {
    proof_source_from_cll(&make_backend(leaves, checkpoint_after), records).unwrap()
}

fn verdict(bundle: &Value) -> &'static str {
    verify_bundle_strict(bundle, &StrictOptions::default()).verdict()
}

fn claims(bundle: &Value) -> BTreeMap<String, String> {
    verify_bundle_strict(bundle, &StrictOptions::default())
        .claims
        .into_iter()
        .map(|(name, claim)| (name.to_string(), claim.status))
        .collect()
}

fn record_ids(bundle: &Value) -> Vec<String> {
    bundle["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(cid)
        .collect()
}

/// Three signed records, each citing the one before; every leaf a record.
fn chain() -> (CllProofSource<Records>, Vec<Value>) {
    let mut records = Records::default();
    let a = capsule(
        "a",
        CapsuleSpec {
            agent_input: Some(json!({"step": 0})),
            ..Default::default()
        },
    );
    let b = capsule(
        "b",
        CapsuleSpec {
            parent: Some(&cid(&a)),
            ..Default::default()
        },
    );
    let c = capsule(
        "c",
        CapsuleSpec {
            parent: Some(&cid(&b)),
            ..Default::default()
        },
    );
    let caps = vec![a, b, c];
    for r in &caps {
        records.put(r, true);
    }
    let leaves: Vec<String> = caps.iter().map(cid).collect();
    (make_log(&leaves, records, None), caps)
}

fn options(root: &Value, interval: Interval) -> BuildOptions {
    BuildOptions::new(cid(root), interval)
}

#[track_caller]
fn refused(result: Result<Value, BuildError>, message: &str) -> BuildError {
    match result {
        Ok(_) => panic!("built a bundle; expected a refusal containing {message:?}"),
        Err(e) => {
            assert!(
                e.to_string().contains(message),
                "refusal {:?} does not contain {message:?}",
                e.to_string()
            );
            e
        }
    }
}

// -- success ------------------------------------------------------------------

#[test]
fn whole_log_range_is_valid() {
    let (source, caps) = chain();
    let bundle = build_evidence_bundle(&source, &options(&caps[2], Interval::From(1))).unwrap();
    let ids: Vec<String> = caps.iter().map(cid).collect();
    assert_eq!(record_ids(&bundle), ids);
    let cert = &bundle["completeness_certificate"];
    assert_eq!(
        (cert["first_seq"].clone(), cert["last_seq"].clone()),
        (json!(1), json!(3))
    );
    assert_eq!(cert["body_digests"], json!(ids));
    assert!(bundle["completeness"].get("selection").is_none());
    for record in bundle["records"].as_array().unwrap() {
        assert_eq!(record["key_id"], json!(producer_key_hex()));
    }
    assert_eq!(verdict(&bundle), "VALID");
}

#[test]
fn suffix_range_is_valid() {
    let (source, caps) = chain();
    let mut opts = options(&caps[2], Interval::From(2));
    opts.closure_depth = 1;
    let bundle = build_evidence_bundle(&source, &opts).unwrap();
    assert_eq!(record_ids(&bundle), [cid(&caps[1]), cid(&caps[2])]);
    assert_eq!(verdict(&bundle), "VALID");
}

#[test]
fn no_range_is_producer_selected_and_incomplete() {
    let (source, caps) = chain();
    let mut opts = options(&caps[1], Interval::ProducerSelected);
    opts.closure_depth = 0;
    let bundle = build_evidence_bundle(&source, &opts).unwrap();
    assert_eq!(record_ids(&bundle), [cid(&caps[1])]);
    assert_eq!(
        bundle["completeness"]["selection"],
        json!("producer-selected")
    );
    assert!(bundle["completeness_certificate"]
        .get("range_proof")
        .is_none());
    assert_eq!(claims(&bundle)["per_record_membership"], "pass");
    assert_eq!(verdict(&bundle), "INCOMPLETE");
}

#[test]
fn checkpoint_fields_come_from_the_signed_statement() {
    let (source, caps) = chain();
    let bundle = build_evidence_bundle(&source, &options(&caps[0], Interval::From(1))).unwrap();
    let cp = &bundle["checkpoint"];
    let cose = B64.decode(cp["cose"].as_str().unwrap()).unwrap();
    let decoded = verify_checkpoint_cose_offline(&cose).decoded.unwrap();
    assert_eq!(cp["log_id"], json!(decoded.log_id));
    assert_eq!(cp["mmr_size"], json!(decoded.mmr_size));
    assert_eq!(cp["root"], json!(decoded.root));
    assert_eq!(cp["prev_size"], json!(decoded.prev_size));
    assert_eq!(cp["prev_root"], json!(decoded.prev_root));
    assert_eq!(cp["key_id"], json!(decoded.key_id));
    assert_eq!(cp["timestamp"], json!(decoded.timestamp));
}

#[test]
fn include_carries_further_records() {
    let (source, caps) = chain();
    let mut opts = options(&caps[2], Interval::ProducerSelected);
    opts.closure_depth = 0;
    opts.include = vec![cid(&caps[0])];
    let bundle = build_evidence_bundle(&source, &opts).unwrap();
    assert_eq!(record_ids(&bundle), [cid(&caps[0]), cid(&caps[2])]);
}

#[test]
fn an_unsigned_record_is_carried_unsigned_and_incomplete() {
    let mut records = Records::default();
    let a = capsule("unsigned", CapsuleSpec::default());
    records.put(&a, false);
    let source = make_log(&[cid(&a)], records, None);
    let bundle = build_evidence_bundle(&source, &options(&a, Interval::From(1))).unwrap();
    let record = &bundle["records"][0];
    assert!(record.get("signature").is_none() && record.get("key_id").is_none());
    assert_eq!(claims(&bundle)["signatures"], "withheld");
    assert_eq!(verdict(&bundle), "INCOMPLETE");
}

#[test]
fn a_missing_citation_is_declared_and_incomplete() {
    let mut records = Records::default();
    let a = capsule(
        "cites-absent",
        CapsuleSpec {
            cites: &[ABSENT],
            ..Default::default()
        },
    );
    records.put(&a, true);
    let source = make_log(&[cid(&a)], records, None);
    let bundle = build_evidence_bundle(&source, &options(&a, Interval::From(1))).unwrap();
    assert_eq!(bundle["completeness"]["missing"], json!([ABSENT]));
    assert_eq!(
        bundle["completeness"]["records_mode"],
        json!("declared_incomplete")
    );
    assert_eq!(verdict(&bundle), "INCOMPLETE");
}

fn overlay(entries: &[(&str, Value)]) -> BTreeMap<String, Map<String, Value>> {
    entries
        .iter()
        .map(|(id, members)| (id.to_string(), members.as_object().unwrap().clone()))
        .collect()
}

#[test]
fn disclosures_and_payloads_mode() {
    let (source, caps) = chain();
    let root = cid(&caps[0]);
    let mut opts = options(&caps[0], Interval::ProducerSelected);
    opts.closure_depth = 0;

    let mut revealed_opts = opts.clone();
    revealed_opts.disclosures = overlay(&[(&root, json!({"agent_input": {"step": 0}}))]);
    let revealed = build_evidence_bundle(&source, &revealed_opts).unwrap();
    assert_eq!(revealed["completeness"]["payloads_mode"], json!("all"));
    assert_eq!(claims(&revealed)["disclosures"], "pass");

    let plain = build_evidence_bundle(&source, &opts).unwrap();
    assert_eq!(plain["completeness"]["payloads_mode"], json!("selected"));

    let mut declared_opts = opts.clone();
    declared_opts.payloads_mode = Some(PayloadsMode::All);
    let declared = build_evidence_bundle(&source, &declared_opts).unwrap();
    assert_eq!(
        declared["completeness"]["payloads_mode"],
        json!("all"),
        "material carried elsewhere is the caller's claim"
    );

    let mut gap = options(&caps[2], Interval::From(1));
    gap.payloads_mode = Some(PayloadsMode::All);
    gap.disclosures = overlay(&[(&cid(&caps[1]), json!({})), (&root, json!({}))]);
    refused(build_evidence_bundle(&source, &gap), "does not reveal");
}

#[test]
fn extensions_verification_and_producer_key() {
    let (source, caps) = chain();
    let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let mut opts = options(&caps[0], Interval::From(1));
    opts.producer_key = Some(key);
    opts.extensions = json!({"example/notes": {"n": 1}})
        .as_object()
        .unwrap()
        .clone();
    opts.verification = Some(
        json!({"producer": "tests", "checks": []})
            .as_object()
            .unwrap()
            .clone(),
    );
    let bundle = build_evidence_bundle(&source, &opts).unwrap();
    assert_eq!(
        bundle["extensions"],
        json!({"example/notes": {"n": 1}, "producer-key/v1": {"public_key": hex::encode(key)}})
    );
    assert_eq!(
        bundle["verification"],
        json!({"producer": "tests", "checks": []})
    );
    assert_eq!(verdict(&bundle), "VALID");
    for owned in ["producer-key/v1", "composed/v1"] {
        let mut bad = options(&caps[0], Interval::From(1));
        bad.extensions.insert(owned.into(), json!({}));
        refused(build_evidence_bundle(&source, &bad), "owns");
    }
}

#[test]
fn proof_source_from_cll_reads_the_backend() {
    let (source, caps) = chain();
    let ids: Vec<String> = caps.iter().map(cid).collect();
    let leaves: Vec<String> = source.leaves().unwrap().iter().map(hex::encode).collect();
    assert_eq!(leaves, ids);
    let cose = source.checkpoint().unwrap();
    assert!(verify_checkpoint_cose_offline(&cose).ok);
    let proof: InclusionProof = source.inclusion_proof(2).unwrap();
    assert_eq!((proof.kind.as_str(), proof.leaf_index), ("inclusion", 1));
    let range: RangeProof = source.range_proof(2).unwrap();
    assert_eq!(
        (
            range.from_seq,
            range.to_seq,
            range.from_index,
            range.to_index
        ),
        (2, 3, 1, 2)
    );
    assert!(source.range_proof(0).is_err() && source.range_proof(4).is_err());
    assert!(source.inclusion_proof(0).is_err() && source.inclusion_proof(4).is_err());
    assert!(source.record(&ids[0]).unwrap().is_some());
    assert!(source.record(ABSENT).unwrap().is_none());
}

// -- tamper -------------------------------------------------------------------

fn flip(text: &str) -> String {
    let first = if text.starts_with('0') { "1" } else { "0" };
    format!("{first}{}", &text[1..])
}

fn flip_at(value: &mut Value) {
    *value = json!(flip(value.as_str().unwrap()));
}

#[test]
fn a_one_byte_change_is_invalid() {
    let (source, caps) = chain();
    let mut opts = options(&caps[2], Interval::From(2));
    opts.closure_depth = 1;
    let bundle = build_evidence_bundle(&source, &opts).unwrap();
    assert_eq!(verdict(&bundle), "VALID");
    let member = cid(&caps[1]);
    for place in [
        "record",
        "body_digest",
        "inclusion_proof",
        "range_witness",
        "cose",
        "checkpoint_root",
    ] {
        let mut bad = bundle.clone();
        match place {
            "record" => flip_at(&mut bad["records"][0]["action_id"]),
            "body_digest" => flip_at(&mut bad["completeness_certificate"]["body_digests"][0]),
            "inclusion_proof" => {
                let proof =
                    &mut bad["completeness_certificate"]["memberships"][&member]["inclusion_proof"];
                let key = ["witness", "peaks_left", "peaks_right"]
                    .into_iter()
                    .find(|k| !proof[*k].as_array().unwrap().is_empty())
                    .unwrap();
                flip_at(&mut proof[key][0]);
            }
            "range_witness" => {
                flip_at(&mut bad["completeness_certificate"]["range_proof"]["witness"][0])
            }
            "cose" => {
                let mut raw = B64
                    .decode(bad["checkpoint"]["cose"].as_str().unwrap())
                    .unwrap();
                *raw.last_mut().unwrap() ^= 1;
                bad["checkpoint"]["cose"] = json!(B64.encode(raw));
            }
            _ => flip_at(&mut bad["checkpoint"]["root"]),
        }
        assert_eq!(verdict(&bad), "INVALID", "{place}");
    }
}

// -- refusals -----------------------------------------------------------------

#[test]
fn interval_from_must_be_a_seq_in_the_log() {
    // Required by type: `BuildOptions::new` takes it, and there is no Default.
    let (source, caps) = chain();
    refused(
        build_evidence_bundle(&source, &options(&caps[0], Interval::From(0))),
        "interval_from must be a seq of at least 1",
    );
    refused(
        build_evidence_bundle(&source, &options(&caps[0], Interval::From(9))),
        "past the checkpoint tip",
    );
}

#[test]
fn a_record_below_interval_from_is_refused_by_name() {
    let (source, caps) = chain();
    let mut opts = options(&caps[2], Interval::From(2));
    opts.closure_depth = 2;
    refused(
        build_evidence_bundle(&source, &opts),
        &format!("below interval_from 2: {} (seq 1)", cid(&caps[0])),
    );
    let mut opts = options(&caps[2], Interval::From(3));
    opts.closure_depth = 0;
    opts.include = vec![cid(&caps[0])];
    refused(build_evidence_bundle(&source, &opts), "below interval_from");
}

#[test]
fn a_range_over_a_non_record_leaf_is_refused() {
    let mut records = Records::default();
    let (a, b) = (
        capsule("a", CapsuleSpec::default()),
        capsule("b", CapsuleSpec::default()),
    );
    records.put(&a, true);
    records.put(&b, true);
    let stamp = "cd".repeat(32); // a leaf the store does not hold as a record
    let source = make_log(&[cid(&a), stamp, cid(&b)], records, None);
    refused(
        build_evidence_bundle(&source, &options(&b, Interval::From(1))),
        "seq 2 in the interval is not a record",
    );
    let bundle = build_evidence_bundle(&source, &options(&b, Interval::From(3))).unwrap();
    assert_eq!(verdict(&bundle), "VALID");
}

#[test]
fn an_uncovered_record_is_refused() {
    let mut records = Records::default();
    let (a, late) = (
        capsule("a", CapsuleSpec::default()),
        capsule("late", CapsuleSpec::default()),
    );
    records.put(&a, true);
    records.put(&late, true);
    let source = make_log(&[cid(&a), cid(&late)], records, Some(1));
    refused(
        build_evidence_bundle(&source, &options(&late, Interval::ProducerSelected)),
        "not covered by the checkpoint",
    );
}

#[test]
fn unknown_root_and_include_are_refused() {
    let (source, caps) = chain();
    refused(
        build_evidence_bundle(
            &source,
            &BuildOptions::new(ABSENT, Interval::ProducerSelected),
        ),
        "no such record",
    );
    let mut opts = options(&caps[0], Interval::ProducerSelected);
    opts.include = vec![ABSENT.to_string()];
    refused(
        build_evidence_bundle(&source, &opts),
        "include: no such record",
    );
}

#[test]
fn bad_options_are_refused() {
    let (source, caps) = chain();
    let root = cid(&caps[0]);
    let base = {
        let mut o = options(&caps[0], Interval::ProducerSelected);
        o.closure_depth = 0;
        o
    };
    let cases: Vec<(BuildOptions, &str)> = vec![
        (
            BuildOptions {
                disclosures: overlay(&[(ABSENT, json!({"agent_input": {}}))]),
                ..base.clone()
            },
            "does not carry",
        ),
        (
            BuildOptions {
                disclosures: overlay(&[(&root, json!({"tool_args": {}}))]),
                ..base.clone()
            },
            "not disclosure-eligible",
        ),
        (
            BuildOptions {
                disclosures: overlay(&[(&root, json!({"agent_input": {"step": 0}}))]),
                suppressed_fields: vec!["agent_input".into()],
                ..base.clone()
            },
            "declared suppressed",
        ),
        (
            BuildOptions {
                suppressed_fields: vec!["tool_args".into()],
                ..base.clone()
            },
            "suppressed_fields names",
        ),
    ];
    for (opts, message) in cases {
        refused(build_evidence_bundle(&source, &opts), message);
    }
}

#[test]
fn a_mismatched_disclosure_is_refused_by_the_self_check() {
    let (source, caps) = chain();
    let mut opts = options(&caps[0], Interval::ProducerSelected);
    opts.closure_depth = 0;
    opts.disclosures = overlay(&[(&cid(&caps[0]), json!({"agent_input": {"step": 9}}))]);
    refused(build_evidence_bundle(&source, &opts), "does not verify");
}

/// A ProofSource that wraps a good one and lies in one member.
struct Lying<'a> {
    base: &'a CllProofSource<Records>,
    lie: Lie,
}

#[derive(Clone)]
enum Lie {
    EmptyCheckpoint,
    DropLastLeaf,
    ExtraLeaf,
    OtherCapsule(Vec<u8>),
    WrongEnvelope,
    NotJson,
    WrongInclusion,
    WrongRange,
}

impl ProofSource for Lying<'_> {
    fn checkpoint(&self) -> Result<Vec<u8>, BuildError> {
        match self.lie {
            Lie::EmptyCheckpoint => Ok(Vec::new()),
            _ => self.base.checkpoint(),
        }
    }

    fn leaves(&self) -> Result<Vec<[u8; 32]>, BuildError> {
        let mut leaves = self.base.leaves()?;
        match self.lie {
            Lie::DropLastLeaf => {
                leaves.pop();
            }
            Lie::ExtraLeaf => leaves.push([0xcd; 32]),
            _ => {}
        }
        Ok(leaves)
    }

    fn record(&self, capsule_id: &str) -> Result<Option<StoredRecord>, BuildError> {
        let held = self.base.record(capsule_id)?;
        Ok(match &self.lie {
            Lie::OtherCapsule(bytes) => Some(StoredRecord {
                capsule: bytes.clone(),
                producer_envelope: Vec::new(),
            }),
            Lie::WrongEnvelope => held.map(|r| StoredRecord {
                producer_envelope: envelope(ABSENT),
                ..r
            }),
            Lie::NotJson => Some(StoredRecord {
                capsule: b"not json".to_vec(),
                producer_envelope: Vec::new(),
            }),
            _ => held,
        })
    }

    fn inclusion_proof(&self, seq: u64) -> Result<InclusionProof, BuildError> {
        let mut proof = self.base.inclusion_proof(seq)?;
        if matches!(self.lie, Lie::WrongInclusion) {
            proof.leaf_index = (proof.leaf_index + 1) % 3;
        }
        Ok(proof)
    }

    fn range_proof(&self, first_seq: u64) -> Result<RangeProof, BuildError> {
        let mut proof = self.base.range_proof(first_seq)?;
        if matches!(self.lie, Lie::WrongRange) {
            proof.witness[0] = flip(&proof.witness[0]);
        }
        Ok(proof)
    }
}

#[test]
fn a_source_that_lies_is_refused() {
    let (source, caps) = chain();
    let other = jcs(&capsule("other", CapsuleSpec::default())).unwrap();
    let cases = [
        (Lie::EmptyCheckpoint, "the checkpoint does not verify"),
        (Lie::DropLastLeaf, "the source gave 2 leaves"),
        (Lie::ExtraLeaf, "the source gave 4 leaves"),
        (Lie::OtherCapsule(other), "different capsule"),
        (Lie::WrongEnvelope, "envelope does not verify"),
        (Lie::NotJson, "not a JSON object"),
        (Lie::WrongInclusion, "does not verify"),
    ];
    for (lie, message) in cases {
        let lying = Lying { base: &source, lie };
        refused(
            build_evidence_bundle(&lying, &options(&caps[2], Interval::ProducerSelected)),
            message,
        );
    }
    // Interval coverage is the strict verifier's call too.
    let lying = Lying {
        base: &source,
        lie: Lie::WrongRange,
    };
    let mut opts = options(&caps[2], Interval::From(2));
    opts.closure_depth = 1;
    refused(build_evidence_bundle(&lying, &opts), "interval_coverage");
}

#[test]
fn a_store_error_other_than_not_found_propagates() {
    let (_, caps) = chain();
    let leaves: Vec<String> = caps.iter().map(cid).collect();
    let broken = Records {
        broken: true,
        ..Default::default()
    };
    let source = make_log(&leaves, broken, None);
    let err = refused(
        build_evidence_bundle(&source, &options(&caps[0], Interval::ProducerSelected)),
        "the record store failed",
    );
    assert!(err.source().unwrap().downcast_ref::<DiskError>().is_some());
}

#[test]
fn a_log_without_a_checkpoint_is_refused() {
    let source = proof_source_from_cll(&MemoryStore::new(), Records::default()).unwrap();
    refused(
        build_evidence_bundle(
            &source,
            &BuildOptions::new(ABSENT, Interval::ProducerSelected),
        ),
        "no checkpoint",
    );
}

// -- the unproven form --------------------------------------------------------

#[test]
fn unproven_bundle_carries_no_log_proof() {
    let (_, caps) = chain();
    let bundle = build_unproven_bundle(&caps, &UnprovenOptions::new(cid(&caps[2]))).unwrap();
    assert!(bundle.get("checkpoint").is_none());
    assert!(bundle.get("completeness_certificate").is_none());
    assert_eq!(bundle["completeness"]["records_mode"], json!("complete"));
    assert_eq!(verdict(&bundle), "INCOMPLETE");
    let partial = build_unproven_bundle(&caps[1..], &UnprovenOptions::new(cid(&caps[2]))).unwrap();
    assert_eq!(partial["completeness"]["missing"], json!([cid(&caps[0])]));
}

#[test]
fn unproven_bundle_refusals() {
    let (_, caps) = chain();
    refused(
        build_unproven_bundle(&caps, &UnprovenOptions::new(ABSENT)),
        "not among the records",
    );
    let doubled: Vec<Value> = caps.iter().chain(&caps[..1]).cloned().collect();
    refused(
        build_unproven_bundle(&doubled, &UnprovenOptions::new(cid(&caps[0]))),
        "duplicate",
    );
    refused(
        build_unproven_bundle(&[json!({})], &UnprovenOptions::new("x")),
        "capsule_id",
    );
    let mut opts = UnprovenOptions::new(cid(&caps[0]));
    opts.disclosures = overlay(&[(ABSENT, json!({}))]);
    refused(build_unproven_bundle(&caps, &opts), "does not carry");
}
