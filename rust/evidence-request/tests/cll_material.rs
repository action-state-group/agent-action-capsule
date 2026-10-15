//! `cll_material` over material a real Checkpointed Local Log builds: the
//! checkpoint statements `checkpointed-local-log` signs, its inclusion and
//! consistency proofs in the profile's encodings, and hand-built checkpoints
//! for the forms step 7 refuses. Each status and the order the steps decide
//! in are asserted through the public checker.

use ciborium::Value as C;
use cll::checkpoint::{checkpoint_to_cose, CheckpointRecord};
use cll::mmr::{
    add_leaf, commitment_object, consistency_proof, inclusion_proof, leaf_hash, node_count, peaks,
    root_from_peaks, Hash, MemoryNodeStore, NodeReader,
};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use evidence_request::cll_material::{
    check_anchor_inclusion, encode_consistency_proof, encode_inclusion_proof, KeyDecision,
    LogKeyPolicy, Status, KIND_CHECKPOINT, KIND_CONSISTENCY, KIND_INCLUSION,
};
use evidence_request::envelope::{sign, Anchor, AnchorFreshness, Envelope, EnvelopeParts};
use evidence_request::request::Subject;
use sha2::{Digest, Sha256};

const LOG_ID: &str = "log-1";
const TS: &str = "2026-10-15T00:00:00Z";

fn key(label: &str) -> SigningKey {
    SigningKey::from_bytes(&Sha256::digest(label.as_bytes()).into())
}

fn sha(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

fn unhex(h: &str) -> Hash {
    hex::decode(h).unwrap().try_into().unwrap()
}

/// A log of `n` artifacts, each logged as its own SHA-256 (profile §6.2.1).
struct Log {
    store: MemoryNodeStore,
    artifacts: Vec<Vec<u8>>,
}

impl Log {
    fn new(n: usize) -> Log {
        let mut store = MemoryNodeStore::new();
        let artifacts: Vec<Vec<u8>> = (0..n)
            .map(|i| format!("artifact {i}").into_bytes())
            .collect();
        for a in &artifacts {
            add_leaf(&mut store, leaf_hash(&sha(a))).unwrap();
        }
        Log { store, artifacts }
    }

    fn peaks(&self, size: u64) -> Vec<Hash> {
        peaks(size)
            .unwrap()
            .iter()
            .map(|&p| self.store.node(p))
            .collect()
    }

    /// The checkpoint statement over the first `leaves` leaves, extending
    /// the one over `prev` leaves when given.
    fn checkpoint(&self, leaves: u64, prev: Option<u64>, signer: &SigningKey) -> Vec<u8> {
        let size = node_count(leaves);
        let prev_size = prev.map_or(0, node_count);
        let record = CheckpointRecord {
            v: 1,
            kind: "mmr_checkpoint".into(),
            log_id: LOG_ID.into(),
            mmr_size: size,
            root: hex::encode(root_from_peaks(&self.peaks(size))),
            prev_size,
            prev_root: prev.map_or(String::new(), |_| {
                hex::encode(root_from_peaks(&self.peaks(prev_size)))
            }),
            key_id: hex::encode(signer.verifying_key().to_bytes()),
            timestamp: TS.into(),
            signature: String::new(),
            witnesses: Vec::new(),
        };
        let prev_peaks = prev.map(|_| self.peaks(prev_size));
        let proof = prev.map(|_| consistency_proof(&self.store, prev_size, size).unwrap());
        checkpoint_to_cose(
            &record,
            signer,
            &self.peaks(size),
            prev_peaks.as_deref(),
            proof.as_ref(),
            None,
        )
        .unwrap()
    }

    fn inclusion(&self, leaf: u64, leaves: u64) -> Vec<u8> {
        let proof = inclusion_proof(&self.store, leaf, node_count(leaves)).unwrap();
        let path: Vec<Hash> = proof.witness.iter().map(|h| unhex(h)).collect();
        encode_inclusion_proof(leaf, &path)
    }

    fn consistency(&self, from: u64, to: u64) -> Vec<u8> {
        let (a, b) = (node_count(from), node_count(to));
        let proof = consistency_proof(&self.store, a, b).unwrap();
        let paths: Vec<Vec<Hash>> = proof
            .witness
            .iter()
            .map(|p| p.iter().map(|h| unhex(h)).collect())
            .collect();
        encode_consistency_proof(a, b, &self.peaks(a), &paths, &self.peaks(b)).unwrap()
    }
}

/// The relying party's answer for every key, or for the pinned key only.
enum Policy {
    Pinned(VerifyingKey),
    Always(KeyDecision),
}

impl LogKeyPolicy for Policy {
    fn resolve(&self, iss: &str, sub: &str, kid: &[u8], _at: &str) -> KeyDecision {
        match self {
            Policy::Always(d) => d.clone(),
            Policy::Pinned(k)
                if iss == LOG_ID && sub.starts_with(LOG_ID) && kid == k.to_bytes() =>
            {
                KeyDecision::Accept(*k)
            }
            Policy::Pinned(_) => KeyDecision::Reject,
        }
    }
}

fn envelope(log: &Log, leaf: usize, statement: &[u8], material: Vec<(&str, Vec<u8>)>) -> Envelope {
    let artifact = log.artifacts[leaf].clone();
    let record = hex::encode(sha(&artifact));
    let anchor = hex::encode(sha(statement));
    let request = format!(
        r#"{{"coverage":{{"expected_pin":"{anchor}"}},"subject":{{"record":"{record}"}}}}"#
    );
    sign(
        request.as_bytes(),
        EnvelopeParts {
            subject: Subject::Record(record),
            derivation: None,
            anchor: Anchor {
                digest: anchor,
                freshness: None,
            },
            artifact,
            verification: material
                .into_iter()
                .map(|(k, o)| (k.to_string(), o))
                .collect(),
            issued_at: TS.into(),
        },
        &key("responder"),
    )
    .unwrap()
}

fn resign(mut e: Envelope) -> Envelope {
    let parts = EnvelopeParts {
        subject: e.subject.clone(),
        derivation: e.derivation.take(),
        anchor: e.anchor.clone(),
        artifact: e.artifact.clone(),
        verification: e
            .verification
            .iter()
            .map(|v| v.kind.clone())
            .zip(e.verification_content.clone())
            .collect(),
        issued_at: e.issued_at.clone(),
    };
    let request = format!(
        r#"{{"coverage":{{"expected_pin":"{}"}},"subject":{{"record":"{}"}}}}"#,
        e.anchor.digest, e.artifact_digest
    );
    sign(request.as_bytes(), parts, &key("responder")).unwrap()
}

fn status(e: &Envelope, policy: &Policy) -> Status {
    check_anchor_inclusion(e, policy).status
}

#[test]
fn a_real_log_passes_with_and_without_consistency() {
    let log_key = key("log");
    let pinned = Policy::Pinned(log_key.verifying_key());
    let log = Log::new(7);
    let first = log.checkpoint(3, None, &log_key);
    for leaf in 0..3 {
        let e = envelope(
            &log,
            leaf,
            &first,
            vec![
                (KIND_CHECKPOINT, first.clone()),
                (KIND_INCLUSION, log.inclusion(leaf as u64, 3)),
            ],
        );
        let r = check_anchor_inclusion(&e, &pinned);
        assert_eq!(r.status, Status::Pass, "leaf {leaf}: {}", r.detail);
        assert_eq!(
            r.method.as_deref(),
            Some("CLL-01 checkpoint (Ed25519) + MMR-02 inclusion")
        );
    }
    let second = log.checkpoint(7, Some(3), &log_key);
    for leaf in 0..7 {
        let e = envelope(
            &log,
            leaf,
            &second,
            vec![
                (KIND_CHECKPOINT, second.clone()),
                (KIND_INCLUSION, log.inclusion(leaf as u64, 7)),
                (KIND_CONSISTENCY, log.consistency(3, 7)),
            ],
        );
        let r = check_anchor_inclusion(&e, &pinned);
        assert_eq!(r.status, Status::Pass, "leaf {leaf}: {}", r.detail);
        assert!(r.method.unwrap().ends_with(" + MMR-02 consistency"));
    }
}

#[test]
fn the_policy_decides_steps_9() {
    let log_key = key("log");
    let log = Log::new(3);
    let cp = log.checkpoint(3, None, &log_key);
    let e = envelope(
        &log,
        1,
        &cp,
        vec![
            (KIND_CHECKPOINT, cp.clone()),
            (KIND_INCLUSION, log.inclusion(1, 3)),
        ],
    );
    assert_eq!(
        status(&e, &Policy::Always(KeyDecision::Reject)),
        Status::Fail
    );
    assert_eq!(
        status(&e, &Policy::Always(KeyDecision::Unknown)),
        Status::Inconclusive
    );
    assert_eq!(
        status(&e, &Policy::Always(KeyDecision::Excluded)),
        Status::NotChecked
    );
    // A key the policy accepts that did not sign the checkpoint: step 10.
    assert_eq!(
        status(
            &e,
            &Policy::Always(KeyDecision::Accept(key("other").verifying_key()))
        ),
        Status::Fail
    );
    assert_eq!(
        status(&e, &Policy::Pinned(key("other").verifying_key())),
        Status::Fail
    );
}

#[test]
fn steps_decide_in_order() {
    let log_key = key("log");
    let pinned = Policy::Pinned(log_key.verifying_key());
    let log = Log::new(3);
    let cp = log.checkpoint(3, None, &log_key);
    let incl = log.inclusion(1, 3);
    let with = |m: Vec<(&str, Vec<u8>)>| envelope(&log, 1, &cp, m);

    // Step 2: no material.
    assert_eq!(status(&with(vec![]), &pinned), Status::NotPresent);
    // Step 3: an unimplemented kind decides before a repeated one.
    let unknown_and_repeated = with(vec![
        (KIND_CHECKPOINT, cp.clone()),
        (KIND_CHECKPOINT, cp.clone()),
        ("witness-receipt", vec![1]),
    ]);
    assert_eq!(status(&unknown_and_repeated, &pinned), Status::NotChecked);
    assert_eq!(
        status(
            &with(vec![
                (KIND_CHECKPOINT, cp.clone()),
                (KIND_INCLUSION, incl.clone()),
                (KIND_INCLUSION, incl.clone())
            ]),
            &pinned
        ),
        Status::Fail
    );
    assert_eq!(
        status(&with(vec![(KIND_CHECKPOINT, cp.clone())]), &pinned),
        Status::NotPresent
    );
    assert_eq!(
        status(&with(vec![(KIND_INCLUSION, incl.clone())]), &pinned),
        Status::NotPresent
    );

    let good = with(vec![
        (KIND_CHECKPOINT, cp.clone()),
        (KIND_INCLUSION, incl.clone()),
    ]);
    // Step 4: material bound to an envelope that does not verify.
    let mut unbound = good.clone();
    unbound.verification_content[1].push(0);
    assert_eq!(status(&unbound, &pinned), Status::NotChecked);
    // Step 1: another subject.
    let mut other = good.clone();
    other.subject = Subject::FullHistory;
    assert_eq!(status(&resign(other), &pinned), Status::NotChecked);
    // Step 5: a record named by a digest that is not the artifact's.
    let mut renamed = good.clone();
    renamed.subject = Subject::Record("ab".repeat(32));
    assert_eq!(status(&resign(renamed), &pinned), Status::NotChecked);
    // Step 6: the checkpoint entry is not the anchor.
    let mut moved = good.clone();
    moved.anchor.digest = "cd".repeat(32);
    assert_eq!(status(&resign(moved), &pinned), Status::Fail);
    // Step 11: freshness names what the checkpoint commits, or fails.
    for (fresh, want) in [
        (AnchorFreshness::Size(node_count(3)), Status::Pass),
        (AnchorFreshness::Size(3), Status::Fail),
        (AnchorFreshness::Time(TS.into()), Status::Pass),
        (
            AnchorFreshness::Time("2026-10-15T00:00:01Z".into()),
            Status::Fail,
        ),
    ] {
        let mut f = good.clone();
        f.anchor.freshness = Some(fresh.clone());
        assert_eq!(status(&resign(f), &pinned), want, "{fresh:?}");
    }
    // Step 12: the path of another leaf, and a non-leaf index.
    let mut wrong_leaf = good.clone();
    wrong_leaf.verification_content[1] = log.inclusion(2, 3);
    assert_eq!(status(&resign(wrong_leaf), &pinned), Status::Fail);
    let mut interior = good.clone();
    interior.verification_content[1] =
        encode_cbor(&C::Array(vec![C::Integer(2.into()), C::Array(vec![])]));
    assert_eq!(status(&resign(interior), &pinned), Status::Fail);
    // Step 13: a consistency proof on a first checkpoint, and a forged one.
    let mut first_cons = good.clone();
    first_cons
        .verification
        .push(first_cons.verification[1].clone());
    first_cons.verification[2].kind = KIND_CONSISTENCY.into();
    first_cons.verification_content.push(log.consistency(1, 3));
    assert_eq!(status(&resign(first_cons), &pinned), Status::Fail);
    let log7 = Log::new(7);
    let second = log7.checkpoint(7, Some(3), &log_key);
    let mut forged = log7.consistency(3, 7);
    let n = forged.len();
    forged[n - 1] ^= 1;
    let e = envelope(
        &log7,
        4,
        &second,
        vec![
            (KIND_CHECKPOINT, second.clone()),
            (KIND_INCLUSION, log7.inclusion(4, 7)),
            (KIND_CONSISTENCY, forged),
        ],
    );
    assert_eq!(status(&e, &pinned), Status::Fail);
}

fn encode_cbor(v: &C) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).unwrap();
    out
}

/// A checkpoint statement in the profile's fixed form over `claims`, signed
/// by `signer`.
fn hand_built(claims: Vec<(C, C)>, signer: &SigningKey) -> Vec<u8> {
    hand_built_alg(claims, signer, -8)
}

/// [`hand_built`] under the COSE algorithm `alg` (the signature is Ed25519
/// whatever `alg` says).
fn hand_built_alg(claims: Vec<(C, C)>, signer: &SigningKey, alg: i64) -> Vec<u8> {
    let protected = encode_cbor(&C::Map(vec![
        (C::Integer(1.into()), C::Integer(alg.into())),
        (
            C::Integer(4.into()),
            C::Bytes(signer.verifying_key().to_bytes().to_vec()),
        ),
        (
            C::Integer(15.into()),
            C::Map(vec![
                (C::Integer(1.into()), C::Text(LOG_ID.into())),
                (C::Integer(2.into()), C::Text(format!("{LOG_ID}#4"))),
            ]),
        ),
    ]));
    let payload = encode_cbor(&C::Map(claims));
    let tbs = encode_cbor(&C::Array(vec![
        C::Text("Signature1".into()),
        C::Bytes(protected.clone()),
        C::Bytes(vec![]),
        C::Bytes(payload.clone()),
    ]));
    let sig = signer.sign(&tbs).to_bytes().to_vec();
    encode_cbor(&C::Tag(
        18,
        Box::new(C::Array(vec![
            C::Bytes(protected),
            C::Map(vec![]),
            C::Bytes(payload),
            C::Bytes(sig),
        ])),
    ))
}

#[test]
fn step_7_refuses_malformed_checkpoints_without_panicking() {
    let log_key = key("log");
    let pinned = Policy::Pinned(log_key.verifying_key());
    let log = Log::new(3);
    let size = node_count(3);
    let claims = |issued_at: &str, log_size: u64, extra: Vec<(C, C)>| {
        let mut c = vec![
            (C::Text("kind".into()), C::Text("cll-checkpoint".into())),
            (C::Text("log_size".into()), C::Integer(log_size.into())),
            (C::Text("prev_size".into()), C::Integer(0.into())),
            (C::Text("issued_at".into()), C::Text(issued_at.into())),
            (
                C::Text("commitment".into()),
                C::Bytes(commitment_object(&log.peaks(size))),
            ),
            (C::Text("prev_commitment".into()), C::Bytes(vec![])),
        ];
        c.extend(extra);
        c
    };
    let check = |cp: Vec<u8>| {
        let e = envelope(
            &log,
            0,
            &cp,
            vec![
                (KIND_CHECKPOINT, cp.clone()),
                (KIND_INCLUSION, log.inclusion(0, 3)),
            ],
        );
        check_anchor_inclusion(&e, &pinned)
    };
    assert_eq!(
        check(hand_built(claims(TS, size, vec![]), &log_key)).status,
        Status::Pass
    );
    // An RFC 3339 leap second and an offset are valid times.
    assert_eq!(
        check(hand_built(
            claims("2016-12-31T23:59:60Z", size, vec![]),
            &log_key
        ))
        .status,
        Status::Pass
    );
    assert_eq!(
        check(hand_built(
            claims("2026-10-15T02:00:00.5+02:00", size, vec![]),
            &log_key
        ))
        .status,
        Status::Pass
    );
    for bad_time in [
        "2026-10-15T00:00:0éZ",
        "2026-10-15T00:00:00+-1:00",
        "2026-10-15T00:00:61Z",
        "2026-02-30T00:00:00Z",
        "yesterday",
    ] {
        assert_eq!(
            check(hand_built(claims(bad_time, size, vec![]), &log_key)).status,
            Status::Fail,
            "{bad_time}"
        );
    }
    // Sizes above 2^53 - 1.
    assert_eq!(
        check(hand_built(claims(TS, 1 << 53, vec![]), &log_key)).status,
        Status::Fail
    );
    // A duplicate key inside an extension claim.
    let dup = C::Map(vec![
        (C::Text("x".into()), C::Integer(1.into())),
        (C::Text("x".into()), C::Integer(2.into())),
    ]);
    assert_eq!(
        check(hand_built(
            claims(TS, size, vec![(C::Text("ext".into()), dup)]),
            &log_key
        ))
        .status,
        Status::Fail
    );
    // Step 8: an algorithm other than EdDSA is not checked.
    assert_eq!(
        check(hand_built_alg(claims(TS, size, vec![]), &log_key, -7)).status,
        Status::NotChecked
    );
    // An unknown extension claim is allowed.
    assert_eq!(
        check(hand_built(
            claims(
                TS,
                size,
                vec![(C::Text("ext".into()), C::Integer(1.into()))]
            ),
            &log_key
        ))
        .status,
        Status::Pass
    );
}

#[test]
fn encode_consistency_proof_refuses_paths_that_do_not_reach() {
    let log = Log::new(7);
    let (a, b) = (node_count(3), node_count(7));
    let proof = consistency_proof(&log.store, a, b).unwrap();
    let paths: Vec<Vec<Hash>> = proof
        .witness
        .iter()
        .map(|p| p.iter().map(|h| unhex(h)).collect())
        .collect();
    assert!(encode_consistency_proof(a, b, &log.peaks(a), &paths, &log.peaks(b)).is_some());
    let mut wrong = log.peaks(b);
    wrong[0][0] ^= 1;
    assert!(encode_consistency_proof(a, b, &log.peaks(a), &paths, &wrong).is_none());
    assert!(encode_consistency_proof(0, b, &[], &[], &log.peaks(b)).is_none());
}
