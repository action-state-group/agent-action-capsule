// SPDX-License-Identifier: BSD-3-Clause
//! `testdata/vectors.json` is a pinned copy of `vectors/bundle/vectors.json`
//! (identical to `go/bundle/testdata/vectors.json`). This test constructs its
//! portable proof material exactly as the Go/Python references do, using
//! `cll`'s low-level MMR functions directly (the Rust `cll` crate has no
//! stateful tree wrapper like Go's `cll-go/mmr.New()`).

use aac_bundle::canonical;
use aac_bundle::{decode_fragment, encode_fragment, verify_bundle, VerificationResult};
use cll::mmr::{self, MemoryNodeStore, NodeReader};
use cll::range_proof;
use serde_json::{json, Map, Value};

struct TestTree {
    nodes: MemoryNodeStore,
}

impl TestTree {
    fn new() -> Self {
        TestTree {
            nodes: MemoryNodeStore::new(),
        }
    }

    fn append_hex_identity(&mut self, hex_id: &str) {
        let bytes: [u8; 32] = hex::decode(hex_id)
            .expect("test fixture: valid hex")
            .try_into()
            .expect("test fixture: 32 bytes");
        let leaf = mmr::leaf_hash(&bytes);
        mmr::add_leaf(&mut self.nodes, leaf).expect("test fixture: add_leaf");
    }

    fn size(&self) -> u64 {
        self.nodes.size()
    }

    fn root(&self) -> [u8; 32] {
        let peak_positions = mmr::peaks(self.nodes.size()).expect("test fixture: peaks");
        let peak_hashes: Vec<[u8; 32]> =
            peak_positions.iter().map(|p| self.nodes.node(*p)).collect();
        mmr::root_from_peaks(&peak_hashes)
    }

    fn inclusion_proof(&self, leaf_index: u64, size: u64) -> mmr::InclusionProof {
        mmr::inclusion_proof(&self.nodes, leaf_index, size).expect("test fixture: inclusion_proof")
    }

    fn range_proof(&self, from_index: u64, to_index: u64, size: u64) -> range_proof::RangeProof {
        range_proof::range_proof(&self.nodes, from_index, to_index, size)
            .expect("test fixture: range_proof")
    }
}

fn proof_to_value(p: &mmr::InclusionProof) -> Value {
    json!({
        "v": p.v, "kind": p.kind, "size": p.size, "leaf_index": p.leaf_index,
        "witness": p.witness, "peaks_left": p.peaks_left, "peaks_right": p.peaks_right,
    })
}

fn range_proof_to_value(
    from_seq: i64,
    to_seq: i64,
    size: u64,
    p: &range_proof::RangeProof,
) -> Value {
    json!({
        "from_seq": from_seq, "to_seq": to_seq, "size": size,
        "from_index": p.from_index, "to_index": p.to_index, "witness": p.witness,
    })
}

fn capsule_id(capsule: &Map<String, Value>) -> &str {
    capsule["capsule_id"]
        .as_str()
        .expect("test fixture: capsule_id")
}

fn test_capsule(
    number: u32,
    output: Option<Value>,
    input: Option<Value>,
    chain: Option<Value>,
) -> Map<String, Value> {
    let mut capsule = Map::new();
    capsule.insert(
        "spec_version".into(),
        json!("draft-mih-scitt-agent-action-capsule-04"),
    );
    capsule.insert("format_version".into(), json!("4"));
    capsule.insert("canonicalization_id".into(), json!("jcs"));
    capsule.insert("action_id".into(), json!(format!("bundle-{number}")));
    capsule.insert("action_type".into(), json!("decide"));
    capsule.insert("operator".into(), json!("ACME-CO"));
    capsule.insert("developer".into(), json!("agent@v1"));
    capsule.insert(
        "timestamp".into(),
        json!(format!("2026-09-14T00:00:0{number}Z")),
    );
    capsule.insert(
        "assurance".into(),
        json!({"effect_mode": "not_applicable", "attestation_mode": "self_attested", "ledger_mode": "standalone"}),
    );
    capsule.insert(
        "disposition".into(),
        json!({"verdict_class": "blocked", "decision": "reject", "approver": "policy", "human_disposed": false}),
    );
    if let Some(output) = output {
        let digest = canonical::json_digest(&output).expect("test fixture: digest");
        capsule.insert(
            "model_attestation".into(),
            json!({"compute_attestation": {"agent_output_digest": digest}}),
        );
    }
    if let Some(input) = input {
        let digest = canonical::json_digest(&input).expect("test fixture: digest");
        capsule.insert(
            "model_attestation".into(),
            json!({"compute_attestation": {"agent_input_digest": digest}}),
        );
    }
    if let Some(chain) = chain {
        capsule.insert("chain".into(), chain);
    }
    let id = canonical::compute_capsule_id(&capsule).expect("test fixture: capsule id");
    capsule.insert("capsule_id".into(), json!(id));
    capsule
}

fn test_bundle(
    records: &[Map<String, Value>],
    root: &Map<String, Value>,
    overlay: Option<Value>,
    missing: &[String],
) -> Value {
    let mut tree = TestTree::new();
    for record in records {
        tree.append_hex_identity(capsule_id(record));
    }
    let size = tree.size();
    let root_hash = tree.root();

    let mut members = Map::new();
    for (index, record) in records.iter().enumerate() {
        let proof = tree.inclusion_proof(index as u64, size);
        members.insert(
            capsule_id(record).to_string(),
            json!({
                "log_coordinates": {"log_id": "bundle-log", "seq": index + 1, "leaf_index": index},
                "inclusion_proof": proof_to_value(&proof),
            }),
        );
    }
    let range_p = tree.range_proof(0, (records.len() - 1) as u64, size);
    let body_digests: Vec<Value> = records.iter().map(|r| r["capsule_id"].clone()).collect();
    let overlay = overlay.unwrap_or_else(|| json!({}));
    let mode = if missing.is_empty() {
        "complete"
    } else {
        "declared_incomplete"
    };

    json!({
        "bundle_version": "2", "bundle_kind": "evidence-bundle/v2", "root": root["capsule_id"],
        "records": records.iter().cloned().map(Value::Object).collect::<Vec<_>>(),
        "completeness": {
            "closure_depth": 2, "records_mode": mode, "payloads_mode": "selected",
            "suppressed_fields": ["agent_input"], "missing": missing,
        },
        "disclosures": overlay,
        "completeness_certificate": {
            "log_id": "bundle-log", "range_root": hex::encode(root_hash), "first_seq": 1, "last_seq": records.len(),
            "body_digests": body_digests,
            "range_proof": range_proof_to_value(1, records.len() as i64, size, &range_p),
            "memberships": members,
        },
        "checkpoint": {"root": hex::encode(root_hash), "mmr_size": size},
        "extensions": {"example/unimplemented": {"note": "digest-covered only"}},
    })
}

fn memberships_mut(bundle: &mut Map<String, Value>) -> &mut Map<String, Value> {
    bundle
        .get_mut("completeness_certificate")
        .expect("test fixture")
        .as_object_mut()
        .expect("test fixture")
        .get_mut("memberships")
        .expect("test fixture")
        .as_object_mut()
        .expect("test fixture")
}

fn inclusion_proof_mut<'a>(
    bundle: &'a mut Map<String, Value>,
    id: &str,
) -> &'a mut Map<String, Value> {
    memberships_mut(bundle)
        .get_mut(id)
        .expect("test fixture")
        .as_object_mut()
        .expect("test fixture")
        .get_mut("inclusion_proof")
        .expect("test fixture")
        .as_object_mut()
        .expect("test fixture")
}

fn test_case(name: &str) -> Value {
    let output = json!({"answer": {"steps": ["check", "approve"], "total": "42"}});
    let input = json!({"request": {"account": "A-17", "amount": "42.00"}});
    let first = test_capsule(1, Some(output.clone()), None, None);
    let middle = test_capsule(2, None, Some(input.clone()), None);
    let root = test_capsule(3, None, None, None);
    let mut overlay = Map::new();
    overlay.insert(
        capsule_id(&first).to_string(),
        json!({"agent_output": output}),
    );
    let mut bundle = test_bundle(
        &[first.clone(), middle.clone(), root.clone()],
        &root,
        Some(Value::Object(overlay)),
        &[],
    );

    match name {
        "neg-deleted-interior-record" => {
            let b = bundle.as_object_mut().expect("test fixture");
            b.insert(
                "records".into(),
                json!([Value::Object(first.clone()), Value::Object(root.clone())]),
            );
            memberships_mut(b).remove(capsule_id(&middle));
        }
        "neg-replaced-interior-record" => {
            let replacement = test_capsule(9, None, Some(input.clone()), None);
            let b = bundle.as_object_mut().expect("test fixture");
            let proof = memberships_mut(b)
                .remove(capsule_id(&middle))
                .expect("test fixture");
            b.insert(
                "records".into(),
                json!([
                    Value::Object(first.clone()),
                    Value::Object(replacement.clone()),
                    Value::Object(root.clone())
                ]),
            );
            memberships_mut(b).insert(capsule_id(&replacement).to_string(), proof);
        }
        "neg-dangling-citation" | "pos-declared-missing-citation" => {
            let absent = "f".repeat(64);
            let chain = json!({"parent_capsule_id": absent, "relation": "derived_from"});
            let cited_root = test_capsule(4, None, None, Some(chain));
            let missing: Vec<String> = if name == "pos-declared-missing-citation" {
                vec![absent]
            } else {
                vec![]
            };
            bundle = test_bundle(
                &[first.clone(), middle.clone(), cited_root.clone()],
                &cited_root,
                None,
                &missing,
            );
        }
        "pos-valid-bundle" | "neg-disclosure-mismatch-nested-match" => {
            if name == "neg-disclosure-mismatch-nested-match" {
                let b = bundle.as_object_mut().expect("test fixture");
                let disclosures = b
                    .get_mut("disclosures")
                    .expect("test fixture")
                    .as_object_mut()
                    .expect("test fixture");
                disclosures.insert(
                    capsule_id(&middle).to_string(),
                    json!({"agent_input": {"request": {"account": "A-17", "amount": "99.00"}}}),
                );
            }
        }
        "neg-supplied-record-unbound" => {
            let extra = test_capsule(9, None, None, None);
            let b = bundle.as_object_mut().expect("test fixture");
            b.get_mut("records")
                .expect("test fixture")
                .as_array_mut()
                .expect("test fixture")
                .push(Value::Object(extra));
        }
        "neg-membership-proof-coordinate-mismatch" => {
            let b = bundle.as_object_mut().expect("test fixture");
            let id = capsule_id(&middle).to_string();
            inclusion_proof_mut(b, &id).insert("leaf_index".into(), json!(0));
        }
        "neg-producer-asserted-checkpoint" => {
            // The default fixture deliberately has no independently verifiable checkpoint receipt.
        }
        "pos-default-completeness-values" => {
            let b = bundle.as_object_mut().expect("test fixture");
            let completeness = b
                .get_mut("completeness")
                .expect("test fixture")
                .as_object_mut()
                .expect("test fixture");
            completeness.remove("closure_depth");
            completeness.remove("missing");
        }
        "neg-portable-proof-version-kind" => {
            let b = bundle.as_object_mut().expect("test fixture");
            let id = capsule_id(&middle).to_string();
            let proof = inclusion_proof_mut(b, &id);
            proof.insert("v".into(), json!(2));
            proof.insert("kind".into(), json!("not-inclusion"));
        }
        "neg-boolean-proof-integer" => {
            let b = bundle.as_object_mut().expect("test fixture");
            let id = capsule_id(&middle).to_string();
            inclusion_proof_mut(b, &id).insert("v".into(), json!(true));
        }
        other => panic!("unknown vector {other:?}"),
    }
    bundle
}

#[derive(serde::Deserialize)]
struct Expected {
    graph_closure: String,
    interval_coverage: String,
    per_record_membership: String,
    disclosures: Option<Vec<String>>,
    interval_findings: Option<Vec<String>>,
    membership_findings: Option<Vec<String>>,
}

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    expected: Expected,
}

#[derive(serde::Deserialize)]
struct Manifest {
    count: usize,
    cases: Vec<Case>,
}

fn manifest() -> Manifest {
    let data = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/vectors.json"
    ))
    .expect("testdata/vectors.json");
    serde_json::from_str(&data).expect("valid manifest JSON")
}

fn compare_claims(a: &VerificationResult, b: &VerificationResult) {
    assert_eq!(a.graph_closure, b.graph_closure);
    assert_eq!(a.interval_coverage, b.interval_coverage);
    assert_eq!(a.per_record_membership, b.per_record_membership);
}

#[test]
fn bundle_vectors() {
    let manifest = manifest();
    assert_eq!(manifest.count, 12);
    assert_eq!(manifest.cases.len(), manifest.count);

    for case in &manifest.cases {
        let input = test_case(&case.name);
        let fragment = encode_fragment(&input).expect("encode");
        let decoded = decode_fragment(&fragment).expect("decode");

        let result = verify_bundle(&input);
        let decoded_result = verify_bundle(&decoded);
        compare_claims(&result, &decoded_result);

        assert_eq!(
            case.expected.graph_closure, result.graph_closure.status,
            "case {}",
            case.name
        );
        assert_eq!(
            case.expected.interval_coverage, result.interval_coverage.status,
            "case {}",
            case.name
        );
        assert_eq!(
            case.expected.per_record_membership, result.per_record_membership.status,
            "case {}",
            case.name
        );
        if let Some(expected_disclosures) = &case.expected.disclosures {
            let mut actual: Vec<String> = result
                .disclosures
                .iter()
                .map(|d| d.status.clone())
                .collect();
            actual.sort();
            let mut expected = expected_disclosures.clone();
            expected.sort();
            assert_eq!(expected, actual, "case {} disclosures", case.name);
        }
        if let Some(expected_findings) = &case.expected.interval_findings {
            assert_eq!(
                expected_findings, &result.interval_coverage.findings,
                "case {} interval findings",
                case.name
            );
        }
        if let Some(expected_findings) = &case.expected.membership_findings {
            assert_eq!(
                expected_findings, &result.per_record_membership.findings,
                "case {} membership findings",
                case.name
            );
        }
    }
}

#[test]
fn fragment_codec_and_digest() {
    let bundle = json!({
        "b": 1,
        "a": "value",
        "countersignatures": [{"type": "cose-sign1", "signature": "ignored-by-digest"}],
    });
    let fragment = encode_fragment(&bundle).expect("encode");
    assert_eq!(
        fragment,
        "eyJhIjoidmFsdWUiLCJiIjoxLCJjb3VudGVyc2lnbmF0dXJlcyI6W3sic2lnbmF0dXJlIjoiaWdub3JlZC1ieS1kaWdlc3QiLCJ0eXBlIjoiY29zZS1zaWduMSJ9XX0"
    );
    let decoded = decode_fragment(&fragment).expect("decode");
    assert_eq!(bundle, decoded);
    let digest = aac_bundle::bundle_digest(&bundle).expect("digest");
    assert_eq!(
        digest,
        "04a0f2c6e056b32f5659fdec506f9f6d6a0b250227004b0fd7ed43d0b77035a5"
    );

    // "{}{}" is unpadded-base64url-valid but carries trailing content past one JSON value.
    use base64::Engine as _;
    let trailing = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}{}");
    assert!(decode_fragment(&trailing).is_err());

    let result = verify_bundle(&json!({
        "countersignatures": ["reserved"],
        "verification": {"producer": "claimed"},
    }));
    assert_eq!(result.countersignatures.len(), 1);
    assert_eq!(result.countersignatures[0].value, json!("reserved"));
    assert_eq!(result.countersignatures[0].status, "unverified");
    let verification = result.verification.expect("verification present");
    assert_eq!(verification.value, json!({"producer": "claimed"}));
    assert_eq!(verification.status, "producer_self_report");
}

/// The bundle-level negative for the CLL #13 every-leaf binding: a
/// well-formed but wrong interior body digest must fail interval coverage
/// (a two-endpoint check would miss it). Cross-language: this is the Rust
/// sibling of Python's Rust-only-until-now `neg-interval-body-digest-altered`
/// case (`python/tests/test_bundle_vectors.py`), kept out of the shared
/// manifest there because it pins CLL #13 behavior specifically -- ported
/// here since this crate's `verify_range_claim` binds every leaf the same way.
#[test]
fn range_rejects_altered_interior_body_digest() {
    let mut bundle = test_case("pos-valid-bundle");
    let cert = bundle
        .as_object_mut()
        .expect("test fixture")
        .get_mut("completeness_certificate")
        .expect("test fixture")
        .as_object_mut()
        .expect("test fixture");
    let body = cert
        .get_mut("body_digests")
        .expect("test fixture")
        .as_array_mut()
        .expect("test fixture");
    body[1] = json!("aa".repeat(32));
    let result = verify_bundle(&bundle);
    assert_eq!(result.interval_coverage.status, "fail");
    assert!(result
        .interval_coverage
        .findings
        .contains(&"range_proof_invalid".to_string()));
}

/// F1 regression: the interval must end at the checkpoint tip
/// (`leaf_count(size) == last_seq`). A sub-tip range -- here `[1,3]` proved
/// against a 4-leaf tree (size 7) -- has a valid core range proof and root,
/// so without the tip bind it verifies; records after `last_seq` could then
/// be silently omitted.
#[test]
fn interval_rejects_sub_tip_range() {
    let caps: Vec<Map<String, Value>> =
        (1..=4).map(|n| test_capsule(n, None, None, None)).collect();
    let mut tree = TestTree::new();
    for c in &caps {
        tree.append_hex_identity(capsule_id(c));
    }
    let size = tree.size();
    let root_hash = tree.root();
    let range_p = tree.range_proof(0, 2, size);
    let records = &caps[..3];
    let mut members = Map::new();
    for (i, c) in records.iter().enumerate() {
        let proof = tree.inclusion_proof(i as u64, size);
        members.insert(
            capsule_id(c).to_string(),
            json!({
                "log_coordinates": {"log_id": "bundle-log", "seq": i + 1, "leaf_index": i},
                "inclusion_proof": proof_to_value(&proof),
            }),
        );
    }
    let bundle = json!({
        "bundle_version": "2", "bundle_kind": "evidence-bundle/v2", "root": records[2]["capsule_id"],
        "records": records.iter().cloned().map(Value::Object).collect::<Vec<_>>(),
        "completeness": {"records_mode": "complete", "missing": []},
        "completeness_certificate": {
            "log_id": "bundle-log", "range_root": hex::encode(root_hash), "first_seq": 1, "last_seq": 3,
            "body_digests": [records[0]["capsule_id"], records[1]["capsule_id"], records[2]["capsule_id"]],
            "range_proof": range_proof_to_value(1, 3, size, &range_p),
            "memberships": members,
        },
        "checkpoint": {"root": hex::encode(root_hash), "mmr_size": size},
    });
    let result = verify_bundle(&bundle);
    assert_eq!(result.interval_coverage.status, "fail");
    assert!(result
        .interval_coverage
        .findings
        .contains(&"range_proof_invalid".to_string()));
}
