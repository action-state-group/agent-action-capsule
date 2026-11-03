//! The `parent-log-witness/v1` extension (Evidence Bundle draft -03, "The
//! parent-log-witness/v1 Extension"). Port of the Python reference's
//! `agent_action_capsule.parent_witness`.
//!
//! A producer can have its checkpoint witnessed without sending it to a
//! witness: the checkpoint (the Bundle's, or an earlier one of the same log
//! with a consistency proof) is a salted leaf of a Merkle tree whose root is
//! one entry of a parent log signed by the same key, and the parent log's
//! checkpoint carries the Receipts. [`verify_parent_log_witness`] checks every
//! link of that chain, then the Receipts over the parent checkpoint with
//! [`witness::verify_witness_receipts`], and computes the extent itself.
//! Nothing the block states about its extent is read.
//!
//! Strict [`super::verify_bundle_strict`] calls it when the Bundle carries the
//! block; see `vectors/bundle/parent-log-witness/`.

use super::{as_bundle_int, is_b64url, parse_inclusion_proof, B64};
use crate::canonical;
use crate::verify::is_hex64;
use crate::witness::{self, SignedCheckpoint, WitnessReceiptResult};
use base64::Engine as _;
use cll::mmr;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The extension kind.
pub const PARENT_LOG_WITNESS_KIND: &str = "parent-log-witness/v1";
/// The most hashes a path may hold.
pub const PARENT_WITNESS_MAX_PATH: usize = 32;

/// How much of the log the parent checkpoint's Receipts cover: the leaf
/// counts of the covered checkpoint and of the Bundle's checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParentWitnessExtent {
    /// Entries under the covered checkpoint: these were witnessed.
    pub entries: u64,
    /// Entries under the Bundle's checkpoint.
    pub of: u64,
}

/// The block's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentWitnessResult {
    /// `pass`, `withheld` or `fail`.
    pub status: String,
    pub findings: Vec<String>,
    /// Set only when `status` is `pass`.
    pub extent: Option<ParentWitnessExtent>,
    /// The Receipts over the parent checkpoint, once every link held.
    pub receipts: Vec<WitnessReceiptResult>,
}

impl ParentWitnessResult {
    fn fail(finding: &str) -> Self {
        ParentWitnessResult {
            status: "fail".to_string(),
            findings: vec![finding.to_string()],
            extent: None,
            receipts: Vec::new(),
        }
    }
}

/// A JSON integer from 0 to 2^53 - 1 (not a boolean or a float).
fn uint(value: Option<&Value>) -> Option<u64> {
    as_bundle_int(value).and_then(|n| u64::try_from(n).ok())
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// The tree leaf naming a checkpoint: SHA-256(0x00 || JCS(...)), with
/// `log_id`, `salt` and `size` as the block states them.
fn leaf(log_id: &Value, size: &Value, checkpoint_cose: &[u8], salt: &Value) -> Option<[u8; 32]> {
    let mut body = Map::new();
    body.insert(
        "checkpoint_sha256".into(),
        Value::String(hex::encode(sha256(&[checkpoint_cose]))),
    );
    body.insert("log_id".into(), log_id.clone());
    body.insert("salt".into(), salt.clone());
    body.insert("size".into(), size.clone());
    let bytes = canonical::jcs(&Value::Object(body)).ok()?;
    Some(sha256(&[&[0x00], &bytes]))
}

/// An interior node: SHA-256(0x01 || left || right).
fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256(&[&[0x01], left, right])
}

/// The root from a leaf, its position and its path (leaf first).
fn tree_root(leaf: [u8; 32], index: u64, path: &[[u8; 32]]) -> [u8; 32] {
    path.iter().enumerate().fold(leaf, |h, (level, sibling)| {
        if (index >> level) & 1 == 0 {
            node(&h, sibling)
        } else {
            node(sibling, &h)
        }
    })
}

enum SignedError {
    Malformed,
    Invalid,
}

/// Verifies `stated.checkpoint.cose`: `Malformed` when it is not unpadded
/// canonical base64url, `Invalid` when the octets do not verify.
fn signed_checkpoint(stated: Option<&Value>) -> Result<(SignedCheckpoint, Vec<u8>), SignedError> {
    let encoded = stated
        .and_then(Value::as_object)
        .and_then(|s| s.get("checkpoint"))
        .and_then(Value::as_object)
        .and_then(|c| c.get("cose"))
        .and_then(Value::as_str)
        .filter(|s| is_b64url(s))
        .ok_or(SignedError::Malformed)?;
    let cose = B64.decode(encoded).map_err(|_| SignedError::Malformed)?;
    let verified = cll::checkpoint::verify_checkpoint_cose_offline(&cose);
    match verified.decoded {
        Some(decoded) if verified.ok => Ok((SignedCheckpoint::from(&decoded), cose)),
        _ => Err(SignedError::Invalid),
    }
}

/// A list of 64-lowercase-hex strings.
fn hex_strings(raw: Option<&Value>) -> Option<Vec<String>> {
    raw?.as_array()?
        .iter()
        .map(|h| h.as_str().filter(|s| is_hex64(s)).map(String::from))
        .collect()
}

/// The block's consistency proof as CLL's, or `None` when its shape is not
/// the draft's.
fn consistency_proof(raw: Option<&Value>) -> Option<mmr::ConsistencyProof> {
    let raw = raw?.as_object()?;
    let old_peaks = hex_strings(raw.get("old_peaks"));
    let new_peaks = hex_strings(raw.get("new_peaks"));
    let witness: Option<Vec<Vec<String>>> = raw
        .get("witness")
        .and_then(Value::as_array)
        .and_then(|paths| paths.iter().map(|p| hex_strings(Some(p))).collect());
    let kind_ok = matches!(raw.get("kind"), Some(Value::String(k)) if k == "consistency");
    let v_ok = uint(raw.get("v")) == Some(1);
    let size_a = uint(raw.get("old_size"));
    let size_b = uint(raw.get("new_size"));
    if !kind_ok || !v_ok {
        return None;
    }
    Some(mmr::ConsistencyProof {
        v: 1,
        kind: "consistency".to_string(),
        size_a: size_a?,
        size_b: size_b?,
        old_peaks: old_peaks?,
        witness: witness?,
        new_peaks: new_peaks?,
    })
}

fn root_bytes(hex_root: &str) -> Option<[u8; 32]> {
    hex::decode(hex_root).ok()?.try_into().ok()
}

/// Checks a `parent-log-witness/v1` block against the Bundle's SIGNED
/// checkpoint (`signed`: its fields as `checkpoint.cose` states them and its
/// COSE octets; `None` when it did not verify), and the Receipts over the
/// parent checkpoint under `directory` (`None` trusts no witness). Never
/// panics on its input.
pub fn verify_parent_log_witness(
    block: &Value,
    signed: Option<(&SignedCheckpoint, &[u8])>,
    directory: Option<&Value>,
) -> ParentWitnessResult {
    let (signed, checkpoint_cose) = match signed {
        Some(s) => s,
        None => {
            return ParentWitnessResult {
                status: "withheld".to_string(),
                findings: vec!["checkpoint_unverified".to_string()],
                extent: None,
                receipts: Vec::new(),
            }
        }
    };
    let block = match block.as_object() {
        Some(b) => b,
        None => return ParentWitnessResult::fail("parent_witness_malformed"),
    };

    let mut prior_holder = None;
    if let Some(earlier) = block.get("earlier") {
        let (prior, prior_cose) = match signed_checkpoint(Some(earlier)) {
            Ok(p) => p,
            Err(SignedError::Malformed) => {
                return ParentWitnessResult::fail("parent_witness_earlier_checkpoint_malformed")
            }
            Err(SignedError::Invalid) => {
                return ParentWitnessResult::fail(
                    "parent_witness_earlier_checkpoint_signature_invalid",
                )
            }
        };
        if prior.key_id != signed.key_id
            || prior.log_id != signed.log_id
            || prior.mmr_size >= signed.mmr_size
        {
            return ParentWitnessResult::fail("parent_witness_earlier_checkpoint_not_this_log");
        }
        let proven = consistency_proof(earlier.get("consistency_proof")).is_some_and(|proof| {
            proof.size_a == prior.mmr_size
                && proof.size_b == signed.mmr_size
                && match (root_bytes(&prior.root), root_bytes(&signed.root)) {
                    (Some(a), Some(b)) => {
                        mmr::verify_consistency(&a, prior.mmr_size, &b, signed.mmr_size, &proof)
                    }
                    _ => false,
                }
        });
        if !proven {
            return ParentWitnessResult::fail("parent_witness_earlier_checkpoint_not_a_prefix");
        }
        prior_holder = Some((prior, prior_cose));
    }
    let (covered, covered_cose): (&SignedCheckpoint, &[u8]) = match &prior_holder {
        Some((prior, cose)) => (prior, cose),
        None => (signed, checkpoint_cose),
    };

    let (log_id, size) = (block.get("log_id"), block.get("size"));
    let names_it = matches!(log_id, Some(Value::String(l)) if *l == covered.log_id)
        && uint(size) == Some(covered.mmr_size);
    if !names_it {
        return ParentWitnessResult::fail("parent_witness_leaf_does_not_name_this_checkpoint");
    }
    let path: Option<Vec<[u8; 32]>> = block
        .get("path")
        .and_then(Value::as_array)
        .filter(|p| p.len() <= PARENT_WITNESS_MAX_PATH)
        .and_then(|p| {
            p.iter()
                .map(|h| h.as_str().filter(|s| is_hex64(s)).and_then(root_bytes))
                .collect()
        });
    let path = match path {
        Some(p) => p,
        None => return ParentWitnessResult::fail("parent_witness_path_malformed"),
    };
    let salt = block.get("salt");
    let index = uint(block.get("index"));
    let index = match (salt, index) {
        (Some(Value::String(s)), Some(i)) if !s.is_empty() && i < 1u64 << path.len() => i,
        _ => return ParentWitnessResult::fail("parent_witness_leaf_malformed"),
    };
    // log_id, size and salt are present: checked above.
    let leaf_hash = match (log_id, size, salt) {
        (Some(l), Some(n), Some(s)) => leaf(l, n, covered_cose, s),
        _ => None,
    };
    let leaf_hash = match leaf_hash {
        Some(h) => h,
        None => return ParentWitnessResult::fail("parent_witness_leaf_malformed"),
    };
    let root = tree_root(leaf_hash, index, &path);

    let parent = block.get("parent");
    let (parent_signed, parent_cose) = match signed_checkpoint(parent) {
        Ok(p) => p,
        Err(SignedError::Malformed) => {
            return ParentWitnessResult::fail("parent_witness_parent_checkpoint_malformed")
        }
        Err(SignedError::Invalid) => {
            return ParentWitnessResult::fail("parent_witness_parent_checkpoint_signature_invalid")
        }
    };
    // signed_checkpoint succeeded, so `parent` is an object.
    let empty = Map::new();
    let parent = parent.and_then(Value::as_object).unwrap_or(&empty);
    if parent_signed.key_id != signed.key_id {
        return ParentWitnessResult::fail("parent_witness_parent_signer_differs");
    }
    if !matches!(parent.get("log_id"), Some(Value::String(l)) if *l == parent_signed.log_id) {
        return ParentWitnessResult::fail("parent_witness_parent_log_id_mismatch");
    }
    let included = match (
        uint(parent.get("entry_index")),
        parse_inclusion_proof(parent.get("inclusion_proof")),
        root_bytes(&parent_signed.root),
    ) {
        (Some(entry_index), Some(proof), Some(parent_root)) => {
            proof.size == parent_signed.mmr_size
                && proof.leaf_index == entry_index
                && mmr::verify_inclusion(
                    &parent_root,
                    parent_signed.mmr_size,
                    entry_index,
                    &root,
                    &proof,
                )
        }
        _ => false,
    };
    if !included {
        return ParentWitnessResult::fail("parent_witness_entry_not_included");
    }

    let report = witness::verify_witness_receipts(
        parent.get("witnesses"),
        Some(&parent_signed),
        Some(&parent_cose),
        directory,
    );
    let extent = if report.status == "pass" {
        match (
            mmr::leaf_count(covered.mmr_size),
            mmr::leaf_count(signed.mmr_size),
        ) {
            (Ok(entries), Ok(of)) => Some(ParentWitnessExtent { entries, of }),
            // A verified checkpoint's size is a valid MMR size.
            _ => None,
        }
    } else {
        None
    };
    ParentWitnessResult {
        status: report.status,
        findings: report.findings,
        extent,
        receipts: report.receipts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_root_follows_the_index_bits() {
        let (l, a, b) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        assert_eq!(tree_root(l, 0, &[]), l);
        assert_eq!(tree_root(l, 0b10, &[a, b]), node(&b, &node(&l, &a)));
        assert_eq!(tree_root(l, 0b01, &[a, b]), node(&node(&a, &l), &b));
    }

    #[test]
    fn integers_keep_their_json_type() {
        assert_eq!(uint(Some(&json!(4))), Some(4));
        assert_eq!(uint(Some(&json!(4.0))), None);
        assert_eq!(uint(Some(&json!(true))), None);
        assert_eq!(uint(Some(&json!(-1))), None);
        assert_eq!(uint(Some(&json!("4"))), None);
    }

    #[test]
    fn a_consistency_proof_needs_the_draft_shape() {
        let h = "ab".repeat(32);
        let good = json!({"v": 1, "kind": "consistency", "old_size": 3, "new_size": 4,
            "old_peaks": [h], "witness": [[h]], "new_peaks": [h]});
        assert!(consistency_proof(Some(&good)).is_some());
        for (member, bad) in [
            ("v", json!(true)),
            ("v", json!(1.0)),
            ("kind", json!("inclusion")),
            ("old_size", json!(3.0)),
            ("witness", json!([h])),
            ("new_peaks", json!([h.to_uppercase()])),
        ] {
            let mut proof = good.clone();
            proof[member] = bad;
            assert!(consistency_proof(Some(&proof)).is_none(), "{member}");
        }
    }

    #[test]
    fn without_a_verified_checkpoint_the_block_is_withheld() {
        let result = verify_parent_log_witness(&json!([]), None, None);
        assert_eq!(result.status, "withheld");
        assert_eq!(result.findings, ["checkpoint_unverified"]);
    }
}
