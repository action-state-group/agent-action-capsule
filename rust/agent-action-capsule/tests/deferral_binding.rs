// SPDX-License-Identifier: BSD-3-Clause
//! The §5.4.4 deferral binding rule through `verify`'s own store argument. The
//! capsule corpus reaches it only through `verify_store`; these cover an
//! id-only store and a forged parent copy.

use agent_action_capsule::verify::{decode_capsule_json, verify, VerificationResult};
use serde_json::Value;
use std::path::PathBuf;

fn ledger() -> Vec<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/capsule/neg-supersedes-action-mismatch/input.json");
    let bytes = std::fs::read(&path).expect("vector input");
    let input = decode_capsule_json(&bytes).expect("vector decodes");
    input["ledger"].as_array().expect("ledger").clone()
}

fn codes(result: &VerificationResult) -> Vec<String> {
    result
        .findings
        .iter()
        .map(|f| format!("{}/{}", f.code, f.severity))
        .collect()
}

#[test]
fn id_only_store_is_not_evaluated() {
    let ledger = ledger();
    let store = vec![ledger[0]["capsule_id"].clone()];
    let result = verify(&ledger[1], Some(&store));
    assert!(result.ok);
    let codes = codes(&result);
    assert!(codes.contains(&"deferral_binding_not_evaluated/info".to_string()));
    assert!(!codes.contains(&"supersedes_action_mismatch/error".to_string()));
}

#[test]
fn forged_parent_copy_does_not_capture() {
    let ledger = ledger();
    let mut forged = ledger[0].clone();
    forged["action_id"] = ledger[1]["action_id"].clone();
    let store = vec![forged, ledger[0].clone(), ledger[1].clone()];
    let result = verify(&ledger[1], Some(&store));
    assert!(!result.ok);
    assert!(codes(&result).contains(&"supersedes_action_mismatch/error".to_string()));
}
