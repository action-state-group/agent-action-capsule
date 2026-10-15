// SPDX-License-Identifier: BSD-3-Clause
//! Runs the shared `vectors/capsule/` and `provenance-mode-vectors/` corpora,
//! comparing what `go/verify`'s corpus tests compare: `ok`, the derived
//! assurance, the recomputed `capsule_id`, and the ordered
//! `(check, severity, code)` of every finding. Detail strings are not
//! compared; Go and Python already word some of them differently.

use agent_action_capsule::canonical::{compute_capsule_id, CanonicalError};
use agent_action_capsule::registries::Registries;
use agent_action_capsule::verify::{
    decode_capsule_json, verify_store_with, verify_with, VerificationResult,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &Path) -> Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    decode_capsule_json(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn registries() -> Registries {
    let text = std::fs::read_to_string(repo().join("spec/REGISTRY.md")).expect("spec/REGISTRY.md");
    Registries::parse(&text).expect("spec/REGISTRY.md parses")
}

fn finding_keys(result: &VerificationResult) -> Vec<String> {
    result
        .findings
        .iter()
        .map(|f| key(f.check.map(i64::from), &f.severity, &f.code))
        .collect()
}

fn key(check: Option<i64>, severity: &str, code: &str) -> String {
    let check = check.map_or("null".to_string(), |c| c.to_string());
    format!("({check},{severity},{code})")
}

/// Compares one result with one expected record; returns the mismatch.
fn compare(result: &VerificationResult, expected: &Value) -> Option<String> {
    let ok = expected["ok"].as_bool().expect("ok");
    let derived: BTreeMap<String, String> = expected["derived"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().expect("derived value").to_string()))
                .collect()
        })
        .unwrap_or_default();
    let id = expected["capsule_id_recomputed"]
        .as_str()
        .map(str::to_string);
    let findings: Vec<String> = expected["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|f| {
            key(
                f["check"].as_i64(),
                f["severity"].as_str().expect("severity"),
                f["code"].as_str().expect("code"),
            )
        })
        .collect();
    let got = finding_keys(result);
    (result.ok != ok || result.assurance != derived || result.capsule_id != id || got != findings)
        .then(|| {
            format!(
                "ok {} (want {ok}), derived {:?} (want {derived:?}), capsule_id {:?} (want {id:?}), \
                 findings {got:?} (want {findings:?})",
                result.ok, result.assurance, result.capsule_id
            )
        })
}

fn canonical_case(input: &Value, expected: &Value) -> Option<String> {
    let capsule = input.as_object().expect("canonical input is an object");
    let got = match compute_capsule_id(capsule) {
        Ok(id) => Ok(id),
        Err(CanonicalError::Float(_)) => Err("FloatInDigestError".to_string()),
        Err(CanonicalError::UnsafeInt(_)) => Err("UnsafeIntegerError".to_string()),
        Err(e) => Err(format!("{e:?}")),
    };
    let want = match expected["exception"].as_str() {
        Some(exception) => Err(exception.to_string()),
        None => Ok(expected["capsule_id_recomputed"]
            .as_str()
            .expect("capsule_id_recomputed")
            .to_string()),
    };
    (got != want).then(|| format!("{got:?} (want {want:?})"))
}

fn run_corpus(root: PathBuf) {
    let regs = registries();
    let manifest = read(&root.join("vectors.json"));
    let cases = manifest["cases"].as_array().expect("cases");
    assert_eq!(manifest["count"].as_u64(), Some(cases.len() as u64));
    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let input = read(&root.join(name).join("input.json"));
        let expected = read(&root.join(name).join("expected.json"));
        let failure = if case["kind"] == "canonical" {
            canonical_case(&input, &expected)
        } else if let Some(ledger) = input.get("ledger") {
            let ledger = ledger.as_array().expect("ledger is an array");
            let want = expected["results"].as_array().expect("results");
            let results = verify_store_with(ledger, &regs);
            if results.len() != want.len() {
                Some(format!("{} results (want {})", results.len(), want.len()))
            } else {
                results
                    .iter()
                    .zip(want)
                    .enumerate()
                    .find_map(|(i, (r, w))| compare(r, w).map(|m| format!("[{i}] {m}")))
            }
        } else {
            compare(&verify_with(&input, None, &regs), &expected)
        };
        if let Some(message) = failure {
            failures.push(format!("{name}: {message}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases diverge:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

#[test]
fn capsule_corpus() {
    run_corpus(repo().join("vectors/capsule"));
}

#[test]
fn provenance_mode_corpus() {
    run_corpus(repo().join("provenance-mode-vectors"));
}
