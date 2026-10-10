// SPDX-License-Identifier: BSD-3-Clause
//! Runs the Class 1 verifier over the shared `vectors/capsule/` corpus that
//! the Python, Go and TypeScript verifiers run.
//!
//! This crate ports checks 1-7 and 9 and omits check 8 by design (see the
//! scope note in `src/verify.rs`), and every check-8 finding is `info`. So each
//! bare-Capsule case is compared on `ok`, the recomputed `capsule_id`, and the
//! ordered (check, severity, code) of every finding that is not `info`.
//! Canonicalization cases (no `ok`) and store cases (`{"ledger": [...]}`) are
//! skipped: they exercise surfaces this crate does not expose.
//!
//! The provenance-mode corpus (check 9) runs the same way.

use aac_bundle::verify::verify;
use serde_json::Value;
use std::path::PathBuf;

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/capsule")
}

fn provenance_corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../provenance-mode-vectors")
}

fn read(path: PathBuf) -> Value {
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn gating(findings: impl Iterator<Item = (Option<i64>, String, String)>) -> Vec<String> {
    findings
        .filter(|(_, severity, _)| severity != "info")
        .map(|(check, severity, code)| format!("({check:?},{severity},{code})"))
        .collect()
}

#[test]
fn capsule_corpus_matches_the_siblings() {
    check_corpus(corpus(), |_| true);
}

#[test]
fn provenance_mode_corpus_matches_the_siblings() {
    check_corpus(provenance_corpus(), |_| true);
}

fn check_corpus(root: PathBuf, select: impl Fn(&str) -> bool) {
    let manifest = read(root.join("vectors.json"));
    let mut run = 0;
    let mut failures = Vec::new();
    for case in manifest["cases"].as_array().expect("cases") {
        let name = case["name"].as_str().expect("name");
        if !select(name) {
            continue;
        }
        let input = read(root.join(name).join("input.json"));
        let expected = read(root.join(name).join("expected.json"));
        let Some(ok) = expected.get("ok").and_then(Value::as_bool) else {
            continue;
        };
        if input.get("ledger").is_some() {
            continue;
        }
        run += 1;
        let result = verify(&input, None);
        let got = gating(
            result
                .findings
                .iter()
                .map(|f| (f.check.map(i64::from), f.severity.clone(), f.code.clone())),
        );
        let want = gating(
            expected["findings"]
                .as_array()
                .expect("findings")
                .iter()
                .map(|f| {
                    (
                        f["check"].as_i64(),
                        f["severity"].as_str().expect("severity").to_string(),
                        f["code"].as_str().expect("code").to_string(),
                    )
                }),
        );
        let want_id = expected["capsule_id_recomputed"]
            .as_str()
            .map(str::to_string);
        if result.ok != ok || got != want || result.capsule_id != want_id {
            failures.push(format!(
                "{name}: ok {} (want {ok}), findings {got:?} (want {want:?}), capsule_id {:?} (want {want_id:?})",
                result.ok, result.capsule_id
            ));
        }
    }
    assert!(run > 0, "no cases ran in {}", root.display());
    assert!(
        failures.is_empty(),
        "{} of {run} cases diverge:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn null_effect_attestation_counts_as_absent() {
    // As in Go, Python and TS: a null effect_attestation is absent, so a
    // not_applicable effect with one is not effect_attestation_present.
    let manifest = read(corpus().join("vectors.json"));
    let name = manifest["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .filter_map(|case| case["name"].as_str())
        .find(|name| {
            let input = read(corpus().join(name).join("input.json"));
            input["effect"].is_null()
                && read(corpus().join(name).join("expected.json"))["ok"] == Value::Bool(true)
        })
        .expect("a positive case without an effect block");
    let mut input = read(corpus().join(name).join("input.json"));
    input["effect"] =
        serde_json::json!({"status": "planned", "type": "x", "effect_attestation": null});
    let codes: Vec<String> = verify(&input, None)
        .findings
        .into_iter()
        .map(|f| f.code)
        .collect();
    assert!(
        !codes.contains(&"effect_attestation_present".to_string()),
        "{codes:?}"
    );
}
