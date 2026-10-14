// SPDX-License-Identifier: BSD-3-Clause
//! Runs the shared `vectors/producer-envelope/` corpus, as
//! `go/envelope/vectors_test.go` does.

use agent_action_capsule::envelope::verify;
use serde_json::Value;
use std::path::PathBuf;

#[test]
fn producer_envelope_corpus() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/producer-envelope");
    let read_json = |path: PathBuf| -> Value {
        serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("json")
    };
    let manifest = read_json(root.join("vectors.json"));
    let cases = manifest["cases"].as_array().expect("cases");
    assert_eq!(manifest["count"].as_u64(), Some(cases.len() as u64));
    for case in cases {
        let dir = root.join(case["name"].as_str().expect("name"));
        let capsule_id = std::fs::read_to_string(dir.join("capsule_id.txt")).expect("capsule_id");
        let envelope = std::fs::read(dir.join("envelope.cose")).expect("envelope");
        let expected = read_json(dir.join("expected.json"));

        let result = verify(capsule_id.trim(), &envelope);
        let codes: Vec<&str> = result.findings.iter().map(|f| f.code.as_str()).collect();
        let want: Vec<&str> = expected["finding_codes"]
            .as_array()
            .expect("finding_codes")
            .iter()
            .map(|c| c.as_str().expect("code"))
            .collect();
        assert_eq!(result.ok, expected["ok"].as_bool().expect("ok"), "{dir:?}");
        assert_eq!(codes, want, "{dir:?}");
        let key = expected["public_key_hex"].as_str().unwrap_or("");
        assert_eq!(hex::encode(&result.public_key), key, "{dir:?}");
    }
}
