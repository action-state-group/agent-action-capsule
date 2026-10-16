//! `encode_inclusion_proof` and `encode_consistency_proof` against
//! `vectors/cll-material/`: for every case, the octets the corpus states.
//! Python's and Go's encoders are checked against the same file.

use evidence_request::cll_material::{
    encode_consistency_proof, encode_inclusion_proof, KIND_CONSISTENCY, KIND_INCLUSION,
};
use serde_json::Value;

type Hash = [u8; 32];

fn nodes(value: &Value) -> Vec<Hash> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            hex::decode(h.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect()
}

#[test]
fn encoders_match_the_corpus() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/cll-material/cases.json"
    );
    let corpus: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 184);
    assert_eq!(corpus["count"], 184);
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let inputs = &case["inputs"];
        let octets = match case["kind"].as_str().unwrap() {
            KIND_INCLUSION => {
                encode_inclusion_proof(inputs["leaf"].as_u64().unwrap(), &nodes(&inputs["path"]))
            }
            KIND_CONSISTENCY => {
                let paths: Vec<Vec<Hash>> = inputs["paths"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(nodes)
                    .collect();
                encode_consistency_proof(
                    inputs["old_size"].as_u64().unwrap(),
                    inputs["new_size"].as_u64().unwrap(),
                    &nodes(&inputs["old_peaks"]),
                    &paths,
                    &nodes(&inputs["new_peaks"]),
                )
            }
            other => panic!("{id}: unknown kind {other}"),
        };
        assert_eq!(
            hex::encode(octets.unwrap_or_else(|| panic!("{id}: encoder refused"))),
            case["expected"]["octets_hex"].as_str().unwrap(),
            "{id}"
        );
    }
}
