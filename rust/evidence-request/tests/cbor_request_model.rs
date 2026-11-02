//! `vectors/cbor-request-model/` through the crate's CBOR request reader: a
//! request is read only in core deterministic encoding with every item,
//! inside ignored members too, in the request data model, as Go and Python
//! read it (#529).

use evidence_request::request::{parse_cbor, RequestError};
use serde_json::Value;

#[test]
fn request_reader_reads_only_the_data_model() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/cbor-request-model/cases.json"
    );
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let cases = doc["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 18);
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let octets = hex::decode(case["cbor_hex"].as_str().unwrap()).unwrap();
        let request = parse_cbor(&octets);
        if case["accept"].as_bool().unwrap() {
            assert_eq!(request.unwrap().nonce.as_deref(), Some("n-1"), "{id}");
        } else {
            assert!(
                matches!(request, Err(RequestError::Malformed(_))),
                "{id}: {request:?}"
            );
        }
    }
}
