//! `vectors/cbor-nesting/` through the crate's public CBOR readers: the
//! request reader and the reply reader read items nested up to 128 levels
//! deep and refuse deeper input as not well-formed, as Go and Python do.

use evidence_request::envelope::{parse_reply, Binding, ReplyError};
use evidence_request::request::{parse_cbor, RequestError};
use serde_json::Value;

fn cases() -> Vec<Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/cbor-nesting/cases.json"
    );
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(doc["max_nesting_depth"], 128);
    doc["cases"].as_array().unwrap().clone()
}

#[test]
fn request_and_reply_readers_share_the_limit() {
    let all = cases();
    assert_eq!(all.len(), 9);
    for case in &all {
        let id = case["id"].as_str().unwrap();
        let octets = hex::decode(case["cbor_hex"].as_str().unwrap()).unwrap();
        let accept = case["accept"].as_bool().unwrap();
        let request = parse_cbor(&octets);
        let reply = parse_reply(&octets, Binding::Cbor);
        if case["tag"].as_bool().unwrap() {
            // A request holds no tag at any depth (vectors/cbor-request-model/).
            assert!(request.is_err(), "{id}");
            assert!(reply.is_err(), "{id}");
        } else if accept {
            assert!(request.is_ok(), "{id}: {request:?}");
            // Read, then refused for what it holds: a request is no reply.
            assert_eq!(reply.err(), Some(ReplyError::Neither), "{id}");
        } else {
            assert!(
                matches!(request, Err(RequestError::Malformed(_))),
                "{id}: {request:?}"
            );
            assert_ne!(reply.err(), Some(ReplyError::Neither), "{id}");
        }
    }
}
