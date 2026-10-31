//! `vectors/json-nesting/` through the crate's public JSON readers: the
//! request reader and the reply reader read text nested up to 128 levels
//! deep and refuse deeper text as not well-formed JSON, as Go, Python and
//! TypeScript do. (serde_json's own decoder stopped at 127.)

use evidence_request::envelope::{parse_reply, Binding, ReplyError};
use evidence_request::request::{parse_json, RequestError};
use serde_json::Value;

const MALFORMED_REQUEST: RequestError = RequestError::Malformed("not well-formed JSON");
const MALFORMED_REPLY: ReplyError = ReplyError::Encoding("not JSON in the profile's data model");

fn cases() -> Vec<Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/json-nesting/cases.json"
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
        let text = case["json"].as_str().unwrap().as_bytes();
        let request = parse_json(text);
        let reply = parse_reply(text, Binding::Json);
        if case["accept"].as_bool().unwrap() {
            // Read, then refused for what it holds (none of the cases is a
            // request or a reply), never as unreadable JSON.
            assert_ne!(request.err(), Some(MALFORMED_REQUEST), "{id}");
            assert_ne!(reply.err(), Some(MALFORMED_REPLY), "{id}");
        } else {
            assert_eq!(request.err(), Some(MALFORMED_REQUEST), "{id}");
            assert_eq!(reply.err(), Some(MALFORMED_REPLY), "{id}");
        }
    }
}

#[test]
fn a_request_with_a_member_at_the_limit_is_read() {
    // A valid request with an extra member nested 127 deep nests 128 levels.
    let deep = format!("{}{}", "[".repeat(127), "]".repeat(127));
    let text = format!(
        r#"{{"coverage":{{"expected_pin":"{pin}"}},"nonce":"n-1","subject":{{"record":"{rec}"}},"x":{deep}}}"#,
        pin = "ab".repeat(32),
        rec = "cd".repeat(32),
    );
    assert!(parse_json(text.as_bytes()).is_ok());
    let deeper = text.replacen(&deep, &format!("[{deep}]"), 1);
    assert_eq!(parse_json(deeper.as_bytes()).err(), Some(MALFORMED_REQUEST));
}
