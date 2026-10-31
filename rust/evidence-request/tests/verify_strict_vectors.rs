//! Every signature check in this crate is dalek's `verify_strict`. This holds
//! it to checkpointed-local-log's shared strict Ed25519 cases
//! (`vectors/cross-language/cll-ed25519-vectors.json`, a verbatim copy):
//! with no pre-check, `verify_strict` accepts exactly the valid ones, the
//! non-canonical and small-order A and R cases included.

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

#[test]
fn verify_strict_matches_the_cll_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/cross-language/cll-ed25519-vectors.json"
    );
    let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let cases = vectors["ed25519_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 54);
    let bytes = |case: &Value, name: &str| hex::decode(case[name].as_str().unwrap()).unwrap();
    for case in cases {
        let key: [u8; 32] = bytes(case, "public_key_hex").try_into().unwrap();
        let signature: [u8; 64] = bytes(case, "signature_hex").try_into().unwrap();
        let verifies = VerifyingKey::from_bytes(&key).is_ok_and(|key| {
            key.verify_strict(
                &bytes(case, "message_hex"),
                &Signature::from_bytes(&signature),
            )
            .is_ok()
        });
        assert_eq!(
            verifies,
            case["valid"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}
