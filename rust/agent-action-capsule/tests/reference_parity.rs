// SPDX-License-Identifier: BSD-3-Clause
//! Capsules outside the shared corpus where a Rust-specific path could
//! diverge. Expected values are the Python reference's (`verify()` in
//! `python/agent_action_capsule`); `go/verify` returns the same.

use agent_action_capsule::verify::{decode_capsule_json, verify};

struct Case {
    name: &'static str,
    capsule: &'static str,
    ok: bool,
    capsule_id: &'static str,
    findings: &'static [&'static str],
}

const CASES: &[Case] = &[
    Case {
        name: "number-token-object",
        capsule: r#"{"spec_version":"draft-mih-scitt-agent-action-capsule-04","format_version":"4","canonicalization_id":"jcs","action_id":"rust-parity","action_type":"fyi","operator":"example-org","developer":"example-agent@v1","timestamp":"2026-10-14T00:00:00Z","extension":{"$serde_json::private::Number":"1"},"capsule_id":"b44025f9171417a722a0cef88fd9a4b3c37bcedc6df592826942528b047325c6"}"#,
        ok: true,
        capsule_id: "b44025f9171417a722a0cef88fd9a4b3c37bcedc6df592826942528b047325c6",
        findings: &[],
    },
    Case {
        name: "effect-attestation-null-confirmed",
        capsule: r#"{"spec_version":"draft-mih-scitt-agent-action-capsule-04","format_version":"4","canonicalization_id":"jcs","action_id":"rust-parity","action_type":"fyi","operator":"example-org","developer":"example-agent@v1","timestamp":"2026-10-14T00:00:00Z","effect":{"type":"write","status":"confirmed","irreversibility_class":"two_way","response_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","effect_attestation":null},"capsule_id":"76a76c90481c5f8d5eaefb72f6d15b31192f5246b2aa107674d7e50ffd3be241"}"#,
        ok: false,
        capsule_id: "76a76c90481c5f8d5eaefb72f6d15b31192f5246b2aa107674d7e50ffd3be241",
        findings: &[
            "(1,error,field_not_string)",
            "(5,error,effect_attestation_missing)",
            "(8,info,unknown_registry_value)",
        ],
    },
    Case {
        name: "effect-attestation-null-planned",
        capsule: r#"{"spec_version":"draft-mih-scitt-agent-action-capsule-04","format_version":"4","canonicalization_id":"jcs","action_id":"rust-parity","action_type":"fyi","operator":"example-org","developer":"example-agent@v1","timestamp":"2026-10-14T00:00:00Z","effect":{"type":"write","status":"planned","effect_attestation":null},"capsule_id":"64b5c3b0e74c1e098b8a1968308b6a73eda8004eef1cb5f519d87d59d52bc261"}"#,
        ok: false,
        capsule_id: "64b5c3b0e74c1e098b8a1968308b6a73eda8004eef1cb5f519d87d59d52bc261",
        findings: &[
            "(1,error,field_not_string)",
            "(8,info,unknown_registry_value)",
        ],
    },
];

#[test]
fn matches_the_python_reference() {
    for case in CASES {
        let capsule = decode_capsule_json(case.capsule.as_bytes()).expect(case.name);
        let result = verify(&capsule, None);
        let findings: Vec<String> = result
            .findings
            .iter()
            .map(|f| {
                let check = f.check.map_or("null".to_string(), |c| c.to_string());
                format!("({check},{},{})", f.severity, f.code)
            })
            .collect();
        assert_eq!(result.ok, case.ok, "{}", case.name);
        assert_eq!(
            result.capsule_id.as_deref(),
            Some(case.capsule_id),
            "{}",
            case.name
        );
        assert_eq!(findings, case.findings, "{}", case.name);
    }
}
