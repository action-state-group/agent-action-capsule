//! Disclosure Envelope status vocabulary (companion registry, §12) -- the
//! four status strings `bundle.rs` reports per disclosed/withheld member.
//! Byte-for-byte port of the Go/Python/TS siblings' `disclosure` status
//! constants; this crate does not need the producer-side envelope builder,
//! only these four labels.

pub const MATCH: &str = "disclosure_match";
pub const MISMATCH: &str = "disclosure_mismatch";
pub const INELIGIBLE: &str = "disclosure_ineligible_field";
pub const NO_COMMITTED_DIGEST: &str = "disclosure_no_committed_digest";

/// The companion Disclosure Envelope registry table: member name -> dotted
/// path below the Capsule root (mirrors Go's `registries.DisclosureEligibleFields`).
pub fn disclosure_eligible_field(member: &str) -> Option<&'static str> {
    match member {
        "agent_input" => Some("model_attestation.compute_attestation.agent_input_digest"),
        "agent_output" => Some("model_attestation.compute_attestation.agent_output_digest"),
        _ => None,
    }
}

/// All eligible member names, in the fixed emission order the siblings use
/// (Go ranges a Go map, which is unordered, but its two entries have no
/// mutual ordering requirement in the shared vectors; this crate fixes an
/// order for determinism).
pub const ELIGIBLE_MEMBERS: [&str; 2] = ["agent_input", "agent_output"];
