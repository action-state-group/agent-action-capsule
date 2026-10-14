//! Reference verification for the Agent Action Capsule
//! (`draft-mih-scitt-agent-action-capsule`): the Rust sibling of the Python
//! reference and the Go and TypeScript implementations in
//! [action-state-group/agent-action-capsule], checked against the same
//! conformance vectors.
//!
//! | Module | Draft | Go package |
//! |---|---|---|
//! | [`canonical`] | JCS, JSON-DIGEST and `capsule_id` (§2, §5.1) | `go/canonical` |
//! | [`registries`] | profile registries (§12) | `go/registries` |
//! | [`verify`] | Class 1 verification, checks 1-9 and the store checks (§6) | `go/verify` |
//! | [`envelope`] | Producer Envelope | `go/envelope` |
//! | `bundle` (feature `bundle`) | Evidence Bundle v2 | `go/bundle` |
//!
//! Numbers keep their source text (`serde_json`'s `arbitrary_precision`), so
//! decode capsules with [`verify::decode_capsule_json`] or `serde_json` and
//! pass the [`serde_json::Value`] in.
//!
//! [action-state-group/agent-action-capsule]: https://github.com/action-state-group/agent-action-capsule

pub mod canonical;
pub mod envelope;
mod references;
pub mod registries;
pub mod verify;

#[cfg(feature = "bundle")]
pub mod bundle;
#[cfg(feature = "bundle")]
mod disclosure;
