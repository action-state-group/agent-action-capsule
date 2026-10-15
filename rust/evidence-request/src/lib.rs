//! The evidence request protocol of draft-mih-agent-evidence-request-00.
//!
//! A requester asks a responder for evidence about a **subject**, under a
//! **coverage** constraint. The interaction ends in exactly one of three
//! outcomes: an artifact, a signed refusal, or the requester's own record
//! that nothing arrived (a recorded absence).
//!
//! This crate implements what both sides need to agree on:
//!
//! - [`request`]: parse a request from its JSON or CBOR binding (the CBOR
//!   binding in core deterministic encoding only) and check it
//!   against -00 (the six subject forms, exactly one coverage member, the
//!   optional fields), giving the exact refusal reason when it is not
//!   well formed.
//! - [`digest`]: the request digest, SHA-256 over the bytes as received.
//! - [`resolve`]: exact-match resolution of a well-formed request against a
//!   responder's holdings ([`resolve::Responder`]): the anchor to serve
//!   under, or the most specific refusal reason. Building the artifact
//!   itself is the responder's business.
//! - [`refusal`]: sign a refusal; authenticate one as a responder's answer
//!   to a request ([`refusal::verify_for`]); or check its shape and
//!   self-consistency ([`refusal::check`], not authentication).
//! - [`outcome`]: map what the requester observed to one recorded state,
//!   under the three-state discipline (a refusal is never an absence).
//! - [`invariance`]: caller invariance of artifacts.
//! - [`retention`]: retention commitments and the breach table.
//!
//! The conformance vectors of the draft (the repository's `vectors/evidence-request/`) are the
//! test suite. Where -00 leaves a wire shape open, this crate follows the
//! reading the vectors document (their ambiguity notes A1-A14); the items a
//! future revision may change are marked in each module.
//!
//! - [`envelope`]: the artifact response in the interop profile's form
//!   (`evidence-interop/0` §6.2): build and sign it ([`envelope::sign`]),
//!   encode it in either binding, read a reply as carried
//!   ([`envelope::parse_reply`]), and accept it as a responder's answer to a
//!   request ([`envelope::Envelope::verify_for`]).
//! - `cll_material` (feature `cll`): check the Checkpointed Local Log
//!   verification material an envelope carries (profile §6.2.1,
//!   `anchor_inclusion`).
//!
//! To accept a refusal as the answer to a request, use
//! [`refusal::verify_for`]; [`refusal::check`] is not authentication. To
//! accept an artifact, use [`envelope::Envelope::verify_for`], and then
//! `cll_material::check_anchor_inclusion` for its material.
//!
//! Building an artifact from a store or a log is the responder's business:
//! a Checkpointed Local Log responder is the `evidencebook` crate.
//!
//! Features: `cll` enables `cll_material` and depends on
//! checkpointed-local-log; `receipt` enables `receipt`. With no features the
//! crate is the protocol core above, with no checkpointed-local-log
//! dependency.
//!
//! Out of scope: transport, storage, and any store-and-forward or delivery
//! guarantee.

#[cfg(feature = "cll")]
pub mod cll_material;
mod det_cbor;
pub mod digest;
pub mod envelope;
pub mod invariance;
pub mod jcs;
pub mod outcome;
#[cfg(feature = "receipt")]
pub mod receipt;
pub mod refusal;
pub mod registry;
pub mod request;
pub mod resolve;
pub mod retention;
pub mod time;
mod value;
