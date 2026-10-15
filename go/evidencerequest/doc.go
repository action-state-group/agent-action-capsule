// SPDX-License-Identifier: Apache-2.0

// Package evidencerequest implements the protocol logic of the evidence
// request interaction, draft-mih-agent-evidence-request-00 (ER), and the
// request, reply and verification-material forms of the Minimum Evidence
// Interoperability Profile (evidence-interop/0) that carries it.
//
// It holds what needs no evidence store: reading and encoding the request
// map in JSON (RFC 8785) and deterministic CBOR (RFC 8949 §4.2.1), the
// request digest over the octets as received, exact-match resolution over a
// View of a responder's holdings, signed refusals and envelopes, reply
// parsing, the three-state outcome discipline, retention commitments,
// caller invariance, and the Merkle Mountain Range checks of the
// Checkpointed Local Log material. Building artifacts, holding evidence and
// carrying messages over a transport belong to the caller.
//
// The conformance vectors in vectors/evidence-request of this repository are
// the package's tests. ERV An names ambiguity n in their README.
package evidencerequest
