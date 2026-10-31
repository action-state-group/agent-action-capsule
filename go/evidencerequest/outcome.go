// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"bytes"
	"fmt"
	"slices"
	"time"
)

// Received is what a requester observed for one request.
type Received int

const (
	// ReceivedNothing: no reply arrived.
	ReceivedNothing Received = iota
	// ReceivedArtifact: an artifact response arrived.
	ReceivedArtifact
	// ReceivedRefusal: a refusal object arrived.
	ReceivedRefusal
	// ReceivedTransportError: the transport failed.
	ReceivedTransportError
	// ReceivedSubprotocolNotOffered: the peer does not offer the
	// subprotocol (ER §10).
	ReceivedSubprotocolNotOffered
)

// Observation is what a requester holds when it records a request's state:
// what arrived, what verifying it showed, and whether its waiting window is
// still open.
type Observation struct {
	Received Received
	// ArtifactVerified: the artifact verified against its anchor.
	ArtifactVerified bool
	// Refusal is CheckRefusal's answer for a refusal as received.
	Refusal RefusalCheck
	// WindowOpen: the requester's waiting window has not closed (ER §4.3).
	WindowOpen bool
}

// The states a request is recorded in (ER §4.5), named as the conformance
// vectors name them.
const (
	StateArtifactVerified           = "artifact_verified"
	StateArtifactVerificationFailed = "artifact_verification_failed"
	// StateRefusal is a conforming signed refusal.
	StateRefusal = "refusal"
	// StateRefusalNonconformant is a correctly signed refusal that does not
	// conform: its reason is not one registered token (ERV A13), or a member
	// ER §4.2 requires is missing or malformed. It is still the responder's
	// signed answer, never an absence.
	StateRefusalNonconformant = "refusal_nonconformant"
	// StateRefusalSignatureInvalid is a refusal-shaped object whose
	// signature does not verify: not the responder's act, and not an
	// absence either.
	StateRefusalSignatureInvalid = "refusal_signature_invalid"
	StatePending                 = "pending"
	StateRecordedAbsence         = "recorded_absence"
)

// State maps an observation to the one state it is recorded as (ER §4,
// §4.5). A signed refusal is never an absence, whatever the window or its
// reason. Silence, a transport error, or a peer that does not offer the
// subprotocol is never a refusal: it is pending while the window is open
// (ER §4.3, ERV A8) and a recorded absence once it closes. A retention
// commitment does not turn silence into a refusal (ER §4.4).
func (o Observation) State() string {
	switch o.Received {
	case ReceivedArtifact:
		if o.ArtifactVerified {
			return StateArtifactVerified
		}
		return StateArtifactVerificationFailed
	case ReceivedRefusal:
		switch {
		case !o.Refusal.SignatureValid:
			return StateRefusalSignatureInvalid
		case o.Refusal.Conformant:
			return StateRefusal
		}
		return StateRefusalNonconformant
	}
	if o.WindowOpen {
		return StatePending
	}
	return StateRecordedAbsence
}

// CommitmentState is the state of a retention commitment for the subject
// when an answer, or none, arrived (ER §9).
type CommitmentState int

const (
	// CommitmentNone: no commitment names the subject.
	CommitmentNone CommitmentState = iota
	// CommitmentInForce: inside until.
	CommitmentInForce
	// CommitmentLapsed: after until.
	CommitmentLapsed
)

// How a refusal stands against a retention commitment (ER §9).
const (
	RetentionNoBreach = "no_breach"
	RetentionBreach   = "breach"
	// RetentionWrongToken: after until, a refusal that reads as "never
	// held" (ERV A10).
	RetentionWrongToken = "wrong_token"
	// RetentionCorrect: after until, retention_expired.
	RetentionCorrect = "correct"
	// RetentionNoCommitment: there is no commitment to breach.
	RetentionNoCommitment = "no_commitment"
)

// ClassifyRefusal classifies a refusal with reason against a commitment.
// Inside until, only the reasons about the request or the responder's
// capability are consistent with the promise, and capacity_exceeded is never
// a breach (-02: flooding must not manufacture one); any other refusal
// breaches it (ERV A9). After until, retention_expired is correct and no_such_subject is
// the wrong token (ERV A10).
func ClassifyRefusal(commitment CommitmentState, reason string) string {
	consistent := slices.Contains([]string{ReasonNotAuthorized, ReasonCoverageUnsatisfiable, ReasonDerivationUnsupported,
		ReasonRequestMalformed, ReasonRequestUnauthenticated, ReasonCapacityExceeded}, reason)
	switch commitment {
	case CommitmentInForce:
		if consistent {
			return RetentionNoBreach
		}
		return RetentionBreach
	case CommitmentLapsed:
		switch reason {
		case ReasonRetentionExpired:
			return RetentionCorrect
		case ReasonNoSuchSubject:
			return RetentionWrongToken
		}
		return RetentionNoBreach
	}
	return RetentionNoCommitment
}

// How a recorded absence stands against a retention commitment (ER §9).
// Either way it stays a recorded absence, never a refusal.
const (
	// AbsenceAttributable: a commitment was in force, so the absence is
	// attributable to the party that promised.
	AbsenceAttributable = "attributable_absence"
	// AbsenceAttemptOnly: the absence records only the attempt.
	AbsenceAttemptOnly = "attempt_only"
)

// ClassifyAbsence classifies a recorded absence against a commitment.
func ClassifyAbsence(commitment CommitmentState) string {
	if commitment == CommitmentInForce {
		return AbsenceAttributable
	}
	return AbsenceAttemptOnly
}

// RetentionCommitment is the content of a retention commitment (ER §9): the
// subject and the evidence stream it belongs to, and when it lapses. The
// signature is in the deployment's evidence mechanism's format and is not
// read here.
type RetentionCommitment struct {
	EvidenceStream string
	Subject        Subject
	Until          time.Time
}

// ParseRetentionCommitment reads a commitment object received as m. Its
// subject must be named by a digest or a position under a checkpoint: a
// record, an exchange or a range, never a correlation, the full history or
// the checkpoints (ERV A11). until is an RFC 3339 UTC time (ERV A5).
func ParseRetentionCommitment(m Message) (RetentionCommitment, error) {
	root, err := Decode(m)
	if err != nil {
		return RetentionCommitment{}, fmt.Errorf("%w: commitment: %v", ErrInvalid, err)
	}
	fields, ok := root.(map[string]any)
	if !ok {
		return RetentionCommitment{}, fmt.Errorf("%w: commitment is not a map", ErrInvalid)
	}
	var c RetentionCommitment
	if c.EvidenceStream, ok = fields["evidence_stream"].(string); !ok || c.EvidenceStream == "" {
		return RetentionCommitment{}, fmt.Errorf("%w: commitment evidence_stream is not a non-empty text string", ErrInvalid)
	}
	if c.Subject, ok = ParseSubject(fields["subject"]); !ok || !Committable(c.Subject.Kind) {
		return RetentionCommitment{}, fmt.Errorf("%w: commitment subject is not a record, an exchange or a range", ErrInvalid)
	}
	until, _ := fields["until"].(string)
	if c.Until, ok = ParseRequestTime(until); !ok {
		return RetentionCommitment{}, fmt.Errorf("%w: commitment until is not an RFC 3339 UTC time", ErrInvalid)
	}
	return c, nil
}

// Committable reports whether a retention commitment may name a subject of
// this form (ER §9, ERV A11).
func Committable(kind SubjectKind) bool {
	return kind == SubjectRecord || kind == SubjectExchange || kind == SubjectRange
}

// Caller invariance (ER §5): artifacts compared under one anchor.
const (
	InvarianceHolds         = "holds"
	InvarianceViolated      = "violated"
	InvarianceNotComparable = "not_comparable"
)

// Answer is one observed artifact of a subject: the anchor it was resolved
// under and its octets.
type Answer struct {
	ResolvedAnchor string
	Artifact       []byte
}

// CompareAnswers checks caller invariance over answers for one subject:
// under the same anchor the artifacts are byte-identical, whoever asked,
// over whatever transport, with whatever nonce or route. Verification
// material beside the artifact may differ and is not compared. Answers
// under different anchors are not comparable (ERV A12: artifacts are
// compared as bytes).
func CompareAnswers(answers []Answer) string {
	if len(answers) == 0 {
		return InvarianceHolds
	}
	first := answers[0]
	for _, a := range answers[1:] {
		if a.ResolvedAnchor != first.ResolvedAnchor {
			return InvarianceNotComparable
		}
	}
	for _, a := range answers[1:] {
		if !bytes.Equal(a.Artifact, first.Artifact) {
			return InvarianceViolated
		}
	}
	return InvarianceHolds
}
