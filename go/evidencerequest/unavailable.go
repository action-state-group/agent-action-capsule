// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/internal/ed25519strict"
)

// The reason classes of an unavailable-window statement (ER -02 §4.7). The
// list is closed: it changes only with a revision of the draft and is not a
// registry.
const (
	UnavailableFlood         = "flood"
	UnavailableMaintenance   = "maintenance"
	UnavailableOutage        = "outage"
	UnavailableOtherDeclared = "other_declared"
)

// UnavailableReasonClasses is the closed list, in the draft's order.
var UnavailableReasonClasses = []string{UnavailableFlood, UnavailableMaintenance, UnavailableOutage, UnavailableOtherDeclared}

// UnavailableShownAs is how a reader shows an absence a statement covers
// (ER -02 §4.7 item 1).
const UnavailableShownAs = "no answer; holder states unavailability"

// UnavailableSignedMembers are the statement members the signature covers in
// the vectors' profile: those of these present, in RFC 8785 form. ER -02
// §4.7 item 3 leaves the format to the deployment (unavailable-window.json
// signature_profile).
var UnavailableSignedMembers = []string{"end", "reason_class", "start"}

// Why a reader ignores an unavailable-window statement. A reader treats an
// ignored statement as if it did not exist.
const (
	StatementMalformed            = "malformed"
	StatementNotSignedByResponder = "not_signed_by_responder"
	StatementNotRegistered        = "not_registered"
)

// RegistrationReceipt is one receipt on a checkpoint whose coverage includes
// a statement: the time it attests, and whether it comes from a transparency
// service the reader accepts as independent of the responder. Which services
// a reader accepts is reader policy; one the responder operates or controls
// is never one (ER -02 §4.7).
type RegistrationReceipt struct {
	Time     string
	Accepted bool
}

// StatementReading is whether a reader recognizes an unavailable-window
// statement. When it does, Why is empty and RegistrationTime is the earliest
// time an accepted receipt attests, as that receipt spells it. When not, Why
// is StatementMalformed, StatementNotSignedByResponder or
// StatementNotRegistered.
type StatementReading struct {
	Recognized       bool
	Why              string
	RegistrationTime string
}

// RecognizeUnavailableWindow reads one unavailable-window statement (ER -02
// §4.7), a decoded JSON object, as a reader holding receipts for it, for the
// responder whose key is responderKey (the lowercase hex of the raw Ed25519
// key a response would be authenticated by).
//
// It is malformed unless reason_class is exactly one of
// UnavailableReasonClasses and start and end are RFC 3339 UTC times with end
// not earlier than start. It is signed by the responder when key_id is
// responderKey and sig is a strict Ed25519 signature under it over
// UnavailableSignedMembers. It is registered when at least one accepted
// receipt attests a time. Other members are ignored and are never the
// reason.
func RecognizeUnavailableWindow(statement map[string]any, receipts []RegistrationReceipt, responderKey string) StatementReading {
	reasonClass, _ := statement["reason_class"].(string)
	start, startOK := statementTime(statement, "start")
	end, endOK := statementTime(statement, "end")
	if !slices.Contains(UnavailableReasonClasses, reasonClass) || !startOK || !endOK || end.Before(start) {
		return StatementReading{Why: StatementMalformed}
	}
	if !signedByResponder(statement, responderKey) {
		return StatementReading{Why: StatementNotSignedByResponder}
	}
	var earliest time.Time
	registration := ""
	for _, r := range receipts {
		attested, ok := ParseRequestTime(r.Time)
		if r.Accepted && ok && (registration == "" || attested.Before(earliest)) {
			earliest, registration = attested, r.Time
		}
	}
	if registration == "" {
		return StatementReading{Why: StatementNotRegistered}
	}
	return StatementReading{Recognized: true, RegistrationTime: registration}
}

func statementTime(statement map[string]any, member string) (time.Time, bool) {
	text, ok := statement[member].(string)
	if !ok {
		return time.Time{}, false
	}
	return ParseRequestTime(text)
}

func signedByResponder(statement map[string]any, responderKey string) bool {
	keyID, _ := statement["key_id"].(string)
	sigHex, _ := statement["sig"].(string)
	if keyID != responderKey {
		return false
	}
	public, err := hex.DecodeString(keyID)
	if err != nil || hex.EncodeToString(public) != keyID {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || hex.EncodeToString(sig) != sigHex {
		return false
	}
	signed := map[string]any{}
	for _, member := range UnavailableSignedMembers {
		if v, present := statement[member]; present {
			signed[member] = v
		}
	}
	body, err := EncodeJCS(signed)
	return err == nil && ed25519strict.Verify(public, body, sig)
}

// WindowStatement is one statement a reader holds, under an ID of the
// reader's choosing, with the receipts it holds for it.
type WindowStatement struct {
	ID        string
	Statement map[string]any
	Receipts  []RegistrationReceipt
}

// StatementLabel is what a reader shows for one statement covering an
// absence (ER -02 §4.7 items 1 to 3): its reason class, its stated period
// from start to end, its registration time, and whether that time is later
// than the close of the absence's waiting window ("stated afterwards"). It
// is the responder's own statement, never proof that it was attacked or
// flooded.
type StatementLabel struct {
	ReasonClass      string
	RegistrationTime string
	StatedAfterwards bool
	StatedPeriod     [2]string
}

// AbsenceDisplay is how a reader shows a recorded state beside the
// statements it holds. CoveredBy lists the IDs of the covering statements in
// the order given, and Labels maps each to its label.
type AbsenceDisplay struct {
	State     string
	ShownAs   string
	CoveredBy []string
	Labels    map[string]StatementLabel
}

// DisplayAbsence shows the request recorded as state (an Observation.State
// value) beside statements, whose IDs are distinct (ER -02 §4.7).
//
// Only StateRecordedAbsence can be covered: any other state, a refusal or a
// pending request among them, is shown as itself and no statement covers
// it. For an absence, sentAt and closedAt are its waiting window, RFC 3339
// UTC times, and an error otherwise. A statement covers it when
// RecognizeUnavailableWindow recognizes it for responderKey and its period,
// both ends included, shares an instant with the window, both ends included.
// A covered absence is shown as UnavailableShownAs with a label per covering
// statement; one with no covering statement as StateRecordedAbsence. The
// absence record and its retention classification (ClassifyAbsence) are
// unchanged.
func DisplayAbsence(state, sentAt, closedAt string, statements []WindowStatement, responderKey string) (AbsenceDisplay, error) {
	display := AbsenceDisplay{State: state, ShownAs: state, Labels: map[string]StatementLabel{}}
	if state != StateRecordedAbsence {
		return display, nil
	}
	opened, openedOK := ParseRequestTime(sentAt)
	closed, closedOK := ParseRequestTime(closedAt)
	if !openedOK || !closedOK {
		return AbsenceDisplay{}, fmt.Errorf("%w: a recorded absence needs sent_at and closed_at as RFC 3339 UTC times", ErrInvalid)
	}
	for _, s := range statements {
		reading := RecognizeUnavailableWindow(s.Statement, s.Receipts, responderKey)
		if !reading.Recognized {
			continue
		}
		// Recognized, so these are well formed.
		start, _ := statementTime(s.Statement, "start")
		end, _ := statementTime(s.Statement, "end")
		if start.After(closed) || end.Before(opened) {
			continue
		}
		registered, _ := ParseRequestTime(reading.RegistrationTime)
		display.CoveredBy = append(display.CoveredBy, s.ID)
		display.Labels[s.ID] = StatementLabel{
			ReasonClass:      s.Statement["reason_class"].(string),
			RegistrationTime: reading.RegistrationTime,
			StatedAfterwards: registered.After(closed),
			StatedPeriod:     [2]string{s.Statement["start"].(string), s.Statement["end"].(string)},
		}
	}
	if len(display.CoveredBy) > 0 {
		display.ShownAs = UnavailableShownAs
	}
	return display, nil
}
