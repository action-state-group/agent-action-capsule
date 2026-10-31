// SPDX-License-Identifier: Apache-2.0

package evidencerequest_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	er "github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var uwKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))

func uwResponder() string { return hex.EncodeToString(uwKey.Public().(ed25519.PublicKey)) }

// uwStatement signs a statement with members, over those of the signed
// members present; a nil value leaves a member out.
func uwStatement(t *testing.T, members map[string]any) map[string]any {
	t.Helper()
	st := map[string]any{"start": "2026-10-29T10:00:00Z", "end": "2026-10-29T10:40:00Z", "reason_class": "flood"}
	for k, v := range members {
		if v == nil {
			delete(st, k)
		} else {
			st[k] = v
		}
	}
	signed := map[string]any{}
	for _, k := range er.UnavailableSignedMembers {
		if v, ok := st[k]; ok {
			signed[k] = v
		}
	}
	body, err := er.EncodeJCS(signed)
	require.NoError(t, err)
	st["key_id"] = uwResponder()
	st["sig"] = hex.EncodeToString(ed25519.Sign(uwKey, body))
	return st
}

func accepted(times ...string) []er.RegistrationReceipt {
	out := make([]er.RegistrationReceipt, 0, len(times))
	for _, at := range times {
		out = append(out, er.RegistrationReceipt{Time: at, Accepted: true})
	}
	return out
}

func TestUnavailableWindowEndingBeforeItStartsIsMalformed(t *testing.T) {
	st := uwStatement(t, map[string]any{"start": "2026-10-29T10:40:00Z", "end": "2026-10-29T10:39:59Z"})
	got := er.RecognizeUnavailableWindow(st, accepted("2026-10-29T10:06:00Z"), uwResponder())
	assert.Equal(t, er.StatementReading{Why: er.StatementMalformed}, got)
	// A fraction is the deadline representation too, and orders as an instant.
	st = uwStatement(t, map[string]any{"start": "2026-10-29T10:00:00.5Z", "end": "2026-10-29T10:00:00.25Z"})
	assert.Equal(t, er.StatementMalformed, er.RecognizeUnavailableWindow(st, accepted("2026-10-29T10:06:00Z"), uwResponder()).Why)
}

func TestUnavailableWindowReasonOutsideTheClosedListIsMalformed(t *testing.T) {
	for _, reason := range []any{"ddos", "Outage", "", uint64(7), []any{"flood"}} {
		st := uwStatement(t, map[string]any{"reason_class": reason})
		assert.Equal(t, er.StatementMalformed, er.RecognizeUnavailableWindow(st, accepted("2026-10-29T10:06:00Z"), uwResponder()).Why, reason)
	}
	assert.Equal(t, er.StatementMalformed, er.RecognizeUnavailableWindow(nil, nil, uwResponder()).Why)
}

func TestOnlyAnAcceptedReceiptThatAttestsATimeRegistersAStatement(t *testing.T) {
	st := uwStatement(t, nil)
	for _, rs := range [][]er.RegistrationReceipt{
		nil,
		{{Time: "2026-10-29T10:06:00Z", Accepted: false}},
		{{Time: "not a time", Accepted: true}},
	} {
		assert.Equal(t, er.StatementNotRegistered, er.RecognizeUnavailableWindow(st, rs, uwResponder()).Why)
	}
	rs := append([]er.RegistrationReceipt{{Time: "2026-10-29T09:00:00Z", Accepted: false}},
		accepted("2026-10-29T10:30:00Z", "2026-10-29T10:06:00Z")...)
	assert.Equal(t, er.StatementReading{Recognized: true, RegistrationTime: "2026-10-29T10:06:00Z"},
		er.RecognizeUnavailableWindow(st, rs, uwResponder()))
}

func TestUnavailableWindowUnderASmallOrderKeyIsNotTheResponders(t *testing.T) {
	identity := "01" + strings.Repeat("00", 31)
	st := map[string]any{"start": "2026-10-29T10:00:00Z", "end": "2026-10-29T10:40:00Z", "reason_class": "flood",
		"key_id": identity, "sig": identity + strings.Repeat("00", 32)}
	assert.Equal(t, er.StatementNotSignedByResponder, er.RecognizeUnavailableWindow(st, accepted("2026-10-29T10:06:00Z"), identity).Why)
	// Upper-case hex is not the key's spelling.
	st = uwStatement(t, nil)
	st["sig"] = strings.ToUpper(st["sig"].(string))
	assert.Equal(t, er.StatementNotSignedByResponder, er.RecognizeUnavailableWindow(st, accepted("2026-10-29T10:06:00Z"), uwResponder()).Why)
}

func TestAStatementRegisteredAfterTheWindowClosesIsStatedAfterwards(t *testing.T) {
	statements := []er.WindowStatement{
		{ID: "late", Statement: uwStatement(t, nil), Receipts: accepted("2026-10-29T10:20:01Z")},
		{ID: "at-close", Statement: uwStatement(t, map[string]any{"reason_class": "outage"}), Receipts: accepted("2026-10-29T10:20:00Z")},
	}
	shown, err := er.DisplayAbsence(er.StateRecordedAbsence, "2026-10-29T10:10:00Z", "2026-10-29T10:20:00Z", statements, uwResponder())
	require.NoError(t, err)
	assert.Equal(t, er.UnavailableShownAs, shown.ShownAs)
	assert.Equal(t, []string{"late", "at-close"}, shown.CoveredBy)
	assert.True(t, shown.Labels["late"].StatedAfterwards)
	assert.False(t, shown.Labels["at-close"].StatedAfterwards)
	assert.Equal(t, [2]string{"2026-10-29T10:00:00Z", "2026-10-29T10:40:00Z"}, shown.Labels["late"].StatedPeriod)
}

func TestOnlyARecordedAbsenceIsCovered(t *testing.T) {
	statements := []er.WindowStatement{{ID: "s1", Statement: uwStatement(t, nil), Receipts: accepted("2026-10-29T10:06:00Z")}}
	for _, state := range []string{er.StatePending, er.StateRefusal, er.StateRefusalNonconformant, er.StateArtifactVerified} {
		shown, err := er.DisplayAbsence(state, "2026-10-29T10:10:00Z", "2026-10-29T10:20:00Z", statements, uwResponder())
		require.NoError(t, err)
		assert.Equal(t, state, shown.ShownAs)
		assert.Empty(t, shown.CoveredBy)
		assert.Empty(t, shown.Labels)
	}
	_, err := er.DisplayAbsence(er.StateRecordedAbsence, "2026-10-29T10:10:00Z", "", statements, uwResponder())
	assert.ErrorIs(t, err, er.ErrInvalid)
}
