// SPDX-License-Identifier: Apache-2.0

package evidencerequest_test

import (
	"encoding/json"
	"testing"

	er "github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type uwReceipt struct {
	Time     string `json:"time"`
	Accepted bool   `json:"accepted"`
}

// receipts maps the corpus's receipts to the reader's: accepted stands for
// the reader's policy on which transparency services are independent of the
// responder.
func receipts(rs []uwReceipt) []er.RegistrationReceipt {
	out := make([]er.RegistrationReceipt, 0, len(rs))
	for _, r := range rs {
		out = append(out, er.RegistrationReceipt{Time: r.Time, Accepted: r.Accepted})
	}
	return out
}

// TestUnavailableWindowVectors runs every case of unavailable-window.json
// (ER -02 §4.7) against every member of its expectation: which statements a
// reader recognizes and why not, and how it shows an absence beside them.
func TestUnavailableWindowVectors(t *testing.T) {
	var corpus struct {
		ReasonClasses    []string `json:"reason_classes"`
		ShownAs          string   `json:"shown_as"`
		SignatureProfile struct {
			SignedMembers []string `json:"signed_members"`
		} `json:"signature_profile"`
	}
	require.NoError(t, json.Unmarshal(readVector(t, "unavailable-window.json"), &corpus))
	assert.Equal(t, er.UnavailableReasonClasses, corpus.ReasonClasses)
	assert.Equal(t, er.UnavailableShownAs, corpus.ShownAs)
	assert.Equal(t, er.UnavailableSignedMembers, corpus.SignatureProfile.SignedMembers)

	type uwLabel struct {
		ReasonClass      string    `json:"reason_class"`
		RegistrationTime string    `json:"registration_time"`
		StatedAfterwards bool      `json:"stated_afterwards"`
		StatedPeriod     [2]string `json:"stated_period"`
	}
	type uwVector struct {
		ID           string         `json:"id"`
		Kind         string         `json:"kind"`
		ResponderKey string         `json:"responder_key"`
		Statement    map[string]any `json:"statement"`
		Receipts     []uwReceipt    `json:"receipts"`
		Absence      struct {
			SentAt              string  `json:"sent_at"`
			ClosedAt            *string `json:"closed_at"`
			Received            string  `json:"received"`
			RetentionCommitment string  `json:"retention_commitment"`
		} `json:"absence"`
		Statements []struct {
			ID        string         `json:"id"`
			Statement map[string]any `json:"statement"`
			Receipts  []uwReceipt    `json:"receipts"`
		} `json:"statements"`
		Expect struct {
			Recognized       *bool              `json:"recognized"`
			Why              string             `json:"why"`
			RegistrationTime string             `json:"registration_time"`
			ShownReason      string             `json:"shown_reason"`
			State            string             `json:"state"`
			CoveredBy        []string           `json:"covered_by"`
			ShownAs          string             `json:"shown_as"`
			Labels           map[string]uwLabel `json:"labels"`
			MustNotShowAs    []string           `json:"must_not_show_as"`
			Retention        string             `json:"retention_classification"`
		} `json:"expect"`
	}
	kinds := map[string]int{}
	for _, c := range loadCases[uwVector](t, "unavailable-window.json") {
		kinds[c.Kind]++
		t.Run(c.ID, func(t *testing.T) {
			if c.Kind == "statement" {
				require.NotNil(t, c.Expect.Recognized)
				reading := er.RecognizeUnavailableWindow(c.Statement, receipts(c.Receipts), c.ResponderKey)
				assert.Equal(t, *c.Expect.Recognized, reading.Recognized)
				assert.Equal(t, c.Expect.Why, reading.Why)
				assert.Equal(t, c.Expect.RegistrationTime, reading.RegistrationTime)
				if reading.Recognized {
					// The token alone is the reason, never another member.
					assert.Equal(t, c.Expect.ShownReason, c.Statement["reason_class"])
				}
				return
			}
			require.Equal(t, "display", c.Kind)
			a := c.Absence
			observation := er.Observation{WindowOpen: a.ClosedAt == nil}
			switch a.Received {
			case "nothing":
				observation.Received = er.ReceivedNothing
			case "refusal":
				observation.Received = er.ReceivedRefusal
				observation.Refusal = er.RefusalCheck{SignatureValid: true, ReasonRegistered: true, Conformant: true}
			default:
				t.Fatalf("received %q", a.Received)
			}
			closedAt := ""
			if a.ClosedAt != nil {
				closedAt = *a.ClosedAt
			}
			statements := make([]er.WindowStatement, 0, len(c.Statements))
			for _, s := range c.Statements {
				statements = append(statements, er.WindowStatement{ID: s.ID, Statement: s.Statement, Receipts: receipts(s.Receipts)})
			}
			shown, err := er.DisplayAbsence(observation.State(), a.SentAt, closedAt, statements, c.ResponderKey)
			require.NoError(t, err)
			assert.Equal(t, c.Expect.State, shown.State)
			assert.Equal(t, c.Expect.ShownAs, shown.ShownAs)
			if len(c.Expect.CoveredBy) == 0 {
				assert.Empty(t, shown.CoveredBy)
			} else {
				assert.Equal(t, c.Expect.CoveredBy, shown.CoveredBy)
			}
			labels := map[string]uwLabel{}
			for id, l := range shown.Labels {
				labels[id] = uwLabel{l.ReasonClass, l.RegistrationTime, l.StatedAfterwards, l.StatedPeriod}
			}
			assert.Equal(t, c.Expect.Labels, labels)
			assert.NotContains(t, c.Expect.MustNotShowAs, shown.ShownAs)
			if shown.State != er.StateRecordedAbsence {
				// A refusal or a pending request has no absence to cover.
				assert.Subset(t, c.Expect.MustNotShowAs, []string{er.UnavailableShownAs, er.StateRecordedAbsence})
				assert.Empty(t, c.Expect.Retention)
				return
			}
			assert.Subset(t, c.Expect.MustNotShowAs, []string{er.StateRefusal, "proof_of_attack"})
			if len(shown.CoveredBy) > 0 {
				assert.Contains(t, c.Expect.MustNotShowAs, "absence_without_statement")
			}
			// The retention classification is unchanged by any statement.
			if c.Expect.Retention != "" {
				require.Equal(t, "in_force", a.RetentionCommitment)
				assert.Equal(t, c.Expect.Retention, er.ClassifyAbsence(er.CommitmentInForce))
			}
		})
	}
	assert.Equal(t, map[string]int{"statement": 19, "display": 16}, kinds)
}
