// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"

	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
)

type unavailableReceipt struct {
	Time     string `json:"time"`
	Accepted bool   `json:"accepted"`
}

type unavailableCase struct {
	ID           string               `json:"id"`
	Kind         string               `json:"kind"`
	ResponderKey string               `json:"responder_key"`
	Statement    map[string]any       `json:"statement"`
	Receipts     []unavailableReceipt `json:"receipts"`
	Absence      struct {
		SentAt   string  `json:"sent_at"`
		ClosedAt *string `json:"closed_at"`
		Received string  `json:"received"`
	} `json:"absence"`
	Statements []struct {
		ID        string               `json:"id"`
		Statement map[string]any       `json:"statement"`
		Receipts  []unavailableReceipt `json:"receipts"`
	} `json:"statements"`
}

func registrationReceipts(rs []unavailableReceipt) []evidencerequest.RegistrationReceipt {
	out := make([]evidencerequest.RegistrationReceipt, 0, len(rs))
	for _, r := range rs {
		out = append(out, evidencerequest.RegistrationReceipt{Time: r.Time, Accepted: r.Accepted})
	}
	return out
}

// orNull is s, or JSON null when s is empty.
func orNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func unavailable(cases []unavailableCase) ([]map[string]any, error) {
	out := []map[string]any{}
	for _, c := range cases {
		if c.Kind == "statement" {
			r := evidencerequest.RecognizeUnavailableWindow(c.Statement, registrationReceipts(c.Receipts), c.ResponderKey)
			out = append(out, map[string]any{"id": c.ID, "recognized": r.Recognized, "why": orNull(r.Why),
				"registration_time": orNull(r.RegistrationTime)})
			continue
		}
		a := c.Absence
		observation := evidencerequest.Observation{WindowOpen: a.ClosedAt == nil}
		switch a.Received {
		case "nothing":
			observation.Received = evidencerequest.ReceivedNothing
		case "refusal":
			observation.Received = evidencerequest.ReceivedRefusal
			observation.Refusal = evidencerequest.RefusalCheck{SignatureValid: true, ReasonRegistered: true, Conformant: true}
		default:
			return nil, fmt.Errorf("%s: received %q", c.ID, a.Received)
		}
		closedAt := ""
		if a.ClosedAt != nil {
			closedAt = *a.ClosedAt
		}
		statements := make([]evidencerequest.WindowStatement, 0, len(c.Statements))
		for _, s := range c.Statements {
			statements = append(statements, evidencerequest.WindowStatement{ID: s.ID, Statement: s.Statement, Receipts: registrationReceipts(s.Receipts)})
		}
		shown, err := evidencerequest.DisplayAbsence(observation.State(), a.SentAt, closedAt, statements, c.ResponderKey)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.ID, err)
		}
		labels := map[string]any{}
		for id, l := range shown.Labels {
			labels[id] = map[string]any{"reason_class": l.ReasonClass, "registration_time": l.RegistrationTime,
				"stated_afterwards": l.StatedAfterwards, "stated_period": l.StatedPeriod[:]}
		}
		coveredBy := shown.CoveredBy
		if coveredBy == nil {
			coveredBy = []string{}
		}
		out = append(out, map[string]any{"id": c.ID, "state": shown.State, "shown_as": shown.ShownAs,
			"covered_by": coveredBy, "labels": labels})
	}
	return out, nil
}
