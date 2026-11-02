// SPDX-License-Identifier: Apache-2.0

package inferencehistory_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/action-state-group/agent-action-capsule/go/inferencehistory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every case of vectors/inference-service-history-v0 and of
// vectors/inference-service-history-v0-interop-v1 runs from its inputs
// alone and is compared with the case's whole expected block, as
// python/tests/test_inference_service_history_v0_vectors.py compares the
// Python reference verifier and its evaluator.

type message struct {
	MediaType  string `json:"media_type"`
	OctetsText string `json:"octets_text"`
}

func (m message) wire() evidencerequest.Message {
	return evidencerequest.Message{Octets: []byte(m.OctetsText), MediaType: m.MediaType}
}

type history struct {
	Definition json.RawMessage `json:"definition"`
	Request    message         `json:"request"`
	Reply      message         `json:"reply"`
}

type vectorCase struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Pins struct {
		TrustPolicy        map[string]any `json:"trust_policy"`
		VerificationPolicy map[string]any `json:"verification_policy"`
		EvaluationTime     string         `json:"evaluation_time"`
		ServiceHistory     struct {
			LogKeys     []string `json:"log_keys"`
			WitnessKeys []string `json:"witness_keys"`
			PeerKeys    []string `json:"peer_keys"`
		} `json:"service_history"`
	} `json:"pins"`
	Inputs struct {
		history
		Histories []history `json:"histories"`
	} `json:"inputs"`
	Expected map[string]any `json:"expected"`
}

type corpus struct {
	Count    int `json:"count"`
	Contract struct {
		Document map[string]any `json:"document"`
	} `json:"contract"`
	Cases []vectorCase `json:"cases"`
}

var sets = []struct {
	dir                               string
	count, histories, pairs, refusals int
}{
	{"inference-service-history-v0", 27, 20, 3, 4},
	{"inference-service-history-v0-interop-v1", 28, 20, 3, 5},
}

func load(t *testing.T, dir string) corpus {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "vectors", dir, "vectors.json"))
	require.NoError(t, err)
	var c corpus
	require.NoError(t, json.Unmarshal(data, &c))
	return c
}

func verifier(t *testing.T, c corpus, vc vectorCase) *evidencerequest.Verifier {
	t.Helper()
	trust, err := evidencerequest.TrustPolicyFromPin(vc.Pins.TrustPolicy)
	require.NoError(t, err)
	v, err := evidencerequest.NewVerifier(trust, evidencerequest.VerificationPolicyFromPin(vc.Pins.VerificationPolicy),
		vc.Pins.EvaluationTime, c.Contract.Document)
	require.NoError(t, err)
	return v
}

func pins(vc vectorCase) inferencehistory.Pins {
	s := vc.Pins.ServiceHistory
	return inferencehistory.Pins{LogKeys: s.LogKeys, WitnessKeys: s.WitnessKeys, PeerKeys: s.PeerKeys}
}

func decode(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	v, err := evidencerequest.DecodeJSON(raw)
	require.NoError(t, err)
	return v
}

func claims(cs []evidencerequest.Claim) []any {
	out := []any{}
	for _, c := range cs {
		m := map[string]any{}
		for k, v := range c {
			m[k] = v
		}
		out = append(out, m)
	}
	return out
}

func renderExchange(x inferencehistory.ExchangeResult) map[string]any {
	r := x.Reply
	props := map[string]any{}
	for _, p := range r.Properties {
		props[p.Property] = p.Status
	}
	reqs := map[string]any{}
	for _, q := range r.RequirementOrder {
		req := r.Requirements[q]
		entry := map[string]any{"row": req.Row, "status": req.Status, "sufficiency": req.Sufficiency, "verdict": req.Verdict}
		if req.Note != "" {
			entry["note"] = req.Note
		}
		reqs[q] = entry
	}
	out := map[string]any{"message_type": r.MessageType, "properties": props, "requirements": reqs,
		"claim": map[string]any{"evidence": claims(r.Evidence), "proofs": claims(r.Proofs)}}
	if r.MessageType == "refusal" {
		out["reason"] = x.Reason
		return out
	}
	out["subject"] = x.Subject
	out["accepted"] = x.Accepted
	return out
}

func strings(m map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func renderHistory(res inferencehistory.Result) map[string]any {
	notCounted := []any{}
	for _, n := range res.Witness.ReceiptsNotCounted {
		notCounted = append(notCounted, map[string]any{"checkpoint": n.Checkpoint, "reason": n.Reason})
	}
	shows := map[string]any{"witness": map[string]any{"checkpoints": res.Witness.Checkpoints,
		"witness_receipts_counted": res.Witness.ReceiptsCounted, "witness_receipts_not_counted": notCounted}}
	if res.Exchanges != nil {
		xs := []any{}
		for _, e := range res.Exchanges {
			s := map[string]any{"client_nonce": e.ClientNonce, "claimed": e.Claimed, "derived": e.Derived, "shown_as": e.ShownAs}
			if e.IssuerIndependence != "" {
				s["issuer_independence"] = e.IssuerIndependence
			}
			xs = append(xs, s)
		}
		shows["exchanges"] = xs
	}
	return map[string]any{"exchange": renderExchange(res.Exchange), "history_properties": strings(res.Properties),
		"coverage": map[string]any{"declared_kind": res.Coverage.DeclaredKind,
			"properties": strings(res.Coverage.Properties), "relative_to": res.Coverage.RelativeTo},
		"shows": shows, "accepted": res.Accepted}
}

func normalize(t *testing.T, v any) any {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	var out any
	require.NoError(t, json.Unmarshal(data, &out))
	return out
}

func comparable(expected map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range expected {
		if k != "fails" {
			out[k] = v
		}
	}
	return out
}

func exchange(h history) inferencehistory.Exchange {
	return inferencehistory.Exchange{Request: h.Request.wire(), Reply: h.Reply.wire()}
}

func evaluate(t *testing.T, c corpus, vc vectorCase) inferencehistory.Result {
	t.Helper()
	res, err := inferencehistory.Evaluate(verifier(t, c, vc), pins(vc), decode(t, vc.Inputs.Definition),
		exchange(vc.Inputs.history), []string{"r-service"})
	require.NoError(t, err)
	return res
}

func evaluatePair(t *testing.T, c corpus, vc vectorCase) inferencehistory.PairResult {
	t.Helper()
	var defs []any
	var xs []inferencehistory.Exchange
	for _, h := range vc.Inputs.Histories {
		defs = append(defs, decode(t, h.Definition))
		xs = append(xs, exchange(h))
	}
	res, err := inferencehistory.EvaluatePair(verifier(t, c, vc), pins(vc), defs, xs, []string{"r-service"})
	require.NoError(t, err)
	return res
}

func failing(res inferencehistory.Result) map[string]bool {
	out := map[string]bool{}
	for _, p := range res.Exchange.Reply.Properties {
		if p.Status == evidencerequest.StatusFail {
			out[p.Property] = true
		}
	}
	for p, s := range res.Properties {
		if s == evidencerequest.StatusFail {
			out[p] = true
		}
	}
	for p, s := range res.Coverage.Properties {
		if s == evidencerequest.StatusFail {
			out[p] = true
		}
	}
	return out
}

func TestInferenceServiceHistoryVectors(t *testing.T) {
	for _, set := range sets {
		t.Run(set.dir, func(t *testing.T) {
			c := load(t, set.dir)
			require.Equal(t, set.count, c.Count)
			require.Len(t, c.Cases, set.count)
			seen := map[string]int{}
			for _, vc := range c.Cases {
				seen[vc.Kind]++
				t.Run(vc.ID, func(t *testing.T) {
					switch vc.Kind {
					case "history":
						res := evaluate(t, c, vc)
						assert.Equal(t, normalize(t, comparable(vc.Expected)), normalize(t, renderHistory(res)))
						// The named properties fail, and the History is accepted exactly when none does.
						want := map[string]bool{}
						for _, p := range vc.Expected["fails"].([]any) {
							want[p.(string)] = true
						}
						assert.Equal(t, want, failing(res))
						assert.Equal(t, len(want) == 0, res.Accepted)
					case "pair":
						res := evaluatePair(t, c, vc)
						exchanges := []any{}
						for _, x := range res.Exchanges {
							exchanges = append(exchanges, renderExchange(x))
						}
						got := map[string]any{"exchanges": exchanges, "period_fixed": res.PeriodFixed, "accepted": res.Accepted}
						assert.Equal(t, normalize(t, comparable(vc.Expected)), normalize(t, got))
					case "refusal":
						x, err := inferencehistory.ExchangeOf(verifier(t, c, vc), exchange(vc.Inputs.history), []string{"r-service"})
						require.NoError(t, err)
						assert.Equal(t, normalize(t, vc.Expected), normalize(t, renderExchange(x)))
					default:
						t.Fatalf("unknown kind %q", vc.Kind)
					}
				})
			}
			assert.Equal(t, set.histories, seen["history"])
			assert.Equal(t, set.pairs, seen["pair"])
			assert.Equal(t, set.refusals, seen["refusal"])
		})
	}
}

// A definition of any shape is evaluated without a panic, and fails
// definition_form.
func TestJunkDefinitionsFailClosed(t *testing.T) {
	c := load(t, "inference-service-history-v0")
	var vc vectorCase
	for _, x := range c.Cases {
		if x.ID == "standard-served-only" {
			vc = x
		}
	}
	for _, junk := range []string{`null`, `1`, `"x"`, `[]`, `{}`, `{"level":"standard"}`,
		`{"level":"detailed","members":{},"reads":3}`} {
		vc.Inputs.Definition = json.RawMessage(junk)
		res := evaluate(t, c, vc)
		assert.Equal(t, evidencerequest.StatusFail, res.Properties["definition_form"], junk)
		assert.False(t, res.Accepted, junk)
	}
}
