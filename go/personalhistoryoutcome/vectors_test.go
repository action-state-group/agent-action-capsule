// SPDX-License-Identifier: Apache-2.0

package personalhistoryoutcome_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/action-state-group/agent-action-capsule/go/personalhistoryoutcome"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every case of vectors/personal-history-outcome-v0 runs from its inputs
// alone and is compared with the case's whole expected block, as
// python/tests/test_personal_history_outcome_v0_vectors.py compares the
// Python reference verifier and its Outcome evaluator. A native object's
// check is taken from the x402 adapter corpus, as that test does.

type message struct {
	MediaType  string `json:"media_type"`
	OctetsText string `json:"octets_text"`
	OctetsHex  string `json:"octets_hex"`
}

func (m message) octets(t *testing.T) []byte {
	t.Helper()
	if m.OctetsText != "" {
		return []byte(m.OctetsText)
	}
	b, err := hex.DecodeString(m.OctetsHex)
	require.NoError(t, err)
	return b
}

type vectorCase struct {
	ID   string `json:"id"`
	Pins struct {
		TrustPolicy        map[string]any `json:"trust_policy"`
		VerificationPolicy map[string]any `json:"verification_policy"`
		EvaluationTime     string         `json:"evaluation_time"`
		OutcomeRoles       struct {
			Counterparty []string `json:"counterparty"`
			Judge        []string `json:"judge"`
		} `json:"outcome_roles"`
		OutcomeRequirements []struct {
			ID        string   `json:"id"`
			Predicate string   `json:"predicate"`
			Sources   []string `json:"sources"`
		} `json:"outcome_requirements"`
		NativeObservations map[string]struct {
			Lookup map[string]any `json:"lookup"`
		} `json:"native_observations"`
	} `json:"pins"`
	Inputs struct {
		Definition json.RawMessage `json:"definition"`
		Exchanges  []struct {
			Request message `json:"request"`
			Reply   message `json:"reply"`
		} `json:"exchanges"`
		Evidence []message       `json:"evidence"`
		Openings json.RawMessage `json:"openings"`
	} `json:"inputs"`
	Expected map[string]any `json:"expected"`
}

type corpus struct {
	Count    int `json:"count"`
	Contract struct {
		Document map[string]any `json:"document"`
	} `json:"contract"`
	Predicates struct {
		Document json.RawMessage `json:"document"`
		Digest   string          `json:"digest"`
	} `json:"predicates"`
	Cases []vectorCase `json:"cases"`
}

func load(t *testing.T) corpus {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "vectors", "personal-history-outcome-v0", "vectors.json"))
	require.NoError(t, err)
	var c corpus
	require.NoError(t, json.Unmarshal(data, &c))
	return c
}

func decode(t *testing.T, raw []byte) any {
	t.Helper()
	v, err := evidencerequest.DecodeJSON(raw)
	require.NoError(t, err)
	return v
}

func normalize(t *testing.T, v any) any {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	var out any
	require.NoError(t, json.Unmarshal(data, &out))
	return out
}

// x402Requires are the checks each x402 predicate requires PASS on
// (spec/adapters/x402-v0.md §8 (d)); a payment shown for a deal also needs
// the payer and asset bound by the relying party's policy (PO §5.3).
var x402Requires = map[string][]string{
	"X1": {"payload_form", "payer_signature"},
	"X2": {"payload_form", "payer_signature", "authorization_terms"},
	"X3": {"payload_form", "payer_signature", "settle_response_form", "settlement_onchain", "authorization_window"},
	"X4": {"receipt_signature", "receipt_signer_authorized"},
	"X5": {"receipt_signature", "receipt_signer_authorized", "delivery_binding"},
}

type x402Case struct {
	Inputs struct {
		Wrapped []struct {
			Digest string `json:"digest"`
		} `json:"wrapped"`
		Lookup string `json:"lookup"`
	} `json:"inputs"`
	Expect struct {
		Reports []struct {
			Status string `json:"status"`
			Detail struct {
				Check string `json:"check"`
			} `json:"detail"`
		} `json:"reports"`
	} `json:"expect"`
}

// nativeChecker is the Python test's native_check over the x402 adapter
// corpus: the case whose wrapped objects the claim cites, the lookup the
// relying party observed, and the statuses that case states.
func nativeChecker(t *testing.T, vc vectorCase) personalhistoryoutcome.NativeChecker {
	dir := filepath.Join("..", "..", "vectors", "adapters", "x402")
	data, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	require.NoError(t, err)
	var corpus struct {
		Cases []x402Case `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &corpus))
	return func(n personalhistoryoutcome.NativeClaim) string {
		const notChecked = evidencerequest.StatusNotChecked
		obs, observed := vc.Pins.NativeObservations["x402-v0"]
		requires, known := x402Requires[n.AdapterPredicate]
		if n.Adapter != "x402-v0" || !observed || !known {
			return notChecked
		}
		want := slices.Clone(n.Evidence)
		sort.Strings(want)
		var found *x402Case
		for i, c := range corpus.Cases {
			var digests []string
			for _, w := range c.Inputs.Wrapped {
				digests = append(digests, w.Digest)
			}
			sort.Strings(digests)
			if slices.Equal(digests, want) {
				found = &corpus.Cases[i]
			}
		}
		if found == nil {
			return notChecked
		}
		raw, err := os.ReadFile(filepath.Join(dir, found.Inputs.Lookup))
		require.NoError(t, err)
		var recorded map[string]any
		require.NoError(t, json.Unmarshal(raw, &recorded))
		withoutFinal := func(m map[string]any) map[string]any {
			out := map[string]any{}
			for k, v := range m {
				if k != "final" {
					out[k] = v
				}
			}
			return out
		}
		if !reflect.DeepEqual(withoutFinal(obs.Lookup), withoutFinal(recorded)) || obs.Lookup["final"] != true {
			return notChecked
		}
		statuses := map[string]string{}
		for _, r := range found.Expect.Reports {
			statuses[r.Detail.Check] = r.Status
		}
		allPass, anyFail := true, false
		for _, k := range append(slices.Clone(requires), "payer_trust", "asset_trust") {
			allPass = allPass && statuses[k] == evidencerequest.StatusPass
			anyFail = anyFail || statuses[k] == evidencerequest.StatusFail
		}
		switch {
		case allPass:
			return evidencerequest.StatusPass
		case anyFail:
			return evidencerequest.StatusFail
		}
		return notChecked
	}
}

func evaluate(t *testing.T, c corpus, vc vectorCase) personalhistoryoutcome.Result {
	t.Helper()
	trust, err := evidencerequest.TrustPolicyFromPin(vc.Pins.TrustPolicy)
	require.NoError(t, err)
	v, err := evidencerequest.NewVerifier(trust, evidencerequest.VerificationPolicyFromPin(vc.Pins.VerificationPolicy),
		vc.Pins.EvaluationTime, c.Contract.Document)
	require.NoError(t, err)
	cfg := personalhistoryoutcome.Config{
		PredicateTable: decode(t, c.Predicates.Document),
		Roles:          personalhistoryoutcome.Roles{Counterparty: vc.Pins.OutcomeRoles.Counterparty, Judge: vc.Pins.OutcomeRoles.Judge},
		Native:         nativeChecker(t, vc),
	}
	for _, r := range vc.Pins.OutcomeRequirements {
		cfg.Requirements = append(cfg.Requirements, personalhistoryoutcome.Requirement{ID: r.ID, Predicate: r.Predicate, Sources: r.Sources})
	}
	in := personalhistoryoutcome.Inputs{Definition: decode(t, vc.Inputs.Definition)}
	for _, x := range vc.Inputs.Exchanges {
		in.Exchanges = append(in.Exchanges, personalhistoryoutcome.Exchange{
			Request: evidencerequest.Message{Octets: x.Request.octets(t), MediaType: x.Request.MediaType},
			Reply:   evidencerequest.Message{Octets: x.Reply.octets(t), MediaType: x.Reply.MediaType}})
	}
	for _, e := range vc.Inputs.Evidence {
		in.Evidence = append(in.Evidence, e.octets(t))
	}
	if vc.Inputs.Openings != nil {
		openings, ok := decode(t, vc.Inputs.Openings).(map[string]any)
		require.True(t, ok)
		in.Openings = openings
	}
	res, err := personalhistoryoutcome.Evaluate(v, cfg, in, []string{"r-deal-steps"})
	require.NoError(t, err)
	return res
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

func render(res personalhistoryoutcome.Result) map[string]any {
	exchanges := []any{}
	for _, x := range res.Exchanges {
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
		exchanges = append(exchanges, map[string]any{"message_type": r.MessageType, "subject": x.Subject, "properties": props,
			"accepted": x.Accepted, "requirements": reqs,
			"claim": map[string]any{"evidence": claims(r.Evidence), "proofs": claims(r.Proofs)}})
	}
	hprops := map[string]any{}
	for k, v := range res.Properties {
		hprops[k] = v
	}
	var cs any
	if res.Claims != nil {
		list := []any{}
		for _, c := range res.Claims {
			props := map[string]any{}
			for k, v := range c.Properties {
				props[k] = v
			}
			var verdict any
			if c.Verdict != "" {
				verdict = c.Verdict
			}
			list = append(list, map[string]any{"deal": c.Deal, "record": c.Record, "predicate": c.Predicate, "source": c.Source,
				"properties": props, "counts": c.Counts, "deal_binding": c.DealBinding, "verdict": verdict})
		}
		cs = list
	}
	var reqs any
	if res.Requirements != nil {
		out := map[string]any{}
		for id, per := range res.Requirements {
			deals := map[string]any{}
			for deal, r := range per {
				deals[deal] = map[string]any{"status": r.Status, "sufficiency": r.Sufficiency, "verdict": r.Verdict}
			}
			out[id] = deals
		}
		reqs = out
	}
	openings := map[string]any{}
	for k, v := range res.Openings {
		openings[k] = v
	}
	return map[string]any{"exchanges": exchanges, "history_properties": hprops, "accepted": res.Accepted, "claims": cs,
		"requirements": reqs, "deal_commitment_opening": openings}
}

// failing is the set of properties that FAIL anywhere in the result.
func failing(res personalhistoryoutcome.Result) map[string]bool {
	out := map[string]bool{}
	for _, x := range res.Exchanges {
		for _, p := range x.Reply.Properties {
			if p.Status == evidencerequest.StatusFail {
				out[p.Property] = true
			}
		}
	}
	for p, s := range res.Properties {
		if s == evidencerequest.StatusFail {
			out[p] = true
		}
	}
	for _, c := range res.Claims {
		for p, s := range c.Properties {
			if s == evidencerequest.StatusFail {
				out[p] = true
			}
		}
	}
	for _, s := range res.Openings {
		if s == evidencerequest.StatusFail {
			out["deal_commitment_opening"] = true
		}
	}
	return out
}

func TestPersonalHistoryOutcomeVectors(t *testing.T) {
	c := load(t)
	require.Equal(t, 25, c.Count)
	require.Len(t, c.Cases, 25)
	for _, vc := range c.Cases {
		t.Run(vc.ID, func(t *testing.T) {
			res := evaluate(t, c, vc)
			expected := map[string]any{}
			for k, v := range vc.Expected {
				if k != "fails" {
					expected[k] = v
				}
			}
			assert.Equal(t, normalize(t, expected), normalize(t, render(res)))
			want := map[string]bool{}
			for _, p := range vc.Expected["fails"].([]any) {
				want[p.(string)] = true
			}
			assert.Equal(t, want, failing(res))
		})
	}
}

// A holder_only claim never carries a verdict, and a requirement whose
// matching counting claims are all holder_only is not_evaluable (PO §8.4).
func TestNoMetFromTheHoldersWordAlone(t *testing.T) {
	c := load(t)
	checked := 0
	for _, vc := range c.Cases {
		res := evaluate(t, c, vc)
		for _, cl := range res.Claims {
			if cl.DealBinding == personalhistoryoutcome.HolderOnly {
				assert.Empty(t, cl.Verdict, vc.ID)
			}
		}
		for _, r := range vc.Pins.OutcomeRequirements {
			for deal, got := range res.Requirements[r.ID] {
				var mine []personalhistoryoutcome.Claim
				for _, cl := range res.Claims {
					if cl.Deal == deal && cl.Predicate == r.Predicate && slices.Contains(r.Sources, cl.Source) && cl.Counts {
						mine = append(mine, cl)
					}
				}
				holderOnly := len(mine) > 0
				for _, cl := range mine {
					holderOnly = holderOnly && cl.DealBinding == personalhistoryoutcome.HolderOnly
				}
				if holderOnly {
					assert.Equal(t, "not_evaluable", got.Verdict, vc.ID)
					checked++
				}
			}
		}
	}
	assert.GreaterOrEqual(t, checked, 2)
}

// With no adapter checker a native object's check is NOT_CHECKED, never
// PASS (PO §5.3).
func TestNativeCheckIsNotCheckedWithoutAnAdapter(t *testing.T) {
	c := load(t)
	for _, vc := range c.Cases {
		if vc.ID != "native-object" {
			continue
		}
		trust, err := evidencerequest.TrustPolicyFromPin(vc.Pins.TrustPolicy)
		require.NoError(t, err)
		v, err := evidencerequest.NewVerifier(trust, evidencerequest.VerificationPolicyFromPin(vc.Pins.VerificationPolicy),
			vc.Pins.EvaluationTime, c.Contract.Document)
		require.NoError(t, err)
		cfg := personalhistoryoutcome.Config{PredicateTable: decode(t, c.Predicates.Document),
			Roles: personalhistoryoutcome.Roles{Counterparty: vc.Pins.OutcomeRoles.Counterparty, Judge: vc.Pins.OutcomeRoles.Judge}}
		in := personalhistoryoutcome.Inputs{Definition: decode(t, vc.Inputs.Definition)}
		for _, x := range vc.Inputs.Exchanges {
			in.Exchanges = append(in.Exchanges, personalhistoryoutcome.Exchange{
				Request: evidencerequest.Message{Octets: x.Request.octets(t), MediaType: x.Request.MediaType},
				Reply:   evidencerequest.Message{Octets: x.Reply.octets(t), MediaType: x.Reply.MediaType}})
		}
		for _, e := range vc.Inputs.Evidence {
			in.Evidence = append(in.Evidence, e.octets(t))
		}
		res, err := personalhistoryoutcome.Evaluate(v, cfg, in, []string{"r-deal-steps"})
		require.NoError(t, err)
		require.Len(t, res.Claims, 1)
		assert.Equal(t, evidencerequest.StatusNotChecked, res.Claims[0].Properties["native_check"])
		assert.False(t, res.Claims[0].Counts)
	}
}

// A definition of any shape is evaluated without a panic, and fails
// definition_form.
func TestJunkDefinitionsFailClosed(t *testing.T) {
	c := load(t)
	vc := c.Cases[0]
	for _, junk := range []string{`null`, `1`, `"x"`, `[]`, `{}`, `{"name":"personal_history_outcome/1"}`,
		`{"selection":{},"sources":3,"reads":null,"predicates":[]}`} {
		vc.Inputs.Definition = json.RawMessage(junk)
		res := evaluate(t, c, vc)
		assert.Equal(t, evidencerequest.StatusFail, res.Properties["definition_form"], junk)
		assert.False(t, res.Accepted, junk)
	}
}
