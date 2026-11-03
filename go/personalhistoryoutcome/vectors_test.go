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
	"github.com/action-state-group/agent-action-capsule/go/personalhistory"
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
		Evidence  []message       `json:"evidence"`
		Openings  json.RawMessage `json:"openings"`
		TickPaths json.RawMessage `json:"tick_paths"`
	} `json:"inputs"`
	Expected map[string]any `json:"expected"`
	// RawInputs is the case's inputs as the one-file History (PO §11).
	RawInputs json.RawMessage `json:"-"`
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
	// Rejected are the cases whose file is not a History at this level
	// (PO §11); load moves them out of Cases.
	Rejected []vectorCase `json:"-"`
}

func load(t *testing.T) corpus {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "vectors", "personal-history-outcome-v0", "vectors.json"))
	require.NoError(t, err)
	var c corpus
	require.NoError(t, json.Unmarshal(data, &c))
	var raw struct {
		Cases []struct {
			Inputs json.RawMessage `json:"inputs"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &raw))
	var histories []vectorCase
	for i, vc := range c.Cases {
		vc.RawInputs = raw.Cases[i].Inputs
		if vc.Expected["not_a_history"] == true {
			c.Rejected = append(c.Rejected, vc)
		} else {
			histories = append(histories, vc)
		}
	}
	c.Cases = histories
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
	in, err := personalhistoryoutcome.ParseFile(vc.RawInputs)
	require.NoError(t, err)
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
	out := map[string]any{"exchanges": exchanges, "history_properties": hprops, "accepted": res.Accepted, "claims": cs,
		"requirements": reqs, "deal_commitment_opening": openings}
	if res.TickPaths != nil {
		paths := []any{}
		for _, p := range res.TickPaths {
			paths = append(paths, map[string]any{"evidence_stream": p.EvidenceStream, "status": p.Status})
		}
		out["tick_paths"] = paths
	}
	return out
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
	require.Equal(t, 29, c.Count)
	require.Len(t, c.Cases, 27)
	require.Len(t, c.Rejected, 2)
	for _, vc := range c.Rejected {
		t.Run(vc.ID, func(t *testing.T) {
			assert.Equal(t, map[string]any{"not_a_history": true, "fails": []any{}}, vc.Expected)
			_, err := personalhistoryoutcome.ParseFile(vc.RawInputs)
			assert.ErrorIs(t, err, personalhistoryoutcome.ErrInvalid)
		})
	}
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
		var file map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(vc.RawInputs, &file))
		file["definition"] = json.RawMessage(junk)
		var err error
		vc.RawInputs, err = json.Marshal(file)
		require.NoError(t, err)
		res := evaluate(t, c, vc)
		assert.Equal(t, evidencerequest.StatusFail, res.Properties["definition_form"], junk)
		assert.False(t, res.Accepted, junk)
	}
}

// A tick path's check is reported beside the History and never changes
// whether it is accepted or what its claims are (PO §8.2, §11); a History
// carrying no tick paths reports none.
func TestTickPathsNeverChangeAcceptance(t *testing.T) {
	c := load(t)
	byID := map[string]vectorCase{}
	for _, vc := range c.Cases {
		byID[vc.ID] = vc
	}
	pass := evaluate(t, c, byID["multi-stream-earlier-tick"])
	fail := evaluate(t, c, byID["mutant-tick-path-consistency-changed"])
	require.Len(t, pass.TickPaths, 1)
	require.Len(t, fail.TickPaths, 1)
	assert.Equal(t, evidencerequest.StatusPass, pass.TickPaths[0].Status)
	assert.Equal(t, evidencerequest.StatusFail, fail.TickPaths[0].Status)
	assert.Contains(t, fail.TickPaths[0].Detail, "step 5")
	assert.True(t, pass.Accepted)
	assert.True(t, fail.Accepted)
	assert.Equal(t, pass.Properties, fail.Properties)
	assert.Equal(t, pass.Claims, fail.Claims)
	assert.Equal(t, pass.Requirements, fail.Requirements)
	assert.Nil(t, evaluate(t, c, byID["holder-record"]).TickPaths)

	// Without the tick log's keys in the trust policy the check is not PASS,
	// and the History is still accepted.
	vc := byID["multi-stream-earlier-tick"]
	keys, ok := vc.Pins.TrustPolicy["log_keys"].([]any)
	require.True(t, ok)
	untrusted := vc
	untrusted.Pins.TrustPolicy = map[string]any{}
	for k, v := range vc.Pins.TrustPolicy {
		untrusted.Pins.TrustPolicy[k] = v
	}
	untrusted.Pins.TrustPolicy["log_keys"] = keys[:len(keys)-2]
	res := evaluate(t, c, untrusted)
	require.Len(t, res.TickPaths, 1)
	assert.NotEqual(t, evidencerequest.StatusPass, res.TickPaths[0].Status)
	assert.True(t, res.Accepted)
}

// The tick paths a History carries are read by personalhistory.ParseTickPaths,
// which rejects a value not of PH §8.3's form (PO §11).
func TestMalformedTickPathsRejected(t *testing.T) {
	c := load(t)
	var raw json.RawMessage
	for _, vc := range c.Cases {
		if vc.ID == "multi-stream-earlier-tick" {
			raw = vc.Inputs.TickPaths
		}
	}
	require.NotNil(t, raw)
	_, err := personalhistory.ParseTickPaths(raw)
	require.NoError(t, err)
	for name, mutate := range map[string]func(map[string]any){
		"extra member":  func(m map[string]any) { m["witness"] = "00" },
		"no paths":      func(m map[string]any) { m["paths"] = []any{} },
		"uppercase hex": func(m map[string]any) { m["anchor_tick"] = "D2" },
		"path extra member": func(m map[string]any) {
			m["paths"].([]any)[0].(map[string]any)["anchor"] = "00"
		},
	} {
		var m map[string]any
		require.NoError(t, json.Unmarshal(raw, &m))
		mutate(m)
		b, err := json.Marshal(m)
		require.NoError(t, err)
		_, err = personalhistory.ParseTickPaths(b)
		assert.ErrorIs(t, err, personalhistory.ErrInvalid, name)
	}
}

// ParseFile reads every History case's file, and rejects a file with a
// member outside PO §11's table or a member not in its form.
func TestParseFile(t *testing.T) {
	c := load(t)
	var base map[string]any
	for _, vc := range c.Cases {
		in, err := personalhistoryoutcome.ParseFile(vc.RawInputs)
		require.NoError(t, err, vc.ID)
		assert.Equal(t, vc.Inputs.TickPaths != nil, in.TickPaths != nil, vc.ID)
		assert.Len(t, in.Evidence, len(vc.Inputs.Evidence), vc.ID)
		if vc.ID == "not-evaluable-delivered-from-payment-evidence" {
			require.NoError(t, json.Unmarshal(vc.RawInputs, &base))
		}
	}
	require.NotNil(t, base)
	for name, mutate := range map[string]func(map[string]any){
		"other member":       func(m map[string]any) { m["witness"] = []any{} },
		"missing openings":   func(m map[string]any) { delete(m, "openings") },
		"basic level name":   func(m map[string]any) { m["history"] = personalhistory.Name },
		"evidence no octets": func(m map[string]any) { m["evidence"] = []any{map[string]any{"media_type": "application/json"}} },
		"evidence bad hex": func(m map[string]any) {
			m["evidence"] = []any{map[string]any{"media_type": "application/octet-stream", "octets_hex": "ABCD"}}
		},
		"opening no text":   func(m map[string]any) { m["openings"] = map[string]any{"d": map[string]any{"nonce": "n"}} },
		"openings an array": func(m map[string]any) { m["openings"] = []any{} },
		"tick_paths empty":  func(m map[string]any) { m["tick_paths"] = map[string]any{} },
		"exchange text as CBOR": func(m map[string]any) {
			m["exchanges"].([]any)[0].(map[string]any)["request"].(map[string]any)["media_type"] = "application/cbor"
		},
	} {
		b, err := json.Marshal(base)
		require.NoError(t, err)
		var m map[string]any
		require.NoError(t, json.Unmarshal(b, &m))
		mutate(m)
		b, err = json.Marshal(m)
		require.NoError(t, err)
		_, err = personalhistoryoutcome.ParseFile(b)
		assert.ErrorIs(t, err, personalhistoryoutcome.ErrInvalid, name)
	}
}
