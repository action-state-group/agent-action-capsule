// SPDX-License-Identifier: Apache-2.0

package personalhistory_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/action-state-group/agent-action-capsule/go/personalhistory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every case of vectors/personal-history-basic-v0 runs from its inputs
// alone and is compared with the case's whole expected block, as
// python/tests/test_personal_history_basic_v0_vectors.py compares the
// Python reference verifier and its History evaluator: the 13 History
// cases through Evaluate, and the lone refusal through the Verifier.

type message struct {
	MediaType  string `json:"media_type"`
	OctetsText string `json:"octets_text"`
}

func (m message) wire() evidencerequest.Message {
	return evidencerequest.Message{Octets: []byte(m.OctetsText), MediaType: m.MediaType}
}

type pins struct {
	TrustPolicy        map[string]any `json:"trust_policy"`
	VerificationPolicy map[string]any `json:"verification_policy"`
	EvaluationTime     string         `json:"evaluation_time"`
}

type vectorCase struct {
	ID     string `json:"id"`
	Pins   pins   `json:"pins"`
	Inputs struct {
		Definition any `json:"definition"`
		Exchanges  []struct {
			Request message `json:"request"`
			Reply   message `json:"reply"`
		} `json:"exchanges"`
		Request   message `json:"request"`
		Reply     message `json:"reply"`
		Requester string  `json:"requester"`
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

func load(t *testing.T) corpus {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "vectors", "personal-history-basic-v0", "vectors.json"))
	require.NoError(t, err)
	var c corpus
	require.NoError(t, json.Unmarshal(data, &c))
	return c
}

func verifier(t *testing.T, p pins, contract map[string]any) *evidencerequest.Verifier {
	t.Helper()
	trust, err := evidencerequest.TrustPolicyFromPin(p.TrustPolicy)
	require.NoError(t, err)
	v, err := evidencerequest.NewVerifier(trust, evidencerequest.VerificationPolicyFromPin(p.VerificationPolicy), p.EvaluationTime, contract)
	require.NoError(t, err)
	return v
}

func renderRequirements(r *evidencerequest.ReplyResult) map[string]any {
	out := map[string]any{}
	for _, q := range r.RequirementOrder {
		req := r.Requirements[q]
		entry := map[string]any{"row": req.Row, "status": req.Status, "sufficiency": req.Sufficiency, "verdict": req.Verdict}
		if req.Note != "" {
			entry["note"] = req.Note
		}
		out[q] = entry
	}
	return out
}

func renderClaims(cs []evidencerequest.Claim) []any {
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

func properties(r *evidencerequest.ReplyResult) map[string]any {
	out := map[string]any{}
	for _, p := range r.Properties {
		out[p.Property] = p.Status
	}
	return out
}

func render(res personalhistory.Result) map[string]any {
	exchanges := []any{}
	for _, x := range res.Exchanges {
		exchanges = append(exchanges, map[string]any{
			"message_type": x.Reply.MessageType, "subject": x.Subject, "properties": properties(x.Reply),
			"accepted": x.Accepted, "requirements": renderRequirements(x.Reply),
			"claim": map[string]any{"evidence": renderClaims(x.Reply.Evidence), "proofs": renderClaims(x.Reply.Proofs)},
		})
	}
	hprops := map[string]any{}
	for k, v := range res.Properties {
		hprops[k] = v
	}
	out := map[string]any{"exchanges": exchanges, "history_properties": hprops, "accepted": res.Accepted}
	if res.States != nil {
		per := map[string]any{}
		for _, d := range res.States.PerDeal {
			per[d.Deal] = d.State
		}
		counts := map[string]any{}
		for k, v := range res.States.Counts {
			counts[k] = v
		}
		out["deal_states"] = map[string]any{"selected_deals": res.States.SelectedDeals, "per_deal": per, "counts": counts}
	}
	return out
}

func normalize(t *testing.T, v any) any {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	var out any
	require.NoError(t, json.Unmarshal(data, &out))
	return out
}

func evaluate(t *testing.T, c corpus, vc vectorCase) personalhistory.Result {
	t.Helper()
	exchanges := make([]personalhistory.FileExchange, len(vc.Inputs.Exchanges))
	for i, x := range vc.Inputs.Exchanges {
		exchanges[i] = personalhistory.FileExchange{Request: x.Request.wire(), Reply: x.Reply.wire()}
	}
	res, err := personalhistory.Evaluate(verifier(t, vc.Pins, c.Contract.Document), vc.Inputs.Definition, exchanges, nil)
	require.NoError(t, err)
	return res
}

func TestPersonalHistoryBasicVectors(t *testing.T) {
	c := load(t)
	require.Equal(t, 14, c.Count)
	require.Len(t, c.Cases, 14)
	history := 0
	for _, vc := range c.Cases {
		if vc.Inputs.Definition == nil {
			continue
		}
		history++
		t.Run(vc.ID, func(t *testing.T) {
			got := render(evaluate(t, c, vc))
			expected := map[string]any{}
			for k, v := range vc.Expected {
				if k != "fails" {
					expected[k] = v
				}
			}
			assert.Equal(t, normalize(t, expected), normalize(t, got))
		})
	}
	assert.Equal(t, 13, history)
}

// Each case fails at least the properties it names (the §6.4 table), and
// is accepted exactly when it names none.
func TestPersonalHistoryNamedPropertyFails(t *testing.T) {
	c := load(t)
	for _, vc := range c.Cases {
		if vc.Inputs.Definition == nil {
			continue
		}
		t.Run(vc.ID, func(t *testing.T) {
			res := evaluate(t, c, vc)
			failing := map[string]bool{}
			for _, x := range res.Exchanges {
				for _, p := range x.Reply.Properties {
					if p.Status == evidencerequest.StatusFail {
						failing[p.Property] = true
					}
				}
			}
			for p, s := range res.Properties {
				if s == evidencerequest.StatusFail {
					failing[p] = true
				}
			}
			named, _ := vc.Expected["fails"].([]any)
			for _, p := range named {
				assert.True(t, failing[p.(string)], "%s fails", p)
			}
			assert.Equal(t, len(named) == 0, res.Accepted)
		})
	}
}

func TestPersonalHistoryRefusalToAnotherRequester(t *testing.T) {
	c := load(t)
	var refusal *vectorCase
	for i := range c.Cases {
		if c.Cases[i].Inputs.Definition == nil {
			refusal = &c.Cases[i]
		}
	}
	require.NotNil(t, refusal)
	v := verifier(t, refusal.Pins, c.Contract.Document)
	res, err := v.Verify([]evidencerequest.Exchange{{Request: refusal.Inputs.Request.wire(), Replies: []evidencerequest.Message{refusal.Inputs.Reply.wire()}}},
		evidencerequest.VerifyOptions{Requirements: []string{"r-deal-steps"}})
	require.NoError(t, err)
	r := res.Exchanges[0].Replies[0]
	got := map[string]any{"message_type": r.MessageType, "reason": r.Reason, "properties": properties(r),
		"requirements": renderRequirements(r), "claim": map[string]any{"evidence": renderClaims(r.Evidence), "proofs": renderClaims(r.Proofs)}}
	assert.Equal(t, normalize(t, refusal.Expected), normalize(t, got))
}

// Definition and DerivationID give the positive run's definition and the
// derivation every one of its requests names.
func TestDefinitionAndDerivationID(t *testing.T) {
	c := load(t)
	var positive vectorCase
	for _, vc := range c.Cases {
		if vc.ID == "history-basic" {
			positive = vc
		}
	}
	held := positive.Inputs.Definition.(map[string]any)
	var selection []string
	for _, s := range held["selection"].([]any) {
		selection = append(selection, s.(string))
	}
	// Given unsorted and repeated, as a caller might hold them.
	built := personalhistory.Definition(append([]string{selection[2], selection[0]}, selection...), held["recipient"].(string))
	assert.Equal(t, normalize(t, held), normalize(t, built))
	id, err := personalhistory.DerivationID(built)
	require.NoError(t, err)
	var request map[string]any
	require.NoError(t, json.Unmarshal([]byte(positive.Inputs.Exchanges[0].Request.OctetsText), &request))
	assert.Equal(t, request["derivation"], id)
}

// resign replaces the artifact of the positive case's first reply with
// artifact, recomputes artifact_digest and re-signs the envelope with the
// holder's test key, as a holder could.
func resign(t *testing.T, c corpus, vc vectorCase, artifact []byte) vectorCase {
	t.Helper()
	seed := sha256.Sum256([]byte("personal-agent-history-profile-v0 conformance vectors: holder key"))
	key := ed25519.NewKeyFromSeed(seed[:])
	var env map[string]any
	require.NoError(t, json.Unmarshal([]byte(vc.Inputs.Exchanges[0].Reply.OctetsText), &env))
	env["artifact_digest"] = evidencerequest.Digest(artifact)
	delete(env, "sig")
	delete(env, "artifact")
	body, err := evidencerequest.EncodeJCS(jsonNumbers(env))
	require.NoError(t, err)
	env["sig"] = hex.EncodeToString(ed25519.Sign(key, body))
	env["artifact"] = base64.RawURLEncoding.EncodeToString(artifact)
	out, err := evidencerequest.EncodeJCS(jsonNumbers(env))
	require.NoError(t, err)
	vc.Inputs.Exchanges = slices.Clone(vc.Inputs.Exchanges)
	vc.Inputs.Exchanges[0].Reply = message{MediaType: evidencerequest.MediaTypeJSON, OctetsText: string(out)}
	return vc
}

func jsonNumbers(v any) any {
	switch x := v.(type) {
	case float64:
		return uint64(x)
	case []any:
		for i := range x {
			x[i] = jsonNumbers(x[i])
		}
	case map[string]any:
		for k := range x {
			x[k] = jsonNumbers(x[k])
		}
	}
	return v
}

// An Artifact is exactly the JCS of one object (PH §4.3). Bytes beside it
// (trailing data, a duplicate member, another encoding) authenticate under
// the holder's signature but are never read by artifact_form, so an
// Artifact carrying any fails artifact_form, while the envelope itself is
// still accepted.
func TestArtifactBytesBesideTheObjectFail(t *testing.T) {
	c := load(t)
	var positive vectorCase
	for _, vc := range c.Cases {
		if vc.ID == "history-basic" {
			positive = vc
		}
	}
	var env map[string]any
	require.NoError(t, json.Unmarshal([]byte(positive.Inputs.Exchanges[0].Reply.OctetsText), &env))
	artifact, err := base64.RawURLEncoding.DecodeString(env["artifact"].(string))
	require.NoError(t, err)
	text := string(artifact)

	same := render(evaluate(t, c, resign(t, c, positive, artifact)))
	assert.Equal(t, true, same["accepted"], "re-signing the same Artifact changes nothing")

	for name, mutated := range map[string]string{
		"trailing object":      text + `{"counterparty":"private value"}`,
		"trailing space":       text + " ",
		"duplicate member":     strings.Replace(text, `{"anchor"`, `{"anchor":"x","anchor"`, 1),
		"not JCS":              strings.Replace(text, `{"anchor"`, `{ "anchor"`, 1),
		"object in leaf_index": jcsOf(t, text, func(r map[string]any) { r["leaf_index"] = map[string]any{"counterparty": "private value"} }),
		"text in leaf_index":   jcsOf(t, text, func(r map[string]any) { r["leaf_index"] = "1" }),
		"digest not hex":       jcsOf(t, text, func(r map[string]any) { r["digest"] = "private value" }),
		"object in a read":     jcsOf(t, text, func(r map[string]any) { r["committed_at"] = map[string]any{"counterparty": "private value"} }),
	} {
		require.NotEqual(t, text, mutated, name)
		res := evaluate(t, c, resign(t, c, positive, []byte(mutated)))
		assert.True(t, res.Exchanges[0].Accepted, "%s: the envelope verifies", name)
		assert.False(t, res.Accepted, name)
		// The whole report, as the Python test states it for the same
		// mutants: an unreadable Artifact fails record_kinds too; one whose
		// entries are readable but malformed fails artifact_form only.
		want := map[string]string{}
		for _, p := range personalhistory.HistoryProperties {
			want[p] = evidencerequest.StatusPass
		}
		want["artifact_form"] = evidencerequest.StatusFail
		if !strings.Contains(name, " in ") && name != "digest not hex" {
			want["record_kinds"] = evidencerequest.StatusFail
		}
		assert.Equal(t, want, res.Properties, name)
	}
}

// jcsOf is the Artifact text with its first record edited, as JCS.
func jcsOf(t *testing.T, text string, edit func(map[string]any)) string {
	t.Helper()
	v, err := evidencerequest.DecodeJSON([]byte(text))
	require.NoError(t, err)
	edit(v.(map[string]any)["records"].([]any)[0].(map[string]any))
	out, err := evidencerequest.EncodeJCS(v)
	require.NoError(t, err)
	return string(out)
}

// holderSign signs an envelope value (its signed members) with the
// holder's test key and returns the reply octets, artifact included.
func holderSign(t *testing.T, env map[string]any, artifact []byte) []byte {
	t.Helper()
	seed := sha256.Sum256([]byte("personal-agent-history-profile-v0 conformance vectors: holder key"))
	key := ed25519.NewKeyFromSeed(seed[:])
	env["responder"] = hex.EncodeToString(key.Public().(ed25519.PublicKey))
	env["artifact_digest"] = evidencerequest.Digest(artifact)
	body, err := evidencerequest.EncodeJCS(env)
	require.NoError(t, err)
	env["sig"] = hex.EncodeToString(ed25519.Sign(key, body))
	env["artifact"] = base64.RawURLEncoding.EncodeToString(artifact)
	out, err := evidencerequest.EncodeJCS(env)
	require.NoError(t, err)
	return out
}

// The Artifact's anchor is the resolved anchor digest (PH §4.3): an
// envelope answered under min_freshness has no anchor digest, and an
// Artifact whose anchor is null does not match it by both being absent.
func TestArtifactAnchorMustBeADigest(t *testing.T) {
	c := load(t)
	definition := personalhistory.Definition([]string{"deal-a"}, "recipient-1")
	derivation, err := personalhistory.DerivationID(definition)
	require.NoError(t, err)
	request, err := evidencerequest.EncodeJCS(map[string]any{
		"coverage": map[string]any{"min_freshness": uint64(1)}, "derivation": derivation, "nonce": "n",
		"profile": evidencerequest.ProfileID, "subject": map[string]any{"correlation": "deal-a"},
	})
	require.NoError(t, err)
	artifact, err := evidencerequest.EncodeJCS(map[string]any{
		"anchor": nil, "derivation": derivation, "evidence_stream": "s",
		"records": []any{map[string]any{"digest": strings.Repeat("a", 64), "leaf_index": uint64(0), "record_type": personalhistory.StepCompleted}},
		"subject": map[string]any{"correlation": "deal-a"},
	})
	require.NoError(t, err)
	reply := holderSign(t, map[string]any{
		"profile": evidencerequest.ProfileID, "request_digest": evidencerequest.Digest(request),
		"subject": map[string]any{"correlation": "deal-a"}, "derivation": derivation,
		"anchor": map[string]any{"freshness": uint64(3)}, "issued_at": "2026-10-15T00:00:00Z",
	}, artifact)
	vc := c.Cases[0]
	res, err := personalhistory.Evaluate(verifier(t, vc.Pins, c.Contract.Document), definition, []personalhistory.FileExchange{{
		Request: evidencerequest.Message{Octets: request, MediaType: evidencerequest.MediaTypeJSON},
		Reply:   evidencerequest.Message{Octets: reply, MediaType: evidencerequest.MediaTypeJSON},
	}}, nil)
	require.NoError(t, err)
	require.True(t, res.Exchanges[0].Accepted, "the envelope itself verifies under min_freshness")
	assert.Equal(t, evidencerequest.StatusFail, res.Properties["artifact_form"])
}

func TestFileRoundTripsTheOctetsExactly(t *testing.T) {
	c := load(t)
	var positive vectorCase
	for _, vc := range c.Cases {
		if vc.ID == "history-basic" {
			positive = vc
		}
	}
	cborReply := []byte{0xa1, 0x61, 0x61, 0x01} // {"a": 1}, any octets: the file never re-encodes them
	f := personalhistory.File{Definition: positive.Inputs.Definition, Exchanges: []personalhistory.FileExchange{
		{Request: positive.Inputs.Exchanges[0].Request.wire(), Reply: positive.Inputs.Exchanges[0].Reply.wire()},
		{Request: evidencerequest.Message{Octets: []byte{0xa0}, MediaType: evidencerequest.MediaTypeCBOR}, Reply: evidencerequest.Message{Octets: cborReply, MediaType: evidencerequest.MediaTypeCBOR}},
	}}
	encoded, err := personalhistory.EncodeFile(f)
	require.NoError(t, err)
	back, err := personalhistory.ParseFile(encoded)
	require.NoError(t, err)
	require.Len(t, back.Exchanges, 2)
	assert.Equal(t, f.Exchanges[0].Request.Octets, back.Exchanges[0].Request.Octets)
	assert.Equal(t, f.Exchanges[0].Reply.Octets, back.Exchanges[0].Reply.Octets)
	assert.Equal(t, cborReply, back.Exchanges[1].Reply.Octets)
	assert.Equal(t, evidencerequest.MediaTypeCBOR, back.Exchanges[1].Reply.MediaType)
	again, err := personalhistory.EncodeFile(back)
	require.NoError(t, err)
	assert.Equal(t, encoded, again, "JCS, so one History has one file")

	_, err = personalhistory.EncodeFile(personalhistory.File{Definition: map[string]any{}, Exchanges: []personalhistory.FileExchange{
		{Request: evidencerequest.Message{Octets: []byte{0xff, 0xfe}, MediaType: evidencerequest.MediaTypeJSON}, Reply: f.Exchanges[0].Reply},
	}})
	assert.ErrorIs(t, err, personalhistory.ErrInvalid, "JSON octets a JSON string cannot carry exactly")
	escaped := evidencerequest.Message{Octets: []byte(`{"a":"\ud800"}`), MediaType: evidencerequest.MediaTypeJSON}
	encoded, err = personalhistory.EncodeFile(personalhistory.File{Definition: map[string]any{}, Exchanges: []personalhistory.FileExchange{{Request: escaped, Reply: escaped}}})
	require.NoError(t, err, "an escape is ASCII, carried as is")
	back, err = personalhistory.ParseFile(encoded)
	require.NoError(t, err)
	assert.Equal(t, escaped.Octets, back.Exchanges[0].Reply.Octets)
	_, err = personalhistory.EncodeFile(personalhistory.File{Definition: map[string]any{}, Exchanges: []personalhistory.FileExchange{
		{Request: evidencerequest.Message{Octets: []byte("{}"), MediaType: "text/plain"}, Reply: f.Exchanges[0].Reply},
	}})
	assert.ErrorIs(t, err, personalhistory.ErrInvalid)
}

func TestParseFileRefusesWhatIsNotTheContainer(t *testing.T) {
	msg := `{"media_type":"application/json","octets_text":"{}"}`
	cases := map[string]string{
		"not JSON":              `not json`,
		"an array":              `[]`,
		"duplicate member":      `{"history":"personal_history_basic/1","history":"personal_history_basic/1","definition":{},"exchanges":[]}`,
		"another level":         `{"history":"personal_history_basic/2","definition":{},"exchanges":[]}`,
		"an extra member":       `{"history":"personal_history_basic/1","definition":{},"exchanges":[],"carrier":"x"}`,
		"no definition":         `{"history":"personal_history_basic/1","exchanges":[]}`,
		"exchanges not a list":  `{"history":"personal_history_basic/1","definition":{},"exchanges":{}}`,
		"exchange extra member": `{"history":"personal_history_basic/1","definition":{},"exchanges":[{"request":` + msg + `,"reply":` + msg + `,"x":1}]}`,
		"message extra member":  `{"history":"personal_history_basic/1","definition":{},"exchanges":[{"request":{"media_type":"application/json","octets_text":"{}","x":1},"reply":` + msg + `}]}`,
		"JSON given as hex":     `{"history":"personal_history_basic/1","definition":{},"exchanges":[{"request":{"media_type":"application/json","octets_hex":"7b7d"},"reply":` + msg + `}]}`,
		"CBOR given as text":    `{"history":"personal_history_basic/1","definition":{},"exchanges":[{"request":{"media_type":"application/cbor","octets_text":"{}"},"reply":` + msg + `}]}`,
		"uppercase hex":         `{"history":"personal_history_basic/1","definition":{},"exchanges":[{"request":{"media_type":"application/cbor","octets_hex":"A0"},"reply":` + msg + `}]}`,
		"odd-length hex":        `{"history":"personal_history_basic/1","definition":{},"exchanges":[{"request":{"media_type":"application/cbor","octets_hex":"a"},"reply":` + msg + `}]}`,
		"unknown media type":    `{"history":"personal_history_basic/1","definition":{},"exchanges":[{"request":{"media_type":"text/plain","octets_text":"{}"},"reply":` + msg + `}]}`,
	}
	for name, text := range cases {
		_, err := personalhistory.ParseFile([]byte(text))
		assert.ErrorIs(t, err, personalhistory.ErrInvalid, name)
	}
	_, err := personalhistory.ParseFile([]byte(`{"history":"personal_history_basic/1","definition":{},"exchanges":[{"request":` + msg + `,"reply":` + msg + `}]}`))
	assert.NoError(t, err, "the container itself")
}
