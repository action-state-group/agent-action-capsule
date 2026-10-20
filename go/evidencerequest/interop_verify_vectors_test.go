// SPDX-License-Identifier: Apache-2.0

package evidencerequest_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The exchange cases of vectors/interop-profile-v0 run through the Verifier
// from their inputs alone, and the result is compared with each case's
// whole expected block, as python/tests/test_interop_profile_verifier.py
// compares the Python reference verifier's. The carriage, acceptance and
// lifecycle cases test parts of the profile this package does not
// implement.

type vectorMessage struct {
	MediaType  string `json:"media_type"`
	OctetsText string `json:"octets_text"`
	OctetsHex  string `json:"octets_hex"`
}

func (m vectorMessage) message(t *testing.T) evidencerequest.Message {
	t.Helper()
	if m.OctetsHex != "" {
		b, err := hex.DecodeString(m.OctetsHex)
		require.NoError(t, err)
		return evidencerequest.Message{Octets: b, MediaType: m.MediaType}
	}
	return evidencerequest.Message{Octets: []byte(m.OctetsText), MediaType: m.MediaType}
}

type vectorPins struct {
	TrustPolicy        map[string]any `json:"trust_policy"`
	VerificationPolicy map[string]any `json:"verification_policy"`
	EvaluationTime     string         `json:"evaluation_time"`
}

func readCorpus(t *testing.T, dir string, into any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "vectors", dir, "vectors.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, into))
}

func newVerifier(t *testing.T, pins vectorPins, contract map[string]any) *evidencerequest.Verifier {
	t.Helper()
	trust, err := evidencerequest.TrustPolicyFromPin(pins.TrustPolicy)
	require.NoError(t, err)
	v, err := evidencerequest.NewVerifier(trust, evidencerequest.VerificationPolicyFromPin(pins.VerificationPolicy), pins.EvaluationTime, contract)
	require.NoError(t, err)
	return v
}

func renderRequirements(order []string, reqs map[string]evidencerequest.RequirementResult) map[string]any {
	out := map[string]any{}
	for _, q := range order {
		r := reqs[q]
		entry := map[string]any{"row": r.Row, "status": nullable(r.Status), "sufficiency": nullable(r.Sufficiency), "verdict": nullable(r.Verdict)}
		if r.Note != "" {
			entry["note"] = r.Note
		}
		out[q] = entry
	}
	return out
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
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

func renderReply(r *evidencerequest.ReplyResult, withNative bool) map[string]any {
	props := map[string]any{}
	for _, p := range r.Properties {
		props[p.Property] = p.Status
	}
	out := map[string]any{"message_type": r.MessageType, "properties": props}
	if withNative {
		var native any
		if r.NativeCheck != nil {
			native = r.NativeCheck.Status
		}
		out["native_check"] = native
	}
	out["requirements"] = renderRequirements(r.RequirementOrder, r.Requirements)
	out["claim"] = map[string]any{"evidence": claims(r.Evidence), "proofs": claims(r.Proofs)}
	for _, q := range r.RequirementOrder {
		if kinds := r.Requirements[q].PresentationKindsAllowed(); kinds != nil {
			out["presentation_kinds_allowed"] = []any{kinds[0], kinds[1]}
		}
	}
	return out
}

// normalize round-trips a value through JSON so rendered and expected
// blocks compare as the same Go types.
func normalize(t *testing.T, v any) any {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	var out any
	require.NoError(t, json.Unmarshal(data, &out))
	return out
}

func TestInteropProfileExchangeVectors(t *testing.T) {
	var corpus struct {
		Contract struct {
			Document map[string]any `json:"document"`
		} `json:"contract"`
		Cases []struct {
			ID     string     `json:"id"`
			Pins   vectorPins `json:"pins"`
			Inputs struct {
				Request      *vectorMessage                    `json:"request"`
				Requests     []vectorMessage                   `json:"requests"`
				Replies      []vectorMessage                   `json:"replies"`
				Absence      *vectorMessage                    `json:"absence_record"`
				Relations    map[string]string                 `json:"requirement_relations"`
				Foreign      *struct{ Path, MediaType string } `json:"-"`
				ForeignRaw   map[string]string                 `json:"foreign_object"`
				A2A          any                               `json:"a2a"`
				MCP          any                               `json:"mcp"`
				Native       any                               `json:"native"`
				Manifests    any                               `json:"manifests"`
				Statements   any                               `json:"statements"`
				Acceptances  any                               `json:"acceptance_records"`
				OtherRequest any                               `json:"other_request"`
			} `json:"inputs"`
			Expected map[string]any `json:"expected"`
		} `json:"cases"`
	}
	readCorpus(t, "interop-profile-v0", &corpus)
	ran := 0
	for _, c := range corpus.Cases {
		in := c.Inputs
		if in.Replies == nil || in.A2A != nil || in.MCP != nil || in.Native != nil || in.Manifests != nil || in.Statements != nil || in.Acceptances != nil {
			continue
		}
		ran++
		t.Run(c.ID, func(t *testing.T) {
			v := newVerifier(t, c.Pins, corpus.Contract.Document)
			requests := in.Requests
			if in.Request != nil {
				requests = []vectorMessage{*in.Request}
			}
			exchanges := make([]evidencerequest.Exchange, len(requests))
			for i, r := range requests {
				exchanges[i].Request = r.message(t)
			}
			for i, rep := range in.Replies {
				k := min(i, len(exchanges)-1)
				exchanges[k].Replies = append(exchanges[k].Replies, rep.message(t))
			}
			if in.Absence != nil {
				m := in.Absence.message(t)
				exchanges[0].Absence = &m
			}
			opts := evidencerequest.VerifyOptions{Requirements: []string{"r-record"}, Relations: in.Relations}
			if in.Relations != nil {
				opts.Requirements = nil
				for q := range in.Relations {
					opts.Requirements = append(opts.Requirements, q)
				}
			}
			if in.ForeignRaw != nil {
				opts.Foreign = &evidencerequest.ForeignObject{Path: in.ForeignRaw["path"], MediaType: in.ForeignRaw["media_type"]}
			}
			result, err := v.Verify(exchanges, opts)
			require.NoError(t, err)
			out := map[string]any{}
			replies := []any{}
			for k, ex := range result.Exchanges {
				for _, r := range ex.Replies {
					rendered := renderReply(r, opts.Foreign != nil)
					if in.Request == nil {
						rendered["request_index"] = k
					}
					replies = append(replies, rendered)
				}
			}
			out["replies"] = replies
			if in.Request != nil {
				out["request_digest"] = result.Exchanges[0].RequestDigest
			} else {
				var digests []any
				artifacts := map[string]bool{}
				var first []byte
				for _, ex := range result.Exchanges {
					digests = append(digests, ex.RequestDigest)
					for _, r := range ex.Replies {
						artifacts[string(r.Artifact)] = true
						if first == nil {
							first = r.Artifact
						}
					}
				}
				out["request_digests"] = digests
				out["artifact_octets_identical"] = len(artifacts) == 1
				out["artifact_digest"] = evidencerequest.Digest(first)
			}
			for _, r := range replies {
				if r.(map[string]any)["message_type"] == "envelope" {
					out["set_properties"] = map[string]any{"caller_invariance": result.CallerInvariance.Status}
					break
				}
			}
			if a := result.Exchanges[0].Absence; a != nil {
				block := map[string]any{"form": a.Form, "requirements": renderRequirements(a.RequirementOrder, a.Requirements)}
				if a.Form == "conforming" {
					block["claim"] = map[string]any{"evidence": claims(a.Evidence), "proofs": []any{}}
					block["presentation_kind_recommended"] = "story"
				}
				out["absence"] = block
			}
			assert.Equal(t, normalize(t, c.Expected), normalize(t, out))
		})
	}
	assert.Equal(t, 26, ran, "every exchange case of the corpus ran")
}
