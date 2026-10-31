// SPDX-License-Identifier: Apache-2.0

package evidencerequest_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	er "github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The exchange cases of vectors/interop-profile-v0 and
// vectors/interop-profile-v0-requirement-facts, and of the v1 sets
// vectors/interop-profile-v1 and vectors/interop-profile-v1-requirement-facts,
// each set with its own contract, run through the Verifier
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

func (m vectorMessage) message(t *testing.T) er.Message {
	t.Helper()
	if m.OctetsHex != "" {
		b, err := hex.DecodeString(m.OctetsHex)
		require.NoError(t, err)
		return er.Message{Octets: b, MediaType: m.MediaType}
	}
	return er.Message{Octets: []byte(m.OctetsText), MediaType: m.MediaType}
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

func newVerifier(t *testing.T, pins vectorPins, contract map[string]any) *er.Verifier {
	t.Helper()
	trust, err := er.TrustPolicyFromPin(pins.TrustPolicy)
	require.NoError(t, err)
	v, err := er.NewVerifier(trust, er.VerificationPolicyFromPin(pins.VerificationPolicy), pins.EvaluationTime, contract)
	require.NoError(t, err)
	return v
}

func renderRequirements(order []string, reqs map[string]er.RequirementResult) map[string]any {
	out := map[string]any{}
	for _, q := range order {
		r := reqs[q]
		entry := map[string]any{"row": r.Row, "status": nullable(r.Status), "sufficiency": nullable(r.Sufficiency), "verdict": nullable(r.Verdict)}
		if r.Note != "" {
			entry["note"] = r.Note
		}
		if r.AppliesFrom != "" {
			entry["applies_from"] = r.AppliesFrom
		}
		if r.OutOfScopeAllowed {
			entry["out_of_scope_allowed"] = true
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

func claims(cs []er.Claim) []any {
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

func renderReply(r *er.ReplyResult, withNative bool) map[string]any {
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
	// Each set and the number of its exchange cases.
	for set, want := range map[string]int{"interop-profile-v0": 26, "interop-profile-v0-requirement-facts": 2,
		"interop-profile-v1": 29, "interop-profile-v1-requirement-facts": 2} {
		t.Run(set, func(t *testing.T) { runExchangeVectors(t, set, want) })
	}
}

func runExchangeVectors(t *testing.T, set string, want int) {
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
				Requirements []string                          `json:"requirements"`
			} `json:"inputs"`
			Expected map[string]any `json:"expected"`
		} `json:"cases"`
	}
	readCorpus(t, set, &corpus)
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
			exchanges := make([]er.Exchange, len(requests))
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
			opts := er.VerifyOptions{Requirements: []string{"r-record"}, Relations: in.Relations}
			if in.Requirements != nil {
				opts.Requirements = in.Requirements
			}
			if in.Relations != nil {
				opts.Requirements = nil
				for q := range in.Relations {
					opts.Requirements = append(opts.Requirements, q)
				}
			}
			if in.ForeignRaw != nil {
				opts.Foreign = &er.ForeignObject{Path: in.ForeignRaw["path"], MediaType: in.ForeignRaw["media_type"]}
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
				out["artifact_digest"] = er.Digest(first)
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
	assert.Equal(t, want, ran, "every exchange case of the corpus ran")
}

// The checkpoint is checked as decoded strictly: its unprotected header,
// which no signature covers, wrapped in the self-described CBOR tag 55799
// is not the empty map step 7 requires, though a generic decoder strips
// the tag. The envelope is re-signed by the vectors' responder key over
// the changed material.
func TestCheckpointUnprotectedHeaderIsReadAsSent(t *testing.T) {
	var corpus struct {
		Contract struct {
			Document map[string]any `json:"document"`
		} `json:"contract"`
		TestKeys struct {
			Keys map[string]struct {
				SeedLabel string `json:"seed_label"`
			} `json:"keys"`
		} `json:"test_keys"`
		Cases []struct {
			ID     string     `json:"id"`
			Pins   vectorPins `json:"pins"`
			Inputs struct {
				Request vectorMessage   `json:"request"`
				Replies []vectorMessage `json:"replies"`
			} `json:"inputs"`
		} `json:"cases"`
	}
	readCorpus(t, "interop-profile-v0", &corpus)
	seed := sha256.Sum256([]byte(corpus.TestKeys.Keys["responder"].SeedLabel))
	key := ed25519.NewKeyFromSeed(seed[:])
	for _, c := range corpus.Cases {
		if c.ID != "valid-exchange" {
			continue
		}
		v := newVerifier(t, c.Pins, corpus.Contract.Document)
		var env map[string]any
		require.NoError(t, json.Unmarshal([]byte(c.Inputs.Replies[0].OctetsText), &env))
		ver := env["verification"].([]any)
		content := env["verification_content"].([]any)
		for i, e := range ver {
			entry := e.(map[string]any)
			if entry["kind"] != er.KindCLLCheckpoint {
				continue
			}
			cp, err := base64.RawURLEncoding.DecodeString(content[i].(string))
			require.NoError(t, err)
			require.Equal(t, []byte{0xd2, 0x84}, cp[:2])
			head := cp[2]
			require.Equal(t, byte(0x40), head&0xe0, "a byte-string protected header")
			n, at := int(head&0x1f), 3
			if n == 24 {
				n, at = int(cp[3]), 4
			}
			unprotected := at + n
			require.Equal(t, byte(0xa0), cp[unprotected])
			changed := append(append(append([]byte{}, cp[:unprotected]...), 0xd9, 0xd9, 0xf7), cp[unprotected:]...)
			content[i] = base64.RawURLEncoding.EncodeToString(changed)
			entry["digest"] = er.Digest(changed)
			env["anchor"].(map[string]any)["digest"] = er.Digest(changed)
		}
		delete(env, "sig")
		signed := map[string]any{}
		for _, k := range []string{"profile", "request_digest", "subject", "derivation", "anchor", "artifact_digest", "verification", "responder", "issued_at"} {
			if x, ok := env[k]; ok {
				signed[k] = x
			}
		}
		body, err := canonical.JCS(signed)
		require.NoError(t, err)
		env["sig"] = hex.EncodeToString(ed25519.Sign(key, body))
		reply, err := canonical.JCS(env)
		require.NoError(t, err)
		res, err := v.Verify([]er.Exchange{{Request: c.Inputs.Request.message(t), Replies: []er.Message{{Octets: reply, MediaType: er.MediaTypeJSON}}}}, er.VerifyOptions{Requirements: []string{"r-record"}})
		require.NoError(t, err)
		r := res.Exchanges[0].Replies[0]
		assert.Equal(t, er.StatusPass, r.Status("envelope_signature"))
		assert.Equal(t, er.StatusPass, r.Status("verification_binding"))
		assert.Equal(t, er.StatusFail, r.Status("anchor_inclusion"))
		return
	}
	t.Fatal("no valid-exchange case")
}
