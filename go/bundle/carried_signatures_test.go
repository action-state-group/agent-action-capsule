// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type signatureObjectCase struct {
	ID       string                 `json:"id"`
	Kind     string                 `json:"kind"`
	Object   map[string]interface{} `json:"object"`
	Signing  string                 `json:"signing_input_hex"`
	Lenient  *bool                  `json:"lenient_ed25519_verifies"`
	Expected struct {
		Profile *string `json:"profile"`
		State   string  `json:"state"`
	} `json:"expect"`
}

type signatureComposedCase struct {
	ID        string                 `json:"id"`
	Container map[string]interface{} `json:"container"`
	Expected  struct {
		Status   string                       `json:"status"`
		Findings []string                     `json:"findings"`
		Members  map[string]map[string]string `json:"members"`
	} `json:"expect"`
}

func readRepoJSON(t *testing.T, target interface{}, path ...string) {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(append([]string{filepath.Dir(filename), "..", ".."}, path...)...))
	require.NoError(t, err)
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	require.NoError(t, decoder.Decode(target))
}

func signatureProfileVectors(t *testing.T) (objects []signatureObjectCase, composed []signatureComposedCase) {
	t.Helper()
	var file struct {
		Count    json.Number             `json:"count"`
		Cases    []signatureObjectCase   `json:"cases"`
		Composed []signatureComposedCase `json:"composed_cases"`
	}
	readRepoJSON(t, &file, "vectors", "bundle", "composed-signature-profiles", "vectors.json")
	require.Equal(t, json.Number("50"), file.Count)
	require.Len(t, file.Cases, 45)
	require.Len(t, file.Composed, 5)
	return file.Cases, file.Composed
}

// TestCarriedSignatureProfileVectors runs the object cases of
// vectors/bundle/composed-signature-profiles (bundle -03, "Carried Signature
// Profiles"): the profile each carried object is read in and its state.
func TestCarriedSignatureProfileVectors(t *testing.T) {
	objects, _ := signatureProfileVectors(t)
	for _, c := range objects {
		t.Run(c.ID, func(t *testing.T) {
			var profile, state string
			if c.Kind == "refusal" {
				profile, state = CarriedRefusalProfile(c.Object), VerifyCarriedRefusal(c.Object)
			} else {
				profile, state = CarriedResponseProfile(c.Object), VerifyCarriedResponse(c.Object)
			}
			want := ""
			if c.Expected.Profile != nil {
				want = *c.Expected.Profile
			}
			require.Equal(t, want, profile)
			require.Equal(t, c.Expected.State, state)
			if c.Signing != "" {
				require.Equal(t, c.Signing, hex.EncodeToString(signingInputOf(t, profile, c.Object)))
			}
			if c.Lenient != nil {
				// The forgery verifies under ed25519.Verify alone: only
				// strictness refuses it.
				key, _ := hex.DecodeString(c.Object["key_id"].(string))
				sigName := "sig"
				if profile == WholeRefusalProfile {
					sigName = "signature"
				}
				sig, _ := hex.DecodeString(c.Object[sigName].(string))
				require.Equal(t, *c.Lenient, ed25519.Verify(key, signingInputOf(t, profile, c.Object), sig))
			}
		})
	}
}

func signingInputOf(t *testing.T, profile string, object map[string]interface{}) []byte {
	t.Helper()
	switch profile {
	case ThreeMemberRefusalProfile:
		input, ok := ThreeMemberRefusalSigningInput(object)
		require.True(t, ok)
		return input
	case WholeRefusalProfile:
		unsigned := map[string]interface{}{}
		for name, member := range object {
			if name != "signature" {
				unsigned[name] = member
			}
		}
		input, err := json.Marshal(unsigned) // ASCII keys, no numbers: JCS here
		require.NoError(t, err)
		return input
	default:
		input, err := ArtifactResponseSigningInput(object["request_digest"].(string), object["anchor"].(string),
			object["artifact_kind"].(string), object["artifact_digest"].(string), object["issued_at"].(string))
		require.NoError(t, err)
		return input
	}
}

// TestCarriedSignatureComposedVectors runs the composed cases with both
// verifiers set, and without them, where every carried signature stays
// signature-unverified.
func TestCarriedSignatureComposedVectors(t *testing.T) {
	_, composed := signatureProfileVectors(t)
	opts := Options{RefusalSignature: VerifyCarriedRefusal, ResponseSignature: VerifyCarriedResponse}
	for _, c := range composed {
		t.Run(c.ID, func(t *testing.T) {
			block := c.Container["extensions"].(map[string]interface{})[ComposedKind]
			result := VerifyComposed(block, opts)
			require.Equal(t, c.Expected.Status, result.Status)
			require.Equal(t, c.Expected.Findings, nonNil(result.Findings))
			plain := VerifyComposed(block, Options{})
			for id, states := range c.Expected.Members {
				for name, want := range states {
					require.Equal(t, want, memberSignature(t, result, id, name), "%s %s", id, name)
					require.Equal(t, RefusalSignatureUnverified, memberSignature(t, plain, id, name), "%s %s default", id, name)
				}
			}
		})
	}
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func memberSignature(t *testing.T, result ComposedResult, id, name string) string {
	t.Helper()
	for _, m := range result.Members {
		if m.ID == id {
			if name == "refusal_signature" {
				return m.RefusalSignature
			}
			return m.ResponseSignature
		}
	}
	t.Fatalf("no member %s", id)
	return ""
}

// The four strict-Ed25519 cases of vectors/interop-profile-v1/: the forged
// refusals are three-member refusals that do not verify; a forged envelope
// carries responder (in none of these profiles). The small-order key's
// forgery verifies any message under ed25519.Verify, so carried as key_id
// and sig of a digest-bound response it tests strictness; the identity-R
// signature is over the envelope's own body, so it is not rehomed.
func TestCarriedSignatureInteropV1Forgeries(t *testing.T) {
	var file struct {
		Cases []struct {
			ID     string `json:"id"`
			Inputs struct {
				Replies []struct {
					Octets string `json:"octets_text"`
				} `json:"replies"`
			} `json:"inputs"`
		} `json:"cases"`
	}
	readRepoJSON(t, &file, "vectors", "interop-profile-v1", "vectors.json")
	reply := func(id string) map[string]interface{} {
		for _, c := range file.Cases {
			if c.ID == id {
				var value map[string]interface{}
				require.NoError(t, json.Unmarshal([]byte(c.Inputs.Replies[0].Octets), &value))
				return value
			}
		}
		t.Fatalf("no interop-profile-v1 case %s", id)
		return nil
	}
	for _, id := range []string{"forged-refusal-small-order-key", "forged-refusal-identity-r"} {
		refusal := reply(id)
		require.Equal(t, ThreeMemberRefusalProfile, CarriedRefusalProfile(refusal), id)
		require.Equal(t, RefusalSignatureInvalid, VerifyCarriedRefusal(refusal), id)
	}
	for _, id := range []string{"envelope-small-order-key", "envelope-identity-r"} {
		envelope := reply(id)
		require.Equal(t, RefusalSignatureUnverified, VerifyCarriedResponse(envelope), id)
		if id != "envelope-small-order-key" {
			continue
		}
		rehomed := map[string]interface{}{
			"request_digest": envelope["request_digest"], "anchor": envelope["anchor"].(map[string]interface{})["digest"],
			"artifact_kind": "evidence-bundle/v2", "artifact_digest": envelope["artifact_digest"],
			"issued_at": envelope["issued_at"], "key_id": envelope["responder"], "sig": envelope["sig"],
		}
		require.Equal(t, RefusalSignatureInvalid, VerifyCarriedResponse(rehomed), id)
		key, _ := hex.DecodeString(rehomed["key_id"].(string))
		sig, _ := hex.DecodeString(rehomed["sig"].(string))
		input := signingInputOf(t, DigestBoundArtifactResponseProfile, rehomed)
		require.True(t, ed25519.Verify(key, input, sig), "lenient Ed25519 accepts the forgery")
	}
}
