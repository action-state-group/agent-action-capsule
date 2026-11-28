// SPDX-License-Identifier: BSD-3-Clause
package ed25519strict

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/stretchr/testify/require"
)

func readVectors(t *testing.T, target interface{}, path ...string) {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(append([]string{filepath.Dir(filename), "..", ".."}, path...)...))
	require.NoError(t, err)
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	require.NoError(t, decoder.Decode(target))
}

// The public Verify over the countersign/v1 entries of
// vectors/bundle/producer-key (Bundle -03 countersign/v1 step 2): each
// strict-* entry, which crypto/ed25519.Verify accepts, is refused, and every
// other entry, a valid signature, verifies.
func TestVerifyCountersignVectors(t *testing.T) {
	var file struct {
		Cases []struct {
			ID     string                 `json:"id"`
			Bundle map[string]interface{} `json:"bundle"`
			Expect struct {
				Signature string `json:"signature"`
			} `json:"expect"`
		} `json:"cases"`
	}
	readVectors(t, &file, "vectors", "bundle", "producer-key", "vectors.json")
	strictCases := 0
	for _, c := range file.Cases {
		entry := c.Bundle["countersignatures"].([]interface{})[0].(map[string]interface{})
		signer := entry["signer"].(map[string]interface{})
		input, err := canonical.JCS(map[string]interface{}{
			"over": entry["over"], "signer": signer, "statement": entry["statement"], "type": "countersign/v1",
		})
		require.NoError(t, err, c.ID)
		key, err := hex.DecodeString(signer["key_id"].(string))
		require.NoError(t, err, c.ID)
		sig, err := hex.DecodeString(entry["signature"].(string))
		require.NoError(t, err, c.ID)
		strict := strings.HasPrefix(c.ID, "strict-")
		if strict {
			strictCases++
			require.Equal(t, "invalid", c.Expect.Signature, c.ID)
			require.True(t, ed25519.Verify(key, input, sig), "%s: lenient Ed25519 accepts it", c.ID)
		}
		require.Equal(t, !strict, Verify(key, input, sig), c.ID)
	}
	require.Equal(t, 2, strictCases)
}

// The public Verify over the commitments of
// vectors/adapters/evidence-commitment-carriers (binding §3 "Signing", V2):
// the strict-* commitments, which crypto/ed25519.Verify accepts, are refused;
// the current commitment of three-carriers-one-commitment verifies.
func TestVerifyCommitmentVectors(t *testing.T) {
	var file struct {
		Cases []struct {
			ID     string            `json:"id"`
			Served map[string]string `json:"served"`
		} `json:"cases"`
	}
	readVectors(t, &file, "vectors", "adapters", "evidence-commitment-carriers", "vectors.json")
	check := func(id string) (strictOK, lenientOK bool) {
		for _, c := range file.Cases {
			if c.ID != id {
				continue
			}
			for _, served := range c.Served {
				octets, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(served, "="))
				require.NoError(t, err, id)
				var commitment map[string]interface{}
				decoder := json.NewDecoder(strings.NewReader(string(octets)))
				decoder.UseNumber()
				if decoder.Decode(&commitment) != nil || commitment["profile"] == nil {
					continue
				}
				spki, err := base64.StdEncoding.DecodeString(commitment["spki"].(string))
				require.NoError(t, err, id)
				key := ed25519.PublicKey(spki[len(spki)-ed25519.PublicKeySize:])
				value := commitment["sig"].(map[string]interface{})["value"].(string)
				sig, err := base64.RawURLEncoding.DecodeString(value)
				require.NoError(t, err, id)
				body := map[string]interface{}{}
				for name, member := range commitment {
					if name != "sig" {
						body[name] = member
					}
				}
				input, err := canonical.JCS(body)
				require.NoError(t, err, id)
				return Verify(key, input, sig), ed25519.Verify(key, input, sig)
			}
		}
		t.Fatalf("no commitment in case %s", id)
		return false, false
	}
	for _, id := range []string{"strict-small-order-key", "strict-identity-r"} {
		strictOK, lenientOK := check(id)
		require.True(t, lenientOK, "%s: lenient Ed25519 accepts it", id)
		require.False(t, strictOK, id)
	}
	strictOK, _ := check("three-carriers-one-commitment")
	require.True(t, strictOK)
}
