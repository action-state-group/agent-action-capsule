// SPDX-License-Identifier: BSD-3-Clause

package controllerbinding_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	cb "github.com/action-state-group/agent-action-capsule/go/controllerbinding"
	er "github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every case of vectors/controller-binding-v0 is run from its inputs alone,
// and the result is compared with the case's whole expected binding block and
// its issuer_independence status, shown_as and reason, as
// python/tests/test_controller_binding_v0_vectors.py compares its evaluator's.
// The halves' own signatures and satisfied_becomes belong to the interop
// profile verifier, not to this package.

type octets struct {
	OctetsText string `json:"octets_text"`
}

type vectorCase struct {
	ID   string `json:"id"`
	Pins struct {
		TrustPolicy struct {
			CredentialIssuers []string `json:"credential_issuers"`
		} `json:"trust_policy"`
		VerificationPolicy struct {
			CredentialMethods []string `json:"credential_methods_implemented"`
		} `json:"verification_policy"`
	} `json:"pins"`
	Inputs struct {
		Halves      []octets `json:"halves"`
		Binding     octets   `json:"binding"`
		Revocations []octets `json:"revocations"`
		Credential  *octets  `json:"credential"`
	} `json:"inputs"`
	Expected struct {
		Binding struct {
			Claim         *string           `json:"claim"`
			BindingDigest string            `json:"binding_digest"`
			Properties    map[string]string `json:"properties"`
			BindsPair     bool              `json:"binds_pair"`
			Applies       bool              `json:"applies"`
			Proves        []string          `json:"proves"`
		} `json:"binding"`
		IssuerIndependence cb.IssuerIndependence `json:"issuer_independence"`
		Fails              []string              `json:"fails"`
	} `json:"expected"`
}

type corpus struct {
	CredentialMethod string       `json:"credential_method"`
	Cases            []vectorCase `json:"cases"`
}

func readCorpus(t *testing.T) corpus {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "vectors", "controller-binding-v0", "vectors.json"))
	require.NoError(t, err)
	var c corpus
	require.NoError(t, json.Unmarshal(data, &c))
	require.Len(t, c.Cases, 25)
	return c
}

// vectorCredential is the credential format the vectors fix for themselves
// (CB §10), checked under the case's pinned credential issuers. It is test
// code: the package ships no credential verifier.
func vectorCredential(issuers []string) cb.CredentialVerifier {
	return func(octets []byte, c cb.Credential, keys [2]string) string {
		value, err := er.DecodeJSON(octets)
		o, ok := value.(map[string]any)
		if err != nil || !ok || len(o) != 5 || o["issuer"] != c.Issuer || !slices.Contains(issuers, c.Issuer) {
			return er.StatusFail
		}
		for _, name := range []string{"issued_at", "organization", "sig"} {
			if _, ok := o[name].(string); !ok {
				return er.StatusFail
			}
		}
		named, ok := o["keys"].([]any)
		if !ok || len(named) != 2 || named[0] != keys[0] || named[1] != keys[1] {
			return er.StatusFail
		}
		sig, _ := o["sig"].(string)
		delete(o, "sig")
		signed, err := er.EncodeJCS(o)
		if err != nil || !verifyHex(c.Issuer, sig, signed) {
			return er.StatusFail
		}
		return er.StatusPass
	}
}

type half struct {
	IssuedAt string `json:"issued_at"`
	Producer string `json:"producer"`
}

func runCase(t *testing.T, c vectorCase, credentialMethod string) (cb.Report, [2]string, []time.Time) {
	t.Helper()
	var keys [2]string
	var times []time.Time
	for i, h := range c.Inputs.Halves {
		var parsed half
		require.NoError(t, json.Unmarshal([]byte(h.OctetsText), &parsed))
		at, err := time.Parse(time.RFC3339, parsed.IssuedAt)
		require.NoError(t, err)
		keys[i] = parsed.Producer
		times = append(times, at)
	}
	opts := cb.Options{CredentialVerifiers: map[string]cb.CredentialVerifier{}}
	for _, r := range c.Inputs.Revocations {
		opts.Revocations = append(opts.Revocations, []byte(r.OctetsText))
	}
	if c.Inputs.Credential != nil {
		opts.Credential = []byte(c.Inputs.Credential.OctetsText)
	}
	for _, m := range c.Pins.VerificationPolicy.CredentialMethods {
		require.Equal(t, credentialMethod, m, "the vectors define one credential method")
		opts.CredentialVerifiers[m] = vectorCredential(c.Pins.TrustPolicy.CredentialIssuers)
	}
	return cb.Verify([]byte(c.Inputs.Binding.OctetsText), times, opts), keys, times
}

func TestVectors(t *testing.T) {
	data := readCorpus(t)
	for _, c := range data.Cases {
		t.Run(c.ID, func(t *testing.T) {
			report, keys, _ := runCase(t, c, data.CredentialMethod)
			want := c.Expected.Binding
			require.NotNil(t, want.Claim)
			assert.Equal(t, *want.Claim, report.Claim)
			assert.Equal(t, want.BindingDigest, report.BindingDigest)
			assert.Equal(t, want.Properties, report.Properties)
			assert.Equal(t, want.BindsPair, report.BindsPair(keys[0], keys[1]))
			assert.Equal(t, want.Applies, report.AppliesTo(keys[0], keys[1]))
			assert.Equal(t, want.Proves, report.Proves)
			assert.Equal(t, c.Expected.IssuerIndependence, cb.PairIndependence(keys[0], keys[1], report))

			var failed []string
			for p, s := range report.Properties {
				if s == er.StatusFail {
					failed = append(failed, p)
				}
			}
			assert.ElementsMatch(t, c.Expected.Fails, failed)
		})
	}
}

// With no credential verifier passed, a delivered credential is NOT_CHECKED,
// never PASS: the package trusts no issuer of its own.
func TestNoCredentialVerifierIsNotChecked(t *testing.T) {
	data := readCorpus(t)
	for _, c := range data.Cases {
		if c.Inputs.Credential == nil {
			continue
		}
		var times []time.Time
		for _, h := range c.Inputs.Halves {
			var parsed half
			require.NoError(t, json.Unmarshal([]byte(h.OctetsText), &parsed))
			at, _ := time.Parse(time.RFC3339, parsed.IssuedAt)
			times = append(times, at)
		}
		report := cb.Verify([]byte(c.Inputs.Binding.OctetsText), times,
			cb.Options{Credential: []byte(c.Inputs.Credential.OctetsText)})
		assert.Equal(t, er.StatusNotChecked, report.Properties[cb.PropertyCredential], c.ID)
		assert.Equal(t, c.Expected.Binding.Applies, report.Applies(), c.ID)
	}
}
