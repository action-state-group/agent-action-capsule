// SPDX-License-Identifier: BSD-3-Clause

package witness

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type cardCase struct {
	Name       string          `json:"name"`
	Card       string          `json:"card"`
	Holder     string          `json:"holder"`
	Anchor     string          `json:"anchor"`
	Statements []string        `json:"statements"`
	Policy     json.RawMessage `json:"policy"`
	Expected   json.RawMessage `json:"expected"`
}

type cardVectors struct {
	Policies map[string]AnchorWitnessPolicy `json:"policies"`
	Cases    []cardCase                     `json:"cases"`
}

func loadCardVectors(t *testing.T) cardVectors {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "card-registration-v0", "vectors.json"))
	require.NoError(t, err)
	var corpus cardVectors
	require.NoError(t, json.Unmarshal(data, &corpus))
	require.NotEmpty(t, corpus.Cases)
	return corpus
}

func (corpus cardVectors) inputs(t *testing.T, c cardCase) ([]byte, [][]byte, AnchorWitnessPolicy) {
	t.Helper()
	var policy AnchorWitnessPolicy
	var name string
	if json.Unmarshal(c.Policy, &name) == nil {
		var ok bool
		policy, ok = corpus.Policies[name]
		require.True(t, ok, name)
	} else {
		require.NoError(t, json.Unmarshal(c.Policy, &policy))
	}
	card, err := hex.DecodeString(c.Card)
	require.NoError(t, err)
	statements := make([][]byte, len(c.Statements))
	for i, text := range c.Statements {
		statements[i], err = hex.DecodeString(text)
		require.NoError(t, err)
	}
	return card, statements, policy
}

func (corpus cardVectors) find(t *testing.T, name string) cardCase {
	t.Helper()
	i := slices.IndexFunc(corpus.Cases, func(c cardCase) bool { return c.Name == name })
	require.GreaterOrEqual(t, i, 0, name)
	return corpus.Cases[i]
}

// TestCardRegistrationVectors runs every case of vectors/card-registration-v0
// and compares the whole report.
func TestCardRegistrationVectors(t *testing.T) {
	corpus := loadCardVectors(t)
	statuses := map[string]bool{}
	for _, c := range corpus.Cases {
		t.Run(c.Name, func(t *testing.T) {
			card, statements, policy := corpus.inputs(t, c)
			got := CheckCardRegistered(card, c.Holder, c.Anchor, statements, policy)
			assert.Equal(t, CardRegisteredMethod, got.Method)
			gotJSON, err := json.Marshal(got)
			require.NoError(t, err)
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(gotJSON, &fields))
			assert.JSONEq(t, `"card_registered"`, string(fields["property"]))
			delete(fields, "property")
			gotJSON, err = json.Marshal(fields)
			require.NoError(t, err)
			assert.JSONEq(t, string(c.Expected), string(gotJSON))
			statuses[got.Status] = true
		})
	}
	assert.Equal(t, map[string]bool{AnchorPass: true, AnchorFail: true, AnchorNotChecked: true, AnchorNotPresent: true}, statuses)
}

// A statement's status does not depend on the order statements arrive in.
func TestCardStatementStatusIndependentOfOrder(t *testing.T) {
	corpus := loadCardVectors(t)
	c := corpus.find(t, "pass-beside-fail")
	card, statements, policy := corpus.inputs(t, c)
	require.Greater(t, len(statements), 1)
	forward := CheckCardRegistered(card, c.Holder, c.Anchor, statements, policy)
	reversed := slices.Clone(statements)
	slices.Reverse(reversed)
	backward := CheckCardRegistered(card, c.Holder, c.Anchor, reversed, policy)
	assert.Equal(t, AnchorPass, backward.Status)
	require.Len(t, backward.Statements, len(forward.Statements))
	for i := range forward.Statements {
		assert.Equal(t, forward.Statements[i], backward.Statements[len(forward.Statements)-1-i])
	}
	assert.Equal(t, forward.Service, backward.Service)
	assert.Equal(t, forward.RegistrationTime, backward.RegistrationTime)
}

func TestCardRegisteredBadInputs(t *testing.T) {
	corpus := loadCardVectors(t)
	c := corpus.find(t, "pass-eddsa-time")
	card, statements, policy := corpus.inputs(t, c)
	zeros := "0000000000000000000000000000000000000000000000000000000000000000"
	require.Equal(t, AnchorPass, CheckCardRegistered(card, c.Holder, c.Anchor, statements, policy).Status)
	assert.Equal(t, AnchorFail, CheckCardRegistered(card, zeros, c.Anchor, statements, policy).Status)
	assert.Equal(t, AnchorFail, CheckCardRegistered(card, c.Holder, c.Anchor, [][]byte{nil, {}}, policy).Status)
	assert.Equal(t, AnchorFail, CheckCardRegistered([]byte("not json"), c.Holder, c.Anchor, statements, policy).Status)
	// The card is only hashed: one more octet is another card.
	assert.Equal(t, AnchorFail, CheckCardRegistered(slices.Concat(card, []byte(" ")), c.Holder, c.Anchor, statements, policy).Status)
	report := CheckCardRegistered(card, c.Holder, c.Anchor, nil, policy)
	assert.Equal(t, AnchorNotPresent, report.Status)
	assert.NotNil(t, report.Statements)
}

// A statement whose sub is not the envelope's anchor.digest fails (step 2),
// even when everything else passes.
func TestCardStatementWrongAnchorFails(t *testing.T) {
	corpus := loadCardVectors(t)
	c := corpus.find(t, "pass-eddsa-time")
	card, statements, policy := corpus.inputs(t, c)
	require.Equal(t, AnchorPass, CheckCardStatement(card, c.Holder, c.Anchor, statements[0], policy).Status)
	for _, anchor := range []string{"", strings.Repeat("0", 64), strings.ToUpper(c.Anchor)} {
		report := CheckCardRegistered(card, c.Holder, anchor, statements, policy)
		assert.Equal(t, AnchorFail, report.Status, anchor)
		assert.Nil(t, report.Service)
		assert.Nil(t, report.RegistrationTime)
	}
}
