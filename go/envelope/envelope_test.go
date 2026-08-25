// SPDX-License-Identifier: BSD-3-Clause
package envelope_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/envelope"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestVerifyProducerEnvelope(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(sequence(0, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	payload := sequence(32, 32)
	capsuleID := hex.EncodeToString(payload)

	encoded := signEnvelope(t, privateKey, map[int64]interface{}{
		1: int64(-8),
		3: envelope.ContentType,
		4: []byte(publicKey),
	}, map[interface{}]interface{}{}, payload)

	result := envelope.Verify(capsuleID, encoded)
	require.True(t, result.OK, result.Findings)
	require.Equal(t, []byte(publicKey), result.PublicKey)

	tamperedID := hex.EncodeToString(sequence(64, 32))
	tampered := envelope.Verify(tamperedID, encoded)
	require.False(t, tampered.OK)
	require.Equal(t, "envelope_payload_mismatch", tampered.Findings[0].Code)
}

func TestVerifyProducerEnvelopeRejectsWrongProfile(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(sequence(0, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	payload := sequence(32, 32)
	capsuleID := hex.EncodeToString(payload)

	tests := []struct {
		name        string
		protected   map[int64]interface{}
		unprotected map[interface{}]interface{}
		wantCode    string
	}{
		{
			name: "wrong algorithm",
			protected: map[int64]interface{}{
				1: int64(-7), 3: envelope.ContentType, 4: []byte(publicKey),
			},
			unprotected: map[interface{}]interface{}{},
			wantCode:    "envelope_algorithm_mismatch",
		},
		{
			name: "wrong content type",
			protected: map[int64]interface{}{
				1: int64(-8), 3: "application/octet-stream", 4: []byte(publicKey),
			},
			unprotected: map[interface{}]interface{}{},
			wantCode:    "envelope_content_type_mismatch",
		},
		{
			name: "non-empty unprotected",
			protected: map[int64]interface{}{
				1: int64(-8), 3: envelope.ContentType, 4: []byte(publicKey),
			},
			unprotected: map[interface{}]interface{}{9: true},
			wantCode:    "envelope_malformed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded := signEnvelope(t, privateKey, test.protected, test.unprotected, payload)
			result := envelope.Verify(capsuleID, encoded)
			require.False(t, result.OK)
			require.Equal(t, test.wantCode, result.Findings[0].Code)
		})
	}
}

func TestVerifyProducerEnvelopeRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name      string
		capsuleID string
		encoded   []byte
		wantCode  string
	}{
		{name: "empty ID", capsuleID: "", wantCode: "capsule_id_malformed"},
		{name: "uppercase ID", capsuleID: strings.Repeat("A", 64), wantCode: "capsule_id_malformed"},
		{name: "short ID", capsuleID: strings.Repeat("0", 63), wantCode: "capsule_id_malformed"},
		{name: "empty envelope", capsuleID: strings.Repeat("0", 64), wantCode: "envelope_malformed"},
		{name: "non-CBOR envelope", capsuleID: strings.Repeat("0", 64), encoded: []byte("not-cbor"), wantCode: "envelope_malformed"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := envelope.Verify(test.capsuleID, test.encoded)
			require.False(t, result.OK)
			require.Equal(t, test.wantCode, result.Findings[0].Code)
		})
	}
}

func signEnvelope(t *testing.T, privateKey ed25519.PrivateKey, protected map[int64]interface{}, unprotected map[interface{}]interface{}, payload []byte) []byte {
	t.Helper()
	mode, err := cbor.CanonicalEncOptions().EncMode()
	require.NoError(t, err)
	protectedBytes, err := mode.Marshal(protected)
	require.NoError(t, err)
	toBeSigned, err := mode.Marshal([]interface{}{"Signature1", protectedBytes, []byte{}, payload})
	require.NoError(t, err)
	signature := ed25519.Sign(privateKey, toBeSigned)
	encoded, err := mode.Marshal(cbor.Tag{Number: 18, Content: []interface{}{protectedBytes, unprotected, payload, signature}})
	require.NoError(t, err)
	return encoded
}

func sequence(start, length int) []byte {
	value := make([]byte, length)
	for index := range value {
		value[index] = byte(start + index)
	}
	return value
}
