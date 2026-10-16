// SPDX-License-Identifier: BSD-3-Clause
package witness

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
)

// VerifyRekorEntry checks one Rekor log entry (a decoded JSON object, numbers
// as json.Number) against the checkpoint it claims to log, offline:
//
//  1. its logID is the SHA-256 of rekorKey's DER SubjectPublicKeyInfo;
//  2. integratedTime and logIndex are JSON integers, body is a string, and
//     verification.signedEntryTimestamp (strict base64 DER ECDSA P-256
//     SHA-256) verifies under rekorKey over {"body","integratedTime","logID",
//     "logIndex"} as JSON with sorted keys and no whitespace;
//  3. body (strict base64 JSON) is a dsse entry whose spec.payloadHash has
//     algorithm "sha256" and value the SHA-256 of checkpointCOSE in hex;
//  4. the verifier keys of spec.signatures (strict base64 PEM, compared
//     without \r and surrounding whitespace) are exactly checkpointKeyID, the
//     raw Ed25519 key in hex, as a SubjectPublicKeyInfo PEM.
//
// It returns nil when all four hold.
func VerifyRekorEntry(entry interface{}, checkpointCOSE []byte, checkpointKeyID string, rekorKey crypto.PublicKey) error {
	receipt, isObject := entry.(map[string]interface{})
	if !isObject {
		return errors.New("unreadable receipt: not a JSON object")
	}
	ecKey, isECDSA := rekorKey.(*ecdsa.PublicKey)
	if !isECDSA || ecKey.Curve != elliptic.P256() {
		return errors.New("the Rekor key is not an ECDSA P-256 key")
	}
	der, err := x509.MarshalPKIXPublicKey(ecKey)
	if err != nil {
		return fmt.Errorf("unreadable Rekor key: %w", err)
	}
	logIDSum := sha256.Sum256(der)
	logID := hex.EncodeToString(logIDSum[:])
	if receipt["logID"] != logID {
		return errors.New("logID is not the pinned Rekor key")
	}
	verification := map[string]interface{}{}
	if value := receipt["verification"]; truthy(value) {
		if verification, isObject = value.(map[string]interface{}); !isObject {
			return errors.New("unreadable receipt: verification is not an object")
		}
	}
	setValue := verification["signedEntryTimestamp"]
	if !truthy(setValue) {
		return errors.New("no signedEntryTimestamp")
	}
	integrated, integratedOK := jsonInteger(receipt["integratedTime"])
	index, indexOK := jsonInteger(receipt["logIndex"])
	if !integratedOK || !indexOK {
		return errors.New("integratedTime and logIndex must be JSON integers")
	}
	body, isString := receipt["body"].(string)
	if !isString {
		return errors.New("body must be a string")
	}
	signed := `{"body":` + pyJSONString(body, false) + `,"integratedTime":` + integrated.String() +
		`,"logID":` + pyJSONString(logID, false) + `,"logIndex":` + index.String() + `}`
	setText, isString := setValue.(string)
	if !isString {
		return errors.New("unreadable receipt: signedEntryTimestamp is not a string")
	}
	set, err := decodeStdBase64(setText)
	if err != nil {
		return fmt.Errorf("unreadable receipt: %w", err)
	}
	digest := sha256.Sum256([]byte(signed))
	if !ecdsa.VerifyASN1(ecKey, digest[:], set) {
		return errors.New("signedEntryTimestamp does not verify under the pinned Rekor key")
	}
	bodyBytes, err := decodeStdBase64(body)
	if err != nil {
		return fmt.Errorf("unreadable receipt: %w", err)
	}
	decoded, err := decodeJSON(bodyBytes)
	if err != nil {
		return fmt.Errorf("unreadable receipt: %w", err)
	}
	logged, isObject := decoded.(map[string]interface{})
	if !isObject {
		return errors.New("unreadable receipt: body is not a JSON object")
	}
	if logged["kind"] != "dsse" {
		return fmt.Errorf("entry kind %v, expected 'dsse'", logged["kind"])
	}
	spec, err := objectOrEmpty(logged["spec"])
	if err != nil {
		return err
	}
	payloadHash, err := objectOrEmpty(spec["payloadHash"])
	if err != nil {
		return err
	}
	coseSum := sha256.Sum256(checkpointCOSE)
	if payloadHash["algorithm"] != "sha256" || payloadHash["value"] != hex.EncodeToString(coseSum[:]) {
		return errors.New("entry payloadHash is not this checkpoint's bytes")
	}
	expected, err := ed25519PEM(checkpointKeyID)
	if err != nil {
		return fmt.Errorf("unreadable checkpoint key: %w", err)
	}
	var signatures []interface{}
	if value := spec["signatures"]; truthy(value) {
		if signatures, isObject = value.([]interface{}); !isObject {
			return errors.New("unreadable receipt: signatures is not a list")
		}
	}
	matched := len(signatures) != 0
	for _, raw := range signatures {
		signature, isObject := raw.(map[string]interface{})
		if !isObject {
			return errors.New("unreadable receipt: a signature is not an object")
		}
		verifierValue, present := signature["verifier"]
		if !present {
			verifierValue = ""
		}
		text, isString := verifierValue.(string)
		if !isString {
			return errors.New("unreadable receipt: verifier is not a string")
		}
		verifier, err := decodeStdBase64(text)
		if err != nil {
			return fmt.Errorf("unreadable receipt: %w", err)
		}
		if !bytes.Equal(trimASCIISpace(bytes.ReplaceAll(verifier, []byte("\r"), nil)), expected) {
			matched = false
		}
	}
	if !matched {
		return errors.New("entry is not signed by the checkpoint's key")
	}
	return nil
}

// truthy is Python truthiness for a decoded JSON value.
func truthy(value interface{}) bool {
	switch value := value.(type) {
	case nil:
		return false
	case bool:
		return value
	case string:
		return value != ""
	case []interface{}:
		return len(value) != 0
	case map[string]interface{}:
		return len(value) != 0
	case json.Number:
		parsed, ok := new(big.Rat).SetString(value.String())
		return !ok || parsed.Sign() != 0
	}
	return true
}

// objectOrEmpty reads Python's `value or {}` followed by a .get: a falsy
// value is the empty object, and any other non-object is unreadable.
func objectOrEmpty(value interface{}) (map[string]interface{}, error) {
	if !truthy(value) {
		return map[string]interface{}{}, nil
	}
	object, isObject := value.(map[string]interface{})
	if !isObject {
		return nil, errors.New("unreadable receipt: expected a JSON object")
	}
	return object, nil
}

// jsonInteger reads a JSON integer (not a float, string or boolean) exactly.
func jsonInteger(value interface{}) (*big.Int, bool) {
	number, isNumber := value.(json.Number)
	if !isNumber || canonical.IsFloat(number) {
		return nil, false
	}
	return new(big.Int).SetString(number.String(), 10)
}

func ed25519PEM(keyID string) ([]byte, error) {
	raw, err := hex.DecodeString(keyID)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("key id is not a raw Ed25519 key")
	}
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(raw))
	if err != nil {
		return nil, err
	}
	return trimASCIISpace(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// trimASCIISpace is Python's bytes.strip(): only ASCII whitespace.
func trimASCIISpace(value []byte) []byte {
	return bytes.Trim(value, " \t\n\r\x0b\x0c")
}
