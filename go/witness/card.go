// SPDX-License-Identifier: BSD-3-Clause

package witness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"

	"github.com/fxamacker/cbor/v2"

	"github.com/action-state-group/agent-action-capsule/go/internal/ed25519strict"
)

// CardRegisteredProperty is the check spec/standard-history-v0.md §13.3
// defines. It is not a card property and never changes an envelope property.
const CardRegisteredProperty = "card_registered"

// CardRegisteredMethod names how card_registered is checked.
const CardRegisteredMethod = "SCITT Transparent Statement over the card digest, RFC 9942 Receipts (standard-history-v0 §13)"

// labelReceipts is the SCITT receipts header label (standard-history-v0 §13.1).
const labelReceipts = 394

// CardStatementReport is one card statement's status, and when it passed,
// its service and registration time (standard-history-v0 §13.3).
type CardStatementReport struct {
	Status           string  `json:"status"`
	Service          *string `json:"service"`
	RegistrationTime *int64  `json:"registration_time"`
	Detail           string  `json:"-"`
}

// CardRegisteredReport is card_registered over every card statement beside
// one card. Service and RegistrationTime always come from the same Receipt.
type CardRegisteredReport struct {
	Property         string                `json:"property"`
	Status           string                `json:"status"`
	Method           string                `json:"-"`
	Statements       []CardStatementReport `json:"statements"`
	Service          *string               `json:"service"`
	RegistrationTime *int64                `json:"registration_time"`
}

// cardStatement is a card statement in the one form of standard-history-v0
// §13.1.
type cardStatement struct {
	protected, payload, signature []byte
	iss, sub                      string
	receipts                      [][]byte
}

// cardProtectedLabelOK reports whether one protected header entry of a card
// statement is allowed, recording iss and sub from CWT_Claims.
func cardProtectedLabelOK(label, value interface{}, out *cardStatement) bool {
	switch label {
	case uint64(labelAlg):
		alg, isInt := value.(int64)
		return isInt && alg == algEdDSA
	case uint64(labelCWTClaims):
		claims, isMap := value.(map[interface{}]interface{})
		iss, issOK := claims[uint64(1)].(string)
		sub, subOK := claims[uint64(2)].(string)
		out.iss, out.sub = iss, sub
		return isMap && issOK && subOK
	case uint64(4):
		_, isBytes := value.([]byte)
		return isBytes
	case uint64(3):
		_, isText := value.(string)
		return isText
	}
	negative, isInt := label.(int64)
	return isInt && negative < privateLabel
}

// parseCardStatement is step 1 of standard-history-v0 §13.3: the COSE_Sign1
// and its protected header decode under the receipt encoding rule of profile
// v1 §6.2.2, with the outer tag 18 the one tag allowed.
func parseCardStatement(octets []byte) (cardStatement, bool) {
	var out cardStatement
	if len(octets) == 0 || len(octets) > maxReceiptBytes {
		return out, false
	}
	decoded, ok := strictReceiptItem(octets, true)
	tag, isTag := decoded.(cbor.Tag)
	if !ok || !isTag || tag.Number != 18 {
		return out, false
	}
	parts, isArray := tag.Content.([]interface{})
	if !isArray || len(parts) != 4 {
		return out, false
	}
	protected, protectedOK := parts[0].([]byte)
	payload, payloadOK := parts[2].([]byte)
	signature, signatureOK := parts[3].([]byte)
	if !protectedOK || len(protected) == 0 || !payloadOK || len(payload) != 32 ||
		!signatureOK || len(signature) != 64 {
		return out, false
	}
	value, ok := strictReceiptItem(protected, false)
	headers, isMap := value.(map[interface{}]interface{})
	if !ok || !isMap {
		return out, false
	}
	for label, value := range headers {
		if !cardProtectedLabelOK(label, value, &out) {
			return out, false
		}
	}
	_, hasAlg := headers[uint64(labelAlg)]
	_, hasClaims := headers[uint64(labelCWTClaims)]
	if !hasAlg || !hasClaims {
		return out, false
	}
	unprotected, isMap := parts[1].(map[interface{}]interface{})
	if !isMap || len(unprotected) != 1 {
		return out, false
	}
	receipts, isArray := unprotected[uint64(labelReceipts)].([]interface{})
	if !isArray || len(receipts) == 0 || len(receipts) > maxProofs {
		return out, false
	}
	for _, item := range receipts {
		receipt, isBytes := item.([]byte)
		if !isBytes {
			return out, false
		}
		out.receipts = append(out.receipts, receipt)
	}
	out.protected, out.payload, out.signature = protected, payload, signature
	return out, true
}

// CheckCardStatement runs steps 1 to 5 of standard-history-v0 §13.3 for one
// card statement beside card (the card octets, hashed and never parsed),
// under the holder key identifier holder (the envelope's responder, 64
// lowercase hex characters), the anchor anchor (the envelope's
// anchor.digest) and the relying party's transparency policy (profile v1
// §6.2.2's witness policy form).
func CheckCardStatement(card []byte, holder, anchor string, statement []byte, policy AnchorWitnessPolicy) CardStatementReport {
	parsed, ok := parseCardStatement(statement)
	if !ok {
		return CardStatementReport{Status: AnchorFail, Detail: "not a card statement in the one form of standard-history-v0 §13.1"}
	}
	digest := sha256.Sum256(card)
	if !bytes.Equal(parsed.payload, digest[:]) {
		return CardStatementReport{Status: AnchorFail, Detail: "the statement is about another card"}
	}
	if parsed.iss != holder || parsed.sub != anchor {
		return CardStatementReport{Status: AnchorFail, Detail: "iss is not the holder key, or sub is not the anchor"}
	}
	if !anchorDigest.MatchString(holder) {
		return CardStatementReport{Status: AnchorFail, Detail: "the holder key identifier is not 64 lowercase hex characters"}
	}
	key, _ := hex.DecodeString(holder)
	message := sigStructure(parsed.protected, parsed.payload)
	if !ed25519strict.Verify(ed25519.PublicKey(key), message, parsed.signature) {
		return CardStatementReport{Status: AnchorFail, Detail: "the statement's signature does not verify under the holder key"}
	}
	entry := sha256.Sum256(message)
	reports := make([]AnchorReceiptReport, len(parsed.receipts))
	failed := false
	details := ""
	for i, receipt := range parsed.receipts {
		reports[i] = receiptOverEntry(entry[:], receipt, policy, "transparency")
		failed = failed || reports[i].Status == AnchorFail
		if i > 0 {
			details += "; "
		}
		details += reports[i].Detail
	}
	if chosen := earliest(reports, func(r *AnchorReceiptReport) (bool, *int64) {
		return r.Status == AnchorPass, r.RegistrationTime
	}); chosen != nil {
		return CardStatementReport{Status: AnchorPass, Service: chosen.Witness, RegistrationTime: chosen.RegistrationTime}
	}
	if failed {
		return CardStatementReport{Status: AnchorFail, Detail: "no Receipt by an accepted service covers the statement"}
	}
	return CardStatementReport{Status: AnchorNotChecked, Detail: details}
}

// CheckCardRegistered reports card_registered over statements (each the
// octets of a card statement, in the order received) beside card, under the
// holder key identifier holder, the anchor anchor (the envelope's
// anchor.digest) and the relying party's transparency policy
// (standard-history-v0 §13.3). The card's service and registration time come
// from one passing statement, chosen as profile v1 §6.2.2 chooses over
// Receipts.
func CheckCardRegistered(card []byte, holder, anchor string, statements [][]byte, policy AnchorWitnessPolicy) CardRegisteredReport {
	report := CardRegisteredReport{
		Property:   CardRegisteredProperty,
		Status:     AnchorNotPresent,
		Method:     CardRegisteredMethod,
		Statements: []CardStatementReport{},
	}
	var passed, failed bool
	for _, statement := range statements {
		r := CheckCardStatement(card, holder, anchor, statement, policy)
		passed = passed || r.Status == AnchorPass
		failed = failed || r.Status == AnchorFail
		report.Statements = append(report.Statements, r)
	}
	switch {
	case len(statements) == 0:
	case passed:
		report.Status = AnchorPass
	case failed:
		report.Status = AnchorFail
	default:
		report.Status = AnchorNotChecked
	}
	if chosen := earliest(report.Statements, func(r *CardStatementReport) (bool, *int64) {
		return r.Status == AnchorPass, r.RegistrationTime
	}); chosen != nil {
		report.Service, report.RegistrationTime = chosen.Service, chosen.RegistrationTime
	}
	return report
}
