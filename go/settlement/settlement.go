// SPDX-License-Identifier: BSD-3-Clause
// Package settlement derives settlement states from two parties' leg records
// (verification only). It is the Go port of the Python reference
// agent_action_capsule.settlement, the verifier of "Two-Party Settlement
// Records for Agent Payments" (draft-mih-agent-settlement-records-00).
//
// The payer and the payee are two independent sealers; each seals only what
// its own system observed, as a Capsule with a top-level settlement member.
// Verify checks each leg record on its own (the Capsule checks, its Producer
// Envelope, the settlement structure and amounts, its wrapped entries and,
// with a key policy, that its key may seal its role), then groups the legs by
// terms_ref and derives the draft's payment and delivery states. A pair whose
// two observed legs share a key is never agreed. Building and sealing legs is
// a producer's job and is not here.
package settlement

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/envelope"
	"github.com/action-state-group/agent-action-capsule/go/internal/ed25519strict"
	"github.com/action-state-group/agent-action-capsule/go/verify"
)

// Member is the Capsule member that carries a leg; Version is its version
// for draft-mih-agent-settlement-records-00.
const (
	Member  = "settlement"
	Version = "0"
)

// Legs, sealer roles and observed statuses of -00.
var (
	Legs     = []string{"terms", "payer_observed", "payee_observed", "delivered"}
	Roles    = []string{"payer", "payee"}
	Statuses = []string{"pending", "settled", "failed", "reversed"}
	// DeliveryDirections maps delivery.direction to the role that seals it.
	DeliveryDirections = map[string]string{"sent": "payee", "received": "payer"}
)

// PaymentRefType is one registered payment reference type: its qualifier
// members, and whether a receive fee may apply ("may_apply" or
// "not_applicable"; x402.transaction is not applicable for the x402 exact
// scheme only).
type PaymentRefType struct {
	Qualifiers []string
	ReceiveFee string
}

// PaymentRefTypes are the initial payment reference types.
var PaymentRefTypes = map[string]PaymentRefType{
	"x402.transaction":               {[]string{"network"}, "not_applicable"},
	"ln.payment_hash":                {nil, "may_apply"},
	"bolt12.invoice_payment_hash":    {nil, "may_apply"},
	"ap2.transaction_id":             {nil, "may_apply"},
	"ap2.payment_id":                 {nil, "may_apply"},
	"ap2.network_confirmation_id":    {nil, "may_apply"},
	"acp.order_id":                   {nil, "may_apply"},
	"ucp.order_id":                   {nil, "may_apply"},
	"mpp.reference":                  {[]string{"method"}, "may_apply"},
	"iso20022.uetr":                  {nil, "may_apply"},
	"iso20022.end_to_end_id":         {[]string{"debtor_agent"}, "may_apply"},
	"open_payments.incoming_payment": {nil, "may_apply"},
}

// WrappedTypes are the initial wrapped object types and their issuer under
// their own specification.
var WrappedTypes = map[string]string{
	"x402.offer":           "payee",
	"x402.receipt":         "payee",
	"x402.payment-payload": "payer",
	"x402.settle-response": "other",
	"ap2.checkout-mandate": "payer",
	"ap2.payment-mandate":  "payer",
	"ap2.checkout-receipt": "other",
	"ap2.payment-receipt":  "other",
	"bolt12.invoice":       "payee",
	"bolt12.payer-proof":   "payer",
	"mpp.payment-receipt":  "payee",
	"iso20022.message":     "other",
	"delivery.proof":       "other",
}

// Members are the required and optional settlement members of each leg.
// Anything else is settlement_malformed.
var Members = map[string]struct{ Required, Optional []string }{
	"terms": {[]string{"version", "leg", "sealer_role", "amount"},
		[]string{"payment_ref", "deliverable", "valid_until", "wrapped"}},
	"payer_observed": {[]string{"version", "leg", "sealer_role", "terms_ref", "amount", "payment_ref", "status", "observed_at"},
		[]string{"routing_fee", "wrapped"}},
	"payee_observed": {[]string{"version", "leg", "sealer_role", "terms_ref", "received", "payment_ref", "status", "observed_at"},
		[]string{"receive_fee", "wrapped"}},
	"delivered": {[]string{"version", "leg", "sealer_role", "terms_ref", "observed_at", "delivery"},
		[]string{"wrapped"}},
}

// ISO20022Status is the ISO 20022 code a reviewer reads for each observed
// leg and status (pacs.002 TxSts; a reversal is a pacs.004 return).
var ISO20022Status = map[[2]string]string{
	{"payer_observed", "pending"}:  "PDNG",
	{"payer_observed", "settled"}:  "ACSC",
	{"payer_observed", "failed"}:   "RJCT",
	{"payer_observed", "reversed"}: "pacs.004",
	{"payee_observed", "pending"}:  "PDNG",
	{"payee_observed", "settled"}:  "ACCC",
	{"payee_observed", "failed"}:   "RJCT",
	{"payee_observed", "reversed"}: "pacs.004",
}

var (
	amountMembers   = []string{"amount", "routing_fee", "received", "receive_fee"}
	deliveryMembers = []string{"direction", "content_digest", "carrier", "tracking_digest", "status", "shipped_at", "delivered_at", "address_digest"}
	// deliveryStatuses are delivery.status for physical goods (the draft's
	// "Delivered" section).
	deliveryStatuses = []string{"pending", "in_transit", "delivered", "failed", "returned"}
	// Every pattern matches the whole string, with ASCII digits only.
	valuePattern   = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	hex64Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	b64urlPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
	rfc3339Pattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$`)
)

// Input is what Verify reads.
type Input struct {
	// Capsules are the leg records, decoded with json.Number numbers, each
	// carrying its Producer Envelope as signature (hex) and key_id.
	Capsules []interface{}
	// WrappedObjects are wrapped objects' octets the caller holds, keyed by
	// their SHA-256 in lowercase hex. They are used for the re-signing check
	// and to read the x402 scheme.
	WrappedObjects map[string][]byte
	// KeyPolicy maps a sealer role (payer, payee) to the hex Ed25519 keys
	// accepted for it. Nil applies no key policy.
	KeyPolicy map[string][]string
}

// Entry is one failure or finding. A record is its capsule_id, or nil when
// the leg's capsule_id is not a string.
type Entry struct {
	Records []*string `json:"records"`
	Code    string    `json:"code"`
}

// Settlement is the derived state of the legs that answer one terms leg.
// PaymentState is nil for a conflated pair that otherwise matches (no state
// of the draft applies; sealer_conflation is listed as a failure).
// AgreedStatus and TermsAmount (equal or differs) are set with agreed only;
// Differs (amount, status, payment_ref) with mismatch only; ISO20022 maps an
// observed leg whose side states one status to its ISO 20022 code.
type Settlement struct {
	Terms         string            `json:"terms"`
	PaymentState  *string           `json:"payment_state"`
	AgreedStatus  string            `json:"agreed_status,omitempty"`
	TermsAmount   string            `json:"terms_amount,omitempty"`
	Differs       []string          `json:"differs,omitempty"`
	ISO20022      map[string]string `json:"iso20022,omitempty"`
	DeliveryState string            `json:"delivery_state"`
}

// Diagnostic is what the draft does not make a state or a failure:
// several_keys_for_role, supersedes_ignored, sealer_conflation and
// delivery_sealed_under_one_key, with the members the Python reference
// reports for each.
type Diagnostic map[string]interface{}

// Result is what Verify derived, in the draft's terms. Keys maps each
// authenticated record ("<capsule_id>:<key>") to its key. KeyPolicyApplied
// says whether a key policy bound each leg's key to its party: without one,
// agreed means two distinct keys agree, not that the keys belong to the payer
// and the payee.
type Result struct {
	Conforming       bool              `json:"conforming"`
	Failures         []Entry           `json:"failures"`
	Findings         []Entry           `json:"findings"`
	Settlements      []Settlement      `json:"settlements"`
	Keys             map[string]string `json:"keys"`
	KeyPolicyApplied bool              `json:"key_policy_applied"`
	Diagnostics      []Diagnostic      `json:"diagnostics"`
}

// leg is one accepted record: its record id, Capsule, capsule_id (nil when
// not a string), authenticated key ("" when none) and settlement member.
type leg struct {
	rid     string
	capsule map[string]interface{}
	cid     *string
	kid     string
	s       map[string]interface{}
}

func (l leg) name() string { text, _ := l.s["leg"].(string); return text }

// Verify derives settlement states from both parties' leg records, offline.
// A record that fails a check is reported and takes no part in any state.
// A record is identified by its capsule_id and its authenticated key: the
// same content signed by another key is a different record, and never stands
// in for, or excludes, the original.
func Verify(in Input) Result {
	objects := in.WrappedObjects
	if objects == nil {
		objects = map[string][]byte{}
	}
	var policy map[string]map[string]bool
	if in.KeyPolicy != nil {
		policy = map[string]map[string]bool{}
		for role, keys := range in.KeyPolicy {
			policy[role] = map[string]bool{}
			for _, key := range keys {
				policy[role][key] = true
			}
		}
	}
	report := Result{Conforming: true, Failures: []Entry{}, Findings: []Entry{}, Settlements: []Settlement{},
		Keys: map[string]string{}, KeyPolicyApplied: policy != nil, Diagnostics: []Diagnostic{}}
	var legs []leg
	seen := map[string]bool{}
	excluded := map[string]bool{}
	for n, item := range in.Capsules {
		capsule, isObject := item.(map[string]interface{})
		if !isObject {
			report.Failures = append(report.Failures, Entry{Records: []*string{nil}, Code: "capsule_invalid"})
			continue
		}
		var cid *string
		if text, isString := capsule["capsule_id"].(string); isString {
			cid = &text
		}
		// A leg nested deeper than any JSON text decodes to (only a value
		// built in Go can be) is refused before the recursive Capsule checks
		// can exhaust the stack; it takes no part in any state.
		if canonical.TooDeep(capsule) {
			report.Failures = append(report.Failures, Entry{Records: []*string{cid}, Code: "capsule_invalid"})
			continue
		}
		var own []string
		kid := ""
		if cid == nil || !verify.Verify(capsule, nil, nil).OK {
			own = append(own, "capsule_invalid")
		} else if kid = envelopeKey(capsule, *cid); kid == "" {
			own = append(own, "envelope_invalid")
		}
		rid := idText(cid) + ":#" + itoa(n)
		if kid != "" {
			rid = idText(cid) + ":" + kid
			if seen[rid] {
				continue // the same capsule under the same key, passed again
			}
		}
		s, sIsObject := capsule[Member].(map[string]interface{})
		structural := StructureFailures(capsule[Member])
		own = append(own, structural...)
		if len(structural) == 0 {
			own = append(own, wrappedFailures(s, kid, objects)...)
			if policy != nil && kid != "" && !policy[s["sealer_role"].(string)][kid] {
				own = append(own, "sealer_not_authorized_for_role")
			}
			if ref, isRef := s["payment_ref"].(map[string]interface{}); isRef {
				if _, known := PaymentRefTypes[ref["type"].(string)]; !known {
					report.Findings = append(report.Findings, Entry{Records: []*string{cid}, Code: "payment_ref_type_unknown"})
				}
			}
		}
		if kid == "" && repeated(report.Failures, cid, own) {
			continue // the same unauthenticated record again: report it once
		}
		for _, code := range own {
			report.Failures = append(report.Failures, Entry{Records: []*string{cid}, Code: code})
		}
		if len(own) != 0 {
			excluded[rid] = true
		}
		if !sIsObject {
			s = map[string]interface{}{}
		}
		seen[rid] = true
		legs = append(legs, leg{rid: rid, capsule: capsule, cid: cid, kid: kid, s: s})
		if kid != "" {
			report.Keys[rid] = kid
		}
	}

	// Distinct keys: a payer-observed and a payee-observed leg for one terms
	// leg under the same key are not two sides. Needs no key policy.
	var observed []leg
	for _, l := range legs {
		if l.kid != "" && strings.HasSuffix(l.name(), "_observed") {
			observed = append(observed, l)
		}
	}
	for _, p := range observed {
		for _, q := range observed {
			if p.name() == "payer_observed" && q.name() == "payee_observed" && p.kid == q.kid && jsonEqual(p.s["terms_ref"], q.s["terms_ref"]) {
				report.Failures = append(report.Failures, Entry{Records: []*string{p.cid, q.cid}, Code: "sealer_conflation"})
			}
		}
	}

	var live []leg
	for _, l := range legs {
		if !excluded[l.rid] {
			live = append(live, l)
		}
	}
	termsByCID := map[string]leg{}
	var termsOrder []string
	for _, l := range live {
		if l.name() == "terms" {
			if _, found := termsByCID[*l.cid]; !found {
				// A re-signed copy of a terms leg is the same terms.
				termsByCID[*l.cid] = l
				termsOrder = append(termsOrder, *l.cid)
			}
		}
	}
	for _, l := range live {
		if l.name() != "terms" {
			if _, found := termsByCID[l.s["terms_ref"].(string)]; !found {
				report.Failures = append(report.Failures, Entry{Records: []*string{l.cid}, Code: "terms_ref_unresolved"})
			}
		}
	}
	for _, termsCID := range termsOrder {
		var answering []leg
		for _, l := range live {
			if l.s["terms_ref"] == termsCID {
				answering = append(answering, l)
			}
		}
		report.Settlements = append(report.Settlements, settle(termsCID, termsByCID[termsCID], answering, &report, policy != nil, objects))
	}
	report.Conforming = len(report.Failures) == 0
	return report
}

func idText(cid *string) string {
	if cid == nil {
		return "None"
	}
	return *cid
}

func itoa(n int) string { data, _ := json.Marshal(n); return string(data) }

// repeated reports whether an earlier failure names exactly this record with
// one of its codes.
func repeated(failures []Entry, cid *string, own []string) bool {
	for _, failure := range failures {
		if len(failure.Records) != 1 || !sameID(failure.Records[0], cid) {
			continue
		}
		for _, code := range own {
			if failure.Code == code {
				return true
			}
		}
	}
	return false
}

func sameID(a, b *string) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

// envelopeKey is the hex key the capsule's Producer Envelope authenticates,
// or "".
func envelopeKey(capsule map[string]interface{}, cid string) string {
	// Hex digit pairs only: hex.DecodeString takes no whitespace, and the
	// empty string is no envelope.
	signature, isString := capsule["signature"].(string)
	if !isString || signature == "" {
		return ""
	}
	data, err := hex.DecodeString(signature)
	if err != nil {
		return ""
	}
	result := envelope.Verify(cid, data)
	if !result.OK {
		return ""
	}
	return hex.EncodeToString(result.PublicKey)
}

// AmountOK reports whether a is an exact amount: exactly value (a string of
// ASCII digits without leading zeros), a non-empty assetCode, and an integer
// assetScale from 0 to 255.
func AmountOK(a interface{}) bool {
	amount, isObject := a.(map[string]interface{})
	if !isObject || len(amount) != 3 {
		return false
	}
	value, valueOK := amount["value"].(string)
	code, codeOK := amount["assetCode"].(string)
	scale, scaleOK := integer(amount["assetScale"])
	return valueOK && valuePattern.MatchString(value) && codeOK && code != "" && scaleOK && scale >= 0 && scale <= 255
}

// StructureFailures returns the draft's structural failure codes for one
// settlement member, in first-found order; empty when there are none.
func StructureFailures(member interface{}) []string {
	s, isObject := member.(map[string]interface{})
	if !isObject || s["version"] != Version || !contains(Legs, s["leg"]) || !contains(Roles, s["sealer_role"]) {
		return []string{"settlement_malformed"}
	}
	var out []string
	add := func(code string) {
		for _, existing := range out {
			if existing == code {
				return
			}
		}
		out = append(out, code)
	}
	name, role := s["leg"].(string), s["sealer_role"].(string)
	allowed := Members[name]
	for _, required := range allowed.Required {
		if _, present := s[required]; !present {
			add("settlement_malformed")
		}
	}
	for key := range s {
		if !containsString(allowed.Required, key) && !containsString(allowed.Optional, key) {
			add("settlement_malformed")
		}
	}
	if (name == "payer_observed" && role != "payer") || (name == "payee_observed" && role != "payee") {
		add("leg_role_mismatch")
	}
	for _, member := range amountMembers {
		if value, present := s[member]; present && !AmountOK(value) {
			add("amount_not_exact")
			break
		}
	}
	if strings.HasSuffix(name, "_observed") && !contains(Statuses, s["status"]) {
		add("settlement_malformed")
	}
	if value, present := s["terms_ref"]; present && !matches(hex64Pattern, value) {
		add("settlement_malformed")
	}
	if value, present := s["observed_at"]; present && !utcTimeOK(value) {
		add("settlement_malformed")
	}
	if name == "delivered" && !deliveryOK(s["delivery"], role) {
		add("settlement_malformed")
	}
	if value, present := s["valid_until"]; present && !utcTimeOK(value) {
		add("settlement_malformed")
	}
	if value, present := s["deliverable"]; name == "terms" && present && !deliverableOK(value) {
		add("settlement_malformed")
	}
	if value, present := s["payment_ref"]; present && !paymentRefOK(value) {
		add("settlement_malformed")
	}
	if !wrappedOK(s) {
		add("settlement_malformed")
	}
	return out
}

func deliveryOK(raw interface{}, role string) bool {
	d, isObject := raw.(map[string]interface{})
	if !isObject {
		return false
	}
	direction, isString := d["direction"].(string)
	if !isString || DeliveryDirections[direction] != role {
		return false
	}
	for key := range d {
		if !containsString(deliveryMembers, key) {
			return false
		}
	}
	_, hasDigest := d["content_digest"]
	carrier, hasCarrier := d["carrier"]
	if !hasDigest && !hasCarrier {
		return false
	}
	// Each optional member present must have the draft's type.
	for _, name := range []string{"content_digest", "tracking_digest", "address_digest"} {
		if value, present := d[name]; present && !matches(hex64Pattern, value) {
			return false
		}
	}
	if _, isString := carrier.(string); hasCarrier && !isString {
		return false
	}
	if status, present := d["status"]; present && !contains(deliveryStatuses, status) {
		return false
	}
	for _, name := range []string{"shipped_at", "delivered_at"} {
		if value, present := d[name]; present && !utcTimeOK(value) {
			return false
		}
	}
	return true
}

func deliverableOK(raw interface{}) bool {
	d, isObject := raw.(map[string]interface{})
	if !isObject || len(d) == 0 {
		return false
	}
	for key, value := range d {
		if (key != "content_digest" && key != "description_digest") || !matches(hex64Pattern, value) {
			return false
		}
	}
	return true
}

func paymentRefOK(raw interface{}) bool {
	ref, isObject := raw.(map[string]interface{})
	if !isObject {
		return false
	}
	kind, kindOK := ref["type"].(string)
	_, valueOK := ref["value"].(string)
	if !kindOK || !valueOK {
		return false
	}
	registered, known := PaymentRefTypes[kind]
	if !known {
		return true
	}
	want := append([]string{"type", "value"}, registered.Qualifiers...)
	if len(ref) != len(want) {
		return false
	}
	for _, key := range want {
		// type and value are strings already; a registered type's qualifiers
		// must be strings too.
		if _, isString := ref[key].(string); !isString {
			return false
		}
	}
	return true
}

func wrappedOK(s map[string]interface{}) bool {
	raw, present := s["wrapped"]
	if !present {
		return true
	}
	entries, isList := raw.([]interface{})
	if !isList {
		return false
	}
	for _, entry := range entries {
		w, isObject := entry.(map[string]interface{})
		if !isObject || w["digest_alg"] != "SHA-256" {
			return false
		}
		kind, isString := w["type"].(string)
		if _, known := WrappedTypes[kind]; !isString || !known || !matches(hex64Pattern, w["digest"]) {
			return false
		}
		if content, present := w["content"]; present {
			if _, isString := content.(string); !isString {
				return false
			}
		}
		for key := range w {
			if key != "type" && key != "digest_alg" && key != "digest" && key != "content" {
				return false
			}
		}
	}
	return true
}

// wrappedEntries is a structurally valid leg's wrapped list.
func wrappedEntries(s map[string]interface{}) []map[string]interface{} {
	raw, _ := s["wrapped"].([]interface{})
	out := make([]map[string]interface{}, 0, len(raw))
	for _, entry := range raw {
		if w, isObject := entry.(map[string]interface{}); isObject {
			out = append(out, w)
		}
	}
	return out
}

func wrappedFailures(s map[string]interface{}, kid string, objects map[string][]byte) []string {
	var out []string
	role, _ := s["sealer_role"].(string)
	for _, w := range wrappedEntries(s) {
		digest, _ := w["digest"].(string)
		octets, held := objects[digest]
		if content, present := w["content"]; present {
			decoded, err := b64urlDecode(content)
			if err != nil {
				// Content that does not decode matches no digest, the empty one included.
				out = append(out, "wrapped_digest_mismatch")
				continue
			}
			sum := sha256.Sum256(decoded)
			if hex.EncodeToString(sum[:]) != digest {
				out = append(out, "wrapped_digest_mismatch")
				continue
			}
			octets, held = decoded, true
		}
		if held && kid != "" && WrappedTypes[w["type"].(string)] != role && jwsVerifies(octets, kid) {
			out = append(out, "wrapped_resigned")
		}
	}
	return out
}

// b64urlDecode reads canonical unpadded base64url; anything else is an error.
func b64urlDecode(value interface{}) ([]byte, error) {
	text, isString := value.(string)
	if !isString || !b64urlPattern.MatchString(text) {
		return nil, errNotBase64URL
	}
	return base64.RawURLEncoding.Strict().DecodeString(text)
}

var errNotBase64URL = errors.New("not unpadded base64url")

// jwsVerifies reports whether octets are a compact JWS whose Ed25519
// signature verifies, strictly, under the hex key. An SD-JWT is the issuer-signed JWS,
// then "~" and any disclosures: only the part before the first "~" is signed.
func jwsVerifies(octets []byte, publicHex string) bool {
	issuer, _, _ := bytes.Cut(octets, []byte("~"))
	parts := bytes.Split(issuer, []byte("."))
	if len(parts) != 3 {
		return false
	}
	key, err := hex.DecodeString(publicHex)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return false
	}
	signature, err := b64urlDecode(string(parts[2]))
	if err != nil {
		return false
	}
	signed := append(append(append([]byte(nil), parts[0]...), '.'), parts[1]...)
	return ed25519strict.Verify(ed25519.PublicKey(key), signed, signature)
}

// x402Scheme is the x402 scheme, from the first wrapped offer or payment
// payload whose octets are held and readable.
func x402Scheme(legs []map[string]interface{}, objects map[string][]byte) interface{} {
	for _, s := range legs {
		for _, w := range wrappedEntries(s) {
			digest, _ := w["digest"].(string)
			octets, held := objects[digest]
			if content, present := w["content"]; present {
				decoded, err := b64urlDecode(content)
				if err != nil {
					continue
				}
				octets, held = decoded, true
			}
			sum := sha256.Sum256(octets)
			if !held || hex.EncodeToString(sum[:]) != digest {
				continue
			}
			switch w["type"] {
			case "x402.offer":
				if bytes.Count(octets, []byte(".")) == 2 && !bytes.HasPrefix(bytes.TrimLeft(octets, " \t\n\r\x0b\x0c"), []byte("{")) {
					payload, err := b64urlDecode(string(bytes.Split(octets, []byte("."))[1]))
					if err != nil {
						continue
					}
					header, isObject := decodeJSON(payload).(map[string]interface{})
					if !isObject {
						continue
					}
					return header["scheme"]
				}
				offer, isObject := decodeJSON(octets).(map[string]interface{})
				if !isObject {
					continue
				}
				payload, present := offer["payload"]
				if !present {
					payload = map[string]interface{}{}
				}
				if payload, isObject := payload.(map[string]interface{}); isObject {
					return payload["scheme"]
				}
				return nil
			case "x402.payment-payload":
				document, isObject := decodeJSON(octets).(map[string]interface{})
				if !isObject {
					continue
				}
				accepted, present := document["accepted"]
				if !present {
					accepted = map[string]interface{}{}
				}
				if accepted, isObject := accepted.(map[string]interface{}); isObject {
					return accepted["scheme"]
				}
				return nil
			}
		}
	}
	return nil
}

// decodeJSON reads one JSON value, or returns nil when it is not JSON.
func decodeJSON(data []byte) interface{} {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value interface{}
	if decoder.Decode(&value) != nil {
		return nil
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil
	}
	return value
}

func receiveFeeNotApplicable(refType string, terms, payer map[string]interface{}, objects map[string][]byte) bool {
	if PaymentRefTypes[refType].ReceiveFee != "not_applicable" {
		return false
	}
	return refType != "x402.transaction" || x402Scheme([]map[string]interface{}{terms, payer}, objects) == "exact"
}

// scaled is an exact amount's value at a larger scale.
// big.Int has no size limit, so an amount of any length is compared exactly;
// AmountOK has already required value to be decimal digits.
func scaled(a map[string]interface{}, scale int64) *big.Int {
	value, _ := new(big.Int).SetString(a["value"].(string), 10)
	own, _ := integer(a["assetScale"])
	factor := new(big.Int).Exp(big.NewInt(10), big.NewInt(scale-own), nil)
	return value.Mul(value, factor)
}

func scaleOf(a map[string]interface{}) int64 {
	scale, _ := integer(a["assetScale"])
	return scale
}

func amountsEqual(a, b map[string]interface{}) bool {
	if a["assetCode"] != b["assetCode"] {
		return false
	}
	scale := max(scaleOf(a), scaleOf(b))
	return scaled(a, scale).Cmp(scaled(b, scale)) == 0
}

// amountRuleHolds is payer.amount == payee.received + receive_fee, exactly,
// in one asset. Never direct equality.
func amountRuleHolds(payer, payee, receiveFee map[string]interface{}) bool {
	amount, received := object(payer["amount"]), object(payee["received"])
	if amount["assetCode"] != received["assetCode"] || received["assetCode"] != receiveFee["assetCode"] {
		return false
	}
	scale := max(scaleOf(amount), scaleOf(received), scaleOf(receiveFee))
	sum := new(big.Int).Add(scaled(received, scale), scaled(receiveFee, scale))
	return scaled(amount, scale).Cmp(sum) == 0
}

func object(value interface{}) map[string]interface{} {
	out, _ := value.(map[string]interface{})
	return out
}

// normalPaymentRef lowercases an EVM x402 transaction hash, which is
// case-insensitive.
func normalPaymentRef(raw interface{}) map[string]interface{} {
	ref := object(raw)
	out := make(map[string]interface{}, len(ref))
	for key, value := range ref {
		out[key] = value
	}
	if network, _ := ref["network"].(string); ref["type"] == "x402.transaction" && strings.HasPrefix(network, "eip155:") {
		value, _ := ref["value"].(string)
		out["value"] = strings.ToLower(value)
	}
	return out
}

// heads drops observed legs that a later leg of the same side supersedes. A
// supersedes link counts only when the superseding record is signed by the
// superseded record's own key; any other link is ignored and reported.
func heads(side []leg, report *Result, termsCID string) []leg {
	superseded := map[string]bool{}
	for _, l := range side {
		chain := object(l.capsule["chain"])
		if chain["relation"] != "supersedes" {
			continue
		}
		parent := chain["parent_capsule_id"]
		var targets, own int
		for _, t := range side {
			if t.rid != l.rid && t.cid != nil && jsonEqual(*t.cid, parent) {
				targets++
				if t.kid == l.kid {
					own++
					superseded[t.rid] = true
				}
			}
		}
		if targets != 0 && own == 0 {
			report.Diagnostics = append(report.Diagnostics, Diagnostic{"terms": termsCID, "code": "supersedes_ignored",
				"record": l.capsule["capsule_id"], "key": l.kid, "parent": parent})
		}
	}
	out := make([]leg, 0, len(side))
	for _, l := range side {
		if !superseded[l.rid] {
			out = append(out, l)
		}
	}
	return out
}

func settle(termsCID string, terms leg, answering []leg, report *Result, withPolicy bool, objects map[string][]byte) Settlement {
	var payerSide, payeeSide []leg
	for _, l := range answering {
		switch l.name() {
		case "payer_observed":
			payerSide = append(payerSide, l)
		case "payee_observed":
			payeeSide = append(payeeSide, l)
		}
	}
	payer := heads(payerSide, report, termsCID)
	payee := heads(payeeSide, report, termsCID)
	result := Settlement{Terms: termsCID}
	for _, side := range []struct {
		role string
		legs []leg
	}{{"payer", payer}, {"payee", payee}} {
		keys := map[string]bool{}
		for _, l := range side.legs {
			keys[l.kid] = true
		}
		if len(keys) > 1 {
			report.Diagnostics = append(report.Diagnostics, Diagnostic{"terms": termsCID, "code": "several_keys_for_role",
				"role": side.role, "keys": sortedKeys(keys), "key_policy_applied": withPolicy})
		}
	}
	state := func(value string) *string { return &value }
	switch {
	case len(payer) == 0 && len(payee) == 0:
		result.PaymentState = state("terms_only")
	case len(payee) == 0:
		result.PaymentState = state("payer_stated")
	case len(payer) == 0:
		result.PaymentState = state("payee_stated")
	default:
		pair(termsCID, terms.s, payer, payee, report, objects, &result)
	}
	for _, side := range []struct {
		name string
		legs []leg
	}{{"payer_observed", payer}, {"payee_observed", payee}} {
		statuses := map[string]bool{}
		for _, l := range side.legs {
			status, _ := l.s["status"].(string)
			statuses[status] = true
		}
		if len(statuses) == 1 {
			if result.ISO20022 == nil {
				result.ISO20022 = map[string]string{}
			}
			for status := range statuses {
				result.ISO20022[side.name] = ISO20022Status[[2]string{side.name, status}]
			}
		}
	}

	pinned, hasPin := object(terms.s["deliverable"])["content_digest"]
	var delivered []leg
	for _, l := range answering {
		if l.name() == "delivered" {
			delivered = append(delivered, l)
		}
	}
	values, directions := map[interface{}]bool{}, map[string]bool{}
	for _, l := range delivered {
		d := object(l.s["delivery"])
		if digest, present := d["content_digest"]; present {
			text, _ := digest.(string)
			values[text] = true
			directions[d["direction"].(string)] = true
		}
	}
	mismatch := len(values) > 1
	if hasPin && pinned != nil {
		for value := range values {
			if value != pinned {
				mismatch = true
			}
		}
	}
	switch {
	case len(delivered) == 0:
		result.DeliveryState = "none"
	case mismatch:
		result.DeliveryState = "mismatch"
	case len(directions) == 2 && directions["sent"] && directions["received"]:
		result.DeliveryState = "matched"
		sent, received := map[string]bool{}, map[string]bool{}
		for _, l := range delivered {
			switch object(l.s["delivery"])["direction"] {
			case "sent":
				sent[l.kid] = true
			case "received":
				received[l.kid] = true
			}
		}
		shared := map[string]bool{}
		overlap := false
		for key := range sent {
			if received[key] {
				overlap = true
				if key != "" {
					shared[key] = true
				}
			}
		}
		if overlap {
			report.Diagnostics = append(report.Diagnostics, Diagnostic{"terms": termsCID, "code": "delivery_sealed_under_one_key",
				"keys": sortedKeys(shared)})
		}
	default:
		result.DeliveryState = "stated"
	}
	return result
}

func pair(termsCID string, terms map[string]interface{}, payer, payee []leg, report *Result, objects map[string][]byte, out *Settlement) {
	// The pair the state is derived from: one payer head and one payee head
	// under distinct keys. If every combination shares a key, it is conflated.
	a, b := payer[0], payee[0]
	conflated := true
	for _, p := range payer {
		for _, q := range payee {
			if conflated && p.kid != q.kid {
				a, b, conflated = p, q, false
			}
		}
	}
	state := func(value string) *string { return &value }
	ref := object(b.s["payment_ref"])
	refType, _ := ref["type"].(string)
	aType, _ := object(a.s["payment_ref"])["type"].(string)
	receiveFee, hasFee := b.s["receive_fee"].(map[string]interface{})
	received := object(b.s["received"])
	if !hasFee && receiveFeeNotApplicable(refType, terms, a.s, objects) {
		receiveFee = map[string]interface{}{"value": "0", "assetCode": received["assetCode"], "assetScale": received["assetScale"]}
		hasFee = true
	}
	_, aKnown := PaymentRefTypes[aType]
	_, bKnown := PaymentRefTypes[refType]
	if !aKnown || !bKnown || aType != refType {
		out.PaymentState = state("unjoined")
		return
	}
	if !hasFee {
		report.Findings = append(report.Findings, Entry{Records: []*string{b.cid}, Code: "fee_unstated"})
		out.PaymentState = state("unjoined")
		return
	}
	routingFee, hasRouting := a.s["routing_fee"].(map[string]interface{})
	// fee_asset_differs names the leg or legs whose fee is in another asset:
	// the payer leg for routing_fee, the payee leg for receive_fee, payer first.
	var differ []*string
	if hasRouting && routingFee["assetCode"] != object(a.s["amount"])["assetCode"] {
		differ = append(differ, a.cid)
	}
	if receiveFee["assetCode"] != received["assetCode"] {
		differ = append(differ, b.cid)
	}
	if len(differ) > 0 {
		report.Findings = append(report.Findings, Entry{Records: differ, Code: "fee_asset_differs"})
		out.PaymentState = state("unjoined")
		return
	}
	var differs []string
	add := func(name string) {
		for _, existing := range differs {
			if existing == name {
				return
			}
		}
		differs = append(differs, name)
	}
	if !amountRuleHolds(a.s, b.s, receiveFee) {
		add("amount")
	}
	if a.s["status"] != b.s["status"] {
		add("status")
	}
	if !jsonEqual(normalPaymentRef(a.s["payment_ref"]), normalPaymentRef(b.s["payment_ref"])) {
		add("payment_ref")
	}
	// More than one head on a side (no supersedes chain between them): each
	// must say the same thing.
	for _, side := range [][]leg{payer, payee} {
		first := side[0].s
		for _, other := range side[1:] {
			for _, name := range amountMembers {
				// The same amount at another scale is the same amount (section 6).
				x, xPresent := first[name].(map[string]interface{})
				y, yPresent := other.s[name].(map[string]interface{})
				if xPresent != yPresent || (xPresent && !amountsEqual(x, y)) {
					add("amount")
				}
			}
			if first["status"] != other.s["status"] {
				add("status")
			}
			if !jsonEqual(normalPaymentRef(other.s["payment_ref"]), normalPaymentRef(first["payment_ref"])) {
				add("payment_ref")
			}
		}
	}
	switch {
	case len(differs) != 0:
		out.PaymentState = state("mismatch")
		out.Differs = differs
	case conflated:
		// The draft: a verifier MUST NOT report agreed for such a pair; it
		// reports sealer_conflation, a failure code, not a state. No row of
		// the draft's state table fits a conflated pair that otherwise
		// matches, so no state is reported and a diagnostic says why.
		report.Diagnostics = append(report.Diagnostics, Diagnostic{"terms": termsCID, "code": "sealer_conflation",
			"note": "agreed withheld; no state of the draft applies"})
	default:
		out.PaymentState = state("agreed")
		out.AgreedStatus, _ = a.s["status"].(string)
		out.TermsAmount = "differs"
		if amountsEqual(object(a.s["amount"]), object(terms["amount"])) {
			out.TermsAmount = "equal"
		}
	}
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func contains(values []string, value interface{}) bool {
	text, isString := value.(string)
	return isString && containsString(values, text)
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func matches(pattern *regexp.Regexp, value interface{}) bool {
	text, isString := value.(string)
	return isString && pattern.MatchString(text)
}

// utcTimeOK reports whether value is an RFC 3339 UTC time that names a real
// instant: the pattern, a month of 1-12, a day that exists in that month
// (proleptic Gregorian leap years), hour 0-23, minute 0-59 and second 0-59
// (no leap second).
func utcTimeOK(value interface{}) bool {
	if !matches(rfc3339Pattern, value) {
		return false
	}
	text := value.(string)
	field := func(from, to int) int {
		n, _ := strconv.Atoi(text[from:to])
		return n
	}
	year, month, day := field(0, 4), field(5, 7), field(8, 10)
	if month < 1 || month > 12 || day < 1 {
		return false
	}
	// Day 0 of the next month is the last day of this one.
	last := time.Date(year, time.Month(month+1), 0, 0, 0, 0, 0, time.UTC).Day()
	return day <= last && field(11, 13) <= 23 && field(14, 16) <= 59 && field(17, 19) <= 59
}

// integer reads a JSON integer (json.Number without a fraction or exponent,
// or a native Go integer).
func integer(value interface{}) (int64, bool) {
	switch value := value.(type) {
	case json.Number:
		if strings.ContainsAny(value.String(), ".eE") {
			return 0, false
		}
		parsed, err := value.Int64()
		return parsed, err == nil
	case int:
		return int64(value), true
	case int64:
		return value, true
	}
	return 0, false
}

// jsonEqual is equality of decoded JSON values, numbers compared by value.
func jsonEqual(a, b interface{}) bool {
	if left, isNumber := a.(json.Number); isNumber {
		right, isNumber := b.(json.Number)
		if !isNumber {
			return false
		}
		l, lok := new(big.Rat).SetString(left.String())
		r, rok := new(big.Rat).SetString(right.String())
		return lok && rok && l.Cmp(r) == 0
	}
	switch left := a.(type) {
	case map[string]interface{}:
		right, isObject := b.(map[string]interface{})
		if !isObject || len(left) != len(right) {
			return false
		}
		for key, value := range left {
			other, present := right[key]
			if !present || !jsonEqual(value, other) {
				return false
			}
		}
		return true
	case []interface{}:
		right, isList := b.([]interface{})
		if !isList || len(left) != len(right) {
			return false
		}
		for i := range left {
			if !jsonEqual(left[i], right[i]) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}
