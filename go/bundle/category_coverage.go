// SPDX-License-Identifier: BSD-3-Clause
package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
)

// The values of a category_coverage property.
const (
	CoveragePass         = "PASS"
	CoverageFail         = "FAIL"
	CoverageNotPresent   = "NOT_PRESENT"
	CoverageNotChecked   = "NOT_CHECKED"
	CoverageInconclusive = "INCONCLUSIVE"
)

// CategoryStatuses are the per-category statuses: the Evidence Layer -00
// retention states AVAILABLE, PARTIAL, WITHHELD and DELETED, and UNDISCLOSED
// and ABSENT, which Bundle -02 defines.
var CategoryStatuses = []string{"AVAILABLE", "PARTIAL", "WITHHELD", "DELETED", "ABSENT", "UNDISCLOSED"}

// CategoryCoverageProperties are the five properties, in report order.
var CategoryCoverageProperties = []string{
	"category_coverage_form",
	"category_coverage_signature",
	"category_coverage_set_registered",
	"category_coverage_request",
	"category_coverage_consistency",
}

// gatingProperties are the properties whose FAIL makes a strict verdict
// INVALID.
var gatingProperties = map[string]bool{
	"category_coverage_form":        true,
	"category_coverage_signature":   true,
	"category_coverage_consistency": true,
}

// CategoryProperty is one category_coverage property and its value.
type CategoryProperty struct {
	Name  string
	Value string
}

var (
	hex128RE = regexp.MustCompile(`^[0-9a-f]{128}$`)
	// RFC 3986 Section 4.3 absolute-URI, checked at the character level: a
	// scheme, ":", then only unreserved, sub-delims, ":", "@", "/", "?" and
	// well-formed percent-encodings. ASCII only; no fragment ("#"), so no
	// relative reference.
	absoluteURIRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})*$`)
)

// privateSet starts a category set id that is never looked up.
const privateSet = "x-"

// CategoryCoverageSigningInput is
// UTF8(JCS({"category_coverage": <member without signature>, "root": root})).
func CategoryCoverageSigningInput(member map[string]interface{}, root interface{}) ([]byte, error) {
	unsigned := make(map[string]interface{}, len(member))
	for name, value := range member {
		if name != "signature" {
			unsigned[name] = value
		}
	}
	return canonical.JCS(map[string]interface{}{"category_coverage": unsigned, "root": root})
}

// CheckCategoryCoverage returns the five properties of
// bundle["category_coverage"] in report order, or nil when the Bundle carries
// no such member.
//
// categorySets maps each category set the caller knows to its names (a set
// starting "x-" is never looked up). request is the Evidence Request's octets
// as received; nil is no request. recordCategories maps each carried record's
// capsule_id to its category, as the set's rule assigns it (a nil value is a
// record in no category); with a nil map, or when a carried record is not in
// it, consistency is NOT_CHECKED. When the member is malformed, every other
// property is NOT_CHECKED.
func CheckCategoryCoverage(bundle map[string]interface{}, categorySets map[string][]string, request []byte, recordCategories map[string]*string) []CategoryProperty {
	raw, present := bundle["category_coverage"]
	if !present {
		return nil
	}
	values := make([]string, len(CategoryCoverageProperties))
	member, ok := wellFormedCoverage(raw)
	if !ok {
		values[0] = CoverageFail
		for i := 1; i < len(values); i++ {
			values[i] = CoverageNotChecked
		}
	} else {
		rawRecords, _ := bundle["records"].([]interface{})
		var recordIDs []string
		for _, rawRecord := range rawRecords {
			record, _ := rawRecord.(map[string]interface{})
			if id, isString := record["capsule_id"].(string); isString {
				recordIDs = append(recordIDs, id)
			}
		}
		values[0] = CoveragePass
		values[1] = coverageSignature(member, bundle["root"])
		values[2] = coverageSetRegistered(member, categorySets)
		values[3] = coverageRequest(member, request)
		values[4] = coverageConsistency(member, recordIDs, recordCategories)
	}
	out := make([]CategoryProperty, len(values))
	for i, value := range values {
		out[i] = CategoryProperty{Name: CategoryCoverageProperties[i], Value: value}
	}
	return out
}

// coverageFails reports whether a gating property is FAIL.
func coverageFails(properties []CategoryProperty) bool {
	for _, property := range properties {
		if gatingProperties[property.Name] && property.Value == CoverageFail {
			return true
		}
	}
	return false
}

func wellFormedCoverage(raw interface{}) (map[string]interface{}, bool) {
	member, ok := raw.(map[string]interface{})
	if !ok {
		return nil, false
	}
	if set, ok := member["set"].(string); !ok || set == "" {
		return nil, false
	}
	categories, ok := member["categories"].(map[string]interface{})
	if !ok || len(categories) == 0 {
		return nil, false
	}
	for name, rawEntry := range categories {
		entry, ok := rawEntry.(map[string]interface{})
		if name == "" || !ok {
			return nil, false
		}
		status, _ := entry["status"].(string)
		if !knownStatus(status) {
			return nil, false
		}
		uri, hasURI := entry["policy_uri"]
		if text, isString := uri.(string); hasURI && (!isString || !absoluteURIRE.MatchString(text)) {
			return nil, false
		}
		if status == "UNDISCLOSED" && !hasURI {
			return nil, false
		}
	}
	if digest, present := member["request_digest"]; present {
		if text, isString := digest.(string); !isString || !hex64RE.MatchString(text) {
			return nil, false
		}
	}
	rawSigner, hasSigner := member["signer"]
	rawSignature, hasSignature := member["signature"]
	if hasSigner != hasSignature {
		return nil, false
	}
	if hasSigner {
		signer, ok := rawSigner.(map[string]interface{})
		if !ok {
			return nil, false
		}
		if keyID, isString := signer["key_id"].(string); !isString || !hex64RE.MatchString(keyID) {
			return nil, false
		}
		if signature, isString := rawSignature.(string); !isString || !hex128RE.MatchString(signature) {
			return nil, false
		}
	}
	return member, true
}

func knownStatus(status string) bool {
	for _, known := range CategoryStatuses {
		if status == known {
			return true
		}
	}
	return false
}

func coverageSignature(member map[string]interface{}, root interface{}) string {
	if _, present := member["signature"]; !present {
		return CoverageNotPresent
	}
	signingInput, err := CategoryCoverageSigningInput(member, root)
	if err != nil {
		return CoverageFail // no canonical signing input, so nothing the signature can cover
	}
	// The form check has made both 64 and 128 lowercase hex digits.
	key, _ := hex.DecodeString(member["signer"].(map[string]interface{})["key_id"].(string))
	signature, _ := hex.DecodeString(member["signature"].(string))
	if smallOrder(key) || !ed25519.Verify(key, signingInput, signature) {
		return CoverageFail
	}
	return CoveragePass
}

var (
	p25519 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	// y8 is the y-coordinate of a point of order 8, little-endian.
	y8 = littleEndian(mustHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"))
)

// smallOrder reports whether key encodes a small-order point, canonically or
// not. Such a key "verifies" signatures over any message, so it is refused,
// as strict verification (RFC 8032 with a small-order check) does;
// crypto/ed25519 does not refuse it.
func smallOrder(key []byte) bool {
	y := littleEndian(key)
	y.SetBit(y, 255, 0)
	y.Mod(y, p25519)
	for _, small := range []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(p25519, big.NewInt(1)), y8, new(big.Int).Sub(p25519, y8)} {
		if y.Cmp(small) == 0 {
			return true
		}
	}
	return false
}

func littleEndian(data []byte) *big.Int {
	reversed := make([]byte, len(data))
	for i, b := range data {
		reversed[len(data)-1-i] = b
	}
	return new(big.Int).SetBytes(reversed)
}

func mustHex(text string) []byte {
	data, err := hex.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return data
}

func coverageSetRegistered(member map[string]interface{}, categorySets map[string][]string) string {
	set := member["set"].(string)
	if strings.HasPrefix(set, privateSet) {
		return CoverageNotPresent
	}
	known, found := categorySets[set]
	if !found || known == nil {
		return CoverageInconclusive
	}
	names := make(map[string]bool, len(known))
	for _, name := range known {
		names[name] = true
	}
	for name := range member["categories"].(map[string]interface{}) {
		if !names[name] {
			return CoverageFail
		}
	}
	return CoveragePass
}

func coverageRequest(member map[string]interface{}, request []byte) string {
	if request == nil {
		return CoverageNotChecked
	}
	// The digest is over the octets as received, so it is checked before (and
	// whether or not) they parse.
	if digest, present := member["request_digest"]; present {
		sum := sha256.Sum256(request)
		if digest != hex.EncodeToString(sum[:]) {
			return CoverageFail
		}
	}
	parsed, err := decodeRequest(request)
	if err != nil {
		return CoverageNotChecked
	}
	object, ok := parsed.(map[string]interface{})
	if !ok {
		return CoverageNotChecked
	}
	rawAsked, present := object["categories"]
	if !present {
		return CoverageNotPresent
	}
	asked, _ := rawAsked.(map[string]interface{})
	set, setOK := asked["set"].(string)
	rawNames, namesOK := asked["names"].([]interface{})
	if !setOK || !namesOK || len(rawNames) == 0 {
		return CoverageNotChecked // a malformed request is the requester's to fix, not the producer's failure
	}
	names := make([]string, len(rawNames))
	distinct := make(map[string]bool, len(rawNames))
	for i, rawName := range rawNames {
		name, isString := rawName.(string)
		if !isString || distinct[name] {
			return CoverageNotChecked
		}
		names[i], distinct[name] = name, true
	}
	if set != member["set"] {
		return CoverageFail
	}
	categories := member["categories"].(map[string]interface{})
	for _, name := range names {
		if _, declared := categories[name]; !declared {
			return CoverageFail
		}
	}
	return CoveragePass
}

var errRequestJSON = errors.New("not a strict JSON text")

// decodeRequest reads the request octets strictly: UTF-8, exactly one JSON
// value, no repeated member name in any object and no unpaired surrogate
// escape (I-JSON, RFC 7493 Section 2.1). encoding/json already refuses NaN
// and Infinity.
func decodeRequest(data []byte) (interface{}, error) {
	if !utf8.Valid(data) {
		return nil, errRequestJSON
	}
	var value interface{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errRequestJSON
	}
	if repeatsMember(json.NewDecoder(bytes.NewReader(data))) || unpairedSurrogate(data) {
		return nil, errRequestJSON
	}
	return value, nil
}

// repeatsMember walks one already-valid JSON value and reports whether any
// object in it names a member twice. A token it cannot read counts as a
// repeat, so the walk never passes a value it did not finish.
func repeatsMember(decoder *json.Decoder) bool {
	decoder.UseNumber()
	type frame struct {
		object bool
		key    bool
		names  map[string]bool
	}
	var stack []*frame
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return false
		}
		if err != nil {
			return true
		}
		top := (*frame)(nil)
		if len(stack) != 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.object && top.key {
			if name, isString := token.(string); isString {
				if top.names[name] {
					return true
				}
				top.names[name] = true
				top.key = false
				continue
			}
		}
		switch token {
		case json.Delim('{'):
			stack = append(stack, &frame{object: true, key: true, names: map[string]bool{}})
			continue
		case json.Delim('['):
			stack = append(stack, &frame{})
			continue
		case json.Delim('}'), json.Delim(']'):
			stack = stack[:len(stack)-1]
		}
		// A value ended: the enclosing object expects a name next.
		if len(stack) != 0 && stack[len(stack)-1].object {
			stack[len(stack)-1].key = true
		}
	}
}

// unpairedSurrogate reports whether a string in one already-valid JSON text
// holds a \u escape of a UTF-16 surrogate that is not a high surrogate
// followed at once by an escaped low one. encoding/json would read it as
// U+FFFD instead of refusing it.
func unpairedSurrogate(data []byte) bool {
	escaped := func(at int) (rune, bool) {
		if at+6 > len(data) || data[at] != '\\' || data[at+1] != 'u' {
			return 0, false
		}
		value, err := strconv.ParseUint(string(data[at+2:at+6]), 16, 16)
		return rune(value), err == nil
	}
	// In valid JSON a backslash occurs only inside a string, so no string
	// boundary needs tracking.
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		r, ok := escaped(i)
		switch {
		case !ok:
			i++ // a one-character escape such as \" or \\
		case utf16.IsSurrogate(r) && r < 0xdc00:
			low, lowOK := escaped(i + 6)
			if !lowOK || low < 0xdc00 || low > 0xdfff {
				return true
			}
			i += 11
		case utf16.IsSurrogate(r):
			return true
		default:
			i += 5
		}
	}
	return false
}

func coverageConsistency(member map[string]interface{}, recordIDs []string, recordCategories map[string]*string) string {
	if recordCategories == nil {
		return CoverageNotChecked
	}
	carried := map[string]bool{}
	for _, id := range recordIDs {
		category, assigned := recordCategories[id]
		if !assigned {
			return CoverageNotChecked // a record the caller could not assign could be in any category
		}
		if category != nil {
			carried[*category] = true
		}
	}
	for name, rawEntry := range member["categories"].(map[string]interface{}) {
		status := rawEntry.(map[string]interface{})["status"]
		if (status == "ABSENT" || status == "WITHHELD") && carried[name] {
			return CoverageFail
		}
	}
	return CoveragePass
}
