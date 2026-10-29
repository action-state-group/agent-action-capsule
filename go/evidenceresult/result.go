// SPDX-License-Identifier: BSD-3-Clause

// Package evidenceresult is the Go gate for an Evidence Result v0 document
// (spec/evidence-result-v0.md). It runs what the Python reference,
// schemas/check_evidence_result_examples.py, runs over the same document:
// the companion JSON Schema, then the cross-element rules the schema cannot
// express (sections 3, 4, 4.1 to 4.3 and 7.1), and returns the claims as a
// consumer reads them. The conformance cases are vectors/evidence-result/.
package evidenceresult

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/internal/ecmaregexp"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The schema is schemas/evidence-result-v0.json of this repository, copied
// because go:embed cannot reach outside the module; TestSchemaIsTheRepositorys
// holds the copy byte-equal to it.
//
//go:embed evidence-result-v0.json
var schemaBytes []byte

const (
	// Version is the document's result_version.
	Version = "evidence-result-v0"
	// SchemaID is the schema's $id.
	SchemaID = "https://agentactioncapsule.org/schemas/evidence-result-v0.json"

	// The claim types of section 4.1. An absent type is a requirement claim.
	TypeRequirement = "requirement"
	TypeReconcile   = "reconcile"
	TypeClose       = "close"
)

// Schema returns the embedded schema's bytes.
func Schema() []byte { return bytes.Clone(schemaBytes) }

var compiled struct {
	sync.Once
	schema *jsonschema.Schema
	err    error
}

// compiledSchema compiles the embedded schema once. Formats are annotations,
// as in the Python reference (draft 2020-12's default): generated_at is held
// to RFC 3339 by the applicability rule, when a claim is dated, not by the
// schema.
func compiledSchema() (*jsonschema.Schema, error) {
	compiled.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
		if err != nil {
			compiled.err = err
			return
		}
		compiler := jsonschema.NewCompiler()
		compiler.UseRegexpEngine(ecmaRegexp)
		if err = compiler.AddResource(SchemaID, doc); err != nil {
			compiled.err = err
			return
		}
		compiled.schema, compiled.err = compiler.Compile(SchemaID)
	})
	return compiled.schema, compiled.err
}

// ecmaRegexp reads schema patterns as ECMA-262 does; shared with
// go/evidenceplan.
var ecmaRegexp = ecmaregexp.Compile

// Decode reads one Result document from its JSON text: one JSON object, its
// numbers kept as json.Number, refusing invalid UTF-8, unpaired surrogate
// escapes and trailing data.
func Decode(raw []byte) (map[string]interface{}, error) {
	value, err := decodeJSONText(raw)
	if err != nil {
		return nil, fmt.Errorf("result is not one JSON text: %w", err)
	}
	doc, ok := value.(map[string]interface{})
	if !ok {
		return nil, errors.New("result must be a JSON object")
	}
	return doc, nil
}

// DecodeRecords reads the record headers a Result's close claims cite (the
// `.records.json` sidecar of vectors/evidence-result/, or the records a
// bundle carries): one JSON array of objects, decoded as Decode does.
func DecodeRecords(raw []byte) ([]map[string]interface{}, error) {
	value, err := decodeJSONText(raw)
	if err != nil {
		return nil, fmt.Errorf("records are not one JSON text: %w", err)
	}
	items, ok := value.([]interface{})
	if !ok {
		return nil, errors.New("records must be a JSON array")
	}
	records := make([]map[string]interface{}, len(items))
	for i, item := range items {
		if records[i], ok = item.(map[string]interface{}); !ok {
			return nil, fmt.Errorf("records[%d] must be a JSON object", i)
		}
	}
	return records, nil
}

func decodeJSONText(raw []byte) (interface{}, error) {
	if err := canonical.CheckJSONText(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value interface{}
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the JSON value")
	}
	return value, nil
}

// Error is a refused Result: every finding, so a producer fixes the document
// once. Schema findings come alone, since the cross-element rules read a
// schema-valid document.
type Error struct {
	// Schema is true when the schema refused the document.
	Schema   bool
	Findings []string
}

func (e *Error) Error() string {
	if e.Schema {
		return "the Result does not satisfy " + Version + ": " + strings.Join(e.Findings, "; ")
	}
	return "the Result does not cross-check: " + strings.Join(e.Findings, "; ")
}

// Claim is one claim as the gate read it.
type Claim struct {
	Index          int
	ID             string
	Type           string // TypeRequirement when the document omits it
	ContractRef    string
	RequirementRef string
	Sufficiency    string
	Verdict        string
	// AppliesFrom is the claim's applies_from, or empty. InForce is false
	// for a later claim (section 4.3): its verdict is readiness, and it is
	// in no bucket and no coverage count.
	AppliesFrom string
	InForce     bool
	// OutOfScopeAllowed is the requirement's copied out_of_scope switch
	// (section 4.2): the fourth bucket is present exactly when a claim
	// carries it.
	OutOfScopeAllowed bool
	// Evidence is evidence[].digest in order; CarrierEvidence is
	// presentation.evidence[].digest when the carrier is a disclosure.
	Evidence        []string
	CarrierEvidence []string
	Close           *Close     // when Type is TypeClose
	Reconcile       *Reconcile // when Type is TypeReconcile
}

// Close is a close claim's body. State has been recomputed from the records'
// links and equals the stated close_state.
type Close struct {
	State       string
	Ref         string // close_ref.digest
	Peer        string
	PeerRef     string // peer_close_ref.digest, or empty
	PeriodStart string
	PeriodEnd   string
}

// Reconcile is a reconcile claim's body.
type Reconcile struct {
	Peer        string
	Tallies     map[string]*big.Int
	PeriodStart string
	PeriodEnd   string
}

// Check is the whole gate. It validates doc (as Decode returns it) against
// the schema, then runs the cross-element rules: claim ids are unique;
// every in-force claim sits in the bucket of its verdict and a later one in
// none; the claims of one requirement agree on out_of_scope_allowed and
// applies_from; the coverage counts and not_yet_in_force recompute from the
// claims; requirements_covered lists every claimed requirement and no more
// unclaimed ones than excluded_not_applicable; a coverage_report's rows and
// summary recompute; and every close claim's state is recomputed from the
// inbound links of the records it cites. records are those record headers;
// a close claim whose Close is not among them is refused, never skipped.
func Check(doc map[string]interface{}, records []map[string]interface{}) ([]Claim, error) {
	schema, err := compiledSchema()
	if err != nil {
		return nil, fmt.Errorf("compiling the %s schema: %w", Version, err)
	}
	if err := schema.Validate(map[string]interface{}(doc)); err != nil {
		var invalid *jsonschema.ValidationError
		if !errors.As(err, &invalid) {
			return nil, err
		}
		return nil, &Error{Schema: true, Findings: schemaFindings(invalid)}
	}
	claims, findings := readClaims(doc)
	findings = append(findings, revisionFindings(doc, claims)...)
	findings = append(findings, coverageFindings(doc)...)
	findings = append(findings, closeFindings(doc, claims, records)...)
	if len(findings) > 0 {
		return nil, &Error{Findings: findings}
	}
	return claims, nil
}

// schemaFindings is one line per failing keyword, at its instance location.
func schemaFindings(invalid *jsonschema.ValidationError) []string {
	var out []string
	seen := map[string]bool{}
	for _, unit := range invalid.BasicOutput().Errors {
		if unit.Error == nil {
			continue
		}
		line := "at " + unitLocation(unit.InstanceLocation) + ": " + unit.Error.String()
		if !seen[line] {
			seen[line] = true
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		out = append(out, invalid.Error())
	}
	return out
}

func unitLocation(location string) string {
	if location == "" {
		return "/"
	}
	return location
}

// readClaims reads a schema-valid document's claims and checks claim id
// uniqueness (section 4: normative, not schema-enforced).
func readClaims(doc map[string]interface{}) ([]Claim, []string) {
	raw, _ := doc["claims"].([]interface{})
	claims := make([]Claim, 0, len(raw))
	var findings []string
	first := map[string]int{}
	for i, item := range raw {
		object, _ := item.(map[string]interface{})
		claim := Claim{Index: i, Type: TypeRequirement, InForce: true}
		claim.ID, _ = object["id"].(string)
		if typ, ok := object["type"].(string); ok {
			claim.Type = typ
		}
		claim.ContractRef, _ = object["contract_ref"].(string)
		claim.RequirementRef, _ = object["requirement_ref"].(string)
		claim.Sufficiency, _ = object["sufficiency"].(string)
		claim.Verdict, _ = object["verdict"].(string)
		claim.AppliesFrom, _ = object["applies_from"].(string)
		claim.OutOfScopeAllowed, _ = object["out_of_scope_allowed"].(bool)
		claim.Evidence = digests(object["evidence"])
		if presentation, ok := object["presentation"].(map[string]interface{}); ok && presentation["kind"] == "disclosure" {
			claim.CarrierEvidence = digests(presentation["evidence"])
		}
		if body, ok := object["close"].(map[string]interface{}); ok {
			c := &Close{}
			c.State, _ = body["close_state"].(string)
			c.Peer, _ = body["peer"].(string)
			c.Ref = digestOf(body["close_ref"])
			c.PeerRef = digestOf(body["peer_close_ref"])
			c.PeriodStart, c.PeriodEnd = period(body)
			claim.Close = c
		}
		if body, ok := object["reconcile"].(map[string]interface{}); ok {
			r := &Reconcile{Tallies: map[string]*big.Int{}}
			r.Peer, _ = body["peer"].(string)
			tallies, _ := body["tallies"].(map[string]interface{})
			for state, count := range tallies {
				// The schema admits any integer value (7, 7.0, 1e100), so a
				// tally is read exactly, never truncated to a machine word.
				if n, ok := number(count); ok && n.IsInt() {
					r.Tallies[state] = new(big.Int).Set(n.Num())
				}
			}
			r.PeriodStart, r.PeriodEnd = period(body)
			claim.Reconcile = r
		}
		if at, dup := first[claim.ID]; dup {
			findings = append(findings, fmt.Sprintf("claims[%d].id %q duplicates claims[%d]; claim ids are unique within a Result", i, claim.ID, at))
		} else {
			first[claim.ID] = i
		}
		claims = append(claims, claim)
	}
	return claims, findings
}

func digestOf(ref interface{}) string {
	object, _ := ref.(map[string]interface{})
	digest, _ := object["digest"].(string)
	return digest
}

func digests(refs interface{}) []string {
	items, _ := refs.([]interface{})
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, digestOf(item))
	}
	return out
}

func period(body map[string]interface{}) (start, end string) {
	p, _ := body["period"].(map[string]interface{})
	start, _ = p["start"].(string)
	end, _ = p["end"].(string)
	return start, end
}
