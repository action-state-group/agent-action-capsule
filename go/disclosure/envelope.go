// SPDX-License-Identifier: BSD-3-Clause
// Package disclosure builds and verifies Agent Action Capsule Disclosure Envelopes.
package disclosure

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/registries"
	"github.com/action-state-group/agent-action-capsule/go/verify"
)

const (
	Match             = "disclosure_match"
	Mismatch          = "disclosure_mismatch"
	Ineligible        = "disclosure_ineligible_field"
	NoCommittedDigest = "disclosure_no_committed_digest"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Finding is one DE-1 through DE-3 result for a disclosed member.
type Finding struct {
	Member string `json:"member"`
	Code   string `json:"code"`
}

// Result keeps Class-1 and disclosure verification results independent.
type Result struct {
	CapsuleResult      verify.VerificationResult `json:"capsule_result"`
	DisclosureFindings []Finding                 `json:"disclosure_findings"`
}

// DisclosuresChecked returns the number of members presented for disclosure.
func (r Result) DisclosuresChecked() int { return len(r.DisclosureFindings) }

// DisclosuresMatched returns the number whose recomputed digest matched.
func (r Result) DisclosuresMatched() int {
	count := 0
	for _, finding := range r.DisclosureFindings {
		if finding.Code == Match {
			count++
		}
	}
	return count
}

// OK is true only when Class 1 passes and every presented disclosure matches.
func (r Result) OK() bool {
	if !r.CapsuleResult.OK {
		return false
	}
	for _, finding := range r.DisclosureFindings {
		if finding.Code != Match {
			return false
		}
	}
	return true
}

// Verify performs Class-1 verification over the embedded Capsule and DE-1
// through DE-3 over disclosures. It never panics for malformed input.
func Verify(envelope interface{}, regs map[string]map[string]bool) Result {
	top, ok := envelope.(map[string]interface{})
	if !ok {
		return Result{CapsuleResult: verify.Verify(envelope, nil, regs)}
	}
	capsule := top["capsule"]
	result := Result{CapsuleResult: verify.Verify(capsule, nil, regs)}
	disclosures, ok := top["disclosures"].(map[string]interface{})
	if !ok {
		return result
	}

	members := make([]string, 0, len(disclosures))
	for member := range disclosures {
		members = append(members, member)
	}
	sort.Strings(members)
	for _, member := range members {
		value := disclosures[member]
		path, eligible := registries.DisclosureEligibleFields[member]
		if !eligible {
			result.DisclosureFindings = append(result.DisclosureFindings, Finding{member, Ineligible})
			continue
		}
		stored, _ := committedDigest(capsule, path)
		if !hex64.MatchString(stored) {
			result.DisclosureFindings = append(result.DisclosureFindings, Finding{member, NoCommittedDigest})
			continue
		}
		var computed string
		var err error
		computed, err = canonical.JSONDigest(value)
		code := Mismatch
		if err == nil && computed == stored {
			code = Match
		}
		result.DisclosureFindings = append(result.DisclosureFindings, Finding{member, code})
	}
	return result
}

// Build constructs a Disclosure Envelope from a Capsule and disclosed member
// preimages. It rejects DE-1-ineligible members, DE-2 missing commitments, and
// DE-3 digest mismatches using the verifier's finding codes. It does not read
// stores, ledgers, or producer packages.
func Build(capsule map[string]interface{}, disclosures map[string]interface{}) (map[string]interface{}, error) {
	for member, value := range disclosures {
		path, eligible := registries.DisclosureEligibleFields[member]
		if !eligible {
			return nil, fmt.Errorf("%s: %s", Ineligible, member)
		}
		stored, ok := committedDigest(capsule, path)
		if !ok || !hex64.MatchString(stored) {
			return nil, fmt.Errorf("%s: %s", NoCommittedDigest, member)
		}
		computed, err := canonical.JSONDigest(value)
		if err != nil || computed != stored {
			return nil, fmt.Errorf("%s: %s", Mismatch, member)
		}
	}
	return map[string]interface{}{"capsule": capsule, "disclosures": disclosures}, nil
}

func committedDigest(value interface{}, path string) (string, bool) {
	current, ok := value.(map[string]interface{})
	if !ok {
		return "", false
	}
	parts := strings.Split(path, ".")
	for _, member := range parts[:len(parts)-1] {
		next, ok := current[member].(map[string]interface{})
		if !ok {
			return "", false
		}
		current = next
	}
	stored, ok := current[parts[len(parts)-1]].(string)
	return stored, ok
}
