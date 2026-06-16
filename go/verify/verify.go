// SPDX-License-Identifier: BSD-3-Clause
// Class 1 verifier (§6).
//
// A verifier validates a Capsule from its own bytes without trusting the producer.
// It MUST return a structured result and NEVER raise/panic (§6). A single ok boolean
// gates trust in every other reported field; findings are reported in a fixed order.
// Unknown registry values are informational and never a rejection (§4, §12).
//
// This is the Class 1 surface only. Substrate verification (COSE_Sign1 signature,
// registration, Receipt inclusion proof) is the SCITT/COSE substrate's responsibility
// by reference (§6) and is not performed here. Class 2 / manifest-aware verification
// (§8.2) is out of scope.
package verify

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/registries"
)

var hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func isHex64(v interface{}) bool {
	s, ok := v.(string)
	return ok && hex64RE.MatchString(s)
}

// requiredFields is the fixed-order list of top-level REQUIRED string fields (§5.1).
var requiredFields = []string{
	"spec_version",
	"format_version",
	"capsule_id",
	"action_id",
	"action_type",
	"operator",
	"developer",
	"timestamp",
}

// neverDispatchVerdictClasses are verdict_class values that by their kind never
// dispatch an effect (§5.4.2); each REQUIRES derived effect_mode "not_applicable".
var neverDispatchVerdictClasses = map[string]bool{
	"blocked":       true,
	"hitl_dispatched": true,
	"denied":        true,
	"engine_failure": true,
	"deferred":      true,
	"needs_decision": true,
	"expired":       true,
	"escalated":     true,
	"resolved":      true,
}

// validApprovers is the closed enum for disposition.approver (§5.4).
var validApprovers = map[string]bool{
	"human":  true,
	"policy": true,
}

// effectModeRank for overclaim detection (§5.3).
var effectModeRank = map[string]int{
	"not_applicable":          0,
	"dispatched_unconfirmed":  0,
	"confirmed":               1,
}

// attestationRank for overclaim detection.
var attestationRank = map[string]int{
	"self_attested": 0,
	"anchored":      1,
}

// ledgerModeRank for overclaim detection.
var ledgerModeRank = map[string]int{
	"standalone": 0,
	"chained":    1,
	"anchored":   2,
}

// registryFields maps (registry_name, block_key, member_key) in check-8 emission order.
var registryFields = []struct{ reg, block, member string }{
	{"verdict_class", "disposition", "verdict_class"},
	{"disposition.decision", "disposition", "decision"},
	{"effect.type", "effect", "type"},
	{"irreversibility_class", "effect", "irreversibility_class"},
	{"effect_attestation", "effect", "effect_attestation"},
	{"chain.relation", "chain", "relation"},
}

// Finding is one structured verification finding.
// Check is nil for findings not belonging to a numbered §6 check.
// Severity "error" gates ok; "warning" and "info" are non-gating.
type Finding struct {
	Code     string
	Detail   string
	Severity string
	Check    *int
}

func mkCheck(n int) *int { return &n }

// VerificationResult is the never-throwing return value of Verify.
type VerificationResult struct {
	OK        bool
	Findings  []Finding
	Assurance map[string]string // derived assurance (effect_mode, attestation_mode, ledger_mode)
	CapsuleID *string           // recomputed capsule_id, nil if not computable
}

// deriveEffectMode derives assurance.effect_mode from the Effect Record (§5.2).
func deriveEffectMode(effect map[string]interface{}) string {
	if effect == nil {
		return "not_applicable"
	}
	status, _ := effect["status"].(string)
	if status == "planned" {
		return "not_applicable"
	}
	if status == "confirmed" {
		if isHex64(effect["response_digest"]) {
			return "confirmed"
		}
		return "dispatched_unconfirmed"
	}
	return "dispatched_unconfirmed"
}

// asMap returns v as a map if it is one, else nil.
func asMap(v interface{}) map[string]interface{} {
	m, _ := v.(map[string]interface{})
	return m
}

// floatPaths returns all JSON paths in v where a JSON float appears.
// Booleans are never floats; json.Number is checked via IsFloat.
func floatPaths(v interface{}, path string) []string {
	var out []string
	switch tv := v.(type) {
	case bool:
		// bool is never a float
	case json.Number:
		if canonical.IsFloat(tv) {
			p := path
			if p == "" {
				p = "<root>"
			}
			out = append(out, p)
		}
	case map[string]interface{}:
		keys := sortedKeysOf(tv)
		for _, k := range keys {
			child := k
			if path != "" {
				child = path + "." + k
			}
			out = append(out, floatPaths(tv[k], child)...)
		}
	case []interface{}:
		for i, x := range tv {
			child := fmt.Sprintf("[%d]", i)
			if path != "" {
				child = fmt.Sprintf("%s[%d]", path, i)
			}
			out = append(out, floatPaths(x, child)...)
		}
	}
	return out
}

// unsafeIntPaths returns all JSON paths in v where an integer exceeds ±MaxSafeInteger.
func unsafeIntPaths(v interface{}, path string) []string {
	var out []string
	switch tv := v.(type) {
	case bool:
		// bool is never an integer here
	case json.Number:
		if !canonical.IsFloat(tv) && canonical.IsUnsafeInt(tv) {
			p := path
			if p == "" {
				p = "<root>"
			}
			out = append(out, p)
		}
	case map[string]interface{}:
		keys := sortedKeysOf(tv)
		for _, k := range keys {
			child := k
			if path != "" {
				child = path + "." + k
			}
			out = append(out, unsafeIntPaths(tv[k], child)...)
		}
	case []interface{}:
		for i, x := range tv {
			child := fmt.Sprintf("[%d]", i)
			if path != "" {
				child = fmt.Sprintf("%s[%d]", path, i)
			}
			out = append(out, unsafeIntPaths(x, child)...)
		}
	}
	return out
}

// sortedKeysOf returns map keys in lexicographic order (deterministic walk for paths).
func sortedKeysOf(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// storeIDs extracts capsule_id strings from a store (slice of capsule maps or strings).
func storeIDs(store []interface{}) map[string]bool {
	ids := make(map[string]bool)
	for _, item := range store {
		switch tv := item.(type) {
		case map[string]interface{}:
			if cid, ok := tv["capsule_id"].(string); ok {
				ids[cid] = true
			}
		case string:
			ids[tv] = true
		}
	}
	return ids
}

func verify(capsule interface{}, store []interface{}, regs map[string]map[string]bool) VerificationResult {
	var findings []Finding

	capsuleMap, isCapsule := capsule.(map[string]interface{})
	if !isCapsule {
		findings = append(findings, Finding{
			Code: "not_an_object", Detail: "Capsule is not a JSON object",
			Severity: "error", Check: mkCheck(1),
		})
		return VerificationResult{OK: false, Findings: findings}
	}

	effect := asMap(capsuleMap["effect"])
	disposition := asMap(capsuleMap["disposition"])
	chain := asMap(capsuleMap["chain"])

	// ---- Check 1: Structural ------------------------------------------------

	// Required fields in fixed order.
	for _, fld := range requiredFields {
		if _, present := capsuleMap[fld]; !present {
			findings = append(findings, Finding{
				Code:     "missing_required_field",
				Detail:   fmt.Sprintf("%s is REQUIRED (§5.1)", fld),
				Severity: "error", Check: mkCheck(1),
			})
		} else if _, ok := capsuleMap[fld].(string); !ok {
			findings = append(findings, Finding{
				Code:     "field_not_string",
				Detail:   fmt.Sprintf("%s MUST be a string (§5.1)", fld),
				Severity: "error", Check: mkCheck(1),
			})
		}
	}

	// capsule_id format.
	cid, cidPresent := capsuleMap["capsule_id"].(string)
	if cidPresent && !hex64RE.MatchString(cid) {
		findings = append(findings, Finding{
			Code:     "capsule_id_malformed",
			Detail:   "capsule_id MUST be 64 lowercase hex (§5.1)",
			Severity: "error", Check: mkCheck(1),
		})
		cidPresent = false // treat as absent for recompute below
	}

	// action_type enum.
	if at, ok := capsuleMap["action_type"].(string); ok {
		if at != "fyi" && at != "decide" {
			findings = append(findings, Finding{
				Code:     "action_type_invalid",
				Detail:   fmt.Sprintf("action_type MUST be 'fyi' or 'decide' (§5.1)"),
				Severity: "error", Check: mkCheck(1),
			})
		}
	}

	// Sub-block type checks (effect, assurance, disposition, chain).
	for _, fld := range []string{"effect", "assurance", "disposition", "chain"} {
		if v, ok := capsuleMap[fld]; ok {
			if _, isMap := v.(map[string]interface{}); !isMap {
				findings = append(findings, Finding{
					Code:     "block_not_object",
					Detail:   fmt.Sprintf("%s MUST be a JSON object when present", fld),
					Severity: "error", Check: mkCheck(1),
				})
			}
		}
	}

	// constraints array check.
	if cv, ok := capsuleMap["constraints"]; ok {
		if _, isList := cv.([]interface{}); !isList {
			findings = append(findings, Finding{
				Code:     "constraints_not_array",
				Detail:   "constraints MUST be an array when present (§8.1)",
				Severity: "error", Check: mkCheck(1),
			})
		}
	}

	// Float check: report all float paths in the capsule.
	for _, p := range floatPaths(capsule, "") {
		findings = append(findings, Finding{
			Code:     "float_in_digest_field",
			Detail:   fmt.Sprintf("floating-point value at %s; §5.1 forbids it", p),
			Severity: "error", Check: mkCheck(1),
		})
	}

	// Unsafe integer check.
	for _, p := range unsafeIntPaths(capsule, "") {
		findings = append(findings, Finding{
			Code: "unsafe_integer_in_digest_field",
			Detail: fmt.Sprintf(
				"integer outside the JS-safe range (+/-%d) at %s; "+
					"large integers MUST be exact decimal strings for cross-impl digest "+
					"reproducibility (impl guard ahead of -00; see -01 flag)",
				canonical.MaxSafeInteger, p,
			),
			Severity: "error", Check: mkCheck(1),
		})
	}

	// Disposition structural checks + honesty assert (§6).
	if disposition != nil {
		approver, approverPresent := disposition["approver"].(string)
		if !approverPresent {
			findings = append(findings, Finding{
				Code:     "missing_required_field",
				Detail:   "disposition.approver is REQUIRED (§5.4)",
				Severity: "error", Check: mkCheck(1),
			})
		} else if !validApprovers[approver] {
			findings = append(findings, Finding{
				Code:     "approver_invalid",
				Detail:   fmt.Sprintf("disposition.approver MUST be human|policy (§5.4); got %q", approver),
				Severity: "error", Check: mkCheck(1),
			})
		}
		if _, ok := disposition["decision"]; !ok {
			findings = append(findings, Finding{
				Code:     "missing_required_field",
				Detail:   "disposition.decision is REQUIRED (§5.4)",
				Severity: "error", Check: mkCheck(1),
			})
		}
		hd, hdBool := disposition["human_disposed"].(bool)
		if !hdBool {
			findings = append(findings, Finding{
				Code:     "field_not_bool",
				Detail:   "disposition.human_disposed is REQUIRED and boolean (§5.4)",
				Severity: "error", Check: mkCheck(1),
			})
		} else if hd && approver != "human" {
			// Defensive honesty check (§6): non-gating warning.
			findings = append(findings, Finding{
				Code: "dishonest_human_disposed",
				Detail: "human_disposed=true with a non-human approver (§5.4). Structurally " +
					"unconstructable by a conforming producer; reported as a non-gating " +
					"defensive warning, not a §6 gating check.",
				Severity: "warning",
				Check:    nil,
			})
		}
	}

	// ---- Check 2: Identity --------------------------------------------------
	var recomputedID *string
	if cidPresent {
		computed, err := canonical.ComputeCapsuleID(capsuleMap)
		if err != nil {
			// Float/unsafe-int errors are already reported structurally (check 1).
			switch err.(type) {
			case *canonical.FloatError, *canonical.UnsafeIntError:
				// already reported; recomputedID stays nil
			default:
				findings = append(findings, Finding{
					Code:     "capsule_id_uncomputable",
					Detail:   err.Error(),
					Severity: "error", Check: mkCheck(2),
				})
			}
		} else {
			recomputedID = &computed
			if computed != cid {
				findings = append(findings, Finding{
					Code:     "capsule_id_mismatch",
					Detail:   fmt.Sprintf("recomputed %s != carried %s", computed, cid),
					Severity: "error", Check: mkCheck(2),
				})
			}
		}
	}

	// ---- Check 3: Confirmed-effect binding ----------------------------------
	if effect != nil {
		status, _ := effect["status"].(string)
		if status == "confirmed" && !isHex64(effect["response_digest"]) {
			findings = append(findings, Finding{
				Code:     "confirmed_without_response",
				Detail:   "effect.status 'confirmed' requires a 64-hex response_digest (§5.2)",
				Severity: "error", Check: mkCheck(3),
			})
		}
	}

	effectMode := deriveEffectMode(effect)

	// ---- Check 4: Verdict/effect orthogonality ------------------------------
	var verdictClass string
	if disposition != nil {
		verdictClass, _ = disposition["verdict_class"].(string)
	}
	if neverDispatchVerdictClasses[verdictClass] && effectMode != "not_applicable" {
		findings = append(findings, Finding{
			Code: "verdict_effect_conflict",
			Detail: fmt.Sprintf(
				"verdict_class %q never dispatches, but derived effect_mode is %q (§5.4.2)",
				verdictClass, effectMode,
			),
			Severity: "error", Check: mkCheck(4),
		})
	}

	// ---- Check 5: Effect-attestation matrix ---------------------------------
	var ea interface{}
	if effect != nil {
		ea = effect["effect_attestation"]
	}
	if effectMode == "confirmed" || effectMode == "dispatched_unconfirmed" {
		if ea == nil {
			findings = append(findings, Finding{
				Code:     "effect_attestation_missing",
				Detail:   fmt.Sprintf("effect_attestation REQUIRED for effect_mode %q (§5.2)", effectMode),
				Severity: "error", Check: mkCheck(5),
			})
		}
	} else { // not_applicable
		if ea != nil {
			findings = append(findings, Finding{
				Code:     "effect_attestation_present",
				Detail:   "effect_attestation MUST be absent for effect_mode 'not_applicable' (§5.2)",
				Severity: "error", Check: mkCheck(5),
			})
		}
	}

	// ---- Check 6: Chain semantics -------------------------------------------
	if chain != nil {
		parent := chain["parent_capsule_id"]
		if !isHex64(parent) {
			findings = append(findings, Finding{
				Code:     "chain_parent_malformed",
				Detail:   "chain.parent_capsule_id MUST be a 64-hex capsule_id (§5.4.4)",
				Severity: "error", Check: mkCheck(6),
			})
		}
		if _, ok := chain["relation"]; !ok {
			findings = append(findings, Finding{
				Code:     "missing_required_field",
				Detail:   "chain.relation is REQUIRED when a chain block is present (§5.4.4)",
				Severity: "error", Check: mkCheck(6),
			})
		}
		if store == nil {
			findings = append(findings, Finding{
				Code:     "chain_check_store_level",
				Detail:   "chain parent-existence and concurrent-supersedes are store-level checks (§6); not run without a store",
				Severity: "info", Check: mkCheck(6),
			})
		} else {
			ids := storeIDs(store)
			if parentStr, ok := parent.(string); ok && !ids[parentStr] {
				findings = append(findings, Finding{
					Code:     "chain_parent_missing",
					Detail:   fmt.Sprintf("chain parent %s not found in the store (§6)", parentStr),
					Severity: "error", Check: mkCheck(6),
				})
			}
		}
	}

	// ---- Check 7: Assurance reconciliation ----------------------------------
	ledgerMode := "standalone"
	if chain != nil {
		ledgerMode = "chained"
	}
	derived := map[string]string{
		"effect_mode":      effectMode,
		"attestation_mode": "self_attested",
		"ledger_mode":      ledgerMode,
	}

	stated := asMap(capsuleMap["assurance"])
	if stated != nil {
		if sm, ok := stated["effect_mode"].(string); ok {
			if r, known := effectModeRank[sm]; known {
				if derived_r, ok := effectModeRank[derived["effect_mode"]]; ok && r > derived_r {
					findings = append(findings, Finding{
						Code:     "assurance_overclaim",
						Detail:   fmt.Sprintf("claimed effect_mode %q but verifier derived %q (§5.3)", sm, derived["effect_mode"]),
						Severity: "error", Check: mkCheck(7),
					})
				}
			}
		}
		if sa, ok := stated["attestation_mode"].(string); ok {
			if r, known := attestationRank[sa]; known {
				if r > attestationRank[derived["attestation_mode"]] {
					findings = append(findings, Finding{
						Code:     "assurance_overclaim",
						Detail:   fmt.Sprintf("claimed attestation_mode %q but no Receipt verified at this layer (§5.3)", sa),
						Severity: "info", Check: mkCheck(7),
					})
				}
			}
		}
		if sl, ok := stated["ledger_mode"].(string); ok {
			if r, known := ledgerModeRank[sl]; known {
				if r > ledgerModeRank[derived["ledger_mode"]] {
					findings = append(findings, Finding{
						Code:     "assurance_overclaim",
						Detail:   fmt.Sprintf("claimed ledger_mode %q but verifier derived %q (§5.3)", sl, derived["ledger_mode"]),
						Severity: "info", Check: mkCheck(7),
					})
				}
			}
		}
	}

	// ---- Check 8: Unknown registry values -----------------------------------
	for _, rf := range registryFields {
		blk := asMap(capsuleMap[rf.block])
		if blk == nil {
			continue
		}
		val, ok := blk[rf.member]
		if !ok || val == nil {
			continue
		}
		valStr, isStr := val.(string)
		if !isStr {
			continue
		}
		seeded := regs[rf.reg]
		if !seeded[valStr] {
			findings = append(findings, Finding{
				Code: "unknown_registry_value",
				Detail: fmt.Sprintf("%s.%s=%q is not a seeded %s value; informational, not rejected (§12)",
					rf.block, rf.member, valStr, rf.reg),
				Severity: "info", Check: mkCheck(8),
			})
			if rf.reg == "effect_attestation" {
				findings = append(findings, Finding{
					Code:     "effect_attestation_graded_floor",
					Detail:   "unknown effect_attestation graded no stronger than 'runtime_claimed' (§5.2)",
					Severity: "info", Check: mkCheck(8),
				})
			}
		}
	}

	ok := true
	for _, f := range findings {
		if f.Severity == "error" {
			ok = false
			break
		}
	}
	return VerificationResult{OK: ok, Findings: findings, Assurance: derived, CapsuleID: recomputedID}
}

// Verify runs Class 1 verification (§6) over a single Capsule. Never panics.
// store is the ledger of capsules for chain-level checks; nil means store-level
// checks are skipped.
// regs is the loaded registry map; nil means the registries are loaded from REGISTRY.md.
func Verify(capsule interface{}, store []interface{}, regs map[string]map[string]bool) (result VerificationResult) {
	if regs == nil {
		var err error
		regs, err = registries.Load("")
		if err != nil {
			return VerificationResult{
				OK: false,
				Findings: []Finding{{
					Code: "verifier_internal_error", Detail: err.Error(), Severity: "error",
				}},
			}
		}
	}
	defer func() {
		if r := recover(); r != nil {
			result = VerificationResult{
				OK: false,
				Findings: []Finding{{
					Code:     "verifier_internal_error",
					Detail:   fmt.Sprintf("%v", r),
					Severity: "error",
				}},
			}
		}
	}()
	return verify(capsule, store, regs)
}

// VerifyStore verifies a ledger of Capsules in order, running the store-level chain
// checks of §6/§5.4.4 (parent existence + concurrent-supersedes).
func VerifyStore(capsules []interface{}, regs map[string]map[string]bool) []VerificationResult {
	if regs == nil {
		var err error
		regs, err = registries.Load("")
		if err != nil {
			out := make([]VerificationResult, len(capsules))
			for i := range out {
				out[i] = VerificationResult{
					OK: false,
					Findings: []Finding{{
						Code: "verifier_internal_error", Detail: err.Error(), Severity: "error",
					}},
				}
			}
			return out
		}
	}

	// Convert to []interface{} slice reference for store-IDs lookup.
	store := capsules

	results := make([]VerificationResult, len(capsules))
	for i, c := range capsules {
		results[i] = Verify(c, store, regs)
	}

	// Concurrent-supersedes (§5.4.4): earliest supersedes over a given parent is
	// authoritative; any later one surfaces as an (info) finding.
	seenParent := make(map[string]bool)
	for i, c := range capsules {
		cm, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		ch := asMap(cm["chain"])
		if ch == nil {
			continue
		}
		if rel, _ := ch["relation"].(string); rel != "supersedes" {
			continue
		}
		parent, _ := ch["parent_capsule_id"].(string)
		if parent == "" {
			continue
		}
		if seenParent[parent] {
			results[i].Findings = append(results[i].Findings, Finding{
				Code: "concurrent_supersedes",
				Detail: fmt.Sprintf(
					"a later supersedes over parent %s; the earliest is authoritative (§5.4.4)",
					parent,
				),
				Severity: "info", Check: mkCheck(6),
			})
		} else {
			seenParent[parent] = true
		}
	}
	return results
}

// StringSet converts a string map key to a sorted slice, for display.
func StringSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FindingKey returns (check, severity, code) as a tuple string for comparison.
func FindingKey(f Finding) string {
	check := "null"
	if f.Check != nil {
		check = fmt.Sprintf("%d", *f.Check)
	}
	return fmt.Sprintf("%s|%s|%s", check, f.Severity, f.Code)
}

// DecodeCapsuleJSON decodes a JSON byte slice into an interface{} with json.Number
// for numbers (preserving integer/float distinction).
func DecodeCapsuleJSON(data []byte) (interface{}, error) {
	var v interface{}
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}
