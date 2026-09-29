// SPDX-License-Identifier: BSD-3-Clause

package verify

import "fmt"

// referenceFindings checks draft-04 §5.5.5 without resolving cited artifacts.
// CPB owns digest representation and comparison context, so a foreign reference
// must not be constrained to AAC's SHA-256 hex encoding. Log coordinates are
// recorded claims only; Class 1 never authenticates their inclusion proofs.
// retentionStringMembers are the string-typed members of a references[]
// entry's retention object (§5.5.5), checked in this order within each entry.
var retentionStringMembers = []string{"declarant", "retained_until", "not_retained_after"}

// retentionFindings adds the check-1 findings for a references[] entry's
// retention (§5.5.5), in order: the object itself, its REQUIRED declarant
// (absent or null is missing, as for disposition.approver), the type of each
// member, and at least one bound.
func retentionFindings(raw interface{}, path string, add func(code, detail string, check int, severity string)) {
	retention := asMap(raw)
	if retention == nil {
		add("field_not_object", path+" MUST be a JSON object when present (§5.5.5)", 1, "error")
		return
	}
	for _, field := range retentionStringMembers {
		v, present := retention[field]
		if field == "declarant" && v == nil {
			add("missing_required_field", path+".declarant is REQUIRED (§5.5.5)", 1, "error")
		} else if _, isString := v.(string); present && !isString {
			add("field_not_string", path+"."+field+" MUST be a string when present (§5.5.5)", 1, "error")
		}
	}
	_, hasFloor := retention["retained_until"]
	_, hasCeiling := retention["not_retained_after"]
	if !hasFloor && !hasCeiling {
		add("retention_empty", path+" MUST carry retained_until or not_retained_after (§5.5.5)", 1, "error")
	}
}

func referenceFindings(capsule map[string]interface{}, known map[string]map[string]bool) []Finding {
	if capsule["format_version"] != "4" {
		return nil
	}
	raw, present := capsule["references"]
	if !present {
		return nil
	}
	var findings []Finding
	add := func(code, detail string, check int, severity string) {
		findings = append(findings, Finding{Code: code, Detail: detail, Check: mkCheck(check), Severity: severity})
	}
	refs, ok := raw.([]interface{})
	if !ok {
		add("references_malformed", "references MUST be an array (§5.5.5)", 1, "error")
		return findings
	}
	chain := asMap(capsule["chain"])
	parent, _ := chain["parent_capsule_id"].(string)
	for i, rawRef := range refs {
		path := fmt.Sprintf("references[%d]", i)
		ref := asMap(rawRef)
		if ref == nil {
			add("reference_malformed", path+" MUST be an object (§5.5.5)", 1, "error")
			continue
		}
		for _, field := range []string{"type", "digest_alg", "digest"} {
			if value, ok := ref[field].(string); !ok || value == "" {
				add("reference_malformed", path+"."+field+" MUST be a non-empty string (§5.5.5)", 1, "error")
			}
		}
		// Compare only a known AAC identity context, never equal-looking digests
		// belonging to a different artifact type or hash algorithm (CPB §7).
		digest, _ := ref["digest"].(string)
		if ref["type"] == "agent-action-capsule" && ref["digest_alg"] == "SHA-256" {
			if digest != "" && !isHex64(digest) {
				add("reference_malformed", path+".digest MUST be an AAC Capsule ID for agent-action-capsule/SHA-256 (§5.5.5)", 1, "error")
			}
			if parent != "" && digest == parent {
				add("reference_duplicates_chain_parent", path+" duplicates chain.parent_capsule_id (§5.5.5)", 6, "error")
			}
		}
		if rawPurpose, present := ref["citation_purpose"]; present {
			purpose, ok := rawPurpose.(string)
			if !ok || purpose == "" {
				add("reference_malformed", path+".citation_purpose MUST be a non-empty string (§5.5.5)", 1, "error")
			} else if !known["citation_purpose"][purpose] {
				add("unknown_registry_value", path+".citation_purpose is not seeded; informational, not rejected (§12)", 8, "info")
			}
		}
		if rawRetention, present := ref["retention"]; present {
			retentionFindings(rawRetention, path+".retention", add)
		}
		if rawCoordinates, present := ref["log_coordinates"]; present {
			coordinates := asMap(rawCoordinates)
			if coordinates == nil {
				add("reference_log_coordinates_malformed", path+".log_coordinates MUST be an object (§5.5.5)", 1, "error")
				continue
			}
			for _, field := range []string{"log_id", "leaf_index", "inclusion_proof"} {
				if value, ok := coordinates[field]; !ok || value == nil {
					add("reference_log_coordinates_malformed", path+".log_coordinates requires "+field+" (§5.5.5)", 1, "error")
				}
			}
		}
	}
	return findings
}
