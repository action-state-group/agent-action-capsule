// SPDX-License-Identifier: BSD-3-Clause

package evidenceresult

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sort"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/internal/rfc3339"
)

// revisionFindings is the Python reference's revision_findings: sections 3,
// 4.2 and 4.3's rules over buckets, rows, counts and dates. It sets each
// claim's InForce.
func revisionFindings(doc map[string]interface{}, claims []Claim) []string {
	var out []string
	aggregate, _ := doc["aggregate"].(map[string]interface{})
	coverage, _ := aggregate["coverage"].(map[string]interface{})

	later := map[string]bool{}
	dated := false
	for _, claim := range claims {
		dated = dated || claim.AppliesFrom != ""
	}
	if dated {
		generatedAt, _ := doc["generated_at"].(string)
		asOf, ok := utcDate(generatedAt)
		if !ok {
			return []string{fmt.Sprintf("generated_at %q is not an RFC 3339 date-time with an offset", generatedAt)}
		}
		for i := range claims {
			if claims[i].AppliesFrom == "" {
				continue
			}
			applies, ok := calendarDate(claims[i].AppliesFrom)
			switch {
			case !ok:
				out = append(out, fmt.Sprintf("%s: applies_from %q is not a calendar date", claims[i].ID, claims[i].AppliesFrom))
			case applies > asOf:
				later[claims[i].ID] = true
			}
		}
	}
	for i := range claims {
		claims[i].InForce = !later[claims[i].ID]
	}

	// The bucket partition: every in-force claim in exactly the bucket of
	// its verdict, a later claim in none, and no entry naming no claim.
	buckets, _ := aggregate["buckets"].(map[string]interface{})
	placed := map[string][]string{}
	for _, key := range sortedKeys(buckets) {
		ids, _ := buckets[key].([]interface{})
		for _, id := range ids {
			name, _ := id.(string)
			placed[name] = append(placed[name], key)
		}
	}
	for _, claim := range claims {
		where, ok := placed[claim.ID]
		delete(placed, claim.ID)
		switch {
		case later[claim.ID]:
			if ok {
				out = append(out, fmt.Sprintf("%s is not yet in force but is in buckets %v", claim.ID, where))
			}
		case len(where) != 1 || where[0] != claim.Verdict:
			out = append(out, fmt.Sprintf("%s (%s) is in buckets %v", claim.ID, claim.Verdict, where))
		}
	}
	for _, id := range sortedKeys(placed) {
		out = append(out, fmt.Sprintf("buckets name %q, which has no claim", id))
	}

	// One value per requirement: its claims copy the same switch and date.
	type row struct{ contract, requirement string }
	var order []row
	rows := map[row][]Claim{}
	for _, claim := range claims {
		key := row{claim.ContractRef, claim.RequirementRef}
		if _, seen := rows[key]; !seen {
			order = append(order, key)
		}
		rows[key] = append(rows[key], claim)
	}
	for _, key := range order {
		members := rows[key]
		for _, member := range []string{"out_of_scope_allowed", "applies_from"} {
			for _, claim := range members[1:] {
				if member == "out_of_scope_allowed" && claim.OutOfScopeAllowed != members[0].OutOfScopeAllowed ||
					member == "applies_from" && claim.AppliesFrom != members[0].AppliesFrom {
					out = append(out, fmt.Sprintf("%s %s: its claims disagree on %s", key.contract, key.requirement, member))
					break
				}
			}
		}
	}

	inForce, unknown := 0, 0
	for _, claim := range claims {
		if !later[claim.ID] {
			inForce++
			if claim.Sufficiency == "UNKNOWN" {
				unknown++
			}
		}
	}
	if !equalsInt(coverage["evaluated_population"], inForce) {
		out = append(out, fmt.Sprintf("evaluated_population %v, but %d in-force claim(s)", coverage["evaluated_population"], inForce))
	}
	if !equalsInt(coverage["unknown_count"], unknown) {
		out = append(out, fmt.Sprintf("unknown_count %v, but %d in-force UNKNOWN claim(s)", coverage["unknown_count"], unknown))
	}
	stated, present := coverage["not_yet_in_force"]
	if len(later) > 0 && !equalsInt(stated, len(later)) {
		out = append(out, fmt.Sprintf("not_yet_in_force %v, but %d later claim(s)", stated, len(later)))
	}
	if len(later) == 0 && present {
		out = append(out, "not_yet_in_force is present, but no claim is later")
	}

	// Section 3's requirements_covered: every claimed requirement listed,
	// and the listed ones no claim cites at most excluded_not_applicable.
	if covered, ok := coverage["requirements_covered"].([]interface{}); ok {
		listed := map[row]bool{}
		for _, item := range covered {
			ref, _ := item.(map[string]interface{})
			contract, _ := ref["contract_ref"].(string)
			requirement, _ := ref["requirement_ref"].(string)
			listed[row{contract, requirement}] = true
		}
		var missing []string
		for _, key := range order {
			if !listed[key] {
				missing = append(missing, fmt.Sprintf("%s %s: a claim cites it, but requirements_covered does not list it", key.contract, key.requirement))
			}
		}
		sort.Strings(missing)
		out = append(out, missing...)
		unclaimed := 0
		for key := range listed {
			if _, cited := rows[key]; !cited {
				unclaimed++
			}
		}
		if excluded, ok := number(coverage["excluded_not_applicable"]); !ok || big.NewRat(int64(unclaimed), 1).Cmp(excluded) > 0 {
			out = append(out, fmt.Sprintf("requirements_covered lists %d requirement(s) no claim cites, but excluded_not_applicable is %v", unclaimed, coverage["excluded_not_applicable"]))
		}
	}
	return out
}

// coverageFindings is the Python reference's coverage_findings: section
// 7.1's rules over a coverage_report, which the schema cannot express.
func coverageFindings(doc map[string]interface{}) []string {
	report, ok := doc["coverage_report"].(map[string]interface{})
	if !ok {
		return nil
	}
	var out []string
	claims := map[string]map[string]interface{}{}
	rawClaims, _ := doc["claims"].([]interface{})
	for _, item := range rawClaims {
		claim, _ := item.(map[string]interface{})
		id, _ := claim["id"].(string)
		claims[id] = claim
	}
	rows, _ := report["requirements"].([]interface{})
	satisfied, withGaps, gaps, withoutRemedy := 0, 0, 0, 0
	for _, item := range rows {
		row, _ := item.(map[string]interface{})
		ref, _ := row["requirement_ref"].(string)
		ids, _ := row["claim_ids"].([]interface{})
		for _, id := range ids {
			name, _ := id.(string)
			claim, known := claims[name]
			switch {
			case !known:
				out = append(out, fmt.Sprintf("%s: claim_ids names %q, which has no claim", ref, name))
			case claim["requirement_ref"] != ref || claim["contract_ref"] != report["contract_ref"]:
				out = append(out, fmt.Sprintf("%s: claim %q is for another requirement or contract", ref, name))
			}
		}
		distinct := map[string]bool{}
		sources, _ := row["sources"].([]interface{})
		for _, item := range sources {
			src, _ := item.(map[string]interface{})
			evidence, _ := src["evidence"].([]interface{})
			if !sumEquals(src["record_count"], src["contemporaneous_count"], src["backfilled_count"]) {
				out = append(out, fmt.Sprintf("%s/%v: contemporaneous + backfilled != record_count", ref, src["source"]))
			}
			if !equalsInt(src["record_count"], len(evidence)) {
				out = append(out, fmt.Sprintf("%s/%v: evidence digests != record_count", ref, src["source"]))
			}
			for _, d := range evidence {
				distinct[digestOf(d)] = true
			}
		}
		ind, _ := row["independence"].(map[string]interface{})
		independent, _ := number(ind["independent_producers"])
		required, _ := number(ind["required_producers"])
		reached := independent != nil && required != nil && independent.Cmp(required) >= 0
		counted := new(big.Rat)
		for _, member := range []string{"independent_producers", "correlated_records", "unattributed_records"} {
			if n, ok := number(ind[member]); ok {
				counted.Add(counted, n)
			}
		}
		if counted.Cmp(big.NewRat(int64(len(distinct)), 1)) != 0 {
			out = append(out, fmt.Sprintf("%s: independent_producers + correlated_records + unattributed_records != %d distinct records", ref, len(distinct)))
		}
		if (ind["producer_basis"] == "none") != equalsInt(ind["independent_producers"], 0) {
			out = append(out, fmt.Sprintf("%s: producer_basis %v disagrees with independent_producers", ref, ind["producer_basis"]))
		}
		if met, _ := ind["met"].(bool); met != reached {
			out = append(out, fmt.Sprintf("%s: independence.met is %t but %v producer(s) against %v required -- records from one producer correlate, they do not corroborate",
				ref, met, ind["independent_producers"], ind["required_producers"]))
		}
		if row["status"] == "SATISFIED" {
			satisfied++
		}
		rowGaps, _ := row["gaps"].([]interface{})
		if len(rowGaps) > 0 {
			withGaps++
		}
		gaps += len(rowGaps)
		for _, item := range rowGaps {
			if gap, _ := item.(map[string]interface{}); gap["remedy"] == nil {
				withoutRemedy++
			}
		}
	}
	expected := map[string]int{
		"requirements":        len(rows),
		"satisfied":           satisfied,
		"with_gaps":           withGaps,
		"gaps":                gaps,
		"gaps_without_remedy": withoutRemedy,
	}
	summary, _ := report["summary"].(map[string]interface{})
	recomputes := len(summary) == len(expected)
	for key, want := range expected {
		recomputes = recomputes && equalsInt(summary[key], want)
	}
	if !recomputes {
		out = append(out, fmt.Sprintf("summary %v does not recompute; expected %v", report["summary"], expected))
	}
	return out
}

// The link types that make a Close's state (section 4.1).
const (
	linkAcknowledges = "acknowledges"
	linkRebuts       = "rebuts"
)

// counterpartyField is the record-header member naming the store a record
// was committed in; the counterparty rule keys on it.
const counterpartyField = "book_id"

// closeFindings is the Python reference's close_state_findings: every close
// claim's state recomputed from the inbound links at the Close it cites. Any
// counterparty `rebuts` link reads CONTESTED, else any counterparty
// `acknowledges` link AGREED, else UNILATERAL. A link counts only from a
// record whose book_id is present, differs from the Close's, and equals the
// claim's named peer; a Close with no book_id accepts no linker.
func closeFindings(doc map[string]interface{}, claims []Claim, records []map[string]interface{}) []string {
	var out []string
	byDigest := map[string]map[string]interface{}{}
	var order []string
	digested := false
	for _, claim := range claims {
		if claim.Type != TypeClose {
			continue
		}
		if !digested {
			digested = true
			for i, record := range records {
				digest, err := canonical.JSONDigest(record)
				if err != nil {
					out = append(out, fmt.Sprintf("records[%d] cannot be digested: %v", i, err))
					continue
				}
				if _, seen := byDigest[digest]; !seen {
					order = append(order, digest)
				}
				byDigest[digest] = record
			}
		}
		rawClaims, _ := doc["claims"].([]interface{})
		object, _ := rawClaims[claim.Index].(map[string]interface{})
		body, _ := object["close"].(map[string]interface{})
		c := claim.Close

		inEvidence := map[string]bool{}
		for _, d := range claim.Evidence {
			inEvidence[d] = true
		}
		for _, ref := range []struct{ field, digest string }{{"close_ref", c.Ref}, {"peer_close_ref", c.PeerRef}} {
			if ref.digest != "" && !inEvidence[ref.digest] {
				out = append(out, fmt.Sprintf("claims[%d].close.%s (%s...) does not resolve inside the claim's evidence[]", claim.Index, ref.field, prefix(ref.digest)))
			}
		}
		closeRecord, ok := byDigest[c.Ref]
		if !ok {
			out = append(out, fmt.Sprintf("claims[%d].close.close_ref names no record among the records supplied; its state cannot be recomputed", claim.Index))
			continue
		}

		closeBook := closeRecord[counterpartyField]
		linking := map[string]map[string]bool{}
		for _, digest := range order {
			record := byDigest[digest]
			book := record[counterpartyField]
			counterparty := closeBook != nil && book != nil && !jsonEqual(book, closeBook) && jsonEqual(book, body["peer"])
			links, _ := record["links"].([]interface{})
			for _, item := range links {
				link, _ := item.(map[string]interface{})
				kind, _ := link["type"].(string)
				if !counterparty || link["target"] != c.Ref || (kind != linkAcknowledges && kind != linkRebuts) {
					continue
				}
				if linking[digest] == nil {
					linking[digest] = map[string]bool{}
				}
				linking[digest][kind] = true
			}
		}
		derived := "UNILATERAL"
		for _, kinds := range linking {
			if kinds[linkRebuts] {
				derived = "CONTESTED"
				break
			}
			if kinds[linkAcknowledges] {
				derived = "AGREED"
			}
		}
		if derived != c.State {
			out = append(out, fmt.Sprintf("claims[%d].close.close_state is asserted %s but the cited Close's counterparty links read %s", claim.Index, c.State, derived))
			continue
		}
		if derived == "CONTESTED" && claim.Verdict == "met" {
			out = append(out, fmt.Sprintf("claims[%d] is CONTESTED by the cited Close's inbound links but carries verdict `met` -- a contested Close never counts as met", claim.Index))
		}
		if derived == "AGREED" || derived == "CONTESTED" {
			wanted := linkAcknowledges
			if derived == "CONTESTED" {
				wanted = linkRebuts
			}
			if !linking[c.PeerRef][wanted] {
				out = append(out, fmt.Sprintf("claims[%d].close.peer_close_ref is not the digest of a counterparty record carrying the `%s` link that makes this Close %s", claim.Index, wanted, derived))
			}
		}
	}
	return out
}

// The record versions a calibration claim cites (section 4.1).
const (
	calibrationSummary = "calibration-summary/v1"
	humanRating        = "human-rating/v1"
)

// calibrationFindings is the Python reference's calibration_findings: every
// calibration claim's evidence[] cites exactly one calibration-summary/v1
// record and otherwise only human-rating/v1 records, each read by its
// record_version. A digest cited twice is one citation.
func calibrationFindings(claims []Claim, records []map[string]interface{}) []string {
	var out []string
	var byDigest map[string]map[string]interface{}
	for _, claim := range claims {
		if claim.Type != TypeCalibration {
			continue
		}
		if byDigest == nil {
			byDigest = map[string]map[string]interface{}{}
			for i, record := range records {
				digest, err := canonical.JSONDigest(record)
				if err != nil {
					out = append(out, fmt.Sprintf("records[%d] cannot be digested: %v", i, err))
					continue
				}
				byDigest[digest] = record
			}
		}
		seen := map[string]bool{}
		summaries := 0
		for _, digest := range claim.Evidence {
			if seen[digest] {
				continue
			}
			seen[digest] = true
			record, ok := byDigest[digest]
			if !ok {
				out = append(out, fmt.Sprintf("claims[%d] cites %s..., which names no record among the records supplied; its kind cannot be read", claim.Index, prefix(digest)))
				continue
			}
			switch kind := record["record_version"]; kind {
			case calibrationSummary:
				summaries++
			case humanRating:
			default:
				out = append(out, fmt.Sprintf("claims[%d] cites %s..., a record of kind %v; a calibration claim cites only %s and %s records", claim.Index, prefix(digest), kind, calibrationSummary, humanRating))
			}
		}
		if summaries != 1 {
			out = append(out, fmt.Sprintf("claims[%d] cites %d %s record(s); a calibration claim cites exactly one", claim.Index, summaries, calibrationSummary))
		}
	}
	return out
}

func prefix(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

// jsonEqual compares two decoded JSON values by their canonical form.
func jsonEqual(a, b interface{}) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	x, errA := canonical.JCS(a)
	y, errB := canonical.JCS(b)
	return errA == nil && errB == nil && string(x) == string(y)
}

// number reads a JSON number exactly. A count is compared by value, as the
// Python reference compares it: 3, 3.0 and 3e0 are the same count.
func number(v interface{}) (*big.Rat, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return nil, false
	}
	return new(big.Rat).SetString(n.String())
}

func equalsInt(v interface{}, want int) bool {
	n, ok := number(v)
	return ok && n.Cmp(big.NewRat(int64(want), 1)) == 0
}

func sumEquals(total interface{}, parts ...interface{}) bool {
	want, ok := number(total)
	if !ok {
		return false
	}
	sum := new(big.Rat)
	for _, part := range parts {
		n, ok := number(part)
		if !ok {
			return false
		}
		sum.Add(sum, n)
	}
	return sum.Cmp(want) == 0
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// The date rules are shared with go/evidenceplan.
type day = rfc3339.Day

var (
	utcDate      = rfc3339.UTCDate
	calendarDate = rfc3339.CalendarDate
)
