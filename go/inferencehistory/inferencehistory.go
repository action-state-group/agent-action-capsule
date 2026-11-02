// SPDX-License-Identifier: Apache-2.0

// Package inferencehistory evaluates a History under the Inference-Service
// History Profile v0 (spec/inference-service-history-profile-v0.md,
// inference-service-history/0, cited as ISH), at its Standard and Detailed
// levels: the acceptance of an answer under the Minimum Evidence
// Interoperability Profile (ISH §8.1), the History properties (ISH §8.3),
// the coverage report (ISH §4.2), what a verifier shows of witness
// receipts (ISH §5.2) and of exchanges (ISH §7.2), and period_fixed
// (ISH §6.3).
//
// Each request and reply is verified by evidencerequest.Verifier, under
// whichever interop profile the verifier's contract and policy name. The
// vectors of vectors/inference-service-history-v0 and
// vectors/inference-service-history-v0-interop-v1 are the package's tests.
package inferencehistory

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/action-state-group/agent-action-capsule/go/internal/ed25519strict"
)

// Profile is the History profile's identifier, the `profile` member of a
// definition (ISH §4.1).
const Profile = "inference-service-history/0"

// The History levels (ISH §3).
const (
	Standard = "standard"
	Detailed = "detailed"
)

// The labels of ISH §7.1, weakest first.
const (
	SelfReported  = "self_reported"
	PeerConfirmed = "peer_confirmed"
	Corroborated  = "corroborated"
)

// maxLengthS keeps a period length within time.Duration.
const maxLengthS = uint64(1<<63-1) / uint64(time.Second)

const (
	peerShown  = "peer-confirmed; not corroborating (independence not established)"
	relativeTo = "the node's stream at the anchor, under all_records; completeness not established: " +
		"counts not checked against records"
)

var (
	common = []string{"profile", "name", "kind", "level", "embeds", "subjects", "members", "reads", "excludes",
		"coverage_declaration", "spec"}
	policyMembers = []string{"epoch", "floor", "length_s", "min_length_s", "suppression"}
	// artifactFixed are the Artifact members every level carries (ISH §8.2).
	artifactFixed = []string{"anchor", "declared", "derivation", "evidence_stream", "history_card",
		"history_card_digest", "subject"}
	units = []string{"exchanges_served", "exchanges_requested", "exchanges_unattributed", "checkpoints",
		"witness_receipts", "referee_verdicts", "records"}
	rank     = map[string]int{SelfReported: 0, PeerConfirmed: 1, Corroborated: 2}
	roleUnit = map[string]string{"served": "exchanges_served", "requested": "exchanges_requested"}
	mustPass = []string{"profile_version", "envelope_signature", "responder_trust", "issued_at_form",
		"request_binding", "subject_binding", "artifact_digest", "anchor_match"}
	namePattern = regexp.MustCompile(`^[a-z0-9_]+/[0-9]+$`)
)

// Pins are the relying party's service-history keys, which the interop
// profile's trust policy does not name (ISH §9): the log keys that sign a
// card's checkpoints, the witness keys whose receipts are counted, and the
// peer keys whose halves confirm an exchange. Each is a lowercase hex
// Ed25519 public key.
type Pins struct {
	LogKeys     []string
	WitnessKeys []string
	PeerKeys    []string
}

// Exchange is one request and the reply to it, as the octets carried.
type Exchange struct {
	Request evidencerequest.Message
	Reply   evidencerequest.Message
}

// ExchangeResult is the verifier's result for one exchange as ISH §8.1
// reads it. Subject and Accepted are set only for an envelope; Reason only
// for a refusal.
type ExchangeResult struct {
	Reply    *evidencerequest.ReplyResult
	Subject  any
	Reason   any
	Accepted bool

	env map[string]any
}

// WitnessShown is what a verifier shows of witness receipts (ISH §5.2).
type WitnessShown struct {
	Checkpoints        int
	ReceiptsCounted    int
	ReceiptsNotCounted []NotCounted
}

// NotCounted is one receipt left out of the count, with the checkpoint's
// position in the card.
type NotCounted struct {
	Checkpoint int
	Reason     string
}

// Coverage is the coverage report (ISH §4.2).
type Coverage struct {
	DeclaredKind string
	Properties   map[string]string
	RelativeTo   string
}

// ExchangeShown is what a verifier shows of one Detailed exchange (ISH
// §7.2): the label the node claimed, the label the evidence supports and
// how it is shown. IssuerIndependence is empty when the evidence names
// none.
type ExchangeShown struct {
	ClientNonce        any
	Claimed            any
	Derived            string
	ShownAs            string
	IssuerIndependence string
}

// Result is one History evaluated: the exchange, the History properties,
// the coverage report, what is shown, and whether the History is accepted.
// Exchanges is set only at the Detailed level.
type Result struct {
	Exchange   ExchangeResult
	Properties map[string]string
	Coverage   Coverage
	Witness    WitnessShown
	Exchanges  []ExchangeShown
	Accepted   bool
}

// PairResult is two or more Histories of one node compared (ISH §6.3).
type PairResult struct {
	Exchanges   []ExchangeResult
	PeriodFixed string
	Accepted    bool
}

// ExchangeOf verifies one request and reply with v and reads the result as
// ISH §8.1 does. requirements are the contract requirements evaluated
// (nil: every one).
func ExchangeOf(v *evidencerequest.Verifier, x Exchange, requirements []string) (ExchangeResult, error) {
	verified, err := v.Verify([]evidencerequest.Exchange{{Request: x.Request, Replies: []evidencerequest.Message{x.Reply}}},
		evidencerequest.VerifyOptions{Requirements: requirements})
	if err != nil {
		return ExchangeResult{}, err
	}
	if len(verified.Exchanges) != 1 || len(verified.Exchanges[0].Replies) != 1 {
		return ExchangeResult{}, errors.New("inferencehistory: the verifier returned no result for the exchange")
	}
	r := verified.Exchanges[0].Replies[0]
	out := ExchangeResult{Reply: r}
	switch r.MessageType {
	case "refusal":
		out.Reason = r.Reason
	case "envelope":
		out.Subject = r.Envelope["subject"]
		out.Accepted = acceptedEnvelope(r)
		out.env = withArtifact(r)
	}
	return out, nil
}

// acceptedEnvelope is ISH §8.1: the required envelope properties PASS,
// anchor_inclusion NOT_CHECKED, and no verification member.
func acceptedEnvelope(r *evidencerequest.ReplyResult) bool {
	for _, p := range mustPass {
		if r.Status(p) != evidencerequest.StatusPass {
			return false
		}
	}
	_, hasVerification := r.Envelope["verification"]
	return r.Status("anchor_inclusion") == evidencerequest.StatusNotChecked && !hasVerification
}

// withArtifact is the envelope with its Artifact decoded as the member
// "artifact"; the member is absent when the Artifact is not UTF-8 of JCS of
// one JSON value (ISH §8.2).
func withArtifact(r *evidencerequest.ReplyResult) map[string]any {
	env := map[string]any{}
	for k, v := range r.Envelope {
		env[k] = v
	}
	if a := artifactValue(r.Artifact); a != nil {
		env["artifact"] = a
	}
	return env
}

// artifactValue reads an Artifact: nil unless the octets are exactly the JCS
// of one JSON value, so a duplicate member, trailing data or any other
// encoding cannot carry bytes that artifact_form never reads.
func artifactValue(octets []byte) any {
	if octets == nil {
		return nil
	}
	v, err := evidencerequest.DecodeJSON(octets)
	if err != nil {
		return nil
	}
	again, err := evidencerequest.EncodeJCS(v)
	if err != nil || !bytes.Equal(again, octets) {
		return nil
	}
	return v
}

// Evaluate verifies the exchange with v and checks the History properties
// (ISH §8.3) of its answer against definition, the definition the
// recipient holds, with pins. A reply that is no envelope is not accepted
// and carries no properties.
func Evaluate(v *evidencerequest.Verifier, pins Pins, definition any, x Exchange, requirements []string) (Result, error) {
	ex, err := ExchangeOf(v, x, requirements)
	if err != nil {
		return Result{}, err
	}
	out := Result{Exchange: ex}
	if ex.env == nil || ex.Reply.MessageType != "envelope" {
		return out, nil
	}
	d := jsonModel(definition)
	out.Properties = historyProperties(pins, d, ex.env)
	out.Coverage = coverageReport(d, ex.env)
	out.Witness = witnessShown(pins, ex.env)
	if str(get(d, "level")) == Detailed {
		out.Exchanges = exchangesShown(pins, ex.env)
	}
	out.Accepted = ex.Accepted
	for _, s := range out.Properties {
		out.Accepted = out.Accepted && s == evidencerequest.StatusPass
	}
	for _, s := range out.Coverage.Properties {
		out.Accepted = out.Accepted && s != evidencerequest.StatusFail
	}
	return out, nil
}

// EvaluatePair evaluates each History, whose definitions are definitions
// in order, and checks period_fixed across them (ISH §6.3). It is
// accepted when every exchange is, every History's properties PASS and
// period_fixed does.
func EvaluatePair(v *evidencerequest.Verifier, pins Pins, definitions []any, exchanges []Exchange, requirements []string) (PairResult, error) {
	if len(definitions) != len(exchanges) {
		return PairResult{}, errors.New("inferencehistory: a definition for each exchange")
	}
	var out PairResult
	var envs []map[string]any
	out.Accepted = true
	for i, x := range exchanges {
		ex, err := ExchangeOf(v, x, requirements)
		if err != nil {
			return PairResult{}, err
		}
		out.Exchanges = append(out.Exchanges, ex)
		out.Accepted = out.Accepted && ex.Accepted
		if ex.env == nil {
			out.Accepted = false
			continue
		}
		envs = append(envs, ex.env)
		for _, s := range historyProperties(pins, jsonModel(definitions[i]), ex.env) {
			out.Accepted = out.Accepted && s == evidencerequest.StatusPass
		}
	}
	out.PeriodFixed = periodFixed(envs)
	out.Accepted = out.Accepted && out.PeriodFixed == evidencerequest.StatusPass
	return out, nil
}

// ---------------------------------------------------------------------------
// The History properties (ISH §8.3)
// ---------------------------------------------------------------------------

func status(ok bool) string {
	if ok {
		return evidencerequest.StatusPass
	}
	return evidencerequest.StatusFail
}

func historyProperties(pins Pins, d any, env map[string]any) map[string]string {
	form := definitionForm(d)
	props := map[string]string{
		"definition_form":    status(form),
		"definition_binding": status(equal(env["derivation"], digest(d))),
	}
	if !form {
		return props
	}
	shape := artifactForm(d, env)
	props["artifact_form"] = status(shape)
	if !shape {
		return props
	}
	props["history_card_content"] = status(cardContent(pins, env))
	props["units"] = status(unitsOK(d, env))
	props["labels"] = status(labelsOK(pins, env))
	if str(get(d, "level")) == Standard {
		props["period_alignment"] = status(periodsOK(d, env))
		props["period_anchor"] = status(anchorOK(d, env))
		props["period_floor"] = status(floorOK(d, env))
	}
	return props
}

func definitionForm(d any) bool {
	m, ok := d.(map[string]any)
	if !ok {
		return false
	}
	level := str(m["level"])
	switch level {
	case Standard:
		if !hasKeys(m, append(slices.Clone(common), "period_policy")) {
			return false
		}
	case Detailed:
		if !hasKeys(m, append(slices.Clone(common), "recipient")) {
			return false
		}
	default:
		return false
	}
	if m["profile"] != Profile || m["kind"] != "projection" || !equal(m["embeds"], []any{"history_card/1"}) ||
		!equal(m["subjects"], []any{"full_history"}) {
		return false
	}
	name, _ := m["name"].(string)
	var wantCoverage any = map[string]any{"kind": "holder_selected"}
	if level == Standard {
		wantCoverage = map[string]any{"kind": "stream_interval", "rule": "all_records"}
	}
	if !namePattern.MatchString(name) || !equal(m["coverage_declaration"], wantCoverage) {
		return false
	}
	members, ok := m["members"].([]any)
	if !ok {
		return false
	}
	seen := map[string]bool{}
	hasCard := false
	var union []any
	for _, raw := range members {
		mem, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		memberName := string(jcs(mem["name"]))
		if seen[memberName] {
			return false
		}
		seen[memberName] = true
		if mem["name"] == "history_card" && mem["required"] == true && mem["derivation"] == "history_card/1" {
			hasCard = true
		}
		for k := range mem {
			if !slices.Contains([]string{"name", "required", "derivation", "reads", "units", "claims"}, k) {
				return false
			}
		}
		us, ok := mem["units"].([]any)
		if !ok || len(us) == 0 {
			return false
		}
		for _, u := range us {
			if !slices.Contains(units, str(get(u, "unit"))) {
				return false
			}
		}
		reads, ok := mem["reads"].([]any)
		if !ok {
			return false
		}
		for _, r := range reads {
			if !slices.ContainsFunc(union, func(x any) bool { return equal(x, r) }) {
				union = append(union, r)
			}
		}
	}
	if !hasCard || !equal(m["reads"], nonNil(union)) {
		return false
	}
	if level == Detailed {
		recipient, ok := m["recipient"].(string)
		return ok && recipient != ""
	}
	p, ok := m["period_policy"].(map[string]any)
	if !ok || !hasKeys(p, policyMembers) || p["suppression"] != "complementary" {
		return false
	}
	length, ok1 := evidencerequest.UintValue(p["length_s"])
	minLength, ok2 := evidencerequest.UintValue(p["min_length_s"])
	floor, ok3 := evidencerequest.UintValue(p["floor"])
	return slices.Contains(list(m["excludes"]), any("requester identity")) && ok1 && ok2 && ok3 &&
		length >= minLength && minLength > 0 && floor >= 1
}

func artifactForm(d any, env map[string]any) bool {
	a, ok := env["artifact"].(map[string]any)
	if !ok {
		return false
	}
	names := map[string]bool{}
	required := map[string]bool{}
	for _, raw := range list(get(d, "members")) {
		n := str(get(raw, "name"))
		names[n] = true
		if get(raw, "required") == true {
			required[n] = true
		}
	}
	declared, ok := a["declared"].([]any)
	if !ok {
		return false
	}
	var ds []string
	for i, x := range declared {
		s, ok := x.(string)
		if !ok || !names[s] || (i > 0 && ds[i-1] >= s) {
			return false
		}
		ds = append(ds, s)
	}
	for n := range required {
		if !slices.Contains(ds, n) {
			return false
		}
	}
	want := slices.Clone(artifactFixed)
	if str(get(d, "level")) == Standard {
		want = append(want, "coverage_declaration")
	}
	for _, n := range ds {
		if !slices.Contains(want, n) {
			want = append(want, n)
		}
	}
	if !hasKeys(a, want) {
		return false
	}
	anchor, _ := env["anchor"].(map[string]any)
	if !equal(a["anchor"], anchor["digest"]) || !equal(a["derivation"], env["derivation"]) || !equal(a["subject"], env["subject"]) {
		return false
	}
	if raw, ok := a["exchanges"]; ok {
		es, ok := raw.([]any)
		if !ok {
			return false
		}
		for _, e := range es {
			half, ok := halfOf(get(e, "half"))
			if !ok || !equal(half["producer"], env["responder"]) || !signedOK(half, "producer") ||
				!equal(half["client_nonce"], get(e, "client_nonce")) {
				return false
			}
			if _, isRole := roleUnit[str(half["role"])]; !isRole {
				return false
			}
		}
	}
	return true
}

// cardContent is ISH §5.2: the card's checkpoints are signed by a log key,
// in order, and end at the anchor; every receipt covers its checkpoint.
// Receipts under a witness key the pins do not hold are not counted.
func cardContent(pins Pins, env map[string]any) bool {
	a, _ := env["artifact"].(map[string]any)
	c, ok := a["history_card"].(map[string]any)
	if !ok || !equal(a["history_card_digest"], digest(c)) || !equal(c["anchor"], a["anchor"]) || c["derivation"] != "history_card/1" {
		return false
	}
	history, ok := c["history"].([]any)
	if !ok || len(history) == 0 {
		return false
	}
	var prev map[string]any
	for _, raw := range history {
		h, _ := raw.(map[string]any)
		cp, ok := h["checkpoint"].(map[string]any)
		if !ok {
			return false
		}
		if !slices.Contains(pins.LogKeys, str(cp["key_id"])) || !signedOK(cp, "key_id") {
			return false
		}
		if prev != nil {
			size, ok1 := evidencerequest.UintValue(cp["log_size"])
			prevSize, ok2 := evidencerequest.UintValue(prev["log_size"])
			at, ok3 := when(cp["timestamp"])
			prevAt, ok4 := when(prev["timestamp"])
			if !ok1 || !ok2 || !ok3 || !ok4 || size < prevSize || !at.After(prevAt) {
				return false
			}
		}
		receipts, ok := h["receipts"].([]any)
		if !ok {
			return false
		}
		for _, rr := range receipts {
			r, ok := rr.(map[string]any)
			if !ok || !equal(r["checkpoint"], digest(cp)) || !signedOK(r, "witness") {
				return false
			}
		}
		prev = cp
	}
	last, _ := history[len(history)-1].(map[string]any)
	return equal(digest(last["checkpoint"]), a["anchor"])
}

func witnessShown(pins Pins, env map[string]any) WitnessShown {
	history := list(get(get(env["artifact"], "history_card"), "history"))
	out := WitnessShown{Checkpoints: len(history)}
	for i, h := range history {
		for _, r := range list(get(h, "receipts")) {
			if slices.Contains(pins.WitnessKeys, str(get(r, "witness"))) {
				out.ReceiptsCounted++
			} else {
				out.ReceiptsNotCounted = append(out.ReceiptsNotCounted, NotCounted{Checkpoint: i, Reason: "witness key not configured"})
			}
		}
	}
	return out
}

// cells are the cells of every period, and false when period_counts is
// present but its periods or cells are not lists of objects.
func cells(env map[string]any) ([]map[string]any, bool) {
	if _, ok := asMap(env["artifact"])["period_counts"]; !ok {
		return nil, true
	}
	periods, ok := get(get(env["artifact"], "period_counts"), "periods").([]any)
	if !ok {
		return nil, false
	}
	var out []map[string]any
	for _, p := range periods {
		raw, ok := get(p, "cells").([]any)
		if !ok {
			return nil, false
		}
		for _, c := range raw {
			m, ok := c.(map[string]any)
			if !ok {
				return nil, false
			}
			out = append(out, m)
		}
	}
	return out, true
}

func unitsOK(d any, env map[string]any) bool {
	byMember := map[string]map[string]bool{}
	for _, raw := range list(get(d, "members")) {
		set := map[string]bool{}
		for _, u := range list(get(raw, "units")) {
			set[str(get(u, "unit"))] = true
		}
		byMember[str(get(raw, "name"))] = set
	}
	all, wellFormed := cells(env)
	if !wellFormed {
		return false
	}
	for _, c := range all {
		u := str(c["unit"])
		if !slices.Contains(units, u) || !byMember["period_counts"][u] {
			return false
		}
	}
	for _, e := range list(get(env["artifact"], "exchanges")) {
		half, ok := halfOf(get(e, "half"))
		if !ok {
			return false
		}
		unit := str(get(e, "unit"))
		if unit != roleUnit[str(half["role"])] || !byMember["exchanges"][unit] {
			return false
		}
	}
	return true
}

// derive is ISH §7.2: what one exchange's evidence supports, how it is
// shown, and issuer independence ("" when the evidence names none).
func derive(pins Pins, env map[string]any, e any) (label, shownAs, independence string) {
	peerRaw, ok := get(e, "peer_half").(map[string]any)
	if !ok {
		return SelfReported, "one-sided", ""
	}
	untrusted := func() (string, string, string) {
		return SelfReported, "peer half not verified under a trusted key", ""
	}
	peer, ok1 := halfOf(peerRaw)
	half, ok2 := halfOf(get(e, "half"))
	if !ok1 || !ok2 || !signedOK(peer, "producer") {
		return untrusted()
	}
	if equal(peer["producer"], env["responder"]) {
		return SelfReported, "redundant, not corroborating", evidencerequest.StatusFail
	}
	if !slices.Contains(pins.PeerKeys, str(peer["producer"])) {
		return untrusted()
	}
	cited := false
	sum := sha256.Sum256([]byte(str(peerRaw["octets_text"])))
	for _, r := range list(half["references"]) {
		if str(get(r, "citation_purpose")) == "counterparty_half" && str(get(r, "digest")) == hex.EncodeToString(sum[:]) {
			cited = true
		}
	}
	peerRole, halfRole := str(peer["role"]), str(half["role"])
	joined := equal(peer["client_nonce"], half["client_nonce"]) && cited &&
		((peerRole == "served" && halfRole == "requested") || (peerRole == "requested" && halfRole == "served"))
	if !joined {
		return SelfReported, "not joinable", ""
	}
	return PeerConfirmed, peerShown, evidencerequest.StatusNotChecked
}

func exchangesShown(pins Pins, env map[string]any) []ExchangeShown {
	var out []ExchangeShown
	for _, e := range list(get(env["artifact"], "exchanges")) {
		label, shownAs, independence := derive(pins, env, e)
		out = append(out, ExchangeShown{ClientNonce: get(e, "client_nonce"), Claimed: get(e, "label"),
			Derived: label, ShownAs: shownAs, IssuerIndependence: independence})
	}
	return out
}

// labelsOK is ISH §7.3: no label is stronger than its evidence. A Standard
// count is the node's own statement.
func labelsOK(pins Pins, env map[string]any) bool {
	all, wellFormed := cells(env)
	if !wellFormed {
		return false
	}
	for _, c := range all {
		if r, ok := rank[str(c["label"])]; !ok || r > 0 {
			return false
		}
	}
	shown := exchangesShown(pins, env)
	for i, e := range list(get(env["artifact"], "exchanges")) {
		claimed, ok := rank[str(get(e, "label"))]
		if !ok || claimed > rank[shown[i].Derived] {
			return false
		}
	}
	return true
}

// periodsOK is ISH §6.1: periods aligned to the epoch, the policy's
// length, sorted, closed at the anchor, and complete: no gap, from one
// holding the stream's first record to the last boundary at the anchor.
func periodsOK(d any, env map[string]any) bool {
	p := get(d, "period_policy")
	pc, ok := get(env["artifact"], "period_counts").(map[string]any)
	if !ok || !equal(pc["policy"], digest(p)) {
		return false
	}
	epoch, ok1 := when(get(p, "epoch"))
	lengthS, ok2 := evidencerequest.UintValue(get(p, "length_s"))
	history := list(get(get(env["artifact"], "history_card"), "history"))
	if !ok1 || !ok2 || lengthS == 0 || lengthS > maxLengthS || len(history) == 0 {
		return false
	}
	length := time.Duration(lengthS) * time.Second
	anchorTime, ok := when(get(get(history[len(history)-1], "checkpoint"), "timestamp"))
	if !ok {
		return false
	}
	periods, ok := pc["periods"].([]any)
	if !ok {
		return false
	}
	var prevTo time.Time
	for i, period := range periods {
		start, ok1 := when(get(period, "from"))
		end, ok2 := when(get(period, "to"))
		if !ok1 || !ok2 || start.Sub(epoch)%length != 0 || end.Sub(start) != length || end.After(anchorTime) {
			return false
		}
		if i > 0 && !start.Equal(prevTo) {
			return false
		}
		prevTo = end
	}
	// ISH §6.1 item 3: the stream's first record is committed before the
	// first checkpoint that commits a record, so the first period starts
	// before that checkpoint; the last ends at the last boundary.
	var first time.Time
	found := false
	for _, h := range history {
		cp := get(h, "checkpoint")
		if n, _ := evidencerequest.UintValue(get(cp, "log_size")); n != 0 {
			first, found = mustWhen(get(cp, "timestamp")), true
			break
		}
	}
	if !found {
		return len(periods) == 0
	}
	if len(periods) == 0 {
		return false
	}
	firstFrom, _ := when(get(periods[0], "from"))
	lastTo, _ := when(get(periods[len(periods)-1], "to"))
	return firstFrom.Before(first) && anchorTime.Sub(lastTo) < length
}

// anchorOK is ISH §6.1 item 2: the anchor's checkpoint time is a period
// boundary.
func anchorOK(d any, env map[string]any) bool {
	p := get(d, "period_policy")
	history := list(get(get(env["artifact"], "history_card"), "history"))
	if len(history) == 0 {
		return false
	}
	at, ok1 := when(get(get(history[len(history)-1], "checkpoint"), "timestamp"))
	epoch, ok2 := when(get(p, "epoch"))
	lengthS, ok3 := evidencerequest.UintValue(get(p, "length_s"))
	return ok1 && ok2 && ok3 && lengthS != 0 && lengthS <= maxLengthS && at.Sub(epoch)%(time.Duration(lengthS)*time.Second) == 0
}

// floorOK is ISH §6.2: a published cell is at least the floor; a suppressed
// cell has no value; a unit's total and all but one of its cells never
// stand published beside one suppressed cell.
func floorOK(d any, env map[string]any) bool {
	floor, ok := evidencerequest.UintValue(get(get(d, "period_policy"), "floor"))
	periods, isList := get(get(env["artifact"], "period_counts"), "periods").([]any)
	if !ok || !isList {
		return false
	}
	for _, period := range periods {
		raw, ok := get(period, "cells").([]any)
		if !ok {
			return false
		}
		var all []map[string]any
		for _, c := range raw {
			cell, ok := c.(map[string]any)
			if !ok {
				return false
			}
			all = append(all, cell)
		}
		for _, c := range all {
			_, suppressed := c["suppressed"]
			if _, hasValue := c["value"]; !hasValue || suppressed != (c["value"] == nil) {
				return false
			}
			if suppressed && c["suppressed"] != "below_floor" && c["suppressed"] != "complementary" {
				return false
			}
			if c["value"] != nil {
				if n, ok := evidencerequest.UintValue(c["value"]); !ok || n < floor {
					return false
				}
			}
		}
		perUnit := map[string]bool{}
		for _, c := range all {
			perUnit[str(c["unit"])] = true
		}
		for unit := range perUnit {
			var total map[string]any
			hidden := 0
			for _, c := range all {
				if str(c["unit"]) != unit {
					continue
				}
				if c["dimension"] == nil {
					if total == nil {
						total = c
					}
				} else if c["value"] == nil {
					hidden++
				}
			}
			if total != nil && total["value"] != nil && hidden == 1 {
				return false
			}
		}
	}
	return true
}

// coverageReport is ISH §4.2: the coverage declaration's checks.
func coverageReport(d any, env map[string]any) Coverage {
	if str(get(d, "level")) == Detailed {
		return Coverage{DeclaredKind: "holder_selected", Properties: map[string]string{"coverage_declaration_form": evidencerequest.StatusPass},
			RelativeTo: "not asserted"}
	}
	a, _ := env["artifact"].(map[string]any)
	dec, _ := a["coverage_declaration"].(map[string]any)
	want := get(d, "coverage_declaration")
	liveSet := list(dec["live_set"])
	interval, _ := dec["interval"].(map[string]any)
	form := dec != nil && hasKeys(dec, []string{"kind", "rule", "interval", "live_set"}) &&
		equal(dec["kind"], get(want, "kind")) && equal(dec["rule"], get(want, "rule")) &&
		hasKeys(interval, []string{"from", "to"}) && len(liveSet) == 1 &&
		hasKeys(asMap(liveSet[0]), []string{"stream", "checkpoint", "start", "count"}) &&
		equal(get(liveSet[0], "stream"), a["evidence_stream"]) &&
		(interval["from"] != nil || equal(get(liveSet[0], "start"), uint64(0)))
	if !form {
		return Coverage{DeclaredKind: "stream_interval", Properties: map[string]string{"coverage_declaration_form": evidencerequest.StatusFail},
			RelativeTo: relativeTo}
	}
	anchor, _ := env["anchor"].(map[string]any)
	ok := equal(interval["to"], anchor["digest"]) && !equal(interval["from"], interval["to"])
	return Coverage{DeclaredKind: "stream_interval", RelativeTo: relativeTo, Properties: map[string]string{
		"coverage_declaration_form":   evidencerequest.StatusPass,
		"coverage_declaration_anchor": status(ok),
		// ISH §4.2, SH-4: a count of records carries no records to compare.
		"coverage_declaration_population": evidencerequest.StatusNotChecked,
		"coverage_declaration_commitment": evidencerequest.StatusNotChecked,
	}}
}

// periodFixed is ISH §6.1 item 4: every period a History carries is
// carried, with the same cells, by every History at the same or a later
// anchor.
func periodFixed(envs []map[string]any) string {
	type key struct{ from, to string }
	periods := func(env map[string]any) map[key]string {
		out := map[key]string{}
		for _, p := range list(get(get(env["artifact"], "period_counts"), "periods")) {
			out[key{str(get(p, "from")), str(get(p, "to"))}] = string(jcs(get(p, "cells")))
		}
		return out
	}
	answeredAt := func(env map[string]any) time.Time {
		history := list(get(get(env["artifact"], "history_card"), "history"))
		if len(history) == 0 {
			return time.Time{}
		}
		return mustWhen(get(get(history[len(history)-1], "checkpoint"), "timestamp"))
	}
	for i, earlier := range envs {
		for j, later := range envs {
			if i != j && !answeredAt(later).Before(answeredAt(earlier)) {
				have := periods(later)
				for k, v := range periods(earlier) {
					if have[k] != v {
						return evidencerequest.StatusFail
					}
				}
			}
		}
	}
	return evidencerequest.StatusPass
}

// ---------------------------------------------------------------------------
// Helpers over decoded JSON
// ---------------------------------------------------------------------------

// halfOf decodes a half carried as {media_type, octets_text}.
func halfOf(v any) (map[string]any, bool) {
	text, ok := get(v, "octets_text").(string)
	if !ok {
		return nil, false
	}
	h, err := evidencerequest.DecodeJSON([]byte(text))
	m, isMap := h.(map[string]any)
	return m, err == nil && isMap
}

func signedOK(o map[string]any, member string) bool {
	key, err1 := hex.DecodeString(str(o[member]))
	sig, err2 := hex.DecodeString(str(o["sig"]))
	if err1 != nil || err2 != nil || len(key) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	body := make(map[string]any, len(o))
	for k, v := range o {
		if k != "sig" {
			body[k] = v
		}
	}
	data := jcs(body)
	return data != nil && ed25519strict.Verify(key, data, sig)
}

func when(v any) (time.Time, bool) {
	s, ok := v.(string)
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

func mustWhen(v any) time.Time {
	t, _ := when(v)
	return t
}

func get(v any, key string) any {
	m, _ := v.(map[string]any)
	return m[key]
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}

func nonNil(l []any) []any {
	if l == nil {
		return []any{}
	}
	return l
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func hasKeys(m map[string]any, keys []string) bool {
	if m == nil || len(m) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

func jcs(v any) []byte {
	out, err := evidencerequest.EncodeJCS(v)
	if err != nil {
		return nil
	}
	return out
}

// unencodable is the digest of a value JCS cannot encode: never a SHA-256
// hex, so no member equals it.
const unencodable = "unencodable"

func digest(v any) string {
	body := jcs(v)
	if body == nil {
		return unencodable
	}
	return evidencerequest.Digest(body)
}

func equal(a, b any) bool {
	ja, jb := jcs(a), jcs(b)
	return ja != nil && jb != nil && bytes.Equal(ja, jb)
}

// jsonModel converts encoding/json numbers to the profile's JSON number
// type, so a definition decoded by either decoder is evaluated alike.
func jsonModel(v any) any {
	switch x := v.(type) {
	case json.Number:
		return evidencerequest.JSONNumber(x)
	case float64:
		if x >= 0 && x <= evidencerequest.MaxSafeInteger && x == float64(uint64(x)) {
			return uint64(x)
		}
		return x
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = jsonModel(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, item := range x {
			out[k] = jsonModel(item)
		}
		return out
	}
	return v
}
