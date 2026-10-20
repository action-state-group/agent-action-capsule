// SPDX-License-Identifier: Apache-2.0

// Package personalhistory evaluates a History at the Basic level of the
// Personal-Agent History Profile v0 (spec/personal-agent-history-profile-v0.md,
// personal_history_basic/1, cited as PH): the definition document and its
// identifier (PH §4.1, §4.2), the acceptance of each answer under the
// Minimum Evidence Interoperability Profile (PH §6.1), the seven History
// properties (PH §6.2), the deal states (PH §5), and the one-file History
// (PH §8.2).
//
// Each exchange is verified by evidencerequest.Verifier. The History
// properties are checked only over the envelopes PH §6.1 accepts. The
// vectors of vectors/personal-history-basic-v0 are the package's tests.
package personalhistory

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
)

// Name is the Basic level's name: what people read, not what the wire
// carries (PH §4.1).
const Name = "personal_history_basic/1"

// The record kinds the Basic level reveals (PH §3).
const (
	StepCompleted = "step_completed"
	StepFailed    = "step_failed"
)

// Reads is the declared field set (PH §4.1, ER §8).
var Reads = []string{"committed_at", "epistemic_type", "event_time_claim", "record_type"}

// HistoryProperties are the seven History properties (PH §6.2), in order.
var HistoryProperties = []string{
	"definition_form", "definition_binding", "selection_coverage", "single_signer", "single_anchor",
	"artifact_form", "record_kinds",
}

// The deal states of PH §5, in the order a verifier counts them.
const (
	StateFailedStep     = "with a recorded failed step"
	StateCompletedSteps = "with recorded completed steps only"
	StateNoStep         = "with no recorded step"
)

// DealStates lists the three deal states in order.
var DealStates = []string{StateFailedStep, StateCompletedSteps, StateNoStep}

// mustPass are the envelope properties PH §6.1 requires PASS.
var mustPass = []string{"profile_version", "envelope_signature", "responder_trust", "issued_at_form", "request_binding",
	"subject_binding", "artifact_digest", "anchor_match"}

var definitionMembers = []string{"completeness", "kind", "name", "reads", "recipient", "selection", "subject_form"}

var artifactMembers = []string{"anchor", "derivation", "evidence_stream", "records", "subject"}

// Definition is the Basic level definition document for a selection and a
// recipient (PH §4.1). selection is sorted and deduplicated here; the
// caller refuses an empty selection or recipient before calling.
func Definition(selection []string, recipient string) map[string]any {
	picked := slices.Clone(selection)
	slices.Sort(picked)
	picked = slices.Compact(picked)
	list := make([]any, len(picked))
	for i, s := range picked {
		list[i] = s
	}
	reads := make([]any, len(Reads))
	for i, r := range Reads {
		reads[i] = r
	}
	return map[string]any{
		"name": Name, "kind": "projection", "subject_form": "correlation", "selection": list,
		"reads": reads, "completeness": "not_asserted", "recipient": recipient,
	}
}

// DerivationID is the derivation identifier of a definition: SHA-256 of
// UTF-8 of JCS of the document (PH §4.2, ER §3.3).
func DerivationID(definition any) (string, error) {
	body, err := evidencerequest.EncodeJCS(definition)
	if err != nil {
		return "", err
	}
	return evidencerequest.Digest(body), nil
}

// FileExchange is one exchange of a one-file History: the request and the
// reply as the octets carried (PH §8.2).
type FileExchange struct {
	Request evidencerequest.Message
	Reply   evidencerequest.Message
}

// File is the one-file History (PH §8.2).
type File struct {
	Definition any
	Exchanges  []FileExchange
}

type fileMessage struct {
	MediaType  string  `json:"media_type"`
	OctetsText *string `json:"octets_text,omitempty"`
	OctetsHex  *string `json:"octets_hex,omitempty"`
}

// ErrInvalid reports a History file that is not the PH §8.2 object.
var ErrInvalid = errors.New("personalhistory: invalid")

// ParseFile reads a one-file History (PH §8.2): exactly the members
// history (this level's name), definition and exchanges, each exchange
// exactly a request and a reply, each as {media_type, octets_text} for
// JSON or {media_type, octets_hex} for CBOR.
func ParseFile(data []byte) (File, error) {
	root, err := evidencerequest.DecodeJSON(data)
	if err != nil {
		return File{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	obj, ok := root.(map[string]any)
	if !ok || !sameKeys(obj, []string{"definition", "exchanges", "history"}) {
		return File{}, fmt.Errorf("%w: a History file holds exactly history, definition and exchanges (PH §8.2)", ErrInvalid)
	}
	if obj["history"] != Name {
		return File{}, fmt.Errorf("%w: history is not %s", ErrInvalid, Name)
	}
	rawExchanges, ok := obj["exchanges"].([]any)
	if !ok {
		return File{}, fmt.Errorf("%w: exchanges is not an array", ErrInvalid)
	}
	f := File{Definition: obj["definition"]}
	for i, raw := range rawExchanges {
		x, ok := raw.(map[string]any)
		if !ok || !sameKeys(x, []string{"reply", "request"}) {
			return File{}, fmt.Errorf("%w: exchange %d is not {request, reply}", ErrInvalid, i)
		}
		request, err := carriedMessage(x["request"])
		if err != nil {
			return File{}, fmt.Errorf("%w: exchange %d request: %v", ErrInvalid, i, err)
		}
		reply, err := carriedMessage(x["reply"])
		if err != nil {
			return File{}, fmt.Errorf("%w: exchange %d reply: %v", ErrInvalid, i, err)
		}
		f.Exchanges = append(f.Exchanges, FileExchange{Request: request, Reply: reply})
	}
	return f, nil
}

func carriedMessage(v any) (evidencerequest.Message, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return evidencerequest.Message{}, errors.New("not an object")
	}
	mediaType, _ := m["media_type"].(string)
	switch {
	case mediaType == evidencerequest.MediaTypeJSON && sameKeys(m, []string{"media_type", "octets_text"}):
		text, ok := m["octets_text"].(string)
		if !ok {
			return evidencerequest.Message{}, errors.New("octets_text is not a string")
		}
		return evidencerequest.Message{Octets: []byte(text), MediaType: mediaType}, nil
	case mediaType == evidencerequest.MediaTypeCBOR && sameKeys(m, []string{"media_type", "octets_hex"}):
		text, ok := m["octets_hex"].(string)
		octets, err := hexBytes(text)
		if !ok || err != nil {
			return evidencerequest.Message{}, errors.New("octets_hex is not lowercase hex")
		}
		return evidencerequest.Message{Octets: octets, MediaType: mediaType}, nil
	}
	return evidencerequest.Message{}, errors.New("not {media_type, octets_text} for JSON or {media_type, octets_hex} for CBOR")
}

// EncodeFile writes a one-file History (PH §8.2) as JCS.
func EncodeFile(f File) ([]byte, error) {
	exchanges := make([]any, len(f.Exchanges))
	for i, x := range f.Exchanges {
		request, err := fileValue(x.Request)
		if err != nil {
			return nil, err
		}
		reply, err := fileValue(x.Reply)
		if err != nil {
			return nil, err
		}
		exchanges[i] = map[string]any{"request": request, "reply": reply}
	}
	return evidencerequest.EncodeJCS(map[string]any{"history": Name, "definition": f.Definition, "exchanges": exchanges})
}

func fileValue(m evidencerequest.Message) (map[string]any, error) {
	switch m.MediaType {
	case evidencerequest.MediaTypeJSON:
		// octets_text carries the octets exactly (PH §8.2), so they must be
		// text a JSON string can hold unchanged.
		if err := canonical.CheckJSONText(m.Octets); err != nil {
			return nil, fmt.Errorf("%w: JSON octets that a JSON string cannot carry exactly: %v", ErrInvalid, err)
		}
		return map[string]any{"media_type": m.MediaType, "octets_text": string(m.Octets)}, nil
	case evidencerequest.MediaTypeCBOR:
		return map[string]any{"media_type": m.MediaType, "octets_hex": fmt.Sprintf("%x", m.Octets)}, nil
	}
	return nil, fmt.Errorf("%w: media type %q", ErrInvalid, m.MediaType)
}

// ExchangeResult is one exchange: the verifier's reply result, the
// envelope's subject, and whether PH §6.1 accepts it.
type ExchangeResult struct {
	Reply    *evidencerequest.ReplyResult
	Subject  any
	Accepted bool
	// Artifact is the envelope's Artifact decoded, numbers kept as
	// evidencerequest.JSONNumber; nil when the reply is no envelope or its
	// Artifact is not exactly the JCS of one JSON value (PH §4.3).
	Artifact any
}

// DealState is one selected deal's PH §5 state.
type DealState struct {
	Deal  string
	State string
}

// States is the PH §5 reading of an accepted History: the number of
// selected deals, each deal's state in deal order, and the count of each
// state, in their own units.
type States struct {
	SelectedDeals int
	PerDeal       []DealState
	Counts        map[string]int
}

// Result is a History evaluated: each exchange, the seven History
// properties, whether the History is accepted, and its deal states when it
// is.
type Result struct {
	Exchanges  []ExchangeResult
	Properties map[string]string
	Accepted   bool
	States     *States
}

// Evaluate verifies each exchange with v, applies PH §6.1 to each reply,
// and checks the seven History properties over the envelopes §6.1 accepts
// (PH §6.2) against definition, the definition the recipient holds.
// requirements are the contract requirements evaluated (nil: every one).
// An exchange whose reply is not an envelope is not accepted.
func Evaluate(v *evidencerequest.Verifier, definition any, exchanges []FileExchange, requirements []string) (Result, error) {
	exs := make([]evidencerequest.Exchange, len(exchanges))
	for i, x := range exchanges {
		exs[i] = evidencerequest.Exchange{Request: x.Request, Replies: []evidencerequest.Message{x.Reply}}
	}
	verified, err := v.Verify(exs, evidencerequest.VerifyOptions{Requirements: requirements})
	if err != nil {
		return Result{}, err
	}
	var out Result
	var accepted []ExchangeResult
	for _, ex := range verified.Exchanges {
		r := ex.Replies[0]
		x := ExchangeResult{Reply: r}
		if r.MessageType == "envelope" {
			x.Subject = r.Envelope["subject"]
			x.Artifact = artifactValue(r.Artifact)
			x.Accepted = acceptedEnvelope(r)
		}
		out.Exchanges = append(out.Exchanges, x)
		if x.Accepted {
			accepted = append(accepted, x)
		}
	}
	out.Properties = properties(definition, accepted)
	out.Accepted = len(out.Exchanges) > 0
	for _, x := range out.Exchanges {
		out.Accepted = out.Accepted && x.Accepted
	}
	for _, p := range HistoryProperties {
		out.Accepted = out.Accepted && out.Properties[p] == evidencerequest.StatusPass
	}
	if out.Accepted {
		s := dealStates(accepted)
		out.States = &s
	}
	return out, nil
}

// acceptedEnvelope is PH §6.1: the required envelope properties PASS,
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

// artifactValue reads an Artifact, which PH §4.3 fixes as UTF-8 of JCS of
// one object: nil unless the octets are exactly that, so a duplicate
// member, trailing data or any other encoding cannot carry bytes that
// artifact_form never reads.
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

func sameKeys(m map[string]any, keys []string) bool {
	if len(m) != len(keys) {
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
	out, err := evidencerequest.EncodeJCS(jsonModel(v))
	if err != nil {
		return nil
	}
	return out
}

// jsonModel converts encoding/json numbers to the profile's JSON number
// type, so artifact values encode with the rest.
func jsonModel(v any) any {
	switch x := v.(type) {
	case json.Number:
		return evidencerequest.JSONNumber(x)
	case float64:
		// A definition decoded by encoding/json without UseNumber: an
		// integral value keeps its JCS form; any other has none.
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

func equal(a, b any) bool {
	ja, jb := jcs(a), jcs(b)
	return ja != nil && jb != nil && bytes.Equal(ja, jb)
}

func textList(v any) ([]string, bool) {
	raw, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(raw))
	for i, item := range raw {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

func definitionForm(d any) bool {
	m, ok := d.(map[string]any)
	if !ok || !sameKeys(m, definitionMembers) {
		return false
	}
	fixed := Definition(nil, "")
	for _, k := range []string{"name", "kind", "subject_form", "reads", "completeness"} {
		if !equal(m[k], fixed[k]) {
			return false
		}
	}
	selection, ok := textList(m["selection"])
	if !ok || len(selection) == 0 {
		return false
	}
	for i, s := range selection {
		if s == "" || (i > 0 && selection[i-1] >= s) {
			return false
		}
	}
	recipient, ok := m["recipient"].(string)
	return ok && recipient != ""
}

func artifactForm(envs []ExchangeResult, reads []string) bool {
	for _, e := range envs {
		a, ok := e.Artifact.(map[string]any)
		if !ok || !sameKeys(a, artifactMembers) {
			return false
		}
		anchor, _ := e.Reply.Envelope["anchor"].(map[string]any)
		digest, isText := a["anchor"].(string)
		if !isText || !evidencerequest.IsDigest(digest) || !equal(a["anchor"], anchor["digest"]) || !equal(a["derivation"], e.Reply.Envelope["derivation"]) || !equal(a["subject"], e.Subject) {
			return false
		}
		records, ok := a["records"].([]any)
		if !ok || len(records) == 0 {
			return false
		}
		for _, raw := range records {
			r, ok := raw.(map[string]any)
			if !ok {
				return false
			}
			if !entryForm(r, reads) {
				return false
			}
		}
		stream, ok := a["evidence_stream"].(string)
		if !ok || stream == "" {
			return false
		}
	}
	return true
}

// entryForm is one records entry (PH §4.3): a digest and a position, and
// otherwise only members of reads, each a header value. The values are
// held to their forms, a 64-hex record digest, an unsigned position and a
// text string for each read member, so no permitted member can carry an
// object or an array. A read member's text is still the holder's: PH fixes
// no form for it, and keeping private text out of it is the holder's
// pre-release scan (PH §4.4).
func entryForm(r map[string]any, reads []string) bool {
	digest, ok := r["digest"].(string)
	if !ok || !evidencerequest.IsDigest(digest) {
		return false
	}
	if _, ok := evidencerequest.UintValue(r["leaf_index"]); !ok {
		return false
	}
	for k, v := range r {
		if k == "digest" || k == "leaf_index" {
			continue
		}
		if _, isText := v.(string); !isText || !slices.Contains(reads, k) {
			return false
		}
	}
	return true
}

func records(e ExchangeResult) []any {
	a, _ := e.Artifact.(map[string]any)
	r, _ := a["records"].([]any)
	return r
}

func properties(definition any, envs []ExchangeResult) map[string]string {
	d, _ := definition.(map[string]any)
	selection, _ := textList(d["selection"])
	reads, _ := textList(d["reads"])
	digest := ""
	if body := jcs(definition); body != nil {
		digest = evidencerequest.Digest(body)
	}
	answered := map[string]int{}
	coverage := true
	signers, anchors := map[string]bool{}, map[string]bool{}
	binding, kinds := true, true
	for _, e := range envs {
		s, ok := e.Subject.(map[string]any)
		correlation, isText := s["correlation"].(string)
		if !ok || len(s) != 1 || !isText || !slices.Contains(selection, correlation) {
			coverage = false
		}
		if ok && isText {
			answered[correlation]++
		}
		binding = binding && digest != "" && e.Reply.Envelope["derivation"] == digest
		signers[string(jcs(e.Reply.Envelope["responder"]))] = true
		anchors[string(jcs(e.Reply.Envelope["anchor"]))] = true
		for _, raw := range records(e) {
			r, _ := raw.(map[string]any)
			kind, _ := r["record_type"].(string)
			kinds = kinds && (kind == StepCompleted || kind == StepFailed)
		}
	}
	for _, s := range selection {
		coverage = coverage && answered[s] == 1
	}
	status := func(ok bool) string {
		if ok {
			return evidencerequest.StatusPass
		}
		return evidencerequest.StatusFail
	}
	return map[string]string{
		"definition_form":    status(definitionForm(definition)),
		"definition_binding": status(binding),
		"selection_coverage": status(coverage),
		"single_signer":      status(len(signers) == 1),
		"single_anchor":      status(len(anchors) == 1),
		"artifact_form":      status(artifactForm(envs, reads)),
		"record_kinds":       status(kinds),
	}
}

func dealStates(envs []ExchangeResult) States {
	per := map[string]string{}
	for _, e := range envs {
		failed, completed := false, false
		for _, raw := range records(e) {
			r, _ := raw.(map[string]any)
			switch r["record_type"] {
			case StepFailed:
				failed = true
			case StepCompleted:
				completed = true
			}
		}
		state := StateNoStep
		switch {
		case failed:
			state = StateFailedStep
		case completed:
			state = StateCompletedSteps
		}
		subject, _ := e.Subject.(map[string]any)
		correlation, _ := subject["correlation"].(string)
		per[correlation] = state
	}
	s := States{SelectedDeals: len(per), Counts: map[string]int{}}
	deals := make([]string, 0, len(per))
	for d := range per {
		deals = append(deals, d)
	}
	sort.Strings(deals)
	for _, state := range DealStates {
		s.Counts[state] = 0
	}
	for _, d := range deals {
		s.PerDeal = append(s.PerDeal, DealState{Deal: d, State: per[d]})
		s.Counts[per[d]]++
	}
	return s
}

var lowerHex = regexp.MustCompile(`^(?:[0-9a-f]{2})*$`)

func hexBytes(s string) ([]byte, error) {
	if !lowerHex.MatchString(s) {
		return nil, ErrInvalid
	}
	return hex.DecodeString(s)
}
