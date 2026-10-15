// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"fmt"
	"regexp"
	"slices"
	"time"
)

// ProfileID identifies the revision of the Minimum Evidence
// Interoperability Profile this package implements (profile §3.1).
const ProfileID = "evidence-interop/0"

// RequestDraft is the Internet-Draft whose request map this package accepts
// (profile §11.4.2 `drafts`).
const RequestDraft = "draft-mih-agent-evidence-request-00"

// Subprotocol is the stream binding's subprotocol identifier (ER §10).
const Subprotocol = "evidence-request/1"

// DerivationHistoryCard is the one derivation the request draft registers
// (ER §8.1).
const DerivationHistoryCard = "history_card/1"

// SubjectKind is one of the request draft's six subject forms (ER §3.1).
type SubjectKind string

const (
	SubjectFullHistory SubjectKind = "full_history"
	SubjectCheckpoints SubjectKind = "checkpoints"
	SubjectRecord      SubjectKind = "record"
	SubjectRange       SubjectKind = "range"
	SubjectCorrelation SubjectKind = "correlation"
	SubjectExchange    SubjectKind = "exchange"
)

// SubjectForms lists the six forms in code-point order.
var SubjectForms = []SubjectKind{SubjectCheckpoints, SubjectCorrelation, SubjectExchange, SubjectFullHistory, SubjectRange, SubjectRecord}

// Refusal reason tokens: the request draft's registry, verbatim (ER §13,
// profile §9.1). No other token is ever emitted.
const (
	ReasonNotAuthorized         = "not_authorized"
	ReasonNoSuchSubject         = "no_such_subject"
	ReasonCoverageUnsatisfiable = "coverage_unsatisfiable"
	ReasonDerivationUnsupported = "derivation_unsupported"
	ReasonPolicyDeclined        = "policy_declined"
	ReasonDeadlineUnmet         = "deadline_unmet"
	ReasonRequestMalformed      = "request_malformed"
	ReasonRetentionExpired      = "retention_expired"
)

// RefusalReasons is the registry, in the draft's order.
var RefusalReasons = []string{
	ReasonNotAuthorized, ReasonNoSuchSubject, ReasonCoverageUnsatisfiable, ReasonDerivationUnsupported,
	ReasonPolicyDeclined, ReasonDeadlineUnmet, ReasonRequestMalformed, ReasonRetentionExpired,
}

// Subject names what is asked for, in one of the six forms. Digest serves
// record and exchange, Range serves range (two zero-based log positions,
// a <= b), Correlation serves correlation. On the wire it is a map with
// exactly one member named by the form (ERV A1).
type Subject struct {
	Kind        SubjectKind
	Digest      string
	Range       [2]uint64
	Correlation string
}

// Value is the subject's wire value (profile §5.2).
func (s Subject) Value() map[string]any {
	switch s.Kind {
	case SubjectFullHistory, SubjectCheckpoints:
		return map[string]any{string(s.Kind): nil}
	case SubjectRecord, SubjectExchange:
		return map[string]any{string(s.Kind): s.Digest}
	case SubjectRange:
		return map[string]any{string(s.Kind): []any{s.Range[0], s.Range[1]}}
	case SubjectCorrelation:
		return map[string]any{string(s.Kind): s.Correlation}
	}
	return map[string]any{}
}

// Valid reports whether s is one of the six forms with conforming content
// and nothing another form would carry.
func (s Subject) Valid() bool {
	switch s.Kind {
	case SubjectFullHistory, SubjectCheckpoints:
		return s.Digest == "" && s.Correlation == "" && s.Range == [2]uint64{}
	case SubjectRecord, SubjectExchange:
		return IsDigest(s.Digest) && s.Correlation == "" && s.Range == [2]uint64{}
	case SubjectRange:
		return s.Range[0] <= s.Range[1] && s.Range[1] <= MaxSafeInteger && s.Digest == "" && s.Correlation == ""
	case SubjectCorrelation:
		return s.Correlation != "" && s.Digest == "" && s.Range == [2]uint64{}
	}
	return false
}

// ParseSubject reads a decoded wire subject: a map with exactly one member,
// a known form, and content of that form's type (ERV A1, A2, A6).
func ParseSubject(v any) (Subject, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return Subject{}, false
	}
	for name, content := range m {
		s := Subject{Kind: SubjectKind(name)}
		switch s.Kind {
		case SubjectFullHistory, SubjectCheckpoints:
			return s, content == nil
		case SubjectRecord, SubjectExchange:
			digest, ok := content.(string)
			s.Digest = digest
			return s, ok && IsDigest(digest)
		case SubjectRange:
			pair, ok := content.([]any)
			if !ok || len(pair) != 2 {
				return Subject{}, false
			}
			a, okA := UintValue(pair[0])
			b, okB := UintValue(pair[1])
			s.Range = [2]uint64{a, b}
			return s, okA && okB && a <= b
		case SubjectCorrelation:
			id, ok := content.(string)
			s.Correlation = id
			return s, ok && id != ""
		}
	}
	return Subject{}, false
}

// Freshness is a min_freshness floor: exactly one of a log size or a time
// (ERV A3).
type Freshness struct {
	Size *uint64
	Time string
}

// Coverage carries exactly one of ExpectedPin (the digest of an anchor the
// requester holds) or MinFreshness (ER §3.2).
type Coverage struct {
	ExpectedPin  string
	MinFreshness *Freshness
}

// Request is the request map (ER §3, profile §6.1).
type Request struct {
	Subject    Subject
	Coverage   Coverage
	Derivation string
	Deadline   string
	Nonce      string
	Route      string
	// Profile is the profile identifier the request names. A requester
	// following the profile sets it to ProfileID; a received request without
	// one is answered as ProfileID (profile §3.3 step 2).
	Profile string
}

// Value is the request's wire value. Optional members are omitted when
// empty. It refuses a request that does not conform, so a requester never
// sends one a conforming responder would refuse request_malformed.
func (r Request) Value() (map[string]any, error) {
	if !r.Subject.Valid() {
		return nil, fmt.Errorf("%w: subject is not one of the six forms with conforming content", ErrInvalid)
	}
	coverage := map[string]any{}
	if r.Coverage.ExpectedPin != "" {
		if !IsDigest(r.Coverage.ExpectedPin) {
			return nil, fmt.Errorf("%w: expected_pin is not a digest", ErrInvalid)
		}
		coverage["expected_pin"] = r.Coverage.ExpectedPin
	}
	if f := r.Coverage.MinFreshness; f != nil {
		switch {
		case f.Size != nil && f.Time == "" && *f.Size <= MaxSafeInteger:
			coverage["min_freshness"] = *f.Size
		case f.Size == nil && f.Time != "":
			if _, ok := ParseRequestTime(f.Time); !ok {
				return nil, fmt.Errorf("%w: min_freshness time %q is not an RFC 3339 UTC time", ErrInvalid, f.Time)
			}
			coverage["min_freshness"] = f.Time
		default:
			return nil, fmt.Errorf("%w: min_freshness is exactly one of a size or a time", ErrInvalid)
		}
	}
	if len(coverage) != 1 {
		return nil, fmt.Errorf("%w: coverage carries exactly one of expected_pin or min_freshness", ErrInvalid)
	}
	out := map[string]any{"subject": r.Subject.Value(), "coverage": coverage}
	if r.Derivation != "" {
		if !ValidDerivation(r.Derivation) {
			return nil, fmt.Errorf("%w: derivation %q is neither a registered token form nor a definition digest", ErrInvalid, r.Derivation)
		}
		out["derivation"] = r.Derivation
	}
	if r.Deadline != "" {
		if _, ok := ParseRequestTime(r.Deadline); !ok {
			return nil, fmt.Errorf("%w: deadline %q is not an RFC 3339 UTC time", ErrInvalid, r.Deadline)
		}
		out["deadline"] = r.Deadline
	}
	for name, text := range map[string]string{"nonce": r.Nonce, "route": r.Route, "profile": r.Profile} {
		if text != "" {
			out[name] = text
		}
	}
	return out, nil
}

// EncodeRequest returns the request octets in the encoding mediaType names:
// JCS for JSON, deterministic CBOR for CBOR (profile §5.1, P-9).
func EncodeRequest(r Request, mediaType string) ([]byte, error) {
	value, err := r.Value()
	if err != nil {
		return nil, err
	}
	return Encode(mediaType, value)
}

var derivationToken = regexp.MustCompile(`^[a-z0-9_]+/[0-9]+$`)

// ValidDerivation reports whether s is a registered token with a /N
// suffix, or a 64-hex definition digest (ERV A14, profile §5.2).
func ValidDerivation(s string) bool {
	return derivationToken.MatchString(s) || IsDigest(s)
}

// RequestCheck is the outcome of reading received request octets: the
// request, or the refusal reason the first failing rule of profile §6.1
// assigns.
type RequestCheck struct {
	Request Request
	// Reason is empty for a well-formed request, otherwise the registered
	// token to refuse it with.
	Reason string
	// Why is the rule that failed, for the caller's diagnostics; it is not
	// sent. Detail is sent: only for an unknown profile, where it lists the
	// identifiers supported (§3.3 step 4). A refusal carries no other
	// detail, so it stays the bare signed object every implementation reads.
	Why    string
	Detail string
}

// ParseRequest validates received request octets in the order of profile
// §6.1 steps 1 to 5. Members it does not define are ignored (ER §3).
// Member names match exactly: a case variant is an unknown member. A
// malformed member wins over a coverage carrying both members (ERV A4).
func ParseRequest(m Message) RequestCheck {
	malformed := func(why string) RequestCheck {
		return RequestCheck{Reason: ReasonRequestMalformed, Why: why}
	}
	root, err := Decode(m)
	if err != nil {
		return malformed("not a well-formed map")
	}
	fields, ok := root.(map[string]any)
	if !ok {
		return malformed("not a map")
	}
	var out RequestCheck
	// Step 2: subject.
	raw, present := fields["subject"]
	if !present {
		return malformed("subject is missing")
	}
	if out.Request.Subject, ok = ParseSubject(raw); !ok {
		return malformed("subject is not one form with conforming content")
	}
	// Step 3: each coverage member present has a conforming value.
	members := 0
	if raw, present := fields["coverage"]; present {
		coverage, ok := raw.(map[string]any)
		if !ok {
			return malformed("coverage is not a map")
		}
		if pin, present := coverage["expected_pin"]; present {
			digest, ok := pin.(string)
			if !ok || !IsDigest(digest) {
				return malformed("expected_pin is not a digest")
			}
			out.Request.Coverage.ExpectedPin = digest
			members++
		}
		if floor, present := coverage["min_freshness"]; present {
			switch value := floor.(type) {
			case string:
				if _, ok := ParseRequestTime(value); !ok {
					return malformed("min_freshness is not an RFC 3339 UTC time")
				}
				out.Request.Coverage.MinFreshness = &Freshness{Time: value}
			default:
				size, ok := UintValue(value)
				if !ok {
					return malformed("min_freshness is neither an unsigned size nor a time")
				}
				out.Request.Coverage.MinFreshness = &Freshness{Size: &size}
			}
			members++
		}
	}
	// The other defined members: a value that does not conform is malformed
	// (ER §3).
	for _, name := range []string{"derivation", "deadline", "nonce", "route", "profile"} {
		raw, present := fields[name]
		if !present {
			continue
		}
		text, ok := raw.(string)
		if !ok {
			return malformed(name + " is not a text string")
		}
		switch name {
		case "derivation":
			if !ValidDerivation(text) {
				return malformed("derivation is neither a registered token form nor a definition digest")
			}
			out.Request.Derivation = text
		case "deadline":
			if _, ok := ParseRequestTime(text); !ok {
				return malformed("deadline is not an RFC 3339 UTC time")
			}
			out.Request.Deadline = text
		case "nonce":
			out.Request.Nonce = text
		case "route":
			out.Request.Route = text
		case "profile":
			out.Request.Profile = text
		}
	}
	// Step 4: exactly one coverage member (ER §3.2; ERV A4).
	if members != 1 {
		out.Reason = ReasonCoverageUnsatisfiable
		out.Why = "coverage carries other than exactly one of expected_pin or min_freshness"
		return out
	}
	// Step 5: a profile this responder does not implement (§3.3 step 4).
	if out.Request.Profile != "" && !slices.Contains(supportedProfiles, out.Request.Profile) {
		return RequestCheck{Reason: ReasonRequestMalformed, Why: "profile is not supported", Detail: "profiles supported: " + ProfileID}
	}
	if out.Request.Profile == "" {
		out.Request.Profile = ProfileID
	}
	return out
}

var supportedProfiles = []string{ProfileID}

// floorTime is a time-valued min_freshness as a time.
func (r Request) floorTime() (time.Time, bool) {
	if f := r.Coverage.MinFreshness; f != nil && f.Size == nil {
		return ParseRequestTime(f.Time)
	}
	return time.Time{}, false
}
