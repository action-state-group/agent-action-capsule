// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"slices"
	"time"
)

// AnchorView is one coverage anchor a responder has issued: its digest, the
// number of log entries it covers, and when it was issued.
type AnchorView struct {
	Digest   string
	Entries  uint64
	IssuedAt time.Time
}

// View is what resolution reads of a responder's evidence. Positions are
// zero-based log positions. Resolution matches exactly: a View never
// matches by prefix or case folding.
type View interface {
	// Anchors are the anchors issued, oldest first.
	Anchors() []AnchorView
	// LogEntries is the number of entries the log holds now, covered or not.
	LogEntries() uint64
	// LeafOf is the position of a servable record.
	LeafOf(digest string) (uint64, bool)
	// Servable reports whether the record at leaf may be served at all.
	Servable(leaf uint64) bool
	// Correlated and Citing are the positions of the servable records
	// carrying a correlation identifier, or citing an exchange half.
	Correlated(id string) []uint64
	Citing(half string) []uint64
	// Lapsed reports a retention commitment for exactly this subject whose
	// until has passed (ER §9).
	Lapsed(subject Subject, now time.Time) bool
}

// Resolution is the decision for one well-formed request: the anchor (an
// index into Anchors()), whether the requester pinned its own exchange
// half, the records served, or the refusal reason. NeedAnchor asks the
// caller to issue a fresh anchor and resolve again.
type Resolution struct {
	Anchor     int
	HalfPin    bool
	Leaves     []uint64
	Reason     string
	NeedAnchor bool
}

// AnchorMeets reports whether an anchor attains a min_freshness floor: at
// least floor.Size entries, or issued no earlier than floorTime as the
// envelope states it (seconds precision, profile §5.2).
func AnchorMeets(a AnchorView, floor *Freshness, floorTime time.Time) bool {
	if floor.Size != nil {
		return a.Entries >= *floor.Size
	}
	return !a.IssuedAt.UTC().Truncate(time.Second).Before(floorTime)
}

// ResolveCoverage picks the anchor (ER §3.2, profile §6.1 step 6). A pin
// must name an anchor this responder issued, or, for an exchange subject,
// the requester's own exchange half. A freshness floor is met by the newest
// anchor that meets it; when none does, mayIssue says whether the responder
// will do the work of issuing one.
func ResolveCoverage(view View, req Request, now time.Time, mayIssue bool) Resolution {
	anchors := view.Anchors()
	if pin := req.Coverage.ExpectedPin; pin != "" {
		for i, a := range anchors {
			if a.Digest == pin {
				return Resolution{Anchor: i}
			}
		}
		if req.Subject.Kind == SubjectExchange && pin == req.Subject.Digest {
			return Resolution{Anchor: -1, HalfPin: true}
		}
		return Resolution{Reason: ReasonCoverageUnsatisfiable}
	}
	floor := req.Coverage.MinFreshness
	if floor == nil {
		return Resolution{Reason: ReasonCoverageUnsatisfiable}
	}
	floorTime, timed := req.floorTime()
	if floor.Size == nil && !timed {
		return Resolution{Reason: ReasonRequestMalformed}
	}
	for i := len(anchors) - 1; i >= 0; i-- {
		if AnchorMeets(anchors[i], floor, floorTime) {
			return Resolution{Anchor: i}
		}
	}
	// No anchor meets the floor. A floor no anchor could meet yet is refused
	// without doing any work: a time in the future, or more entries than the
	// log holds.
	if floor.Size != nil && *floor.Size > view.LogEntries() || floor.Size == nil && floorTime.After(now) {
		return Resolution{Reason: ReasonCoverageUnsatisfiable}
	}
	if !mayIssue || view.LogEntries() == 0 {
		return Resolution{Reason: ReasonCoverageUnsatisfiable}
	}
	return Resolution{NeedAnchor: true}
}

// ResolveSubject finds the servable records the subject names under the
// anchor ResolveCoverage chose (ER §3.1). A subject that exists only beyond
// the anchor is coverage_unsatisfiable, never no_such_subject: the
// responder does hold it. Matching is exact, never by prefix or case
// folding.
func ResolveSubject(view View, req Request, r Resolution, now time.Time) Resolution {
	anchors := view.Anchors()
	if r.HalfPin {
		// The requester pinned its own half: the anchor is the earliest one
		// covering every anchored record that cites it, so growth that adds
		// no citing record never changes the artifact (ER §3.2, §5).
		cited := view.Citing(req.Subject.Digest)
		if len(cited) == 0 {
			return withRetention(view, req, now, Resolution{Reason: ReasonNoSuchSubject})
		}
		latest := uint64(0)
		if n := len(anchors); n > 0 {
			latest = anchors[n-1].Entries
		}
		var last uint64
		anchored := false
		for _, leaf := range cited {
			if leaf < latest {
				last, anchored = max(last, leaf), true
			}
		}
		if !anchored {
			return Resolution{Reason: ReasonCoverageUnsatisfiable}
		}
		for i, a := range anchors {
			if a.Entries > last {
				r.Anchor = i
				break
			}
		}
	}
	if r.Anchor < 0 || r.Anchor >= len(anchors) {
		return Resolution{Reason: ReasonCoverageUnsatisfiable}
	}
	covered := anchors[r.Anchor].Entries
	switch req.Subject.Kind {
	case SubjectCheckpoints:
		return r
	case SubjectFullHistory:
		for leaf := uint64(0); leaf < covered; leaf++ {
			if view.Servable(leaf) {
				r.Leaves = append(r.Leaves, leaf)
			}
		}
		if len(r.Leaves) == 0 && req.Derivation == "" {
			r.Reason = ReasonNoSuchSubject
		}
		return r
	case SubjectRecord:
		leaf, held := view.LeafOf(req.Subject.Digest)
		switch {
		case !held:
			return withRetention(view, req, now, Resolution{Reason: ReasonNoSuchSubject})
		case leaf >= covered:
			return Resolution{Reason: ReasonCoverageUnsatisfiable}
		}
		r.Leaves = []uint64{leaf}
		return r
	case SubjectRange:
		a, b := req.Subject.Range[0], req.Subject.Range[1]
		if b >= covered {
			if b < view.LogEntries() {
				return Resolution{Reason: ReasonCoverageUnsatisfiable}
			}
			return withRetention(view, req, now, Resolution{Reason: ReasonNoSuchSubject})
		}
		for leaf := a; leaf <= b; leaf++ {
			if view.Servable(leaf) {
				r.Leaves = append(r.Leaves, leaf)
			}
		}
		if len(r.Leaves) == 0 {
			return withRetention(view, req, now, Resolution{Reason: ReasonNoSuchSubject})
		}
		return r
	case SubjectCorrelation, SubjectExchange:
		var all []uint64
		if req.Subject.Kind == SubjectCorrelation {
			all = view.Correlated(req.Subject.Correlation)
		} else {
			all = view.Citing(req.Subject.Digest)
		}
		for _, leaf := range all {
			if leaf < covered {
				r.Leaves = append(r.Leaves, leaf)
			}
		}
		switch {
		case len(r.Leaves) > 0:
			slices.Sort(r.Leaves)
			r.Leaves = slices.Compact(r.Leaves)
			return r
		case len(all) > 0:
			return Resolution{Reason: ReasonCoverageUnsatisfiable}
		}
		return withRetention(view, req, now, Resolution{Reason: ReasonNoSuchSubject})
	}
	return Resolution{Reason: ReasonRequestMalformed}
}

// withRetention turns no_such_subject into retention_expired when the
// responder once committed to answer exactly this subject and the
// commitment has lapsed, so a lapsed promise never reads as never having
// held the evidence (ER §4.2 item 2, §9).
func withRetention(view View, req Request, now time.Time, r Resolution) Resolution {
	if r.Reason == ReasonNoSuchSubject && view.Lapsed(req.Subject, now) {
		r.Reason = ReasonRetentionExpired
	}
	return r
}

// Policy is what a decision reads besides the evidence: the derivations a
// responder supports, who may ask, which refusal policy it declares, and
// what its evidence mechanism can do.
type Policy struct {
	// Derivation reports the subject forms a derivation other than
	// history_card/1 is registered for, and false when the responder does
	// not support it. Nil supports none. history_card/1 is always supported,
	// over full_history and checkpoints (ER §8.1).
	Derivation func(name string) (forms []SubjectKind, ok bool)
	// Authorize reports whether the requester may have req answered. It is
	// asked once the derivation is known to be supported; it decides whether
	// a request is answered, never what is answered (ER §3.7, §5). Nil
	// authorizes every request.
	Authorize func(req Request) bool
	// Uniform declares the uniform refusal policy: policy_declined wherever
	// a more specific token would disclose what the policy protects (ER
	// §4.2, §12).
	Uniform bool
	// Unanchored says the evidence mechanism serves no coverage anchors, so
	// no request can be covered.
	Unanchored bool
	// Unpositioned says the evidence mechanism defines no positional
	// ordering, so a range subject cannot be resolved.
	Unpositioned bool
	// MayIssue says the responder will issue a fresh anchor to meet a
	// freshness floor no existing anchor meets.
	MayIssue bool
}

// Disclose applies the refusal policy to a reason: under the uniform
// policy, a reason that would disclose whether a subject exists, whether it
// is covered yet, or whether this requester may see it becomes
// policy_declined.
func (p Policy) Disclose(reason string) string {
	if p.Uniform && slices.Contains([]string{ReasonNotAuthorized, ReasonNoSuchSubject, ReasonCoverageUnsatisfiable}, reason) {
		return ReasonPolicyDeclined
	}
	return reason
}

// Decide applies a responder's steps that follow the request reader, in
// order: the deadline, derivation support (at all, then for this subject;
// ER §3.3), authorization, the mechanism, coverage, the subject, and the
// refusal policy. req is a request ParseRequest read as well formed. When
// the decision is NeedAnchor, the caller issues an anchor and decides
// again; a second NeedAnchor is coverage_unsatisfiable under the policy.
func Decide(view View, req Request, p Policy, now time.Time) Resolution {
	refuse := func(reason string) Resolution { return Resolution{Reason: reason} }
	if req.Deadline != "" {
		deadline, ok := ParseRequestTime(req.Deadline)
		if !ok {
			return refuse(ReasonRequestMalformed)
		}
		if !now.Before(deadline) {
			return refuse(ReasonDeadlineUnmet)
		}
	}
	var forms []SubjectKind
	registered := false
	switch {
	case req.Derivation == DerivationHistoryCard:
		if req.Subject.Kind != SubjectFullHistory && req.Subject.Kind != SubjectCheckpoints {
			return refuse(ReasonNoSuchSubject)
		}
	case req.Derivation != "":
		if p.Derivation != nil {
			forms, registered = p.Derivation(req.Derivation)
		}
		if !registered {
			return refuse(ReasonDerivationUnsupported)
		}
	}
	if p.Authorize != nil && !p.Authorize(req) {
		return refuse(p.Disclose(ReasonNotAuthorized))
	}
	if registered && !slices.Contains(forms, req.Subject.Kind) {
		return refuse(p.Disclose(ReasonNoSuchSubject))
	}
	if p.Unanchored || p.Unpositioned && req.Subject.Kind == SubjectRange {
		return refuse(p.Disclose(ReasonCoverageUnsatisfiable))
	}
	r := ResolveCoverage(view, req, now, p.MayIssue)
	if r.Reason == "" && !r.NeedAnchor {
		r = ResolveSubject(view, req, r, now)
	}
	r.Reason = p.Disclose(r.Reason)
	return r
}
