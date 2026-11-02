// SPDX-License-Identifier: Apache-2.0

// Package personalhistoryoutcome evaluates a History at the Outcome level
// of the Personal-Agent History Profile v0
// (spec/personal-agent-history-outcome-v0.md, personal_history_outcome/1,
// cited as PO): the acceptance of each answer under the Minimum Evidence
// Interoperability Profile (PO §8.1), the level's History properties
// (PO §8.2), the properties of each outcome claim (PO §5, §8.3), the
// requirement results (PO §8.4) and the deal commitment openings (PO §7).
//
// Each exchange is verified by evidencerequest.Verifier. Claims are
// evaluated only over a History that is accepted. A native object's own
// check belongs to its adapter, which the caller supplies as a
// NativeChecker; with none, the check is NOT_CHECKED. The vectors of
// vectors/personal-history-outcome-v0 are the package's tests.
package personalhistoryoutcome

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"

	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/action-state-group/agent-action-capsule/go/internal/ed25519strict"
)

// Name is the Outcome level's name: what people read, not what the wire
// carries (PO §3).
const Name = "personal_history_outcome/1"

// The claim sources (PO §5).
const (
	HolderRecord     = "holder_record"
	CounterpartyHalf = "counterparty_half"
	NativeObject     = "native_object"
	JudgeVerdict     = "judge_verdict"
)

// The deal binding of a claim (PO §8.3): whether the claim's own evidence
// ties it to the deal, or only the holder's word does.
const (
	Carried    = "carried"
	HolderOnly = "holder_only"
)

// The requirement statuses of PO §8.4.
const (
	Satisfied    = "SATISFIED"
	Unknown      = "UNKNOWN"
	Insufficient = "INSUFFICIENT"
	Gap          = "GAP"
)

// The statuses of the opening check (PO §7) beyond PASS and FAIL.
const NotPresent = "NOT_PRESENT"

const (
	commitAlg = "sha256-jcs-nonce256"
	notEval   = "not_evaluable"
)

var (
	definitionMembers = []string{"name", "kind", "subject_form", "selection", "reads", "coverage_declaration",
		"holder_role", "sources", "predicates", "recipient"}
	// Reads is the declared field set (PO §3).
	Reads = []string{"commit_alg", "committed_at", "consent", "deal_commitment", "epistemic_type", "event_time_claim",
		"outcome", "record_type"}
	roles           = []string{"seller", "buyer"}
	sources         = []string{HolderRecord, CounterpartyHalf, NativeObject, JudgeVerdict}
	artifactMembers = []string{"anchor", "derivation", "evidence_stream", "records", "subject"}
	judgeVerdicts   = []string{"met", "not_met", notEval}
	recordKinds     = []string{"step_completed", "step_failed", "outcome_recorded", "judge_consent"}
	mustPass        = []string{"profile_version", "envelope_signature", "responder_trust", "issued_at_form", "request_binding", "subject_binding", "artifact_digest", "anchor_match"}
	claimMembers    = map[string][]string{
		HolderRecord:     {"predicate", "source"},
		CounterpartyHalf: {"predicate", "source", "evidence"},
		JudgeVerdict:     {"predicate", "source", "evidence"},
		NativeObject:     {"predicate", "source", "evidence", "adapter", "adapter_predicate"},
	}
	declarationMembers = map[string][]string{
		"holder_selected":      {"kind"},
		"stream_interval":      {"kind", "rule", "interval", "live_set"},
		"source_authoritative": {"kind", "source", "method", "population"},
	}
	hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Roles are the keys the relying party trusts for each role of an outcome
// claim (PO §5.2, §5.4): lowercase hex Ed25519 public keys.
type Roles struct {
	Counterparty []string
	Judge        []string
}

// Requirement is one outcome requirement the relying party holds (PO
// §8.4): the predicate it asks for and the sources it accepts.
type Requirement struct {
	ID        string
	Predicate string
	Sources   []string
}

// NativeClaim is a native_object claim whose objects are all held, for an
// adapter to check (PO §5.3).
type NativeClaim struct {
	Adapter          string
	AdapterPredicate string
	// Evidence lists the digests the claim cites; Objects holds each
	// object's octets by digest.
	Evidence []string
	Objects  map[string][]byte
}

// NativeChecker is an adapter's own result for a claim: PASS, FAIL or
// NOT_CHECKED. It is called only for a claim whose cited objects are all
// held.
type NativeChecker func(NativeClaim) string

// Config is what the relying party holds: the predicate table (PO §6.1, the
// document decoded from JSON, whose digest a definition's predicates
// member must equal), the trusted roles, the requirements, and the
// adapter checker (nil: every native check is NOT_CHECKED).
type Config struct {
	PredicateTable any
	Roles          Roles
	Requirements   []Requirement
	Native         NativeChecker
}

// Exchange is one request and the reply to it, as the octets carried.
type Exchange struct {
	Request evidencerequest.Message
	Reply   evidencerequest.Message
}

// Inputs are what is evaluated: the definition the recipient holds, the
// exchanges, the evidence objects held (each by the digest of its
// octets), and the deal commitment openings by deal.
type Inputs struct {
	Definition any
	Exchanges  []Exchange
	Evidence   [][]byte
	Openings   map[string]any
}

// ExchangeResult is one exchange: the verifier's reply result, the
// envelope's subject, and whether PO §8.1 accepts it.
type ExchangeResult struct {
	Reply    *evidencerequest.ReplyResult
	Subject  any
	Accepted bool

	env map[string]any
}

// Claim is one outcome claim evaluated (PO §8.3). Verdict is empty unless
// the claim counts and is carried.
type Claim struct {
	Deal        string
	Record      string
	Predicate   string
	Source      string
	Properties  map[string]string
	Counts      bool
	DealBinding string
	Verdict     string
}

// RequirementResult is one requirement's result for one deal (PO §8.4).
type RequirementResult struct {
	Status      string
	Sufficiency string
	Verdict     string
}

// Result is a History evaluated. Claims, Requirements are nil unless the
// History is accepted; Requirements maps a requirement id to each deal's
// result; Openings maps a deal that commits to its opening's check.
type Result struct {
	Exchanges    []ExchangeResult
	Properties   map[string]string
	Accepted     bool
	Claims       []Claim
	Requirements map[string]map[string]RequirementResult
	Openings     map[string]string
}

// Evaluate verifies each exchange with v and applies PO §8.1 to each
// reply, checks the History properties over the envelopes §8.1 accepts
// (PO §8.2), and, when the History is accepted, evaluates each outcome
// claim (§8.3) and the requirements (§8.4). The deal commitment openings
// (§7) are checked over every accepted envelope. requirements are the
// contract requirements evaluated (nil: every one).
func Evaluate(v *evidencerequest.Verifier, cfg Config, in Inputs, requirements []string) (Result, error) {
	exs := make([]evidencerequest.Exchange, len(in.Exchanges))
	for i, x := range in.Exchanges {
		exs[i] = evidencerequest.Exchange{Request: x.Request, Replies: []evidencerequest.Message{x.Reply}}
	}
	verified, err := v.Verify(exs, evidencerequest.VerifyOptions{Requirements: requirements})
	if err != nil {
		return Result{}, err
	}
	var out Result
	var accepted []ExchangeResult
	allAccepted := true
	for _, ex := range verified.Exchanges {
		if len(ex.Replies) != 1 {
			return Result{}, errors.New("personalhistoryoutcome: the verifier returned no single reply for an exchange")
		}
		r := ex.Replies[0]
		x := ExchangeResult{Reply: r}
		if r.MessageType == "envelope" {
			x.Subject = r.Envelope["subject"]
			x.Accepted = acceptedEnvelope(r)
			x.env = withArtifact(r)
		}
		out.Exchanges = append(out.Exchanges, x)
		allAccepted = allAccepted && x.Accepted
		if x.Accepted {
			accepted = append(accepted, x)
		}
	}
	definition := jsonModel(in.Definition)
	table := newTable(cfg.PredicateTable)
	envs := make([]map[string]any, len(accepted))
	for i, x := range accepted {
		envs[i] = x.env
	}
	out.Properties = historyProperties(table, definition, envs)
	out.Accepted = allAccepted
	for _, s := range out.Properties {
		out.Accepted = out.Accepted && s == evidencerequest.StatusPass
	}
	objects := map[string][]byte{}
	for _, o := range in.Evidence {
		objects[sha(o)] = o
	}
	if out.Accepted {
		e := evaluator{cfg: cfg, table: table, definition: definition, objects: objects}
		for _, env := range envs {
			for _, raw := range list(get(env["artifact"], "records")) {
				rec := asMap(raw)
				if rec["record_type"] == "outcome_recorded" {
					out.Claims = append(out.Claims, e.claim(env, rec))
				}
			}
		}
		if out.Claims == nil {
			out.Claims = []Claim{}
		}
		var deals []string
		for _, env := range envs {
			deals = append(deals, str(get(env["subject"], "correlation")))
		}
		out.Requirements = requirementResults(cfg, deals, out.Claims)
	}
	out.Openings = openingResults(envs, jsonModelMap(in.Openings))
	return out, nil
}

func acceptedEnvelope(r *evidencerequest.ReplyResult) bool {
	for _, p := range mustPass {
		if r.Status(p) != evidencerequest.StatusPass {
			return false
		}
	}
	_, hasVerification := r.Envelope["verification"]
	return r.Status("anchor_inclusion") == evidencerequest.StatusNotChecked && !hasVerification
}

func withArtifact(r *evidencerequest.ReplyResult) map[string]any {
	env := map[string]any{}
	for k, v := range r.Envelope {
		env[k] = v
	}
	if a, err := evidencerequest.DecodeJSON(r.Artifact); r.Artifact != nil && err == nil {
		env["artifact"] = a
	}
	return env
}

// ---------------------------------------------------------------------------
// The predicate table (PO §6.1)
// ---------------------------------------------------------------------------

type predicate struct {
	sources []string
	native  []any
}

type table struct {
	digest     string
	predicates map[string]predicate
}

func newTable(doc any) table {
	doc = jsonModel(doc)
	t := table{predicates: map[string]predicate{}}
	if body := jcs(doc); body != nil {
		t.digest = sha(body)
	}
	for _, raw := range list(get(doc, "predicates")) {
		p := predicate{native: list(get(raw, "native"))}
		for _, s := range list(get(raw, "sources")) {
			p.sources = append(p.sources, str(s))
		}
		t.predicates[str(get(raw, "id"))] = p
	}
	return t
}

// ---------------------------------------------------------------------------
// The History properties (PO §8.2)
// ---------------------------------------------------------------------------

func status(ok bool) string {
	if ok {
		return evidencerequest.StatusPass
	}
	return evidencerequest.StatusFail
}

func historyProperties(t table, definition any, envs []map[string]any) map[string]string {
	d, _ := definition.(map[string]any)
	selection := list(d["selection"])
	digest := ""
	if body := jcs(definition); body != nil {
		digest = sha(body)
	}
	binding := true
	signers, anchors := map[string]bool{}, map[string]bool{}
	answered := map[string]int{}
	coverage := true
	kinds := true
	for _, env := range envs {
		binding = binding && digest != "" && env["derivation"] == digest
		signers[string(jcs(env["responder"]))] = true
		anchors[string(jcs(env["anchor"]))] = true
		s := asMap(env["subject"])
		correlation, isText := s["correlation"].(string)
		if isText {
			answered[correlation]++
		}
		if len(s) != 1 || !isText || !slices.ContainsFunc(selection, func(x any) bool { return x == any(correlation) }) {
			coverage = false
		}
		for _, raw := range list(get(env["artifact"], "records")) {
			r, ok := raw.(map[string]any)
			kinds = kinds && ok && recordKindOK(r)
		}
		kinds = kinds && dealCommitmentsOK(env)
	}
	for _, s := range selection {
		name, _ := s.(string)
		coverage = coverage && answered[name] == 1
	}
	return map[string]string{
		"definition_form":           status(definitionForm(definition)),
		"definition_binding":        status(binding),
		"predicate_binding":         status(str(d["predicates"]) == t.digest && t.digest != ""),
		"coverage_declaration_form": status(declarationForm(d["coverage_declaration"])),
		"selection_coverage":        status(coverage),
		"single_signer":             status(len(signers) == 1),
		"single_anchor":             status(len(anchors) == 1),
		"artifact_form":             status(artifactForm(envs)),
		"record_kinds":              status(kinds),
	}
}

func definitionForm(d any) bool {
	m, ok := d.(map[string]any)
	if !ok || !hasKeys(m, definitionMembers) || m["name"] != Name || m["kind"] != "projection" ||
		m["subject_form"] != "correlation" || !equal(m["reads"], textValues(Reads)) {
		return false
	}
	role, _ := m["holder_role"].(string)
	predicates, _ := m["predicates"].(string)
	if !slices.Contains(roles, role) || !hex64.MatchString(predicates) {
		return false
	}
	return sortedSet(m["selection"], nil) && sortedSet(m["sources"], sources) && nonEmptyText(m["recipient"])
}

// sortedSet is a non-empty list of non-empty, strictly ascending texts,
// each in allowed when allowed is given.
func sortedSet(v any, allowed []string) bool {
	l, ok := v.([]any)
	if !ok || len(l) == 0 {
		return false
	}
	prev := ""
	for i, x := range l {
		s, ok := x.(string)
		if !ok || s == "" || (i > 0 && prev >= s) || (allowed != nil && !slices.Contains(allowed, s)) {
			return false
		}
		prev = s
	}
	return true
}

func nonEmptyText(v any) bool {
	s, ok := v.(string)
	return ok && s != ""
}

// declarationForm is IP §6.7.1 coverage_declaration_form, with PO §3's
// restriction to the rule all_records.
func declarationForm(v any) bool {
	dec, ok := v.(map[string]any)
	if !ok {
		return false
	}
	kind, _ := dec["kind"].(string)
	members, known := declarationMembers[kind]
	if !known || !hasKeys(dec, members) {
		return false
	}
	switch kind {
	case "stream_interval":
		live, ok := dec["live_set"].([]any)
		return dec["rule"] == "all_records" && ok && len(live) > 0
	case "source_authoritative":
		source, _ := dec["source"].(string)
		population, _ := dec["population"].(string)
		_, method := dec["method"].(string)
		return hex64.MatchString(source) && method && hex64.MatchString(population)
	}
	return true
}

func artifactForm(envs []map[string]any) bool {
	for _, env := range envs {
		a, ok := env["artifact"].(map[string]any)
		if !ok || !hasKeys(a, artifactMembers) || !nonEmptyText(a["evidence_stream"]) {
			return false
		}
		anchor := asMap(env["anchor"])
		if !equal(a["anchor"], anchor["digest"]) || !equal(a["derivation"], env["derivation"]) || !equal(a["subject"], env["subject"]) {
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
			if _, ok := r["digest"]; !ok {
				return false
			}
			if _, ok := r["leaf_index"]; !ok {
				return false
			}
			for k := range r {
				if k != "digest" && k != "leaf_index" && !slices.Contains(Reads, k) {
					return false
				}
			}
		}
	}
	return true
}

// recordKindOK is PO §4: the closed kinds, outcome exactly on outcome
// records, consent exactly on consent records, and the commitment's two
// members together.
func recordKindOK(r map[string]any) bool {
	kind, _ := r["record_type"].(string)
	_, hasOutcome := r["outcome"]
	_, hasConsent := r["consent"]
	_, hasAlg := r["commit_alg"]
	_, hasCommitment := r["deal_commitment"]
	alg, algOK := r["commit_alg"]
	return slices.Contains(recordKinds, kind) && hasOutcome == (kind == "outcome_recorded") &&
		hasConsent == (kind == "judge_consent") && hasAlg == hasCommitment && (!algOK || alg == commitAlg)
}

func dealCommitmentsOK(env map[string]any) bool {
	n := 0
	for _, raw := range list(get(env["artifact"], "records")) {
		if _, ok := asMap(raw)["deal_commitment"]; ok {
			n++
		}
	}
	return n <= 1
}

// ---------------------------------------------------------------------------
// Outcome claims (PO §5, §8.3)
// ---------------------------------------------------------------------------

type evaluator struct {
	cfg        Config
	table      table
	definition any
	objects    map[string][]byte
}

func (e evaluator) claim(env, rec map[string]any) Claim {
	deal := str(get(env["subject"], "correlation"))
	o := rec["outcome"]
	props, verdict := e.properties(env, rec, deal)
	source := str(get(o, "source"))
	subject := map[string]string{CounterpartyHalf: "half_subject", JudgeVerdict: "judge_subject"}[source]
	binding := HolderOnly
	if subject != "" && props[subject] == evidencerequest.StatusPass {
		binding = Carried
	}
	ok := counts(props)
	c := Claim{Deal: deal, Record: str(rec["digest"]), Predicate: str(get(o, "predicate")), Source: source,
		Properties: props, Counts: ok, DealBinding: binding}
	if ok && binding == Carried {
		c.Verdict = verdict
	}
	return c
}

// counts is whether every property counts the claim: PASS, except that
// issuer independence not established is still counted (IP §6.7.4).
func counts(props map[string]string) bool {
	for p, s := range props {
		if s != evidencerequest.StatusPass && !(p == "issuer_independence" && s == evidencerequest.StatusNotChecked) {
			return false
		}
	}
	return true
}

func (e evaluator) properties(env, rec map[string]any, deal string) (map[string]string, string) {
	o := rec["outcome"]
	m, _ := o.(map[string]any)
	props := map[string]string{
		"outcome_form":           status(e.outcomeForm(o)),
		"outcome_source_allowed": status(slices.ContainsFunc(list(get(e.definition, "sources")), func(s any) bool { return s == m["source"] })),
	}
	source := str(m["source"])
	if source == HolderRecord {
		return props, ""
	}
	evidence := textValuesOf(m["evidence"])
	held := true
	for _, d := range evidence {
		if _, ok := e.objects[d]; !ok {
			held = false
		}
	}
	props["outcome_evidence"] = evidencerequest.StatusNotPresent
	if held {
		props["outcome_evidence"] = evidencerequest.StatusPass
	}
	switch source {
	case CounterpartyHalf:
		for k, v := range e.half(m, deal, str(env["responder"]), evidence) {
			props[k] = v
		}
		return props, "met"
	case NativeObject:
		maps := false
		for _, n := range e.table.predicates[str(m["predicate"])].native {
			maps = maps || equal(n, map[string]any{"adapter": m["adapter"], "predicate": m["adapter_predicate"]})
		}
		props["adapter_predicate_maps"] = status(maps)
		props["native_check"] = e.nativeCheck(m, evidence)
		return props, ""
	}
	jp, verdict := e.judge(m, deal, rec, list(get(env["artifact"], "records")), evidence)
	for k, v := range jp {
		props[k] = v
	}
	return props, verdict
}

func (e evaluator) outcomeForm(o any) bool {
	m, ok := o.(map[string]any)
	if !ok {
		return false
	}
	source, _ := m["source"].(string)
	members, known := claimMembers[source]
	if !known || !hasKeys(m, members) {
		return false
	}
	p, known := e.table.predicates[str(m["predicate"])]
	if _, isText := m["predicate"].(string); !isText || !known || !slices.Contains(p.sources, source) {
		return false
	}
	ev, present := m["evidence"]
	if !present || ev == nil {
		return true
	}
	l, ok := ev.([]any)
	if !ok || len(l) == 0 {
		return false
	}
	prev := ""
	for i, x := range l {
		s, ok := x.(string)
		if !ok || !hex64.MatchString(s) || (i > 0 && prev >= s) {
			return false
		}
		prev = s
	}
	return true
}

func (e evaluator) half(o map[string]any, deal, holder string, evidence []string) map[string]string {
	var h map[string]any
	if len(evidence) == 1 {
		h = e.object(evidence[0])
	}
	if h == nil {
		return notChecked("half_signature", "half_signer_trust", "half_subject", "half_states", "issuer_independence")
	}
	independence := evidencerequest.StatusNotChecked
	if h["producer"] == holder {
		// IP §6.7.4: the same key is FAIL; distinct keys alone are NOT_CHECKED.
		independence = evidencerequest.StatusFail
	}
	return map[string]string{
		"half_signature":      status(signedOK(h, "producer")),
		"half_signer_trust":   status(slices.Contains(e.cfg.Roles.Counterparty, str(h["producer"]))),
		"half_subject":        status(h["subject_ref"] == deal),
		"half_states":         status(equal(h["claim"], o["predicate"])),
		"issuer_independence": independence,
	}
}

func (e evaluator) nativeCheck(o map[string]any, evidence []string) string {
	if e.cfg.Native == nil {
		return evidencerequest.StatusNotChecked
	}
	for _, d := range evidence {
		if _, ok := e.objects[d]; !ok {
			return evidencerequest.StatusNotChecked
		}
	}
	got := e.cfg.Native(NativeClaim{Adapter: str(o["adapter"]), AdapterPredicate: str(o["adapter_predicate"]),
		Evidence: evidence, Objects: e.objects})
	switch got {
	case evidencerequest.StatusPass, evidencerequest.StatusFail:
		return got
	}
	return evidencerequest.StatusNotChecked
}

// judge is PO §5.4: the judge's record, its signer, its subject, its
// grounds in the deal's records, the consent that precedes it and the
// verdict allowed. The verdict returned is the record's, when it is text.
func (e evaluator) judge(o map[string]any, deal string, rec map[string]any, dealRecords []any, evidence []string) (map[string]string, string) {
	var j map[string]any
	if len(evidence) == 1 {
		j = e.object(evidence[0])
	}
	if j == nil {
		return notChecked("judge_signature", "judge_signer_trust", "judge_subject", "judge_grounds",
			"consent_precedes_judgment", "judge_verdict_allowed"), ""
	}
	report := asMap(j["record"])
	var mine []map[string]any
	for _, c := range list(report["cases"]) {
		if m, ok := c.(map[string]any); ok && equal(m["case_id"], o["predicate"]) {
			mine = append(mine, m)
		}
	}
	digests := map[string]bool{}
	for _, r := range dealRecords {
		digests[str(get(r, "digest"))] = true
	}
	var acts []any
	for _, c := range mine {
		for _, a := range list(c["acts"]) {
			acts = append(acts, get(a, "digest"))
		}
	}
	grounded := len(mine) == 1 && len(acts) > 0
	for _, a := range acts {
		s, ok := a.(string)
		grounded = grounded && ok && digests[s]
	}
	position, havePosition := evidencerequest.UintValue(rec["leaf_index"])
	consented := false
	for _, r := range dealRecords {
		c := asMap(r)
		at, ok := evidencerequest.UintValue(c["leaf_index"])
		if c["record_type"] == "judge_consent" && ok && havePosition && at < position &&
			equal(c["consent"], map[string]any{"judge": j["judge"], "contract_ref": report["contract_ref"]}) {
			consented = true
		}
	}
	// PO §5.4: this level's requirements carry no out_of_scope switch, so
	// any other verdict fails.
	allowed := evidencerequest.StatusNotChecked
	var verdict string
	if len(mine) == 1 {
		v, isText := mine[0]["verdict"].(string)
		allowed = status(isText && slices.Contains(judgeVerdicts, v))
		verdict = v
	}
	return map[string]string{
		"judge_signature":           status(signedOK(j, "judge")),
		"judge_signer_trust":        status(slices.Contains(e.cfg.Roles.Judge, str(j["judge"]))),
		"judge_subject":             status(j["subject_ref"] == deal),
		"judge_grounds":             status(grounded),
		"consent_precedes_judgment": status(consented),
		"judge_verdict_allowed":     allowed,
	}, verdict
}

func (e evaluator) object(digest string) map[string]any {
	raw, ok := e.objects[digest]
	if !ok {
		return nil
	}
	v, err := evidencerequest.DecodeJSON(raw)
	if err != nil {
		return nil
	}
	m, _ := v.(map[string]any)
	return m
}

func notChecked(names ...string) map[string]string {
	out := map[string]string{}
	for _, n := range names {
		out[n] = evidencerequest.StatusNotChecked
	}
	return out
}

// requirementResults is PO §8.4.
func requirementResults(cfg Config, deals []string, claims []Claim) map[string]map[string]RequirementResult {
	out := map[string]map[string]RequirementResult{}
	for _, req := range cfg.Requirements {
		per := map[string]RequirementResult{}
		for _, deal := range deals {
			var mine []Claim
			verdicts := map[string]bool{}
			anyCounts, anyOpen := false, false
			for _, c := range claims {
				if c.Deal != deal || c.Predicate != req.Predicate || !slices.Contains(req.Sources, c.Source) {
					continue
				}
				mine = append(mine, c)
				if c.Counts && c.DealBinding == Carried {
					verdicts[c.Verdict] = true
				}
				anyCounts = anyCounts || c.Counts
				open := true
				for _, s := range c.Properties {
					open = open && (s == evidencerequest.StatusPass || s == evidencerequest.StatusNotChecked || s == evidencerequest.StatusInconclusive)
				}
				anyOpen = anyOpen || open
			}
			var st string
			switch {
			case len(mine) == 0:
				st = Gap
			case len(verdicts) == 1 && (verdicts["met"] || verdicts["not_met"]):
				st = Satisfied
			case len(verdicts) > 0 || anyCounts || anyOpen:
				st = Unknown
			default:
				st = Insufficient
			}
			verdict := notEval
			if st == Satisfied {
				for v := range verdicts {
					verdict = v
				}
			}
			per[deal] = RequirementResult{Status: st, Sufficiency: st, Verdict: verdict}
		}
		out[req.ID] = per
	}
	return out
}

// openingResults is PO §7: each deal's commitment recomputed from its
// opening. A deal with no commitment is not reported.
func openingResults(envs []map[string]any, openings map[string]any) map[string]string {
	out := map[string]string{}
	for _, env := range envs {
		deal := str(get(env["subject"], "correlation"))
		var committed any
		found := false
		for _, raw := range list(get(env["artifact"], "records")) {
			if c, ok := asMap(raw)["deal_commitment"]; ok && !found {
				committed, found = c, true
			}
		}
		if !found {
			continue
		}
		o, ok := openings[deal]
		if !ok {
			out[deal] = NotPresent
			continue
		}
		m, isMap := o.(map[string]any)
		nonce, _ := get(o, "nonce").(string)
		out[deal] = status(isMap && hex64.MatchString(nonce) && hasKeys(m, []string{"nonce", "text"}) &&
			equal(sha(jcs(o)), committed))
	}
	return out
}

// ---------------------------------------------------------------------------
// Helpers over decoded JSON
// ---------------------------------------------------------------------------

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
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

func str(v any) string {
	s, _ := v.(string)
	return s
}

func textValues(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func textValuesOf(v any) []string {
	var out []string
	for _, x := range list(v) {
		out = append(out, str(x))
	}
	return out
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

func equal(a, b any) bool {
	ja, jb := jcs(a), jcs(b)
	return ja != nil && jb != nil && bytes.Equal(ja, jb)
}

func jsonModelMap(m map[string]any) map[string]any {
	out, _ := jsonModel(m).(map[string]any)
	return out
}

// jsonModel converts encoding/json numbers to the profile's JSON number
// type, so a document decoded by either decoder is evaluated alike.
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
