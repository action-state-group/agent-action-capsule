// SPDX-License-Identifier: Apache-2.0

// Package standardhistory implements the standard_history/1 derivation
// (spec/standard-history-v0.md, cited as SH): Derive builds a card from the
// deal entries (SH §5.2), the policy's window and digest (SH §5.1) and the
// anchor; Check reports the six card properties of SH §6 for a card, from
// whatever the caller holds beside it.
//
// It is at parity with the Python reference,
// python/agent_action_capsule/standard_history.py. The vectors of
// vectors/standard-history-v0 are the package's tests.
package standardhistory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"time"
)

// Derivation is the registered token (SH §3).
const Derivation = "standard_history/1"

// Properties are the card properties of SH §6, in the order a verifier
// reports them.
var Properties = []string{
	"card_form", "counts_integral", "denominator", "window_from_policy", "as_of", "counts_recompute",
}

// The property statuses (IP §7.1).
const (
	Pass       = "PASS"
	Fail       = "FAIL"
	NotChecked = "NOT_CHECKED"
)

// CounterpartyClasses are the values of counterparty_class (SH §7).
var CounterpartyClasses = []string{"person_agent", "business_agent", "shop_preauth"}

const notCounted = "shop_preauth"

var (
	holderKinds     = []string{"person", "node"}
	roles           = []string{"provided", "bought"}
	outcomes        = []string{"held", "did_not_hold", "undecided"}
	happened        = []string{"stamped_by_both", "receipt_only", "no_record"}
	sides           = []string{"raised", "received"}
	disputeOutcomes = []string{"open", "for", "against", "split", "no_finding", "withdrawn"}
	forums          = []string{"auto", "network", "rail", "external"}
)

// controllerClasses are the one controller class /1 allows for each holder
// kind (SH §4).
var controllerClasses = map[string]string{"person": "person_declared", "node": "node_declared"}

// tallies are SH §4's tallies and their parts; `of` is every tally's
// denominator.
var tallies = []struct {
	name  string
	parts []string
}{
	{"in_window", []string{"counted", "not_counted"}},
	{"class_missing", []string{"count"}},
	{"outcomes", outcomes},
	{"roles", roles},
	{"happened", happened},
}

var cardMembers = []string{
	"derivation", "holder_kind", "controller_class", "anchor", "since", "window", "policy", "bands",
	"disputes", "in_window", "class_missing", "outcomes", "roles", "happened",
}

const maxCount = 1<<53 - 1

var (
	hex64     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	month     = regexp.MustCompile(`^\d{4}-(?:0[1-9]|1[0-2])$`)
	timeForm  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`) // IP §5.2
	valueForm = regexp.MustCompile(`^(?:0|[1-9][0-9]*)$`)                    // SR "Amounts"
	// A JSON integer literal: what Python's json reads as an int (-0 is 0).
	intLiteral = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)$`)
	// SR "Amounts" assetCode: an ISO 4217 alphabetic code (BTC included),
	// or a CAIP-19 asset type.
	currencyForm = regexp.MustCompile(`^(?:[A-Z]{3}|[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128})$`)
)

// Window is the policy's window (SH §5.1): Months calendar months, or All.
type Window struct {
	Months int
	All    bool
}

// MarshalJSON writes {"months": N} or {"all": true}.
func (w Window) MarshalJSON() ([]byte, error) {
	if w.All {
		return []byte(`{"all":true}`), nil
	}
	return json.Marshal(map[string]int{"months": w.Months})
}

// UnmarshalJSON reads a window, rejecting any other form.
func (w *Window) UnmarshalJSON(data []byte) error {
	v, err := decode(data)
	if err != nil {
		return err
	}
	got, ok := windowOf(v)
	if !ok {
		return fmt.Errorf("not a policy window: %s", data)
	}
	*w = got
	return nil
}

// Policy is the two members of the policy in force at the anchor that the
// card reads (SH §5.1).
type Policy struct {
	Digest string `json:"digest"`
	Window Window `json:"window"`
}

// AsOf is the anchor the card is as of, its time, and the time of the
// stream's first checkpoint.
type AsOf struct {
	Anchor              string `json:"anchor"`
	AnchorTime          string `json:"anchor_time"`
	FirstCheckpointTime string `json:"first_checkpoint_time"`
}

// Amount is the settlement-records amount triple.
type Amount struct {
	Value      string `json:"value"`
	AssetCode  string `json:"assetCode"`
	AssetScale int    `json:"assetScale"`
}

// Dispute is one dispute about a record of a deal (SH §5.4).
type Dispute struct {
	Side    string `json:"side"`
	Outcome string `json:"outcome"`
	Forum   string `json:"forum"`
}

// Deal is one deal entry (SH §5.2). A nil CounterpartyClass is a deal
// without the member.
type Deal struct {
	Deal              string    `json:"deal"`
	AgreedAt          string    `json:"agreed_at"`
	CounterpartyClass *string   `json:"counterparty_class,omitempty"`
	Role              string    `json:"role"`
	Amount            Amount    `json:"amount"`
	Outcome           string    `json:"outcome"`
	Happened          string    `json:"happened"`
	Disputes          []Dispute `json:"disputes"`
}

// UnmarshalJSON refuses a counterparty_class of null, which would otherwise
// read as a deal without the member, and an assetScale that is not a JSON
// integer (SR "Amounts" rule 2).
func (d *Deal) UnmarshalJSON(data []byte) error {
	type plain Deal
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	var members struct {
		Class  json.RawMessage `json:"counterparty_class"`
		Amount struct {
			AssetScale json.RawMessage `json:"assetScale"`
		} `json:"amount"`
	}
	if err := json.Unmarshal(data, &members); err != nil {
		return err
	}
	if members.Class != nil && p.CounterpartyClass == nil {
		return fmt.Errorf("deal %s: counterparty_class is not a string", p.Deal)
	}
	if !intLiteral.Match(members.Amount.AssetScale) {
		return fmt.Errorf("deal %s: assetScale is not a JSON integer", p.Deal)
	}
	*d = Deal(p)
	return nil
}

// parseTime reads an IP §5.2 time from year 1 on, as Python's datetime does.
func parseTime(s string) (time.Time, error) {
	if !timeForm.MatchString(s) {
		return time.Time{}, fmt.Errorf("not an IP §5.2 time: %q", s)
	}
	t, err := time.Parse("2006-01-02T15:04:05Z", s)
	if err == nil && t.Year() < 1 {
		err = fmt.Errorf("time before year 1: %q", s)
	}
	return t, err
}

// windowStart is SH §5.1: the same time of day and day of the month, months
// calendar months earlier, clamped to the last day of a shorter month. ok is
// false when that is before year 1, the first year a time can name: every
// deal is then after the start.
func windowStart(t time.Time, months int) (start time.Time, ok bool) {
	total := t.Year()*12 + int(t.Month()) - 1 - months
	year := total / 12
	if total%12 < 0 {
		year--
	}
	if year < 1 {
		return time.Time{}, false
	}
	m := time.Month(total-year*12) + 1
	last := time.Date(year, m+1, 0, 0, 0, 0, 0, time.UTC).Day()
	day := min(t.Day(), last)
	return time.Date(year, m, day, t.Hour(), t.Minute(), t.Second(), 0, time.UTC), true
}

func inWindow(agreed time.Time, w Window, anchor time.Time) bool {
	if agreed.After(anchor) {
		return false
	}
	if w.All {
		return true
	}
	start, ok := windowStart(anchor, w.Months)
	return !ok || !agreed.Before(start)
}

// decade is SH §5.3: floor(log10(value / 10^assetScale)), exactly
// digits(value) - assetScale - 1; nil for a zero amount.
func decade(a Amount) (*int, error) {
	if !valueForm.MatchString(a.Value) {
		return nil, fmt.Errorf("amount value is not an exact integer string: %q", a.Value)
	}
	if a.AssetScale < 0 || a.AssetScale > 255 {
		return nil, fmt.Errorf("amount assetScale out of range: %d", a.AssetScale)
	}
	if a.Value == "0" {
		return nil, nil
	}
	d := len(a.Value) - a.AssetScale - 1
	return &d, nil
}

func checkEntry(d Deal) error {
	if d.Deal == "" {
		return errors.New("deal entry without a deal reference")
	}
	if _, err := parseTime(d.AgreedAt); err != nil {
		return err
	}
	if d.CounterpartyClass != nil && !slices.Contains(CounterpartyClasses, *d.CounterpartyClass) {
		return fmt.Errorf("unknown counterparty_class: %q", *d.CounterpartyClass)
	}
	for _, c := range []struct {
		member, value string
		values        []string
	}{{"role", d.Role, roles}, {"outcome", d.Outcome, outcomes}, {"happened", d.Happened, happened}} {
		if !slices.Contains(c.values, c.value) {
			return fmt.Errorf("deal %s: %s %q", d.Deal, c.member, c.value)
		}
	}
	if !currencyForm.MatchString(d.Amount.AssetCode) {
		return fmt.Errorf("deal %s: amount without an SR assetCode", d.Deal)
	}
	if _, err := decade(d.Amount); err != nil {
		return err
	}
	if d.Disputes == nil {
		return fmt.Errorf("deal %s: disputes is not an array", d.Deal)
	}
	for _, x := range d.Disputes {
		if !slices.Contains(sides, x.Side) || !slices.Contains(disputeOutcomes, x.Outcome) ||
			!slices.Contains(forums, x.Forum) {
			return fmt.Errorf("deal %s: malformed dispute %+v", d.Deal, x)
		}
	}
	return nil
}

func zero(parts []string) map[string]int {
	t := map[string]int{"of": 0}
	for _, p := range parts {
		t[p] = 0
	}
	return t
}

type disputeTally struct {
	Of        int            `json:"of"`
	ByOutcome map[string]int `json:"by_outcome"`
	ByForum   map[string]int `json:"by_forum"`
}

// counts are the tallies SH §5 derives from the deal entries, keyed by card
// member.
func counts(deals []Deal, w Window, anchor time.Time) (map[string]any, error) {
	t := map[string]map[string]int{}
	for _, x := range tallies {
		t[x.name] = zero(x.parts)
	}
	// A zero amount's band has no decade (null), and sorts first.
	type key struct {
		currency  string
		hasDecade bool
		decade    int
	}
	bands := map[key]map[string]any{}
	disputes := map[string]*disputeTally{}
	for _, s := range sides {
		disputes[s] = &disputeTally{ByOutcome: zero(disputeOutcomes), ByForum: zero(forums)}
	}
	for _, d := range deals {
		if err := checkEntry(d); err != nil {
			return nil, err
		}
		agreed, _ := parseTime(d.AgreedAt)
		if !inWindow(agreed, w, anchor) {
			continue
		}
		t["in_window"]["of"]++
		if d.CounterpartyClass != nil && *d.CounterpartyClass == notCounted {
			t["in_window"]["not_counted"]++
			continue
		}
		t["in_window"]["counted"]++
		t["class_missing"]["of"]++
		if d.CounterpartyClass == nil {
			t["class_missing"]["count"]++
		}
		for _, x := range []struct{ name, value string }{
			{"outcomes", d.Outcome}, {"roles", d.Role}, {"happened", d.Happened},
		} {
			t[x.name]["of"]++
			t[x.name][x.value]++
		}
		dec, _ := decade(d.Amount)
		k := key{currency: d.Amount.AssetCode}
		var decadeValue any
		if dec != nil {
			k.hasDecade, k.decade, decadeValue = true, *dec, *dec
		}
		b, ok := bands[k]
		if !ok {
			b = map[string]any{"currency": k.currency, "decade": decadeValue}
			for p, v := range zero(outcomes) {
				b[p] = v
			}
			bands[k] = b
		}
		b["of"] = b["of"].(int) + 1
		b[d.Outcome] = b[d.Outcome].(int) + 1
		for _, x := range d.Disputes {
			dt := disputes[x.Side]
			dt.Of++
			dt.ByOutcome["of"]++
			dt.ByOutcome[x.Outcome]++
			dt.ByForum["of"]++
			dt.ByForum[x.Forum]++
		}
	}
	keys := make([]key, 0, len(bands))
	for k := range bands {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].currency != keys[j].currency {
			return keys[i].currency < keys[j].currency
		}
		if keys[i].hasDecade != keys[j].hasDecade {
			return !keys[i].hasDecade
		}
		return keys[i].decade < keys[j].decade
	})
	out := map[string]any{}
	for name, v := range t {
		out[name] = v
	}
	list := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		list = append(list, bands[k])
	}
	out["bands"] = list
	out["disputes"] = map[string]*disputeTally{"raised": disputes["raised"], "received": disputes["received"]}
	return out, nil
}

// Derive returns the card SH §4 states for these inputs, as JCS-ready JSON
// octets (members in any order; callers canonicalize).
func Derive(holderKind, controllerClass string, asOf AsOf, policy Policy, deals []Deal) ([]byte, error) {
	if _, err := parseTime(asOf.FirstCheckpointTime); err != nil {
		return nil, err
	}
	anchor, err := parseTime(asOf.AnchorTime)
	if err != nil {
		return nil, err
	}
	if !policy.Window.All && (policy.Window.Months < 1 || policy.Window.Months > maxCount) {
		return nil, fmt.Errorf("not a policy window: %+v", policy.Window)
	}
	card, err := counts(deals, policy.Window, anchor)
	if err != nil {
		return nil, err
	}
	card["derivation"] = Derivation
	card["holder_kind"] = holderKind
	card["controller_class"] = controllerClass
	card["anchor"] = asOf.Anchor
	card["since"] = asOf.FirstCheckpointTime[:7]
	card["window"] = policy.Window
	card["policy"] = policy.Digest
	return json.Marshal(card)
}

// decode parses JSON keeping numbers as json.Number, so that counts_integral
// sees every number.
func decode(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after the JSON value")
	}
	return v, nil
}

func isNumber(v any) bool {
	_, ok := v.(json.Number)
	return ok
}

// num is a number's value. A number out of float64's range is +Inf, which no
// check accepts.
func num(v any) float64 {
	f, err := strconv.ParseFloat(string(v.(json.Number)), 64)
	if err != nil {
		return math.Inf(1)
	}
	return f
}

func windowOf(v any) (Window, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return Window{}, false
	}
	if all, ok := m["all"]; ok {
		return Window{All: true}, all == true
	}
	months, ok := m["months"]
	if !ok || !isNumber(months) || num(months) < 1 {
		return Window{}, false
	}
	f := num(months)
	if f != math.Trunc(f) || f > maxCount {
		// A window the card states is still compared by value (SH §6): a
		// non-integral month count is counts_integral's FAIL.
		return Window{Months: -1}, true
	}
	return Window{Months: int(f)}, true
}

func keysExactly(m map[string]any, want []string) bool {
	if len(m) != len(want) {
		return false
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

// tallyForm is SH §6 card_form for one tally: exactly its parts, each a
// number, and optionally `of`.
func tallyForm(v any, parts []string) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	for _, p := range parts {
		if _, ok := m[p]; !ok {
			return false
		}
	}
	for k, x := range m {
		if k != "of" && !slices.Contains(parts, k) {
			return false
		}
		if !isNumber(x) {
			return false
		}
	}
	return true
}

func str(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func cardForm(v any) bool {
	card, ok := v.(map[string]any)
	if !ok || !keysExactly(card, cardMembers) {
		return false
	}
	if card["derivation"] != Derivation {
		return false
	}
	kind, ok := str(card["holder_kind"])
	if !ok || !slices.Contains(holderKinds, kind) {
		return false
	}
	if card["controller_class"] != controllerClasses[kind] {
		return false
	}
	for _, member := range []string{"anchor", "policy"} {
		if s, ok := str(card[member]); !ok || !hex64.MatchString(s) {
			return false
		}
	}
	if s, ok := str(card["since"]); !ok || !month.MatchString(s) {
		return false
	}
	if _, ok := windowOf(card["window"]); !ok {
		return false
	}
	for _, t := range tallies {
		if !tallyForm(card[t.name], t.parts) {
			return false
		}
	}
	bands, ok := card["bands"].([]any)
	if !ok {
		return false
	}
	var prevCurrency string
	var prevHas bool
	var prevDecade float64
	for i, b := range bands {
		m, ok := b.(map[string]any)
		if !ok {
			return false
		}
		currency, ok := str(m["currency"])
		if !ok || !currencyForm.MatchString(currency) {
			return false
		}
		rawDecade, present := m["decade"]
		if !present || (rawDecade != nil && !isNumber(rawDecade)) {
			return false
		}
		rest := map[string]any{}
		for k, x := range m {
			if k != "currency" && k != "decade" {
				rest[k] = x
			}
		}
		if !tallyForm(rest, outcomes) {
			return false
		}
		has, d := rawDecade != nil, 0.0
		if has {
			d = num(rawDecade)
		}
		if i > 0 && (currency < prevCurrency || (currency == prevCurrency &&
			(prevHas && !has || prevHas == has && d <= prevDecade))) {
			return false
		}
		prevCurrency, prevHas, prevDecade = currency, has, d
	}
	disputes, ok := card["disputes"].(map[string]any)
	if !ok || !keysExactly(disputes, sides) {
		return false
	}
	for _, x := range disputes {
		d, ok := x.(map[string]any)
		if !ok {
			return false
		}
		_, hasOutcome := d["by_outcome"]
		_, hasForum := d["by_forum"]
		of, hasOf := d["of"]
		if !hasOutcome || !hasForum || len(d) != 2+btoi(hasOf) {
			return false
		}
		if hasOf && !isNumber(of) {
			return false
		}
		if !tallyForm(d["by_outcome"], disputeOutcomes) || !tallyForm(d["by_forum"], forums) {
			return false
		}
	}
	return true
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func walkNumbers(v any, fn func(any) bool) bool {
	switch x := v.(type) {
	case map[string]any:
		for _, e := range x {
			if !walkNumbers(e, fn) {
				return false
			}
		}
	case []any:
		for _, e := range x {
			if !walkNumbers(e, fn) {
				return false
			}
		}
	case json.Number:
		return fn(x)
	}
	return true
}

func integral(low float64) func(any) bool {
	return func(n any) bool {
		f := num(n)
		return f == math.Trunc(f) && f >= low && f <= maxCount
	}
}

// countsIntegral is SH §6: every number an integer of at most 2^53 - 1 in
// magnitude, and 0 or more except a band's decade. A card travels as JCS,
// which writes 75.0 as 75, so the check is on the value, not on how it was
// written.
func countsIntegral(card any) bool {
	var decades []any
	rest := card
	if m, ok := card.(map[string]any); ok {
		if bands, ok := m["bands"].([]any); ok {
			stripped := make([]any, len(bands))
			for i, b := range bands {
				stripped[i] = b
				if bm, ok := b.(map[string]any); ok {
					if d, ok := bm["decade"]; ok {
						decades = append(decades, d)
						cp := make(map[string]any, len(bm))
						for k, v := range bm {
							if k != "decade" {
								cp[k] = v
							}
						}
						stripped[i] = cp
					}
				}
			}
			cp := make(map[string]any, len(m))
			for k, v := range m {
				cp[k] = v
			}
			cp["bands"] = stripped
			rest = cp
		}
	}
	return walkNumbers(rest, integral(0)) && walkNumbers(decades, integral(-maxCount))
}

func field(m any, k string) float64 {
	return num(m.(map[string]any)[k])
}

func has(m any, k string) bool {
	_, ok := m.(map[string]any)[k]
	return ok
}

func partitions(t any, parts []string) bool {
	if !has(t, "of") {
		return false
	}
	sum := 0.0
	for _, p := range parts {
		sum += field(t, p)
	}
	return sum == field(t, "of")
}

// denominator is SH §4 "Denominators". Run only on a card whose form and
// counts are PASS.
func denominator(v any) bool {
	card := v.(map[string]any)
	for _, t := range tallies {
		x := card[t.name]
		if !has(x, "of") {
			return false
		}
		if t.name == "class_missing" {
			if field(x, "count") > field(x, "of") {
				return false
			}
		} else if !partitions(x, t.parts) {
			return false
		}
	}
	counted := field(card["in_window"], "counted")
	for _, name := range []string{"class_missing", "outcomes", "roles", "happened"} {
		if field(card[name], "of") != counted {
			return false
		}
	}
	bands := card["bands"].([]any)
	for _, b := range bands {
		if !partitions(b, outcomes) || field(b, "of") < 1 {
			return false
		}
	}
	for _, o := range append([]string{"of"}, outcomes...) {
		sum := 0.0
		for _, b := range bands {
			sum += field(b, o)
		}
		if sum != field(card["outcomes"], o) {
			return false
		}
	}
	for _, x := range card["disputes"].(map[string]any) {
		if !has(x, "of") {
			return false
		}
		d := x.(map[string]any)
		if !partitions(d["by_outcome"], disputeOutcomes) || !partitions(d["by_forum"], forums) {
			return false
		}
		if field(d["by_outcome"], "of") != field(d, "of") || field(d["by_forum"], "of") != field(d, "of") {
			return false
		}
	}
	return true
}

func status(ok bool) string {
	if ok {
		return Pass
	}
	return Fail
}

// numbers turns every json.Number in v into its float64 value, so that two
// cards compare by value.
func numbers(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = numbers(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = numbers(e)
		}
		return out
	case json.Number:
		return num(x)
	}
	return v
}

// Check reports the six card properties of SH §6 for the card's JSON octets.
// policy, asOf and deals are each optional (nil); a property that needs a
// missing one is NOT_CHECKED. It returns an error for a malformed input,
// never for a malformed card: a card that is not JSON at all fails every
// property that reads it.
func Check(card []byte, policy *Policy, asOf *AsOf, deals []Deal) (map[string]string, error) {
	p := map[string]string{}
	v, err := decode(card)
	parsed := err == nil
	if !parsed {
		v = nil
	}
	p["card_form"] = status(cardForm(v))
	p["counts_integral"] = status(parsed && countsIntegral(v))
	if p["card_form"] == Pass && p["counts_integral"] == Pass {
		p["denominator"] = status(denominator(v))
	} else {
		p["denominator"] = NotChecked
	}
	m, _ := v.(map[string]any)
	if policy == nil {
		p["window_from_policy"] = NotChecked
	} else {
		if !policy.Window.All && (policy.Window.Months < 1 || policy.Window.Months > maxCount) {
			return nil, fmt.Errorf("not a policy window: %+v", policy.Window)
		}
		w, ok := windowOf(m["window"])
		p["window_from_policy"] = status(m != nil && ok && w == policy.Window && m["policy"] == policy.Digest)
	}
	if asOf == nil {
		p["as_of"] = NotChecked
	} else {
		if _, err := parseTime(asOf.FirstCheckpointTime); err != nil {
			return nil, err
		}
		p["as_of"] = status(m != nil && m["anchor"] == asOf.Anchor && m["since"] == asOf.FirstCheckpointTime[:7])
	}
	ready := deals != nil && policy != nil && asOf != nil &&
		p["card_form"] == Pass && p["counts_integral"] == Pass && p["denominator"] == Pass
	if !ready {
		p["counts_recompute"] = NotChecked
		return p, nil
	}
	anchor, err := parseTime(asOf.AnchorTime)
	if err != nil {
		return nil, err
	}
	derived, err := counts(deals, policy.Window, anchor)
	if err != nil {
		return nil, err
	}
	octets, err := json.Marshal(derived)
	if err != nil {
		return nil, err
	}
	want, err := decode(octets)
	if err != nil {
		return nil, err
	}
	same := true
	for k, x := range want.(map[string]any) {
		if !reflect.DeepEqual(numbers(m[k]), numbers(x)) {
			same = false
		}
	}
	p["counts_recompute"] = status(same)
	return p, nil
}

// IsStandard is SH §6: a standard card reports every property as PASS or
// NOT_CHECKED, and its form, counts and denominators PASS.
func IsStandard(p map[string]string) bool {
	for _, k := range Properties {
		if p[k] != Pass && p[k] != NotChecked {
			return false
		}
	}
	return p["card_form"] == Pass && p["counts_integral"] == Pass && p["denominator"] == Pass
}
