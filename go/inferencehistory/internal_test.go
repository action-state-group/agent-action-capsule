// SPDX-License-Identifier: Apache-2.0

package inferencehistory

import (
	"math"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/stretchr/testify/assert"
)

func dig(v any) string { return evidencerequest.Digest(jcs(v)) }

func envWith(pc any, history ...any) map[string]any {
	return map[string]any{"artifact": map[string]any{"period_counts": pc,
		"history_card": map[string]any{"history": history}}}
}

func checkpoint(at string, size uint64) any {
	return map[string]any{"checkpoint": map[string]any{"timestamp": at, "log_size": size}}
}

func policy() any {
	return map[string]any{"epoch": "2026-10-01T00:00:00Z", "length_s": uint64(86400), "floor": uint64(5)}
}

func period(from, to string, cells ...any) any {
	return map[string]any{"from": from, "to": to, "cells": append([]any{}, cells...)}
}

func counts(t *testing.T, pc any) map[string]any {
	t.Helper()
	return pc.(map[string]any)
}

func TestMalformedPeriodCountsFailClosed(t *testing.T) {
	d := map[string]any{"period_policy": policy()}
	for name, periods := range map[string][]any{
		"no cells":        {map[string]any{"from": "2026-10-01T00:00:00Z", "to": "2026-10-02T00:00:00Z"}},
		"cells not list":  {map[string]any{"from": "2026-10-01T00:00:00Z", "to": "2026-10-02T00:00:00Z", "cells": uint64(7)}},
		"cell not object": {period("2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", "x")},
	} {
		env := envWith(map[string]any{"policy": dig(policy()), "periods": periods},
			checkpoint("2026-10-02T00:00:00Z", 3))
		_, wellFormed := cells(env)
		assert.False(t, wellFormed, name)
		assert.False(t, floorOK(d, env), name)
	}
	_, wellFormed := cells(envWith(map[string]any{"periods": "x"}))
	assert.False(t, wellFormed)
}

func TestPeriodStartAtABoundaryAndEmptyStream(t *testing.T) {
	d := map[string]any{"period_policy": policy()}
	pc := func(periods ...any) any {
		return map[string]any{"policy": dig(policy()), "periods": append([]any{}, periods...)}
	}
	// An empty stream (no checkpoint commits a record) has no periods.
	assert.True(t, periodsOK(d, envWith(pc(), checkpoint("2026-10-02T00:00:00Z", 0))))
	assert.False(t, periodsOK(d, envWith(pc(period("2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z")),
		checkpoint("2026-10-02T00:00:00Z", 0))))
	// A stream with records needs periods.
	assert.False(t, periodsOK(d, envWith(pc(), checkpoint("2026-10-02T00:00:00Z", 2))))
	// The first period starts before the first checkpoint that commits a record.
	ok := envWith(pc(period("2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z")), checkpoint("2026-10-01T12:00:00Z", 2),
		checkpoint("2026-10-02T00:00:00Z", 3))
	assert.True(t, periodsOK(d, ok))
	// A period not aligned to the epoch fails.
	assert.False(t, periodsOK(d, envWith(pc(period("2026-10-01T06:00:00Z", "2026-10-02T06:00:00Z")),
		checkpoint("2026-10-02T06:00:00Z", 2))))
}

func TestPeriodLengthOverflowFailsClosed(t *testing.T) {
	p := map[string]any{"epoch": "2026-10-01T00:00:00Z", "length_s": uint64(1 << 40), "floor": uint64(1)}
	d := map[string]any{"period_policy": p}
	env := envWith(map[string]any{"policy": dig(p), "periods": []any{}}, checkpoint("2026-10-02T00:00:00Z", 0))
	assert.False(t, periodsOK(d, env))
	assert.False(t, anchorOK(d, env))
}

func TestPeriodFixedAtOneAnchor(t *testing.T) {
	cell := func(v uint64) any {
		return map[string]any{"unit": "exchanges_served", "label": "self_reported", "dimension": nil, "value": v}
	}
	at := checkpoint("2026-10-02T00:00:00Z", 3)
	a := envWith(map[string]any{"periods": []any{period("2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", cell(5))}}, at)
	same := envWith(map[string]any{"periods": []any{period("2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", cell(5))}}, at)
	changed := envWith(map[string]any{"periods": []any{period("2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", cell(6))}}, at)
	dropped := envWith(map[string]any{"periods": []any{}}, at)
	assert.Equal(t, evidencerequest.StatusPass, periodFixed([]map[string]any{a, same}))
	assert.Equal(t, evidencerequest.StatusFail, periodFixed([]map[string]any{a, changed}))
	assert.Equal(t, evidencerequest.StatusFail, periodFixed([]map[string]any{a, dropped}))
}

func TestUnencodableValueHasNoDigest(t *testing.T) {
	// A float has no JCS form: nothing, not even a producer-chosen
	// "unencodable" or an empty string, is its digest.
	v := map[string]any{"x": 0.5}
	for _, x := range []any{"unencodable", "", evidencerequest.Digest(nil)} {
		assert.False(t, digestIs(x, v), x)
	}
	assert.True(t, digestIs(dig(policy()), policy()))
}

func part(value any, why string) map[string]any {
	c := map[string]any{"dimension": map[string]any{"model": "m"}, "value": value}
	if why != "" {
		c["suppressed"] = why
	}
	return c
}

func total(value any, why string) map[string]any {
	c := part(value, why)
	c["dimension"] = nil
	return c
}

// ISH §6.2 items 3 and 5 under each revision, one table at a time.
func TestTableOKByRevision(t *testing.T) {
	b, cmp := "below_floor", "complementary"
	for _, tc := range []struct {
		name       string
		parts      []map[string]any
		total      map[string]any
		floor      uint64
		rev0, rev1 bool
	}{
		{"4+4 beside a published 8", []map[string]any{part(nil, b), part(nil, b)}, total(uint64(8), ""), 5, true, false},
		{"five 1s beside a published 5", []map[string]any{part(nil, b), part(nil, b), part(nil, b), part(nil, b), part(nil, b)},
			total(uint64(5), ""), 5, true, false},
		{"3+4 beside a published 7", []map[string]any{part(nil, b), part(nil, b)}, total(uint64(7), ""), 5, true, true},
		{"10 and 4+4 beside a published 18", []map[string]any{part(uint64(10), ""), part(nil, b), part(nil, b)},
			total(uint64(18), ""), 5, true, false},
		{"one withheld beside a published total", []map[string]any{part(uint64(9), ""), part(nil, b)}, total(uint64(12), ""), 5, false, false},
		{"one withheld and its partner", []map[string]any{part(nil, cmp), part(nil, b)}, total(uint64(12), ""), 5, true, true},
		{"total withheld beside two under the floor", []map[string]any{part(nil, b), part(nil, b)}, total(nil, cmp), 5, true, true},
		{"total withheld complementary beside one", []map[string]any{part(nil, cmp), part(nil, b)}, total(nil, cmp), 5, true, false},
		{"total withheld below the floor", []map[string]any{part(nil, b)}, total(nil, b), 5, true, true},
		{"three withheld, a rest of 2", []map[string]any{part(uint64(10), ""), part(nil, b), part(nil, b), part(nil, b)},
			total(uint64(12), ""), 5, true, false},
		{"published cells over the total", []map[string]any{part(uint64(10), ""), part(uint64(9), "")}, total(uint64(12), ""), 5, true, false},
		{"floor 1: nothing withheld", []map[string]any{part(uint64(1), ""), part(uint64(1), "")}, total(uint64(2), ""), 1, true, true},
		{"floor 2: two 1s beside 7 and 9", []map[string]any{part(nil, b), part(nil, b), part(uint64(7), "")}, total(uint64(9), ""), 2, true, false},
		{"no total", []map[string]any{part(nil, b), part(nil, b)}, nil, 5, true, true},
		{"floor 1: two withheld beside a withheld total", []map[string]any{part(nil, b), part(nil, b)}, total(nil, cmp), 1, true, false},
		{"floor 1: two withheld beside a total withheld below it", []map[string]any{part(nil, b), part(nil, b)}, total(nil, b), 1, true, false},
		{"floor 2: two under the floor, total 3", []map[string]any{part(nil, b), part(nil, b)}, total(uint64(3), ""), 2, true, false},
		{"10 and two under the floor beside 19", []map[string]any{part(uint64(10), ""), part(nil, b), part(nil, b)},
			total(uint64(19), ""), 5, true, false},
		{"/0 never sums: published cells past uint64", []map[string]any{part(uint64(1<<63), ""), part(uint64(1<<63), "")},
			total(uint64(5), ""), 5, true, false},
	} {
		assert.Equal(t, tc.rev0, tableOK(tc.parts, tc.total, tc.floor, 0), "/0 %s", tc.name)
		assert.Equal(t, tc.rev1, tableOK(tc.parts, tc.total, tc.floor, 1), "/1 %s", tc.name)
	}
}

func TestTableOKUnderRevision2(t *testing.T) {
	b, cmp := "below_floor", "complementary"
	one := func(published ...uint64) []map[string]any {
		out := []map[string]any{part(nil, b), part(nil, cmp)}
		for _, n := range published {
			out = append(out, part(n, ""))
		}
		return out
	}
	for _, tc := range []struct {
		name       string
		parts      []map[string]any
		total      map[string]any
		floor      uint64
		rev1, rev2 bool
	}{
		{"1, 5 and 9 beside 15", one(9), total(uint64(15), ""), 5, true, false},
		{"4, 6 and 6 beside 16", one(6), total(uint64(16), ""), 5, true, false},
		{"3, 5 and 5 beside 13", one(5), total(uint64(13), ""), 5, true, false},
		{"3, 6 and 6 beside 15", one(6), total(uint64(15), ""), 5, true, true},
		{"1 and 5 beside 6", one(), total(uint64(6), ""), 5, true, false},
		{"3 and 7 beside 10", one(), total(uint64(10), ""), 5, true, true},
		{"1, 5 and 9 beside 14", one(9), total(uint64(14), ""), 5, true, false},
		{"1, 5 and 9 beside 23", one(9), total(uint64(23), ""), 5, true, false},
		{"one and its partner beside a withheld total", one(9), total(nil, cmp), 5, false, true},
		{"one, no partner, beside a withheld total", []map[string]any{part(nil, b), part(uint64(9), "")}, total(nil, cmp), 5, false, false},
		{"one and two partners beside a withheld total", []map[string]any{part(nil, b), part(nil, cmp), part(nil, cmp)}, total(nil, cmp), 5, false, false},
		{"one and two partners beside 20", []map[string]any{part(nil, b), part(nil, cmp), part(nil, cmp), part(uint64(6), "")}, total(uint64(20), ""), 5, true, true},
		{"floor 2: one and its partner beside 5", one(), total(uint64(5), ""), 2, true, false},
		{"a total alone", nil, total(uint64(23), ""), 5, false, true},
		{"the largest floor: one and its partner beside a total under it", one(), total(uint64(10), ""), math.MaxUint64, true, false},
		{"a published cell near the top of uint64", one(1 << 62), total(uint64(1<<62)+6, ""), 5, true, false},
		{"a rest near the top of uint64", one(1 << 62), total(uint64(1<<62)+(1<<62)+4, ""), 5, true, false},
	} {
		assert.Equal(t, tc.rev1, tableOK(tc.parts, tc.total, tc.floor, 1), "/1 %s", tc.name)
		assert.Equal(t, tc.rev2, tableOK(tc.parts, tc.total, tc.floor, 2), "/2 %s", tc.name)
	}
}
