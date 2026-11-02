// SPDX-License-Identifier: Apache-2.0

package inferencehistory

import (
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
