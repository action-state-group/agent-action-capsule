// SPDX-License-Identifier: Apache-2.0

package personalhistoryoutcome

import (
	"encoding/json"
	"testing"

	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/stretchr/testify/assert"
)

func judgeEval(t *testing.T, cases []any) (map[string]string, string) {
	t.Helper()
	record := map[string]any{"judge": "j", "subject_ref": "deal", "record": map[string]any{"contract_ref": "c@1", "cases": cases}}
	raw, err := json.Marshal(record)
	assert.NoError(t, err)
	d := sha(raw)
	e := evaluator{cfg: Config{Roles: Roles{Judge: []string{"j"}}}, objects: map[string][]byte{d: raw}}
	return e.judge(map[string]any{"predicate": "completed"}, "deal", map[string]any{"leaf_index": uint64(9)}, nil, []string{d})
}

func TestJudgeVerdictAllowedFailsClosedOnAnyOtherVerdict(t *testing.T) {
	for _, verdict := range []any{"out_of_scope", "not_applicable", "", []any{}, map[string]any{}, 1, nil} {
		props, _ := judgeEval(t, []any{map[string]any{"case_id": "completed", "verdict": verdict, "acts": []any{}}})
		assert.Equal(t, evidencerequest.StatusFail, props["judge_verdict_allowed"], verdict)
		assert.False(t, counts(props))
	}
	// A missing verdict fails too.
	props, _ := judgeEval(t, []any{map[string]any{"case_id": "completed", "acts": []any{}}})
	assert.Equal(t, evidencerequest.StatusFail, props["judge_verdict_allowed"])
}

func TestJudgeVerdictAllowedPassesTheThree(t *testing.T) {
	for _, verdict := range []string{"met", "not_met", "not_evaluable"} {
		props, got := judgeEval(t, []any{map[string]any{"case_id": "completed", "verdict": verdict, "acts": []any{}}})
		assert.Equal(t, evidencerequest.StatusPass, props["judge_verdict_allowed"])
		assert.Equal(t, verdict, got)
	}
}

func TestJudgeVerdictAllowedNotCheckedWithoutOneCase(t *testing.T) {
	one := map[string]any{"case_id": "completed", "verdict": "out_of_scope", "acts": []any{}}
	for _, cases := range [][]any{{}, {one, one}} {
		props, verdict := judgeEval(t, cases)
		assert.Equal(t, evidencerequest.StatusNotChecked, props["judge_verdict_allowed"])
		assert.Empty(t, verdict)
		assert.False(t, counts(props))
	}
	// The judge record not held.
	e := evaluator{}
	props, verdict := e.judge(map[string]any{"predicate": "completed"}, "deal", map[string]any{"leaf_index": uint64(9)}, nil, []string{"00"})
	assert.Equal(t, evidencerequest.StatusNotChecked, props["judge_verdict_allowed"])
	assert.Empty(t, verdict)
}

func TestOpeningResults(t *testing.T) {
	nonce := "10c056721ca284db057474a7638332db075bf354bb52830e8574ad5901d917b0"
	opening := map[string]any{"nonce": nonce, "text": "terms"}
	commit := sha(jcs(opening))
	env := map[string]any{"subject": map[string]any{"correlation": "d"},
		"artifact": map[string]any{"records": []any{map[string]any{"deal_commitment": commit}}}}
	envs := []map[string]any{env}
	assert.Equal(t, map[string]string{"d": "PASS"}, openingResults(envs, map[string]any{"d": opening}))
	assert.Equal(t, map[string]string{"d": NotPresent}, openingResults(envs, map[string]any{}))
	assert.Equal(t, map[string]string{"d": NotPresent}, openingResults(envs, map[string]any{"d": nil}))
	assert.Equal(t, map[string]string{"d": "FAIL"}, openingResults(envs, map[string]any{"d": map[string]any{"nonce": nonce, "text": "other"}}))
	// A value JCS cannot encode never matches the digest of the empty string.
	empty := map[string]any{"subject": map[string]any{"correlation": "d"},
		"artifact": map[string]any{"records": []any{map[string]any{"deal_commitment": sha(nil)}}}}
	assert.Equal(t, map[string]string{"d": "FAIL"},
		openingResults([]map[string]any{empty}, map[string]any{"d": map[string]any{"nonce": nonce, "text": 0.5}}))
}

func TestNativeCheckerGetsACopyOfTheCitedObjectsOnly(t *testing.T) {
	d1, d2 := sha([]byte("a")), sha([]byte("b"))
	e := evaluator{objects: map[string][]byte{d1: []byte("a"), d2: []byte("b")}}
	e.cfg.Native = func(n NativeClaim) string {
		assert.Len(t, n.Objects, 1)
		n.Objects[d1][0] = 'x'
		return evidencerequest.StatusPass
	}
	assert.Equal(t, evidencerequest.StatusPass, e.nativeCheck(map[string]any{}, []string{d1}))
	assert.Equal(t, []byte("a"), e.objects[d1])
}
