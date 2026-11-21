// SPDX-License-Identifier: Apache-2.0

package evidencerequest_test

import (
	"encoding/json"
	"math/bits"
	"testing"
	"time"

	er "github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// history-card-2.json and checkpoints-range.json are ER -03 corpora: the
// history_card/2 positions and card checks, and the ranged checkpoints
// subject.

type historyCard2Corpus struct {
	Draft     string   `json:"draft"`
	Count     int      `json:"count"`
	Findings  []string `json:"findings"`
	MaxWindow uint64   `json:"max_window"`
	LogKeys   []string `json:"log_keys"`
	Positions []struct {
		N         uint64   `json:"n"`
		Window    uint64   `json:"window"`
		Positions []uint64 `json:"positions"`
	} `json:"positions"`
	Cases []struct {
		ID     string          `json:"id"`
		Card   json.RawMessage `json:"card"`
		Anchor string          `json:"anchor"`
		Expect struct {
			Valid   bool    `json:"valid"`
			Finding *string `json:"finding"`
		} `json:"expect"`
	} `json:"cases"`
}

func loadHistoryCard2(t *testing.T) historyCard2Corpus {
	t.Helper()
	var c historyCard2Corpus
	require.NoError(t, json.Unmarshal(readVector(t, "history-card-2.json"), &c))
	require.Equal(t, "draft-mih-agent-evidence-request-03", c.Draft)
	require.Equal(t, c.Count, len(c.Cases))
	return c
}

func TestHistoryCard2Positions(t *testing.T) {
	c := loadHistoryCard2(t)
	require.Equal(t, er.HistoryCardFindings, c.Findings)
	require.Equal(t, uint64(er.MaxHistoryWindow), c.MaxWindow)
	require.NotEmpty(t, c.Positions)
	for _, row := range c.Positions {
		assert.Equal(t, row.Positions, er.HistoryPositions(row.N, row.Window), "n %d window %d", row.N, row.Window)
	}
}

func TestHistoryCard2PositionsBound(t *testing.T) {
	for _, n := range []uint64{1, 2, 5, 100, 1023, 1024, 4097, 1_000_000, 1<<40 + 3} {
		for _, w := range []uint64{1, 2, 8, 64} {
			got := er.HistoryPositions(n, w)
			require.Equal(t, uint64(0), got[0])
			require.Equal(t, n, got[len(got)-1])
			assert.LessOrEqual(t, len(got), int(w)+bits.Len64(n)+1, "W + floor(log2 n) + 2")
		}
	}
	assert.Equal(t, []uint64{0}, er.HistoryPositions(0, 1))
}

func TestHistoryCard2Vectors(t *testing.T) {
	c := loadHistoryCard2(t)
	seen := map[string]bool{}
	for _, tc := range c.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			card, err := er.DecodeJSON(tc.Card)
			require.NoError(t, err)
			got := er.CheckHistoryCard2(card, tc.Anchor, c.LogKeys)
			if tc.Expect.Valid {
				assert.Empty(t, got)
				require.Nil(t, tc.Expect.Finding)
			} else {
				require.NotNil(t, tc.Expect.Finding)
				assert.Equal(t, *tc.Expect.Finding, got)
				seen[got] = true
			}
		})
	}
	for _, f := range er.HistoryCardFindings {
		assert.True(t, seen[f], "a case for %s", f)
	}
}

type checkpointsRangeCorpus struct {
	Draft     string `json:"draft"`
	Responder struct {
		LogSize            uint64 `json:"log_size"`
		PositionalOrdering bool   `json:"positional_ordering"`
		Anchors            []struct {
			Digest   string `json:"digest"`
			Size     uint64 `json:"size"`
			IssuedAt string `json:"issued_at"`
		} `json:"anchors"`
		Records              []string            `json:"records"`
		Correlations         map[string][]string `json:"correlations"`
		ExchangeCitations    map[string][]string `json:"exchange_citations"`
		SupportedDerivations map[string][]string `json:"supported_derivations"`
	} `json:"responder"`
	CheckpointPositions map[string]int `json:"checkpoint_positions"`
	RequestCases        []requestVector
	Cases               []struct {
		requestVector
		Expect struct {
			Answer string `json:"answer"`
			Reason string `json:"reason"`
		} `json:"expect"`
	} `json:"cases"`
}

func loadCheckpointsRange(t *testing.T) checkpointsRangeCorpus {
	t.Helper()
	var c checkpointsRangeCorpus
	data := readVector(t, "checkpoints-range.json")
	require.NoError(t, json.Unmarshal(data, &c))
	var raw struct {
		RequestCases []requestVector `json:"request_cases"`
	}
	require.NoError(t, json.Unmarshal(data, &raw))
	c.RequestCases = raw.RequestCases
	require.Equal(t, "draft-mih-agent-evidence-request-03", c.Draft)
	return c
}

func TestCheckpointsRangeRequestVectors(t *testing.T) {
	c := loadCheckpointsRange(t)
	require.NotEmpty(t, c.RequestCases)
	for _, tc := range c.RequestCases {
		t.Run(tc.ID, func(t *testing.T) {
			messages, digests := tc.bindings(t)
			require.Len(t, messages, 2)
			for i, m := range messages {
				assert.Equal(t, digests[i], er.Digest(m.Octets))
				got := er.ParseRequest(m)
				if tc.Expect.WellFormed {
					require.Empty(t, got.Reason, "%s: %s", m.MediaType, got.Why)
					assert.True(t, got.Request.Subject.Valid())
				} else {
					assert.Equal(t, tc.Expect.Reason, got.Reason, "%s", m.MediaType)
				}
			}
		})
	}
}

func TestCheckpointsRangeResolutionVectors(t *testing.T) {
	c := loadCheckpointsRange(t)
	state := c.Responder
	view := vectorView{logSize: state.LogSize, records: state.Records, correlation: state.Correlations, citations: state.ExchangeCitations}
	for i, a := range state.Anchors {
		issued, ok := er.ParseProfileTime(a.IssuedAt)
		require.True(t, ok)
		require.Equal(t, i, c.CheckpointPositions[a.Digest], "anchors are listed in checkpoint order")
		view.anchorList = append(view.anchorList, er.AnchorView{Digest: a.Digest, Entries: a.Size, IssuedAt: issued})
	}
	policy := er.Policy{Unpositioned: !state.PositionalOrdering, Derivation: func(name string) ([]er.SubjectKind, bool) {
		forms, ok := state.SupportedDerivations[name]
		out := make([]er.SubjectKind, 0, len(forms))
		for _, f := range forms {
			out = append(out, er.SubjectKind(f))
		}
		return out, ok
	}}
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	for _, tc := range c.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			messages, _ := tc.bindings(t)
			for _, m := range messages {
				parsed := er.ParseRequest(m)
				require.Empty(t, parsed.Reason, parsed.Why)
				d := er.Decide(view, parsed.Request, policy, now)
				require.False(t, d.NeedAnchor)
				if tc.Expect.Answer == "artifact" {
					assert.Empty(t, d.Reason, "%s", m.MediaType)
				} else {
					assert.Equal(t, tc.Expect.Reason, d.Reason, "%s", m.MediaType)
				}
			}
		})
	}
}

// A checkpoint_range subject (ER -03 §3.1) is signed as its range and
// read back the same from either encoding; changing the range breaks the
// signature.
func TestEnvelopeSignsACheckpointRange(t *testing.T) {
	s, keyID := signer(t, 3)
	artifact := []byte(`{"history":[]}`)
	ranged := er.Subject{Kind: er.SubjectCheckpointRange, Range: [2]uint64{2, 5}}
	require.True(t, ranged.Valid())
	assert.Equal(t, map[string]any{"checkpoint_range": []any{uint64(2), uint64(5)}}, ranged.Value())
	unsigned := er.Envelope{
		Profile: er.ProfileID, RequestDigest: digestOf("req"), Subject: ranged,
		Anchor: er.Anchor{Digest: digestOf("anchor")}, ArtifactDigest: er.Digest(artifact),
		Responder: keyID, IssuedAt: "2026-11-17T00:00:00Z", Artifact: artifact,
	}
	e, err := unsigned.Sign(t.Context(), s)
	require.NoError(t, err)
	for _, mediaType := range []string{er.MediaTypeJSON, er.MediaTypeCBOR} {
		reply, err := er.EncodeReply(mediaType, &e, nil)
		require.NoError(t, err)
		parsed, err := er.ParseReply(reply.Message)
		require.NoError(t, err)
		require.NotNil(t, parsed.Envelope)
		assert.Equal(t, e, *parsed.Envelope)
		assert.NoError(t, parsed.Envelope.Verify())
	}
	widened := e
	widened.Subject.Range[1] = 6
	assert.Error(t, widened.Verify(), "the range is signed")
	unranged := e
	unranged.Subject = er.Subject{Kind: er.SubjectCheckpoints}
	assert.Error(t, unranged.Verify(), "a checkpoint_range is not a checkpoints subject")
}

// Both history cards are built in: Decide accepts history_card/2 with no
// Policy.Derivation, over checkpoints and full_history only.
func TestDecideHistoryCard2IsBuiltIn(t *testing.T) {
	issued := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	view := vectorView{logSize: 3, records: []string{digestOf("r")}, anchorList: []er.AnchorView{{Digest: digestOf("a0"), Entries: 1, IssuedAt: issued}, {Digest: digestOf("a1"), Entries: 3, IssuedAt: issued.Add(time.Hour)}}}
	now := issued.Add(24 * time.Hour)
	pin := er.Coverage{ExpectedPin: digestOf("a1")}
	for _, tc := range []struct {
		subject er.Subject
		reason  string
	}{
		{er.Subject{Kind: er.SubjectCheckpoints}, ""},
		{er.Subject{Kind: er.SubjectFullHistory}, ""},
		{er.Subject{Kind: er.SubjectCheckpointRange, Range: [2]uint64{0, 1}}, er.ReasonNoSuchSubject},
		{er.Subject{Kind: er.SubjectRecord, Digest: digestOf("r")}, er.ReasonNoSuchSubject},
	} {
		d := er.Decide(view, er.Request{Subject: tc.subject, Coverage: pin, Derivation: er.DerivationHistoryCard2}, er.Policy{}, now)
		assert.Equal(t, tc.reason, d.Reason, "%v", tc.subject)
	}
}
