// SPDX-License-Identifier: Apache-2.0

package evidencerequest_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	er "github.com/action-state-group/agent-action-capsule/go/evidencerequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The request-draft conformance vectors, read in place from this
// repository's vectors/evidence-request. Every expected result there was
// written from draft-mih-agent-evidence-request-00, never from an
// implementation. Each corpus test requires the corpus's full case count,
// and TestVectorChecksums requires those counts to total the manifest's 125.
func vectorDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Join(filepath.Dir(filename), "..", "..", "vectors", "evidence-request")
}

// corpusCounts is the case count of each corpus, as manifest.json states it.
var corpusCounts = map[string]int{
	"request.json": 33, "resolution.json": 19, "digest.json": 7, "refusal.json": 22,
	"outcomes.json": 13, "invariance.json": 6, "retention.json": 25,
}

func readVector(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorDir(t), name))
	require.NoError(t, err)
	return data
}

func loadCases[T any](t *testing.T, name string) []T {
	t.Helper()
	var corpus struct {
		Count int `json:"count"`
		Cases []T `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(readVector(t, name), &corpus))
	require.Len(t, corpus.Cases, corpusCounts[name], "%s case count", name)
	require.Equal(t, corpus.Count, len(corpus.Cases), "%s count member", name)
	return corpus.Cases
}

// TestVectorChecksums checks every file the corpus lists in SHA256SUMS, and
// that the manifest's per-file case counts are the ones the tests assert.
func TestVectorChecksums(t *testing.T) {
	file, err := os.Open(filepath.Join(vectorDir(t), "SHA256SUMS"))
	require.NoError(t, err)
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var names []string
	for scanner.Scan() {
		sum, name, ok := strings.Cut(scanner.Text(), "  ")
		require.True(t, ok, "SHA256SUMS line %q", scanner.Text())
		assert.Equal(t, sum, er.Digest(readVector(t, name)), "%s does not match SHA256SUMS", name)
		names = append(names, name)
	}
	require.NoError(t, scanner.Err())
	entries, err := os.ReadDir(vectorDir(t))
	require.NoError(t, err)
	for _, entry := range entries {
		if entry.Name() != "SHA256SUMS" {
			assert.Contains(t, names, entry.Name(), "a vector file is missing from SHA256SUMS")
		}
	}

	var manifest struct {
		Files []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Count  int    `json:"count"`
		} `json:"files"`
	}
	require.NoError(t, json.Unmarshal(readVector(t, "manifest.json"), &manifest))
	total := 0
	for _, entry := range manifest.Files {
		assert.Equal(t, entry.SHA256, er.Digest(readVector(t, entry.Path)), "manifest digest of %s", entry.Path)
		if want, corpus := corpusCounts[entry.Path]; corpus {
			assert.Equal(t, want, entry.Count, "manifest case count of %s", entry.Path)
			total += entry.Count
		} else if entry.Path == "refusal-imported.json" {
			// One object, asserted as refusal.json's pos-imported-interop-vector.
			assert.Equal(t, 1, entry.Count)
		}
	}
	require.Len(t, corpusCounts, 7)
	assert.Equal(t, 125, total)
}

// TestRegistryVector: the strings the draft fixes are this package's.
func TestRegistryVector(t *testing.T) {
	var registry struct {
		SubjectForms   []string       `json:"subject_forms"`
		RefusalReasons []string       `json:"refusal_reasons"`
		Derivations    map[string]any `json:"derivations"`
		Subprotocol    string         `json:"subprotocol"`
		NotRegistered  []string       `json:"not_registered_examples"`
		Coverage       []string       `json:"coverage_members"`
	}
	require.NoError(t, json.Unmarshal(readVector(t, "registry.json"), &registry))
	assert.Equal(t, registry.RefusalReasons, er.RefusalReasons)
	forms := make([]string, len(er.SubjectForms))
	for i, f := range er.SubjectForms {
		forms[i] = string(f)
	}
	assert.ElementsMatch(t, registry.SubjectForms, forms)
	assert.Equal(t, map[string]any{er.DerivationHistoryCard: map[string]any{"declared_fields": []any{}}}, registry.Derivations)
	assert.Equal(t, er.Subprotocol, registry.Subprotocol)
	assert.Equal(t, []string{"expected_pin", "min_freshness"}, registry.Coverage)
	for _, token := range registry.NotRegistered {
		assert.NotContains(t, er.RefusalReasons, token)
		assert.NotContains(t, forms, token)
	}
}

type requestVector struct {
	ID                string `json:"id"`
	RequestJSON       string `json:"request_json"`
	RequestJSONDigest string `json:"request_json_digest"`
	RequestCBORHex    string `json:"request_cbor_hex"`
	RequestCBORDigest string `json:"request_cbor_digest"`
	Expect            struct {
		WellFormed bool   `json:"well_formed"`
		Reason     string `json:"reason"`
	} `json:"expect"`
}

// bindings is the request octets of a case in each binding it gives, with
// the digest the case states for each.
func (c requestVector) bindings(t *testing.T) ([]er.Message, []string) {
	t.Helper()
	messages := []er.Message{{Octets: []byte(c.RequestJSON), MediaType: er.MediaTypeJSON}}
	digests := []string{c.RequestJSONDigest}
	if c.RequestCBORHex != "" {
		octets, err := hex.DecodeString(c.RequestCBORHex)
		require.NoError(t, err)
		messages = append(messages, er.Message{Octets: octets, MediaType: er.MediaTypeCBOR})
		digests = append(digests, c.RequestCBORDigest)
	}
	return messages, digests
}

// TestRequestVectors runs every request.json case through ParseRequest in
// both bindings: each must be well formed, or refused with exactly the
// stated reason. The digest of the octets fed is the stated digest.
func TestRequestVectors(t *testing.T) {
	for _, c := range loadCases[requestVector](t, "request.json") {
		t.Run(c.ID, func(t *testing.T) {
			messages, digests := c.bindings(t)
			for i, m := range messages {
				require.NotEmpty(t, digests[i], "%s: the case states a digest", m.MediaType)
				assert.Equal(t, digests[i], er.Digest(m.Octets), "%s: digest of the octets", m.MediaType)
				got := er.ParseRequest(m)
				if c.Expect.WellFormed {
					assert.Empty(t, got.Reason, "%s: refused (%s), want well formed", m.MediaType, got.Why)
				} else {
					assert.Equal(t, c.Expect.Reason, got.Reason, "%s", m.MediaType)
				}
			}
		})
	}
}

// TestDigestVectors: the request digest is over the octets as received,
// and a refusal identifies a request only by the digest of those octets.
func TestDigestVectors(t *testing.T) {
	type digestVector struct {
		ID                   string `json:"id"`
		Encoding             string `json:"encoding"`
		RequestJSON          string `json:"request_json"`
		RequestCBORHex       string `json:"request_cbor_hex"`
		RefusalRequestDigest string `json:"refusal_request_digest"`
		Expect               struct {
			RequestDigest     string `json:"request_digest"`
			IdentifiesRequest *bool  `json:"identifies_request"`
		} `json:"expect"`
	}
	for _, c := range loadCases[digestVector](t, "digest.json") {
		t.Run(c.ID, func(t *testing.T) {
			m := er.Message{Octets: []byte(c.RequestJSON), MediaType: er.MediaTypeJSON}
			if c.Encoding == "cbor" {
				octets, err := hex.DecodeString(c.RequestCBORHex)
				require.NoError(t, err)
				m = er.Message{Octets: octets, MediaType: er.MediaTypeCBOR}
			}
			assert.Empty(t, er.ParseRequest(m).Reason, "every digest case is a well-formed request")
			if c.Expect.IdentifiesRequest != nil {
				assert.Equal(t, *c.Expect.IdentifiesRequest, c.RefusalRequestDigest == er.Digest(m.Octets))
				return
			}
			require.NotEmpty(t, c.Expect.RequestDigest)
			assert.Equal(t, c.Expect.RequestDigest, er.Digest(m.Octets))
		})
	}
}

type refusalVector struct {
	ID             string          `json:"id"`
	Refusal        json.RawMessage `json:"refusal"`
	File           string          `json:"file"`
	FileSHA256     string          `json:"file_sha256"`
	SigningBody    string          `json:"signing_body"`
	RefusalCBORHex string          `json:"refusal_cbor_hex"`
	RefusalCBORSum string          `json:"refusal_cbor_digest"`
	Expect         struct {
		Signature        string `json:"signature"`
		Conformant       bool   `json:"conformant"`
		ReasonRegistered bool   `json:"reason_registered"`
	} `json:"expect"`
}

type seededSigner struct{ key ed25519.PrivateKey }

func (s seededSigner) Sign(_ context.Context, message []byte) ([]byte, error) {
	return ed25519.Sign(s.key, message), nil
}

// TestRefusalVectors checks every refusal.json case with CheckRefusal, in
// each binding it gives, keeping the signature, registry and conformance
// answers apart (ERV A13). A refusal ParseReply reads verifies and conforms
// exactly when the case says so, and a conforming one is reproduced
// byte for byte by Refusal.Sign under the corpus's fixed key.
func TestRefusalVectors(t *testing.T) {
	var corpus struct {
		Keys map[string]struct {
			Seed   string `json:"seed_hex"`
			Public string `json:"public_key_hex"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(readVector(t, "refusal.json"), &corpus))
	keys := map[string]ed25519.PrivateKey{}
	for name, k := range corpus.Keys {
		seed, err := hex.DecodeString(k.Seed)
		require.NoError(t, err)
		private := ed25519.NewKeyFromSeed(seed)
		require.Equal(t, k.Public, hex.EncodeToString(private.Public().(ed25519.PublicKey)), "key %s", name)
		keys[k.Public] = private
	}
	for _, c := range loadCases[refusalVector](t, "refusal.json") {
		t.Run(c.ID, func(t *testing.T) {
			raw := []byte(c.Refusal)
			if c.File != "" {
				raw = readVector(t, c.File)
				assert.Equal(t, c.FileSHA256, er.Digest(raw))
			}
			messages := []er.Message{{Octets: raw, MediaType: er.MediaTypeJSON}}
			if c.RefusalCBORHex != "" {
				octets, err := hex.DecodeString(c.RefusalCBORHex)
				require.NoError(t, err)
				assert.Equal(t, c.RefusalCBORSum, er.Digest(octets))
				messages = append(messages, er.Message{Octets: octets, MediaType: er.MediaTypeCBOR})
			}
			for _, m := range messages {
				check := er.CheckRefusal(m)
				assert.Equal(t, c.Expect.Signature == "valid", check.SignatureValid, "%s signature", m.MediaType)
				assert.Equal(t, c.Expect.ReasonRegistered, check.ReasonRegistered, "%s reason_registered", m.MediaType)
				assert.Equal(t, c.Expect.Conformant, check.Conformant, "%s conformant", m.MediaType)
				// What a requester records for this refusal (ER §4.5).
				want := er.StateRefusalSignatureInvalid
				switch {
				case c.Expect.Conformant:
					want = er.StateRefusal
				case c.Expect.Signature == "valid":
					want = er.StateRefusalNonconformant
				}
				for _, open := range []bool{true, false} {
					assert.Equal(t, want, er.Observation{Received: er.ReceivedRefusal, Refusal: check, WindowOpen: open}.State(), "%s state", m.MediaType)
				}

				reply, err := er.ParseReply(m)
				if err != nil {
					assert.False(t, c.Expect.Conformant, "%s: a conforming refusal was not read: %v", m.MediaType, err)
					continue
				}
				require.NotNil(t, reply.Refusal)
				r := *reply.Refusal
				verified := r.Verify() == nil
				assert.Equal(t, c.Expect.Signature == "valid", verified, "%s Verify", m.MediaType)
				assert.Equal(t, c.Expect.Conformant, verified && r.Conforming(), "%s Conforming", m.MediaType)
				assert.Equal(t, c.Expect.Conformant, r.VerifyFor(r.KeyID, r.RequestDigest) == nil, "%s VerifyFor", m.MediaType)
				if c.SigningBody != "" {
					body, err := r.SigningBody()
					require.NoError(t, err)
					assert.Equal(t, c.SigningBody, string(body))
				}
				if key, held := keys[r.KeyID]; held && c.Expect.Conformant {
					resigned, err := er.Refusal{RequestDigest: r.RequestDigest, Reason: r.Reason, IssuedAt: r.IssuedAt, KeyID: r.KeyID, Detail: r.Detail}.Sign(context.Background(), seededSigner{key})
					require.NoError(t, err)
					assert.Equal(t, r.Sig, resigned.Sig, "Ed25519 is deterministic: the same key signs the same body identically")
					if m.MediaType == er.MediaTypeCBOR {
						encoded, err := er.EncodeReply(er.MediaTypeCBOR, nil, &resigned)
						require.NoError(t, err)
						assert.Equal(t, m.Octets, encoded.Octets, "the CBOR frame is the deterministic encoding")
					}
				}
			}
		})
	}
}

// vectorView is the resolution.json responder state as a View.
type vectorView struct {
	logSize     uint64
	anchorList  []er.AnchorView
	records     []string
	correlation map[string][]string
	citations   map[string][]string
}

func (v vectorView) Anchors() []er.AnchorView { return v.anchorList }
func (v vectorView) LogEntries() uint64       { return v.logSize }
func (v vectorView) LeafOf(d string) (uint64, bool) {
	i := slices.Index(v.records, d)
	return uint64(i), i >= 0
}
func (v vectorView) Servable(leaf uint64) bool { return leaf < uint64(len(v.records)) }
func (v vectorView) positions(ds []string) []uint64 {
	var out []uint64
	for _, d := range ds {
		if leaf, ok := v.LeafOf(d); ok {
			out = append(out, leaf)
		}
	}
	return out
}
func (v vectorView) Correlated(id string) []uint64     { return v.positions(v.correlation[id]) }
func (v vectorView) Citing(half string) []uint64       { return v.positions(v.citations[half]) }
func (v vectorView) Lapsed(er.Subject, time.Time) bool { return false }

// TestResolutionVectors runs every resolution.json case through
// ParseRequest and Decide, with the corpus's declared responder state as
// the View and its declared capabilities (and each case's overrides) as the
// Policy. The vectors' "now" is the day after the newest anchor.
func TestResolutionVectors(t *testing.T) {
	var corpus struct {
		Responder struct {
			LogSize            uint64 `json:"log_size"`
			PositionalOrdering bool   `json:"positional_ordering"`
			Anchors            []struct {
				Digest   string `json:"digest"`
				Size     uint64 `json:"size"`
				IssuedAt string `json:"issued_at"`
			} `json:"anchors"`
			Records               []string            `json:"records"`
			Correlations          map[string][]string `json:"correlations"`
			ExchangeCitations     map[string][]string `json:"exchange_citations"`
			SupportedDerivations  map[string][]string `json:"supported_derivations"`
			IssuesNewCommitments  bool                `json:"issues_new_commitments"`
			UniformPolicyDeclined bool                `json:"uniform_policy_declined"`
		} `json:"responder"`
	}
	require.NoError(t, json.Unmarshal(readVector(t, "resolution.json"), &corpus))
	state := corpus.Responder
	require.Equal(t, map[string][]string{er.DerivationHistoryCard: {"full_history", "checkpoints"}}, state.SupportedDerivations,
		"the corpus's derivations are the built-in history_card/1 over full_history and checkpoints")
	view := vectorView{logSize: state.LogSize, records: state.Records, correlation: state.Correlations, citations: state.ExchangeCitations}
	for _, a := range state.Anchors {
		issued, ok := er.ParseProfileTime(a.IssuedAt)
		require.True(t, ok)
		view.anchorList = append(view.anchorList, er.AnchorView{Digest: a.Digest, Entries: a.Size, IssuedAt: issued})
	}
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

	type resolutionVector struct {
		requestVector
		Overrides map[string]any `json:"responder_overrides"`
		Expect    struct {
			Answer string `json:"answer"`
			Reason string `json:"reason"`
		} `json:"expect"`
	}
	for _, c := range loadCases[resolutionVector](t, "resolution.json") {
		t.Run(c.ID, func(t *testing.T) {
			policy := er.Policy{Uniform: state.UniformPolicyDeclined, Unpositioned: !state.PositionalOrdering, MayIssue: state.IssuesNewCommitments}
			for name, value := range c.Overrides {
				set, ok := value.(bool)
				require.True(t, ok, "override %s", name)
				switch name {
				case "uniform_policy_declined":
					policy.Uniform = set
				case "positional_ordering":
					policy.Unpositioned = !set
				default:
					t.Fatalf("override %s is not one this test reads", name)
				}
			}
			require.Contains(t, []string{"artifact", "refusal"}, c.Expect.Answer)
			messages, digests := c.bindings(t)
			for i, m := range messages {
				assert.Equal(t, digests[i], er.Digest(m.Octets), "%s: digest of the octets", m.MediaType)
				got := er.ParseRequest(m).Reason
				if got == "" {
					req := er.ParseRequest(m).Request
					d := er.Decide(view, req, policy, now)
					require.False(t, d.NeedAnchor, "this responder issues no new commitments")
					got = d.Reason
					if got == "" {
						assert.NotEmpty(t, view.anchorList, "an artifact is under an anchor")
						assert.True(t, d.HalfPin || d.Anchor >= 0 && d.Anchor < len(view.anchorList))
					}
				}
				if c.Expect.Answer == "artifact" {
					assert.Empty(t, got, "%s: refused, want an artifact", m.MediaType)
				} else {
					assert.Equal(t, c.Expect.Reason, got, "%s", m.MediaType)
				}
			}
		})
	}
}

// TestOutcomeVectors maps each outcomes.json case's facts to a state: the
// one expected, and none it must never be recorded as.
func TestOutcomeVectors(t *testing.T) {
	type outcomeVector struct {
		ID    string `json:"id"`
		Facts struct {
			Received     string `json:"received"`
			Verification string `json:"artifact_verification"`
			Signature    string `json:"refusal_signature"`
			Reason       string `json:"refusal_reason"`
			Window       string `json:"window"`
		} `json:"facts"`
		Expect struct {
			State         string   `json:"state"`
			MustNotRecord []string `json:"must_not_record_as"`
		} `json:"expect"`
	}
	received := map[string]er.Received{
		"artifact": er.ReceivedArtifact, "refusal": er.ReceivedRefusal, "nothing": er.ReceivedNothing,
		"transport_error": er.ReceivedTransportError, "subprotocol_not_offered": er.ReceivedSubprotocolNotOffered,
	}
	for _, c := range loadCases[outcomeVector](t, "outcomes.json") {
		t.Run(c.ID, func(t *testing.T) {
			kind, ok := received[c.Facts.Received]
			require.True(t, ok, "received %q", c.Facts.Received)
			require.Contains(t, []string{"open", "closed"}, c.Facts.Window)
			// A refusal's facts state its signature and reason; its other
			// members are well formed, so it conforms when both hold.
			valid, registered := c.Facts.Signature == "valid", slices.Contains(er.RefusalReasons, c.Facts.Reason)
			o := er.Observation{
				Received:         kind,
				ArtifactVerified: c.Facts.Verification == "verified",
				Refusal:          er.RefusalCheck{SignatureValid: valid, ReasonRegistered: registered, Conformant: valid && registered},
				WindowOpen:       c.Facts.Window == "open",
			}
			state := o.State()
			assert.Equal(t, c.Expect.State, state)
			assert.NotContains(t, c.Expect.MustNotRecord, state)
		})
	}
}

// TestRetentionVectors classifies each retention.json case: a refusal or
// an absence against the commitment, or a commitment's well-formedness.
func TestRetentionVectors(t *testing.T) {
	type retentionVector struct {
		ID         string          `json:"id"`
		Facts      map[string]any  `json:"facts"`
		Commitment json.RawMessage `json:"commitment"`
		Expect     struct {
			Classification string `json:"classification"`
			State          string `json:"state"`
			WellFormed     *bool  `json:"well_formed"`
		} `json:"expect"`
	}
	commitments := map[string]er.CommitmentState{"in_force": er.CommitmentInForce, "lapsed": er.CommitmentLapsed, "none": er.CommitmentNone}
	for _, c := range loadCases[retentionVector](t, "retention.json") {
		t.Run(c.ID, func(t *testing.T) {
			if c.Facts == nil {
				require.NotNil(t, c.Expect.WellFormed)
				_, err := er.ParseRetentionCommitment(er.Message{Octets: c.Commitment, MediaType: er.MediaTypeJSON})
				assert.Equal(t, *c.Expect.WellFormed, err == nil, "%v", err)
				return
			}
			commitment, ok := commitments[c.Facts["commitment"].(string)]
			require.True(t, ok)
			if reason, isRefusal := c.Facts["refusal_reason"].(string); isRefusal {
				assert.Equal(t, c.Expect.Classification, er.ClassifyRefusal(commitment, reason))
				return
			}
			require.Equal(t, "nothing", c.Facts["received"])
			assert.Equal(t, c.Expect.Classification, er.ClassifyAbsence(commitment))
			o := er.Observation{Received: er.ReceivedNothing, WindowOpen: c.Facts["window"] == "open"}
			assert.Equal(t, c.Expect.State, o.State())
		})
	}
}

// TestInvarianceVectors compares each invariance.json case's observations.
func TestInvarianceVectors(t *testing.T) {
	type invarianceVector struct {
		ID           string `json:"id"`
		Observations []struct {
			ResolvedAnchor string `json:"resolved_anchor"`
			ArtifactHex    string `json:"artifact_hex"`
		} `json:"observations"`
		Expect struct {
			Invariance string `json:"invariance"`
		} `json:"expect"`
	}
	for _, c := range loadCases[invarianceVector](t, "invariance.json") {
		t.Run(c.ID, func(t *testing.T) {
			require.GreaterOrEqual(t, len(c.Observations), 2)
			answers := make([]er.Answer, len(c.Observations))
			for i, o := range c.Observations {
				artifact, err := hex.DecodeString(o.ArtifactHex)
				require.NoError(t, err)
				answers[i] = er.Answer{ResolvedAnchor: o.ResolvedAnchor, Artifact: artifact}
			}
			assert.Equal(t, c.Expect.Invariance, er.CompareAnswers(answers))
		})
	}
}
