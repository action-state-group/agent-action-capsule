// SPDX-License-Identifier: BSD-3-Clause
package bundle

// The Evidence Bundle producer: BuildEvidenceBundle over a ProofSource and
// BuildUnprovenBundle. Every produced Bundle is read back with VerifyStrict:
// a range-proven Bundle of signed records is VALID, a producer-selected one
// INCOMPLETE, and a one-byte change INVALID. Each refusal is checked by name.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/envelope"
	"github.com/action-state-group/agent-action-capsule/go/witness"
	"github.com/action-state-group/checkpointed-local-log/go/checkpoint"
	"github.com/action-state-group/checkpointed-local-log/go/cll"
	"github.com/action-state-group/checkpointed-local-log/go/store/memory"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	producerKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x0B}, ed25519.SeedSize))
	logKey      = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x2C}, ed25519.SeedSize))
	producedAt  = time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	absent      = strings.Repeat("ab", 32)
)

const producerLogID = "producer-tests"

type capsuleOptions struct {
	parent     string
	cites      []string
	agentInput interface{}
}

func producerCapsule(t *testing.T, actionID string, opts capsuleOptions) map[string]interface{} {
	t.Helper()
	record := map[string]interface{}{
		"spec_version":        "draft-mih-scitt-agent-action-capsule-04",
		"format_version":      "4",
		"canonicalization_id": "jcs",
		"action_id":           actionID,
		"action_type":         "fyi",
		"operator":            "ACME-CO",
		"developer":           "agent@v1",
		"timestamp":           "2026-10-19T00:00:00Z",
		"assurance":           map[string]interface{}{"effect_mode": "not_applicable", "attestation_mode": "self_attested", "ledger_mode": "standalone"},
		"disposition":         map[string]interface{}{"verdict_class": "not_applicable", "decision": "report", "approver": "policy", "human_disposed": false},
	}
	if opts.parent != "" {
		record["chain"] = map[string]interface{}{"parent_capsule_id": opts.parent, "relation": "follows"}
	}
	if len(opts.cites) != 0 {
		references := make([]interface{}, len(opts.cites))
		for i, cited := range opts.cites {
			references[i] = map[string]interface{}{"type": "agent-action-capsule", "digest_alg": "SHA-256", "digest": cited}
		}
		record["references"] = references
	}
	if opts.agentInput != nil {
		value, err := jsonObject(map[string]interface{}{"v": opts.agentInput}, "test")
		require.NoError(t, err)
		digest, err := canonical.JSONDigest(value["v"])
		require.NoError(t, err)
		record["model_attestation"] = map[string]interface{}{"compute_attestation": map[string]interface{}{"agent_input_digest": digest}}
	}
	id, err := canonical.ComputeCapsuleID(record)
	require.NoError(t, err)
	record["capsule_id"] = id
	return record
}

func signedEnvelope(t *testing.T, capsuleID string) []byte {
	t.Helper()
	payload, err := hex.DecodeString(capsuleID)
	require.NoError(t, err)
	mode, err := cbor.CanonicalEncOptions().EncMode()
	require.NoError(t, err)
	protected, err := mode.Marshal(map[int64]interface{}{1: int64(-8), 3: envelope.ContentType, 4: []byte(producerKey.Public().(ed25519.PublicKey))})
	require.NoError(t, err)
	toBeSigned, err := mode.Marshal([]interface{}{"Signature1", protected, []byte{}, payload})
	require.NoError(t, err)
	encoded, err := mode.Marshal(cbor.Tag{Number: 18, Content: []interface{}{protected, map[interface{}]interface{}{}, payload, ed25519.Sign(producerKey, toBeSigned)}})
	require.NoError(t, err)
	return encoded
}

// testRecords is a RecordSource holding records by Capsule ID.
type testRecords struct{ held map[string]StoredRecord }

func newRecords() *testRecords { return &testRecords{held: map[string]StoredRecord{}} }

func (r *testRecords) put(t *testing.T, record map[string]interface{}, signed bool) {
	t.Helper()
	data, err := canonical.JCS(record)
	require.NoError(t, err)
	id := record["capsule_id"].(string)
	stored := StoredRecord{Capsule: data}
	if signed {
		stored.ProducerEnvelope = signedEnvelope(t, id)
	}
	r.held[id] = stored
}

func (r *testRecords) GetRecord(_ context.Context, id string) ([]byte, []byte, error) {
	stored, found := r.held[id]
	if !found {
		return nil, nil, fmt.Errorf("%w: %s", ErrRecordNotFound, id)
	}
	return stored.Capsule, stored.ProducerEnvelope, nil
}

// makeLog is a CLL memory backend holding leaves (hex values), checkpointed
// after the first covered of them (all when covered is negative).
func makeLog(t *testing.T, leaves []string, records RecordSource, covered int) ProofSource {
	t.Helper()
	ctx := t.Context()
	store := memory.New()
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	if covered < 0 {
		covered = len(leaves)
	}
	appendLeaves := func(values []string) {
		for _, value := range values {
			raw, err := hex.DecodeString(value)
			require.NoError(t, err)
			_, err = store.Append(ctx, cll.AppendInput{Value: raw, AppendedAt: producedAt})
			require.NoError(t, err)
		}
	}
	appendLeaves(leaves[:covered])
	signer, err := checkpoint.NewEd25519Signer(logKey)
	require.NoError(t, err)
	config := checkpoint.DefaultRunnerConfig(producerLogID)
	config.Cadence.CadenceEntries = 1
	runner, err := checkpoint.NewRunner(config, store, signer)
	require.NoError(t, err)
	_, err = runner.RunOnce(ctx, producedAt)
	require.NoError(t, err)
	appendLeaves(leaves[covered:])
	return ProofSourceFromCLL(store, records)
}

func ids(records ...map[string]interface{}) []string {
	out := make([]string, len(records))
	for i, record := range records {
		out[i] = record["capsule_id"].(string)
	}
	return out
}

func carriedIDs(bundle map[string]interface{}) []string {
	var out []string
	for _, record := range bundle["records"].([]interface{}) {
		out = append(out, record.(map[string]interface{})["capsule_id"].(string))
	}
	return out
}

func strictVerdictOf(bundle map[string]interface{}) string {
	return VerifyStrict(bundle, StrictOptions{}).Verdict
}

func claimStatus(t *testing.T, bundle map[string]interface{}, name string) string {
	t.Helper()
	claim := VerifyStrict(bundle, StrictOptions{}).Claim(name)
	require.NotNil(t, claim, name)
	return claim.Status
}

func requireRefusal(t *testing.T, err error, contains string) {
	t.Helper()
	var refusal *BuildError
	require.ErrorAs(t, err, &refusal)
	require.Contains(t, refusal.Error(), contains)
}

func depth(n int) *int { return &n }

// testChain is three signed records, each citing the one before; every leaf
// is a record.
func testChain(t *testing.T) (ProofSource, []map[string]interface{}, *testRecords) {
	t.Helper()
	records := newRecords()
	a := producerCapsule(t, "a", capsuleOptions{agentInput: map[string]interface{}{"step": 0}})
	b := producerCapsule(t, "b", capsuleOptions{parent: a["capsule_id"].(string)})
	c := producerCapsule(t, "c", capsuleOptions{parent: b["capsule_id"].(string)})
	for _, record := range []map[string]interface{}{a, b, c} {
		records.put(t, record, true)
	}
	return makeLog(t, ids(a, b, c), records, -1), []map[string]interface{}{a, b, c}, records
}

func cid(record map[string]interface{}) string { return record["capsule_id"].(string) }

// roundTrip is bundle as it reads back from its JSON text.
func roundTrip(t *testing.T, bundle map[string]interface{}) map[string]interface{} {
	t.Helper()
	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	value, err := decodeJSONText(data)
	require.NoError(t, err)
	return value.(map[string]interface{})
}

// -- success ---------------------------------------------------------------------

func TestBuildWholeLogRangeIsValid(t *testing.T) {
	source, caps, _ := testChain(t)
	bundle, err := BuildEvidenceBundle(t.Context(), source, BuildOptions{Root: cid(caps[2]), IntervalFrom: 1})
	require.NoError(t, err)
	assert.Equal(t, ids(caps...), carriedIDs(bundle))
	certificate := bundle["completeness_certificate"].(map[string]interface{})
	assert.Equal(t, json.Number("1"), certificate["first_seq"])
	assert.Equal(t, json.Number("3"), certificate["last_seq"])
	assert.Equal(t, stringList(ids(caps...)), certificate["body_digests"])
	assert.NotContains(t, bundle["completeness"], "selection")
	for _, record := range bundle["records"].([]interface{}) {
		assert.Equal(t, hex.EncodeToString(producerKey.Public().(ed25519.PublicKey)), record.(map[string]interface{})["key_id"])
	}
	assert.Equal(t, VerdictValid, strictVerdictOf(bundle))
	// Its JSON text reads back VALID too, and the digest is computable: every
	// number is a JSON integer.
	assert.Equal(t, VerdictValid, strictVerdictOf(roundTrip(t, bundle)))
	_, err = BundleDigest(bundle)
	require.NoError(t, err)
}

func TestBuildSuffixRangeIsValid(t *testing.T) {
	source, caps, _ := testChain(t)
	bundle, err := BuildEvidenceBundle(t.Context(), source, BuildOptions{Root: cid(caps[2]), IntervalFrom: 2, ClosureDepth: depth(1)})
	require.NoError(t, err)
	assert.Equal(t, ids(caps[1:]...), carriedIDs(bundle))
	assert.Equal(t, VerdictValid, strictVerdictOf(bundle))
}

func TestBuildNoRangeIsProducerSelectedAndIncomplete(t *testing.T) {
	source, caps, _ := testChain(t)
	bundle, err := BuildEvidenceBundle(t.Context(), source, BuildOptions{Root: cid(caps[1]), NoRange: true, ClosureDepth: depth(0)})
	require.NoError(t, err)
	assert.Equal(t, ids(caps[1]), carriedIDs(bundle))
	assert.Equal(t, SelectionProducerSelected, bundle["completeness"].(map[string]interface{})["selection"])
	assert.NotContains(t, bundle["completeness_certificate"], "range_proof")
	assert.Equal(t, "pass", claimStatus(t, bundle, "per_record_membership"))
	assert.Equal(t, VerdictIncomplete, strictVerdictOf(bundle))
}

func TestBuildCheckpointFieldsComeFromTheSignedStatement(t *testing.T) {
	source, caps, _ := testChain(t)
	bundle, err := BuildEvidenceBundle(t.Context(), source, BuildOptions{Root: cid(caps[0]), IntervalFrom: 1})
	require.NoError(t, err)
	stated := bundle["checkpoint"].(map[string]interface{})
	cose, err := strictB64URL.DecodeString(stated["cose"].(string))
	require.NoError(t, err)
	signed, err := witness.ParseSignedCheckpoint(cose)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"log_id": signed.LogID, "mmr_size": jsonInteger(signed.MMRSize), "root": signed.Root,
		"prev_size": jsonInteger(signed.PrevSize), "prev_root": signed.PrevRoot, "key_id": signed.KeyID,
		"timestamp": signed.Timestamp, "cose": stated["cose"],
	}, stated)
	assert.Equal(t, producerLogID, signed.LogID)
}

func TestBuildIncludeCarriesFurtherRecords(t *testing.T) {
	source, caps, _ := testChain(t)
	bundle, err := BuildEvidenceBundle(t.Context(), source, BuildOptions{Root: cid(caps[2]), NoRange: true, ClosureDepth: depth(0), Include: []string{cid(caps[0])}})
	require.NoError(t, err)
	assert.Equal(t, ids(caps[0], caps[2]), carriedIDs(bundle))
}

func TestBuildUnsignedRecordIsCarriedUnsignedAndIncomplete(t *testing.T) {
	records := newRecords()
	a := producerCapsule(t, "unsigned", capsuleOptions{})
	records.put(t, a, false)
	bundle, err := BuildEvidenceBundle(t.Context(), makeLog(t, ids(a), records, -1), BuildOptions{Root: cid(a), IntervalFrom: 1})
	require.NoError(t, err)
	record := bundle["records"].([]interface{})[0].(map[string]interface{})
	assert.NotContains(t, record, "signature")
	assert.NotContains(t, record, "key_id")
	assert.Equal(t, "withheld", claimStatus(t, bundle, "signatures"))
	assert.Equal(t, VerdictIncomplete, strictVerdictOf(bundle))
}

func TestBuildMissingCitationIsDeclaredAndIncomplete(t *testing.T) {
	records := newRecords()
	a := producerCapsule(t, "cites-absent", capsuleOptions{cites: []string{absent}})
	records.put(t, a, true)
	bundle, err := BuildEvidenceBundle(t.Context(), makeLog(t, ids(a), records, -1), BuildOptions{Root: cid(a), IntervalFrom: 1})
	require.NoError(t, err)
	complete := bundle["completeness"].(map[string]interface{})
	assert.Equal(t, []interface{}{absent}, complete["missing"])
	assert.Equal(t, "declared_incomplete", complete["records_mode"])
	assert.Equal(t, VerdictIncomplete, strictVerdictOf(bundle))
}

func TestBuildDisclosuresAndPayloadsMode(t *testing.T) {
	source, caps, _ := testChain(t)
	ctx := t.Context()
	root := cid(caps[0])
	payloadsMode := func(bundle map[string]interface{}) interface{} {
		return bundle["completeness"].(map[string]interface{})["payloads_mode"]
	}

	// A Go int in the overlay is carried as a JSON integer, so it matches the
	// committed digest.
	revealed, err := BuildEvidenceBundle(ctx, source, BuildOptions{Root: root, NoRange: true, ClosureDepth: depth(0),
		Disclosures: map[string]map[string]interface{}{root: {"agent_input": map[string]interface{}{"step": 0}}}})
	require.NoError(t, err)
	assert.Equal(t, "all", payloadsMode(revealed))
	assert.Equal(t, "pass", claimStatus(t, revealed, "disclosures"))

	plain, err := BuildEvidenceBundle(ctx, source, BuildOptions{Root: root, NoRange: true, ClosureDepth: depth(0)})
	require.NoError(t, err)
	assert.Equal(t, "selected", payloadsMode(plain))

	// Material carried elsewhere is the caller's claim.
	declared, err := BuildEvidenceBundle(ctx, source, BuildOptions{Root: root, NoRange: true, ClosureDepth: depth(0), PayloadsMode: "all"})
	require.NoError(t, err)
	assert.Equal(t, "all", payloadsMode(declared))

	_, err = BuildEvidenceBundle(ctx, source, BuildOptions{Root: cid(caps[2]), IntervalFrom: 1, PayloadsMode: "all",
		Disclosures: map[string]map[string]interface{}{cid(caps[1]): {}, root: {}}})
	requireRefusal(t, err, "does not reveal")
}

func TestBuildExtensionsVerificationAndProducerKey(t *testing.T) {
	source, caps, _ := testChain(t)
	ctx := t.Context()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	bundle, err := BuildEvidenceBundle(ctx, source, BuildOptions{Root: cid(caps[0]), IntervalFrom: 1, ProducerKey: key,
		Extensions:   map[string]interface{}{"example/notes": map[string]interface{}{"n": 1}},
		Verification: map[string]interface{}{"producer": "tests", "checks": []string{}}})
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"example/notes":   map[string]interface{}{"n": json.Number("1")},
		"producer-key/v1": map[string]interface{}{"public_key": hex.EncodeToString(key)},
	}, bundle["extensions"])
	assert.Equal(t, map[string]interface{}{"producer": "tests", "checks": []interface{}{}}, bundle["verification"])
	assert.Equal(t, VerdictValid, strictVerdictOf(bundle))

	for _, owned := range []string{"producer-key/v1", "composed/v1"} {
		_, err := BuildEvidenceBundle(ctx, source, BuildOptions{Root: cid(caps[0]), IntervalFrom: 1, Extensions: map[string]interface{}{owned: map[string]interface{}{}}})
		requireRefusal(t, err, "owns")
	}
	_, err = BuildEvidenceBundle(ctx, source, BuildOptions{Root: cid(caps[0]), IntervalFrom: 1, ProducerKey: []byte("short")})
	requireRefusal(t, err, "32-byte")
}

// -- tamper ----------------------------------------------------------------------

func flip(text string) string {
	if text[0] != '0' {
		return "0" + text[1:]
	}
	return "1" + text[1:]
}

func TestBuildOneByteChangeIsInvalid(t *testing.T) {
	source, caps, _ := testChain(t)
	built, err := BuildEvidenceBundle(t.Context(), source, BuildOptions{Root: cid(caps[2]), IntervalFrom: 2, ClosureDepth: depth(1)})
	require.NoError(t, err)
	tampers := map[string]func(bundle, certificate map[string]interface{}){
		"record": func(bundle, _ map[string]interface{}) {
			record := bundle["records"].([]interface{})[0].(map[string]interface{})
			record["action_id"] = flip(record["action_id"].(string))
		},
		"body_digest": func(_, certificate map[string]interface{}) {
			digests := certificate["body_digests"].([]interface{})
			digests[0] = flip(digests[0].(string))
		},
		"inclusion_proof": func(_, certificate map[string]interface{}) {
			member := certificate["memberships"].(map[string]interface{})[cid(caps[1])].(map[string]interface{})
			proof := member["inclusion_proof"].(map[string]interface{})
			for _, key := range []string{"witness", "peaks_left", "peaks_right"} {
				if hashes := proof[key].([]interface{}); len(hashes) != 0 {
					hashes[0] = flip(hashes[0].(string))
					return
				}
			}
			t.Fatal("the inclusion proof has no hash to change")
		},
		"range_witness": func(_, certificate map[string]interface{}) {
			witness := certificate["range_proof"].(map[string]interface{})["witness"].([]interface{})
			witness[0] = flip(witness[0].(string))
		},
		"cose": func(bundle, _ map[string]interface{}) {
			stated := bundle["checkpoint"].(map[string]interface{})
			raw, err := strictB64URL.DecodeString(stated["cose"].(string))
			require.NoError(t, err)
			raw[len(raw)-1] ^= 1
			stated["cose"] = strictB64URL.EncodeToString(raw)
		},
		"checkpoint_root": func(bundle, _ map[string]interface{}) {
			stated := bundle["checkpoint"].(map[string]interface{})
			stated["root"] = flip(stated["root"].(string))
		},
	}
	for name, tamper := range tampers {
		t.Run(name, func(t *testing.T) {
			bad := roundTrip(t, built)
			tamper(bad, bad["completeness_certificate"].(map[string]interface{}))
			assert.Equal(t, VerdictInvalid, strictVerdictOf(bad))
		})
	}
}

// -- refusals --------------------------------------------------------------------

func TestBuildIntervalIsRequired(t *testing.T) {
	source, caps, _ := testChain(t)
	ctx := t.Context()
	_, err := BuildEvidenceBundle(ctx, source, BuildOptions{Root: cid(caps[0])})
	requireRefusal(t, err, "IntervalFrom is required")
	_, err = BuildEvidenceBundle(ctx, source, BuildOptions{Root: cid(caps[0]), IntervalFrom: 1, NoRange: true})
	requireRefusal(t, err, "both set")
	_, err = BuildEvidenceBundle(ctx, source, BuildOptions{Root: cid(caps[0]), IntervalFrom: 9})
	requireRefusal(t, err, "past the checkpoint tip")
}

func TestBuildRecordBelowIntervalFromIsRefusedByName(t *testing.T) {
	source, caps, _ := testChain(t)
	ctx := t.Context()
	_, err := BuildEvidenceBundle(ctx, source, BuildOptions{Root: cid(caps[2]), IntervalFrom: 2, ClosureDepth: depth(2)})
	requireRefusal(t, err, fmt.Sprintf("below IntervalFrom 2: %s (seq 1)", cid(caps[0])))
	_, err = BuildEvidenceBundle(ctx, source, BuildOptions{Root: cid(caps[2]), IntervalFrom: 3, ClosureDepth: depth(0), Include: []string{cid(caps[0])}})
	requireRefusal(t, err, "below IntervalFrom")
}

func TestBuildRangeOverANonRecordLeafIsRefused(t *testing.T) {
	records := newRecords()
	a := producerCapsule(t, "a", capsuleOptions{})
	b := producerCapsule(t, "b", capsuleOptions{})
	records.put(t, a, true)
	records.put(t, b, true)
	stamp := strings.Repeat("cd", 32) // a leaf the store does not hold as a record
	source := makeLog(t, []string{cid(a), stamp, cid(b)}, records, -1)
	_, err := BuildEvidenceBundle(t.Context(), source, BuildOptions{Root: cid(b), IntervalFrom: 1})
	requireRefusal(t, err, "seq 2 in the interval is not a record")
	bundle, err := BuildEvidenceBundle(t.Context(), source, BuildOptions{Root: cid(b), IntervalFrom: 3})
	require.NoError(t, err)
	assert.Equal(t, VerdictValid, strictVerdictOf(bundle))
}

func TestBuildUncoveredRecordIsRefused(t *testing.T) {
	records := newRecords()
	a := producerCapsule(t, "a", capsuleOptions{})
	late := producerCapsule(t, "late", capsuleOptions{})
	records.put(t, a, true)
	records.put(t, late, true)
	source := makeLog(t, ids(a, late), records, 1)
	_, err := BuildEvidenceBundle(t.Context(), source, BuildOptions{Root: cid(late), NoRange: true})
	requireRefusal(t, err, "not covered by the checkpoint")
}

func TestBuildUnknownRootAndIncludeAreRefused(t *testing.T) {
	source, caps, _ := testChain(t)
	ctx := t.Context()
	_, err := BuildEvidenceBundle(ctx, source, BuildOptions{Root: absent, NoRange: true})
	requireRefusal(t, err, "no such record")
	_, err = BuildEvidenceBundle(ctx, source, BuildOptions{Root: cid(caps[0]), NoRange: true, Include: []string{absent}})
	requireRefusal(t, err, "Include: no such record")
}

func TestBuildBadOptionsAreRefused(t *testing.T) {
	source, caps, _ := testChain(t)
	root := cid(caps[0])
	cases := []struct {
		name        string
		disclosures map[string]map[string]interface{}
		suppressed  []string
		payloads    string
		message     string
	}{
		{"overlay for a record not carried", map[string]map[string]interface{}{absent: {"agent_input": map[string]interface{}{}}}, nil, "", "does not carry"},
		{"ineligible overlay member", map[string]map[string]interface{}{root: {"tool_args": map[string]interface{}{}}}, nil, "", "not disclosure-eligible"},
		{"suppressed overlay member", map[string]map[string]interface{}{root: {"agent_input": map[string]interface{}{"step": 0}}}, []string{"agent_input"}, "", "declared suppressed"},
		{"ineligible suppressed field", nil, []string{"tool_args"}, "", "SuppressedFields names"},
		{"unknown payloads mode", nil, nil, "none", "PayloadsMode must be"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := BuildEvidenceBundle(t.Context(), source, BuildOptions{Root: root, NoRange: true, ClosureDepth: depth(0),
				Disclosures: c.disclosures, SuppressedFields: c.suppressed, PayloadsMode: c.payloads})
			requireRefusal(t, err, c.message)
		})
	}
}

func TestBuildMismatchedDisclosureIsRefusedByTheSelfCheck(t *testing.T) {
	source, caps, _ := testChain(t)
	root := cid(caps[0])
	_, err := BuildEvidenceBundle(t.Context(), source, BuildOptions{Root: root, NoRange: true, ClosureDepth: depth(0),
		Disclosures: map[string]map[string]interface{}{root: {"agent_input": map[string]interface{}{"step": 9}}}})
	requireRefusal(t, err, "does not verify")
}

func TestBuildNegativeClosureDepthIsRefused(t *testing.T) {
	source, caps, _ := testChain(t)
	_, err := BuildEvidenceBundle(t.Context(), source, BuildOptions{Root: cid(caps[0]), NoRange: true, ClosureDepth: depth(-1)})
	requireRefusal(t, err, "ClosureDepth")
}

// lying wraps a good ProofSource and overrides the members it sets.
type lying struct {
	ProofSource
	checkpoint func(context.Context) ([]byte, error)
	leaves     func(context.Context) ([][]byte, error)
	record     func(context.Context, string) (StoredRecord, bool, error)
	inclusion  func(context.Context, uint64) (InclusionProof, error)
	rangeProof func(context.Context, uint64) (RangeProof, error)
}

func (l lying) Checkpoint(ctx context.Context) ([]byte, error) {
	if l.checkpoint != nil {
		return l.checkpoint(ctx)
	}
	return l.ProofSource.Checkpoint(ctx)
}

func (l lying) Leaves(ctx context.Context) ([][]byte, error) {
	if l.leaves != nil {
		return l.leaves(ctx)
	}
	return l.ProofSource.Leaves(ctx)
}

func (l lying) Record(ctx context.Context, id string) (StoredRecord, bool, error) {
	if l.record != nil {
		return l.record(ctx, id)
	}
	return l.ProofSource.Record(ctx, id)
}

func (l lying) InclusionProof(ctx context.Context, seq uint64) (InclusionProof, error) {
	if l.inclusion != nil {
		return l.inclusion(ctx, seq)
	}
	return l.ProofSource.InclusionProof(ctx, seq)
}

func (l lying) RangeProof(ctx context.Context, first uint64) (RangeProof, error) {
	if l.rangeProof != nil {
		return l.rangeProof(ctx, first)
	}
	return l.ProofSource.RangeProof(ctx, first)
}

func TestBuildASourceThatLiesIsRefused(t *testing.T) {
	source, caps, records := testChain(t)
	root := cid(caps[2])
	other := producerCapsule(t, "other", capsuleOptions{})
	otherBytes, err := canonical.JCS(other)
	require.NoError(t, err)
	goodLeaves := func(ctx context.Context) [][]byte {
		leaves, err := source.Leaves(ctx)
		require.NoError(t, err)
		return leaves
	}
	cases := []struct {
		name     string
		liar     lying
		interval uint64
		message  string
	}{
		{"empty checkpoint", lying{checkpoint: func(context.Context) ([]byte, error) { return []byte{}, nil }}, 0, "checkpoint does not verify"},
		{"tampered checkpoint", lying{checkpoint: func(ctx context.Context) ([]byte, error) {
			cose, err := source.Checkpoint(ctx)
			require.NoError(t, err)
			cose = append([]byte(nil), cose...)
			cose[len(cose)-1] ^= 1
			return cose, nil
		}}, 0, "checkpoint does not verify"},
		{"a leaf short", lying{leaves: func(ctx context.Context) ([][]byte, error) { return goodLeaves(ctx)[:2], nil }}, 0, "the source gave 2 leaves"},
		{"a short leaf", lying{leaves: func(ctx context.Context) ([][]byte, error) {
			return append([][]byte{[]byte("short")}, goodLeaves(ctx)[1:]...), nil
		}}, 0, "32-byte"},
		{"a different capsule", lying{record: func(context.Context, string) (StoredRecord, bool, error) {
			return StoredRecord{Capsule: otherBytes}, true, nil
		}}, 0, "different capsule"},
		{"an envelope over another ID", lying{record: func(_ context.Context, id string) (StoredRecord, bool, error) {
			return StoredRecord{Capsule: records.held[id].Capsule, ProducerEnvelope: signedEnvelope(t, absent)}, true, nil
		}}, 0, "envelope does not verify"},
		{"not JSON", lying{record: func(context.Context, string) (StoredRecord, bool, error) {
			return StoredRecord{Capsule: []byte("not json")}, true, nil
		}}, 0, "not a JSON object"},
		{"a wrong inclusion proof", lying{inclusion: func(ctx context.Context, seq uint64) (InclusionProof, error) {
			proof, err := source.InclusionProof(ctx, seq)
			require.NoError(t, err)
			proof.LeafIndex = (proof.LeafIndex + 1) % 3
			return proof, nil
		}}, 0, "does not verify"},
		{"a wrong range proof", lying{rangeProof: func(ctx context.Context, first uint64) (RangeProof, error) {
			proof, err := source.RangeProof(ctx, first)
			require.NoError(t, err)
			proof.Witness = append([]string(nil), proof.Witness...)
			proof.Witness[0] = flip(proof.Witness[0])
			return proof, nil
		}}, 2, "range_proof_invalid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.liar.ProofSource = source
			opts := BuildOptions{Root: root, NoRange: c.interval == 0, IntervalFrom: c.interval}
			if c.interval > 1 {
				opts.ClosureDepth = depth(1) // seq 1 stays out of [2, tip]
			}
			_, err := BuildEvidenceBundle(t.Context(), c.liar, opts)
			requireRefusal(t, err, c.message)
		})
	}
}

type brokenRecords struct{ err error }

func (b brokenRecords) GetRecord(context.Context, string) ([]byte, []byte, error) {
	return nil, nil, b.err
}

func TestBuildStoreAndSourceErrorsPropagate(t *testing.T) {
	_, caps, _ := testChain(t)
	disk := errors.New("disk")
	source := makeLog(t, ids(caps...), brokenRecords{err: disk}, -1)
	_, err := BuildEvidenceBundle(t.Context(), source, BuildOptions{Root: cid(caps[0]), NoRange: true})
	require.ErrorIs(t, err, disk)
	var refusal *BuildError
	assert.False(t, errors.As(err, &refusal))

	good, _, _ := testChain(t)
	_, err = BuildEvidenceBundle(t.Context(), lying{ProofSource: good, checkpoint: func(context.Context) ([]byte, error) { return nil, disk }}, BuildOptions{Root: cid(caps[0]), NoRange: true})
	require.ErrorIs(t, err, disk)
}

func TestBuildALogWithoutACheckpointIsRefused(t *testing.T) {
	store := memory.New()
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	_, err := BuildEvidenceBundle(t.Context(), ProofSourceFromCLL(store, newRecords()), BuildOptions{Root: absent, NoRange: true})
	requireRefusal(t, err, "no checkpoint")
}

// -- the unproven form -----------------------------------------------------------

func TestUnprovenBundleCarriesNoLogProof(t *testing.T) {
	_, caps, _ := testChain(t)
	bundle, err := BuildUnprovenBundle(caps, cid(caps[2]), UnprovenOptions{})
	require.NoError(t, err)
	assert.NotContains(t, bundle, "checkpoint")
	assert.NotContains(t, bundle, "completeness_certificate")
	assert.Equal(t, "complete", bundle["completeness"].(map[string]interface{})["records_mode"])
	assert.Equal(t, VerdictIncomplete, strictVerdictOf(bundle))

	partial, err := BuildUnprovenBundle(caps[1:], cid(caps[2]), UnprovenOptions{})
	require.NoError(t, err)
	assert.Equal(t, []interface{}{cid(caps[0])}, partial["completeness"].(map[string]interface{})["missing"])
}

func TestUnprovenBundleRefusals(t *testing.T) {
	_, caps, _ := testChain(t)
	_, err := BuildUnprovenBundle(caps, absent, UnprovenOptions{})
	requireRefusal(t, err, "not among the records")
	_, err = BuildUnprovenBundle(append(append([]map[string]interface{}(nil), caps...), caps[0]), cid(caps[0]), UnprovenOptions{})
	requireRefusal(t, err, "duplicate")
	_, err = BuildUnprovenBundle([]map[string]interface{}{{}}, "x", UnprovenOptions{})
	requireRefusal(t, err, "capsule_id")
	_, err = BuildUnprovenBundle(caps, cid(caps[0]), UnprovenOptions{Disclosures: map[string]map[string]interface{}{absent: {}}})
	requireRefusal(t, err, "does not carry")
}
