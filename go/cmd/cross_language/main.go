// SPDX-License-Identifier: BSD-3-Clause
// Command cross_language is the stdin/stdout adapter for the CI interlock.
//
// seal and verify read a Capsule. bundle-produce <kind> reads a producer
// fixture (vectors/cross-language/bundle-producer-log.json or
// bundle-producer-padded-log.json) and writes the JCS bytes of the Bundle kind
// names in its builds. bundle-verify reads a
// Bundle's JSON text and prints its strict verdict.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/bundle"
	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/verify"
	"github.com/action-state-group/checkpointed-local-log/go/cll"
)

const usage = "usage: cross_language seal|verify|bundle-produce <kind>|bundle-verify"

func main() {
	args := os.Args[1:]
	switch {
	case len(args) == 2 && args[0] == "bundle-produce":
		os.Exit(bundleProduce(args[1]))
	case len(args) == 1 && args[0] == "bundle-verify":
		os.Exit(bundleVerify())
	case len(args) != 1 || (args[0] != "seal" && args[0] != "verify"):
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	decoder := json.NewDecoder(os.Stdin)
	decoder.UseNumber()
	var capsule map[string]interface{}
	if err := decoder.Decode(&capsule); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if args[0] == "seal" {
		id, err := canonical.ComputeCapsuleID(capsule)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		capsule["capsule_id"] = id
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(capsule); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	result := verify.Verify(capsule, nil, nil)
	if !result.OK {
		for _, finding := range result.Findings {
			fmt.Fprintln(os.Stderr, finding.Code)
		}
		os.Exit(1)
	}
	if result.CapsuleID != nil {
		fmt.Println(*result.CapsuleID)
	}
}

// hexBytes is a JSON string of lowercase hex, decoded to its bytes.
type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	raw, err := hex.DecodeString(text)
	*h = raw
	return err
}

// fixture is the producer fixture: one checkpointed log, its records, and
// the Bundles to build from them.
type fixture struct {
	Root   string `json:"root"`
	Builds map[string]struct {
		IntervalFrom         *uint64 `json:"interval_from"`
		ClosureDepth         int     `json:"closure_depth"`
		CarryNonRecordLeaves bool    `json:"carry_non_record_leaves"`
	} `json:"builds"`
	// LeafContents is each padding leaf's content by seq, as a store holds it.
	LeafContents map[string]map[string]interface{} `json:"leaf_contents"`
	Log          struct {
		Entries []hexBytes `json:"entries"`
		State   struct {
			Size       uint64     `json:"size"`
			Nodes      []hexBytes `json:"nodes"`
			IndexedSeq uint64     `json:"indexed_seq"`
			Checkpoint struct {
				COSE       hexBytes   `json:"cose"`
				Size       uint64     `json:"size"`
				IndexedSeq uint64     `json:"indexed_seq"`
				Peaks      []hexBytes `json:"peaks"`
			} `json:"checkpoint"`
		} `json:"state"`
	} `json:"log"`
	Records map[string]struct {
		Capsule          hexBytes `json:"capsule"`
		ProducerEnvelope hexBytes `json:"producer_envelope"`
	} `json:"records"`
}

// fixtureBackend is a CLL backend (ScanEntries and LoadCLL) over the
// fixture's log.
type fixtureBackend struct {
	entries []cll.Entry
	state   cll.State
}

func (b *fixtureBackend) ScanEntries(_ context.Context, afterSeq uint64, limit int) ([]cll.Entry, error) {
	if afterSeq >= uint64(len(b.entries)) {
		return nil, nil
	}
	end := afterSeq + uint64(limit)
	if end > uint64(len(b.entries)) {
		end = uint64(len(b.entries))
	}
	return b.entries[afterSeq:end], nil
}

func (b *fixtureBackend) LoadCLL(context.Context) (cll.State, error) { return b.state, nil }

// fixtureRecords is a RecordSource over the fixture's records.
type fixtureRecords map[string]bundle.StoredRecord

func (r fixtureRecords) GetRecord(_ context.Context, id string) ([]byte, []byte, error) {
	stored, found := r[id]
	if !found {
		return nil, nil, fmt.Errorf("%w: %s", bundle.ErrRecordNotFound, id)
	}
	return stored.Capsule, stored.ProducerEnvelope, nil
}

// withLeafContent is a ProofSource with the optional LeafContent capability,
// over the fixture's leaf_contents.
type withLeafContent struct {
	bundle.ProofSource
	contents map[string]map[string]interface{}
}

func (w withLeafContent) LeafContent(_ context.Context, seq uint64) (map[string]interface{}, error) {
	return w.contents[strconv.FormatUint(seq, 10)], nil
}

func byteLists(values []hexBytes) [][]byte {
	out := make([][]byte, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}

func bundleProduce(kind string) int {
	var fx fixture
	if err := json.NewDecoder(os.Stdin).Decode(&fx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	build, found := fx.Builds[kind]
	if !found {
		fmt.Fprintf(os.Stderr, "unknown bundle kind %q\n", kind)
		return 2
	}
	appendedAt := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	backend := &fixtureBackend{}
	for i, value := range fx.Log.Entries {
		backend.entries = append(backend.entries, cll.Entry{Seq: uint64(i + 1), Value: value, AppendedAt: appendedAt})
	}
	state, checkpoint := fx.Log.State, fx.Log.State.Checkpoint
	backend.state = cll.State{
		Size:       state.Size,
		Nodes:      byteLists(state.Nodes),
		IndexedSeq: state.IndexedSeq,
		Checkpoint: &cll.CheckpointState{
			Bytes: checkpoint.COSE, Size: checkpoint.Size, IndexedSeq: checkpoint.IndexedSeq, Peaks: byteLists(checkpoint.Peaks),
		},
	}
	records := fixtureRecords{}
	for id, record := range fx.Records {
		records[id] = bundle.StoredRecord{Capsule: record.Capsule, ProducerEnvelope: record.ProducerEnvelope}
	}
	opts := bundle.BuildOptions{
		Root: fx.Root, ClosureDepth: &build.ClosureDepth, NoRange: build.IntervalFrom == nil,
		CarryNonRecordLeaves: build.CarryNonRecordLeaves,
	}
	if build.IntervalFrom != nil {
		opts.IntervalFrom = *build.IntervalFrom
	}
	source := bundle.ProofSourceFromCLL(backend, records)
	if fx.LeafContents != nil {
		source = withLeafContent{source, fx.LeafContents}
	}
	built, err := bundle.BuildEvidenceBundle(context.Background(), source, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	data, err := canonical.JCS(built)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if _, err := os.Stdout.Write(data); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func bundleVerify() int {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	// The Bundle's own strict reader: its URL-fragment decoder over these bytes.
	value, err := bundle.DecodeFragment(base64.RawURLEncoding.EncodeToString(bytes.TrimSpace(raw)))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(bundle.VerifyStrict(value, bundle.StrictOptions{}).Verdict)
	return 0
}
