// SPDX-License-Identifier: BSD-3-Clause
// Command cross_language is the stdin/stdout adapter for the CI interlock.
//
// seal and verify read a Capsule. signature reads one record (a Capsule with
// its local-only signature and key_id) and prints its producer-signature
// verdict. binding reads a Controller Binding v0 record with what was
// received beside it and prints its report. bundle-produce <kind> reads a
// producer fixture (vectors/cross-language/bundle-producer-log.json or
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
	"sort"
	"strconv"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/bundle"
	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/envelope"
	"github.com/action-state-group/agent-action-capsule/go/verify"
	"github.com/action-state-group/checkpointed-local-log/go/cll"
)

const usage = "usage: cross_language seal|verify|signature|binding|bundle-produce <kind>|bundle-verify|composed-verify"

func main() {
	args := os.Args[1:]
	switch {
	case len(args) == 2 && args[0] == "bundle-produce":
		os.Exit(bundleProduce(args[1]))
	case len(args) == 1 && args[0] == "bundle-verify":
		os.Exit(bundleVerify())
	case len(args) == 1 && args[0] == "composed-verify":
		os.Exit(composedVerify(os.Stdin, os.Stdout, os.Stderr))
	case len(args) == 1 && args[0] == "signature":
		os.Exit(signature(os.Stdin, os.Stdout, os.Stderr))
	case len(args) == 1 && args[0] == "binding":
		os.Exit(binding(os.Stdin, os.Stdout, os.Stderr))
	case len(args) == 1 && (args[0] == "seal" || args[0] == "verify"):
		os.Exit(capsuleMode(args[0], os.Stdin, os.Stdout, os.Stderr))
	}
	fmt.Fprintln(os.Stderr, usage)
	os.Exit(2)
}

// capsuleMode runs seal or verify on the Capsule read from in.
func capsuleMode(mode string, in io.Reader, out, errOut io.Writer) int {
	raw, err := io.ReadAll(in)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	// The verifier's strict decoder: one value, numbers as written, and no
	// invalid UTF-8 or lone surrogate that encoding/json would repair.
	value, err := verify.DecodeCapsuleJSON(raw)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	capsule, ok := value.(map[string]interface{})
	if !ok {
		fmt.Fprintln(errOut, "stdin is not a JSON object")
		return 2
	}
	if mode == "seal" {
		id, err := canonical.ComputeCapsuleID(capsule)
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		capsule["capsule_id"] = id
		encoder := json.NewEncoder(out)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(capsule); err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		return 0
	}
	result := verify.Verify(capsule, nil, nil)
	if !result.OK {
		for _, finding := range result.Findings {
			fmt.Fprintln(errOut, finding.Code)
		}
		return 1
	}
	if result.CapsuleID != nil {
		fmt.Fprintln(out, *result.CapsuleID)
	}
	return 0
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

// signatureExit is each producer-signature verdict's exit code. A caller
// tells unclaimed (unsigned, not checked) from invalid (a forgery or a
// malformed claim) by the code alone; 2 stays the usage and input code.
var signatureExit = map[string]int{envelope.Authored: 0, envelope.Invalid: 1, envelope.Unclaimed: 3}

// signature prints the producer-signature verdict of the one JSON value on
// in; anything after that value is refused, so a stream of records is never
// read as its first. authored means the Producer Envelope verifies under the record's own
// key_id over its recomputed Capsule ID; that key is self-attested, so the
// caller still decides whether it is the key it expects.
func signature(in io.Reader, out, errOut io.Writer) int {
	raw, err := io.ReadAll(in)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	// The verifier's strict decoder: one value, numbers as written, and no
	// invalid UTF-8 or lone surrogate that encoding/json would repair.
	record, err := verify.DecodeCapsuleJSON(raw)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	verdict, messages := envelope.VerifyRecordSignature(record)
	for _, message := range messages {
		fmt.Fprintln(errOut, message)
	}
	code, known := signatureExit[verdict]
	if !known {
		fmt.Fprintf(errOut, "unknown verdict %q\n", verdict)
		return 1
	}
	fmt.Fprintln(out, verdict)
	return code
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

// composedVerify reads {container, controller_bindings, binding_revocations}
// and prints the container's composed/v1 block as one JCS line: its status
// and, per join, the declared and derived state, result and corroboration.
// The Python, TypeScript and Rust adapters print the same line.
func composedVerify(in io.Reader, out, errOut io.Writer) int {
	decoder := json.NewDecoder(in)
	decoder.UseNumber()
	var input struct {
		Container          interface{}              `json:"container"`
		ControllerBindings []map[string]interface{} `json:"controller_bindings"`
		BindingRevocations []map[string]interface{} `json:"binding_revocations"`
	}
	if err := decoder.Decode(&input); err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	result := bundle.VerifyBundleWithOptions(input.Container, bundle.Options{
		ControllerBindings: input.ControllerBindings,
		BindingRevocations: input.BindingRevocations,
	})
	for _, extension := range result.Extensions {
		composed := extension.Composed
		if composed == nil {
			continue
		}
		joins := make([]interface{}, len(composed.Joins))
		for i, join := range composed.Joins {
			var derived, reason interface{}
			if join.Derived != "" {
				derived = join.Derived
			}
			if composed.Corroboration[i].Reason != "" {
				reason = composed.Corroboration[i].Reason
			}
			joins[i] = map[string]interface{}{
				"members": []interface{}{join.Members[0], join.Members[1]}, "declared": join.Declared,
				"derived": derived, "result": join.Result,
				"corroboration": composed.Corroboration[i].Result, "reason": reason,
			}
		}
		findings := make([]interface{}, 0, len(composed.Findings))
		for _, finding := range composed.Findings {
			findings = append(findings, finding)
		}
		sort.Slice(findings, func(i, k int) bool { return findings[i].(string) < findings[k].(string) })
		line, err := canonical.JCS(map[string]interface{}{"status": composed.Status, "findings": findings, "joins": joins})
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
		fmt.Fprintf(out, "%s\n", line)
		return 0
	}
	fmt.Fprintln(errOut, "no composed/v1 block")
	return 1
}
