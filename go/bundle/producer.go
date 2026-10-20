// SPDX-License-Identifier: BSD-3-Clause
package bundle

// The producer. BuildEvidenceBundle assembles a Bundle from a ProofSource and
// checks the result with VerifyStrict before returning it. It holds no key and
// trusts nothing the source returns: the checkpoint is verified from its COSE
// form, and every proof and record is checked by the strict verifier.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/envelope"
	"github.com/action-state-group/agent-action-capsule/go/registries"
	"github.com/action-state-group/agent-action-capsule/go/witness"
	"github.com/action-state-group/checkpointed-local-log/go/cll"
	"github.com/action-state-group/checkpointed-local-log/go/mmr"
)

// BuildError is a refusal by BuildEvidenceBundle or BuildUnprovenBundle; its
// message says why. An error a ProofSource or RecordSource returns is passed
// through unchanged instead.
type BuildError struct{ Reason string }

func (e *BuildError) Error() string { return e.Reason }

func refuse(format string, args ...interface{}) error {
	return &BuildError{Reason: fmt.Sprintf(format, args...)}
}

// ErrRecordNotFound is what a RecordSource returns (or wraps) for a record it
// does not hold. Any other error is a failure of the store and is passed
// through.
var ErrRecordNotFound = errors.New("record not found")

// StoredRecord is a record as a store holds it: the Capsule's JSON bytes and
// its Producer Envelope bytes, empty when the record is unsigned.
type StoredRecord struct {
	Capsule          []byte
	ProducerEnvelope []byte
}

// InclusionProof is a Bundle membership's inclusion_proof in its wire shape:
// v 1, kind "inclusion", the MMR size, the 0-based leaf index and the
// lowercase-hex witness and peak hashes.
type InclusionProof struct {
	V          uint64   `json:"v"`
	Kind       string   `json:"kind"`
	Size       uint64   `json:"size"`
	LeafIndex  uint64   `json:"leaf_index"`
	Witness    []string `json:"witness"`
	PeaksLeft  []string `json:"peaks_left"`
	PeaksRight []string `json:"peaks_right"`
}

// RangeProof is a completeness certificate's range_proof in its wire shape:
// the 1-based seqs and 0-based indexes of the range, the MMR size and the
// lowercase-hex witness hashes.
type RangeProof struct {
	FromSeq   uint64   `json:"from_seq"`
	ToSeq     uint64   `json:"to_seq"`
	Size      uint64   `json:"size"`
	FromIndex uint64   `json:"from_index"`
	ToIndex   uint64   `json:"to_index"`
	Witness   []string `json:"witness"`
}

// ProofSource is the read-only proof material BuildEvidenceBundle reads. The
// proofs are in the Bundle's own wire shape, so an implementer never handles
// a log library's types.
type ProofSource interface {
	// Checkpoint returns the signed CLL COSE checkpoint the Bundle is built
	// against.
	Checkpoint(ctx context.Context) ([]byte, error)
	// Leaves returns the 32-byte value of every leaf, seq 1 to
	// leaf_count(mmr_size), in order; a record's value is its Capsule ID.
	Leaves(ctx context.Context) ([][]byte, error)
	// Record returns the stored record, or false when the log does not hold
	// that leaf as a record. Any other failure is an error.
	Record(ctx context.Context, capsuleID string) (StoredRecord, bool, error)
	// InclusionProof returns the inclusion proof for the leaf at seq at the
	// checkpoint's size.
	InclusionProof(ctx context.Context, seq uint64) (InclusionProof, error)
	// RangeProof returns the range proof over [firstSeq, tip] at the
	// checkpoint's size.
	RangeProof(ctx context.Context, firstSeq uint64) (RangeProof, error)
}

// LeafContentSource is an optional ProofSource capability: the content of a
// leaf that is not a record (a padding record's four members), or nil when
// the source does not hold it. BuildEvidenceBundle reads it only with
// BuildOptions.CarryNonRecordLeaves; a source without it builds exactly as
// before.
type LeafContentSource interface {
	LeafContent(ctx context.Context, seq uint64) (map[string]interface{}, error)
}

// RecordSource looks records up by Capsule ID: the Capsule's JSON bytes and
// its Producer Envelope bytes (empty when unsigned). A record it does not hold
// is ErrRecordNotFound (errors.Is).
type RecordSource interface {
	GetRecord(ctx context.Context, id string) (capsule, envelope []byte, err error)
}

// ProofSourceFromCLL is a ProofSource over a CLL backend (its entries and
// checkpoint state) and a record store. It reads the backend's state once, on
// first use, and serves one consistent snapshot from then on: the checkpoint,
// leaves and proofs all come from that read, at the latest checkpoint's size,
// however the log grows afterwards. Use a new source for a later checkpoint.
// A log with no checkpoint is refused.
func ProofSourceFromCLL(backend interface {
	cll.EntrySource
	LoadCLL(context.Context) (cll.State, error)
}, records RecordSource) ProofSource {
	return &cllProofSource{backend: backend, records: records}
}

type cllProofSource struct {
	backend interface {
		cll.EntrySource
		LoadCLL(context.Context) (cll.State, error)
	}
	records RecordSource

	mu         sync.Mutex
	loaded     bool
	checkpoint *cll.CheckpointState
	tree       *mmr.Tree
}

func (s *cllProofSource) state(ctx context.Context) (*cll.CheckpointState, *mmr.Tree, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		state, err := s.backend.LoadCLL(ctx)
		if err != nil {
			return nil, nil, err
		}
		if state.Checkpoint != nil {
			tree, err := mmr.New(state.Nodes)
			if err != nil {
				return nil, nil, fmt.Errorf("restore the log's MMR: %w", err)
			}
			s.tree = tree
		}
		s.checkpoint, s.loaded = state.Checkpoint, true
	}
	if s.checkpoint == nil {
		return nil, nil, refuse("the log has no checkpoint: nothing can be proven until one is cut")
	}
	return s.checkpoint, s.tree, nil
}

func (s *cllProofSource) Checkpoint(ctx context.Context) ([]byte, error) {
	checkpoint, _, err := s.state(ctx)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), checkpoint.Bytes...), nil
}

func (s *cllProofSource) Leaves(ctx context.Context) ([][]byte, error) {
	checkpoint, _, err := s.state(ctx)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for uint64(len(out)) < checkpoint.IndexedSeq {
		limit := checkpoint.IndexedSeq - uint64(len(out))
		if limit > cll.MaxScanLimit {
			limit = cll.MaxScanLimit
		}
		page, err := s.backend.ScanEntries(ctx, uint64(len(out)), int(limit))
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			break
		}
		for _, entry := range page {
			out = append(out, append([]byte(nil), entry.Value...))
		}
	}
	return out, nil
}

func (s *cllProofSource) Record(ctx context.Context, capsuleID string) (StoredRecord, bool, error) {
	capsule, producerEnvelope, err := s.records.GetRecord(ctx, capsuleID)
	if errors.Is(err, ErrRecordNotFound) {
		return StoredRecord{}, false, nil
	}
	if err != nil {
		return StoredRecord{}, false, err
	}
	return StoredRecord{Capsule: capsule, ProducerEnvelope: producerEnvelope}, true, nil
}

func (s *cllProofSource) InclusionProof(ctx context.Context, seq uint64) (InclusionProof, error) {
	checkpoint, tree, err := s.state(ctx)
	if err != nil {
		return InclusionProof{}, err
	}
	if seq < 1 {
		return InclusionProof{}, fmt.Errorf("seq %d is not a log position", seq)
	}
	proof, err := tree.InclusionProof(seq-1, checkpoint.Size)
	if err != nil {
		return InclusionProof{}, err
	}
	return InclusionProof{
		V: proof.V, Kind: proof.Kind, Size: proof.Size, LeafIndex: proof.LeafIndex,
		Witness: hexList(proof.Witness), PeaksLeft: hexList(proof.PeaksLeft), PeaksRight: hexList(proof.PeaksRight),
	}, nil
}

func (s *cllProofSource) RangeProof(ctx context.Context, firstSeq uint64) (RangeProof, error) {
	checkpoint, tree, err := s.state(ctx)
	if err != nil {
		return RangeProof{}, err
	}
	tip, ok := mmr.LeafCount(checkpoint.Size)
	if !ok || firstSeq < 1 || firstSeq > tip {
		return RangeProof{}, fmt.Errorf("no range from seq %d at MMR size %d", firstSeq, checkpoint.Size)
	}
	proof, err := tree.RangeProof(firstSeq-1, tip-1, checkpoint.Size)
	if err != nil {
		return RangeProof{}, err
	}
	return RangeProof{
		FromSeq: firstSeq, ToSeq: tip, Size: proof.Size,
		FromIndex: proof.FromIndex, ToIndex: proof.ToIndex, Witness: hexList(proof.Witness),
	}, nil
}

func hexList(values [][]byte) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = hex.EncodeToString(value)
	}
	return out
}

// BuildOptions configures BuildEvidenceBundle.
//
// The interval is required, in one of two forms, and the zero value is
// refused so that a caller never proves or omits the rest of the log by
// accident: IntervalFrom N (at least 1) proves the range [N, tip] and carries
// every record in it and none below it; NoRange carries only the chosen
// records, each with its own inclusion proof
// (completeness.selection "producer-selected", which VerifyStrict reads as
// INCOMPLETE). Setting both is refused.
type BuildOptions struct {
	// Root is the Capsule ID the Bundle is built around.
	Root string
	// IntervalFrom is the first seq of a range proof that ends at the
	// checkpoint tip; 1 is the whole log.
	IntervalFrom uint64
	// NoRange builds without a range proof.
	NoRange bool
	// ClosureDepth is the citation depth from Root; nil is the draft's 2.
	ClosureDepth *int
	// Include names further records to carry.
	Include []string
	// Disclosures is the Bundle-level overlay: Capsule ID to member to value.
	Disclosures map[string]map[string]interface{}
	// SuppressedFields are disclosure-eligible members declared suppressed.
	SuppressedFields []string
	// PayloadsMode is "all" or "selected"; empty derives it: "all" when no
	// committed, eligible, unsuppressed member of a carried record is left
	// unrevealed, else "selected".
	// A declared "all" must reveal every committed, unsuppressed member of
	// each record the overlay discloses.
	PayloadsMode string
	// ProducerKey, a raw 32-byte Ed25519 public key, adds producer-key/v1.
	ProducerKey ed25519.PublicKey
	// Extensions adds extension blocks of any kind except producer-key/v1
	// (set through ProducerKey) and composed/v1.
	Extensions map[string]interface{}
	// Verification is the producer's self-report, carried as given.
	Verification map[string]interface{}
	// CarryNonRecordLeaves lets a range cover a padding leaf: the source's
	// LeafContent is carried in completeness_certificate.non_record_leaves
	// (Bundle -02). It is off by default because a verifier that predates -02
	// reads such a Bundle as missing those seqs; turn it on only for readers
	// that check the member.
	CarryNonRecordLeaves bool
}

// UnprovenOptions configures BuildUnprovenBundle.
type UnprovenOptions struct {
	// ClosureDepth is the citation depth from the root; nil is the draft's 2.
	ClosureDepth *int
	// Disclosures is the Bundle-level overlay.
	Disclosures map[string]map[string]interface{}
	// SuppressedFields are disclosure-eligible members declared suppressed.
	SuppressedFields []string
}

// ownedExtensions are the extension kinds this package owns.
var ownedExtensions = []string{"producer-key/v1", ComposedKind}

// BuildEvidenceBundle builds an Evidence Bundle around opts.Root from source
// (see BuildOptions for the interval forms). It returns the Bundle as a JSON
// value whose integers are json.Number, ready for VerifyStrict, BundleDigest
// or encoding/json.
//
// It refuses, with a *BuildError: a checkpoint that does not verify, a leaf
// count that disagrees with it, a stored capsule that is not the requested
// one, a claimed envelope that does not verify, a range over a leaf that is
// not a record, a carried record below IntervalFrom, a record past the
// checkpoint, an overlay for a record not carried, an ineligible or
// suppressed overlay member, a proof the verifier cannot parse, caller input
// nested too deeply, a Bundle with no canonical digest (a float or an integer
// beyond 2^53-1 in Extensions or Verification), and any result VerifyStrict
// calls INVALID. A
// missing citation or an unsigned record is stated, not refused, and reads
// INCOMPLETE. An error from source is returned unchanged.
func BuildEvidenceBundle(ctx context.Context, source ProofSource, opts BuildOptions) (map[string]interface{}, error) {
	checked, err := checkOptions(opts.ClosureDepth, opts.Disclosures, opts.SuppressedFields, opts.PayloadsMode, opts.Extensions)
	if err != nil {
		return nil, err
	}
	switch {
	case opts.NoRange && opts.IntervalFrom != 0:
		return nil, refuse("IntervalFrom and NoRange are both set: choose one")
	case !opts.NoRange && opts.IntervalFrom == 0:
		return nil, refuse("IntervalFrom is required: a seq of at least 1, or NoRange for no range proof")
	}
	if opts.ProducerKey != nil && len(opts.ProducerKey) != ed25519.PublicKeySize {
		return nil, refuse("ProducerKey must be a raw 32-byte Ed25519 public key")
	}
	extensions, err := jsonObject(opts.Extensions, "Extensions")
	if err != nil {
		return nil, err
	}
	verification, err := jsonObject(opts.Verification, "Verification")
	if err != nil {
		return nil, err
	}

	cose, err := source.Checkpoint(ctx)
	if err != nil {
		return nil, err
	}
	signed, err := witness.ParseSignedCheckpoint(cose)
	if err != nil {
		return nil, refuse("the checkpoint does not verify: %v", err)
	}
	tip, ok := mmr.LeafCount(signed.MMRSize)
	if !ok {
		return nil, refuse("the checkpoint does not verify: mmr_size %d is not a complete MMR", signed.MMRSize)
	}
	leaves, err := source.Leaves(ctx)
	if err != nil {
		return nil, err
	}
	if uint64(len(leaves)) != tip {
		return nil, refuse("the source gave %d leaves; the checkpoint covers %d 32-byte leaves", len(leaves), tip)
	}
	seqOf := make(map[string]uint64, len(leaves))
	for i, value := range leaves {
		if len(value) != cll.EntryBytes {
			return nil, refuse("the source gave a %d-byte leaf at seq %d; the checkpoint covers %d 32-byte leaves", len(value), i+1, tip)
		}
		id := hex.EncodeToString(value)
		if _, seen := seqOf[id]; !seen {
			seqOf[id] = uint64(i + 1)
		}
	}

	lookup := func(capsuleID string) (map[string]interface{}, error) {
		stored, found, err := source.Record(ctx, capsuleID)
		if err != nil || !found {
			return nil, err
		}
		if _, covered := seqOf[capsuleID]; !covered {
			return nil, refuse("record %s is not a leaf at or below the checkpoint (not yet covered, or not in this log)", capsuleID)
		}
		return decodeRecord(capsuleID, stored)
	}

	carried, missing, err := closure(opts.Root, checked.depth, lookup)
	if err != nil {
		return nil, err
	}
	for _, capsuleID := range opts.Include {
		if carried[capsuleID] != nil {
			continue
		}
		record, err := lookup(capsuleID)
		if err != nil {
			return nil, err
		}
		if record == nil {
			return nil, refuse("Include: no such record: %s", capsuleID)
		}
		carried[capsuleID] = record
	}

	certificate := map[string]interface{}{"log_id": signed.LogID, "range_root": signed.Root}
	if !opts.NoRange {
		first := opts.IntervalFrom
		if first > tip {
			return nil, refuse("IntervalFrom %d is past the checkpoint tip %d", first, tip)
		}
		var below []string
		for _, capsuleID := range sortedBySeq(carried, seqOf) {
			if seq := seqOf[capsuleID]; seq < first {
				below = append(below, fmt.Sprintf("%s (seq %d)", capsuleID, seq))
			}
		}
		if len(below) != 0 {
			return nil, refuse("record(s) below IntervalFrom %d: %s; lower it or build without a range", first, strings.Join(below, ", "))
		}
		bodyDigests := make([]interface{}, 0, tip-first+1)
		var nonRecord []interface{}
		for seq := first; seq <= tip; seq++ {
			capsuleID := hex.EncodeToString(leaves[seq-1])
			bodyDigests = append(bodyDigests, capsuleID)
			if carried[capsuleID] != nil {
				continue
			}
			record, err := lookup(capsuleID)
			if err != nil {
				return nil, err
			}
			if record == nil {
				var content map[string]interface{}
				if opts.CarryNonRecordLeaves {
					if content, err = paddingContent(ctx, source, seq, capsuleID); err != nil {
						return nil, err
					}
				}
				if content == nil {
					return nil, refuse("seq %d in the interval is not a record the source holds; a range cannot cover it: start the interval after it or build without a range", seq)
				}
				nonRecord = append(nonRecord, map[string]interface{}{"seq": jsonInteger(seq), "content": content})
				continue
			}
			carried[capsuleID] = record
		}
		proof, err := source.RangeProof(ctx, first)
		if err != nil {
			return nil, err
		}
		wire, err := rangeProofWire(proof)
		if err != nil {
			return nil, refuse("the source's range proof from seq %d is malformed: %v", first, err)
		}
		certificate["first_seq"] = jsonInteger(first)
		certificate["last_seq"] = jsonInteger(tip)
		certificate["body_digests"] = bodyDigests
		certificate["range_proof"] = wire
		if len(nonRecord) != 0 {
			certificate["non_record_leaves"] = nonRecord
		}
	}

	ordered := sortedBySeq(carried, seqOf)
	if err := checkOverlayTargets(checked.disclosures, carried); err != nil {
		return nil, err
	}
	records := make([]interface{}, len(ordered))
	recordMaps := make([]map[string]interface{}, len(ordered))
	memberships := make(map[string]interface{}, len(ordered))
	for i, capsuleID := range ordered {
		seq := seqOf[capsuleID]
		proof, err := source.InclusionProof(ctx, seq)
		if err != nil {
			return nil, err
		}
		wire, err := inclusionProofWire(proof)
		if err != nil {
			return nil, refuse("the source's inclusion proof for seq %d is malformed: %v", seq, err)
		}
		records[i], recordMaps[i] = carried[capsuleID], carried[capsuleID]
		memberships[capsuleID] = map[string]interface{}{
			"log_coordinates": map[string]interface{}{"log_id": signed.LogID, "seq": jsonInteger(seq), "leaf_index": jsonInteger(seq - 1)},
			"inclusion_proof": wire,
		}
	}
	certificate["memberships"] = memberships
	complete, err := completenessBlock(recordMaps, checked, missing, opts.PayloadsMode)
	if err != nil {
		return nil, err
	}
	if opts.NoRange {
		complete["selection"] = SelectionProducerSelected
	}
	bundle := map[string]interface{}{
		"bundle_version":           "2",
		"bundle_kind":              bundleKind,
		"root":                     opts.Root,
		"records":                  records,
		"completeness":             complete,
		"completeness_certificate": certificate,
		"checkpoint": map[string]interface{}{
			"log_id":    signed.LogID,
			"mmr_size":  jsonInteger(signed.MMRSize),
			"root":      signed.Root,
			"prev_size": jsonInteger(signed.PrevSize),
			"prev_root": signed.PrevRoot,
			"key_id":    signed.KeyID,
			"timestamp": signed.Timestamp,
			"cose":      base64.RawURLEncoding.EncodeToString(cose),
		},
	}
	if len(checked.disclosures) != 0 {
		bundle["disclosures"] = checked.disclosures
	}
	if opts.ProducerKey != nil {
		if extensions == nil {
			extensions = map[string]interface{}{}
		}
		extensions["producer-key/v1"] = map[string]interface{}{"public_key": hex.EncodeToString(opts.ProducerKey)}
	}
	if len(extensions) != 0 {
		bundle["extensions"] = extensions
	}
	if verification != nil {
		bundle["verification"] = verification
	}
	return selfChecked(bundle)
}

// paddingContent is the source's content for the non-record leaf at seq, when
// it is a padding record whose recomputed capsule_id is that leaf; nil when the
// source has no LeafContent or holds nothing for seq. Any other content is
// refused by name: the producer carries padding only.
func paddingContent(ctx context.Context, source ProofSource, seq uint64, leafHex string) (map[string]interface{}, error) {
	reader, ok := source.(LeafContentSource)
	if !ok {
		return nil, nil
	}
	stored, err := reader.LeafContent(ctx, seq)
	if err != nil || stored == nil {
		return nil, err
	}
	if stored["record_type"] != paddingType {
		return nil, refuse("seq %d: the source's leaf content is not a padding record; a range cannot cover it", seq)
	}
	// Local-only producer envelope members are outside the leaf's preimage.
	content := make(map[string]interface{}, len(stored))
	for name, value := range stored {
		if name != "signature" && name != "key_id" {
			content[name] = value
		}
	}
	content, err = jsonObject(content, fmt.Sprintf("the padding record at seq %d", seq))
	if err != nil {
		return nil, err
	}
	leaf, err := paddingLeaf(content)
	if err != nil {
		return nil, refuse("seq %d: the padding record has no canonical digest", seq)
	}
	if leaf != leafHex || content["capsule_id"] != leafHex {
		return nil, refuse("seq %d: the padding record does not hash to the leaf", seq)
	}
	return content, nil
}

// BuildUnprovenBundle builds an Evidence Bundle with no log proof, no
// checkpoint and no certificate, for Capsules that belong to no log. Every
// given record is carried, in order; the closure from root decides missing.
// VerifyStrict reads it as INCOMPLETE. Refusals are *BuildError.
func BuildUnprovenBundle(records []map[string]interface{}, root string, opts UnprovenOptions) (map[string]interface{}, error) {
	checked, err := checkOptions(opts.ClosureDepth, opts.Disclosures, opts.SuppressedFields, "", nil)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]map[string]interface{}, len(records))
	carried := make([]interface{}, len(records))
	recordMaps := make([]map[string]interface{}, len(records))
	for i, given := range records {
		value, err := jsonObject(given, "records")
		if err != nil {
			return nil, err
		}
		id, isString := value["capsule_id"].(string)
		if !isString {
			return nil, refuse("every record needs a capsule_id")
		}
		if byID[id] != nil {
			return nil, refuse("duplicate capsule_id among the records: %s", id)
		}
		byID[id], carried[i], recordMaps[i] = value, value, value
	}
	if byID[root] == nil {
		return nil, refuse("root %s is not among the records", root)
	}
	held := make(map[string]map[string]interface{}, len(byID))
	for id, record := range byID {
		held[id] = record
	}
	if err := checkOverlayTargets(checked.disclosures, held); err != nil {
		return nil, err
	}
	_, missing, err := closure(root, checked.depth, func(id string) (map[string]interface{}, error) { return byID[id], nil })
	if err != nil {
		return nil, err
	}
	complete, err := completenessBlock(recordMaps, checked, missing, "")
	if err != nil {
		return nil, err
	}
	bundle := map[string]interface{}{
		"bundle_version": "2",
		"bundle_kind":    bundleKind,
		"root":           root,
		"records":        carried,
		"completeness":   complete,
	}
	if len(checked.disclosures) != 0 {
		bundle["disclosures"] = checked.disclosures
	}
	return selfChecked(bundle)
}

// checkedOptions are the options both builders share, validated and in JSON
// form.
type checkedOptions struct {
	depth       int
	disclosures map[string]interface{}
	suppressed  []string
}

func checkOptions(depth *int, disclosures map[string]map[string]interface{}, suppressed []string, payloadsMode string, extensions map[string]interface{}) (checkedOptions, error) {
	out := checkedOptions{depth: 2}
	if depth != nil {
		if *depth < 0 || int64(*depth) > canonical.MaxSafeInteger {
			return out, refuse("ClosureDepth must be a non-negative safe integer (at most 2^53-1)")
		}
		out.depth = *depth
	}
	if payloadsMode != "" && payloadsMode != "all" && payloadsMode != "selected" {
		return out, refuse("PayloadsMode must be all or selected, or empty to derive it")
	}
	suppressedSet := map[string]bool{}
	var ineligible []string
	for _, member := range suppressed {
		if _, eligible := registries.DisclosureEligibleFields[member]; !eligible {
			ineligible = append(ineligible, member)
		}
		suppressedSet[member] = true
	}
	if len(ineligible) != 0 {
		sort.Strings(ineligible)
		return out, refuse("SuppressedFields names members that are not disclosure-eligible: %v", ineligible)
	}
	out.suppressed = make([]string, 0, len(suppressedSet))
	for member := range suppressedSet {
		out.suppressed = append(out.suppressed, member)
	}
	sort.Strings(out.suppressed)
	ids := make([]string, 0, len(disclosures))
	for id := range disclosures {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		var bad, both []string
		for member := range disclosures[id] {
			if _, eligible := registries.DisclosureEligibleFields[member]; !eligible {
				bad = append(bad, member)
			}
			if suppressedSet[member] {
				both = append(both, member)
			}
		}
		sort.Strings(bad)
		sort.Strings(both)
		if len(bad) != 0 {
			return out, refuse("Disclosures[%s] names members that are not disclosure-eligible: %v", id, bad)
		}
		if len(both) != 0 {
			return out, refuse("Disclosures[%s] reveals member(s) declared suppressed: %v", id, both)
		}
	}
	var owned []string
	for _, kind := range ownedExtensions {
		if _, present := extensions[kind]; present {
			owned = append(owned, kind)
		}
	}
	if len(owned) != 0 {
		sort.Strings(owned)
		return out, refuse("Extensions cannot set kinds this producer owns: %v", owned)
	}
	if len(disclosures) != 0 {
		overlay := make(map[string]interface{}, len(disclosures))
		for id, members := range disclosures {
			if members == nil {
				members = map[string]interface{}{}
			}
			overlay[id] = members
		}
		value, err := jsonObject(overlay, "Disclosures")
		if err != nil {
			return out, err
		}
		out.disclosures = value
	}
	return out, nil
}

// checkOverlayTargets refuses an overlay entry for a record the Bundle does
// not carry.
func checkOverlayTargets(disclosures map[string]interface{}, carried map[string]map[string]interface{}) error {
	var unknown []string
	for id := range disclosures {
		if carried[id] == nil {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) != 0 {
		sort.Strings(unknown)
		return refuse("Disclosures given for record(s) the bundle does not carry: %v", unknown)
	}
	return nil
}

// closure returns the records reached from root within depth citation edges
// (root included) and, in first-seen order, the targets lookup does not hold:
// the traversal the verifier checks graph closure with (citationTargets).
func closure(root string, depth int, lookup func(string) (map[string]interface{}, error)) (map[string]map[string]interface{}, []string, error) {
	rootRecord, err := lookup(root)
	if err != nil {
		return nil, nil, err
	}
	if rootRecord == nil {
		return nil, nil, refuse("root %s: no such record", root)
	}
	found := map[string]map[string]interface{}{root: rootRecord}
	isMissing := map[string]bool{}
	var missing []string
	frontier := []string{root}
	for i := 0; i < depth && len(frontier) != 0; i++ {
		var next []string
		for _, sourceID := range frontier {
			for _, target := range citationTargets(found[sourceID]) {
				if found[target] != nil || isMissing[target] {
					continue
				}
				record, err := lookup(target)
				if err != nil {
					return nil, nil, err
				}
				if record == nil {
					isMissing[target] = true
					missing = append(missing, target)
					continue
				}
				found[target] = record
				next = append(next, target)
			}
		}
		frontier = next
	}
	return found, missing, nil
}

// completenessBlock states closure_depth, records_mode, missing,
// suppressed_fields and payloads_mode: as declared, else all when no
// committed, eligible, unsuppressed member of any carried record is left
// unrevealed (vacuously so when there is none), else selected.
func completenessBlock(records []map[string]interface{}, checked checkedOptions, missing []string, payloadsMode string) (map[string]interface{}, error) {
	suppressed := map[string]bool{}
	for _, member := range checked.suppressed {
		suppressed[member] = true
	}
	var unrevealed, gaps []string
	for _, record := range records {
		id, _ := record["capsule_id"].(string)
		members, disclosed := checked.disclosures[id].(map[string]interface{})
		for _, member := range eligibleMembers {
			if suppressed[member] {
				continue
			}
			if _, committed := committedDigest(record, registries.DisclosureEligibleFields[member]); !committed {
				continue
			}
			if _, revealed := members[member]; revealed {
				continue
			}
			unrevealed = append(unrevealed, id+":"+member)
			if disclosed {
				gaps = append(gaps, id+":"+member)
			}
		}
	}
	if payloadsMode == "all" && len(checked.disclosures) != 0 && len(gaps) != 0 {
		return nil, refuse("PayloadsMode all, but the Disclosures overlay does not reveal: %v", gaps)
	}
	if payloadsMode == "" {
		payloadsMode = "selected"
		if len(unrevealed) == 0 {
			payloadsMode = "all"
		}
	}
	recordsMode := "complete"
	if len(missing) != 0 {
		recordsMode = "declared_incomplete"
	}
	return map[string]interface{}{
		"closure_depth":     jsonInteger(uint64(checked.depth)),
		"records_mode":      recordsMode,
		"payloads_mode":     payloadsMode,
		"suppressed_fields": stringList(checked.suppressed),
		"missing":           stringList(missing),
	}, nil
}

// decodeRecord is the stored record as a Bundle carries it: the Capsule
// without any signature or key_id of its own, and with a claimed Producer
// Envelope re-inlined as those local-only fields (both outside the
// capsule_id preimage).
func decodeRecord(capsuleID string, stored StoredRecord) (map[string]interface{}, error) {
	value, err := decodeJSONText(stored.Capsule)
	if err != nil {
		return nil, refuse("record %s: the stored capsule is not a JSON object (%v)", capsuleID, err)
	}
	capsule, isObject := value.(map[string]interface{})
	if !isObject {
		return nil, refuse("record %s: the stored capsule is not a JSON object", capsuleID)
	}
	if capsule["capsule_id"] != capsuleID {
		return nil, refuse("record %s: the store returned a different capsule", capsuleID)
	}
	// Only the stored envelope speaks for the record: signature fields in the
	// stored JSON are dropped, so an empty envelope always reads unsigned.
	delete(capsule, "signature")
	delete(capsule, "key_id")
	if len(stored.ProducerEnvelope) != 0 {
		checked := envelope.Verify(capsuleID, stored.ProducerEnvelope)
		if !checked.OK {
			return nil, refuse("record %s: its producer envelope does not verify", capsuleID)
		}
		capsule["signature"] = hex.EncodeToString(stored.ProducerEnvelope)
		capsule["key_id"] = hex.EncodeToString(checked.PublicKey)
	}
	return capsule, nil
}

// selfChecked returns bundle unless its digest cannot be computed (a number
// JCS refuses) or VerifyStrict calls it INVALID.
func selfChecked(bundle map[string]interface{}) (map[string]interface{}, error) {
	if _, err := BundleDigest(bundle); err != nil {
		return nil, refuse("the bundle has no canonical digest: %v", err)
	}
	result := VerifyStrict(bundle, StrictOptions{})
	if result.Verdict != VerdictInvalid {
		return bundle, nil
	}
	var failed []string
	for _, claim := range result.Claims {
		if claim.Status == "fail" {
			detail := strings.Join(claim.Findings, ", ")
			if detail == "" {
				detail = claim.Status
			}
			failed = append(failed, claim.Name+": "+detail)
		}
	}
	if result.Witnesses != nil && result.Witnesses.Status == "fail" {
		failed = append(failed, "witnesses: "+strings.Join(result.Witnesses.Findings, ", "))
	}
	if len(failed) == 0 {
		failed = []string{"not an evidence bundle"}
	}
	return nil, refuse("the bundle does not verify: %s", strings.Join(failed, "; "))
}

// jsonObject returns value as the JSON object it encodes, integers as
// json.Number, so a caller's Go values (int, float64, structs) are carried as
// JCS and the verifiers read them. nil stays nil.
func jsonObject(value map[string]interface{}, name string) (map[string]interface{}, error) {
	if value == nil {
		return nil, nil
	}
	if canonical.TooDeep(value) {
		return nil, refuse("%s is nested too deeply (more than %d levels)", name, canonical.MaxNestingDepth)
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, refuse("%s is not JSON: %v", name, err)
	}
	decoded, err := decodeJSONText(data)
	if err != nil {
		return nil, refuse("%s is not JSON: %v", name, err)
	}
	object, _ := decoded.(map[string]interface{})
	return object, nil
}

func sortedBySeq(records map[string]map[string]interface{}, seqOf map[string]uint64) []string {
	ids := make([]string, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return seqOf[ids[i]] < seqOf[ids[j]] })
	return ids
}

func jsonInteger(value uint64) json.Number { return json.Number(strconv.FormatUint(value, 10)) }

func stringList(values []string) []interface{} {
	out := make([]interface{}, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}

// inclusionProofWire reads a source's inclusion proof with the verifier's own
// parser and returns only its wire fields, so a proof the verifier cannot
// read is refused here rather than carried.
func inclusionProofWire(proof InclusionProof) (map[string]interface{}, error) {
	parsed, err := parseInclusionProof(map[string]interface{}{
		"v": jsonInteger(proof.V), "kind": proof.Kind, "size": jsonInteger(proof.Size), "leaf_index": jsonInteger(proof.LeafIndex),
		"witness": stringList(proof.Witness), "peaks_left": stringList(proof.PeaksLeft), "peaks_right": stringList(proof.PeaksRight),
	})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"v": jsonInteger(parsed.V), "kind": parsed.Kind, "size": jsonInteger(parsed.Size), "leaf_index": jsonInteger(parsed.LeafIndex),
		"witness": stringList(hexList(parsed.Witness)), "peaks_left": stringList(hexList(parsed.PeaksLeft)), "peaks_right": stringList(hexList(parsed.PeaksRight)),
	}, nil
}

// rangeProofWire is inclusionProofWire for a range proof.
func rangeProofWire(proof RangeProof) (map[string]interface{}, error) {
	parsed, err := parseRangeProof(map[string]interface{}{
		"from_seq": jsonInteger(proof.FromSeq), "to_seq": jsonInteger(proof.ToSeq), "size": jsonInteger(proof.Size),
		"from_index": jsonInteger(proof.FromIndex), "to_index": jsonInteger(proof.ToIndex), "witness": stringList(proof.Witness),
	})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"from_seq": jsonInteger(uint64(parsed.FromSeq)), "to_seq": jsonInteger(uint64(parsed.ToSeq)), "size": jsonInteger(parsed.Size),
		"from_index": jsonInteger(parsed.Proof.FromIndex), "to_index": jsonInteger(parsed.Proof.ToIndex), "witness": stringList(hexList(parsed.Proof.Witness)),
	}, nil
}
