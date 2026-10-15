// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/bits"
	"slices"
)

// The Merkle Mountain Range functions the profile's CLL material uses
// (profile §6.2.1), written from the algorithms of the pinned MMR revision
// (draft-bryce-cose-receipts-mmr-profile-02): index_height (§9),
// included_root (§5.2), peaks (§7.1.1) and consistent_roots (§7.1). Node
// indices are zero-based; positions are one-based in the hash
// (pos = index + 1), and an interior node is
// SHA-256(pos as 8 big-endian octets || left || right) (§8.2.1). all_ones is
// read as the profile reads it (P-31): pos & (pos+1) == 0.

func mmrAllOnes(pos uint64) bool { return pos != 0 && pos&(pos+1) == 0 }

// MMRIndexHeight is the height of the node at zero-based index i; leaves
// have height 0.
func MMRIndexHeight(i uint64) uint64 {
	pos := i + 1
	for !mmrAllOnes(pos) {
		pos = pos - (uint64(1) << (bits.Len64(pos) - 1)) + 1
	}
	return uint64(bits.Len64(pos) - 1)
}

func mmrHashPosPair(pos uint64, left, right []byte) []byte {
	h := sha256.New()
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], pos)
	h.Write(encoded[:])
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// MMRIncludedRoot is the root reached from node at index i by proof. The
// node's height plus len(proof) must not exceed maxMMRHeight, or the
// positions it computes overflow; the verifiers check this first.
func MMRIncludedRoot(i uint64, node []byte, proof [][]byte) []byte {
	root, g := node, MMRIndexHeight(i)
	for _, sibling := range proof {
		if MMRIndexHeight(i+1) > g {
			i++
			root = mmrHashPosPair(i+1, sibling, root)
		} else {
			i += uint64(2) << g
			root = mmrHashPosPair(i+1, root, sibling)
		}
		g++
	}
	return root
}

// MMRPeaks is the indices of the peaks of the MMR whose last node is at
// index i.
func MMRPeaks(i uint64) []uint64 {
	var out []uint64
	var peak uint64
	size := i + 1
	for size > 0 {
		highest := (uint64(1) << (bits.Len64(size+1) - 1)) - 1
		peak += highest
		out = append(out, peak-1)
		size -= highest
	}
	return out
}

// MMRConsistentRoots is the roots each old peak reaches by its consistency
// path, with adjacent repeats merged. ifrom is the index of the old MMR's
// last node.
func MMRConsistentRoots(ifrom uint64, accumulator [][]byte, paths [][][]byte) [][]byte {
	var roots [][]byte
	for k, index := range MMRPeaks(ifrom) {
		if k >= len(accumulator) || k >= len(paths) {
			break
		}
		root := MMRIncludedRoot(index, accumulator[k], paths[k])
		if len(roots) == 0 || !bytes.Equal(roots[len(roots)-1], root) {
			roots = append(roots, root)
		}
	}
	return roots
}

// MMRLeafIndex is the zero-based MMR node index of zero-based leaf n.
func MMRLeafIndex(n uint64) uint64 {
	return 2*n - uint64(bits.OnesCount64(n))
}

// CLLLeafValue is the profile's leaf for a logged entry E: SHA-256(0x00 || E)
// (profile §6.2.1, P-31).
func CLLLeafValue(entry []byte) []byte {
	sum := sha256.Sum256(append([]byte{0}, entry...))
	return sum[:]
}

// maxProofNodes bounds every node list a proof carries: no MMR the profile
// can address has more peaks or a longer path.
const maxProofNodes = 64

// maxMMRHeight is the greatest node height in an MMR whose indices fit in a
// profile integer (below 2^53). A path that would climb above it names no
// node of such an MMR, and following it would overflow a position.
const maxMMRHeight = 52

// pathFits reports whether a path of n siblings from the node at index stays
// within maxMMRHeight.
func pathFits(index uint64, n int) bool {
	return index <= MaxSafeInteger && MMRIndexHeight(index)+uint64(n) <= maxMMRHeight
}

// EncodeCLLInclusionProof is the cll-inclusion-proof octets for zero-based
// leaf n: deterministic CBOR of [MMR index, inclusion path] (profile
// §6.2.1).
func EncodeCLLInclusionProof(leaf uint64, path [][]byte) ([]byte, error) {
	return EncodeCBOR([]any{MMRLeafIndex(leaf), byteStringList(path)})
}

// EncodeCLLConsistencyProof is the cll-consistency-proof octets proving the
// MMR of oldSize nodes extends to newSize nodes: deterministic CBOR of
// [tree-size-1, tree-size-2, consistency-paths, right-peaks] (profile
// §6.2.1). paths are the old peaks' paths, right the new peaks no old peak
// reaches.
func EncodeCLLConsistencyProof(oldSize, newSize uint64, paths [][][]byte, right [][]byte) ([]byte, error) {
	encoded := make([]any, len(paths))
	for i, path := range paths {
		encoded[i] = byteStringList(path)
	}
	return EncodeCBOR([]any{oldSize, newSize, encoded, byteStringList(right)})
}

func byteStringList(nodes [][]byte) []any {
	out := make([]any, len(nodes))
	for i, node := range nodes {
		out[i] = node
	}
	return out
}

// VerifyCLLInclusion checks cll-inclusion-proof octets: that entry is a
// leaf whose path reaches one of peaks, the commitment of a checkpoint
// (profile §6.2.1 step 12).
func VerifyCLLInclusion(peaks [][]byte, entry, inclusion []byte) error {
	proof, err := DecodeCBOR(inclusion)
	if err != nil {
		return fmt.Errorf("%w: inclusion proof: %v", ErrInvalid, err)
	}
	pair, ok := proof.([]any)
	if !ok || len(pair) != 2 {
		return fmt.Errorf("%w: inclusion proof is not [index, path]", ErrInvalid)
	}
	index, ok := UintValue(pair[0])
	path, pathOK := byteStrings32(pair[1])
	if !ok || !pathOK {
		return fmt.Errorf("%w: inclusion proof is not [index, [32-octet byte strings]]", ErrInvalid)
	}
	if MMRIndexHeight(index) != 0 {
		return fmt.Errorf("%w: inclusion index %d is not a leaf", ErrInvalid, index)
	}
	if !pathFits(index, len(path)) {
		return fmt.Errorf("%w: inclusion path is longer than any MMR can have", ErrInvalid)
	}
	root := MMRIncludedRoot(index, CLLLeafValue(entry), path)
	if !slices.ContainsFunc(peaks, func(peak []byte) bool { return bytes.Equal(peak, root) }) {
		return fmt.Errorf("%w: the inclusion path reaches no peak of the checkpoint", ErrInvalid)
	}
	return nil
}

// VerifyCLLConsistency checks cll-consistency-proof octets: that the
// commitment newPeaks extends the commitment oldPeaks (profile §6.2.1 step
// 13; MMR §7.1, §7.1.1).
func VerifyCLLConsistency(oldPeaks, newPeaks [][]byte, consistency []byte) error {
	decoded, err := DecodeCBOR(consistency)
	if err != nil {
		return fmt.Errorf("%w: consistency proof: %v", ErrInvalid, err)
	}
	parts, ok := decoded.([]any)
	if !ok || len(parts) != 4 {
		return fmt.Errorf("%w: consistency proof is not four members", ErrInvalid)
	}
	size1, ok1 := UintValue(parts[0])
	size2, ok2 := UintValue(parts[1])
	rawPaths, ok3 := parts[2].([]any)
	right, ok4 := byteStrings32(parts[3])
	if !ok1 || !ok2 || !ok3 || !ok4 || size1 == 0 || size1 > size2 || len(rawPaths) > maxProofNodes {
		return fmt.Errorf("%w: consistency proof is malformed", ErrInvalid)
	}
	paths := make([][][]byte, len(rawPaths))
	for i, raw := range rawPaths {
		if paths[i], ok = byteStrings32(raw); !ok {
			return fmt.Errorf("%w: consistency path %d is malformed", ErrInvalid, i)
		}
	}
	peaks := MMRPeaks(size1 - 1)
	if n := len(peaks); n != len(paths) || n != len(oldPeaks) {
		return fmt.Errorf("%w: consistency proof does not match the earlier commitment", ErrInvalid)
	}
	for k, index := range peaks {
		if !pathFits(index, len(paths[k])) {
			return fmt.Errorf("%w: consistency path %d is longer than any MMR can have", ErrInvalid, k)
		}
	}
	roots := MMRConsistentRoots(size1-1, oldPeaks, paths)
	if len(right) != len(MMRPeaks(size2-1))-len(roots) {
		return fmt.Errorf("%w: consistency proof has the wrong number of right peaks", ErrInvalid)
	}
	if !slices.EqualFunc(append(roots, right...), newPeaks, bytes.Equal) {
		return fmt.Errorf("%w: consistency proof does not reach the later commitment", ErrInvalid)
	}
	return nil
}

func byteStrings32(v any) ([][]byte, bool) {
	items, ok := v.([]any)
	if !ok || len(items) > maxProofNodes {
		return nil, false
	}
	out := make([][]byte, len(items))
	for i, item := range items {
		b, ok := item.([]byte)
		if !ok || len(b) != sha256.Size {
			return nil, false
		}
		out[i] = b
	}
	return out, true
}
