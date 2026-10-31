// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"encoding/binary"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
)

// cborNestsTooDeep reports whether the first CBOR data item in data nests
// more than canonical.MaxNestingDepth levels: an array, a map or a tag around
// an item is one level, so [] is one level and [[]] two (vectors/cbor-nesting/,
// #504). It walks the heads without recursion, so it cannot exhaust the stack,
// and counts exactly where a library's own limit does not (fxamacker counts a
// tag only when it directly wraps a tag). Input it cannot walk (truncated,
// reserved information) reports false and is left to the decoder to refuse.
func cborNestsTooDeep(data []byte) bool {
	type frame struct {
		remaining uint64 // children left; ^uint64(0) when indefinite
		level     bool   // counts as a level (not an indefinite string)
	}
	var stack []frame
	levels := 0
	pos := 0
	// complete records one finished item and closes every frame it finishes.
	complete := func() bool {
		for len(stack) > 0 {
			top := &stack[len(stack)-1]
			if top.remaining != ^uint64(0) {
				top.remaining--
				if top.remaining != 0 {
					return false
				}
				if top.level {
					levels--
				}
				stack = stack[:len(stack)-1]
				continue
			}
			return false
		}
		return true
	}
	for pos < len(data) {
		initial := data[pos]
		pos++
		if initial == 0xff { // break closes an indefinite frame
			if len(stack) == 0 || stack[len(stack)-1].remaining != ^uint64(0) {
				return false
			}
			if stack[len(stack)-1].level {
				levels--
			}
			stack = stack[:len(stack)-1]
			if complete() {
				return false
			}
			continue
		}
		major, info := initial>>5, initial&31
		var arg uint64
		indefinite := false
		switch {
		case info < 24:
			arg = uint64(info)
		case info <= 27:
			width := 1 << (info - 24)
			if pos+width > len(data) {
				return false
			}
			switch width {
			case 1:
				arg = uint64(data[pos])
			case 2:
				arg = uint64(binary.BigEndian.Uint16(data[pos:]))
			case 4:
				arg = uint64(binary.BigEndian.Uint32(data[pos:]))
			default:
				arg = binary.BigEndian.Uint64(data[pos:])
			}
			pos += width
		case info == 31 && major >= 2 && major <= 5:
			indefinite = true
		default:
			return false
		}
		switch major {
		case 0, 1, 7:
			if complete() {
				return false
			}
		case 2, 3:
			if indefinite {
				stack = append(stack, frame{remaining: ^uint64(0)})
				continue
			}
			if arg > uint64(len(data)-pos) {
				return false
			}
			pos += int(arg)
			if complete() {
				return false
			}
		default: // 4 array, 5 map, 6 tag
			levels++
			if levels > canonical.MaxNestingDepth {
				return true
			}
			children := arg
			if major == 5 {
				children = arg * 2
				if arg > ^uint64(0)/2 {
					return false
				}
			} else if major == 6 {
				children = 1
			}
			switch {
			case indefinite:
				stack = append(stack, frame{remaining: ^uint64(0), level: true})
			case children == 0:
				levels--
				if complete() {
					return false
				}
			default:
				stack = append(stack, frame{remaining: children, level: true})
			}
		}
	}
	return false
}
