// SPDX-License-Identifier: BSD-3-Clause
package canonical

// MaxNestingDepth is the deepest nesting of objects and arrays a verifier
// reads. encoding/json refuses deeper text, so only a value built in Go can
// exceed it; recursing over such a value could exhaust the goroutine stack,
// which is fatal rather than a recoverable panic.
const MaxNestingDepth = 10000

// TooDeep reports whether value nests objects or arrays more than
// MaxNestingDepth levels deep; a value that contains itself is infinitely
// deep. It walks iteratively, so it cannot itself exhaust the stack, and
// steps through an array in place, so a wide array costs no extra memory.
func TooDeep(value interface{}) bool {
	// Each frame holds the members of one open container still to visit.
	type frame struct {
		members []interface{}
		next    int
	}
	stack := []frame{{members: []interface{}{value}}}
	for len(stack) != 0 {
		top := &stack[len(stack)-1]
		if top.next == len(top.members) {
			stack = stack[:len(stack)-1]
			continue
		}
		member := top.members[top.next]
		top.next++
		// The member's own depth is len(stack) - 1.
		switch node := member.(type) {
		case map[string]interface{}:
			if len(stack) > MaxNestingDepth {
				return true
			}
			members := make([]interface{}, 0, len(node))
			for _, m := range node {
				members = append(members, m)
			}
			stack = append(stack, frame{members: members})
		case []interface{}:
			if len(stack) > MaxNestingDepth {
				return true
			}
			stack = append(stack, frame{members: node})
		}
	}
	return false
}
