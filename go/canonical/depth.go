// SPDX-License-Identifier: BSD-3-Clause
package canonical

// MaxNestingDepth is the deepest nesting of objects and arrays a verifier
// reads. encoding/json refuses deeper text, so only a value built in Go can
// exceed it; recursing over such a value could exhaust the goroutine stack,
// which is fatal rather than a recoverable panic.
const MaxNestingDepth = 10000

// TooDeep reports whether value nests objects or arrays more than
// MaxNestingDepth levels deep. It walks iteratively, so it cannot itself
// exhaust the stack.
func TooDeep(value interface{}) bool {
	type entry struct {
		value interface{}
		depth int
	}
	stack := []entry{{value, 0}}
	for len(stack) != 0 {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch node := top.value.(type) {
		case map[string]interface{}:
			if top.depth >= MaxNestingDepth {
				return true
			}
			for _, member := range node {
				stack = append(stack, entry{member, top.depth + 1})
			}
		case []interface{}:
			if top.depth >= MaxNestingDepth {
				return true
			}
			for _, member := range node {
				stack = append(stack, entry{member, top.depth + 1})
			}
		}
	}
	return false
}
