import { JsonNumber } from "./json.js";

/**
 * The deepest nesting of objects and arrays this package decodes, renders or
 * verifies: `[]` is one level, `[[]]` two. Go, Python and Rust refuse the
 * same documents (vectors/json-nesting/), so one value never reads
 * differently across implementations.
 */
export const MAX_NESTING_DEPTH = 128;

/**
 * Whether `value` nests arrays and objects more than {@link MAX_NESTING_DEPTH}
 * levels deep. The walk is iterative and depth first, so it never overflows
 * the stack and stops on a value that contains itself, which is infinitely
 * deep. Arrays and every object but a `JsonNumber` nest, so a value built in
 * code from class instances meets the same limit as parsed text.
 */
export function nestedTooDeep(value: unknown): boolean {
  const stack: [unknown, number][] = [[value, 0]];
  while (stack.length !== 0) {
    const [node, depth] = stack.pop()!;
    let children: readonly unknown[];
    if (Array.isArray(node)) children = node;
    else if (
      node !== null &&
      typeof node === "object" &&
      !(node instanceof JsonNumber)
    )
      children = Object.values(node as Record<string, unknown>);
    else continue;
    if (depth >= MAX_NESTING_DEPTH) return true;
    for (const child of children) stack.push([child, depth + 1]);
  }
  return false;
}
