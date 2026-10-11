import { describe, expect, it } from "vitest";
import { decodeStrictJson, jcs } from "../src/json.js";

describe("decodeStrictJson object members", () => {
  it("keeps a member named __proto__ as an own member inside the canonical form", () => {
    const value = decodeStrictJson('{"x":{"__proto__":{"a":1},"b":2}}') as {
      x: Record<string, unknown>;
    };
    expect(Object.keys(value.x)).toEqual(["__proto__", "b"]);
    expect(Object.getPrototypeOf(value.x)).toBe(Object.prototype);
    expect(new TextDecoder().decode(jcs(value))).toBe(
      '{"x":{"__proto__":{"a":1},"b":2}}',
    );
  });

  it("rejects a repeated name unless the last value is asked to win", () => {
    expect(() => decodeStrictJson('{"a":1,"a":2}')).toThrow(SyntaxError);
    const value = decodeStrictJson('{"a":1,"a":"two"}', {
      lastDuplicateWins: true,
    });
    expect(value).toEqual({ a: "two" });
  });
});
