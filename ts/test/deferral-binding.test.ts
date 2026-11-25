import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { decodeStrictJson, type ParsedJson } from "../src/json.js";
import { verifyClass1 } from "../src/verify.js";

// The §5.4.4 deferral binding rule through verifyClass1's own store argument.
// The capsule corpus reaches it only through verifyStore; these cover a
// caller-supplied array store, a forged parent copy and an id-only Set.

const ledger = (
  decodeStrictJson(
    readFileSync(
      resolve(
        import.meta.dirname,
        "..",
        "..",
        "vectors",
        "capsule",
        "neg-supersedes-action-mismatch",
        "input.json",
      ),
    ),
  ) as { ledger: ParsedJson[] }
).ledger;
const [parent, child] = ledger as [ParsedJson, ParsedJson];
const parentId = (parent as { capsule_id: string }).capsule_id;

describe("deferral binding rule with a verifyClass1 store", () => {
  it("an array of Capsules applies it", async () => {
    const result = await verifyClass1(child, [parent, child]);
    expect(result.ok).toBe(false);
    expect(
      result.findings.filter((f) => f.code === "supersedes_action_mismatch"),
    ).toHaveLength(1);
  });

  it("a Set of ids reports the rule as not evaluated", async () => {
    const result = await verifyClass1(child, new Set([parentId]));
    expect(result.ok).toBe(true);
    const codes = result.findings.map((f) => f.code);
    expect(codes).not.toContain("supersedes_action_mismatch");
    expect(
      result.findings.filter(
        (f) =>
          f.code === "deferral_binding_not_evaluated" && f.severity === "info",
      ),
    ).toHaveLength(1);
  });

  it("a forged first copy of the parent does not capture the binding", async () => {
    const childAction = (child as { action_id: string }).action_id;
    const forged = {
      ...(parent as Record<string, ParsedJson>),
      action_id: childAction,
    };
    const result = await verifyClass1(child, [forged, parent, child]);
    expect(result.ok).toBe(false);
    expect(result.findings.map((f) => f.code)).toContain(
      "supersedes_action_mismatch",
    );
  });
});
