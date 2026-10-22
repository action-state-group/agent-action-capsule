import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  isCalendarDate,
  laterClaimIds,
  recomputeCounts,
  utcDateOf,
  validateEvidenceResult,
} from "../src/result-root.js";

// Spec/evidence-result-v0.md sections 4.2 (out_of_scope) and 4.3
// (applicability), read from the shared vectors every implementation checks.
type Obj = Record<string, unknown>;

function vector(name: string): Obj {
  return JSON.parse(
    readFileSync(
      new URL(`../../vectors/evidence-result/${name}.json`, import.meta.url),
      "utf8",
    ),
  ) as Obj;
}

const POSITIVES = [
  "pos-example-org-out-of-scope-result",
  "pos-example-org-out-of-scope-empty-result",
  "pos-example-org-close-switched-on-result",
  "pos-example-org-applicability-result",
  "pos-example-org-applicability-boundary-result",
  "pos-example-org-applicability-in-force-result",
  "pos-example-org-reconcile-later-result",
  "pos-example-org-repeated-requirement-result",
];

// Refused by the validator: the schema rules this mirror carries, and the
// cross-element rules of sections 4.2 and 4.3.
const REFUSED = [
  "neg-out-of-scope-without-switch",
  "neg-out-of-scope-bucket-absent",
  "neg-out-of-scope-bucket-without-switch",
  "neg-out-of-scope-with-gap",
  "neg-out-of-scope-not-applicable-carrier",
  "neg-satisfied-not-evaluable",
  "neg-not-applicable-verdict",
  "neg-out-of-scope-on-reconcile-claim",
  "neg-out-of-scope-listed-in-met",
  "neg-later-claim-in-bucket",
  "neg-switch-disagrees-in-row",
  "neg-applies-from-disagrees-in-row",
  "neg-generated-at-unparseable",
  "neg-applies-from-not-a-date",
];

// Valid documents whose stated counts the claims do not bear out: the
// reader recomputes and marks them, as for every other headline number.
const MISCOUNTED: ReadonlyArray<readonly [string, string]> = [
  ["neg-later-claim-in-population", "evaluated_population"],
  ["neg-later-unknown-counted", "unknown_count"],
  ["neg-not-yet-in-force-absent", "not_yet_in_force"],
  ["neg-not-yet-in-force-wrong", "not_yet_in_force"],
];

describe("Result v0 sections 4.2 and 4.3", () => {
  it.each(POSITIVES)("%s validates and its counts stand", (name) => {
    const doc = vector(name);
    expect(validateEvidenceResult(doc)).toEqual([]);
    expect(recomputeCounts(doc).mismatches).toEqual([]);
  });

  it.each(REFUSED)("%s is refused", (name) => {
    expect(validateEvidenceResult(vector(name))).not.toEqual([]);
  });

  it.each(MISCOUNTED)(
    "%s validates, and its %s is a count mismatch",
    (name, field) => {
      const doc = vector(name);
      expect(validateEvidenceResult(doc)).toEqual([]);
      expect(recomputeCounts(doc).mismatches.map((m) => m.field)).toEqual([
        field,
      ]);
    },
  );

  it("counts later claims outside the population and the buckets", () => {
    const counts = recomputeCounts(
      vector("pos-example-org-applicability-result"),
    );
    expect(counts.coverage).toEqual({
      evaluatedPopulation: 2,
      excludedNotApplicable: 1,
      unknownCount: 0,
      notYetInForce: 3,
    });
    expect(counts.bucketCounts).toEqual({
      met: 1,
      notMet: 0,
      notEvaluable: 1,
      outOfScope: 0,
      failed: 0,
    });
  });

  it("judges in force by the UTC date of generated_at", () => {
    const doc = vector("pos-example-org-applicability-boundary-result");
    expect(utcDateOf(doc.generated_at)).toBe("2026-09-23");
    expect([...laterClaimIds(doc)]).toEqual(["claim-2"]);
    expect(utcDateOf("2026-09-22")).toBeUndefined();
    expect(utcDateOf("2026-09-22T00:00:00")).toBeUndefined();
    expect(isCalendarDate("2024-02-29")).toBe(true);
    expect(isCalendarDate("2027-02-30")).toBe(false);
    expect(isCalendarDate("2027-13-01")).toBe(false);
  });
});
