import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { decodeFragment, encodeFragment, verifyBundle } from "../src/index.js";

// The single-record report bundle (the /demos shape) and its two distinguishing
// negatives. `expected` holds for every conforming verifier, including the one
// embedded in a rendered report; the Python reference additionally pins
// `expected_without_cll`, which does not apply here (cll is a hard dependency).
type Expected = {
  graph_closure: string;
  interval_coverage: string;
  interval_findings: string[];
  per_record_membership: string;
  membership_findings: string[];
};
const vector = JSON.parse(
  readFileSync(
    resolve(
      import.meta.dirname,
      "..",
      "..",
      "vectors",
      "bundle",
      "report-single-record.json",
    ),
    "utf8",
  ),
) as {
  count: number;
  cases: { name: string; bundle: unknown; expected: Expected }[];
};

describe("report single-record bundle vector", () => {
  it("has the positive and both negatives", () => {
    expect(vector.cases).toHaveLength(vector.count);
  });
  for (const testCase of vector.cases)
    it(testCase.name, async () => {
      expect(decodeFragment(encodeFragment(testCase.bundle))).toEqual(
        testCase.bundle,
      );
      const result = await verifyBundle(testCase.bundle);
      expect({
        graph_closure: result.graphClosure.status,
        interval_coverage: result.intervalCoverage.status,
        interval_findings: [...result.intervalCoverage.findings].sort(),
        per_record_membership: result.perRecordMembership.status,
        membership_findings: [...result.perRecordMembership.findings].sort(),
      }).toEqual({
        ...testCase.expected,
        interval_findings: [...testCase.expected.interval_findings].sort(),
        membership_findings: [...testCase.expected.membership_findings].sort(),
      });
    });
});
