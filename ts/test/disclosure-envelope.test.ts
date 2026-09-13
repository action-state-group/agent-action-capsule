import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { decodeStrictJson, verifyDisclosureEnvelope } from "../src/index.js";

const root = resolve(
  import.meta.dirname,
  "..",
  "..",
  "vectors",
  "disclosure-envelope",
);
const manifest = JSON.parse(
  readFileSync(resolve(root, "vectors.json"), "utf8"),
) as {
  cases: Array<{ name: string }>;
};

describe("authoritative Disclosure Envelope corpus", () => {
  for (const item of manifest.cases) {
    it(item.name, () => {
      const input = decodeStrictJson(
        readFileSync(resolve(root, item.name, "input.json")),
      );
      const wrapper = (
        input as { envelope: Parameters<typeof verifyDisclosureEnvelope>[0] }
      ).envelope;
      const expected = JSON.parse(
        readFileSync(resolve(root, item.name, "expected.json"), "utf8"),
      ) as {
        ok: boolean;
        capsule: {
          ok: boolean;
          derived: Record<string, string>;
          capsule_id_recomputed: string;
          findings: Array<{ code: string }>;
        };
        disclosures_checked: number;
        disclosures_matched: number;
        disclosure_findings: Array<{ member: string; code: string }>;
      };
      const actual = verifyDisclosureEnvelope(wrapper);
      expect(actual.ok).toBe(expected.ok);
      expect(actual.capsuleResult.ok).toBe(expected.capsule.ok);
      expect(actual.capsuleResult.assurance).toEqual(expected.capsule.derived);
      expect(actual.capsuleResult.capsuleId).toBe(
        expected.capsule.capsule_id_recomputed,
      );
      expect(
        actual.capsuleResult.findings.map((finding) => finding.code),
      ).toEqual(expected.capsule.findings.map((finding) => finding.code));
      expect(actual.disclosuresChecked).toBe(expected.disclosures_checked);
      expect(actual.disclosuresMatched).toBe(expected.disclosures_matched);
      expect(actual.disclosureFindings).toEqual(expected.disclosure_findings);
    });
  }
});
