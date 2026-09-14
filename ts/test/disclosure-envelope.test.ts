import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { resolveDisclosurePath } from "../src/disclosure-path.js";
import {
  asJsonObject,
  buildDisclosureEnvelope,
  computeCapsuleId,
  decodeStrictJson,
  disclosureEligibleFields,
  verifyDisclosureEnvelope,
  jsonDigest,
  type ParsedJson,
} from "../src/index.js";

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
    it(item.name, async () => {
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
      const actual = await verifyDisclosureEnvelope(wrapper);
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

it("follows the complete registered path instead of matching its final name", async () => {
  const input = decodeStrictJson(
    readFileSync(
      resolve(root, "pos-disclosure-envelope-nested-input", "input.json"),
    ),
  );
  const wrapper = asJsonObject(asJsonObject(input)?.envelope)!;
  const capsule = asJsonObject(wrapper.capsule)!;
  const committed = resolveDisclosurePath(
    capsule,
    disclosureEligibleFields.agent_input,
  );
  capsule.agent_input_digest = "0".repeat(64);

  expect(
    resolveDisclosurePath(capsule, disclosureEligibleFields.agent_input),
  ).toBe(committed);
  expect((await verifyDisclosureEnvelope(wrapper)).disclosureFindings).toEqual([
    { member: "agent_input", code: "disclosure_match" },
  ]);
});

it("verifies a vector-based commitment for a deeply nested disclosure", async () => {
  const input = decodeStrictJson(
    readFileSync(
      resolve(root, "pos-disclosure-envelope-nested-input", "input.json"),
    ),
  );
  const wrapper = asJsonObject(asJsonObject(input)?.envelope)!;
  const capsule = asJsonObject(wrapper.capsule)!;
  const disclosures = asJsonObject(wrapper.disclosures)!;
  const nested = decodeStrictJson(
    '{"request":{"items":[{"attributes":{"fragile":true},"sku":"A"},{"attributes":{"fragile":false},"sku":"B"}]}}',
  );
  const committedDigest =
    "8842ab7f1b59276804c967ba4a0a3286d359ff624ca2a913e9f0b29b7d4c0f9a";
  disclosures.agent_input = nested;
  const compute = asJsonObject(
    asJsonObject(capsule.model_attestation)?.compute_attestation,
  )!;
  expect(await jsonDigest(nested)).toBe(committedDigest);
  compute.agent_input_digest = committedDigest;
  capsule.capsule_id = await computeCapsuleId(
    capsule as Record<string, ParsedJson>,
  );

  const actual = await verifyDisclosureEnvelope(wrapper);
  expect(actual.ok).toBe(true);
  expect(actual.capsuleResult.ok).toBe(true);
  expect(actual.disclosureFindings).toEqual([
    { member: "agent_input", code: "disclosure_match" },
  ]);
});

it("builds and verifies a deeply nested disclosure", async () => {
  const input = decodeStrictJson(
    readFileSync(
      resolve(root, "pos-disclosure-envelope-nested-input", "input.json"),
    ),
  );
  const wrapper = asJsonObject(asJsonObject(input)?.envelope)!;
  const capsule = asJsonObject(wrapper.capsule)!;
  const value = decodeStrictJson(
    '{"outer":{"items":[{"nested":{"value":"one"}},{"nested":{"value":"two"}}]}}',
  );
  const compute = asJsonObject(
    asJsonObject(capsule.model_attestation)?.compute_attestation,
  )!;
  compute.agent_input_digest = await jsonDigest(value);
  capsule.capsule_id = await computeCapsuleId(capsule);

  const envelope = await buildDisclosureEnvelope(capsule, {
    agent_input: value,
  });

  expect(await verifyDisclosureEnvelope(envelope)).toMatchObject({
    ok: true,
    disclosureFindings: [{ member: "agent_input", code: "disclosure_match" }],
  });
});

it("rejects ineligible, uncommitted, malformed, and mismatched disclosures", async () => {
  const input = decodeStrictJson(
    readFileSync(
      resolve(root, "pos-disclosure-envelope-nested-input", "input.json"),
    ),
  );
  const wrapper = asJsonObject(asJsonObject(input)?.envelope)!;
  const capsule = asJsonObject(wrapper.capsule)!;

  await expect(
    buildDisclosureEnvelope(capsule, { not_eligible: "value" }),
  ).rejects.toThrow("disclosure_ineligible_field: not_eligible");
  await expect(
    buildDisclosureEnvelope(capsule, { agent_output: "value" }),
  ).rejects.toThrow("disclosure_no_committed_digest: agent_output");
  await expect(
    buildDisclosureEnvelope(capsule, { agent_input: "different" }),
  ).rejects.toThrow("disclosure_mismatch: agent_input");

  const compute = asJsonObject(
    asJsonObject(capsule.model_attestation)?.compute_attestation,
  )!;
  compute.agent_input_digest = "malformed";
  await expect(
    buildDisclosureEnvelope(capsule, { agent_input: "value" }),
  ).rejects.toThrow("disclosure_no_committed_digest: agent_input");
});
