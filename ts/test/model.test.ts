import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import {
  CURRENT_SPEC_VERSION,
  PUBLISHED_SPEC_VERSIONS,
  decodeCapsuleJson,
  disclosureEligibleFields,
  parseCapsule,
  registries,
  sealCapsule,
  verifyClass1,
} from "../src/index.js";

const capsuleVectors = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "vectors",
  "capsule",
);

it("seals and parses a typed format-4 record", async () => {
  const capsule = await sealCapsule({
    spec_version: CURRENT_SPEC_VERSION,
    format_version: "4",
    canonicalization_id: "jcs",
    action_id: "ts-model-test",
    action_type: "fyi",
    operator: "operator",
    developer: "developer",
    timestamp: "2026-09-13T00:00:00Z",
    references: [],
  });
  await expect(parseCapsule(JSON.stringify(capsule))).resolves.toEqual(capsule);
});

it("exports all seven registries and the disclosure eligibility table", () => {
  expect(Object.keys(registries)).toHaveLength(7);
  expect(registries.citation_purpose).toEqual(
    new Set([
      "acted_on",
      "responds_to",
      "corroborates_source_time",
      "counterparty_half",
      "counterparty_inclusion",
    ]),
  );
  expect(disclosureEligibleFields).toEqual({
    agent_input: "model_attestation.compute_attestation.agent_input_digest",
    agent_output: "model_attestation.compute_attestation.agent_output_digest",
  });
});

it("producers emit -05 and verifiers accept both -04 and -05", async () => {
  expect(CURRENT_SPEC_VERSION).toBe("draft-mih-scitt-agent-action-capsule-05");
  const load = (name: string) =>
    decodeCapsuleJson(readFileSync(join(capsuleVectors, name, "input.json")));
  // A committed -04 vector and its -05 twin (same body, only spec_version differs).
  const v04 = load("pos-v4-jcs-chain-committed");
  const v05 = load("pos-v05-spec-version-chain-committed");
  expect(v04.spec_version).toBe("draft-mih-scitt-agent-action-capsule-04");
  expect(v05.spec_version).toBe(CURRENT_SPEC_VERSION);
  for (const capsule of [v04, v05]) {
    expect(PUBLISHED_SPEC_VERSIONS).toContain(capsule.spec_version);
    const result = await verifyClass1(capsule);
    expect(result.ok).toBe(true);
    expect(result.capsuleId).toBe(capsule.capsule_id);
  }
  expect(v05.capsule_id).not.toBe(v04.capsule_id);
});
