import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import {
  CURRENT_SPEC_VERSION,
  computeCapsuleId,
  ACCEPTED_SPEC_VERSIONS,
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
      "ran_under",
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

it("CURRENT_SPEC_VERSION is -05", () => {
  expect(CURRENT_SPEC_VERSION).toBe("draft-mih-scitt-agent-action-capsule-05");
});

const loadVector = (name: string) =>
  decodeCapsuleJson(readFileSync(join(capsuleVectors, name, "input.json")));

it("spec_version selects no algorithm: -04 and -05 twins both verify", async () => {
  // A committed -04 vector and its -05 twin (same body, only spec_version differs).
  const v04 = loadVector("pos-v4-jcs-chain-committed");
  const v05 = loadVector("pos-v05-spec-version-chain-committed");
  expect([v04.spec_version, v05.spec_version]).toEqual(ACCEPTED_SPEC_VERSIONS);
  for (const capsule of [v04, v05]) {
    const result = await verifyClass1(capsule);
    expect(result.ok).toBe(true);
    expect(result.capsuleId).toBe(capsule.capsule_id);
  }
  expect(v05.capsule_id).not.toBe(v04.capsule_id);
});

it("an unrecognized spec_version is not a rejection", async () => {
  const body = loadVector("pos-v05-spec-version-chain-committed");
  body.spec_version = "not-a-published-revision";
  delete body.capsule_id;
  const capsule = { ...body, capsule_id: await computeCapsuleId(body) };
  const result = await verifyClass1(capsule);
  expect(result.ok).toBe(true);
  expect(result.findings.filter((f) => f.severity === "error")).toEqual([]);
});
