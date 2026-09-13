import { expect, it } from "vitest";
import {
  disclosureEligibleFields,
  parseCapsule,
  registries,
  sealCapsule,
} from "../src/index.js";

it("seals and parses a typed format-4 record", () => {
  const capsule = sealCapsule({
    spec_version: "draft-mih-scitt-agent-action-capsule-04",
    format_version: "4",
    canonicalization_id: "jcs",
    action_id: "ts-model-test",
    action_type: "fyi",
    operator: "operator",
    developer: "developer",
    timestamp: "2026-09-13T00:00:00Z",
    references: [],
  });
  expect(parseCapsule(JSON.stringify(capsule))).toEqual(capsule);
});

it("exports all seven registries and the disclosure eligibility table", () => {
  expect(Object.keys(registries)).toHaveLength(7);
  expect(registries.citation_purpose).toEqual(
    new Set(["acted_on", "responds_to"]),
  );
  expect(disclosureEligibleFields).toEqual({
    agent_input: "model_attestation.compute_attestation.agent_input_digest",
    agent_output: "model_attestation.compute_attestation.agent_output_digest",
  });
});
