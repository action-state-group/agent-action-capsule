import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, it } from "vitest";
import {
  computeCapsuleId,
  sealCapsule,
  verifyClass1,
  verifyDisclosureEnvelope,
  verifyProducerEnvelope,
} from "../src/browser.js";
import type { ParsedJson } from "../src/browser.js";

it("runs the browser entry with platform WebCrypto", async () => {
  expect(globalThis.crypto?.subtle).toBeDefined();
  const capsule = await sealCapsule({
    spec_version: "draft-mih-scitt-agent-action-capsule-04",
    format_version: "4",
    canonicalization_id: "jcs",
    action_id: "browser-test",
    action_type: "fyi",
    operator: "operator",
    developer: "developer",
    timestamp: "2026-09-13T00:00:00Z",
    references: [],
  });
  const jsonCapsule = capsule as unknown as Record<string, ParsedJson>;
  expect(await computeCapsuleId(jsonCapsule)).toBe(capsule.capsule_id);
  expect((await verifyClass1(jsonCapsule)).ok).toBe(true);
  expect(
    (
      await verifyDisclosureEnvelope({
        capsule: jsonCapsule,
        disclosures: {},
      })
    ).ok,
  ).toBe(true);

  const vector = resolve(
    import.meta.dirname,
    "..",
    "..",
    "vectors",
    "producer-envelope",
    "valid",
  );
  expect(
    (
      await verifyProducerEnvelope(
        readFileSync(resolve(vector, "capsule_id.txt"), "utf8").trim(),
        readFileSync(resolve(vector, "envelope.cose")),
      )
    ).ok,
  ).toBe(true);
});
