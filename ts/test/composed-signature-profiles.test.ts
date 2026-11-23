// The carried signature profiles of composed/v1
// (draft-mih-zhang-agent-disclosure-bundle-03, "Carried Signature Profiles";
// #676): every case of vectors/bundle/composed-signature-profiles/, as
// python/tests/test_bundle_composed_signature_profiles.py reads them, and the
// four strict-Ed25519 cases of vectors/interop-profile-v1/.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  artifactResponseSigningInput,
  carriedRefusalProfile,
  carriedResponseProfile,
  threeMemberRefusalSigningInput,
  verifyBundle,
  verifyCarriedRefusal,
  verifyCarriedResponse,
  type ComposedResult,
} from "../src/index.js";

type Obj = Record<string, unknown>;
interface ObjectCase {
  id: string;
  kind: "refusal" | "response";
  object: Obj;
  signing_input_hex?: string;
  expect: { profile: string | null; state: string };
}
interface ComposedCase {
  id: string;
  container: Obj;
  expect: {
    status: string;
    findings: string[];
    members: Record<string, Record<string, string>>;
  };
}
const read = (...path: string[]): unknown =>
  JSON.parse(readFileSync(resolve(process.cwd(), "..", ...path), "utf8"));
const FILE = read(
  "vectors",
  "bundle",
  "composed-signature-profiles",
  "vectors.json",
) as { count: number; cases: ObjectCase[]; composed_cases: ComposedCase[] };
const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

async function composed(c: ComposedCase, hooks: boolean) {
  const result = await verifyBundle(
    c.container,
    hooks
      ? {
          refusalSignature: verifyCarriedRefusal,
          responseSignature: verifyCarriedResponse,
        }
      : {},
  );
  const entry = result.extensions.find((e) => e.kind === "composed/v1")!;
  return entry.composed as Exclude<ComposedResult, { malformed: true }>;
}

describe("composed/v1 carried signature profiles", () => {
  it("reads every case", () => {
    expect(FILE.count).toBe(48);
    expect(FILE.cases).toHaveLength(43);
    expect(FILE.composed_cases).toHaveLength(5);
  });

  for (const c of FILE.cases)
    it(c.id, async () => {
      const profile =
        c.kind === "refusal"
          ? carriedRefusalProfile(c.object)
          : carriedResponseProfile(c.object);
      const state =
        c.kind === "refusal"
          ? await verifyCarriedRefusal(c.object)
          : await verifyCarriedResponse(c.object);
      expect(profile ?? null).toBe(c.expect.profile);
      expect(state).toBe(c.expect.state);
      if (c.signing_input_hex === undefined) return;
      if (profile === "three-member-refusal/v1")
        expect(hex(threeMemberRefusalSigningInput(c.object)!)).toBe(
          c.signing_input_hex,
        );
      if (profile === "digest-bound-artifact-response/v1") {
        const o = c.object as Record<string, string>;
        expect(
          hex(
            artifactResponseSigningInput(
              o.request_digest!,
              o.anchor!,
              o.artifact_kind!,
              o.artifact_digest!,
              o.issued_at!,
            ),
          ),
        ).toBe(c.signing_input_hex);
      }
    });

  for (const c of FILE.composed_cases)
    it(c.id, async () => {
      const result = await composed(c, true);
      const plain = await composed(c, false);
      expect(result.status).toBe(c.expect.status);
      for (const [id, states] of Object.entries(c.expect.members))
        for (const [name, state] of Object.entries(states)) {
          const key =
            name === "refusal_signature"
              ? "refusalSignature"
              : "responseSignature";
          expect(result.members.find((m) => m.id === id)![key]).toBe(state);
          expect(plain.members.find((m) => m.id === id)![key]).toBe(
            "signature_unverified",
          );
          if (state === "invalid")
            expect(result.members.find((m) => m.id === id)!.findings).toContain(
              `${name}_invalid`,
            );
        }
    });

  it("reads an unserializable signing input as invalid, never an error", async () => {
    const refusal = FILE.cases.find((c) => c.id === "three-member-verified")!;
    const response = FILE.cases.find((c) => c.id === "response-verified")!;
    expect(
      await verifyCarriedRefusal({ ...refusal.object, issued_at: "\ud800" }),
    ).toBe("invalid");
    expect(
      await verifyCarriedResponse({ ...response.object, issued_at: "\ud800" }),
    ).toBe("invalid");
    expect(
      await verifyCarriedRefusal({
        key_id: refusal.object.key_id,
        signature: refusal.object.sig,
        detail: "\ud800",
      }),
    ).toBe("invalid");
  });

  it("refuses the interop-profile-v1 forgeries", async () => {
    const cases = (
      read("vectors", "interop-profile-v1", "vectors.json") as {
        cases: { id: string; inputs: { replies: { octets_text: string }[] } }[];
      }
    ).cases;
    const reply = (id: string): Obj =>
      JSON.parse(
        cases.find((c) => c.id === id)!.inputs.replies[0]!.octets_text,
      ) as Obj;
    for (const id of [
      "forged-refusal-small-order-key",
      "forged-refusal-identity-r",
    ]) {
      expect(carriedRefusalProfile(reply(id))).toBe("three-member-refusal/v1");
      expect(await verifyCarriedRefusal(reply(id))).toBe("invalid");
    }
    for (const id of ["envelope-small-order-key", "envelope-identity-r"]) {
      const envelope = reply(id);
      expect(await verifyCarriedResponse(envelope)).toBe(
        "signature_unverified",
      );
      // Only the small-order key's forgery verifies any message under a
      // lenient verifier; the identity-R signature is over the envelope.
      if (id !== "envelope-small-order-key") continue;
      const rehomed = {
        request_digest: envelope.request_digest,
        anchor: (envelope.anchor as Obj).digest,
        artifact_kind: "evidence-bundle/v2",
        artifact_digest: envelope.artifact_digest,
        issued_at: envelope.issued_at,
        key_id: envelope.responder,
        sig: envelope.sig,
      };
      expect(await verifyCarriedResponse(rehomed)).toBe("invalid");
    }
  });
});
