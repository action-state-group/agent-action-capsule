// verifyKeyBinding over the shared vectors/controller-binding-v0 files (the
// same ones Go reads): the key asked about is the first half's producer.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { parseProfileTime } from "../src/controller-binding.js";
import { verifyKeyBinding } from "../src/key-binding.js";
import { decodeStrictJson } from "../src/json.js";

interface Case {
  id: string;
  inputs: {
    halves: { octets_text: string }[];
    binding: { octets_text: string };
    revocations?: { octets_text: string }[];
  };
  expected: { binding: { binds_pair: boolean; applies: boolean } };
}
const corpus = JSON.parse(
  readFileSync(
    resolve(
      process.cwd(),
      "..",
      "vectors",
      "controller-binding-v0",
      "vectors.json",
    ),
    "utf8",
  ),
) as { cases: Case[] };

const half = (c: Case, i: number) =>
  decodeStrictJson(c.inputs.halves[i]!.octets_text) as {
    producer: string;
    issued_at: string;
  };
const get = (id: string) => corpus.cases.find((c) => c.id === id)!;

describe("verifyKeyBinding", () => {
  it("is NOT_CHECKED with no cited binding", async () => {
    const c = get("valid-same-controller");
    const r = await verifyKeyBinding(
      half(c, 0).producer,
      parseProfileTime(half(c, 0).issued_at)!,
      [],
    );
    expect(r.status).toBe("NOT_CHECKED");
  });
  it("is NOT_CHECKED when the binding names neither half's key", async () => {
    const c = get("no-half-key-bound");
    const r = await verifyKeyBinding(
      half(c, 0).producer,
      parseProfileTime(half(c, 0).issued_at)!,
      [c.inputs.binding.octets_text],
    );
    expect(r.status).toBe("NOT_CHECKED");
  });
  for (const c of corpus.cases) {
    const key = half(c, 0).producer;
    it(`${c.id}: PASS only when the binding applies, never for a revocation`, async () => {
      const r = await verifyKeyBinding(
        key,
        parseProfileTime(half(c, 0).issued_at)!,
        [c.inputs.binding.octets_text],
        { revocations: (c.inputs.revocations ?? []).map((x) => x.octets_text) },
      );
      if (r.bindings.length === 0) expect(r.status).toBe("NOT_CHECKED");
      else {
        // a binding that names this key applies exactly as the Go and CB §6.2 vectors say
        // when asked at the first half's time (single-time, not the pair's two times)
        expect(r.status).toBe(
          r.bindings.some((b) => b.applies) ? "PASS" : "FAIL",
        );
        if (c.id === "revoked" || c.id === "expired")
          expect(r.status).toBe("FAIL");
        if (c.id === "valid-same-controller") expect(r.status).toBe("PASS");
        expect(r.revocationChecked).toBe(false);
      }
    });
  }
});
