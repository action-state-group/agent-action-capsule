// Salted JSON-DIGEST commitment vectors (vectors/salted-digest-commitment/, informative) —
// TypeScript parity with python/tests/test_salted_digest_commitment_vectors.py. Every opening's
// JCS string and JSON-DIGEST are recomputed here; positives open their commitment, negatives do
// not open the commitment of the positive they name.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { jcs, jsonDigest } from "../src/json.js";

interface SaltedCase {
  id: string;
  against?: string;
  opening: { nonce: string; text: string };
  opening_jcs: string;
  commitment: string;
  recomputed?: string;
}

const vectors = JSON.parse(
  readFileSync(
    resolve(
      import.meta.dirname,
      "..",
      "..",
      "vectors",
      "salted-digest-commitment",
      "vectors.json",
    ),
    "utf8",
  ),
) as {
  positive: SaltedCase[];
  negative: SaltedCase[];
  equality: { nonce: string; text: string; first: string };
};

const jcsText = (value: unknown): string =>
  new TextDecoder().decode(jcs(value));
const positive = new Map(vectors.positive.map((c) => [c.id, c.commitment]));

describe("salted JSON-DIGEST commitment vectors", () => {
  it("has three positives and five negatives", () => {
    expect(vectors.positive).toHaveLength(3);
    expect(vectors.negative).toHaveLength(5);
  });
  for (const c of vectors.positive) {
    it(c.id, async () => {
      expect(jcsText(c.opening)).toBe(c.opening_jcs);
      expect(await jsonDigest(c.opening)).toBe(c.commitment);
    });
  }
  for (const c of vectors.negative) {
    it(c.id, async () => {
      const recomputed = await jsonDigest(c.opening);
      expect(jcsText(c.opening)).toBe(c.opening_jcs);
      expect(recomputed).toBe(c.recomputed);
      expect(c.commitment).toBe(positive.get(c.against ?? ""));
      expect(recomputed).not.toBe(c.commitment);
    });
  }
  it("equality-same-nonce-same-text", async () => {
    const { nonce, text, first } = vectors.equality;
    expect(await jsonDigest({ nonce, text })).toBe(first);
  });
});
