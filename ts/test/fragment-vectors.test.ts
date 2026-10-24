// The Evidence Bundle permalink codec (bundle.ts encodeFragment and
// decodeFragment) against vectors/bundle/fragment/, which
// go/bundle/fragment_vectors_test.go also runs: an ASCII payload encodes to
// the recorded token, a non-ASCII one to a different token (the recorded
// encoder escapes where this writes UTF-8), and every recorded token decodes
// to its payload.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { decodeFragment, encodeFragment } from "../src/bundle.js";

interface Vector {
  readonly name: string;
  readonly ascii_json: boolean;
  readonly fragment_py: string;
  readonly payload: unknown;
}

const DIR = resolve(
  import.meta.dirname,
  "..",
  "..",
  "vectors",
  "bundle",
  "fragment",
);
const raw = readFileSync(resolve(DIR, "vectors.json"));
const vectors = (JSON.parse(raw.toString("utf8")) as { cases: Vector[] }).cases;

describe("vectors/bundle/fragment", () => {
  it("covers ASCII and non-ASCII cases, as its manifest counts", () => {
    expect(vectors.filter((v) => v.ascii_json).length).toBeGreaterThan(3);
    expect(vectors.filter((v) => !v.ascii_json).length).toBeGreaterThan(0);
    const manifest = JSON.parse(
      readFileSync(resolve(DIR, "manifest.json"), "utf8"),
    ) as { case_count: number; files: Record<string, { sha256: string }> };
    expect(manifest.case_count).toBe(vectors.length);
    expect(manifest.files["vectors.json"]?.sha256).toBe(
      createHash("sha256").update(raw).digest("hex"),
    );
  });

  for (const vector of vectors) {
    it(`${vector.name}: ${vector.ascii_json ? "writes the recorded token" : "reads the recorded token, whose escapes are the only difference"}`, () => {
      const token = encodeFragment(vector.payload);
      if (vector.ascii_json) expect(token).toBe(vector.fragment_py);
      else expect(token).not.toBe(vector.fragment_py);
      expect(decodeFragment(vector.fragment_py)).toEqual(vector.payload);
      expect(decodeFragment(token)).toEqual(vector.payload);
    });
  }
});
