import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  checkPresentationFragment,
  decodeFragmentToken,
  decodePresentationFragment,
  encodeFragmentToken,
  encodePresentationFragment,
  FRAGMENT_TOKEN_MAX_LENGTH,
  FRAGMENT_URL_MAX_LENGTH,
  FragmentDecodeError,
  FragmentTooLargeError,
  PRESENTATION_FRAGMENT_VERSION,
  scopeDisclosures,
  type PresentationFragment,
} from "../src/presentation-fragment.js";

interface Vector {
  readonly name: string;
  readonly ascii_json: boolean;
  readonly fragment_py: string;
  readonly payload: unknown;
}
const vectors = (
  JSON.parse(
    readFileSync(
      resolve(
        import.meta.dirname,
        "testdata",
        "presentation-fragment-vectors.json",
      ),
      "utf8",
    ),
  ) as { cases: Vector[] }
).cases;

const payload = (bundle: unknown = { n: 1 }): PresentationFragment => ({
  fragment_version: PRESENTATION_FRAGMENT_VERSION,
  audience: "counterparty",
  presentation: "auto",
  core_runtime_sha256: "a".repeat(64),
  module_sha256: [],
  bundle,
});

describe("the fragment codec against capsule-viewer's fragment.py", () => {
  it("covers ASCII and non-ASCII cases", () => {
    expect(vectors.filter((v) => v.ascii_json).length).toBeGreaterThan(3);
    expect(vectors.filter((v) => !v.ascii_json).length).toBeGreaterThan(0);
  });

  for (const vector of vectors) {
    it(`${vector.name}: ${vector.ascii_json ? "writes the same token" : "reads fragment.py's token, and fragment.py's escapes are the only difference"}`, () => {
      const token = encodeFragmentToken(vector.payload);
      if (vector.ascii_json) expect(token).toBe(vector.fragment_py);
      else expect(token).not.toBe(vector.fragment_py);
      expect(decodeFragmentToken(vector.fragment_py)).toEqual(vector.payload);
      expect(decodeFragmentToken(`#${token}`)).toEqual(vector.payload);
    });
  }

  it("never pads, and uses only the base64url alphabet", () => {
    for (const vector of vectors)
      expect(encodeFragmentToken(vector.payload)).toMatch(/^[A-Za-z0-9_-]*$/u);
  });

  it("refuses a character outside the alphabet instead of dropping it", () => {
    expect(() => decodeFragmentToken("eyJhIjoiYiJ9=")).toThrow(
      FragmentDecodeError,
    );
    expect(() => decodeFragmentToken("eyJhIjo iYiJ9")).toThrow(
      /outside the base64url alphabet/u,
    );
    expect(() => decodeFragmentToken("bm90IGpzb24")).toThrow(/not UTF-8 JSON/u);
  });
});

describe("size limits", () => {
  it("states the limits", () => {
    expect(FRAGMENT_URL_MAX_LENGTH).toBe(1_048_576);
    expect(FRAGMENT_TOKEN_MAX_LENGTH).toBe(1_048_576 - 2_048);
  });

  it("refuses a payload over the maximum, and never truncates", () => {
    const big = payload({ blob: "x".repeat(FRAGMENT_TOKEN_MAX_LENGTH) });
    let error: unknown;
    try {
      encodePresentationFragment(big);
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(FragmentTooLargeError);
    expect((error as FragmentTooLargeError).maxLength).toBe(
      FRAGMENT_TOKEN_MAX_LENGTH,
    );
    expect((error as Error).message).toMatch(/refused, never truncated/u);
  });

  it("refuses over a caller's lower limit, and a limit above the maximum", () => {
    const small = payload();
    const { fragment } = encodePresentationFragment(small);
    expect(() =>
      encodePresentationFragment(small, { maxLength: fragment.length - 1 }),
    ).toThrow(FragmentTooLargeError);
    expect(
      encodePresentationFragment(small, { maxLength: fragment.length })
        .fragment,
    ).toBe(fragment);
    expect(() =>
      encodePresentationFragment(small, {
        maxLength: FRAGMENT_TOKEN_MAX_LENGTH + 1,
      }),
    ).toThrow(RangeError);
  });

  it("refuses a whole URL over the URL maximum", () => {
    const near = payload({
      blob: "x".repeat(Math.floor((FRAGMENT_TOKEN_MAX_LENGTH * 3) / 4) - 400),
    });
    const { fragment } = encodePresentationFragment(near);
    const viewerUrl = `https://viewer.example/${"p".repeat(FRAGMENT_URL_MAX_LENGTH - fragment.length)}`;
    expect(() => encodePresentationFragment(near, { viewerUrl })).toThrow(
      /permalink URL/u,
    );
    expect(
      encodePresentationFragment(near, {
        viewerUrl: "https://viewer.example/v",
      }).url,
    ).toBe(`https://viewer.example/v#${fragment}`);
    expect(() =>
      encodePresentationFragment(near, { viewerUrl: "https://x.example/#a" }),
    ).toThrow(/already carry a fragment/u);
  });

  it("refuses an over-long token before decoding it", () => {
    expect(() => decodeFragmentToken("A".repeat(9), 8)).toThrow(
      FragmentTooLargeError,
    );
  });
});

describe("the payload", () => {
  it("round-trips", () => {
    const value = {
      ...payload({ a: [1, "é"] }),
      depth: "L1" as const,
      title: "T",
      theme_css: ":root{}",
      wording: { pack: "{}", sha256: "b".repeat(64) },
    };
    const { fragment } = encodePresentationFragment(value);
    expect(decodePresentationFragment(fragment)).toEqual(value);
  });

  it("rejects an unknown member, a wrong version and a bad pin", () => {
    expect(() => checkPresentationFragment({ ...payload(), extra: 1 })).toThrow(
      /unknown member/u,
    );
    expect(() =>
      checkPresentationFragment({ ...payload(), fragment_version: "v1" }),
    ).toThrow(/fragment_version/u);
    expect(() =>
      checkPresentationFragment({ ...payload(), core_runtime_sha256: "A" }),
    ).toThrow(/core_runtime_sha256/u);
    expect(() =>
      checkPresentationFragment({ ...payload(), depth: "L3" }),
    ).toThrow(/depth/u);
    const { bundle: _omit, ...noBundle } = payload();
    expect(() => checkPresentationFragment(noBundle)).toThrow(/bundle/u);
  });
});

describe("scopeDisclosures", () => {
  const bundle = {
    root: "r",
    records: [{ capsule_id: "r" }, { capsule_id: "s" }],
    disclosures: {
      r: { agent_input: { a: 1 }, agent_output: { b: 2 } },
      s: { agent_input: { c: 3 } },
    },
  };

  it("keeps exactly the listed members and removes the rest", () => {
    expect(scopeDisclosures(bundle, { r: ["agent_output"] })).toEqual({
      ...bundle,
      disclosures: { r: { agent_output: { b: 2 } } },
    });
    expect(scopeDisclosures(bundle, {})).toEqual({
      ...bundle,
      disclosures: {},
    });
  });

  it("never adds, and leaves the input untouched", () => {
    const before = JSON.stringify(bundle);
    const scoped = scopeDisclosures(bundle, {
      r: ["agent_input", "agent_output"],
      s: ["agent_input", "agent_output"],
      t: ["agent_input"],
    });
    expect(scoped).toEqual(bundle);
    expect(scoped).not.toBe(bundle);
    expect(JSON.stringify(bundle)).toBe(before);
  });
});
