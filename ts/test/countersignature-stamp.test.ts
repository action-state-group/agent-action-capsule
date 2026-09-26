import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { classifyCountersignatures } from "../src/countersignature-stamp.js";
import { bundleDigest } from "../src/bundle.js";
import {
  countersignerDirectory,
  derivedFixture,
} from "./helpers/derived-fixtures.js";

function fixture(name: string): Record<string, unknown> {
  return JSON.parse(
    readFileSync(resolve(process.cwd(), "test", "testdata", name), "utf8"),
  ) as Record<string, unknown>;
}

const directory = fixture("countersigner-directory.json") as unknown as Array<{
  publicKey: string;
  name: string;
  logoDataUrl: string;
  checksRecomputed: number;
}>;

describe("classifyCountersignatures", () => {
  it("keeps the committed directory in step with the derived fixtures' signer", () => {
    expect(directory).toEqual(countersignerDirectory());
  });

  it("renders the hollow default when countersignatures[] is absent", async () => {
    const bundle = fixture("week-bundle.json");
    expect(bundle.countersignatures).toBeUndefined();
    const digest = await bundleDigest(bundle);
    expect(await classifyCountersignatures([], digest, undefined, [])).toEqual([
      { kind: "hollow" },
    ]);
  });

  it("renders the hollow default when countersignatures[] is an empty array", async () => {
    const bundle = await derivedFixture(
      "week-bundle-empty-countersignatures.json",
    );
    expect(bundle.countersignatures).toEqual([]);
    const digest = await bundleDigest(bundle);
    expect(
      await classifyCountersignatures(
        bundle.countersignatures as unknown[],
        digest,
        undefined,
        [],
      ),
    ).toEqual([{ kind: "hollow" }]);
  });

  it("classifies the producer's own key as not independent", async () => {
    const bundle = await derivedFixture(
      "week-bundle-producer-countersigned.json",
    );
    const digest = await bundleDigest(bundle);
    const producerKey = (
      bundle.extensions as { "producer-key/v1": { public_key: string } }
    )["producer-key/v1"].public_key;
    const result = await classifyCountersignatures(
      bundle.countersignatures as unknown[],
      digest,
      producerKey,
      directory,
    );
    expect(result).toEqual([{ kind: "producer" }]);
  });

  it("resolves a directory signer with name, logo, and checks recomputed", async () => {
    const bundle = await derivedFixture(
      "week-bundle-directory-countersigned.json",
    );
    const digest = await bundleDigest(bundle);
    const result = await classifyCountersignatures(
      bundle.countersignatures as unknown[],
      digest,
      undefined,
      directory,
    );
    expect(result).toEqual([
      {
        kind: "directory",
        name: "Example Countersigners Ltd",
        logoDataUrl: directory[0]!.logoDataUrl,
        checksRecomputed: 7,
        date: "2026-09-12T00:00:00Z",
      },
    ]);
  });

  it("never takes the directory logo from the bundle itself", async () => {
    const bundle = await derivedFixture(
      "week-bundle-directory-countersigned.json",
    );
    const digest = await bundleDigest(bundle);
    const spoofedLogo = "data:image/png;base64,spoofed-by-bundle";
    const spoofedDirectory = [{ ...directory[0]!, logoDataUrl: spoofedLogo }];
    const result = await classifyCountersignatures(
      bundle.countersignatures as unknown[],
      digest,
      undefined,
      spoofedDirectory,
    );
    expect(result[0]).toMatchObject({ logoDataUrl: spoofedLogo });
    // The bundle carries no logo of its own for this record; only the
    // caller-supplied directory can ever produce a logo here.
    expect(JSON.stringify(bundle)).not.toContain(spoofedLogo);
  });

  it("classifies a verified signer that is neither producer nor directory as unresolved", async () => {
    const bundle = await derivedFixture(
      "week-bundle-unresolved-countersigned.json",
    );
    const digest = await bundleDigest(bundle);
    const result = await classifyCountersignatures(
      bundle.countersignatures as unknown[],
      digest,
      undefined,
      directory,
    );
    expect(result).toEqual([{ kind: "unresolved" }]);
  });

  it("classifies a malformed entry as invalid, never as hollow", async () => {
    const digest = await bundleDigest(fixture("week-bundle.json"));
    const result = await classifyCountersignatures(
      [{ type: "cose-sign1", signature: "not-base64url-cose" }],
      digest,
      undefined,
      directory,
    );
    expect(result).toEqual([{ kind: "invalid" }]);
  });

  it("fails every entry when the bundle digest itself is uncomputable", async () => {
    const result = await classifyCountersignatures(
      [{ type: "cose-sign1", signature: "AAAA" }],
      undefined,
      undefined,
      directory,
    );
    expect(result).toEqual([{ kind: "invalid" }]);
  });

  it("catches a countersignature over a tampered (wholesale-edited) bundle", async () => {
    const bundle = await derivedFixture(
      "week-bundle-directory-countersigned.json",
    );
    const originalDigest = await bundleDigest(bundle);
    const tampered: Record<string, unknown> = {
      ...bundle,
      root: `${(bundle.root as string).slice(0, -1)}0`,
    };
    const tamperedDigest = await bundleDigest(tampered);
    expect(tamperedDigest).not.toBe(originalDigest);
    const result = await classifyCountersignatures(
      tampered.countersignatures as unknown[],
      tamperedDigest,
      undefined,
      directory,
    );
    expect(result).toEqual([{ kind: "invalid" }]);
  });
});
