import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { readPresentationBlock } from "../src/presentation.js";
import { derivedFixture } from "./helpers/derived-fixtures.js";

function fixture(name: string): unknown {
  return JSON.parse(
    readFileSync(resolve(process.cwd(), "test", "testdata", name), "utf8"),
  );
}

describe("readPresentationBlock", () => {
  it("reads the producer display name, logo, and title", async () => {
    const bundle = (await derivedFixture("week-bundle-presentation.json")) as {
      extensions: {
        "presentation/v1": {
          producer_display_name: string;
          logo_data_url: string;
          title: string;
        };
      };
    };
    const block = readPresentationBlock(bundle);
    expect(block).toEqual({
      producerDisplayName:
        bundle.extensions["presentation/v1"].producer_display_name,
      logoDataUrl: bundle.extensions["presentation/v1"].logo_data_url,
      title: bundle.extensions["presentation/v1"].title,
    });
  });

  it("is absent when the bundle has no presentation/v1 extension", () => {
    expect(readPresentationBlock(fixture("week-bundle.json"))).toBeUndefined();
  });

  it("never surfaces a member other than the three known fields", () => {
    const bundle = {
      extensions: {
        "presentation/v1": {
          title: "Weekly Report",
          badge: "VERIFIED",
          verified: true,
          check_results_override: ["pass", "pass"],
        },
      },
    };
    const block = readPresentationBlock(bundle);
    expect(block).toEqual({ title: "Weekly Report" });
    expect(Object.keys(block!)).toEqual(["title"]);
  });

  it("rejects a logo that is not a data:image/ URL", () => {
    const bundle = {
      extensions: {
        "presentation/v1": {
          title: "x",
          logo_data_url: "javascript:alert(1)",
        },
      },
    };
    expect(readPresentationBlock(bundle)?.logoDataUrl).toBeUndefined();
  });
});
