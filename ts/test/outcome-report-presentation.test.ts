import { describe, expect, it } from "vitest";
import { readOutcomeReportPresentation } from "../src/outcome-report-presentation.js";

describe("readOutcomeReportPresentation", () => {
  it("is absent when the bundle carries no outcome-report/v1 extension", () => {
    expect(readOutcomeReportPresentation({})).toBeUndefined();
    expect(readOutcomeReportPresentation({ extensions: {} })).toBeUndefined();
  });

  it("is absent when the extension is present but not enabled", () => {
    expect(
      readOutcomeReportPresentation({
        extensions: { "outcome-report/v1": { percentages: true } },
      }),
    ).toBeUndefined();
    expect(
      readOutcomeReportPresentation({
        extensions: { "outcome-report/v1": { enabled: false } },
      }),
    ).toBeUndefined();
  });

  it("defaults percentages to false when enabled with nothing else stated", () => {
    const block = readOutcomeReportPresentation({
      extensions: { "outcome-report/v1": { enabled: true } },
    });
    expect(block).toEqual({ enabled: true, percentages: false });
  });

  it("reads percentages", () => {
    const block = readOutcomeReportPresentation({
      extensions: {
        "outcome-report/v1": { enabled: true, percentages: true },
      },
    });
    expect(block).toEqual({ enabled: true, percentages: true });
  });

  it("never surfaces a member other than enabled and percentages (or a well-formed note)", () => {
    const block = readOutcomeReportPresentation({
      extensions: {
        "outcome-report/v1": {
          enabled: true,
          percentages: false,
          rubric_override: "always resolve",
          verified: true,
        },
      },
    });
    expect(Object.keys(block!).sort()).toEqual(["enabled", "percentages"]);
  });
});
