import { expect, it } from "vitest";
import { readCompliancePresentation } from "../src/compliance-presentation.js";
import { NOT_STATED } from "../src/outcome-report.js";

function bundle(block: unknown): unknown {
  return { extensions: { "eu-ai-act-compliance/v1": block } };
}

const MINIMAL_OBLIGATION = {
  key: "art5",
  article: "Art 5(1)(a)",
  title: "No manipulative or deceptive techniques",
  plain: "Plain text.",
  applicability: { status: "in_force", note: "In force since 2 Feb 2025" },
  method: "Method text.",
  rows: [
    {
      criterion_id: "art5.no_manipulation_or_deception",
      name: "No manipulative or deceptive technique",
      desc: "Desc.",
      tier: "judged",
    },
  ],
};

it("absent extension reads as undefined", () => {
  expect(readCompliancePresentation({})).toBeUndefined();
});

it("enabled: false reads as undefined, same as absent", () => {
  expect(
    readCompliancePresentation(
      bundle({ enabled: false, obligations: [MINIMAL_OBLIGATION] }),
    ),
  ).toBeUndefined();
});

it("enabled but zero recognizable obligations reads as undefined", () => {
  expect(
    readCompliancePresentation(bundle({ enabled: true, obligations: [] })),
  ).toBeUndefined();
  expect(
    readCompliancePresentation(
      bundle({ enabled: true, obligations: [{ key: "x" }] }),
    ),
  ).toBeUndefined();
});

it("a well-formed block with no regulation field reads it as NOT_STATED, never a filled-in guess", () => {
  // Absent is never pass: the bundle itself never asserted this card's
  // regulation, so it is reported as not stated rather than silently
  // defaulted to the EU AI Act citation this card happens to be about today.
  const presentation = readCompliancePresentation(
    bundle({ enabled: true, obligations: [MINIMAL_OBLIGATION] }),
  )!;
  expect(presentation.enabled).toBe(true);
  expect(presentation.regulation).toBe(NOT_STATED);
  expect(presentation.obligations).toHaveLength(1);
  expect(presentation.obligations[0]!.rows[0]!.criterionId).toBe(
    "art5.no_manipulation_or_deception",
  );
});

it("an explicit regulation string is read as stated", () => {
  const presentation = readCompliancePresentation(
    bundle({
      enabled: true,
      regulation: "Custom Regulation",
      obligations: [MINIMAL_OBLIGATION],
    }),
  )!;
  expect(presentation.regulation).toBe("Custom Regulation");
});

it("a malformed obligation (missing article) is dropped, not fatal -- the pack compiler is the real gate", () => {
  const malformed = { ...MINIMAL_OBLIGATION, article: undefined };
  const presentation = readCompliancePresentation(
    bundle({
      enabled: true,
      obligations: [malformed, { ...MINIMAL_OBLIGATION, key: "art50" }],
    }),
  )!;
  expect(presentation.obligations).toHaveLength(1);
  expect(presentation.obligations[0]!.key).toBe("art50");
});

it("a row with no finding block carries none -- never fabricated", () => {
  const presentation = readCompliancePresentation(
    bundle({ enabled: true, obligations: [MINIMAL_OBLIGATION] }),
  )!;
  expect(presentation.obligations[0]!.rows[0]!.finding).toBeUndefined();
});

it("a row's finding block parses when complete", () => {
  const withFinding = {
    ...MINIMAL_OBLIGATION,
    rows: [
      {
        ...MINIMAL_OBLIGATION.rows[0],
        finding: {
          id: "F-01",
          severity: "Medium",
          recommendation: "Do the thing.",
          owner_due: "Owner · 1 Jan 2027",
        },
      },
    ],
  };
  const presentation = readCompliancePresentation(
    bundle({ enabled: true, obligations: [withFinding] }),
  )!;
  const finding = presentation.obligations[0]!.rows[0]!.finding!;
  expect(finding).toEqual({
    id: "F-01",
    severity: "Medium",
    recommendation: "Do the thing.",
    ownerDue: "Owner · 1 Jan 2027",
  });
});

it("a malformed finding block (missing a required field) drops the finding, not the row", () => {
  const withBadFinding = {
    ...MINIMAL_OBLIGATION,
    rows: [{ ...MINIMAL_OBLIGATION.rows[0], finding: { id: "F-01" } }],
  };
  const presentation = readCompliancePresentation(
    bundle({ enabled: true, obligations: [withBadFinding] }),
  )!;
  expect(presentation.obligations[0]!.rows).toHaveLength(1);
  expect(presentation.obligations[0]!.rows[0]!.finding).toBeUndefined();
});

it("quality_protocol is optional and parses when present", () => {
  const withQuality = readCompliancePresentation(
    bundle({
      enabled: true,
      obligations: [MINIMAL_OBLIGATION],
      quality_protocol: {
        protocol: "blind-v2",
        cadence: "weekly",
        note: "a note",
      },
    }),
  )!;
  expect(withQuality.qualityProtocol).toEqual({
    protocol: "blind-v2",
    cadence: "weekly",
    note: "a note",
  });
  const without = readCompliancePresentation(
    bundle({ enabled: true, obligations: [MINIMAL_OBLIGATION] }),
  )!;
  expect(without.qualityProtocol).toBeUndefined();
});
