import type { BundleVerificationResult } from "./bundle.js";
import type { VerificationResult } from "./verify.js";

export type CheckStatus = "pass" | "withheld" | "fail" | "not_checked";

export interface CheckSummary {
  readonly name: string;
  readonly status: CheckStatus;
  /** Exactly five words -- never "proves"/"certificate"/"tamper-proof"/"first". */
  readonly result: string;
}

/** A receipt's grade WORD, read from the receipt header -- never a client-ladder word. */
export type ReceiptGradeWord = "consistency-verified" | "existence-and-time";

export interface ReceiptEntry {
  readonly witness: string;
  readonly grade: ReceiptGradeWord;
  readonly time: string;
}

export interface CompletenessStatement {
  readonly closureDepth?: number;
  readonly recordsMode?: string;
  readonly payloadsMode?: string;
  readonly suppressedFields: readonly string[];
}

export interface VerificationPageModel {
  readonly bundleDigest?: string;
  readonly checkpointRoot?: string;
  readonly checkpointSize?: number;
  readonly receipts: readonly ReceiptEntry[];
  readonly completeness?: CompletenessStatement;
  readonly checks: readonly CheckSummary[];
  readonly verifyIndependentlyLine: string;
}

export const VERIFY_INDEPENDENTLY_LINE =
  "verify independently at verify.agentactioncapsule.org or with the CLI";

const FIVE_WORD_RESULT: Readonly<Record<CheckStatus, string>> = Object.freeze({
  pass: "passed with no errors found",
  withheld: "still withheld pending producer disclosure",
  fail: "failed at least one check",
  not_checked: "not checked no evidence supplied",
});

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function capsuleGroupStatus(
  capsuleResults: Readonly<Record<string, VerificationResult>>,
  checks: readonly number[],
): CheckStatus {
  const results = Object.values(capsuleResults);
  if (results.length === 0) return "not_checked";
  const failed = results.some((result) =>
    result.findings.some(
      (finding) =>
        finding.severity === "error" &&
        finding.check !== undefined &&
        checks.includes(finding.check),
    ),
  );
  return failed ? "fail" : "pass";
}

function receiptGradeWord(value: unknown): ReceiptGradeWord | undefined {
  return value === "mmr-verified"
    ? "consistency-verified"
    : value === "countersigned-observed"
      ? "existence-and-time"
      : undefined;
}

function receipts(raw: unknown): ReceiptEntry[] {
  if (!Array.isArray(raw)) return [];
  return raw.flatMap((entry): ReceiptEntry[] => {
    const record = object(entry);
    if (record === undefined) return [];
    const witness = record.witness,
      time = record.time,
      grade = receiptGradeWord(record.grade);
    return typeof witness === "string" &&
      typeof time === "string" &&
      grade !== undefined
      ? [{ witness, grade, time }]
      : [];
  });
}

function completenessStatement(
  raw: unknown,
): CompletenessStatement | undefined {
  const record = object(raw);
  if (record === undefined) return undefined;
  return {
    ...(typeof record.closure_depth === "number"
      ? { closureDepth: record.closure_depth }
      : {}),
    ...(typeof record.records_mode === "string"
      ? { recordsMode: record.records_mode }
      : {}),
    ...(typeof record.payloads_mode === "string"
      ? { payloadsMode: record.payloads_mode }
      : {}),
    suppressedFields: Array.isArray(record.suppressed_fields)
      ? record.suppressed_fields.filter(
          (field): field is string => typeof field === "string",
        )
      : [],
  };
}

function summarize(name: string, status: CheckStatus): CheckSummary {
  return { name, status, result: FIVE_WORD_RESULT[status] };
}

/**
 * Build the viewer-owned verification page model from VERIFIED data only:
 * the already-computed BundleVerificationResult (never bundle-supplied
 * markup). Ten named checks: six aggregate the base-profile Capsule checks
 * (numbered 1-8 by verifyClass1) into six groups; four are Bundle-level
 * claims already computed independently by verifyBundle.
 */
export function buildVerificationPageModel(
  bundle: unknown,
  verified: BundleVerificationResult,
): VerificationPageModel {
  const top = object(bundle) ?? {};
  const checkpoint = object(top.checkpoint);
  const checks: CheckSummary[] = [
    summarize(
      "Required fields",
      capsuleGroupStatus(verified.capsuleResults, [1]),
    ),
    summarize(
      "Capsule identity",
      capsuleGroupStatus(verified.capsuleResults, [2]),
    ),
    summarize(
      "Effect consistency",
      capsuleGroupStatus(verified.capsuleResults, [3, 5]),
    ),
    summarize(
      "Verdict conflict",
      capsuleGroupStatus(verified.capsuleResults, [4]),
    ),
    summarize("Chain parent", capsuleGroupStatus(verified.capsuleResults, [6])),
    summarize(
      "Assurance claims",
      capsuleGroupStatus(verified.capsuleResults, [7, 8]),
    ),
    summarize(
      "Bundle digest",
      verified.bundleDigest === undefined ? "fail" : "pass",
    ),
    summarize("Graph closure", verified.graphClosure.status),
    summarize("Interval coverage", verified.intervalCoverage.status),
    summarize("Per-record membership", verified.perRecordMembership.status),
  ];
  return {
    ...(verified.bundleDigest === undefined
      ? {}
      : { bundleDigest: verified.bundleDigest }),
    ...(typeof checkpoint?.root === "string"
      ? { checkpointRoot: checkpoint.root }
      : {}),
    ...(typeof checkpoint?.mmr_size === "number"
      ? { checkpointSize: checkpoint.mmr_size }
      : {}),
    receipts: receipts(top.receipts),
    ...(completenessStatement(top.completeness) === undefined
      ? {}
      : { completeness: completenessStatement(top.completeness)! }),
    checks,
    verifyIndependentlyLine: VERIFY_INDEPENDENTLY_LINE,
  };
}
