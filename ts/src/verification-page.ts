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

/**
 * One supplied record's own standing under the checkpoint, read from the
 * verifier's per-record membership claim and nothing else. `checkpointed`
 * -- bound to the range root by its own inclusion proof, stated only when
 * the claim established coverage (see `CoverageStatement`); `uncheckpointed`
 * -- supplied with no membership entry at all (the verifier's
 * `membership_record_unbound`); `membership_invalid` -- a membership entry
 * was supplied but did not verify (`membership_proof_invalid`,
 * `membership_coordinates_missing`, `membership_coordinates_invalid`,
 * `membership_record_unknown`); `unverified` -- the verifier never reached
 * this record's proof, or stopped on a finding that is not this record's
 * own (no memberships object, a certificate, range-proof or checkpoint
 * failure, a missing or duplicated sequence), so nothing about its standing
 * is established. A record's status is its own: it is never inherited from
 * a neighbour and never summarised away -- and never defaulted to
 * `checkpointed` by the absence of a finding.
 */
export type RecordCoverageStatus =
  | "checkpointed"
  | "uncheckpointed"
  | "membership_invalid"
  | "unverified";

export interface RecordCoverage {
  readonly capsuleId: string;
  readonly status: RecordCoverageStatus;
}

/**
 * Whether the per-record membership claim established each supplied
 * record's standing. `established` -- the claim passed, or failed only
 * because some records are bound to no log position (the accepted
 * relaxation); `not_established` -- the claim failed on at least one
 * finding that is not a clean unbound record, named in `reason`;
 * `withheld` -- the claim was never evaluated (no checkpoint or no
 * certificate), so there is no standing to list at all.
 */
export type CoverageStatement =
  | { readonly status: "established" }
  | { readonly status: "not_established"; readonly reason: string }
  | { readonly status: "withheld"; readonly reason: string };

export interface VerificationPageModel {
  readonly bundleDigest?: string;
  readonly checkpointRoot?: string;
  readonly checkpointSize?: number;
  readonly receipts: readonly ReceiptEntry[];
  /**
   * True when a checkpoint is supplied but no transparency-service receipt
   * is: the checkpoint is at most producer-signed, so the log witnesses
   * only itself.
   */
  readonly selfWitnessed: boolean;
  /** Every supplied record, in bundle order, with its own coverage status. */
  readonly records: readonly RecordCoverage[];
  /** Records with status `uncheckpointed`: unbound and nothing else wrong. */
  readonly uncheckpointedCount: number;
  readonly coverage: CoverageStatement;
  readonly completeness?: CompletenessStatement;
  readonly checks: readonly CheckSummary[];
  readonly verifyIndependentlyLine: string;
}

const UNBOUND = "membership_record_unbound:";
// A membership entry that was supplied but rejected. The verifier emits
// coordinates_* and record_unknown BEFORE it binds the record, so each of
// those also gets a `membership_record_unbound` twin; the rejected entry wins
// over the twin. (`membership_seq_duplicate` is keyed by seq, not capsule_id,
// and cannot be attributed to a record from here.)
const INVALID =
  /^membership_(?:proof_invalid|coordinates_missing|coordinates_invalid|record_unknown):(.+)$/u;

function invalidRecordIds(verified: BundleVerificationResult): Set<string> {
  return new Set(
    verified.perRecordMembership.findings.flatMap((finding) => {
      const match = INVALID.exec(finding);
      return match === null ? [] : [match[1]!];
    }),
  );
}

/**
 * The capsule_ids of supplied records the verifier found bound to no log
 * position -- present in `records`, absent from `memberships`. These are the
 * only per-record membership findings that describe a record's coverage
 * rather than a broken proof: a record whose supplied entry was rejected is
 * not unbound, even though the verifier also emits the unbound finding for
 * it, and is left out here.
 */
export function unboundRecordIds(
  verified: BundleVerificationResult,
): readonly string[] {
  const invalid = invalidRecordIds(verified);
  return verified.perRecordMembership.findings.flatMap((finding) => {
    if (!finding.startsWith(UNBOUND)) return [];
    const id = finding.slice(UNBOUND.length);
    return invalid.has(id) ? [] : [id];
  });
}

/**
 * The claim's findings that are not unbound records, one name each with
 * any `:id` / `:seq` suffix removed, in first-seen order. An unbound twin
 * of a rejected entry is left out: that record is already named by the
 * finding that rejected it.
 */
function nonUnboundFindings(verified: BundleVerificationResult): string[] {
  const names: string[] = [];
  for (const finding of verified.perRecordMembership.findings) {
    if (finding.startsWith(UNBOUND)) continue;
    const name = finding.split(":", 1)[0]!;
    if (!names.includes(name)) names.push(name);
  }
  return names;
}

export function coverageStatement(
  verified: BundleVerificationResult,
): CoverageStatement {
  const claim = verified.perRecordMembership;
  if (claim.status === "withheld")
    return { status: "withheld", reason: claim.findings.join(", ") };
  if (claim.status === "pass") return { status: "established" };
  const reasons = nonUnboundFindings(verified);
  return reasons.length === 0
    ? { status: "established" }
    : { status: "not_established", reason: reasons.join(", ") };
}

function recordCoverage(
  bundle: Record<string, unknown>,
  verified: BundleVerificationResult,
  coverage: CoverageStatement,
): RecordCoverage[] {
  const unbound = new Set(unboundRecordIds(verified));
  const invalid = invalidRecordIds(verified);
  return (Array.isArray(bundle.records) ? bundle.records : []).flatMap(
    (record): RecordCoverage[] => {
      const capsuleId = object(record)?.capsule_id;
      if (typeof capsuleId !== "string") return [];
      return [
        {
          capsuleId,
          status: invalid.has(capsuleId)
            ? "membership_invalid"
            : unbound.has(capsuleId)
              ? "uncheckpointed"
              : coverage.status === "established"
                ? "checkpointed"
                : "unverified",
        },
      ];
    },
  );
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
  const coverage = coverageStatement(verified);
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
    selfWitnessed:
      checkpoint !== undefined && receipts(top.receipts).length === 0,
    records: recordCoverage(top, verified, coverage),
    uncheckpointedCount: unboundRecordIds(verified).length,
    coverage,
    ...(completenessStatement(top.completeness) === undefined
      ? {}
      : { completeness: completenessStatement(top.completeness)! }),
    checks,
    verifyIndependentlyLine: VERIFY_INDEPENDENTLY_LINE,
  };
}
