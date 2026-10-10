import type {
  BundleVerificationResult,
  ExtensionInterpreterId,
  ExtensionResult,
} from "./bundle.js";
import {
  presentationRefusalLine,
  presentationRefusalRow,
  type PresentationRefusal,
  type PresentationRefusalReason,
} from "./presentation-registry.js";
import type { CountersignatureStamp } from "./countersignature-stamp.js";
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

/**
 * How the verification page shows a receipt's grade. This runtime does not
 * check witness receipts, so the shown text says the grade is the receipt's
 * claim and never calls it verified. The grade word itself is unchanged.
 */
export const RECEIPT_GRADE_DISPLAY: Readonly<Record<ReceiptGradeWord, string>> =
  Object.freeze({
    "consistency-verified": "consistency claimed (not checked here)",
    "existence-and-time": "existence and time claimed (not checked here)",
  });

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

/**
 * The semantics cell of an uninterpreted extension whose block the bundle
 * digest covers. Exact user-facing wording: covered bytes are not understood
 * bytes, and this line never lets the first read as the second.
 */
export const EXTENSION_NOT_INTERPRETED =
  "Integrity verified; meaning not interpreted by this viewer";
/**
 * The same cell when the bundle digest could not be computed: nothing about
 * the block's bytes was verified either, so the line must not claim it.
 */
export const EXTENSION_NOT_INTERPRETED_NOT_COVERED =
  "Integrity not verified; meaning not interpreted by this viewer";

/**
 * One row per `extensions` member, in kind order: its id, whether the bundle
 * digest covers it, and who (if anyone) applied its meaning. `interpreter`
 * is set only for a block this rendering actually interpreted.
 */
export interface ExtensionRow {
  readonly id: string;
  readonly integrity: "covered" | "not covered";
  readonly interpreter?: ExtensionInterpreterId;
  /**
   * Set when a presentation module that requires this extension matched and
   * this runtime refused it (presentation contract section 3.2). It takes
   * precedence over `interpreter`: the refused module never ran.
   */
  readonly refusal?: PresentationRefusal;
  /**
   * "interpreted by <interpreter>", one of the two not-interpreted lines, or
   * the refusal wording of section 3.2 (`presentationRefusalRow`).
   */
  readonly semantics: string;
}

/**
 * A refused presentation module that requires no extension, so has no row
 * of its own: the verification page shows `line` after the extension rows
 * (presentation contract section 3.2).
 */
export interface PresentationRefusalNotice {
  readonly id: string;
  readonly reason: PresentationRefusalReason;
  /** `presentationRefusalLine`, exactly. */
  readonly line: string;
}

/**
 * The verification page's extension rows. `applied`, when given, is the set
 * of interpreters this rendering actually ran: an extension the library can
 * interpret but whose module did not render (an outcome-report/v1 block on a
 * root that is not a Result, say) is shown as not interpreted, because here
 * its meaning was not applied. Omitted, the verifier's status stands.
 */
export function extensionRows(
  extensions: readonly ExtensionResult[],
  applied?: ReadonlySet<ExtensionInterpreterId>,
  refused: readonly PresentationRefusal[] = [],
): readonly ExtensionRow[] {
  return extensions.map((extension): ExtensionRow => {
    const integrity = extension.integrityCovered ? "covered" : "not covered";
    // The first refused module (in resolution order) that requires this
    // kind names the row; the refusal outranks any interpreter.
    const refusal = refused.find((r) => r.extensions.includes(extension.kind));
    if (refusal !== undefined)
      return {
        id: extension.kind,
        integrity,
        refusal,
        semantics: presentationRefusalRow(refusal, extension.integrityCovered),
      };
    if (
      extension.status === "interpreted" &&
      (applied === undefined || applied.has(extension.interpreter))
    )
      return {
        id: extension.kind,
        integrity,
        interpreter: extension.interpreter,
        semantics: `interpreted by ${extension.interpreter}`,
      };
    return {
      id: extension.kind,
      integrity,
      semantics: extension.integrityCovered
        ? EXTENSION_NOT_INTERPRETED
        : EXTENSION_NOT_INTERPRETED_NOT_COVERED,
    };
  });
}

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
  /** One row per supplied extension (empty when the bundle carries none). */
  readonly extensions: readonly ExtensionRow[];
  /**
   * One per refused presentation module that requires no extension, in
   * resolution order; empty when nothing was refused.
   */
  readonly presentationRefusals: readonly PresentationRefusalNotice[];
  /** Which checks this page ran, which failed, and which it did not run. */
  readonly checkLists: VerificationCheckLists;
  readonly verifyIndependentlyLine: string;
}

/** The refused modules that have no extension row (section 3.2). */
export function presentationRefusalNotices(
  refused: readonly PresentationRefusal[],
): readonly PresentationRefusalNotice[] {
  return refused
    .filter((refusal) => refusal.extensions.length === 0)
    .map((refusal) => ({
      id: refusal.id,
      reason: refusal.reason,
      line: presentationRefusalLine(refusal),
    }));
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

/**
 * The checks the verification page names in its derived lists (presentation
 * contract section 6.1), in the order the lists draw them.
 *
 * - `record-digests`: each record's capsule ID recomputed from its contents
 *   (Class 1 check 2);
 * - `record-rules`: the other Class 1 checks on each record (required
 *   fields, effects, verdict, chain parent, assurance claims);
 * - `closure`: the graph closure from the root to the stated depth;
 * - `range`: the completeness certificate's range over the log;
 * - `membership`: each record's inclusion at its log position;
 * - `checkpoint-signature`: the COSE signature on the log's checkpoint;
 * - `disclosures`: each disclosed value against its committed digest;
 * - `countersignatures`: each countersign/v1 signature over the bundle digest;
 * - `composed`: a composed/v1 block, its member bundles and its digest;
 * - `cited-signers`: the producer signature on the records a page module
 *   cites as signers (a Close and the records that link to it);
 * - `producer-signatures`: the producer signature on every record;
 * - `witness-receipts`: the witness receipts the bundle carries;
 * - `countersignature-types`: a countersignature of a type this runtime does
 *   not check;
 * - `countersignature-receipts`: a receipt carried with a countersignature.
 */
export const VERIFICATION_CHECK_IDS = Object.freeze([
  "record-digests",
  "record-rules",
  "closure",
  "range",
  "membership",
  "checkpoint-signature",
  "disclosures",
  "countersignatures",
  "composed",
  "cited-signers",
  "producer-signatures",
  "witness-receipts",
  "countersignature-types",
  "countersignature-receipts",
] as const);
export type VerificationCheckId = (typeof VERIFICATION_CHECK_IDS)[number];

/**
 * The page's own checks, split by what happened to each here. Every entry is
 * read from this runtime's verification result, its countersignature
 * classification and what its page module checked; none is read from a claim
 * in the bundle. `page`: the check ran here and passed. `failed`: it ran here
 * and did not pass, so it is never listed as checked. `notChecked`: the
 * bundle carries what the check needs, and this runtime does not run it or
 * could not complete it.
 */
export interface VerificationCheckLists {
  readonly page: readonly VerificationCheckId[];
  readonly failed: readonly VerificationCheckId[];
  readonly notChecked: readonly VerificationCheckId[];
  /**
   * True when the checkpoint signature is not checked although the claims
   * that rest on it passed (the verifier recorded `checkpoint_unverified`).
   */
  readonly passedWithoutCheckpoint: boolean;
}

/** What else this runtime checked, beyond the verification result. */
export interface CheckListInputs {
  /** The countersignature classification the page draws. */
  readonly stamps?: readonly CountersignatureStamp[];
  /** True when the rendered page module checked the signers it cites. */
  readonly citedSigners?: boolean;
}

export const CHECKED_ON_THIS_PAGE = "Checked on this page";
export const FAILED_ON_THIS_PAGE = "Failed on this page";
export const NOT_CHECKED_ON_THIS_PAGE = "Not checked on this page";
/** Drawn after the not-checked list; it names no product or command. */
export const FULL_VERIFIER_LINE =
  "To run these checks, verify the bundle with a full verifier.";
/** Drawn after the lists, whatever they hold. */
export const CHECKS_SCOPE_LINE =
  "None of these checks says who produced the records, or that this file is the most recent copy.";

/**
 * One line per check, worded so it reads true under each heading: it names
 * what was checked, never the outcome. A check this page did not run is
 * never called verified.
 */
export const VERIFICATION_CHECK_WORDS: Readonly<
  Record<VerificationCheckId, string>
> = Object.freeze({
  "record-digests":
    "Each record's contents against the capsule ID it was sealed with.",
  "record-rules":
    "Each record's required fields, effects, verdict, chain parent and assurance claims.",
  closure:
    "That every record the root cites, to the stated depth, is in this file or listed as missing.",
  range:
    "That no record is missing from the stretch of the log this file covers.",
  membership: "That each record bound to a log position sits at that position.",
  "checkpoint-signature": "The signature on the log's checkpoint.",
  disclosures:
    "Each disclosed value against the digest its record committed to.",
  countersignatures:
    "Each countersignature's signature, over this bundle's digest, under the key it names.",
  composed:
    "Each bundle this file composes, and the digest over the composition.",
  "cited-signers":
    "The producer signature on the records this page cites as signers, each marked beside it as verified or not. Not the signature on every record.",
  "producer-signatures": "The producer signature on every record.",
  "witness-receipts": "Each witness receipt this file carries.",
  "countersignature-types":
    "A countersignature of a type this page does not check.",
  "countersignature-receipts": "The receipt carried with a countersignature.",
});

/** Added to the checkpoint line when the page passed the bundle without it. */
export const CHECKPOINT_NOT_CHECKED_NOTE =
  "This page could not check it, and shows the bundle as passing without it.";

/** The words a list item shows for `id` under `list`. */
export function verificationCheckWords(
  id: VerificationCheckId,
  list: keyof Omit<VerificationCheckLists, "passedWithoutCheckpoint">,
  lists: VerificationCheckLists,
): string {
  const words = VERIFICATION_CHECK_WORDS[id];
  return id === "checkpoint-signature" &&
    list === "notChecked" &&
    lists.passedWithoutCheckpoint
    ? `${words} ${CHECKPOINT_NOT_CHECKED_NOTE}`
    : words;
}

// Findings that say the completeness evaluation stopped before it reached
// the checkpoint signature, so neither it nor the memberships ran.
const STOPPED_BEFORE_CHECKPOINT = new Set([
  "bundle_malformed",
  "completeness_certificate_invalid",
  "range_proof_invalid",
]);

/**
 * Derive the page's check lists from its own results. Nothing here reads a
 * bundle claim as a result: the bundle is read only for what it carries
 * (a checkpoint signature, record signatures, witness receipts), which
 * decides whether a check is called for at all.
 */
export function verificationCheckLists(
  bundle: unknown,
  verified: BundleVerificationResult,
  inputs: CheckListInputs = {},
): VerificationCheckLists {
  const top = object(bundle) ?? {};
  const outcome = new Map<
    VerificationCheckId,
    "page" | "failed" | "notChecked"
  >();
  const ran = (id: VerificationCheckId, passed: boolean): void => {
    outcome.set(id, passed ? "page" : "failed");
  };

  // Class 1, per record.
  if (Object.keys(verified.capsuleResults).length > 0) {
    ran(
      "record-digests",
      capsuleGroupStatus(verified.capsuleResults, [2]) === "pass",
    );
    ran(
      "record-rules",
      capsuleGroupStatus(verified.capsuleResults, [1, 3, 4, 5, 6, 7, 8]) ===
        "pass",
    );
  }
  // The graph closure always runs; a declared-incomplete bundle passes it
  // with its missing records listed.
  ran("closure", verified.graphClosure.status !== "fail");

  // Range, membership and the checkpoint signature run only when the bundle
  // carries a completeness certificate and a checkpoint.
  const range = verified.intervalCoverage;
  const signed =
    typeof object(top.checkpoint)?.cose === "string" &&
    object(top.checkpoint)!.cose !== "";
  let passedWithoutCheckpoint = false;
  if (range.status !== "withheld") {
    const stopped = range.findings.some((f) =>
      STOPPED_BEFORE_CHECKPOINT.has(f),
    );
    const checkpointInvalid = range.findings.includes(
      "checkpoint_authentication_invalid",
    );
    ran("range", !stopped || range.status === "pass");
    if (stopped || checkpointInvalid) {
      outcome.set("membership", "notChecked");
    } else {
      ran("membership", coverageStatement(verified).status === "established");
    }
    if (checkpointInvalid) outcome.set("checkpoint-signature", "failed");
    else if (signed) {
      const unchecked = [range, verified.perRecordMembership].some((claim) =>
        claim.findings.includes("checkpoint_unverified"),
      );
      if (stopped || unchecked) {
        outcome.set("checkpoint-signature", "notChecked");
        passedWithoutCheckpoint = !stopped && range.status === "pass";
      } else outcome.set("checkpoint-signature", "page");
    }
  }

  const disclosed = verified.disclosures.filter((d) => d.status !== "withheld");
  if (disclosed.length > 0)
    ran(
      "disclosures",
      disclosed.every((d) => d.status === "disclosure_match"),
    );

  const stamps = inputs.stamps ?? [];
  const signedStamps = stamps.filter(
    (s) =>
      s.kind === "resolved" ||
      s.kind === "not-independent" ||
      s.kind === "unresolved-signer",
  );
  const invalidStamps = stamps.filter((s) => s.kind === "invalid");
  if (signedStamps.length + invalidStamps.length > 0)
    ran("countersignatures", invalidStamps.length === 0);

  const composed = verified.extensions.flatMap((e) =>
    e.composed === undefined ? [] : [e.composed],
  );
  if (composed.some((c) => c.status === "fail")) ran("composed", false);
  else if (composed.some((c) => c.status === "withheld"))
    outcome.set("composed", "notChecked");
  else if (composed.length > 0) ran("composed", true);

  if (inputs.citedSigners === true) ran("cited-signers", true);

  // Called for by what the bundle carries; this runtime does not run them.
  if (
    Array.isArray(top.records) &&
    top.records.some(
      (record) =>
        typeof object(record)?.signature === "string" &&
        object(record)!.signature !== "",
    )
  )
    outcome.set("producer-signatures", "notChecked");
  if (Array.isArray(top.receipts) && top.receipts.length > 0)
    outcome.set("witness-receipts", "notChecked");
  if (stamps.some((s) => s.kind === "unverified"))
    outcome.set("countersignature-types", "notChecked");
  if (
    signedStamps.some(
      (s) => "statement" in s && s.statement.receipt === "unverified",
    )
  )
    outcome.set("countersignature-receipts", "notChecked");

  const pick = (which: "page" | "failed" | "notChecked") =>
    VERIFICATION_CHECK_IDS.filter((id) => outcome.get(id) === which);
  return {
    page: pick("page"),
    failed: pick("failed"),
    notChecked: pick("notChecked"),
    passedWithoutCheckpoint,
  };
}

export const VERIFY_INDEPENDENTLY_LINE =
  "verify independently at verify.agentactioncapsule.org or with a full verifier";

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
  appliedInterpreters?: ReadonlySet<ExtensionInterpreterId>,
  refused: readonly PresentationRefusal[] = [],
  checkInputs: CheckListInputs = {},
): VerificationPageModel {
  const top = object(bundle) ?? {};
  const checkpoint = object(top.checkpoint);
  const checks: CheckSummary[] = [
    summarize(
      "Required fields",
      capsuleGroupStatus(verified.capsuleResults, [1]),
    ),
    summarize(
      "Capsule ID matches contents",
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
    extensions: extensionRows(
      verified.extensions,
      appliedInterpreters,
      refused,
    ),
    presentationRefusals: presentationRefusalNotices(refused),
    checkLists: verificationCheckLists(bundle, verified, checkInputs),
    verifyIndependentlyLine: VERIFY_INDEPENDENTLY_LINE,
  };
}
