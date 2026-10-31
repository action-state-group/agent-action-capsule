/**
 * Readers for two judge-family records (spec/judge-record-family-v1.md):
 * `calibration-summary/v1` (section 8, schemas/judge/calibration-summary-v1.json)
 * and `human-rating/v1` (section 5, schemas/judge/human-rating-v1.json).
 *
 * Each reader returns the record only when it matches its schema exactly:
 * every required member present, no other member (each object in both
 * schemas is `additionalProperties: false`), and each value of the type and
 * constant the schema fixes. A record that carries a stored rate, or any
 * other member the schema lacks, does not match and reads as undefined. The
 * calibration summary also has to meet the cross-field rule section 8 puts on
 * a verifier: `k <= n` for every count pair.
 *
 * `format: date-time` is an annotation under JSON Schema 2020-12 (the Python
 * checker in schemas/ attaches no format checker either), so `computed_at` and
 * `rated_at` are read as strings and never parsed here.
 *
 * Nothing here computes a rate or a percentage: a count stays `k` of `n`.
 */

// Local, not imported from evidence-graph.ts, which imports this module.
type ObjectValue = Record<string, unknown>;
const isObject = (value: unknown): value is ObjectValue =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const asString = (value: unknown): string | undefined =>
  typeof value === "string" ? value : undefined;

export const CALIBRATION_SUMMARY_V1 = "calibration-summary/v1";
export const HUMAN_RATING_V1 = "human-rating/v1";

/** A count pair, never a ratio: `k` of `n`, with `0 <= k <= n`. */
export interface KOfN {
  readonly k: number;
  readonly n: number;
}

/** A family citation (section 0) with its `citation_purpose` fixed by the field that holds it. */
export interface JudgeRecordCitation {
  readonly type: string;
  readonly digest: string;
}

export interface CalibrationClauseTally {
  readonly clauseRef: string;
  readonly agreement: KOfN;
  readonly drift: KOfN;
}

/** A `calibration-summary/v1` record as its schema defines it. */
export interface CalibrationSummaryRecord {
  readonly recordId: string;
  readonly computedAt: string;
  /** `judge_pin`, a citation with `citation_purpose: calibrates`. */
  readonly judgePin: JudgeRecordCitation;
  readonly clauses: readonly CalibrationClauseTally[];
}

/** A `human-rating/v1` record as its schema defines it (`blind` is always true). */
export interface HumanRatingRecord {
  readonly recordId: string;
  readonly ratedAt: string;
  /** An opaque principal reference, never a name. */
  readonly raterRef: string;
  /** `case`, a citation with `citation_purpose: rated_case`. */
  readonly ratedCase: JudgeRecordCitation;
  readonly label: string;
}

const HEX_DIGEST = /^[0-9a-f]{64}$/u;

const hasExactly = (
  value: ObjectValue,
  members: readonly string[],
): boolean => {
  const keys = Object.keys(value);
  return (
    keys.length === members.length &&
    members.every((member) => Object.hasOwn(value, member))
  );
};

const nonEmpty = (value: unknown): string | undefined => {
  const text = asString(value);
  return text === undefined || text.length === 0 ? undefined : text;
};

const isCount = (value: unknown): boolean =>
  Number.isSafeInteger(value) && (value as number) >= 0;

/** `KOfN`, plus section 8's `k <= n`. */
const readKOfN = (value: unknown): KOfN | undefined => {
  if (!isObject(value) || !hasExactly(value, ["k", "n"])) return undefined;
  if (!isCount(value.k) || !isCount(value.n)) return undefined;
  const k = value.k as number;
  const n = value.n as number;
  return k <= n ? { k, n } : undefined;
};

const readCitation = (
  value: unknown,
  purpose: string,
): JudgeRecordCitation | undefined => {
  if (
    !isObject(value) ||
    !hasExactly(value, ["type", "digest_alg", "digest", "citation_purpose"])
  )
    return undefined;
  const type = nonEmpty(value.type);
  const digest = asString(value.digest);
  if (
    type === undefined ||
    value.digest_alg !== "SHA-256" ||
    digest === undefined ||
    !HEX_DIGEST.test(digest) ||
    value.citation_purpose !== purpose
  )
    return undefined;
  return { type, digest };
};

const readClause = (value: unknown): CalibrationClauseTally | undefined => {
  if (
    !isObject(value) ||
    !hasExactly(value, ["clause_ref", "agreement", "drift"])
  )
    return undefined;
  const clauseRef = nonEmpty(value.clause_ref);
  const agreement = readKOfN(value.agreement);
  const drift = readKOfN(value.drift);
  if (clauseRef === undefined || agreement === undefined || drift === undefined)
    return undefined;
  return { clauseRef, agreement, drift };
};

/** The record when `value` matches calibration-summary-v1.json and every count has `k <= n`; otherwise undefined. */
export function readCalibrationSummary(
  value: unknown,
): CalibrationSummaryRecord | undefined {
  if (
    !isObject(value) ||
    !hasExactly(value, [
      "record_version",
      "record_id",
      "epistemic_type",
      "computed_at",
      "judge_pin",
      "clauses",
    ]) ||
    value.record_version !== CALIBRATION_SUMMARY_V1 ||
    value.epistemic_type !== "derived_metric"
  )
    return undefined;
  const recordId = nonEmpty(value.record_id);
  const computedAt = asString(value.computed_at);
  const judgePin = readCitation(value.judge_pin, "calibrates");
  if (
    recordId === undefined ||
    computedAt === undefined ||
    judgePin === undefined ||
    !Array.isArray(value.clauses) ||
    value.clauses.length === 0
  )
    return undefined;
  const clauses: CalibrationClauseTally[] = [];
  for (const entry of value.clauses) {
    const clause = readClause(entry);
    if (clause === undefined) return undefined;
    clauses.push(clause);
  }
  return { recordId, computedAt, judgePin, clauses };
}

/** The record when `value` matches human-rating-v1.json; otherwise undefined. */
export function readHumanRating(value: unknown): HumanRatingRecord | undefined {
  if (
    !isObject(value) ||
    !hasExactly(value, [
      "record_version",
      "record_id",
      "epistemic_type",
      "rated_at",
      "blind",
      "rater_ref",
      "case",
      "label",
    ]) ||
    value.record_version !== HUMAN_RATING_V1 ||
    value.epistemic_type !== "human_report" ||
    value.blind !== true
  )
    return undefined;
  const recordId = nonEmpty(value.record_id);
  const ratedAt = asString(value.rated_at);
  const raterRef = nonEmpty(value.rater_ref);
  const ratedCase = readCitation(value.case, "rated_case");
  const label = nonEmpty(value.label);
  if (
    recordId === undefined ||
    ratedAt === undefined ||
    raterRef === undefined ||
    ratedCase === undefined ||
    label === undefined
  )
    return undefined;
  return { recordId, ratedAt, raterRef, ratedCase, label };
}
