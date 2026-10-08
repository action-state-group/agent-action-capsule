import { isHex64, jsonDigest, sha256Hex } from "./json.js";
import {
  AGENT_INPUT_ORIGINALS_EXTENSION,
  BOOK_PAYLOADS_EXTENSION,
} from "./extension-interpreters.js";
import { verifyProducerEnvelope } from "./producer-envelope-verification.js";
import { hexToBytes } from "./producer-envelope-wire.js";
import { computeCapsuleId, decodeCapsuleJson } from "./verify.js";
import {
  disclosureOf,
  verifiedBundleContext,
  verifiedPayload,
  type VerifiedBundleContext,
} from "./bundle.js";
import {
  asString,
  committedDigest,
  EvidenceGraphError,
  isObject,
  logCoordinates,
  recordTimes,
  type DisclosureField,
  type DisclosureResolution,
  type ObjectValue,
  type RecordTimes,
  type RecordWithId,
  type ResolvedLogCoordinates,
} from "./evidence-graph.js";

/**
 * Evidence Result v0 as the bundle root (spec/evidence-result-v0.md; schema
 * schemas/evidence-result-v0.json). The root record is a sealed capsule whose
 * disclosed member carries the Result document, in one of two forms: the
 * member IS the document (payload form), or the member is an evidence-book
 * record header of `record_type: "evidence_result"` whose `statement` is the
 * document (book form; see `resultDocument`). Headlines -- coverage, buckets,
 * each claim's sufficiency / verdict / tier / grade -- are read from that
 * document and nowhere else; every drill-down is read from the records the
 * claims cite by digest, resolved against this same bundle.
 *
 * The one rule this module adds to the Result's own: a claim whose cited
 * evidence does not all resolve in `records` is `unsupported`. It is never
 * shown as `met`, and it is never dropped.
 *
 * Headline values are never taken on the producer's word (maintainer's
 * adversarial review, 2026-09-28). Four consequences, each pinned in
 * test/result-root.test.ts: the buckets must partition the claims exactly
 * (every claim in exactly one bucket, entries equal to claims) or the
 * Result is rejected; the coverage counts and the per-bucket counts are
 * recomputed from the claims, and a disagreement is carried as a
 * `countMismatches` entry and drawn as a marker beside the recomputed
 * value, never the stated one; a bundle carries exactly one Result v0 -- a
 * second candidate document anywhere in it is an error; and a `close`
 * claim's state is recomputed from the cited Close's inbound links in this
 * bundle when the Close is supplied, with the asserted value drawn only
 * under a `producer-asserted` marker when it is not.
 *
 * No JSON Schema validator is wired into this package, so `validateEvidenceResult`
 * mirrors the schema's required members, closed vocabularies and the
 * sufficiency/verdict if-then by hand; test/result-root.test.ts reads the
 * schema file and keeps the two in step. The mirror closes the document's
 * top level only. Every nested object is read open-world: members the schema
 * does not define are tolerated on a claim, a carrier, `aggregate`, its
 * coverage and buckets, and on digest and proof refs (a claim `type` this
 * module does not know renders as `unrecognized`, never dropped).
 */

export const RESULT_VERSION = "evidence-result-v0";

/**
 * The evidence-book `record_type` under which `capsulectl result build`
 * seals a Result into a book. A book bundle discloses a record's header
 * under `agent_input` (evidencebook's `HeaderMember`), so at such a root
 * `disclosures[root].agent_input` is the header and the Result document is
 * its `statement` member, verbatim.
 */
export const RESULT_RECORD_TYPE = "evidence_result";

/**
 * How the root member carries the Result: `payload` when the disclosed
 * member is the document itself (a capsule sealed by `AssembleBundle`);
 * `book` when it is an evidence-book record header whose `statement` is the
 * document (a bundle built by `evidencebook.Book.Bundle`).
 */
export type ResultRootForm = "payload" | "book";

export const TIERS = Object.freeze(["recomputed", "judged"] as const);
export const GRADES = Object.freeze([
  "self-attested",
  "witnessed",
  "countersigned",
] as const);
export const SUFFICIENCIES = Object.freeze([
  "SATISFIED",
  "GAP",
  "INSUFFICIENT",
  "UNKNOWN",
] as const);
export const VERDICTS = Object.freeze([
  "met",
  "not_met",
  "not_evaluable",
] as const);
export const EVIDENCE_STATUSES = Object.freeze([
  "SATISFIED",
  "INSUFFICIENT",
  "NOT_FOUND",
  "NOT_COMMITTED",
  "WITHHELD",
  "CONTRADICTED",
  "NOT_APPLICABLE",
  "UNKNOWN",
] as const);
export const DISCLOSED_STATUSES = Object.freeze([
  "SATISFIED",
  "INSUFFICIENT",
  "NOT_FOUND",
  "CONTRADICTED",
  "NOT_APPLICABLE",
  "UNKNOWN",
] as const);
export const PROOF_KINDS = Object.freeze([
  "inclusion_proof",
  "receipt",
] as const);
/** The document's members: the schema closes the top level to these. */
export const RESULT_MEMBERS = Object.freeze([
  "result_version",
  "generated_at",
  "claims",
  "aggregate",
  "view",
] as const);
export const CLAIM_REQUIRED = Object.freeze([
  "id",
  "contract_ref",
  "requirement_ref",
  "tier",
  "grade",
  "sufficiency",
  "verdict",
  "evidence",
  "proofs",
  "presentation",
] as const);

export type Tier = (typeof TIERS)[number];
export type Grade = (typeof GRADES)[number];
export type Sufficiency = (typeof SUFFICIENCIES)[number];
export type Verdict = (typeof VERDICTS)[number];
export type EvidenceStatus = (typeof EVIDENCE_STATUSES)[number];
export type ProofKind = (typeof PROOF_KINDS)[number];

/** The claim type this module renders as a requirement row. */
export const REQUIREMENT_CLAIM = "requirement";
/**
 * The claim type whose `close` body this module reads: one sealed Close,
 * cited by digest (`close_ref`), with a `close_state` the Result asserts
 * and this module recomputes (spec/evidence-result-v0.md section 4.1)
 * from the Close's COUNTERPARTY links only -- a link from the named
 * peer's book (`book_id` == the claim's `peer`, != the Close's) signed
 * under a different, VERIFIED `key_id` than the Close (see
 * `counterpartyLinks` and `signerOf`).
 */
export const CLOSE_CLAIM = "close";
export const CLOSE_STATES = Object.freeze([
  "UNILATERAL",
  "AGREED",
  "CONTESTED",
] as const);
export type CloseState = (typeof CLOSE_STATES)[number];
/** The two link types that make a Close's state (evidence-layer draft, "Reconcile and Close"). */
export const CLOSE_LINK_TYPES = Object.freeze([
  "acknowledges",
  "rebuts",
] as const);
export type CloseLinkType = (typeof CLOSE_LINK_TYPES)[number];

/**
 * Where a drawn close state came from: `recomputed` when the cited Close
 * is a record in this bundle and its inbound links were read;
 * `producer-asserted` when it is not, so the Result's own value is all
 * there is -- drawn only under that marker, never bare.
 */
export type CloseDerivation = "recomputed" | "producer-asserted";

export interface CloseLink {
  readonly type: CloseLinkType;
  /** The capsule id of the record carrying the link. */
  readonly recordId: string;
  /** The linking record header's `book_id`; absent when the header names none. */
  readonly bookId?: string;
  /**
   * The linking record's signer: its local Producer Envelope `key_id`
   * (draft-mih-scitt-agent-action-capsule-04 section capsule_id -- the
   * envelope field a local composite carries beside `signature`, excluded
   * from the capsule id). Absent when the record carries none.
   */
  readonly keyId?: string;
  /**
   * Present with `keyId`. True only when the record's local Producer
   * Envelope (`signature`, the COSE_Sign1 over its capsule id) verifies,
   * with this module's own `verifyProducerEnvelope`, over the record's
   * RECOMPUTED capsule id, and its protected `kid` -- the raw Ed25519
   * public key -- is `keyId`. False: a stated key_id (not verified), which
   * never satisfies the different-key condition.
   */
  readonly keyVerified?: boolean;
}

/** The label a view draws beside a key_id whose signature did not verify. */
export const UNVERIFIED_KEY_LABEL = "stated key_id (not verified)";

/**
 * An inbound acknowledges/rebuts link that made no state: it is not from
 * the counterparty (maintainer's third pass, 2026-09-29). `reason` says
 * which of the three parts failed, for the reader.
 */
export interface IgnoredCloseLink extends CloseLink {
  readonly reason: string;
}

export interface ResultClose {
  readonly closeRef: string;
  /** The cited Close's own `book_id` (its header's); absent when it names none, and then no link counts. */
  readonly bookId?: string;
  /** The cited Close's signer key (its local `key_id`); absent when it carries none, and then no link counts. */
  readonly keyId?: string;
  /** Present with `keyId`: whether the Close's own Producer Envelope verifies under it. When false, no link counts. */
  readonly keyVerified?: boolean;
  readonly period?: { readonly start: string; readonly end: string };
  /** The state the Result wrote. Never drawn as the state when `derived` disagrees. */
  readonly asserted: CloseState;
  /** The state this bundle's links read at `closeRef`; absent when the Close is not supplied. */
  readonly derived?: CloseState;
  /** The state a view draws: `derived` when known, else `asserted`. */
  readonly state: CloseState;
  readonly derivation: CloseDerivation;
  /** `derived` is known and differs from `asserted`. */
  readonly stateMismatch: boolean;
  /**
   * The state is AGREED or CONTESTED by this bundle's links, but
   * `peer_close_ref` is not a record carrying that link.
   */
  readonly peerRefMismatch: boolean;
  readonly peer?: string;
  readonly peerCloseRef?: string;
  /**
   * Every COUNTERPARTY acknowledges/rebuts link this bundle makes to
   * `closeRef` -- the links the state is read from. A link counts only
   * when the linking record (1) carries a `book_id` that differs from the
   * Close's, (2) that `book_id` is the claim's named `peer`, and (3) it is
   * signed under a different, VERIFIED `key_id` than the Close
   * (maintainer's third and fourth passes, 2026-09-29: neither book nor
   * key alone is enough; a key_id counts only when the record's Producer
   * Envelope verifies under it). A Close with no `book_id`, or no verified
   * `key_id`, takes no link at all.
   */
  readonly links: readonly CloseLink[];
  /** Every other inbound acknowledges/rebuts link, with why it made no state. */
  readonly ignored: readonly IgnoredCloseLink[];
}

/** Which rule failed a claim, for the row's `data-failed` attribute. */
export type ClaimFailure = "close_state" | "evidence" | "peer_close_ref";

/**
 * `supported`: every cited evidence digest names a record supplied in the
 * bundle. `unsupported`: at least one does not, or the claim cites nothing
 * -- a claim that cannot be traced to evidence in this bundle.
 */
export type ClaimSupport = "supported" | "unsupported";

export interface ClaimEvidenceRef {
  readonly digest: string;
  /** True when a record with this capsule_id is supplied in the bundle. */
  readonly resolved: boolean;
}

export interface ClaimProofRef {
  readonly kind: ProofKind;
  readonly digest: string;
}

export interface ClaimPresentation {
  readonly kind: "disclosure" | "analysis" | "story";
  readonly status: EvidenceStatus;
  readonly summary?: string;
  readonly narrative?: string;
  readonly evidence?: readonly string[];
}

export interface ResultClaim {
  readonly id: string;
  /**
   * The claim `type` as written, or `requirement` when absent. `recognized`
   * is false for any other value: the row is still built, with its axes, and
   * the view labels it `unrecognized`.
   */
  readonly type: string;
  readonly recognized: boolean;
  readonly contractRef: string;
  readonly requirementRef: string;
  readonly tier: Tier;
  readonly grade: Grade;
  readonly sufficiency: Sufficiency;
  readonly verdict: Verdict;
  readonly support: ClaimSupport;
  readonly evidence: readonly ClaimEvidenceRef[];
  /** The cited digests no supplied record carries, in citation order. */
  readonly missing: readonly string[];
  readonly proofs: readonly ClaimProofRef[];
  readonly presentation: ClaimPresentation;
  /** Present on a recognized `close` claim. */
  readonly close?: ResultClose;
  /**
   * The claim FAILED verification (maintainer's second and third passes,
   * 2026-09-28 / 2026-09-29): its close state, recomputed from this
   * bundle's counterparty links, is not the state the Result asserts; or
   * `close_ref` / `peer_close_ref` is not among the claim's `evidence[]`
   * digests; or `peer_close_ref` is not the counterparty record carrying
   * the link that makes the recomputed state. A failed claim's
   * `sufficiency` and `verdict` are the producer's words and are never
   * drawn as the claim's; it is counted under `bucketCounts.failed`, never
   * under its stated verdict.
   */
  readonly failed: boolean;
  /** Why the claim failed, for the reader; absent when it stands. */
  readonly failure?: string;
  /** The first rule that failed it; absent when it stands. */
  readonly failedOn?: ClaimFailure;
}

export interface ResultCoverage {
  readonly evaluatedPopulation: number;
  readonly excludedNotApplicable: number;
  readonly unknownCount: number;
}

export interface ResultBuckets {
  readonly met: readonly string[];
  readonly notMet: readonly string[];
  readonly notEvaluable: readonly string[];
}

/**
 * Per-bucket headline counts, recomputed from the claims' own verdicts --
 * over the claims that stand. A claim that FAILED verification (see
 * `ResultClaim.failed`) is counted under `failed` and under no verdict.
 */
export interface ResultBucketCounts {
  readonly met: number;
  readonly notMet: number;
  readonly notEvaluable: number;
  readonly failed: number;
}

export type CountField =
  | "evaluated_population"
  | "unknown_count"
  | "buckets.met"
  | "buckets.not_met"
  | "buckets.not_evaluable";

/** A headline number the producer stated that the claims do not bear out. */
export interface CountMismatch {
  readonly field: CountField;
  readonly stated: number;
  readonly recomputed: number;
}

export interface RecomputedCounts {
  /**
   * `evaluatedPopulation` and `unknownCount` are recomputed from the
   * claims (the claim count; claims whose sufficiency is UNKNOWN).
   * `excludedNotApplicable` is carried as stated: requirements excluded as
   * not applicable are outside the evaluated population by construction
   * and are never claims, so the document holds nothing to recount them
   * from -- the view says so beside the number.
   */
  readonly coverage: ResultCoverage;
  readonly bucketCounts: ResultBucketCounts;
  readonly mismatches: readonly CountMismatch[];
}

/** See `CitedRecord.stated`. */
export interface StatedTimes {
  readonly timestamp?: string;
  readonly provenanceMode?: ObjectValue;
}

function statedTimes(capsule: ObjectValue): StatedTimes {
  const timestamp = asString(capsule.timestamp);
  const provenanceMode = isObject(capsule.provenance_mode)
    ? capsule.provenance_mode
    : undefined;
  return {
    ...(timestamp === undefined ? {} : { timestamp }),
    ...(provenanceMode === undefined ? {} : { provenanceMode }),
  };
}

/** A record reachable from a claim's evidence, resolved from this bundle. */
export interface CitedRecord extends RecordTimes {
  readonly capsuleId: string;
  readonly agentInput: DisclosureResolution;
  /**
   * Present only when this record is an evidence-book `published_capsule`
   * record whose header is disclosed: the agent_input original of the capsule
   * that record carries (see `resolveCarriedInput`). For such a record
   * `agentInput` is the book's header, never the capsule's own input, so a
   * reader that wants what the capsule sealed reads this instead.
   */
  readonly carriedInput?: DisclosureResolution;
  /**
   * Present only when the claim cited this capsule by its own id and the
   * bundle supplies it as an evidence-book record that carries it (a
   * disclosed `published_capsule` header whose `subject_ref` is that id):
   * the book record's own id, under which the bundle's records, memberships
   * and disclosures hold it. `capsuleId` stays the id the claim cited.
   */
  readonly bookRecordId?: string;
  /**
   * For an evidence-book `published_capsule` record: the id of the capsule it
   * carries and that capsule's agent_input commitment, present only when the
   * capsule bytes match their commitment and the recomputed id equals both
   * `capsule_id` and the header's `subject_ref` (see
   * `carriedCapsuleCommitment`). Present even when the original itself is
   * not carried, so two records can be shown to commit to the same input.
   */
  readonly carriedCapsuleId?: string;
  readonly carriedInputDigest?: string;
  /**
   * The occurrence-time fields the capsule itself states, verbatim, never
   * parsed or assigned a zone: its `timestamp` and, when present, its
   * `provenance_mode` block (AAC -05 "Provenance mode and backfilled
   * records"). For an evidence-book record these are the CARRIED capsule's,
   * read only when `carriedCapsuleCommitment`'s checks pass -- the book
   * record's own timestamp is when the book took it in, never when the
   * action happened. For a plain record they are the record's own. Absent
   * for a book record whose carried capsule does not check out.
   */
  readonly stated?: StatedTimes;
  readonly agentOutput: DisclosureResolution;
  /** The digests the record committed to, so a withheld member shows its digest. */
  readonly agentInputDigest?: string;
  readonly agentOutputDigest?: string;
  readonly logCoordinates?: ResolvedLogCoordinates;
  /** Capsule ids this record cites `acted_on`, as written; not all resolve. */
  readonly cites: readonly string[];
}

export interface ResultRoot extends RecordTimes {
  readonly capsuleId: string;
  /** The disclosed member that carried the Result document. */
  readonly member: DisclosureField;
  /** Whether that member was the document itself or a book record header. */
  readonly form: ResultRootForm;
  readonly generatedAt: string;
  /**
   * The coverage a view draws: `evaluatedPopulation` and `unknownCount`
   * recomputed from the claims, `excludedNotApplicable` as stated (see
   * `RecomputedCounts`). The producer's own numbers are `statedCoverage`.
   */
  readonly coverage: ResultCoverage;
  readonly statedCoverage: ResultCoverage;
  readonly buckets: ResultBuckets;
  /** Headline counts per bucket, from the claims' verdicts, never from `buckets`' lengths. */
  readonly bucketCounts: ResultBucketCounts;
  /** Every stated headline number the claims disagree with; empty on an honest Result. */
  readonly countMismatches: readonly CountMismatch[];
  readonly claims: readonly ResultClaim[];
  /** Every record reachable from a claim's evidence through `acted_on` citations. */
  readonly records: ReadonlyMap<string, CitedRecord>;
  readonly logCoordinates?: ResolvedLogCoordinates;
}

const oneOf = <T extends string>(
  values: readonly T[],
  value: unknown,
): value is T => typeof value === "string" && values.includes(value as T);

const nonEmptyString = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0;

const CONTRACT_REF = /^[^@\s]+@[^@\s]+$/u;

const nonNegativeInteger = (value: unknown): value is number =>
  Number.isSafeInteger(value) && (value as number) >= 0;

function digestRefFindings(path: string, value: unknown): string[] {
  if (!isObject(value)) return [`${path}: not an object`];
  const findings: string[] = [];
  if (value.digest_alg !== "SHA-256") findings.push(`${path}.digest_alg`);
  if (!isHex64(value.digest)) findings.push(`${path}.digest`);
  return findings;
}

function presentationFindings(path: string, value: unknown): string[] {
  if (!isObject(value)) return [`${path}: not an object`];
  const findings: string[] = [];
  switch (value.kind) {
    case "disclosure":
      if (!oneOf(DISCLOSED_STATUSES, value.status))
        findings.push(`${path}.status: not a disclosable status`);
      if (!Array.isArray(value.evidence)) findings.push(`${path}.evidence`);
      else
        value.evidence.forEach((item, index) =>
          findings.push(
            ...digestRefFindings(`${path}.evidence[${index}]`, item),
          ),
        );
      break;
    case "analysis":
      if (!oneOf(EVIDENCE_STATUSES, value.status))
        findings.push(`${path}.status`);
      if (!nonEmptyString(value.summary)) findings.push(`${path}.summary`);
      break;
    case "story":
      if (!oneOf(EVIDENCE_STATUSES, value.status))
        findings.push(`${path}.status`);
      if (!nonEmptyString(value.narrative)) findings.push(`${path}.narrative`);
      break;
    default:
      findings.push(`${path}.kind: not disclosure, analysis, or story`);
  }
  return findings;
}

function claimFindings(path: string, value: unknown): string[] {
  if (!isObject(value)) return [`${path}: not an object`];
  const findings: string[] = [];
  for (const member of CLAIM_REQUIRED)
    if (!Object.hasOwn(value, member))
      findings.push(`${path}.${member}: absent`);
  if (findings.length > 0) return findings;
  if (!nonEmptyString(value.id)) findings.push(`${path}.id`);
  if (
    typeof value.contract_ref !== "string" ||
    !CONTRACT_REF.test(value.contract_ref)
  )
    findings.push(`${path}.contract_ref: not <contract_id>@<version>`);
  if (!nonEmptyString(value.requirement_ref))
    findings.push(`${path}.requirement_ref`);
  if (!oneOf(TIERS, value.tier)) findings.push(`${path}.tier`);
  if (!oneOf(GRADES, value.grade)) findings.push(`${path}.grade`);
  if (!oneOf(SUFFICIENCIES, value.sufficiency))
    findings.push(`${path}.sufficiency`);
  if (!oneOf(VERDICTS, value.verdict)) findings.push(`${path}.verdict`);
  // The rule that binds the two axes (spec section 1): a verdict is met or
  // not_met only under SATISFIED sufficiency, and not_evaluable otherwise.
  if (oneOf(SUFFICIENCIES, value.sufficiency) && oneOf(VERDICTS, value.verdict))
    if (
      value.sufficiency === "SATISFIED"
        ? value.verdict === "not_evaluable"
        : value.verdict !== "not_evaluable"
    )
      findings.push(
        `${path}.verdict: ${value.verdict} is not a verdict under sufficiency ${value.sufficiency}`,
      );
  if (!Array.isArray(value.evidence)) findings.push(`${path}.evidence`);
  else
    value.evidence.forEach((item, index) =>
      findings.push(...digestRefFindings(`${path}.evidence[${index}]`, item)),
    );
  if (!Array.isArray(value.proofs)) findings.push(`${path}.proofs`);
  else
    value.proofs.forEach((item, index) => {
      const itemPath = `${path}.proofs[${index}]`;
      findings.push(...digestRefFindings(itemPath, item));
      if (isObject(item) && !oneOf(PROOF_KINDS, item.kind))
        findings.push(`${itemPath}.kind`);
    });
  findings.push(
    ...presentationFindings(`${path}.presentation`, value.presentation),
  );
  return findings;
}

/**
 * A structural mirror of schemas/evidence-result-v0.json, not a JSON Schema
 * validation. It checks: the document's top-level members (the schema closes
 * the document, so a key outside `RESULT_MEMBERS` is a finding); required
 * members, closed vocabularies (enums, consts) and the sufficiency/verdict
 * if-then on the closed objects it mirrors -- claims, carriers, digest and
 * proof refs, `aggregate`, coverage and buckets; and the two cross-element
 * rules spec section 4 makes a verifier's duty: claim ids are unique, and
 * every bucket entry names a claim whose verdict is that bucket. Below the
 * top level it is open-world on additional keys. `view` is not checked, and
 * `generated_at` is checked as a string, not as a date-time. Empty findings
 * mean the document passed this mirror -- nothing more.
 */
export function validateEvidenceResult(value: unknown): string[] {
  if (!isObject(value)) return ["result: not an object"];
  const findings: string[] = [];
  for (const key of Object.keys(value))
    if (!RESULT_MEMBERS.includes(key as (typeof RESULT_MEMBERS)[number]))
      findings.push(`${key}: not a member of an Evidence Result v0`);
  if (value.result_version !== RESULT_VERSION)
    findings.push(`result_version: not ${RESULT_VERSION}`);
  if (typeof value.generated_at !== "string") findings.push("generated_at");
  if (!Array.isArray(value.claims) || value.claims.length === 0)
    findings.push("claims: not a non-empty array");
  else
    value.claims.forEach((claim, index) =>
      findings.push(...claimFindings(`claims[${index}]`, claim)),
    );
  const aggregate = isObject(value.aggregate) ? value.aggregate : undefined;
  if (aggregate === undefined) findings.push("aggregate: not an object");
  const coverage = isObject(aggregate?.coverage)
    ? aggregate.coverage
    : undefined;
  if (coverage === undefined)
    findings.push("aggregate.coverage: not an object");
  else
    for (const member of [
      "evaluated_population",
      "excluded_not_applicable",
      "unknown_count",
    ])
      if (!nonNegativeInteger(coverage[member]))
        findings.push(
          `aggregate.coverage.${member}: not a non-negative integer`,
        );
  const buckets = isObject(aggregate?.buckets) ? aggregate.buckets : undefined;
  if (buckets === undefined) findings.push("aggregate.buckets: not an object");
  else
    for (const member of VERDICTS)
      if (
        !Array.isArray(buckets[member]) ||
        !buckets[member].every(nonEmptyString)
      )
        findings.push(`aggregate.buckets.${member}: not an array of claim ids`);
  if (findings.length > 0) return findings;

  const verdictById = new Map<string, string>();
  (value.claims as ObjectValue[]).forEach((claim, index) => {
    const id = claim.id as string;
    if (verdictById.has(id))
      findings.push(`claims[${index}].id: duplicate ${id}`);
    verdictById.set(id, claim.verdict as string);
  });
  const appearances = new Map<string, number>();
  let entries = 0;
  for (const member of VERDICTS)
    for (const id of buckets![member] as string[]) {
      entries += 1;
      appearances.set(id, (appearances.get(id) ?? 0) + 1);
      if (verdictById.get(id) !== member)
        findings.push(
          `aggregate.buckets.${member}: ${id} is not a claim with that verdict`,
        );
    }
  // The exact partition (2026-09-28): every claim in exactly one bucket, and
  // exactly as many entries as claims. A claim in no bucket is a verdict the
  // headline hides; one in two is a verdict counted twice.
  for (const [id, verdict] of verdictById) {
    const count = appearances.get(id) ?? 0;
    if (count === 0)
      findings.push(
        `aggregate.buckets: ${id} (${verdict}) appears in no bucket`,
      );
    else if (count > 1)
      findings.push(
        `aggregate.buckets: ${id} appears ${count} times across the buckets`,
      );
  }
  if (entries !== verdictById.size)
    findings.push(
      `aggregate.buckets: ${entries} entries for ${verdictById.size} claims`,
    );
  return findings;
}

const countOf = (value: unknown): number =>
  nonNegativeInteger(value) ? value : 0;

/**
 * The headline numbers as the claims bear them out. Takes a document that
 * passed `validateEvidenceResult` and returns coverage and per-bucket
 * counts recomputed from `claims[]` -- the claim count, the UNKNOWN
 * sufficiencies, and the verdicts -- beside a list of every stated number
 * that disagrees. `excluded_not_applicable` is carried as stated (no claim
 * backs it, by construction). Pure, so a disagreement the partition gate
 * makes unreachable through `buildResultRoot` is still provable here.
 *
 * `failed` names the claims that failed verification (a close-state
 * mismatch; `ResultClaim.failed`). They stay in `evaluated_population` --
 * the producer did evaluate them -- but contribute to no verdict count and
 * to no unresolved count: their sufficiency and verdict are withheld, and
 * they are counted under `bucketCounts.failed` instead. A producer's
 * `buckets.met` that lists a failed claim therefore reads as a count
 * mismatch beside the recomputed `met`.
 */
export function recomputeCounts(
  document: ObjectValue,
  failed: ReadonlySet<string> = new Set(),
): RecomputedCounts {
  const claims = document.claims as ObjectValue[];
  const aggregate = document.aggregate as ObjectValue;
  const coverage = aggregate.coverage as ObjectValue;
  const buckets = aggregate.buckets as ObjectValue;
  const standing = claims.filter((claim) => !failed.has(claim.id as string));
  const stated = {
    evaluated_population: countOf(coverage.evaluated_population),
    unknown_count: countOf(coverage.unknown_count),
    "buckets.met": (buckets.met as unknown[]).length,
    "buckets.not_met": (buckets.not_met as unknown[]).length,
    "buckets.not_evaluable": (buckets.not_evaluable as unknown[]).length,
  } as const;
  const recomputed = {
    evaluated_population: claims.length,
    unknown_count: standing.filter((claim) => claim.sufficiency === "UNKNOWN")
      .length,
    "buckets.met": standing.filter((claim) => claim.verdict === "met").length,
    "buckets.not_met": standing.filter((claim) => claim.verdict === "not_met")
      .length,
    "buckets.not_evaluable": standing.filter(
      (claim) => claim.verdict === "not_evaluable",
    ).length,
  } as const;
  const mismatches: CountMismatch[] = [];
  for (const field of Object.keys(stated) as CountField[])
    if (stated[field] !== recomputed[field])
      mismatches.push({
        field,
        stated: stated[field],
        recomputed: recomputed[field],
      });
  return {
    coverage: {
      evaluatedPopulation: recomputed.evaluated_population,
      excludedNotApplicable: countOf(coverage.excluded_not_applicable),
      unknownCount: recomputed.unknown_count,
    },
    bucketCounts: {
      met: recomputed["buckets.met"],
      notMet: recomputed["buckets.not_met"],
      notEvaluable: recomputed["buckets.not_evaluable"],
      failed: claims.length - standing.length,
    },
    mismatches,
  };
}

/**
 * The state a Close's inbound links read: any `rebuts` link makes it
 * CONTESTED; otherwise any `acknowledges` link makes it AGREED; neither
 * leaves it UNILATERAL (spec section 4.1 -- a standing rebuttal keeps a
 * Close out of AGREED whatever else links to it).
 */
export function deriveCloseState(links: readonly CloseLink[]): CloseState {
  if (links.some((link) => link.type === "rebuts")) return "CONTESTED";
  if (links.some((link) => link.type === "acknowledges")) return "AGREED";
  return "UNILATERAL";
}

/** A `close` body this module can read: a state in the vocabulary and a Close cited by digest. */
function closeBody(
  raw: ObjectValue,
):
  | (ObjectValue & { close_state: CloseState; close_ref: ObjectValue })
  | undefined {
  const body = raw.close;
  if (
    !isObject(body) ||
    !oneOf(CLOSE_STATES, body.close_state) ||
    !isObject(body.close_ref) ||
    !isHex64(body.close_ref.digest)
  )
    return undefined;
  return body as ObjectValue & {
    close_state: CloseState;
    close_ref: ObjectValue;
  };
}

/**
 * Every acknowledges/rebuts link the bundle's records make, keyed by the
 * target digest. Links are read from each record's disclosed `agent_input`
 * when it is an evidence-book record header carrying `links[{type,
 * target}]`; a member that is withheld, or does not hash to its committed
 * digest, contributes nothing.
 */
async function inboundCloseLinks(
  context: VerifiedBundleContext,
): Promise<ReadonlyMap<string, readonly CloseLink[]>> {
  const inbound = new Map<string, CloseLink[]>();
  for (const record of context.records) {
    const header = verifiedPayload(context, record.capsule_id, "agent_input");
    if (!isObject(header) || !Array.isArray(header.links)) continue;
    const bookId = asString(header.book_id);
    const signer = await signerOf(record);
    for (const link of header.links) {
      if (!isObject(link) || !oneOf(CLOSE_LINK_TYPES, link.type)) continue;
      const target = asString(link.target);
      if (target === undefined) continue;
      const list = inbound.get(target) ?? [];
      list.push({
        type: link.type,
        recordId: record.capsule_id,
        ...(bookId === undefined ? {} : { bookId }),
        ...signer,
      });
      inbound.set(target, list);
    }
  }
  return inbound;
}

/**
 * A record's signer as the bundle model exposes it: the local Producer
 * Envelope `key_id` carried beside `signature` on a composite capsule
 * (excluded from the capsule id, capsule-05 check 2) -- the Ed25519 public
 * key, 64 hex -- and whether it is VERIFIED (maintainer's fourth pass,
 * 2026-09-29: "verify the signature under key_id, or label it 'stated
 * key_id (not verified)' and don't let it pass the check"). The key
 * material travels with the record: the envelope's protected `kid` is the
 * raw public key. So `keyVerified` is true only when (a) `signature` is
 * hex, (b) the record's capsule id recomputes to the carried one, (c)
 * `verifyProducerEnvelope` accepts the envelope over that id, and (d) the
 * envelope's `kid` is `key_id`. Anything else -- no signature, a
 * signature by another key, an envelope over another id, a runtime
 * without Ed25519 WebCrypto -- is a stated key_id, never a verified one.
 */
async function signerOf(
  record: RecordWithId,
): Promise<{ readonly keyId?: string; readonly keyVerified?: boolean }> {
  const keyId = record.key_id;
  if (typeof keyId !== "string" || !isHex64(keyId)) return {};
  return { keyId, keyVerified: await keyVerifies(record, keyId) };
}

const lowerHex = /^(?:[0-9a-f]{2})+$/u;

async function keyVerifies(
  record: RecordWithId,
  keyId: string,
): Promise<boolean> {
  const signature = record.signature;
  if (typeof signature !== "string" || !lowerHex.test(signature)) return false;
  let recomputed: string;
  try {
    recomputed = await computeCapsuleId(record as never);
  } catch {
    return false;
  }
  if (recomputed !== record.capsule_id) return false;
  const envelope = await verifyProducerEnvelope(
    recomputed,
    hexToBytes(signature),
  );
  if (!envelope.ok || envelope.publicKey === undefined) return false;
  const kid = Array.from(envelope.publicKey, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  return kid === keyId;
}

/**
 * Split a Close's inbound links into the ones that make its state and the
 * ones that do not (maintainer's third pass, 2026-09-29: "neither book_id
 * nor signer alone is enough, since a producer can mint a second book or a
 * second key equally easily"). A link counts only when ALL of:
 *   (1) the linking record's `book_id` is present and differs from the
 *       Close's;
 *   (2) that `book_id` equals the claim's named `peer`;
 *   (3) the linking record's `key_id` is present, VERIFIED (its Producer
 *       Envelope verifies under it -- see `signerOf`), and differs from
 *       the Close's, which must itself be verified.
 * A Close with no `book_id`, or no verified `key_id`, takes no link:
 * nothing can be shown to be its counterparty. A linking record whose
 * key_id is only stated is ignored with the reason "stated key_id (not
 * verified)". AGREED therefore reads "acknowledged by
 * the named peer's book under a different key", never "by an independent
 * party", until the contract pins the peer's key.
 */
export function counterpartyLinks(
  close: {
    readonly bookId?: string;
    readonly keyId?: string;
    readonly keyVerified?: boolean;
  },
  peer: string | undefined,
  inbound: readonly CloseLink[],
): { readonly links: CloseLink[]; readonly ignored: IgnoredCloseLink[] } {
  const links: CloseLink[] = [];
  const ignored: IgnoredCloseLink[] = [];
  for (const link of inbound) {
    const reason =
      close.bookId === undefined
        ? "the cited Close names no book_id, so nothing can be its counterparty"
        : close.keyId === undefined
          ? "the cited Close carries no key_id, so no signer can be shown to differ from its own"
          : close.keyVerified !== true
            ? `the cited Close's key_id is a ${UNVERIFIED_KEY_LABEL}: its Producer Envelope does not verify under it, so no signer can be shown to differ from its own`
            : link.bookId === undefined
              ? "the linking record names no book_id"
              : link.bookId === close.bookId
                ? "the linking record is from the Close's own book"
                : link.bookId !== peer
                  ? peer === undefined
                    ? "the claim names no peer, so no book can be the counterparty"
                    : `the linking record's book_id ${link.bookId} is not the claim's named peer ${peer}`
                  : link.keyId === undefined
                    ? "the linking record carries no key_id"
                    : link.keyVerified !== true
                      ? `${UNVERIFIED_KEY_LABEL}: the linking record's Producer Envelope does not verify under its key_id`
                      : link.keyId === close.keyId
                        ? "the linking record is signed under the Close's own key"
                        : undefined;
    if (reason === undefined) links.push(link);
    else ignored.push({ ...link, reason });
  }
  return { links, ignored };
}

const actedOnReferences = (record: RecordWithId): string[] =>
  Array.isArray(record.references)
    ? record.references.flatMap((reference) =>
        isObject(reference) &&
        reference.type === "agent-action-capsule" &&
        reference.citation_purpose === "acted_on" &&
        typeof reference.digest === "string"
          ? [reference.digest]
          : [],
      )
    : [];

interface CarriedResult {
  readonly member: DisclosureField;
  readonly form: ResultRootForm;
  /**
   * The Result document as carried. In book form this is the header's
   * `statement` as written -- possibly absent or malformed; the caller
   * validates it and names the statement when it fails.
   */
  readonly document: unknown;
}

/**
 * The disclosed member of the root record that carries the Result document,
 * if any, in either of its two forms. `agent_output` is consulted first: a
 * Result is what its producer emitted. A member is the Result in payload
 * form when it names itself one (`result_version`); `agent_input` is the
 * Result in book form when it is a record header of `record_type
 * "evidence_result"` -- the document is then its `statement`, taken as
 * written. Neither member carrying one means the root is not a Result root.
 */
function resultDocument(
  context: VerifiedBundleContext,
  root: RecordWithId,
): CarriedResult | undefined {
  return resultCarriers(context, root)[0];
}

/** Every disclosed member of `record` that carries a Result v0, in `agent_output`, `agent_input` order. */
function resultCarriers(
  context: VerifiedBundleContext,
  record: RecordWithId,
): CarriedResult[] {
  const carriers: CarriedResult[] = [];
  for (const member of ["agent_output", "agent_input"] as const) {
    const payload = verifiedPayload(context, record.capsule_id, member);
    if (!isObject(payload)) continue;
    if (payload.result_version === RESULT_VERSION)
      carriers.push({ member, form: "payload", document: payload });
    else if (
      member === "agent_input" &&
      payload.record_type === RESULT_RECORD_TYPE
    )
      carriers.push({ member, form: "book", document: payload.statement });
  }
  return carriers;
}

/**
 * What the root does carry, for the error that says it is not a Result:
 * a book record header of some other `record_type`, or nothing named.
 */
function nonResultDescription(
  context: VerifiedBundleContext,
  root: RecordWithId,
): string {
  const header = verifiedPayload(context, root.capsule_id, "agent_input");
  const recordType = isObject(header) ? header.record_type : undefined;
  return typeof recordType === "string"
    ? `agent_input is a book record header of record_type ${JSON.stringify(recordType)}, not ${JSON.stringify(RESULT_RECORD_TYPE)}`
    : `no disclosed member carries an ${RESULT_VERSION} document or an ${RESULT_RECORD_TYPE} record header`;
}

/**
 * True when the bundle's root record discloses a member that names itself
 * an Evidence Result v0, in payload form (`result_version`) or book form
 * (a record header of `record_type: "evidence_result"`) -- the dispatch test
 * a viewer runs before choosing a root model. It says nothing about whether
 * the document (in book form, the header's `statement`) is well-formed;
 * `buildResultRoot` decides that and throws when it is not.
 */
export async function isResultRoot(
  context: VerifiedBundleContext,
): Promise<boolean>;
export async function isResultRoot(bundle: unknown): Promise<boolean>;
export async function isResultRoot(input: unknown): Promise<boolean> {
  const context = await verifiedBundleContext(input);
  const bundle = context.bundle;
  if (
    !isObject(bundle) ||
    !Array.isArray(bundle.records) ||
    !isObject(bundle.disclosures)
  )
    return false;
  const record =
    context.root === undefined
      ? undefined
      : context.recordIndex.get(context.root);
  return record !== undefined && resultDocument(context, record) !== undefined;
}

// Both kinds live with the extension interpreter table, so the table and
// this builder name the same strings; re-exported here unchanged.
export {
  AGENT_INPUT_ORIGINALS_EXTENSION,
  BOOK_PAYLOADS_EXTENSION,
} from "./extension-interpreters.js";
/** The evidence-book `record_type` of a record that carries a published capsule as its payloads. */
export const PUBLISHED_CAPSULE_RECORD_TYPE = "published_capsule";

const utf8 = new TextDecoder("utf-8", { fatal: true });

function base64UrlBytes(value: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]*$/u.test(value)) return undefined;
  try {
    const padded = `${value}${"=".repeat((4 - (value.length % 4)) % 4)}`;
    const binary = atob(padded.replaceAll("-", "+").replaceAll("_", "/"));
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    return undefined;
  }
}

/** The payload bytes committed under `digest`, only when they hash to it. */
async function verifiedBookPayload(
  payloads: ObjectValue,
  digest: string,
): Promise<Uint8Array | undefined> {
  const encoded = asString(payloads[digest]);
  if (encoded === undefined) return undefined;
  const bytes = base64UrlBytes(encoded);
  if (bytes === undefined) return undefined;
  return (await sha256Hex(bytes)) === digest ? bytes : undefined;
}

/**
 * The agent_input original of the capsule an evidence-book
 * `published_capsule` record carries, resolved from the bundle's
 * `evidencebook/payloads` extension. `undefined` when `header` is not such a
 * record's header. Every link is checked, none is taken on the producer's
 * word: the header (already matched to the record's committed digest by
 * the verifier, via the context's resolved disclosures) commits to the carried capsule's bytes as its first
 * payload; those bytes must hash to that commitment, decode as a capsule whose
 * recomputed capsule id equals both its stated `capsule_id` and the header's
 * `subject_ref`; and an original is `disclosed` only when some other payload
 * the header commits to hashes to its commitment AND its JSON-DIGEST equals
 * the capsule's own `agent_input_digest`. A capsule published before the book
 * carried originals (two payloads, capsule and producer envelope) resolves
 * `withheld`; a broken link resolves `disclosure_mismatch`.
 */
/**
 * The capsule a `published_capsule` book header carries, checked link by link
 * (capsule bytes against their commitment, recomputed id against
 * `capsule_id` and `subject_ref`): its id and its agent_input commitment.
 * Undefined when any link fails or the header is not a published capsule.
 */
export async function carriedCapsuleCommitment(
  header: unknown,
  payloads: ObjectValue,
): Promise<
  { capsuleId: string; inputDigest: string; stated: StatedTimes } | undefined
> {
  if (!isObject(header) || header.record_type !== PUBLISHED_CAPSULE_RECORD_TYPE)
    return undefined;
  const commitments = Array.isArray(header.payload_commitments)
    ? header.payload_commitments.filter(isHex64)
    : [];
  const capsuleDigest = commitments[0];
  if (capsuleDigest === undefined) return undefined;
  const capsuleBytes = await verifiedBookPayload(payloads, capsuleDigest);
  if (capsuleBytes === undefined) return undefined;
  try {
    const capsule = decodeCapsuleJson(capsuleBytes);
    const id = await computeCapsuleId(capsule);
    if (id !== capsule.capsule_id || id !== header.subject_ref)
      return undefined;
    const committed = committedDigest(
      capsule as unknown as RecordWithId,
      "agent_input",
    );
    return isHex64(committed)
      ? {
          capsuleId: id,
          inputDigest: committed,
          stated: statedTimes(capsule as unknown as ObjectValue),
        }
      : undefined;
  } catch {
    return undefined;
  }
}

export async function resolveCarriedInput(
  header: unknown,
  payloads: ObjectValue,
  originals: ObjectValue = {},
): Promise<DisclosureResolution | undefined> {
  if (!isObject(header) || header.record_type !== PUBLISHED_CAPSULE_RECORD_TYPE)
    return undefined;
  const commitments = Array.isArray(header.payload_commitments)
    ? header.payload_commitments.filter(isHex64)
    : [];
  const capsuleDigest = commitments[0];
  if (capsuleDigest === undefined) return { state: "withheld" };
  const capsuleBytes = await verifiedBookPayload(payloads, capsuleDigest);
  if (capsuleBytes === undefined) return { state: "withheld" };
  let committed: string | undefined;
  let capsuleId: string;
  try {
    const capsule = decodeCapsuleJson(capsuleBytes);
    const id = await computeCapsuleId(capsule);
    if (id !== capsule.capsule_id || id !== header.subject_ref)
      return { state: "disclosure_mismatch" };
    capsuleId = id;
    committed = committedDigest(
      capsule as unknown as RecordWithId,
      "agent_input",
    );
  } catch {
    return { state: "disclosure_mismatch" };
  }
  if (!isHex64(committed)) return { state: "withheld" };
  for (const digest of commitments.slice(1)) {
    const bytes = await verifiedBookPayload(payloads, digest);
    if (bytes === undefined) continue;
    try {
      const value: unknown = JSON.parse(utf8.decode(bytes));
      if ((await jsonDigest(value)) === committed)
        return { state: "disclosed", payload: value };
    } catch {
      /* not JSON (the producer envelope), or JCS cannot render it */
    }
  }
  // An original attached at disclose time (AGENT_INPUT_ORIGINALS_EXTENSION),
  // keyed by the capsule id just recomputed: disclosed only when its
  // JSON-DIGEST is the capsule's committed agent_input_digest.
  const attached = asString(originals[capsuleId]);
  if (attached !== undefined) {
    const bytes = base64UrlBytes(attached);
    if (bytes === undefined) return { state: "disclosure_mismatch" };
    try {
      const value: unknown = JSON.parse(utf8.decode(bytes));
      if ((await jsonDigest(value)) === committed)
        return { state: "disclosed", payload: value };
    } catch {
      /* not JSON, or JCS cannot render it */
    }
    return { state: "disclosure_mismatch" };
  }
  return { state: "withheld" };
}

/**
 * Build the Result-root model. Throws `EvidenceGraphError` when the bundle
 * has no root record, when no disclosed member of the root carries an
 * Evidence Result v0 in either form, or when the document fails
 * `validateEvidenceResult` -- in book form the findings are rooted at
 * `agent_input.statement`, so the error names the statement. Never throws
 * for a claim it does not understand: an unknown claim `type` is carried as
 * `recognized: false`, and a claim whose evidence is not in the bundle is
 * carried as `unsupported`.
 */
export async function buildResultRoot(
  context: VerifiedBundleContext,
): Promise<ResultRoot>;
export async function buildResultRoot(bundle: unknown): Promise<ResultRoot>;
export async function buildResultRoot(input: unknown): Promise<ResultRoot> {
  const context = await verifiedBundleContext(input);
  const bundle = context.bundle;
  if (
    !isObject(bundle) ||
    !Array.isArray(bundle.records) ||
    !isObject(bundle.disclosures)
  )
    throw new EvidenceGraphError("bundle must contain records and disclosures");
  const records = context.records;
  const rootRecord =
    context.root === undefined
      ? undefined
      : context.recordIndex.get(context.root);
  if (rootRecord === undefined)
    throw new EvidenceGraphError(
      bundle.records.some(
        (record) => isObject(record) && record.capsule_id === context.root,
      )
        ? "root record failed verification"
        : "root record not supplied",
    );
  const rootCarriers = resultCarriers(context, rootRecord);
  const carried = rootCarriers[0];
  if (carried === undefined)
    throw new EvidenceGraphError(
      `root is not a Result v0: ${nonResultDescription(context, rootRecord)}`,
    );
  // One headline document per root (2026-09-28): the root carries exactly
  // one Result v0, in one member, and no other record in the bundle
  // carries one. A second candidate anywhere is an error, never a choice.
  if (rootCarriers.length > 1)
    throw new EvidenceGraphError(
      `root ${rootRecord.capsule_id} carries a Result v0 in both agent_output and agent_input; a bundle has exactly one headline document`,
    );
  const otherCarriers: string[] = [];
  for (const record of records)
    if (record !== rootRecord && resultCarriers(context, record).length > 0)
      otherCarriers.push(record.capsule_id);
  if (otherCarriers.length > 0)
    throw new EvidenceGraphError(
      `bundle carries ${otherCarriers.length + 1} Result v0 documents: root ${rootRecord.capsule_id} and ${otherCarriers.join(", ")}; a bundle has exactly one headline document`,
    );
  const findings =
    carried.form === "book"
      ? isObject(carried.document)
        ? validateEvidenceResult(carried.document).map(
            (finding) => `agent_input.statement.${finding}`,
          )
        : [
            `agent_input.statement: ${carried.document === undefined ? "absent" : "not an object"} on the ${RESULT_RECORD_TYPE} record header`,
          ]
      : validateEvidenceResult(carried.document);
  if (findings.length > 0)
    throw new EvidenceGraphError(
      `root is not a Result v0: ${findings.join("; ")}`,
    );
  const document = carried.document as ObjectValue;

  const memberships = context.completeness.memberships;
  const recordsById = context.recordIndex;
  const bookPayloads =
    isObject(bundle.extensions) &&
    isObject(bundle.extensions[BOOK_PAYLOADS_EXTENSION])
      ? bundle.extensions[BOOK_PAYLOADS_EXTENSION]
      : {};
  const inputOriginals =
    isObject(bundle.extensions) &&
    isObject(bundle.extensions[AGENT_INPUT_ORIGINALS_EXTENSION])
      ? bundle.extensions[AGENT_INPUT_ORIGINALS_EXTENSION]
      : {};

  // A book bundle (capsulectl disclose on a jsonl profile) supplies a
  // published capsule as the evidence-book record that carries it, under
  // the BOOK record's id; a claim cites the capsule by its own id (what
  // `publish` returned and the producer recorded). The carried capsule's id
  // is the header's `subject_ref`, read only from a header that is itself
  // disclosed and matched to the book record's committed digest -- never
  // from an unverified value. Built on first need: a payload-form bundle,
  // where every cited id is a record id, never pays for it.
  let carriersById: Map<string, RecordWithId> | undefined;
  const bookCarrier = async (id: string): Promise<RecordWithId | undefined> => {
    if (carriersById === undefined) {
      carriersById = new Map();
      for (const record of records) {
        const header = disclosureOf(context, record.capsule_id, "agent_input");
        if (
          header.state !== "disclosed" ||
          !isObject(header.payload) ||
          header.payload.record_type !== PUBLISHED_CAPSULE_RECORD_TYPE
        )
          continue;
        const subject = header.payload.subject_ref;
        if (isHex64(subject) && !recordsById.has(subject))
          carriersById.set(subject, record);
      }
    }
    return carriersById.get(id);
  };

  const cited = new Map<string, CitedRecord>();
  const resolveRecord = async (
    id: string,
    carrier?: RecordWithId,
  ): Promise<void> => {
    if (cited.has(id)) return;
    const record = carrier ?? recordsById.get(id);
    if (record === undefined) return;
    const cites = actedOnReferences(record);
    const coordinates = logCoordinates(memberships, record.capsule_id);
    const agentInputDigest = committedDigest(record, "agent_input");
    const agentOutputDigest = committedDigest(record, "agent_output");
    const agentInput = disclosureOf(context, record.capsule_id, "agent_input");
    const carriedInput =
      agentInput.state === "disclosed"
        ? await resolveCarriedInput(
            agentInput.payload,
            bookPayloads,
            inputOriginals,
          )
        : undefined;
    const carriedCapsule =
      agentInput.state === "disclosed"
        ? await carriedCapsuleCommitment(agentInput.payload, bookPayloads)
        : undefined;
    cited.set(id, {
      capsuleId: id,
      ...(record.capsule_id === id ? {} : { bookRecordId: record.capsule_id }),
      agentInput,
      ...(carriedInput === undefined ? {} : { carriedInput }),
      ...(carriedCapsule === undefined
        ? {}
        : {
            carriedCapsuleId: carriedCapsule.capsuleId,
            carriedInputDigest: carriedCapsule.inputDigest,
          }),
      ...(carriedCapsule !== undefined
        ? { stated: carriedCapsule.stated }
        : agentInput.state === "disclosed" &&
            isObject(agentInput.payload) &&
            agentInput.payload.record_type === PUBLISHED_CAPSULE_RECORD_TYPE
          ? {}
          : { stated: statedTimes(record) }),
      agentOutput: disclosureOf(context, record.capsule_id, "agent_output"),
      ...(agentInputDigest === undefined ? {} : { agentInputDigest }),
      ...(agentOutputDigest === undefined ? {} : { agentOutputDigest }),
      ...(coordinates === undefined ? {} : { logCoordinates: coordinates }),
      cites,
      ...recordTimes(record),
    });
    for (const target of cites) await resolveRecord(target);
  };

  const hasCloseClaim = (document.claims as ObjectValue[]).some(
    (raw) => raw.type === CLOSE_CLAIM,
  );
  const inbound = hasCloseClaim
    ? await inboundCloseLinks(context)
    : new Map<string, readonly CloseLink[]>();

  const claims: ResultClaim[] = [];
  for (const raw of document.claims as ObjectValue[]) {
    const evidence: ClaimEvidenceRef[] = [];
    for (const ref of raw.evidence as ObjectValue[]) {
      const digest = ref.digest as string;
      const carrier = recordsById.has(digest)
        ? undefined
        : await bookCarrier(digest);
      const resolved = recordsById.has(digest) || carrier !== undefined;
      evidence.push({ digest, resolved });
      if (resolved) await resolveRecord(digest, carrier);
    }
    const missing = evidence
      .filter((ref) => !ref.resolved)
      .map((ref) => ref.digest);
    const type = Object.hasOwn(raw, "type")
      ? typeof raw.type === "string"
        ? raw.type
        : JSON.stringify(raw.type)
      : REQUIREMENT_CLAIM;
    const presentation = raw.presentation as ObjectValue;
    const body = type === CLOSE_CLAIM ? closeBody(raw) : undefined;
    let close: ResultClose | undefined;
    if (body !== undefined) {
      const closeRef = body.close_ref.digest as string;
      const asserted = body.close_state;
      const closeRecord = recordsById.get(closeRef);
      const supplied = closeRecord !== undefined;
      const peer = asString(body.peer);
      // The Close's own book and signer: its disclosed header's `book_id`
      // and its local `key_id`. Only a link from another book -- the
      // named peer's -- under another key can make its state.
      const closeHeader =
        closeRecord === undefined
          ? undefined
          : verifiedPayload(context, closeRecord.capsule_id, "agent_input");
      const closeBookId = isObject(closeHeader)
        ? asString(closeHeader.book_id)
        : undefined;
      const closeSigner =
        closeRecord === undefined ? {} : await signerOf(closeRecord);
      const { links, ignored } = counterpartyLinks(
        {
          ...(closeBookId === undefined ? {} : { bookId: closeBookId }),
          ...closeSigner,
        },
        peer,
        inbound.get(closeRef) ?? [],
      );
      const derived = supplied ? deriveCloseState(links) : undefined;
      const peerCloseRef = isObject(body.peer_close_ref)
        ? asString(body.peer_close_ref.digest)
        : undefined;
      const period = isObject(body.period)
        ? {
            start: asString(body.period.start) ?? "",
            end: asString(body.period.end) ?? "",
          }
        : undefined;
      const wanted: CloseLinkType | undefined =
        derived === "AGREED"
          ? "acknowledges"
          : derived === "CONTESTED"
            ? "rebuts"
            : undefined;
      close = {
        closeRef,
        ...(closeBookId === undefined ? {} : { bookId: closeBookId }),
        ...closeSigner,
        ...(period === undefined ? {} : { period }),
        asserted,
        ...(derived === undefined ? {} : { derived }),
        state: derived ?? asserted,
        derivation: derived === undefined ? "producer-asserted" : "recomputed",
        stateMismatch: derived !== undefined && derived !== asserted,
        peerRefMismatch:
          wanted !== undefined &&
          !links.some(
            (link) => link.type === wanted && link.recordId === peerCloseRef,
          ),
        ...(peer === undefined ? {} : { peer }),
        ...(peerCloseRef === undefined ? {} : { peerCloseRef }),
        links,
        ignored,
      };
      if (supplied) await resolveRecord(closeRef);
    }
    // Three rules FAIL a close claim (#140 section 4.1; maintainer's
    // second and third passes, 2026-09-28 / 2026-09-29). The claim's
    // stated sufficiency and verdict are then the producer's words only:
    // never drawn as the claim's, never counted under its verdict.
    //   evidence:       close_ref and peer_close_ref must be among the
    //                   claim's own evidence[] digests -- a claim reports
    //                   only on a Close, and cites only a state-making
    //                   record, that it puts in evidence.
    //   close_state:    the asserted state differs from the one the
    //                   counterparty links read (a self-acknowledged, a
    //                   third-book or a same-key acknowledger makes no
    //                   state, so an asserted AGREED over it fails here).
    //   peer_close_ref: the record it names is not the counterparty
    //                   record carrying the link that makes the state.
    let failedOn: ClaimFailure | undefined;
    let failure: string | undefined;
    if (close !== undefined) {
      const inEvidence = new Set(evidence.map((ref) => ref.digest));
      const outside = (
        [
          ["close_ref", close.closeRef],
          ["peer_close_ref", close.peerCloseRef],
        ] as const
      ).filter(([, digest]) => digest !== undefined && !inEvidence.has(digest));
      if (outside.length > 0) {
        failedOn = "evidence";
        failure = outside
          .map(
            ([field, digest]) =>
              `${field} ${digest} is not among the claim's evidence[] digests`,
          )
          .join("; ");
      } else if (close.stateMismatch) {
        failedOn = "close_state";
        const why =
          close.ignored.length === 0
            ? ""
            : ` (ignored ${close.ignored.map((link) => `${link.type} from ${link.recordId}: ${link.reason}`).join("; ")})`;
        failure = `close_state mismatch: asserted ${close.asserted}, the cited Close's links read ${close.state}${why}`;
      } else if (close.peerRefMismatch) {
        failedOn = "peer_close_ref";
        failure = `peer_close_ref ${close.peerCloseRef ?? "(absent)"} is not the counterparty record carrying the ${close.state === "AGREED" ? "acknowledges" : "rebuts"} link that makes this Close ${close.state}`;
      }
    }
    claims.push({
      id: raw.id as string,
      type,
      recognized: type === REQUIREMENT_CLAIM || body !== undefined,
      contractRef: raw.contract_ref as string,
      requirementRef: raw.requirement_ref as string,
      tier: raw.tier as Tier,
      grade: raw.grade as Grade,
      sufficiency: raw.sufficiency as Sufficiency,
      verdict: raw.verdict as Verdict,
      support:
        evidence.length > 0 && missing.length === 0
          ? "supported"
          : "unsupported",
      evidence,
      missing,
      proofs: (raw.proofs as ObjectValue[]).map((proof) => ({
        kind: proof.kind as ProofKind,
        digest: proof.digest as string,
      })),
      presentation: {
        kind: presentation.kind as ClaimPresentation["kind"],
        status: presentation.status as EvidenceStatus,
        ...(typeof presentation.summary === "string"
          ? { summary: presentation.summary }
          : {}),
        ...(typeof presentation.narrative === "string"
          ? { narrative: presentation.narrative }
          : {}),
        ...(Array.isArray(presentation.evidence)
          ? {
              evidence: (presentation.evidence as ObjectValue[]).map(
                (ref) => ref.digest as string,
              ),
            }
          : {}),
      },
      ...(close === undefined ? {} : { close }),
      failed: failure !== undefined,
      ...(failure === undefined ? {} : { failure }),
      ...(failedOn === undefined ? {} : { failedOn }),
    });
  }

  const aggregate = document.aggregate as ObjectValue;
  const coverage = aggregate.coverage as ObjectValue;
  const buckets = aggregate.buckets as ObjectValue;
  const counts = recomputeCounts(
    document,
    new Set(claims.filter((claim) => claim.failed).map((claim) => claim.id)),
  );
  const rootCoordinates = logCoordinates(memberships, rootRecord.capsule_id);
  return {
    capsuleId: rootRecord.capsule_id,
    member: carried.member,
    form: carried.form,
    generatedAt: document.generated_at as string,
    coverage: counts.coverage,
    statedCoverage: {
      evaluatedPopulation: coverage.evaluated_population as number,
      excludedNotApplicable: coverage.excluded_not_applicable as number,
      unknownCount: coverage.unknown_count as number,
    },
    bucketCounts: counts.bucketCounts,
    countMismatches: counts.mismatches,
    buckets: {
      met: [...(buckets.met as string[])],
      notMet: [...(buckets.not_met as string[])],
      notEvaluable: [...(buckets.not_evaluable as string[])],
    },
    claims,
    records: cited,
    ...(rootCoordinates === undefined
      ? {}
      : { logCoordinates: rootCoordinates }),
    ...recordTimes(rootRecord),
  };
}
