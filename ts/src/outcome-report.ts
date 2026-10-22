import {
  asString,
  isObject,
  zoneStatement,
  type ObjectValue,
  type ZoneStatement,
} from "./evidence-graph.js";
import { jsonDigest } from "./json.js";
import {
  REQUIREMENT_CLAIM,
  type CitedRecord,
  type ResultClaim,
  type ResultRoot,
  type Tier,
} from "./result-root.js";

/**
 * The outcome-report card: a presentation of a verified Result v0 root,
 * never a source of facts. Every number here is recomputed from
 * `result.claims` and the `evaluation-report/v1` / `calibration-summary/v1`
 * records they cite -- never carried as a producer's word, the same rule
 * `result-root.ts` already holds for the generic Result page -- and every
 * term it prints (pack, version, outcome statement, checks, criterion
 * wording) is read from the sealed claims and reports, or shown as "not
 * stated". Nothing here computes money: the card reports outcomes; pricing
 * over them is a product concern outside this package.
 *
 * Claim identity carries the grouping this card needs and Result v0 does
 * not natively have (a claim is one requirement, not one conversation):
 * `id` is `<conversationId>::<checkId>.<criterionId>`, `requirement_ref` is
 * `<checkId>.<criterionId>`. Both are this card's own convention (the
 * producer writes them; evidencebook-skills' `scripts/result_v0.py` does);
 * nothing about Evidence Result v0 requires it, and a bundle that does not
 * follow it simply yields no conversations (see `groupClaims`).
 *
 * DATA SHAPE: the judge seals one `evaluation-report/v1` capsule per case
 * PER CRITERION. Each of this card's claims cites exactly one such report
 * by digest, and that report record itself is this card's whole source for
 * that claim's rationale, structured reason code (when present), judge pin
 * digest, contract id and criterion wording -- see `reportPayload`.
 */

export interface OutcomeReportCriterionTerm {
  readonly id: string;
  /** The criterion id, made readable (`done_in_full` reads "Done in full"); the id itself is shown beside it where it matters. */
  readonly label: string;
  /** Always `NOT_STATED`: the wording a page prints is the sealed `clause_claim` (see `criterionWordings`), never a table of this card's. */
  readonly text: string;
}
export interface OutcomeReportCheckTerm {
  readonly id: string;
  /** The check id, made readable; no sealed record states a check's question. */
  readonly question: string;
  readonly description: string;
  /** An icon NAME the view draws as inline SVG, never an emoji glyph. */
  readonly icon: string;
  readonly criteria: readonly OutcomeReportCriterionTerm[];
}
export interface OutcomeReportPackTerm {
  /** `<contract_id>` of the one `contract_ref` every requirement claim names, else `NOT_STATED`. */
  readonly id: string;
  /** `<version>` of that `contract_ref`, else `NOT_STATED`. */
  readonly version: string;
  /** The outcome requirement's `statement` of a cited Evidence Contract record for that contract, else `NOT_STATED`. */
  readonly outcomeStatement: string;
  /** When the terms were locked. No Evidence Contract field states it, so this is `NOT_STATED`. */
  readonly locked: string;
  /** Whether the counterparty agreed to these terms. Nothing this card reads shows that (a countersignature over the contract would), so this is `NOT_STATED`. */
  readonly agreement: string;
  /** How this card resolves a conversation: its own roll-up rule, stated so a reader can check it, not a term of any agreement. */
  readonly resolutionRule: string;
}
/**
 * The terms the page prints, all read from the bundle: the claims, the
 * reports they cite and, when cited, the Evidence Contract record. Nothing
 * in this object is hard-coded about any domain; what the bundle does not
 * state reads `NOT_STATED`.
 */
export interface OutcomeReportTerms {
  readonly pack: OutcomeReportPackTerm;
  readonly checks: readonly OutcomeReportCheckTerm[];
  /**
   * Human labels for a structured `reason_code`. No sealed record states
   * them yet, so this is empty and `missedReasonGroups` names the failing
   * criterion instead: an unlabelled code never reaches the page as raw
   * text, and no label is invented for one.
   */
  readonly reasonCodes: Readonly<Record<string, string>>;
}

/** What the page prints for a term no sealed record in the bundle states. */
export const NOT_STATED = "not stated";

/** The roll-up rule this card applies (see `rollUp`), printed verbatim. */
export const RESOLUTION_RULE =
  "A conversation resolves only when every criterion judged for it is met or does not apply, and at least one is met.";

/** `done_in_full` reads "Done in full". */
export function readableId(id: string): string {
  const words = id.replaceAll("_", " ").replaceAll("-", " ").trim();
  return words.length === 0 ? id : words[0]!.toUpperCase() + words.slice(1);
}

const CLAIM_ID_SEPARATOR = "::";

export type ConversationVerdict = "met" | "not_met" | "not_evaluable";

export interface ConversationCriterion {
  readonly checkId: string;
  readonly criterionId: string;
  /**
   * Absent only for `verdict: "not_applicable"`: Evidence Result v0's Verdict
   * enum has no not_applicable value (evidencebook-skills' result_v0.py
   * excludes such a criterion from `claims[]` entirely -- see
   * `aggregate.coverage.excluded_not_applicable` -- never emits a claim with
   * that verdict), so there is no claim object to carry for it here either.
   * Every other verdict always has one, `out_of_scope` included (Result v0
   * section 4.2: a judged claim, counted on its own, never as not
   * applicable).
   */
  readonly claim?: ResultClaim;
  /** The claim's own drawn verdict: `failed`/`unsupported` never read as `met` (see `drawnVerdict`). `not_applicable` carries no claim (see `claim` above) -- a reader is still shown WHICH criterion, just not its rationale/tier/evidence, none of which the Result v0 document carries for an excluded criterion. */
  readonly verdict:
    | ConversationVerdict
    | "failed"
    | "unsupported"
    | "not_applicable"
    | "out_of_scope";
  readonly rationale?: string;
  /** Present only when the cited evaluation-report/v1 record carries one; never inferred from rationale text. */
  readonly reasonCode?: string;
  /**
   * The judge's per-verdict probabilities and confidence, read back out of the
   * sealed `rationale` text (`probabilities={...}, confidence=...`), which is
   * where the judge pipeline wrote them: the report carries no structured
   * probability field. Absent when the sealed text does not carry that form --
   * never estimated.
   */
  readonly probabilities?: Readonly<Record<string, number>>;
  readonly confidence?: number;
  /** The cited report: the id the claim cites (the report capsule) and, for a book-form record, the book record carrying it. */
  readonly reportCapsuleId?: string;
  readonly reportRecordId?: string;
  /** The case record the report says it judged (`source_capsule_id`), as the sealed report states it. */
  readonly sourceCapsuleId?: string;
  /** The judge pin digest the cited report states, when it is disclosed: a judge ran on this criterion. */
  readonly judgePinDigest?: string;
  /**
   * What the bundle shows of the cited report (see `ReportState`); present
   * whenever `claim` is. Whether a judge ran on this criterion is then
   * known only for a disclosed report (yes when it states a judge pin, no
   * when it does not); for a withheld, mismatched or unreadable report it
   * is unknown, and a view says so rather than guess.
   */
  readonly reportState?: ReportState;
  /**
   * The criterion's wording exactly as the cited report sealed it
   * (`evaluation-report/v1.clause_claim`: the text the judge was given), read
   * only when the report's own `clause_id` names this criterion.
   */
  readonly clauseClaim?: string;
}

/**
 * Where the wording a reader is shown for one criterion comes from.
 *
 * - `sealed`: every cited report of this criterion that states a
 *   `clause_claim` states this same text -- the wording the judge was given,
 *   sealed in the evidence;
 * - `unstated`: no cited report states one (an older pipeline, or a
 *   criterion judged not_applicable everywhere, which Result v0 never
 *   cites); the page says "not stated";
 * - `mixed`: cited reports state different wordings; none is picked and the
 *   disagreement is labelled.
 */
export interface CriterionWording {
  readonly text: string;
  readonly source: "sealed" | "unstated" | "mixed";
}

/**
 * The judge's probabilities, parsed from the sealed rationale text only. The
 * pattern is the one evidencebook-skills' Jev judge writes
 * ("probabilities={'met': 0.89, ...}, confidence=0.86"); anything else yields
 * nothing.
 */
export function parseJudgeProbabilities(rationale: string | undefined): {
  probabilities?: Record<string, number>;
  confidence?: number;
} {
  if (rationale === undefined) return {};
  const out: { probabilities?: Record<string, number>; confidence?: number } =
    {};
  const block = /probabilities=\{([^}]*)\}/u.exec(rationale);
  if (block !== null) {
    // Every entry must be a whole `'name': <number>` pair whose number is a
    // whole token (sign, fraction, signed exponent, then a delimiter) in
    // [0, 1]. One entry that is not -- `'met': 1e+2`, `1.2e2`, text -- makes
    // the whole set unreadable: a partial set would misstate the judge.
    const probabilities: Record<string, number> = {};
    let readable = true;
    const entries = block[1]!.split(",").map((e) => e.trim());
    for (const entry of entries) {
      if (entry === "" && entries.length === 1) {
        readable = false;
        break;
      }
      const match = new RegExp(`^'([a-z_]+)':\\s*(${NUMBER_TOKEN})$`, "u").exec(
        entry,
      );
      const value = match === null ? Number.NaN : Number(match[2]);
      if (match === null || !isProbability(value)) {
        readable = false;
        break;
      }
      probabilities[match[1]!] = value;
    }
    if (readable && Object.keys(probabilities).length > 0)
      out.probabilities = probabilities;
  }
  const confidence = new RegExp(
    `confidence=(${NUMBER_TOKEN})(?=[\\s,.;)]*$|[\\s,;)])`,
    "u",
  ).exec(rationale);
  if (confidence !== null) {
    const value = Number(confidence[1]);
    if (isProbability(value)) out.confidence = value;
  }
  return out;
}

/** One whole JSON-style number: optional sign, digits, fraction, signed exponent. */
const NUMBER_TOKEN =
  "[+-]?(?:[0-9]+(?:\\.[0-9]+)?|\\.[0-9]+)(?:[eE][+-]?[0-9]+)?";

function isProbability(value: number): boolean {
  return Number.isFinite(value) && value >= 0 && value <= 1;
}

export interface TranscriptToolCall {
  readonly name: string;
  /** The call's arguments as sealed, rendered as JSON text. */
  readonly arguments: string;
}
export interface TranscriptTurn {
  readonly role: string;
  readonly content?: string;
  readonly toolCalls: readonly TranscriptToolCall[];
}
/**
 * What the agent did, as the bundle carries it. `verified` only when a cited
 * book record carries a transcript whose agent_input commitment equals the
 * commitment of the case capsule the judge's reports name
 * (`source_capsule_id`), and whose sealed case identity is this
 * conversation; `mismatch` when a transcript is cited but one of those links
 * fails (it is then not drawn); `absent` when none is cited.
 *
 * `cited` is the weaker statement for a case read from the claims because
 * every report is withheld (`Conversation.caseFrom` "claims"): the
 * transcript is the case the claims cite -- the case record's own disclosed
 * input, or a different cited record committing to the same input -- but no
 * report in the bundle names the case the judge read, so this is never
 * "the conversation the judge read". It is never `verified`.
 */
export interface ConversationTranscript {
  readonly state: "verified" | "cited" | "mismatch" | "absent";
  readonly turns?: readonly TranscriptTurn[];
  readonly transcriptRecordId?: string;
  readonly caseRecordId?: string;
  readonly inputDigest?: string;
  readonly reason?: string;
}

/**
 * Which date a conversation is counted under: the record's own date when
 * the bundle carries one verifiably, labelled as such, so a relying party
 * knows a capsule sealed today may report on an earlier day.
 *
 * - `source`: the judged case record is backfilled (`provenance_mode.mode`
 *   "backfilled", AAC -05 "Provenance mode and backfilled records"): the
 *   source's own `source_asserted_at`, as given -- "source says",
 *   self-attested, never witnessed by being carried;
 * - `record`: the judged case record states no backfill: its own
 *   `timestamp`, as given -- when its producer says the action occurred;
 * - `judged`: no case record the reports name is cited and checks out, or
 *   it states no usable time: the day the judge's reports were sealed under
 *   (`period`), the card's behaviour before record dating.
 *
 * The day is the first ten characters of the stated time exactly as written
 * (`YYYY-MM-DD`): no zone is assigned and nothing is converted. `stated` is
 * the full value verbatim; `zone` marks a time that states no zone.
 */
export interface ConversationDate {
  readonly basis: "source" | "record" | "judged";
  readonly date: string;
  readonly stated?: string;
  readonly zone?: ZoneStatement;
  /** `provenance_mode.imported_at`, as given, when the record is backfilled. */
  readonly importedAt?: string;
}

export interface Conversation {
  readonly conversationId: string;
  readonly transcript: ConversationTranscript;
  /** The case record every cited report of this conversation names (`source_capsule_id`), only when they all agree; when every report is withheld, the one case capsule every claim cites (`caseFrom: "claims"`). */
  readonly sourceCapsuleId?: string;
  /** Where `sourceCapsuleId` was read: the disclosed reports, or the claims' own citations when the reports are withheld. */
  readonly caseFrom?: "reports" | "claims";
  /** The date this conversation is counted under (`dated.date`), see `ConversationDate`. */
  readonly day: string;
  readonly dated: ConversationDate;
  /** The day its judge's reports were sealed under (`period`), whatever `dated` says. */
  readonly judgedDay: string;
  readonly criteria: readonly ConversationCriterion[];
  readonly checkVerdicts: ReadonlyMap<string, ConversationVerdict>;
  /** AND over every check, recomputed here (see `rollUp`) -- never asserted by any record. */
  readonly verdict: ConversationVerdict;
}

export interface OutcomeReportDay {
  readonly date: string;
  readonly policyChanged: string | null;
  readonly conversations: readonly Conversation[];
  readonly resolvedCount: number;
  /** The days this day's conversations were judged and sealed under, sorted. */
  readonly judgedDays: readonly string[];
}

/** How the calendar and period are dated across the whole bundle. */
export interface OutcomeReportDating {
  /** `mixed` when conversations are dated on different bases. */
  readonly basis: ConversationDate["basis"] | "mixed";
  readonly counts: Readonly<Record<ConversationDate["basis"], number>>;
  /** Every day a cited report was sealed under, sorted. */
  readonly judgedDays: readonly string[];
  /** Conversations whose stated time carries no zone. */
  readonly zoneNotStated: number;
}

/**
 * The judge pin's components as the cited reports carry them
 * (`evaluation-report/v1.judge_pin`: exactly what `capsulectl judge pin` was
 * given). Shown only beside a digest they were checked against: see
 * `verifyJudgePin`.
 */
export interface JudgePinComponents {
  readonly modelId: string;
  readonly modelVersion?: string;
  readonly promptDigest: string;
  readonly axesDigest: string;
  readonly samplingParams?: ObjectValue;
}

export interface OutcomeReportRunInfo {
  /**
   * The `<contract_id>@<version>` every requirement claim of the Result names
   * (`claims[].contract_ref`, the headline document's own word, schema-checked
   * by `result build`), when every one agrees. Only when no claim names one is
   * it read from the cited reports instead (`contract_ref`, else `contract`).
   */
  readonly contract?: string;
  /** `capsulectl judge pin`'s combined digest over model id + judge prompt + axes + sampling params -- the one judge-identity value the real pipeline actually seals (never split back into model id / prompt digest / axes digest unless the reports carry the components, see `judgePin`). */
  readonly judgePinDigest?: string;
  /** The pin's components, when every judged report carries the same ones. */
  readonly judgePin?: JudgePinComponents;
  /**
   * Whether `judgePin` recomputes to `judgePinDigest` (JSON-DIGEST over
   * model_id, model_version, sampling_params, prompt_digest, axes_digest --
   * capsule-cli's `judgePinDigest`). Undefined until `verifyJudgePin` has run,
   * or when there are no components to check. A view draws the components
   * only when this is true.
   */
  readonly judgePinRecomputes?: boolean;
  /** False when the cited reports disagree on contract or judge pin; `contract`/`judgePinDigest` are then omitted entirely, never drawn from an arbitrary one of the disagreeing values. */
  readonly pinned: boolean;
  /** Claims whose cited report the bundle carries but does not disclose (`reportState` withheld), of `reportsCited`: the judge pin and rationale live in those reports, so a view says "withheld", never "not stated". */
  readonly reportsWithheld?: number;
  /** Claims whose cited report is supplied but does not match its commitment (`reportState` mismatch): never read, and never counted as withheld. */
  readonly reportsMismatched?: number;
  /** Claims whose cited report is disclosed but is not an object (`reportState` unreadable): never counted as withheld. */
  readonly reportsUnreadable?: number;
  /** Claims whose cited report capsule is missing or does not check out (`reportState` invalid): never counted as withheld. */
  readonly reportsInvalid?: number;
  /** Claims citing a report the bundle carries; present whenever any of the four counts above is. */
  readonly reportsCited?: number;
}

export interface CalibrationSample {
  readonly conversationId: string;
  readonly aiVerdict: string;
  readonly humanVerdict: string;
  readonly note?: string;
  readonly agrees: boolean;
}
export interface CalibrationWeek {
  readonly weekId: string;
  readonly from?: string;
  readonly to?: string;
  readonly k: number;
  readonly n: number;
  readonly sample: readonly CalibrationSample[];
  readonly claim: ResultClaim;
}

export interface MissedReasonGroup {
  readonly key: string;
  readonly label: string;
  /** True when every claim in the group carried a structured reason_code WITH a human label in `terms.reasonCodes`; false when this is a criterion-only fallback group. */
  readonly structured: boolean;
  readonly conversations: readonly Conversation[];
}

export interface OutcomeReportOptions {
  readonly percentages: boolean;
  /** Producer's plain-text note, labelled not evidence -- see `OutcomeReportPresentation`. */
  readonly producerNote?: {
    readonly title: string;
    readonly lines: readonly string[];
  };
  /** Criteria the producer marks as edited, with badge text -- see `OutcomeReportPresentation`. */
  readonly editedCriteria?: readonly {
    readonly criterion: string;
    readonly badge: string;
  }[];
}

/** A criterion's tier as observed across every claim citing it: `Tier` when every claim citing this criterion agrees, `"unknown"` when no claim cites it at all, `"mixed"` when cited claims disagree -- the tier a reader is shown is never picked arbitrarily when the records themselves don't settle it. */
export type CriterionTierReading = Tier | "unknown" | "mixed";

export interface OutcomeReportModel {
  readonly terms: OutcomeReportTerms;
  readonly options: OutcomeReportOptions;
  readonly days: readonly OutcomeReportDay[];
  readonly dating: OutcomeReportDating;
  readonly conversations: readonly Conversation[];
  readonly runInfo: OutcomeReportRunInfo;
  readonly calibration: readonly CalibrationWeek[];
  readonly checkPassCounts: ReadonlyMap<string, number>;
  readonly missedReasons: readonly MissedReasonGroup[];
  /** requirementRef (`<checkId>.<criterionId>`) -> tier, read from the claims that cite it -- never from `terms`. See `CriterionTierReading`. */
  readonly criterionTiers: ReadonlyMap<string, CriterionTierReading>;
  /** requirementRef -> the wording to print, from the sealed reports when they state it. See `CriterionWording`. */
  readonly criterionWording: ReadonlyMap<string, CriterionWording>;
  readonly resolvedCount: number;
  readonly missedCount: number;
  readonly totalCount: number;
  readonly heldCount: number;
  readonly addedCount: number;
  /** Criterion judgments read as not_applicable (see `ConversationCriterion.verdict`) across every conversation -- never folded into `missedCount`, consistent with the roll-up's own rule that not_applicable counts as passing. */
  readonly notApplicableCount: number;
  /** Criterion judgments read as out_of_scope (Result v0 section 4.2), counted apart from not_applicable. */
  readonly outOfScopeCount: number;
  readonly capsuleId: string;
}

function parseClaimGrouping(
  claim: ResultClaim,
):
  | { conversationId: string; checkId: string; criterionId: string }
  | undefined {
  const sep = claim.id.indexOf(CLAIM_ID_SEPARATOR);
  if (sep === -1) return undefined;
  const conversationId = claim.id.slice(0, sep);
  const dot = claim.requirementRef.indexOf(".");
  if (dot === -1) return undefined;
  return {
    conversationId,
    checkId: claim.requirementRef.slice(0, dot),
    criterionId: claim.requirementRef.slice(dot + 1),
  };
}

/** The claim's verdict as a reader may draw it: never `met` for a failed or unsupported claim. */
function drawnVerdict(claim: ResultClaim): ConversationCriterion["verdict"] {
  if (claim.failed) return "failed";
  if (claim.support === "unsupported") return "unsupported";
  return claim.verdict;
}

/**
 * The claim's one cited `evaluation-report/v1` record, disclosed and
 * resolved against this bundle -- this card's whole source for that
 * criterion's rationale, reason code, judge pin and contract id. Unlike
 * v1, there is no day-level wrapper to unwrap: the cited record IS the
 * per-criterion judgment.
 */
function reportPayload(
  records: ReadonlyMap<string, CitedRecord>,
  claim: ResultClaim,
): ObjectValue | undefined {
  const digest = claim.evidence[0]?.digest;
  if (digest === undefined) return undefined;
  const record = records.get(digest);
  if (record === undefined) return undefined;
  // An evidence-book record's own agent_input is the book's header, not the
  // report: the report is the agent_input of the capsule that record carries,
  // resolved (and digest-checked link by link) by result-root.ts's
  // resolveCarriedInput. A book-form record whose carried input is withheld
  // yields nothing -- the header is never mistaken for the report.
  const input = record.carriedInput ?? record.agentInput;
  if (input.state !== "disclosed") return undefined;
  return isObject(input.payload) ? input.payload : undefined;
}

function dayOf(payload: ObjectValue | undefined): string {
  const period = asString(payload?.period);
  if (period === undefined) return "unknown";
  const colon = period.indexOf(":");
  return colon === -1 ? period : period.slice(colon + 1);
}

const STATED_DAY = /^(\d{4}-\d{2}-\d{2})/u;

/**
 * The day a claim's report was sealed. The report's own `period` when the
 * report is disclosed; otherwise, only when the report is withheld
 * (`reportState` "withheld"), the `timestamp` its capsule states, read only
 * when the bundle carries that capsule and it checks out (`stated`, see
 * result-root.ts). A bundle that withholds the reports (no transcripts
 * attached) still carries the report capsules, so its period is no longer
 * "unknown". A disclosed report without a `period`, and a mismatched,
 * unreadable or invalid report, get no fallback: undefined, as before.
 */
export function reportSealedDay(
  records: ReadonlyMap<string, CitedRecord>,
  claim: ResultClaim,
): string | undefined {
  const period = asString(reportPayload(records, claim)?.period);
  if (period !== undefined) {
    const colon = period.indexOf(":");
    return colon === -1 ? period : period.slice(colon + 1);
  }
  if (reportState(records, claim) !== "withheld") return undefined;
  const digest = claim.evidence[0]?.digest;
  const timestamp =
    digest === undefined ? undefined : records.get(digest)?.stated?.timestamp;
  return timestamp === undefined ? undefined : STATED_DAY.exec(timestamp)?.[1];
}

/**
 * What this bundle lets a reader see of one claim's cited report:
 *
 * - `disclosed`: the report is disclosed, checks against its commitment and
 *   is a JSON object;
 * - `withheld`: the bundle carries the report capsule but not its original
 *   (a bundle built without transcripts);
 * - `mismatch`: an original is supplied but does not match the commitment
 *   (`disclosure_mismatch`), so it is not read;
 * - `unreadable`: disclosed, but not an object a report could be;
 * - `invalid`: the claim cites an evidence-book record whose report capsule
 *   is missing or does not check out (the header commits to no payloads,
 *   the capsule bytes are absent or fail their digest, or the capsule
 *   commits to no hex agent_input digest): nothing was withheld, the
 *   report is broken;
 * - `not_carried`: the claim cites no report the bundle carries.
 *
 * Only `withheld` means "the reports are withheld": a mismatched,
 * unreadable or invalid report is a different statement, and a view says
 * so. Only `withheld` reports let the claims name the case
 * (`claimsCitedCase`) or date the judging (`reportSealedDay`).
 */
export type ReportState =
  | "disclosed"
  | "withheld"
  | "mismatch"
  | "unreadable"
  | "invalid"
  | "not_carried";

export function reportState(
  records: ReadonlyMap<string, CitedRecord>,
  claim: ResultClaim,
): ReportState {
  const digest = claim.evidence[0]?.digest;
  const record = digest === undefined ? undefined : records.get(digest);
  if (record === undefined) return "not_carried";
  const input = record.carriedInput ?? record.agentInput;
  switch (input.state) {
    case "disclosed":
      return isObject(input.payload) ? "disclosed" : "unreadable";
    case "withheld":
      // A book record's carried report resolves "withheld" also when its
      // capsule is missing or fails its checks (resolveCarriedInput). Only
      // a checked carried capsule (carriedCapsuleId) is truly withheld.
      return record.carriedInput !== undefined &&
        record.carriedCapsuleId === undefined
        ? "invalid"
        : "withheld";
    case "disclosure_mismatch":
      return "mismatch";
    default:
      return "unreadable";
  }
}

/**
 * The `action_id`s a benchmark case capsule for this conversation declares
 * itself under: `urn:<conversation id>`, and for a model-named id
 * (`benchmark:domain:<model>:task-N:trial-T`) also the model-less
 * `urn:benchmark:domain:task-N:trial-T` the backfill seals. This is the
 * case model's own identity (evidencebook-skills' backfill), read from the
 * checked carried capsule, never from a hint.
 */
function caseActionIds(conversationId: string): string[] {
  const ids = [`urn:${conversationId}`];
  const named = /^([^:]+):([^:]+):.+:(task-[^:]+:trial-[^:]+)$/u.exec(
    conversationId,
  );
  if (named !== null) ids.push(`urn:${named[1]}:${named[2]}:${named[3]}`);
  return ids;
}

/**
 * Whether `record` is this conversation's case record: an evidence-book
 * record whose carried capsule checks out (`carriedCapsuleId`) and declares
 * itself this conversation's case (`carriedActionId`, see `caseActionIds`).
 * A shared transcript, policy, rubric or judge-pin capsule declares
 * something else and is never one.
 */
function isCaseRecordFor(
  record: CitedRecord | undefined,
  conversationId: string,
): record is CitedRecord & { carriedCapsuleId: string } {
  return (
    record?.carriedCapsuleId !== undefined &&
    record.carriedActionId !== undefined &&
    caseActionIds(conversationId).includes(record.carriedActionId)
  );
}

/**
 * The case capsule the claims of one conversation cite beside their reports
 * (`evidence[1..]`), read only when EVERY claim's report is withheld (see
 * `reportState`): the Result's own signed claims then say which case they
 * were judged on. It is a case only when all of these hold:
 *
 * - the record is a case record for this conversation (`isCaseRecordFor`:
 *   a checked carried capsule whose own `action_id` declares this case);
 * - each claim cites exactly one such record, and every claim the same one;
 * - no claim of any other conversation (of `allClaims`, by its
 *   conversation id) cites it.
 *
 * Otherwise there is no case (undefined), and a view says "not stated",
 * never a guess. A conversation whose reports are disclosed but name no case
 * (an older pipeline without `source_capsule_id`), or whose reports are
 * mismatched, unreadable or invalid, gets nothing here either. A case read
 * here is the one the claims cite, not one a report names: which
 * conversation the judge read is not shown (`findTranscript` "cited").
 */
export function claimsCitedCase(
  records: ReadonlyMap<string, CitedRecord>,
  conversationId: string,
  claims: readonly ResultClaim[],
  allClaims: readonly ResultClaim[] = claims,
): string | undefined {
  if (
    claims.length === 0 ||
    !claims.every((claim) => reportState(records, claim) === "withheld")
  )
    return undefined;
  let found: string | undefined;
  for (const claim of claims) {
    const cases = new Set<string>();
    for (const ref of claim.evidence.slice(1)) {
      const record = records.get(ref.digest);
      if (isCaseRecordFor(record, conversationId))
        cases.add(record.carriedCapsuleId);
    }
    if (cases.size !== 1) return undefined;
    const only = [...cases][0]!;
    if (found !== undefined && found !== only) return undefined;
    found = only;
  }
  if (found === undefined) return undefined;
  for (const claim of allClaims) {
    const sep = claim.id.indexOf(CLAIM_ID_SEPARATOR);
    if (sep === -1 || claim.id.slice(0, sep) === conversationId) continue;
    for (const ref of claim.evidence)
      if (
        ref.digest === found ||
        records.get(ref.digest)?.carriedCapsuleId === found
      )
        return undefined;
  }
  return found;
}

/**
 * Of these claims' cited reports (`total`: the claims citing a report the
 * bundle carries): how many are withheld, and how many the bundle supplies
 * but cannot be read (`mismatched`: the original does not match its
 * commitment; `unreadable`: disclosed but not an object; `invalid`: the
 * report capsule is missing or does not check out). Only `withheld` counts
 * as withheld. See `reportState`.
 */
export function withheldReports(
  records: ReadonlyMap<string, CitedRecord>,
  claims: readonly ResultClaim[],
): {
  withheld: number;
  mismatched: number;
  unreadable: number;
  invalid: number;
  total: number;
} {
  let withheld = 0;
  let mismatched = 0;
  let unreadable = 0;
  let invalid = 0;
  let total = 0;
  for (const claim of claims) {
    const state = reportState(records, claim);
    if (state === "not_carried") continue;
    total += 1;
    if (state === "withheld") withheld += 1;
    else if (state === "mismatch") mismatched += 1;
    else if (state === "unreadable") unreadable += 1;
    else if (state === "invalid") invalid += 1;
  }
  return { withheld, mismatched, unreadable, invalid, total };
}

/**
 * The case record the reports name, when this bundle cites it and its
 * capsule checks out: a book record carrying it (`carriedCapsuleId`) or the
 * plain record itself. Only its `stated` times are read.
 */
function caseRecord(
  result: ResultRoot,
  claims: readonly ResultClaim[],
  sourceCapsuleId: string | undefined,
): CitedRecord | undefined {
  if (sourceCapsuleId === undefined) return undefined;
  for (const claim of claims)
    for (const ref of claim.evidence) {
      const record = result.records.get(ref.digest);
      if (record === undefined || record.stated === undefined) continue;
      if (
        record.carriedCapsuleId === sourceCapsuleId ||
        (record.carriedCapsuleId === undefined &&
          record.bookRecordId === undefined &&
          record.capsuleId === sourceCapsuleId)
      )
        return record;
    }
  return undefined;
}

/** See `ConversationDate`. */
function conversationDate(
  record: CitedRecord | undefined,
  judgedDay: string,
): ConversationDate {
  const judged: ConversationDate = { basis: "judged", date: judgedDay };
  const stated = record?.stated;
  if (stated === undefined) return judged;
  const mode = stated.provenanceMode;
  if (asString(mode?.mode) === "backfilled") {
    const source = asString(mode?.source_asserted_at);
    const day = source === undefined ? undefined : STATED_DAY.exec(source)?.[1];
    if (source === undefined || day === undefined) return judged;
    const importedAt = asString(mode?.imported_at);
    return {
      basis: "source",
      date: day,
      stated: source,
      zone: zoneStatement(source),
      ...(importedAt === undefined ? {} : { importedAt }),
    };
  }
  const timestamp = stated.timestamp;
  const day =
    timestamp === undefined ? undefined : STATED_DAY.exec(timestamp)?.[1];
  if (timestamp === undefined || day === undefined) return judged;
  return {
    basis: "record",
    date: day,
    stated: timestamp,
    zone: zoneStatement(timestamp),
  };
}

function checksById(
  terms: OutcomeReportTerms,
): ReadonlyMap<string, OutcomeReportCheckTerm> {
  return new Map(terms.checks.map((check) => [check.id, check]));
}

/** AND over a set of drawn per-criterion verdicts: met only when every one is met (never on a failed/unsupported claim); not_met when any is; otherwise not_evaluable. */
function rollUp(
  verdicts: readonly (
    | ConversationVerdict
    | "failed"
    | "unsupported"
    | "not_applicable"
    | "out_of_scope"
  )[],
): ConversationVerdict {
  // Absent is never pass: a check or conversation with no claims at all
  // (the producer submitted none of its criteria) is not_evaluable, never
  // a vacuous met.
  if (verdicts.length === 0) return "not_evaluable";
  if (
    verdicts.some(
      (v) => v === "not_met" || v === "failed" || v === "unsupported",
    )
  )
    return "not_met";
  if (verdicts.some((v) => v === "not_evaluable")) return "not_evaluable";
  // not_applicable counts as passing beside a met ("does not apply" is still
  // an answer), but never alone: a check or conversation whose criteria are
  // ALL not_applicable had nothing checked, so it is not_evaluable, never a
  // vacuous met -- the same rule as evidencebook-skills' roll-up. An
  // out_of_scope judgment ("did not arise") rolls up the same way, and is
  // counted on its own (outOfScopeCount), never as not_applicable.
  if (!verdicts.some((v) => v === "met")) return "not_evaluable";
  return "met";
}

/**
 * The conversation ids a sealed case payload answers to. A case that names
 * the agent model (`case.agent_model`, the four-model backfills) is
 * `benchmark:domain:<model>:task-N:trial-T`; the older form without the model
 * is still accepted, so earlier bundles keep matching. The id only picks the
 * candidate: the transcript is tied to the judged case by digest either way.
 */
function sealedCaseIds(payload: ObjectValue): string[] {
  const c = isObject(payload.case) ? payload.case : undefined;
  if (c === undefined) return [];
  const parts = [c.benchmark, c.domain, c.task_id, c.trial].map((v) =>
    typeof v === "string" || typeof v === "number" ? String(v) : undefined,
  );
  if (parts.some((v) => v === undefined)) return [];
  const ids = [`${parts[0]}:${parts[1]}:task-${parts[2]}:trial-${parts[3]}`];
  const model = asString(c.agent_model);
  if (model !== undefined && model.length > 0)
    ids.unshift(
      `${parts[0]}:${parts[1]}:${model}:task-${parts[2]}:trial-${parts[3]}`,
    );
  return ids;
}

function transcriptTurns(payload: ObjectValue): TranscriptTurn[] | undefined {
  const interaction = isObject(payload.agent_interaction)
    ? payload.agent_interaction
    : undefined;
  if (interaction === undefined || !Array.isArray(interaction.messages))
    return undefined;
  return interaction.messages.flatMap((m): TranscriptTurn[] => {
    if (!isObject(m)) return [];
    const role = asString(m.role) ?? "unknown";
    const content = asString(m.content);
    const calls = Array.isArray(m.tool_calls) ? m.tool_calls : [];
    return [
      {
        role,
        ...(content === undefined ? {} : { content }),
        toolCalls: calls.flatMap((call): TranscriptToolCall[] =>
          isObject(call)
            ? [
                {
                  name: asString(call.name) ?? "unnamed",
                  arguments: JSON.stringify(call.arguments ?? null),
                },
              ]
            : [],
        ),
      },
    ];
  });
}

/** See `ConversationTranscript`. Reads only cited records, never anything uncited. */
export function findTranscript(
  result: ResultRoot,
  conversationId: string,
  claims: readonly ResultClaim[],
  sourceCapsuleId: string | undefined,
  caseFrom: "reports" | "claims" = "reports",
): ConversationTranscript {
  const records: CitedRecord[] = [];
  const seen = new Set<string>();
  for (const claim of claims)
    for (const ref of claim.evidence.slice(1)) {
      if (seen.has(ref.digest)) continue;
      seen.add(ref.digest);
      const record = result.records.get(ref.digest);
      if (record !== undefined) records.push(record);
    }
  const carriers = records.filter(
    (r) =>
      r.carriedInput?.state === "disclosed" &&
      isObject(r.carriedInput.payload) &&
      transcriptTurns(r.carriedInput.payload) !== undefined,
  );
  if (carriers.length === 0) return { state: "absent" };
  if (sourceCapsuleId === undefined)
    return {
      state: "mismatch",
      reason: "the reports do not agree on one case record",
    };
  const caseRecord = records.find(
    (r) => r.carriedCapsuleId === sourceCapsuleId,
  );
  if (caseRecord?.carriedInputDigest === undefined)
    return {
      state: "mismatch",
      reason: `the case record the reports name (${sourceCapsuleId}) is not cited, so the transcript cannot be tied to it`,
    };
  if (caseFrom === "claims") {
    // No report names the case: the claims do. Draw the case's own
    // conversation, as "cited", never "verified". The case record's own
    // disclosed input is its conversation (checked against its commitment
    // when resolved); a different record counts only when it commits to the
    // same input. A record is never compared with itself as a tie.
    const ordered = [
      ...carriers.filter((c) => c === caseRecord),
      ...carriers.filter((c) => c !== caseRecord),
    ];
    for (const carrier of ordered) {
      const payload = (carrier.carriedInput as { payload: ObjectValue })
        .payload;
      if (
        (carrier === caseRecord ||
          carrier.carriedInputDigest === caseRecord.carriedInputDigest) &&
        sealedCaseIds(payload).includes(conversationId)
      )
        return {
          state: "cited",
          turns: transcriptTurns(payload)!,
          transcriptRecordId: carrier.capsuleId,
          caseRecordId: caseRecord.capsuleId,
          inputDigest: caseRecord.carriedInputDigest,
          reason:
            "the claims cite this case; the judge's reports are withheld, so which conversation the judge read is not shown",
        };
    }
    return {
      state: "mismatch",
      reason:
        "a cited transcript does not commit to the same input as the case record the claims cite",
    };
  }
  for (const carrier of carriers) {
    const payload =
      carrier.carriedInput!.state === "disclosed"
        ? (carrier.carriedInput as { payload: ObjectValue }).payload
        : undefined;
    if (payload === undefined) continue;
    if (
      carrier.carriedInputDigest === caseRecord.carriedInputDigest &&
      sealedCaseIds(payload).includes(conversationId)
    )
      return {
        state: "verified",
        turns: transcriptTurns(payload)!,
        transcriptRecordId: carrier.capsuleId,
        caseRecordId: caseRecord.capsuleId,
        inputDigest: caseRecord.carriedInputDigest,
      };
  }
  return {
    state: "mismatch",
    reason:
      "a cited transcript does not commit to the same input as the case record the judge read",
  };
}

function groupClaims(
  result: ResultRoot,
  terms: OutcomeReportTerms,
): { conversations: Conversation[]; days: Map<string, Conversation[]> } {
  const order = checksById(terms);
  const byConversation = new Map<string, ResultClaim[]>();
  for (const claim of result.claims) {
    // Calibration claims (type "calibration") and anything else this card
    // does not recognize are never grouped as a conversation criterion,
    // enforced on the claim's own type -- not left to coincide with the
    // id-shape check below, which a future claim type could otherwise
    // satisfy by accident.
    if (claim.type !== REQUIREMENT_CLAIM) continue;
    const grouping = parseClaimGrouping(claim);
    if (grouping === undefined || !order.has(grouping.checkId)) continue;
    const list = byConversation.get(grouping.conversationId) ?? [];
    list.push(claim);
    byConversation.set(grouping.conversationId, list);
  }
  const conversations: Conversation[] = [];
  const byDay = new Map<string, Conversation[]>();
  for (const [conversationId, claims] of byConversation) {
    const criteria: ConversationCriterion[] = [];
    for (const check of terms.checks) {
      for (const criterion of check.criteria) {
        const claim = claims.find(
          (candidate) =>
            candidate.requirementRef === `${check.id}.${criterion.id}`,
        );
        if (claim === undefined) {
          // No claim for this criterion in this conversation. Evidence Result
          // v0 has no verdict value for not_applicable (agent-action-capsule's
          // spec/evidence-result-v0.md: "excluded from the evaluated
          // population entirely... never as a claim") -- evidencebook-skills'
          // result_v0.py therefore seals a not_applicable criterion with no
          // claim at all, counted only in the bundle-wide
          // aggregate.coverage.excluded_not_applicable. A conversation this
          // card groups at all is already a complete one (the judge pipeline
          // refuses an incomplete case before it reaches a Result v0
          // document), so a missing criterion here is read as
          // not_applicable, not as an unjudged gap -- consistent with the
          // roll-up. This is the one place that
          // attribution cannot be independently verified from this document
          // alone (no digest, no rationale survives the exclusion); flagged
          // here as the known limit, not hidden.
          criteria.push({
            checkId: check.id,
            criterionId: criterion.id,
            verdict: "not_applicable",
          });
          continue;
        }
        // Result v0 section 4.3: a claim not yet in force is readiness only,
        // outside the population; this deprecated card draws no criterion
        // for it, unless it failed verification: a failure is still drawn.
        if (claim.later && !claim.failed) continue;
        const judgment = reportPayload(result.records, claim);
        const rationale = judgment ? asString(judgment.rationale) : undefined;
        const reasonCode = judgment
          ? asString(judgment.reason_code)
          : undefined;
        const sourceCapsuleId = judgment
          ? asString(judgment.source_capsule_id)
          : undefined;
        const judgePinDigest = judgment
          ? asString(judgment.judge_pin_digest)
          : undefined;
        const clauseClaim =
          judgment !== undefined &&
          asString(judgment.clause_id) === `${check.id}.${criterion.id}`
            ? asString(judgment.clause_claim)
            : undefined;
        const { probabilities, confidence } =
          parseJudgeProbabilities(rationale);
        const cited = claim.evidence[0]?.digest;
        const record =
          cited === undefined ? undefined : result.records.get(cited);
        criteria.push({
          checkId: check.id,
          criterionId: criterion.id,
          claim,
          verdict: drawnVerdict(claim),
          ...(rationale === undefined ? {} : { rationale }),
          ...(reasonCode === undefined ? {} : { reasonCode }),
          ...(probabilities === undefined ? {} : { probabilities }),
          ...(confidence === undefined ? {} : { confidence }),
          ...(cited === undefined ? {} : { reportCapsuleId: cited }),
          ...(record?.bookRecordId === undefined
            ? {}
            : { reportRecordId: record.bookRecordId }),
          ...(sourceCapsuleId === undefined ? {} : { sourceCapsuleId }),
          ...(judgePinDigest === undefined ? {} : { judgePinDigest }),
          reportState: reportState(result.records, claim),
          ...(clauseClaim === undefined || clauseClaim.trim() === ""
            ? {}
            : { clauseClaim }),
        });
      }
    }
    const firstClaim = criteria.find((c) => c.claim !== undefined)?.claim;
    const judgedDay =
      (firstClaim === undefined
        ? undefined
        : reportSealedDay(result.records, firstClaim)) ?? dayOf(undefined);
    const checkVerdicts = new Map<string, ConversationVerdict>();
    for (const check of terms.checks) {
      const forCheck = criteria.filter((c) => c.checkId === check.id);
      checkVerdicts.set(check.id, rollUp(forCheck.map((c) => c.verdict)));
    }
    const sources = new Set(
      criteria.flatMap((c) =>
        c.sourceCapsuleId === undefined ? [] : [c.sourceCapsuleId],
      ),
    );
    // No report names the case because every report is withheld: take the
    // one case capsule the claims themselves cite, when they agree on one.
    // claimsCitedCase refuses otherwise (disclosed reports that name no
    // case, mismatched reports), so the case then stays unresolved and the
    // transcript is never verified against a case no report named.
    let caseFrom: Conversation["caseFrom"] = "reports";
    if (sources.size === 0) {
      const cited = claimsCitedCase(
        result.records,
        conversationId,
        claims,
        result.claims,
      );
      if (cited !== undefined) {
        sources.add(cited);
        caseFrom = "claims";
      }
    }
    const dated = conversationDate(
      caseRecord(
        result,
        claims,
        sources.size === 1 ? [...sources][0]! : undefined,
      ),
      judgedDay,
    );
    const date = dated.date;
    const conversation: Conversation = {
      conversationId,
      transcript: findTranscript(
        result,
        conversationId,
        claims,
        sources.size === 1 ? [...sources][0]! : undefined,
        caseFrom,
      ),
      ...(sources.size === 1
        ? { sourceCapsuleId: [...sources][0]!, caseFrom }
        : {}),
      day: date,
      dated,
      judgedDay,
      criteria,
      checkVerdicts,
      verdict: rollUp(criteria.map((c) => c.verdict)),
    };
    conversations.push(conversation);
    const dayList = byDay.get(date) ?? [];
    dayList.push(conversation);
    byDay.set(date, dayList);
  }
  conversations.sort((a, b) =>
    a.day === b.day
      ? a.conversationId.localeCompare(b.conversationId)
      : a.day.localeCompare(b.day),
  );
  return { conversations, days: byDay };
}

/** Every criterion's tier, read from the claims that cite it -- see `CriterionTierReading`. A criterion with zero claims anywhere in this bundle reads "unknown"; one whose claims disagree reads "mixed", never an arbitrary pick. */
function criterionTiers(
  terms: OutcomeReportTerms,
  conversations: readonly Conversation[],
): Map<string, CriterionTierReading> {
  const tiers = new Map<string, CriterionTierReading>();
  for (const check of terms.checks) {
    for (const criterion of check.criteria) {
      const ref = `${check.id}.${criterion.id}`;
      const seen = new Set<Tier>();
      for (const conversation of conversations)
        for (const c of conversation.criteria)
          if (
            c.checkId === check.id &&
            c.criterionId === criterion.id &&
            c.claim !== undefined
          )
            seen.add(c.claim.tier);
      tiers.set(
        ref,
        seen.size === 0 ? "unknown" : seen.size === 1 ? [...seen][0]! : "mixed",
      );
    }
  }
  return tiers;
}

function pinComponents(value: unknown): JudgePinComponents | undefined {
  if (!isObject(value)) return undefined;
  const modelId = asString(value.model_id);
  const promptDigest = asString(value.prompt_digest);
  const axesDigest = asString(value.axes_digest);
  if (
    modelId === undefined ||
    promptDigest === undefined ||
    axesDigest === undefined
  )
    return undefined;
  const modelVersion = asString(value.model_version);
  return {
    modelId,
    ...(modelVersion === undefined ? {} : { modelVersion }),
    promptDigest,
    axesDigest,
    ...(isObject(value.sampling_params)
      ? { samplingParams: value.sampling_params }
      : {}),
  };
}

/** The exact object capsule-cli's `judgePinDigest` digests: absent model_version and sampling_params are JSON null there, never omitted. */
function pinPreimage(pin: JudgePinComponents): ObjectValue {
  return {
    model_id: pin.modelId,
    model_version: pin.modelVersion ?? null,
    sampling_params: pin.samplingParams ?? null,
    prompt_digest: pin.promptDigest,
    axes_digest: pin.axesDigest,
  } as ObjectValue;
}

function buildRunInfo(
  result: ResultRoot,
  conversations: readonly Conversation[],
): OutcomeReportRunInfo {
  const claimContracts = new Set<string>();
  const reportContracts = new Set<string>();
  const pins = new Set<string>();
  const components = new Map<string, JudgePinComponents>();
  for (const conversation of conversations) {
    for (const criterion of conversation.criteria) {
      const claim = criterion.claim;
      if (claim === undefined) continue;
      claimContracts.add(claim.contractRef);
      const payload = reportPayload(result.records, claim);
      const contract =
        asString(payload?.contract_ref) ?? asString(payload?.contract);
      if (contract !== undefined) reportContracts.add(contract);
      const pin = asString(payload?.judge_pin_digest);
      if (pin !== undefined) pins.add(pin);
      const parts = pinComponents(payload?.judge_pin);
      if (parts !== undefined)
        components.set(JSON.stringify(pinPreimage(parts)), parts);
    }
  }
  const contracts = claimContracts.size > 0 ? claimContracts : reportContracts;
  // Vacuously pinned on zero conversations, same as v1's every()-on-empty
  // rule: "no cited runs disagree" is true when there are none to disagree.
  const pinned = contracts.size <= 1 && pins.size <= 1 && components.size <= 1;
  const counted = withheldReports(
    result.records,
    conversations.flatMap((c) =>
      c.criteria.flatMap((cr) => (cr.claim === undefined ? [] : [cr.claim])),
    ),
  );
  return {
    ...(counted.withheld > 0 ? { reportsWithheld: counted.withheld } : {}),
    ...(counted.mismatched > 0
      ? { reportsMismatched: counted.mismatched }
      : {}),
    ...(counted.unreadable > 0
      ? { reportsUnreadable: counted.unreadable }
      : {}),
    ...(counted.invalid > 0 ? { reportsInvalid: counted.invalid } : {}),
    ...(counted.withheld +
      counted.mismatched +
      counted.unreadable +
      counted.invalid >
    0
      ? { reportsCited: counted.total }
      : {}),
    ...(contracts.size === 1 ? { contract: [...contracts][0]! } : {}),
    ...(pins.size === 1 ? { judgePinDigest: [...pins][0]! } : {}),
    ...(pins.size === 1 && components.size === 1
      ? { judgePin: [...components.values()][0]! }
      : {}),
    pinned,
  };
}

/**
 * Recompute the judge pin digest from the components the reports carry and
 * record whether it matches the sealed `judge_pin_digest`. Async (WebCrypto)
 * and therefore separate from `buildOutcomeReportModel`; the view runs it
 * before drawing "What ran", and draws the components only on a match.
 */
export async function verifyJudgePin(
  runInfo: OutcomeReportRunInfo,
): Promise<OutcomeReportRunInfo> {
  if (runInfo.judgePin === undefined || runInfo.judgePinDigest === undefined)
    return runInfo;
  let recomputes = false;
  try {
    recomputes =
      (await jsonDigest(pinPreimage(runInfo.judgePin))) ===
      runInfo.judgePinDigest;
  } catch {
    recomputes = false;
  }
  return { ...runInfo, judgePinRecomputes: recomputes };
}

function buildCalibration(result: ResultRoot): CalibrationWeek[] {
  const weeks: CalibrationWeek[] = [];
  for (const claim of result.claims) {
    if (claim.type !== "calibration") continue;
    const payload = reportPayload(result.records, claim);
    if (payload === undefined) continue;
    const weekId = asString(payload.week);
    if (weekId === undefined) continue;
    const sample = (
      Array.isArray(payload.sample) ? payload.sample : []
    ).flatMap((entry): CalibrationSample[] => {
      if (!isObject(entry)) return [];
      const conversationId = asString(entry.conversation_id);
      const aiVerdict = asString(entry.ai_verdict);
      const humanVerdict = asString(entry.human_verdict);
      if (
        conversationId === undefined ||
        aiVerdict === undefined ||
        humanVerdict === undefined
      )
        return [];
      const note = asString(entry.note);
      return [
        {
          conversationId,
          aiVerdict,
          humanVerdict,
          ...(note === undefined ? {} : { note }),
          agrees: aiVerdict === humanVerdict,
        },
      ];
    });
    // k and n are recomputed from the enumerable sample -- never taken from
    // the record's own stated `agreement` field, the same rule
    // result-root.ts's recomputeCounts already holds for every other
    // headline count in this codebase (a stated aggregate that disagrees
    // with the enumerable data it summarizes is exactly the failure mode
    // the Result page's recompute already fixes for buckets/coverage).
    const k = sample.filter((entry) => entry.agrees).length;
    const n = sample.length;
    const from = asString(payload.from);
    const to = asString(payload.to);
    weeks.push({
      weekId,
      ...(from === undefined ? {} : { from }),
      ...(to === undefined ? {} : { to }),
      k,
      n,
      sample,
      claim,
    });
  }
  weeks.sort((a, b) => a.weekId.localeCompare(b.weekId));
  return weeks;
}

/** From the calibration samples only -- never from the claims' own verdicts, which is where "resolved" is recomputed from above. */
function heldAndAdded(weeks: readonly CalibrationWeek[]): {
  held: number;
  added: number;
} {
  let held = 0,
    added = 0;
  for (const week of weeks)
    for (const sample of week.sample) {
      if (sample.aiVerdict === "met" && sample.humanVerdict !== "met")
        held += 1;
      else if (sample.aiVerdict !== "met" && sample.humanVerdict === "met")
        added += 1;
    }
  return { held, added };
}

function missedReasonGroups(
  terms: OutcomeReportTerms,
  conversations: readonly Conversation[],
): MissedReasonGroup[] {
  const labelOf = (checkId: string, criterionId: string): string => {
    const check = terms.checks.find((c) => c.id === checkId);
    const criterion = check?.criteria.find((c) => c.id === criterionId);
    return criterion === undefined
      ? `${checkId}.${criterionId}`
      : `${criterion.label} (${check!.question})`;
  };
  // A reason_code is only ever shown by its human label, read from
  // terms.reasonCodes -- a code with no entry there is treated exactly like
  // no code at all (REASONS: never a raw code on the page, whatever the
  // record carries).
  const labelledReasonCode = (code: string | undefined): string | undefined =>
    code === undefined ? undefined : terms.reasonCodes[code];
  const groups = new Map<string, Conversation[]>();
  const structured = new Map<string, boolean>();
  const labels = new Map<string, string>();
  for (const conversation of conversations) {
    if (conversation.verdict === "met") continue;
    // A genuine miss (not_met/failed/unsupported) outranks a mere
    // not_evaluable: grouping prefers to name what actually failed. Only
    // when nothing failed outright -- the conversation missed solely
    // because a criterion couldn't be judged -- does a not_evaluable
    // criterion become the reason. Falling back to criteria[0] here would
    // pick an arbitrary MET criterion whenever the true cause is
    // not_evaluable and isn't the first one in check order.
    const failing = conversation.criteria.filter(
      (c) =>
        c.verdict === "not_met" ||
        c.verdict === "failed" ||
        c.verdict === "unsupported",
    );
    const notEvaluable = conversation.criteria.filter(
      (c) => c.verdict === "not_evaluable",
    );
    const first = failing[0] ?? notEvaluable[0];
    if (first === undefined) continue;
    const label = labelledReasonCode(first.reasonCode);
    const key =
      label !== undefined
        ? first.reasonCode!
        : `${first.checkId}.${first.criterionId}`;
    const list = groups.get(key) ?? [];
    list.push(conversation);
    groups.set(key, list);
    structured.set(key, label !== undefined);
    labels.set(key, label ?? labelOf(first.checkId, first.criterionId));
  }
  return [...groups.entries()]
    .map(([key, convos]) => ({
      key,
      label: labels.get(key)!,
      structured: structured.get(key)!,
      conversations: convos,
    }))
    .sort((a, b) => b.conversations.length - a.conversations.length);
}

/**
 * Every criterion's wording, from the sealed evidence only: the
 * `clause_claim` its cited reports carry when they all agree, else "not
 * stated" (or the disagreement, labelled). See `CriterionWording`.
 */
export function criterionWordings(
  terms: OutcomeReportTerms,
  conversations: readonly Conversation[],
): Map<string, CriterionWording> {
  const out = new Map<string, CriterionWording>();
  for (const check of terms.checks) {
    for (const criterion of check.criteria) {
      const sealed = new Set<string>();
      for (const conversation of conversations)
        for (const c of conversation.criteria)
          if (
            c.checkId === check.id &&
            c.criterionId === criterion.id &&
            c.clauseClaim !== undefined
          )
            sealed.add(c.clauseClaim);
      const ref = `${check.id}.${criterion.id}`;
      if (sealed.size === 1)
        out.set(ref, { text: [...sealed][0]!, source: "sealed" });
      else
        out.set(ref, {
          text: NOT_STATED,
          source: sealed.size === 0 ? "unstated" : "mixed",
        });
    }
  }
  return out;
}

/** The one Evidence Contract record the bundle cites for `contractRef`, when it does. */
function citedContract(
  result: ResultRoot,
  contractRef: string,
): ObjectValue | undefined {
  for (const record of result.records.values()) {
    const input = record.carriedInput ?? record.agentInput;
    if (input.state !== "disclosed" || !isObject(input.payload)) continue;
    const doc = input.payload;
    const id = asString(doc.id);
    const version = asString(doc.version);
    if (
      id !== undefined &&
      version !== undefined &&
      Array.isArray(doc.requirements) &&
      `${id}@${version}` === contractRef
    )
      return doc;
  }
  return undefined;
}

/**
 * The terms this card prints, read from the bundle (see
 * `OutcomeReportTerms`): checks and criteria from the requirement claims'
 * `requirement_ref`s, in the order the claims first name them; pack id and
 * version from the one `contract_ref` they all name; the outcome statement
 * from a cited Evidence Contract record for that contract. Anything else
 * reads `NOT_STATED`.
 */
export function readOutcomeReportTerms(result: ResultRoot): OutcomeReportTerms {
  const checks = new Map<string, string[]>();
  const contracts = new Set<string>();
  for (const claim of result.claims) {
    if (claim.type !== REQUIREMENT_CLAIM) continue;
    const grouping = parseClaimGrouping(claim);
    if (grouping === undefined) continue;
    contracts.add(claim.contractRef);
    const criteria = checks.get(grouping.checkId) ?? [];
    if (!criteria.includes(grouping.criterionId))
      criteria.push(grouping.criterionId);
    checks.set(grouping.checkId, criteria);
  }
  const contractRef = contracts.size === 1 ? [...contracts][0]! : undefined;
  const at = contractRef?.lastIndexOf("@") ?? -1;
  const contract =
    contractRef === undefined ? undefined : citedContract(result, contractRef);
  const outcome = Array.isArray(contract?.requirements)
    ? contract.requirements.find(
        (r): r is ObjectValue =>
          isObject(r) &&
          r.profile === "outcome" &&
          asString(r.statement) !== undefined,
      )
    : undefined;
  return {
    pack: {
      id:
        contractRef === undefined || at <= 0
          ? NOT_STATED
          : contractRef.slice(0, at),
      version:
        contractRef === undefined || at <= 0 || at === contractRef.length - 1
          ? NOT_STATED
          : contractRef.slice(at + 1),
      outcomeStatement: asString(outcome?.statement) ?? NOT_STATED,
      locked: NOT_STATED,
      agreement: NOT_STATED,
      resolutionRule: RESOLUTION_RULE,
    },
    checks: [...checks.entries()].map(([id, criteria]) => ({
      id,
      question: readableId(id),
      description: NOT_STATED,
      icon: "check",
      criteria: criteria.map((criterionId) => ({
        id: criterionId,
        label: readableId(criterionId),
        text: NOT_STATED,
      })),
    })),
    reasonCodes: {},
  };
}

function buildDating(
  conversations: readonly Conversation[],
): OutcomeReportDating {
  const counts = { source: 0, record: 0, judged: 0 };
  for (const c of conversations) counts[c.dated.basis] += 1;
  const used = (Object.keys(counts) as ConversationDate["basis"][]).filter(
    (basis) => counts[basis] > 0,
  );
  return {
    basis:
      used.length === 1 ? used[0]! : used.length === 0 ? "judged" : "mixed",
    counts,
    judgedDays: [...new Set(conversations.map((c) => c.judgedDay))].sort(),
    zoneNotStated: conversations.filter((c) => c.dated.zone === "not-stated")
      .length,
  };
}

export function buildOutcomeReportModel(
  result: ResultRoot,
  options: OutcomeReportOptions,
): OutcomeReportModel {
  const terms = readOutcomeReportTerms(result);
  const { conversations, days } = groupClaims(result, terms);
  const dayList: OutcomeReportDay[] = [...days.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([date, convos]) => ({
      date,
      // No evaluation-report/v1 record carries a day-level policy-change
      // flag (that was a property of v1's invented day wrapper, which this
      // real data shape has no analogue for) -- absent is never pass, so
      // this reads null until a real day-summary record exists to cite.
      policyChanged: null,
      conversations: convos,
      resolvedCount: convos.filter((c) => c.verdict === "met").length,
      judgedDays: [...new Set(convos.map((c) => c.judgedDay))].sort(),
    }));
  const calibration = buildCalibration(result);
  const { held, added } = heldAndAdded(calibration);
  const checkPassCounts = new Map<string, number>();
  for (const check of terms.checks)
    checkPassCounts.set(
      check.id,
      conversations.filter((c) => c.checkVerdicts.get(check.id) === "met")
        .length,
    );
  const resolvedCount = conversations.filter((c) => c.verdict === "met").length;
  const countOf = (verdict: ConversationCriterion["verdict"]): number =>
    conversations.reduce(
      (sum, c) =>
        sum + c.criteria.filter((cr) => cr.verdict === verdict).length,
      0,
    );
  const notApplicableCount = countOf("not_applicable");
  const outOfScopeCount = countOf("out_of_scope");
  return {
    terms,
    options,
    days: dayList,
    dating: buildDating(conversations),
    conversations,
    runInfo: buildRunInfo(result, conversations),
    calibration,
    checkPassCounts,
    missedReasons: missedReasonGroups(terms, conversations),
    criterionTiers: criterionTiers(terms, conversations),
    criterionWording: criterionWordings(terms, conversations),
    resolvedCount,
    missedCount: conversations.length - resolvedCount,
    totalCount: conversations.length,
    heldCount: held,
    addedCount: added,
    notApplicableCount,
    outOfScopeCount,
    capsuleId: result.capsuleId,
  };
}
