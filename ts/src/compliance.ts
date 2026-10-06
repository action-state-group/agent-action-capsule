import { asString, isObject, type ObjectValue } from "./evidence-graph.js";
import type {
  ComplianceApplicability,
  ComplianceFinding,
  ComplianceObligation,
  CompliancePresentation,
  ComplianceRow,
} from "./compliance-presentation.js";
import {
  findTranscript,
  NOT_STATED,
  readableId,
  type ConversationTranscript,
} from "./outcome-report.js";
import {
  REQUIREMENT_CLAIM,
  type CitedRecord,
  type ResultClaim,
  type ResultRoot,
} from "./result-root.js";

/**
 * The EU AI Act obligations-report card, rendered from a verified Result v0
 * root. Results are stated as counts of sessions per TEST; there is no
 * per-conversation roll-up and no overall compliance percentage anywhere in
 * this model.
 *
 * Where each thing on the page comes from:
 *
 * - From the sealed records (or "not stated"): which obligations and tests
 *   exist (the requirement claims' `requirement_ref`s, `<obligation>.<test>`,
 *   in the order the claims first name them), every verdict and count, the
 *   pack id and version (the claims' one `contract_ref`), each test's wording
 *   (the cited reports' `clause_claim`, when they all agree), each test's
 *   tier (the cited reports' `epistemic_type`, when they all agree), the
 *   contract and judge pin, the rationale, and the transcript (only when the
 *   bundle carries it verifiably; see `findTranscript`).
 * - From the producer's `eu-ai-act-compliance/v1` extension, outside the
 *   signed records: the regulatory mapping -- article, obligation title,
 *   plain-language summary, applicability, method, the not-evaluable note and
 *   the finding templates (severity, recommendation, owner). The page labels
 *   it as the producer's mapping. An obligation the claims name but the
 *   extension does not map reads "not stated"; a test the extension names but
 *   no claim does is not drawn.
 *
 * A finding is drawn only for a test whose finding template exists AND whose
 * sealed not-met count is above zero.
 */

const CLAIM_ID_SEPARATOR = "::";

export type TestVerdict =
  | "met"
  | "not_met"
  | "not_evaluable"
  | "not_applicable"
  | "failed"
  | "unsupported";

/** A test's tier as the sealed reports state it. */
export type TierReading = "judged" | "recomputed" | "not stated" | "mixed";

export interface SealedText {
  readonly text: string;
  readonly source: "sealed" | "unstated" | "mixed";
}

export interface SessionTest {
  readonly criterionId: string;
  readonly verdict: TestVerdict;
  readonly tier: TierReading;
  readonly rationale?: string;
  readonly claim?: ResultClaim;
  readonly reportDigest?: string;
  readonly judgePinDigest?: string;
  readonly contract?: string;
}

export interface Session {
  readonly conversationId: string;
  readonly day: string;
  readonly tests: readonly SessionTest[];
  readonly sourceCapsuleId?: string;
  readonly transcript: ConversationTranscript;
}

export interface ObligationRowModel {
  readonly criterionId: string;
  /** The producer's short label when it maps this test, else the test id made readable. */
  readonly name: string;
  /** The wording the test was run against: the sealed `clause_claim`, or not stated. */
  readonly wording: SealedText;
  readonly tier: TierReading;
  readonly notEvaluableNote?: string;
  readonly finding?: ComplianceFinding;
  readonly metCount: number;
  readonly notMetCount: number;
  readonly notEvaluableCount: number;
  readonly notApplicableCount: number;
  /** verdict bucket -> conversation ids, for the row's own drill-down. failed/unsupported fold into not_met here. */
  readonly sessionsByVerdict: ReadonlyMap<
    "met" | "not_met" | "not_evaluable" | "not_applicable",
    readonly string[]
  >;
}

export interface ObligationModel {
  readonly key: string;
  /** True when the producer's extension maps this obligation; otherwise every mapping field reads not stated. */
  readonly mapped: boolean;
  readonly article: string;
  readonly title: string;
  readonly plain: string;
  readonly judgedTerms: readonly string[];
  readonly applicability: {
    readonly status: ComplianceApplicability["status"] | "not stated";
    readonly note: string;
  };
  readonly method: string;
  readonly rows: readonly ObligationRowModel[];
}

export interface ComplianceFindingModel {
  readonly id: string;
  readonly criterionId: string;
  readonly obligationKey: string;
  readonly article: string;
  readonly testName: string;
  readonly severity: string;
  readonly recommendation: string;
  readonly ownerDue: string;
  readonly sessionIds: readonly string[];
}

export interface ComplianceRunInfo {
  readonly contract?: string;
  readonly judgePinDigest?: string;
  readonly pinned: boolean;
}

export interface CompliancePack {
  /** `<contract_id>` of the one `contract_ref` the counted claims name, else not stated. */
  readonly id: string;
  /** `<version>` of that `contract_ref`, else not stated. */
  readonly version: string;
}

export interface ComplianceModel {
  readonly regulation: string;
  readonly pack: CompliancePack;
  readonly obligations: readonly ObligationModel[];
  readonly sessions: readonly Session[];
  readonly findings: readonly ComplianceFindingModel[];
  readonly totalSessions: number;
  readonly runInfo: ComplianceRunInfo;
  readonly qualityProtocol: CompliancePresentation["qualityProtocol"];
  readonly capsuleId: string;
}

function drawnVerdict(claim: ResultClaim): TestVerdict {
  if (claim.failed) return "failed";
  if (claim.support === "unsupported") return "unsupported";
  return claim.verdict;
}

/**
 * The claim's cited `evaluation-report/v1`, resolved against this bundle.
 * A book record's own agent_input is the book's header, not the report: the
 * report is the agent_input of the capsule the record carries
 * (`carriedInput`, digest-checked by result-root.ts).
 */
function reportPayload(
  records: ReadonlyMap<string, CitedRecord>,
  claim: ResultClaim,
): ObjectValue | undefined {
  const digest = claim.evidence[0]?.digest;
  if (digest === undefined) return undefined;
  const record = records.get(digest);
  if (record === undefined) return undefined;
  const input = record.carriedInput ?? record.agentInput;
  if (input.state !== "disclosed") return undefined;
  return isObject(input.payload) ? input.payload : undefined;
}

function dayOf(payload: ObjectValue | undefined): string {
  const period = asString(payload?.period);
  if (period === undefined) return NOT_STATED;
  const colon = period.indexOf(":");
  return colon === -1 ? period : period.slice(colon + 1);
}

function sealedTier(payload: ObjectValue | undefined): TierReading {
  const type = asString(payload?.epistemic_type);
  if (type === "semantic_judgment") return "judged";
  if (type === "recomputed_determination") return "recomputed";
  return "not stated";
}

function agree<T extends string>(values: readonly T[], none: T, mixed: T): T {
  const distinct = new Set(values.filter((v) => v !== none));
  if (distinct.size === 0) return none;
  return distinct.size === 1 ? [...distinct][0]! : mixed;
}

interface ParsedClaim {
  readonly claim: ResultClaim;
  readonly conversationId: string;
  readonly obligationKey: string;
}

function parseClaim(claim: ResultClaim): ParsedClaim | undefined {
  if (claim.type !== REQUIREMENT_CLAIM) return undefined;
  const sep = claim.id.indexOf(CLAIM_ID_SEPARATOR);
  if (sep <= 0) return undefined;
  const dot = claim.requirementRef.indexOf(".");
  if (dot <= 0 || dot === claim.requirementRef.length - 1) return undefined;
  return {
    claim,
    conversationId: claim.id.slice(0, sep),
    obligationKey: claim.requirementRef.slice(0, dot),
  };
}

/**
 * The claims this card counts, and the pack they belong to. When the claims
 * name one `contract_ref`, all of them. When they name more than one (a
 * bundle carrying a different pack's claims too), only the claims whose test
 * the producer's extension maps, and the pack reads not stated: a different
 * pack's claim is never grouped into this card's sessions.
 */
function countedClaims(
  result: ResultRoot,
  presentation: CompliancePresentation,
): { claims: ParsedClaim[]; pack: CompliancePack } {
  const parsed = result.claims.flatMap((c): ParsedClaim[] => {
    const p = parseClaim(c);
    return p === undefined ? [] : [p];
  });
  const refs = new Set(parsed.map((p) => p.claim.contractRef));
  if (refs.size === 1) {
    const ref = [...refs][0]!;
    const at = ref.lastIndexOf("@");
    return {
      claims: parsed,
      pack: {
        id: at <= 0 ? NOT_STATED : ref.slice(0, at),
        version:
          at <= 0 || at === ref.length - 1 ? NOT_STATED : ref.slice(at + 1),
      },
    };
  }
  const mapped = new Set(
    presentation.obligations.flatMap((o) => o.rows.map((r) => r.criterionId)),
  );
  return {
    claims: parsed.filter((p) => mapped.has(p.claim.requirementRef)),
    pack: { id: NOT_STATED, version: NOT_STATED },
  };
}

function buildSessions(
  result: ResultRoot,
  claims: readonly ParsedClaim[],
  testIds: readonly string[],
): Session[] {
  const byConversation = new Map<string, ResultClaim[]>();
  for (const p of claims) {
    const list = byConversation.get(p.conversationId) ?? [];
    list.push(p.claim);
    byConversation.set(p.conversationId, list);
  }
  const sessions: Session[] = [];
  for (const [conversationId, conversationClaims] of byConversation) {
    const tests: SessionTest[] = [];
    const sources = new Set<string>();
    let day: string = NOT_STATED;
    for (const criterionId of testIds) {
      const claim = conversationClaims.find(
        (c) => c.requirementRef === criterionId,
      );
      if (claim === undefined) {
        // The Result v0 schema has no not_applicable verdict: a test the
        // roll-up left out for this conversation reads not_applicable,
        // never a silent gap.
        tests.push({
          criterionId,
          verdict: "not_applicable",
          tier: "not stated",
        });
        continue;
      }
      const payload = reportPayload(result.records, claim);
      const rationale = asString(payload?.rationale);
      // The Result's own schema-checked contract_ref first, then what the
      // report states.
      const contract =
        claim.contractRef ||
        asString(payload?.contract_ref) ||
        asString(payload?.contract);
      const judgePinDigest = asString(payload?.judge_pin_digest);
      const source = asString(payload?.source_capsule_id);
      if (source !== undefined) sources.add(source);
      if (day === NOT_STATED) day = dayOf(payload);
      const reportDigest = claim.evidence[0]?.digest;
      tests.push({
        criterionId,
        verdict: drawnVerdict(claim),
        tier: sealedTier(payload),
        claim,
        ...(reportDigest === undefined ? {} : { reportDigest }),
        ...(rationale === undefined ? {} : { rationale }),
        ...(contract === undefined ? {} : { contract }),
        ...(judgePinDigest === undefined ? {} : { judgePinDigest }),
      });
    }
    const sourceCapsuleId = sources.size === 1 ? [...sources][0]! : undefined;
    sessions.push({
      conversationId,
      day,
      tests,
      ...(sourceCapsuleId === undefined ? {} : { sourceCapsuleId }),
      transcript: findTranscript(
        result,
        conversationId,
        conversationClaims,
        sourceCapsuleId,
      ),
    });
  }
  sessions.sort((a, b) =>
    a.day === b.day
      ? a.conversationId.localeCompare(b.conversationId)
      : a.day.localeCompare(b.day),
  );
  return sessions;
}

function sealedWording(
  result: ResultRoot,
  claims: readonly ParsedClaim[],
  criterionId: string,
): SealedText {
  const texts = new Set<string>();
  for (const p of claims) {
    if (p.claim.requirementRef !== criterionId) continue;
    const text = asString(reportPayload(result.records, p.claim)?.clause_claim);
    if (text !== undefined) texts.add(text);
  }
  if (texts.size === 1) return { text: [...texts][0]!, source: "sealed" };
  return { text: NOT_STATED, source: texts.size === 0 ? "unstated" : "mixed" };
}

function buildRow(
  criterionId: string,
  mapping: ComplianceRow | undefined,
  wording: SealedText,
  sessions: readonly Session[],
): ObligationRowModel {
  const byVerdict = new Map<
    "met" | "not_met" | "not_evaluable" | "not_applicable",
    string[]
  >([
    ["met", []],
    ["not_met", []],
    ["not_evaluable", []],
    ["not_applicable", []],
  ]);
  const tiers: TierReading[] = [];
  for (const session of sessions) {
    const test = session.tests.find((t) => t.criterionId === criterionId);
    if (test === undefined) continue;
    tiers.push(test.tier);
    // failed/unsupported (a claim that failed verification, or cites
    // evidence this bundle can't resolve) is never read as met: it folds
    // into not_met.
    const bucket =
      test.verdict === "failed" || test.verdict === "unsupported"
        ? "not_met"
        : test.verdict;
    byVerdict.get(bucket)!.push(session.conversationId);
  }
  return {
    criterionId,
    name:
      mapping?.name ??
      readableId(criterionId.slice(criterionId.indexOf(".") + 1)),
    wording,
    tier: agree<TierReading>(tiers, "not stated", "mixed"),
    ...(mapping?.notEvaluableNote === undefined
      ? {}
      : { notEvaluableNote: mapping.notEvaluableNote }),
    ...(mapping?.finding === undefined ? {} : { finding: mapping.finding }),
    metCount: byVerdict.get("met")!.length,
    notMetCount: byVerdict.get("not_met")!.length,
    notEvaluableCount: byVerdict.get("not_evaluable")!.length,
    notApplicableCount: byVerdict.get("not_applicable")!.length,
    sessionsByVerdict: byVerdict,
  };
}

function buildObligation(
  key: string,
  mapping: ComplianceObligation | undefined,
  rows: readonly ObligationRowModel[],
): ObligationModel {
  if (mapping === undefined)
    return {
      key,
      mapped: false,
      article: NOT_STATED,
      title: readableId(key),
      plain: NOT_STATED,
      judgedTerms: [],
      applicability: { status: "not stated", note: NOT_STATED },
      method: NOT_STATED,
      rows,
    };
  return {
    key,
    mapped: true,
    article: mapping.article,
    title: mapping.title,
    plain: mapping.plain,
    judgedTerms: mapping.judgedTerms,
    applicability: mapping.applicability,
    method: mapping.method,
    rows,
  };
}

function buildRunInfo(sessions: readonly Session[]): ComplianceRunInfo {
  const contracts = new Set<string>();
  const pins = new Set<string>();
  for (const session of sessions)
    for (const test of session.tests) {
      if (test.contract !== undefined) contracts.add(test.contract);
      if (test.judgePinDigest !== undefined) pins.add(test.judgePinDigest);
    }
  return {
    ...(contracts.size === 1 ? { contract: [...contracts][0]! } : {}),
    ...(pins.size === 1 ? { judgePinDigest: [...pins][0]! } : {}),
    pinned: contracts.size <= 1 && pins.size <= 1,
  };
}

function buildFindings(
  obligations: readonly ObligationModel[],
): ComplianceFindingModel[] {
  const findings: ComplianceFindingModel[] = [];
  for (const obligation of obligations)
    for (const row of obligation.rows) {
      // Derived from the sealed verdicts: a test with no finding template
      // can never produce one, and a test WITH one produces nothing when
      // its not-met count is zero.
      if (row.finding === undefined || row.notMetCount === 0) continue;
      findings.push({
        id: row.finding.id,
        criterionId: row.criterionId,
        obligationKey: obligation.key,
        article: obligation.article,
        testName: row.name,
        severity: row.finding.severity,
        recommendation: row.finding.recommendation,
        ownerDue: row.finding.ownerDue,
        sessionIds: row.sessionsByVerdict.get("not_met") ?? [],
      });
    }
  return findings;
}

export function buildComplianceModel(
  result: ResultRoot,
  presentation: CompliancePresentation,
): ComplianceModel {
  const { claims, pack } = countedClaims(result, presentation);
  // Obligations and tests in the order the claims first name them.
  const tests = new Map<string, string[]>();
  for (const p of claims) {
    const list = tests.get(p.obligationKey) ?? [];
    if (!list.includes(p.claim.requirementRef))
      list.push(p.claim.requirementRef);
    tests.set(p.obligationKey, list);
  }
  const testIds = [...tests.values()].flat();
  const sessions = buildSessions(result, claims, testIds);
  const mappings = new Map(presentation.obligations.map((o) => [o.key, o]));
  const obligations = [...tests.entries()].map(([key, ids]) => {
    const mapping = mappings.get(key);
    const rowMappings = new Map(
      (mapping?.rows ?? []).map((r) => [r.criterionId, r]),
    );
    return buildObligation(
      key,
      mapping,
      ids.map((id) =>
        buildRow(
          id,
          rowMappings.get(id),
          sealedWording(result, claims, id),
          sessions,
        ),
      ),
    );
  });
  return {
    regulation: presentation.regulation,
    pack,
    obligations,
    sessions,
    findings: buildFindings(obligations),
    totalSessions: sessions.length,
    runInfo: buildRunInfo(sessions),
    qualityProtocol: presentation.qualityProtocol,
    capsuleId: result.capsuleId,
  };
}
