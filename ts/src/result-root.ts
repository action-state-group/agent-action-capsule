import { isHex64 } from "./json.js";
import {
  asString,
  committedDigest,
  disclosurePayload,
  EvidenceGraphError,
  isObject,
  logCoordinates,
  recordTimes,
  resolveDisclosure,
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

/** A record reachable from a claim's evidence, resolved from this bundle. */
export interface CitedRecord extends RecordTimes {
  readonly capsuleId: string;
  readonly agentInput: DisclosureResolution;
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
  readonly coverage: ResultCoverage;
  readonly buckets: ResultBuckets;
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
  for (const member of VERDICTS)
    for (const id of buckets![member] as string[])
      if (verdictById.get(id) !== member)
        findings.push(
          `aggregate.buckets.${member}: ${id} is not a claim with that verdict`,
        );
  return findings;
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
async function resultDocument(
  root: RecordWithId,
  disclosures: ObjectValue,
): Promise<CarriedResult | undefined> {
  for (const member of ["agent_output", "agent_input"] as const) {
    const payload = await disclosurePayload(root, disclosures, member);
    if (!isObject(payload)) continue;
    if (payload.result_version === RESULT_VERSION)
      return { member, form: "payload", document: payload };
    if (member === "agent_input" && payload.record_type === RESULT_RECORD_TYPE)
      return { member, form: "book", document: payload.statement };
  }
  return undefined;
}

/**
 * What the root does carry, for the error that says it is not a Result:
 * a book record header of some other `record_type`, or nothing named.
 */
async function nonResultDescription(
  root: RecordWithId,
  disclosures: ObjectValue,
): Promise<string> {
  const header = await disclosurePayload(root, disclosures, "agent_input");
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
export async function isResultRoot(bundle: unknown): Promise<boolean> {
  if (
    !isObject(bundle) ||
    !Array.isArray(bundle.records) ||
    !isObject(bundle.disclosures)
  )
    return false;
  const root = asString(bundle.root);
  const record = bundle.records.find(
    (candidate): candidate is RecordWithId =>
      isObject(candidate) && candidate.capsule_id === root,
  );
  return (
    record !== undefined &&
    (await resultDocument(record, bundle.disclosures)) !== undefined
  );
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
export async function buildResultRoot(bundle: unknown): Promise<ResultRoot> {
  if (
    !isObject(bundle) ||
    !Array.isArray(bundle.records) ||
    !isObject(bundle.disclosures)
  )
    throw new EvidenceGraphError("bundle must contain records and disclosures");
  const disclosures = bundle.disclosures;
  const records = bundle.records.filter(
    (record): record is RecordWithId =>
      isObject(record) && asString(record.capsule_id) !== undefined,
  );
  const root = asString(bundle.root);
  const rootRecord = records.find((record) => record.capsule_id === root);
  if (rootRecord === undefined)
    throw new EvidenceGraphError("root record not supplied");
  const carried = await resultDocument(rootRecord, disclosures);
  if (carried === undefined)
    throw new EvidenceGraphError(
      `root is not a Result v0: ${await nonResultDescription(rootRecord, disclosures)}`,
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

  const memberships = isObject(bundle.completeness_certificate)
    ? isObject(bundle.completeness_certificate.memberships)
      ? bundle.completeness_certificate.memberships
      : {}
    : {};
  const recordsById = new Map(
    records.map((record) => [record.capsule_id, record]),
  );

  const cited = new Map<string, CitedRecord>();
  const resolveRecord = async (id: string): Promise<void> => {
    if (cited.has(id)) return;
    const record = recordsById.get(id);
    if (record === undefined) return;
    const cites = actedOnReferences(record);
    const coordinates = logCoordinates(memberships, id);
    const agentInputDigest = committedDigest(record, "agent_input");
    const agentOutputDigest = committedDigest(record, "agent_output");
    cited.set(id, {
      capsuleId: id,
      agentInput: await resolveDisclosure(record, disclosures, "agent_input"),
      agentOutput: await resolveDisclosure(record, disclosures, "agent_output"),
      ...(agentInputDigest === undefined ? {} : { agentInputDigest }),
      ...(agentOutputDigest === undefined ? {} : { agentOutputDigest }),
      ...(coordinates === undefined ? {} : { logCoordinates: coordinates }),
      cites,
      ...recordTimes(record),
    });
    for (const target of cites) await resolveRecord(target);
  };

  const claims: ResultClaim[] = [];
  for (const raw of document.claims as ObjectValue[]) {
    const evidence: ClaimEvidenceRef[] = [];
    for (const ref of raw.evidence as ObjectValue[]) {
      const digest = ref.digest as string;
      const resolved = recordsById.has(digest);
      evidence.push({ digest, resolved });
      if (resolved) await resolveRecord(digest);
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
    claims.push({
      id: raw.id as string,
      type,
      recognized: type === REQUIREMENT_CLAIM,
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
    });
  }

  const aggregate = document.aggregate as ObjectValue;
  const coverage = aggregate.coverage as ObjectValue;
  const buckets = aggregate.buckets as ObjectValue;
  const rootCoordinates = logCoordinates(memberships, rootRecord.capsule_id);
  return {
    capsuleId: rootRecord.capsule_id,
    member: carried.member,
    form: carried.form,
    generatedAt: document.generated_at as string,
    coverage: {
      evaluatedPopulation: coverage.evaluated_population as number,
      excludedNotApplicable: coverage.excluded_not_applicable as number,
      unknownCount: coverage.unknown_count as number,
    },
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
