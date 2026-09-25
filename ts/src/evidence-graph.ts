import { isHex64, jsonDigest } from "./json.js";

/**
 * How a record's disclosable member resolved against the bundle overlay:
 * `disclosed` -- a value was supplied and hashes to the committed digest;
 * `withheld` -- no value was supplied; `disclosure_mismatch` -- a value was
 * supplied but does not hash to the committed digest (or nothing was
 * committed to compare it with). Only `disclosed` ever carries a payload.
 */
export type DisclosureState = "disclosed" | "withheld" | "disclosure_mismatch";
export type DisclosureField = "agent_input" | "agent_output";

/**
 * The times a record states, each kept exactly as written -- never parsed,
 * normalised, or assigned a zone. `sealTime` is the capsule's `timestamp`
 * (the registration time inside the digest commitment, base profile
 * "Identity and parties"). `actionTime` is when the agent acted, read from
 * the record's `occurred_at` when the producer states one: a backfilled
 * record keeps its source's own time there, and the seal time never stands
 * in for it. `provenanceMode` is the record's `provenance_mode` as written
 * (for example `backfilled`).
 */
export interface RecordTimes {
  sealTime?: string;
  actionTime?: string;
  provenanceMode?: string;
}

/**
 * Whether a written time states its zone. A timestamp with a `Z` or
 * `+HH:MM` designator is `stated`; a bare `YYYY-MM-DD` names a day, not an
 * instant, and is `date-only`; anything else -- a naive timestamp such as
 * `2026-08-26T05:34:57.860343`, or a string that is not a timestamp at all --
 * is `not-stated`. The view prints every time verbatim and marks
 * `not-stated` ones; nothing here assigns a zone.
 */
export type ZoneStatement = "stated" | "not-stated" | "date-only";

export const zoneStatement = (value: string): ZoneStatement =>
  /^\d{4}-\d{2}-\d{2}$/u.test(value)
    ? "date-only"
    : /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})$/u.test(
          value,
        )
      ? "stated"
      : "not-stated";

export interface ActNode extends RecordTimes {
  capsuleId: string;
  caseId: string;
  turnIdx: number;
  agentInput?: unknown;
  agentOutput?: unknown;
  agentInputDisclosure: DisclosureState;
  agentOutputDisclosure: DisclosureState;
  agentInputDigest?: string;
  agentOutputDigest?: string;
  logCoordinates?: { logId: string; seq: number; leafIndex: number };
}
export interface AxisJudgment {
  axisId: string;
  outcomeId: string;
  status: "pass" | "fail" | "not_applicable" | "unjudgeable";
  rationale: string;
  evidenceIds: string[];
}
export interface CaseNode {
  caseId: string;
  taskId: string;
  trial: number;
  aggregate: "pass" | "fail" | null;
  acts: ActNode[];
  judgments: AxisJudgment[];
}
export interface Outcome {
  outcomeId: string;
  role: "required" | "optional";
  aggregate: "pass" | "fail" | null;
}
export interface RatingNode {
  capsuleId: string;
  reportId: string;
  verdict: "pass" | "fail" | "unsure";
}
export interface ReportNode extends RecordTimes {
  capsuleId: string;
  /** The report's `date`, exactly as the producer wrote it. */
  date: string;
  /**
   * 1-based position of the report in its period. Taken from the payload's
   * `day` when stated; otherwise derived from `date` as UTC calendar days
   * since the earliest dated report in the graph, plus one. A `date` may be
   * a bare YYYY-MM-DD or an RFC 3339 timestamp; a timestamp without a zone
   * designator is read as UTC. Absent only when the payload states no `day`
   * and its `date` is neither.
   */
  day?: number;
  outcomes: Outcome[];
  cases: CaseNode[];
  ratings: RatingNode[];
  withheldActs: ActNode[];
  logCoordinates?: { logId: string; seq: number; leafIndex: number };
}
export interface SummaryNode {
  capsuleId: string;
  crossCaseAggregation?: string;
  perAxis?: unknown;
  counts?: { reports: number; uniqueCases: number };
  cohort?: unknown;
}
export interface CalibrationNode {
  capsuleId: string;
  periodWindow?: unknown;
  confusion?: unknown;
  agreement?: unknown;
  correctedRate?: unknown;
  correctedRateCi?: unknown;
}
export interface EvidenceGraph {
  aggregate: SummaryNode;
  reports: ReportNode[];
  calibration?: CalibrationNode;
}

export class EvidenceGraphError extends Error {}

export type ObjectValue = Record<string, unknown>;
export type RecordWithId = ObjectValue & { capsule_id: string };
export type ResolvedLogCoordinates = {
  logId: string;
  seq: number;
  leafIndex: number;
};

export const isObject = (value: unknown): value is ObjectValue =>
  value !== null && typeof value === "object" && !Array.isArray(value);

export const asString = (value: unknown): string | undefined =>
  typeof value === "string" ? value : undefined;

const asNumber = (value: unknown): number | undefined =>
  typeof value === "number" && Number.isFinite(value) ? value : undefined;

const objectOrEmpty = (value: unknown): ObjectValue =>
  isObject(value) ? value : {};

/**
 * Days since the Unix epoch for the UTC calendar day a report's `date` names;
 * undefined when it is not a calendar date or timestamp.
 *
 * Accepted: a bare `YYYY-MM-DD`, or an RFC 3339 timestamp `YYYY-MM-DDTHH:MM`
 * with optional seconds, fraction, and a `Z` or `+HH:MM` designator. A
 * timestamp with a designator is read in that offset and folded to UTC.
 *
 * Naive timestamps are read as UTC; the producer should stamp Z -- see
 * provenance. The real corpus mixes naive timestamps
 * (`2026-08-26T05:34:57.860343`) with `Z` ones, and `new Date(string)` would
 * read a naive one in the reader's local zone, so the same report could land
 * on a different day depending on where the graph is built. Nothing here
 * goes through the local-time parser: the fields are taken from the string
 * and the day is fixed arithmetic on UTC.
 */
const calendarDay = (date: string): number | undefined => {
  const match =
    /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?(Z|[+-]\d{2}:\d{2})?)?$/u.exec(
      date,
    );
  if (match === null) return undefined;
  const year = Number(match[1]),
    month = Number(match[2]),
    day = Number(match[3]),
    hour = Number(match[4] ?? "0"),
    minute = Number(match[5] ?? "0"),
    second = Number(match[6] ?? "0");
  const designator = match[7];
  if (hour > 23 || minute > 59 || second > 60) return undefined;
  const midnight = Date.UTC(year, month - 1, day);
  const parsed = new Date(midnight);
  if (
    parsed.getUTCFullYear() !== year ||
    parsed.getUTCMonth() !== month - 1 ||
    parsed.getUTCDate() !== day
  )
    return undefined;
  const offsetMinutes =
    designator === undefined || designator === "Z"
      ? 0
      : (designator.startsWith("-") ? -1 : 1) *
        (Number(designator.slice(1, 3)) * 60 + Number(designator.slice(4, 6)));
  if (Math.abs(offsetMinutes) > 23 * 60 + 59) return undefined;
  const instant =
    midnight +
    ((hour * 60 + minute) * 60 + second) * 1_000 -
    offsetMinutes * 60_000;
  return Math.floor(instant / 86_400_000);
};

/** The times a record states, verbatim; a member is absent when not stated. */
export const recordTimes = (record: RecordWithId): RecordTimes => {
  const sealTime = asString(record.timestamp);
  const actionTime = asString(record.occurred_at);
  const provenanceMode = asString(record.provenance_mode);
  return {
    ...(sealTime === undefined ? {} : { sealTime }),
    ...(actionTime === undefined ? {} : { actionTime }),
    ...(provenanceMode === undefined ? {} : { provenanceMode }),
  };
};

/** The digest a record committed to for a disclosable member, if any. */
export const committedDigest = (
  record: RecordWithId,
  field: DisclosureField,
): string | undefined =>
  asString(
    objectOrEmpty(objectOrEmpty(record.model_attestation).compute_attestation)[
      `${field}_digest`
    ],
  );

export interface DisclosureResolution {
  readonly state: DisclosureState;
  /** Present only when `state` is `disclosed`. */
  readonly payload?: unknown;
}

/**
 * Resolve one disclosable member of a record from the bundle's disclosure
 * overlay. The overlay is keyed by `capsule_id` (Evidence Bundle spec,
 * "Bundle-Level Disclosures"); a payload digest is never a lookup key, so a
 * supplied entry under some other name is simply not this record's
 * disclosure. A supplied value is accepted only when its JSON-DIGEST equals
 * the digest the record itself committed to -- the same DE-3 rule the bundle
 * verifier applies -- so a forged or edited value never leaves this function
 * as a payload: it resolves to `disclosure_mismatch` and the view shows the
 * committed digest instead.
 */
export const resolveDisclosure = async (
  record: RecordWithId,
  disclosures: ObjectValue,
  field: DisclosureField,
): Promise<DisclosureResolution> => {
  const entry = disclosures[record.capsule_id];
  if (!isObject(entry) || !Object.hasOwn(entry, field))
    return { state: "withheld" };
  const committed = committedDigest(record, field);
  if (isHex64(committed)) {
    try {
      if ((await jsonDigest(entry[field])) === committed)
        return { state: "disclosed", payload: entry[field] };
    } catch {
      /* a value JCS cannot render cannot be the committed preimage */
    }
  }
  return { state: "disclosure_mismatch" };
};

/** The verified payload for a member, or undefined when withheld or mismatched. */
export const disclosurePayload = async (
  record: RecordWithId,
  disclosures: ObjectValue,
  field: DisclosureField,
): Promise<unknown> =>
  (await resolveDisclosure(record, disclosures, field)).payload;

export const logCoordinates = (
  memberships: ObjectValue,
  capsuleId: string,
): ResolvedLogCoordinates | undefined => {
  const membership = memberships[capsuleId];
  if (!isObject(membership) || !isObject(membership.log_coordinates))
    return undefined;
  const coordinates = membership.log_coordinates;
  const logId = asString(coordinates.log_id);
  const seq = asNumber(coordinates.seq);
  const leafIndex = asNumber(coordinates.leaf_index);
  return logId === undefined || seq === undefined || leafIndex === undefined
    ? undefined
    : { logId, seq, leafIndex };
};

const status = (value: unknown): AxisJudgment["status"] | undefined =>
  value === "pass" ||
  value === "fail" ||
  value === "not_applicable" ||
  value === "unjudgeable"
    ? value
    : undefined;

const verdict = (value: unknown): RatingNode["verdict"] | undefined =>
  value === "pass" || value === "fail" || value === "unsure"
    ? value
    : undefined;

const actedOnReferences = (record: RecordWithId): string[] =>
  Array.isArray(record.references)
    ? record.references.flatMap((reference) =>
        isObject(reference) &&
        reference.type === "agent-action-capsule" &&
        reference.citation_purpose === "acted_on"
          ? asString(reference.digest) === undefined
            ? []
            : [asString(reference.digest)!]
          : [],
      )
    : [];

const committedDigests = (
  record: RecordWithId,
): Pick<ActNode, "agentInputDigest" | "agentOutputDigest"> => {
  const agentInputDigest = committedDigest(record, "agent_input");
  const agentOutputDigest = committedDigest(record, "agent_output");
  return {
    ...(agentInputDigest === undefined ? {} : { agentInputDigest }),
    ...(agentOutputDigest === undefined ? {} : { agentOutputDigest }),
  };
};

export async function buildEvidenceGraph(
  bundle: unknown,
): Promise<EvidenceGraph> {
  if (
    !isObject(bundle) ||
    !Array.isArray(bundle.records) ||
    !isObject(bundle.disclosures)
  ) {
    throw new EvidenceGraphError("bundle must contain records and disclosures");
  }
  const disclosures = bundle.disclosures;
  const records = bundle.records.filter(
    (record): record is RecordWithId =>
      isObject(record) && asString(record.capsule_id) !== undefined,
  );
  const root = asString(bundle.root);
  const rootRecord = records.find((record) => record.capsule_id === root);
  if (rootRecord === undefined) {
    throw new EvidenceGraphError("root aggregate payload not disclosed");
  }
  const rootPayload = await disclosurePayload(
    rootRecord,
    disclosures,
    "agent_input",
  );
  if (
    !isObject(rootPayload) ||
    rootPayload.spec_version !== "evaluation-summary/v1"
  ) {
    throw new EvidenceGraphError("root aggregate payload is not disclosed");
  }

  const memberships = isObject(bundle.completeness_certificate)
    ? isObject(bundle.completeness_certificate.memberships)
      ? bundle.completeness_certificate.memberships
      : {}
    : {};
  const aggregate: SummaryNode = {
    capsuleId: rootRecord.capsule_id,
    ...(asString(rootPayload.cross_case_aggregation) === undefined
      ? {}
      : {
          crossCaseAggregation: asString(rootPayload.cross_case_aggregation)!,
        }),
    ...(Object.hasOwn(rootPayload, "per_axis")
      ? { perAxis: rootPayload.per_axis }
      : {}),
    ...(isObject(rootPayload.counts) &&
    asNumber(rootPayload.counts.reports) !== undefined &&
    asNumber(rootPayload.counts.unique_cases) !== undefined
      ? {
          counts: {
            reports: asNumber(rootPayload.counts.reports)!,
            uniqueCases: asNumber(rootPayload.counts.unique_cases)!,
          },
        }
      : {}),
    ...(Object.hasOwn(rootPayload, "cohort")
      ? { cohort: rootPayload.cohort }
      : {}),
  };

  const recordsById = new Map(
    records.map((record) => [record.capsule_id, record]),
  );
  const reportIds = new Set<string>();
  const visitedSummaries = new Set<string>();
  const collectReports = async (record: RecordWithId): Promise<void> => {
    if (visitedSummaries.has(record.capsule_id)) return;
    visitedSummaries.add(record.capsule_id);
    for (const id of actedOnReferences(record)) {
      const referenced = recordsById.get(id);
      if (referenced === undefined) continue;
      const payload = await disclosurePayload(
        referenced,
        disclosures,
        "agent_input",
      );
      if (!isObject(payload)) continue;
      if (payload.spec_version === "evaluation-report/v1") reportIds.add(id);
      else if (payload.spec_version === "evaluation-summary/v1")
        await collectReports(referenced);
    }
  };
  await collectReports(rootRecord);

  const reports: ReportNode[] = [];
  for (const reportId of reportIds) {
    const record = recordsById.get(reportId)!;
    const payload = await disclosurePayload(record, disclosures, "agent_input");
    if (!isObject(payload) || payload.spec_version !== "evaluation-report/v1")
      continue;
    const date = asString(payload.date);
    if (date === undefined) continue;
    const day = asNumber(payload.day);
    const reportCases = Array.isArray(payload.cases) ? payload.cases : [];
    const acts: ActNode[] = [];
    for (const actId of actedOnReferences(record)) {
      const actRecord = recordsById.get(actId);
      if (actRecord === undefined) continue;
      const input = await resolveDisclosure(
        actRecord,
        disclosures,
        "agent_input",
      );
      const output = await resolveDisclosure(
        actRecord,
        disclosures,
        "agent_output",
      );
      const inputCase =
        isObject(input.payload) && isObject(input.payload.case)
          ? input.payload.case
          : {};
      const caseId = asString(inputCase.conversation_id);
      const turnIdx = asNumber(inputCase.turn_idx);
      const actResolvedLogCoordinates = logCoordinates(
        memberships,
        actRecord.capsule_id,
      );
      acts.push({
        capsuleId: actRecord.capsule_id,
        caseId: caseId ?? actRecord.capsule_id,
        turnIdx: turnIdx ?? Number.MAX_SAFE_INTEGER,
        ...(isObject(input.payload) ? { agentInput: input.payload } : {}),
        ...(output.state === "disclosed"
          ? { agentOutput: output.payload }
          : {}),
        agentInputDisclosure: input.state,
        agentOutputDisclosure: output.state,
        ...committedDigests(actRecord),
        ...recordTimes(actRecord),
        ...(actResolvedLogCoordinates === undefined
          ? {}
          : {
              logCoordinates: actResolvedLogCoordinates,
            }),
      });
    }
    const cases = reportCases.flatMap((casePayload): CaseNode[] => {
      if (!isObject(casePayload)) return [];
      const taskId = asString(casePayload.task_id);
      const trial = asNumber(casePayload.trial);
      if (taskId === undefined || trial === undefined) return [];
      const matchingActs = acts.filter((act) => {
        const actCase =
          isObject(act.agentInput) && isObject(act.agentInput.case)
            ? act.agentInput.case
            : {};
        return actCase.task_id === taskId && actCase.trial === trial;
      });
      const caseId = matchingActs[0]?.caseId ?? `${taskId}:${trial}`;
      const judgments = (
        Array.isArray(casePayload.axis_judgments)
          ? casePayload.axis_judgments
          : []
      ).flatMap((judgment): AxisJudgment[] => {
        if (!isObject(judgment)) return [];
        const axisId = asString(judgment.axis_id),
          outcomeId = asString(judgment.outcome_id),
          judgmentStatus = status(judgment.status),
          rationale = asString(judgment.rationale);
        return axisId === undefined ||
          outcomeId === undefined ||
          judgmentStatus === undefined ||
          rationale === undefined
          ? []
          : [
              {
                axisId,
                outcomeId,
                status: judgmentStatus,
                rationale,
                evidenceIds: Array.isArray(judgment.evidence_ids)
                  ? judgment.evidence_ids.filter(
                      (id): id is string => typeof id === "string",
                    )
                  : [],
              },
            ];
      });
      return [
        {
          caseId,
          taskId,
          trial,
          aggregate:
            casePayload.case_aggregate === "pass" ||
            casePayload.case_aggregate === "fail"
              ? casePayload.case_aggregate
              : null,
          acts: matchingActs.sort((a, b) => a.turnIdx - b.turnIdx),
          judgments,
        },
      ];
    });
    const outcomes = (
      Array.isArray(payload.outcomes) ? payload.outcomes : []
    ).flatMap((outcome): Outcome[] =>
      isObject(outcome) &&
      asString(outcome.outcome_id) !== undefined &&
      (outcome.role === "required" || outcome.role === "optional")
        ? [
            {
              outcomeId: asString(outcome.outcome_id)!,
              role: outcome.role,
              aggregate:
                outcome.aggregate === "pass" || outcome.aggregate === "fail"
                  ? outcome.aggregate
                  : null,
            },
          ]
        : [],
    );
    const reportResolvedLogCoordinates = logCoordinates(
      memberships,
      record.capsule_id,
    );
    reports.push({
      capsuleId: record.capsule_id,
      date,
      ...(day === undefined ? {} : { day }),
      outcomes,
      cases,
      ratings: [],
      withheldActs: acts.filter(
        (act) => act.agentInput === undefined || act.agentOutput === undefined,
      ),
      ...recordTimes(record),
      ...(reportResolvedLogCoordinates === undefined
        ? {}
        : {
            logCoordinates: reportResolvedLogCoordinates,
          }),
    });
  }
  reports.sort((a, b) => a.date.localeCompare(b.date));
  // The real producer (evaluation-compiler's assemble_week) emits `date` and
  // no `day`; a report is a tile by its date, so `day` is derived rather
  // than required. A stated `day` is kept as stated. The day is the UTC
  // calendar day (see calendarDay), so the same bundle derives the same days
  // wherever it is read; `date` itself is kept exactly as the producer wrote it.
  const origin = Math.min(
    ...reports.flatMap((report) => {
      const position = calendarDay(report.date);
      return position === undefined ? [] : [position];
    }),
  );
  for (const report of reports) {
    if (report.day !== undefined) continue;
    const position = calendarDay(report.date);
    if (position !== undefined) report.day = position - origin + 1;
  }

  for (const record of records) {
    if (
      !isObject(record.chain) ||
      record.chain.relation !== "io.evaluation.human_rates"
    )
      continue;
    const reportId = asString(record.chain.parent_capsule_id);
    if (reportId === undefined) continue;
    const payload = await disclosurePayload(record, disclosures, "agent_input");
    const ratingVerdict = isObject(payload)
      ? verdict(payload.verdict)
      : undefined;
    const report = reports.find(
      (candidate) => candidate.capsuleId === reportId,
    );
    if (report !== undefined && ratingVerdict !== undefined)
      report.ratings.push({
        capsuleId: record.capsule_id,
        reportId,
        verdict: ratingVerdict,
      });
  }
  let calibration: CalibrationNode | undefined;
  for (const record of records) {
    const payload = await disclosurePayload(record, disclosures, "agent_input");
    if (!isObject(payload) || payload.spec_version !== "calibration-summary/v1")
      continue;
    calibration = {
      capsuleId: record.capsule_id,
      ...(Object.hasOwn(payload, "period_window")
        ? { periodWindow: payload.period_window }
        : {}),
      ...(Object.hasOwn(payload, "confusion")
        ? { confusion: payload.confusion }
        : {}),
      ...(Object.hasOwn(payload, "agreement")
        ? { agreement: payload.agreement }
        : {}),
      ...(Object.hasOwn(payload, "corrected_rate")
        ? { correctedRate: payload.corrected_rate }
        : {}),
      ...(Object.hasOwn(payload, "corrected_rate_ci")
        ? { correctedRateCi: payload.corrected_rate_ci }
        : {}),
    };
    break;
  }
  return {
    aggregate,
    reports,
    ...(calibration === undefined ? {} : { calibration }),
  };
}
