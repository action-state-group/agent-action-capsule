export interface ActNode {
  capsuleId: string;
  caseId: string;
  turnIdx: number;
  agentInput?: unknown;
  agentOutput?: unknown;
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
export interface ReportNode {
  capsuleId: string;
  date: string;
  day: number;
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

export const disclosurePayload = (
  record: RecordWithId,
  disclosures: ObjectValue,
  field: "agent_input" | "agent_output",
): unknown => {
  const digest = isObject(record.model_attestation)
    ? isObject(record.model_attestation.compute_attestation)
      ? asString(
          record.model_attestation.compute_attestation[`${field}_digest`],
        )
      : undefined
    : undefined;
  const disclosure = digest === undefined ? undefined : disclosures[digest];
  const resolved = isObject(disclosure)
    ? disclosure
    : disclosures[record.capsule_id];
  return isObject(resolved) ? resolved[field] : undefined;
};

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
  const committed = isObject(record.model_attestation)
    ? objectOrEmpty(record.model_attestation.compute_attestation)
    : {};
  return {
    ...(asString(committed.agent_input_digest) === undefined
      ? {}
      : { agentInputDigest: asString(committed.agent_input_digest)! }),
    ...(asString(committed.agent_output_digest) === undefined
      ? {}
      : { agentOutputDigest: asString(committed.agent_output_digest)! }),
  };
};

const objectOrEmpty = (value: unknown): ObjectValue =>
  isObject(value) ? value : {};

export function buildEvidenceGraph(bundle: unknown): EvidenceGraph {
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
  const rootPayload = disclosurePayload(rootRecord, disclosures, "agent_input");
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
  const collectReports = (record: RecordWithId): void => {
    if (visitedSummaries.has(record.capsule_id)) return;
    visitedSummaries.add(record.capsule_id);
    for (const id of actedOnReferences(record)) {
      const referenced = recordsById.get(id);
      if (referenced === undefined) continue;
      const payload = disclosurePayload(referenced, disclosures, "agent_input");
      if (!isObject(payload)) continue;
      if (payload.spec_version === "evaluation-report/v1") reportIds.add(id);
      else if (payload.spec_version === "evaluation-summary/v1")
        collectReports(referenced);
    }
  };
  collectReports(rootRecord);

  const reports = [...reportIds]
    .flatMap((reportId): ReportNode[] => {
      const record = recordsById.get(reportId)!;
      const payload = disclosurePayload(record, disclosures, "agent_input");
      if (!isObject(payload) || payload.spec_version !== "evaluation-report/v1")
        return [];
      const date = asString(payload.date);
      const day = asNumber(payload.day);
      if (date === undefined || day === undefined) return [];
      const reportCases = Array.isArray(payload.cases) ? payload.cases : [];
      const acts = actedOnReferences(record).flatMap((actId): ActNode[] => {
        const actRecord = recordsById.get(actId);
        if (actRecord === undefined) return [];
        const input = disclosurePayload(actRecord, disclosures, "agent_input");
        const inputCase =
          isObject(input) && isObject(input.case) ? input.case : {};
        const caseId = asString(inputCase.conversation_id);
        const turnIdx = asNumber(inputCase.turn_idx);
        const agentOutput = disclosurePayload(
          actRecord,
          disclosures,
          "agent_output",
        );
        const actResolvedLogCoordinates = logCoordinates(
          memberships,
          actRecord.capsule_id,
        );
        return [
          {
            capsuleId: actRecord.capsule_id,
            caseId: caseId ?? actRecord.capsule_id,
            turnIdx: turnIdx ?? Number.MAX_SAFE_INTEGER,
            ...(isObject(input) ? { agentInput: input } : {}),
            ...(agentOutput === undefined
              ? {}
              : {
                  agentOutput,
                }),
            ...committedDigests(actRecord),
            ...(actResolvedLogCoordinates === undefined
              ? {}
              : {
                  logCoordinates: actResolvedLogCoordinates,
                }),
          },
        ];
      });
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
      return [
        {
          capsuleId: record.capsule_id,
          date,
          day,
          outcomes,
          cases,
          ratings: [],
          withheldActs: acts.filter(
            (act) =>
              act.agentInput === undefined || act.agentOutput === undefined,
          ),
          ...(reportResolvedLogCoordinates === undefined
            ? {}
            : {
                logCoordinates: reportResolvedLogCoordinates,
              }),
        },
      ];
    })
    .sort((a, b) => a.date.localeCompare(b.date));

  for (const record of records) {
    if (
      !isObject(record.chain) ||
      record.chain.relation !== "io.evaluation.human_rates"
    )
      continue;
    const reportId = asString(record.chain.parent_capsule_id);
    if (reportId === undefined) continue;
    const payload = disclosurePayload(record, disclosures, "agent_input");
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
  const calibration = records.flatMap((record): CalibrationNode[] => {
    const payload = disclosurePayload(record, disclosures, "agent_input");
    if (!isObject(payload) || payload.spec_version !== "calibration-summary/v1")
      return [];
    return [
      {
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
      },
    ];
  })[0];
  return {
    aggregate,
    reports,
    ...(calibration === undefined ? {} : { calibration }),
  };
}
