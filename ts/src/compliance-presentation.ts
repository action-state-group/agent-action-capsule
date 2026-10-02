/**
 * `eu-ai-act-compliance/v1` typed extension: opts a verified Result v0
 * bundle into the EU AI Act obligations-report card, read only after the
 * bundle verified, and carries the producer's REGULATORY MAPPING for it:
 * per obligation its article, title, plain-language summary, applicability
 * and method; per test its short label, an optional not-evaluable note and
 * an optional finding template (severity, recommendation, owner).
 *
 * Everything read here is presentation, outside the signed records, and the
 * card labels it so. Which obligations and tests exist, every verdict and
 * count, each test's wording and tier, and the pack come from the sealed
 * claims and reports (compliance.ts), never from this block.
 */

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function str(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function strArray(value: unknown): readonly string[] {
  return Array.isArray(value)
    ? value.filter((v): v is string => typeof v === "string")
    : [];
}

export interface ComplianceFinding {
  readonly id: string;
  readonly severity: string;
  readonly recommendation: string;
  readonly ownerDue: string;
}

export interface ComplianceRow {
  readonly criterionId: string;
  readonly name: string;
  readonly notEvaluableNote?: string;
  readonly finding?: ComplianceFinding;
}

export interface ComplianceApplicability {
  readonly status: "in_force" | "future";
  readonly note: string;
}

export interface ComplianceObligation {
  readonly key: string;
  readonly article: string;
  readonly title: string;
  readonly plain: string;
  readonly judgedTerms: readonly string[];
  readonly applicability: ComplianceApplicability;
  readonly method: string;
  readonly rows: readonly ComplianceRow[];
}

export interface ComplianceQualityProtocol {
  readonly protocol?: string;
  readonly cadence?: string;
  readonly note?: string;
}

export interface CompliancePresentation {
  readonly enabled: boolean;
  readonly regulation: string;
  readonly obligations: readonly ComplianceObligation[];
  readonly qualityProtocol?: ComplianceQualityProtocol;
}

function readFinding(value: unknown): ComplianceFinding | undefined {
  const obj = object(value);
  const id = str(obj?.id);
  const severity = str(obj?.severity);
  const recommendation = str(obj?.recommendation);
  const ownerDue = str(obj?.owner_due);
  if (
    id === undefined ||
    severity === undefined ||
    recommendation === undefined ||
    ownerDue === undefined
  )
    return undefined;
  return { id, severity, recommendation, ownerDue };
}

function readRow(value: unknown): ComplianceRow | undefined {
  const obj = object(value);
  const criterionId = str(obj?.criterion_id);
  const name = str(obj?.name);
  if (criterionId === undefined || name === undefined) return undefined;
  const notEvaluableNote = str(obj?.not_evaluable_note);
  const finding =
    obj?.finding === undefined ? undefined : readFinding(obj.finding);
  return {
    criterionId,
    name,
    ...(notEvaluableNote === undefined ? {} : { notEvaluableNote }),
    ...(finding === undefined ? {} : { finding }),
  };
}

function readApplicability(
  value: unknown,
): ComplianceApplicability | undefined {
  const obj = object(value);
  const status =
    obj?.status === "in_force" || obj?.status === "future"
      ? obj.status
      : undefined;
  const note = str(obj?.note);
  if (status === undefined || note === undefined) return undefined;
  return { status, note };
}

function readObligation(value: unknown): ComplianceObligation | undefined {
  const obj = object(value);
  const key = str(obj?.key);
  const article = str(obj?.article);
  const title = str(obj?.title);
  const plain = str(obj?.plain);
  const method = str(obj?.method);
  const applicability = readApplicability(obj?.applicability);
  if (
    key === undefined ||
    article === undefined ||
    title === undefined ||
    plain === undefined ||
    method === undefined ||
    applicability === undefined
  )
    return undefined;
  const rows = Array.isArray(obj?.rows)
    ? obj.rows.flatMap((r): ComplianceRow[] => {
        const row = readRow(r);
        return row === undefined ? [] : [row];
      })
    : [];
  return {
    key,
    article,
    title,
    plain,
    judgedTerms: strArray(obj?.judged_terms),
    applicability,
    method,
    rows,
  };
}

function readQualityProtocol(
  value: unknown,
): ComplianceQualityProtocol | undefined {
  const obj = object(value);
  if (obj === undefined) return undefined;
  const protocol = str(obj.protocol);
  const cadence = str(obj.cadence);
  const note = str(obj.note);
  if (protocol === undefined && cadence === undefined && note === undefined)
    return undefined;
  return {
    ...(protocol === undefined ? {} : { protocol }),
    ...(cadence === undefined ? {} : { cadence }),
    ...(note === undefined ? {} : { note }),
  };
}

export function readCompliancePresentation(
  bundle: unknown,
): CompliancePresentation | undefined {
  const top = object(bundle);
  const extensions = object(top?.extensions);
  const block = object(extensions?.["eu-ai-act-compliance/v1"]);
  if (block === undefined || block.enabled !== true) return undefined;
  const regulation = str(block.regulation) ?? "Regulation (EU) 2024/1689";
  const obligations = Array.isArray(block.obligations)
    ? block.obligations.flatMap((o): ComplianceObligation[] => {
        const obligation = readObligation(o);
        return obligation === undefined ? [] : [obligation];
      })
    : [];
  // Absent is never pass: a block with `enabled: true` but zero recognizable
  // obligations is not a usable card -- treated the same as not enabled at
  // all, falling back to the generic Result page rather than rendering an
  // empty shell.
  if (obligations.length === 0) return undefined;
  const qualityProtocol = readQualityProtocol(block.quality_protocol);
  return {
    enabled: true,
    regulation,
    obligations,
    ...(qualityProtocol === undefined ? {} : { qualityProtocol }),
  };
}
