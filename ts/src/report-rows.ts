import {
  asString,
  disclosurePayload,
  isObject,
  logCoordinates,
  type ResolvedLogCoordinates,
  type ObjectValue,
  type RecordWithId,
} from "./evidence-graph.js";

/**
 * `report/v1`: the generic, pack-agnostic row model. A report is DATA --
 * a row per clause/outcome with a status and citations into the same
 * bundle -- never bespoke per-report HTML. Any pack (obligations, outcomes,
 * anything else) that seals its findings as `report/v1` rows renders here
 * without this module knowing what the rows are about.
 */

export interface ReportRowCitation {
  readonly capsuleId: string;
  readonly disclosedPayload?: unknown;
  readonly logCoordinates?: ResolvedLogCoordinates;
}

export interface ReportRow {
  readonly rowId: string;
  readonly label: string;
  readonly status: string;
  readonly reason?: string;
  readonly citations: readonly ReportRowCitation[];
}

export interface ReportRows {
  readonly capsuleId: string;
  readonly title?: string;
  readonly rows: readonly ReportRow[];
  readonly logCoordinates?: ResolvedLogCoordinates;
}

const rowCitationDigests = (row: ObjectValue): string[] =>
  Array.isArray(row.references)
    ? row.references.flatMap((reference) =>
        isObject(reference) &&
        reference.type === "agent-action-capsule" &&
        reference.citation_purpose === "acted_on"
          ? asString(reference.digest) === undefined
            ? []
            : [asString(reference.digest)!]
          : [],
      )
    : [];

/**
 * Returns undefined (never throws) when the bundle's root is not a
 * `report/v1` payload, so callers can fall back to another root model.
 * A malformed row is dropped, never patched with invented data.
 */
export function buildReportRows(bundle: unknown): ReportRows | undefined {
  if (
    !isObject(bundle) ||
    !Array.isArray(bundle.records) ||
    !isObject(bundle.disclosures)
  ) {
    return undefined;
  }
  const disclosures = bundle.disclosures;
  const records = bundle.records.filter(
    (record): record is RecordWithId =>
      isObject(record) && asString(record.capsule_id) !== undefined,
  );
  const root = asString(bundle.root);
  const rootRecord = records.find((record) => record.capsule_id === root);
  if (rootRecord === undefined) return undefined;
  const rootPayload = disclosurePayload(rootRecord, disclosures, "agent_input");
  if (!isObject(rootPayload) || rootPayload.spec_version !== "report/v1")
    return undefined;

  const memberships = isObject(bundle.completeness_certificate)
    ? isObject(bundle.completeness_certificate.memberships)
      ? bundle.completeness_certificate.memberships
      : {}
    : {};
  const recordsById = new Map(
    records.map((record) => [record.capsule_id, record]),
  );

  const rows = (
    Array.isArray(rootPayload.rows) ? rootPayload.rows : []
  ).flatMap((raw): ReportRow[] => {
    if (!isObject(raw)) return [];
    const rowId = asString(raw.row_id);
    const label = asString(raw.label);
    const rowStatus = asString(raw.status);
    if (rowId === undefined || label === undefined || rowStatus === undefined)
      return [];
    const reason = asString(raw.reason);
    const citations = rowCitationDigests(raw).flatMap(
      (digest): ReportRowCitation[] => {
        const record = recordsById.get(digest);
        if (record === undefined) return [];
        const payload = disclosurePayload(record, disclosures, "agent_input");
        const coordinates = logCoordinates(memberships, record.capsule_id);
        return [
          {
            capsuleId: record.capsule_id,
            ...(payload === undefined ? {} : { disclosedPayload: payload }),
            ...(coordinates === undefined
              ? {}
              : { logCoordinates: coordinates }),
          },
        ];
      },
    );
    return [
      {
        rowId,
        label,
        status: rowStatus,
        ...(reason === undefined ? {} : { reason }),
        citations,
      },
    ];
  });

  const title = asString(rootPayload.title);
  const rootResolvedLogCoordinates = logCoordinates(
    memberships,
    rootRecord.capsule_id,
  );
  return {
    capsuleId: rootRecord.capsule_id,
    ...(title === undefined ? {} : { title }),
    rows,
    ...(rootResolvedLogCoordinates === undefined
      ? {}
      : { logCoordinates: rootResolvedLogCoordinates }),
  };
}
