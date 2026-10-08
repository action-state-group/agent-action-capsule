// TEST-ONLY ORACLE. The page-shape dispatch renderEvidenceGraph ran before the
// presentation registry, kept verbatim (minus the DOM) so the registry can be
// held to it: for every bundle, resolve() must pick the module this control
// flow picked. It is never imported by src/.
import {
  type BundleVerificationResult,
  type VerifiedBundleContext,
} from "../../src/bundle.js";
import { readCompliancePresentation } from "../../src/compliance-presentation.js";
import {
  buildEvidenceGraph,
  EvidenceGraphError,
  type EvidenceGraph,
} from "../../src/evidence-graph.js";
import { readOutcomeReportPresentation } from "../../src/outcome-report-presentation.js";
import { buildReportRows } from "../../src/report-rows.js";
import { buildResultRoot, isResultRoot } from "../../src/result-root.js";
import { unboundRecordIds } from "../../src/verification-page.js";

export const ID_ROWS = "aac.builtin.report-rows/v0";
export const ID_OUTCOME = "aac.builtin.result-outcome-report/v0";
export const ID_COMPLIANCE = "aac.builtin.result-compliance/v0";
export const ID_RESULT = "aac.builtin.result/v0";
export const ID_GRAPH = "aac.builtin.evaluation-summary-graph/v0";
export const ID_NO_AGGREGATE = "aac.builtin.no-aggregate/v0";
export const REFUSAL = "<refusal>";

// The pre-registry verification gate, copied as it stood in
// evidence-graph-view.ts (the registry now owns its own copy).
function membershipProvenOrUnbound(result: BundleVerificationResult): boolean {
  return (
    result.perRecordMembership.status === "pass" ||
    (result.perRecordMembership.status === "fail" &&
      result.perRecordMembership.findings.length > 0 &&
      result.perRecordMembership.findings.length ===
        unboundRecordIds(result).length)
  );
}

export function legacyBundleVerified(
  result: BundleVerificationResult,
): boolean {
  return (
    result.graphClosure.status === "pass" &&
    result.intervalCoverage.status === "pass" &&
    membershipProvenOrUnbound(result) &&
    Object.values(result.capsuleResults).every((capsule) => capsule.ok) &&
    result.disclosures.every(
      (disclosure) =>
        disclosure.status === "disclosure_match" ||
        disclosure.status === "withheld",
    )
  );
}

/**
 * The module id the old if-chain rendered, REFUSAL for an unverified
 * bundle. Throws exactly where the old renderEvidenceGraph threw before
 * writing anything (a malformed Result root, a non-EvidenceGraphError).
 */
export async function legacyDispatch(
  context: VerifiedBundleContext,
): Promise<string> {
  const { bundle, verification } = context;
  const verified = legacyBundleVerified(verification);
  const reportRows = verified ? await buildReportRows(context) : undefined;
  const result =
    verified && reportRows === undefined && (await isResultRoot(context))
      ? await buildResultRoot(context)
      : undefined;
  let graph: EvidenceGraph | undefined;
  let noAggregate = false;
  if (verified && reportRows === undefined && result === undefined) {
    try {
      graph = await buildEvidenceGraph(context);
    } catch (err) {
      if (!(err instanceof EvidenceGraphError)) throw err;
      noAggregate = true;
    }
  }
  const outcomeReport =
    result !== undefined ? readOutcomeReportPresentation(bundle) : undefined;
  const compliance =
    result !== undefined && outcomeReport === undefined
      ? readCompliancePresentation(bundle)
      : undefined;
  if (reportRows !== undefined) return ID_ROWS;
  if (result !== undefined && outcomeReport !== undefined) return ID_OUTCOME;
  if (result !== undefined && compliance !== undefined) return ID_COMPLIANCE;
  if (result !== undefined) return ID_RESULT;
  if (graph !== undefined) return ID_GRAPH;
  if (noAggregate) return ID_NO_AGGREGATE;
  return REFUSAL;
}

/**
 * The same if-chain over a descriptor, as the contract's checker transcribes
 * it (appendix A.3). `graphBuilds` stands for "buildEvidenceGraph did not
 * throw an EvidenceGraphError". The oracle test proves this transcription
 * equals legacyDispatch on every real fixture, which is what lets the
 * 1,536-case table speak for the real code.
 */
export function legacyOverDescriptor(
  d: {
    readonly verified: boolean;
    readonly profiles: ReadonlySet<string>;
    readonly extensions: ReadonlySet<string>;
  },
  graphBuilds: boolean,
): string {
  if (!d.verified) return REFUSAL;
  if (d.profiles.has("spec_version:report/v1")) return ID_ROWS;
  if (d.profiles.has("result_version:evidence-result-v0")) {
    if (d.extensions.has("outcome-report/v1")) return ID_OUTCOME;
    if (d.extensions.has("eu-ai-act-compliance/v1")) return ID_COMPLIANCE;
    return ID_RESULT;
  }
  if (d.profiles.has("spec_version:evaluation-summary/v1") && graphBuilds)
    return ID_GRAPH;
  return ID_NO_AGGREGATE;
}
