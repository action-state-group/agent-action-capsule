import type { PresentationManifest } from "./presentation-registry.js";

/**
 * The six built-in manifests of spec/presentation-contract-v0.md appendix A,
 * as values. Each equals the JSON file of the same name under
 * schemas/examples/presentation-manifest-v0/ (test/builtin-manifests.test.ts
 * compares them when those files are present). The precedence between the
 * built-in page shapes is stated here, in `forbids`, and nowhere in code:
 *
 * - rows first: every Result manifest forbids `spec_version:report/v1`;
 * - compliance only when outcome-report is not engaged: the compliance
 *   manifest forbids `outcome-report/v1`;
 * - the generic Result page only when neither card is engaged;
 * - Result before graph: the graph forbids the Result profile;
 * - the no-aggregate note is the one fallback.
 */

export const BUILTIN_MANIFEST_REPORT_ROWS: PresentationManifest = Object.freeze(
  {
    spec_version: "aac.presentation-manifest/v0",
    id: "aac.builtin.report-rows/v0",
    presentation_api: "aac.presentation-api/v0",
    runtime_min: "0.1.0",
    trust_class: "trusted-executable",
    requires: {
      bundle_kind: "evidence-bundle/v2",
      profiles: ["spec_version:report/v1"],
    },
    audiences: ["*"],
    formats: ["html", "fragment", "embedded"],
    fallback: false,
    priority: 1,
    executable: { carrier: "core-runtime" },
  },
) as PresentationManifest;

export const BUILTIN_MANIFEST_RESULT_OUTCOME_REPORT: PresentationManifest =
  Object.freeze({
    spec_version: "aac.presentation-manifest/v0",
    id: "aac.builtin.result-outcome-report/v0",
    presentation_api: "aac.presentation-api/v0",
    runtime_min: "0.1.0",
    trust_class: "trusted-executable",
    requires: {
      bundle_kind: "evidence-bundle/v2",
      profiles: ["result_version:evidence-result-v0"],
      extensions: { required: ["outcome-report/v1"] },
    },
    forbids: { profiles: ["spec_version:report/v1"] },
    audiences: ["*"],
    formats: ["html", "fragment", "embedded"],
    fallback: false,
    priority: 1,
    executable: { carrier: "core-runtime" },
  }) as PresentationManifest;

export const BUILTIN_MANIFEST_RESULT_COMPLIANCE: PresentationManifest =
  Object.freeze({
    spec_version: "aac.presentation-manifest/v0",
    id: "aac.builtin.result-compliance/v0",
    presentation_api: "aac.presentation-api/v0",
    runtime_min: "0.1.0",
    trust_class: "trusted-executable",
    requires: {
      bundle_kind: "evidence-bundle/v2",
      profiles: ["result_version:evidence-result-v0"],
      extensions: { required: ["eu-ai-act-compliance/v1"] },
    },
    forbids: {
      profiles: ["spec_version:report/v1"],
      extensions: ["outcome-report/v1"],
    },
    audiences: ["*"],
    formats: ["html", "fragment", "embedded"],
    fallback: false,
    priority: 1,
    executable: { carrier: "core-runtime" },
  }) as PresentationManifest;

export const BUILTIN_MANIFEST_RESULT: PresentationManifest = Object.freeze({
  spec_version: "aac.presentation-manifest/v0",
  id: "aac.builtin.result/v0",
  presentation_api: "aac.presentation-api/v0",
  runtime_min: "0.1.0",
  trust_class: "trusted-executable",
  requires: {
    bundle_kind: "evidence-bundle/v2",
    profiles: ["result_version:evidence-result-v0"],
  },
  forbids: {
    profiles: ["spec_version:report/v1"],
    extensions: ["outcome-report/v1", "eu-ai-act-compliance/v1"],
  },
  audiences: ["*"],
  formats: ["html", "fragment", "embedded"],
  fallback: false,
  priority: 1,
  executable: { carrier: "core-runtime" },
}) as PresentationManifest;

export const BUILTIN_MANIFEST_EVALUATION_SUMMARY_GRAPH: PresentationManifest =
  Object.freeze({
    spec_version: "aac.presentation-manifest/v0",
    id: "aac.builtin.evaluation-summary-graph/v0",
    presentation_api: "aac.presentation-api/v0",
    runtime_min: "0.1.0",
    trust_class: "trusted-executable",
    requires: {
      bundle_kind: "evidence-bundle/v2",
      profiles: ["spec_version:evaluation-summary/v1"],
    },
    forbids: { profiles: ["result_version:evidence-result-v0"] },
    audiences: ["*"],
    formats: ["html", "fragment", "embedded"],
    fallback: false,
    priority: 1,
    executable: { carrier: "core-runtime" },
  }) as PresentationManifest;

export const BUILTIN_MANIFEST_NO_AGGREGATE: PresentationManifest =
  Object.freeze({
    spec_version: "aac.presentation-manifest/v0",
    id: "aac.builtin.no-aggregate/v0",
    presentation_api: "aac.presentation-api/v0",
    runtime_min: "0.1.0",
    trust_class: "trusted-executable",
    requires: { bundle_kind: "evidence-bundle/v2" },
    audiences: ["*"],
    formats: ["html", "fragment", "embedded"],
    fallback: true,
    executable: { carrier: "core-runtime" },
  }) as PresentationManifest;

/** All six, in appendix A's table order (an order that decides nothing). */
export const BUILTIN_MANIFESTS: readonly PresentationManifest[] = Object.freeze(
  [
    BUILTIN_MANIFEST_REPORT_ROWS,
    BUILTIN_MANIFEST_RESULT_OUTCOME_REPORT,
    BUILTIN_MANIFEST_RESULT_COMPLIANCE,
    BUILTIN_MANIFEST_RESULT,
    BUILTIN_MANIFEST_EVALUATION_SUMMARY_GRAPH,
    BUILTIN_MANIFEST_NO_AGGREGATE,
  ],
);

/**
 * The composition section: the generic view of a `composed/v1` block
 * (members, observers, joins, composition closure, composed digest, and
 * same-custody agreement shown as redundant, not corroborating). A specific
 * module selected by the engaged extension alone.
 *
 * It is NOT one of the page manifests above, and must not be: one
 * descriptor matches it together with each of the five specific page
 * manifests (a Result root that also carries composed/v1, say), so the
 * registration test of contract section 4.5 refuses it in that set, and it
 * would equally refuse every composition-aware page module (appendix B,
 * `org.example.composition-aware/v0`) that it is meant to sit beneath. It is
 * resolved in the core's section registry instead, by the same algorithm,
 * and renders after whichever page module the page registry selected.
 */
export const BUILTIN_MANIFEST_COMPOSED: PresentationManifest = Object.freeze({
  spec_version: "aac.presentation-manifest/v0",
  id: "aac.builtin.composed/v0",
  trust_class: "trusted-executable",
  requires: {
    bundle_kind: "evidence-bundle/v2",
    extensions: { required: ["composed/v1"] },
  },
  audiences: ["*"],
  formats: ["html", "fragment", "embedded"],
  fallback: false,
  priority: 1,
  executable: { carrier: "core-runtime" },
}) as PresentationManifest;

/** The built-in section manifests (one today). */
export const BUILTIN_SECTION_MANIFESTS: readonly PresentationManifest[] =
  Object.freeze([BUILTIN_MANIFEST_COMPOSED]);
