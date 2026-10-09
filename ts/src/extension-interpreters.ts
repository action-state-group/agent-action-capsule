import {
  declaredProducerKeys,
  PRODUCER_KEY_V1,
} from "./countersignature-stamp.js";
import { readCompliancePresentation } from "./compliance-presentation.js";
import { readOutcomeReportPresentation } from "./outcome-report-presentation.js";
import { readPresentationBlock } from "./presentation.js";

/** The evidence-book bundle extension that carries a disclosed record's payloads, keyed by payload commitment (SHA-256 of the exact bytes), each base64url without padding. */
export const BOOK_PAYLOADS_EXTENSION = "evidencebook/payloads";
/**
 * The bundle extension `capsulectl disclose --attach-input-originals` builds
 * at disclose time: a published capsule's id -> its agent_input original's
 * exact bytes, base64url without padding. The book itself stores only
 * digests; an original rides in a bundle only when its producer opts in.
 */
export const AGENT_INPUT_ORIGINALS_EXTENSION =
  "capsulectl/agent-input-originals/v1";

/**
 * The parts of this viewer that apply an extension block's meaning. Each id
 * names the one module that reads the kind; nothing else reads it.
 */
export type ExtensionInterpreterId =
  | "presentation-header"
  | "countersignature-stamp"
  | "outcome-report-card"
  | "compliance-card"
  | "result-root";

const object = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

interface Interpreter {
  readonly id: ExtensionInterpreterId;
  /** True when the interpreter would apply this bundle's block (the same reader it uses). */
  readonly accepts: (bundle: unknown) => boolean;
}

/**
 * Every extension kind this viewer has an interpreter for, each keyed to the
 * reader that interpreter uses, so "interpreted" can never drift from what
 * the module actually reads. A kind absent here (composed/v1 included, until
 * a module for it lands) is uninterpreted, whatever its block holds.
 */
const INTERPRETERS: Readonly<Record<string, Interpreter>> = Object.freeze({
  // evidence-graph-view.ts renderPresentationHeader -> presentation.ts readPresentationBlock
  "presentation/v1": {
    id: "presentation-header",
    accepts: (bundle) => readPresentationBlock(bundle) !== undefined,
  },
  // evidence-graph-view.ts renderVerificationPage -> countersignature-stamp.ts declaredProducerKeys
  [PRODUCER_KEY_V1]: {
    id: "countersignature-stamp",
    accepts: (bundle) => declaredProducerKeys(bundle).length > 0,
  },
  // outcome-report-presentation.ts readOutcomeReportPresentation (the outcome-report card)
  "outcome-report/v1": {
    id: "outcome-report-card",
    accepts: (bundle) => readOutcomeReportPresentation(bundle) !== undefined,
  },
  // compliance-presentation.ts readCompliancePresentation (the compliance card)
  "eu-ai-act-compliance/v1": {
    id: "compliance-card",
    accepts: (bundle) => readCompliancePresentation(bundle) !== undefined,
  },
  // result-root.ts buildResultRoot reads both blocks when it is an object
  [BOOK_PAYLOADS_EXTENSION]: {
    id: "result-root",
    accepts: (bundle) =>
      object(bundle) &&
      object(bundle.extensions) &&
      object(bundle.extensions[BOOK_PAYLOADS_EXTENSION]),
  },
  [AGENT_INPUT_ORIGINALS_EXTENSION]: {
    id: "result-root",
    accepts: (bundle) =>
      object(bundle) &&
      object(bundle.extensions) &&
      object(bundle.extensions[AGENT_INPUT_ORIGINALS_EXTENSION]),
  },
});

/**
 * The interpreter that applies `kind`'s block in `bundle`, or undefined when
 * this viewer has none for the kind, or has one whose reader ignores this
 * block (malformed, or not enabled): a block whose meaning is never applied
 * is not interpreted.
 */
export function extensionInterpreter(
  kind: string,
  bundle: unknown,
): ExtensionInterpreterId | undefined {
  const interpreter = Object.hasOwn(INTERPRETERS, kind)
    ? INTERPRETERS[kind]
    : undefined;
  return interpreter !== undefined && interpreter.accepts(bundle)
    ? interpreter.id
    : undefined;
}
