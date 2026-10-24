// The core's fixed text (vectors/viewer-core-text/): the banner's line for
// each verification state, the refusal, and the verification page's check
// lists, exactly as this package defines them (presentation contract
// sections 6.1 and 6.2). test/verification-states.test.ts compares the
// committed files with what this writes, and reads every final state from
// the verification model against them; capsule-viewer renders every state.
//
//   AAC_WRITE_VECTORS=1 npx vitest run test/verification-states.test.ts
import { createHash } from "node:crypto";
import {
  CHECKED_ON_THIS_PAGE,
  CHECKPOINT_NOT_CHECKED_NOTE,
  CHECKS_SCOPE_LINE,
  EXTENSION_NOT_INTERPRETED,
  EXTENSION_NOT_INTERPRETED_NOT_COVERED,
  EXTENSION_READ_BY_PAGE,
  EXTENSION_SHOWN,
  FAILED_ON_THIS_PAGE,
  FULL_VERIFIER_LINE,
  NOT_CHECKED_ON_THIS_PAGE,
  UNVERIFIED_BUNDLE_REFUSAL,
  VERIFICATION_BANNER_LINES,
  VERIFICATION_CHECK_IDS,
  VERIFICATION_CHECK_TECHNICAL_NAMES,
  UNABLE_TO_VERIFY_LINES,
  VERIFICATION_CHECK_WORDS,
} from "../../src/verification-page.js";

/** One banner state of section 6.2's table, with its fixed line. */
export interface WireBannerState {
  readonly id: string;
  readonly description: string;
  readonly data_verify: string;
  readonly data_verdict: string | null;
  /**
   * Whether the checks let the records be shown; a presentation refusal can
   * still withhold them under the same banner.
   */
  readonly records_shown: boolean;
  readonly line: string;
}

export const BANNER_STATES: readonly WireBannerState[] = [
  {
    id: "checking",
    description: "The checks have not finished.",
    data_verify: "checking",
    data_verdict: null,
    records_shown: false,
    line: VERIFICATION_BANNER_LINES.checking,
  },
  {
    id: "verified",
    description: "Every check the bundle calls for ran here and passed.",
    data_verify: "verified",
    data_verdict: "valid",
    records_shown: true,
    line: VERIFICATION_BANNER_LINES.verified,
  },
  {
    id: "incomplete",
    description:
      "No check failed, but some were not run, and the page draws a not-checked list.",
    data_verify: "incomplete",
    data_verdict: "incomplete",
    records_shown: true,
    line: VERIFICATION_BANNER_LINES.incomplete,
  },
  {
    id: "incomplete-no-list",
    description:
      "No check failed, but some were not run, and the page draws no not-checked list (for example, nothing is signed).",
    data_verify: "incomplete",
    data_verdict: "incomplete",
    records_shown: true,
    line: VERIFICATION_BANNER_LINES.incompleteNoList,
  },
  {
    id: "failed",
    description: "A check failed and the records are still shown.",
    data_verify: "failed",
    data_verdict: "invalid",
    records_shown: true,
    line: VERIFICATION_BANNER_LINES.failed,
  },
  {
    id: "refused",
    description:
      "A check failed and the page's own checks refuse the records; the refusal line follows.",
    data_verify: "failed",
    data_verdict: "invalid",
    records_shown: false,
    line: VERIFICATION_BANNER_LINES.refused,
  },
  {
    id: "unable",
    description: "This runtime could not run the checks at all.",
    data_verify: "unable",
    data_verdict: null,
    records_shown: false,
    line: VERIFICATION_BANNER_LINES.unable,
  },
];

const json = (value: unknown): string => `${JSON.stringify(value, null, 2)}\n`;
const sha256 = (text: string): string =>
  createHash("sha256").update(text).digest("hex");

/** The corpus files, by name. */
export function generateCoreTextVectors(): Record<string, string> {
  const coreText = json({
    description:
      "The core's fixed text (spec/verification-display-v0.md sections 6.1, 6.2 and 8): one banner line per verification state, the refusal, the unable-to-verify lines, the check lists' headings and lines, and the extension rows. A viewer draws exactly these words; no module, wording pack or bundle supplies them.",
    count: BANNER_STATES.length + VERIFICATION_CHECK_IDS.length,
    banner: BANNER_STATES,
    refusal: UNVERIFIED_BUNDLE_REFUSAL,
    unable: {
      reason: UNABLE_TO_VERIFY_LINES.reason,
      command: UNABLE_TO_VERIFY_LINES.command,
      no_command: UNABLE_TO_VERIFY_LINES.noCommand,
    },
    check_lists: {
      headings: {
        page: CHECKED_ON_THIS_PAGE,
        failed: FAILED_ON_THIS_PAGE,
        not_checked: NOT_CHECKED_ON_THIS_PAGE,
      },
      lines: VERIFICATION_CHECK_IDS.map((id) => ({
        id,
        words: VERIFICATION_CHECK_WORDS[id],
        technical_name: VERIFICATION_CHECK_TECHNICAL_NAMES[id],
      })),
      checkpoint_not_checked_note: CHECKPOINT_NOT_CHECKED_NOTE,
      full_verifier: FULL_VERIFIER_LINE,
      scope: CHECKS_SCOPE_LINE,
    },
    extension_rows: {
      shown_covered: EXTENSION_SHOWN.covered,
      shown_not_covered: EXTENSION_SHOWN.notCovered,
      read_by_page_covered: EXTENSION_READ_BY_PAGE.covered,
      read_by_page_not_covered: EXTENSION_READ_BY_PAGE.notCovered,
      not_interpreted_covered: EXTENSION_NOT_INTERPRETED,
      not_interpreted_not_covered: EXTENSION_NOT_INTERPRETED_NOT_COVERED,
    },
  });
  return {
    "core-text.json": coreText,
    "manifest.json": json({
      contract: "spec/verification-display-v0.md (sections 6.1, 6.2, 8)",
      provenance: "reference-derived",
      generator: "ts/test/helpers/viewer-core-text-vectors.ts",
      normative_for: ["ts/src/verification-page.ts"],
      files: [
        {
          path: "core-text.json",
          sha256: sha256(coreText),
          count: (JSON.parse(coreText) as { count: number }).count,
        },
      ],
    }),
  };
}
