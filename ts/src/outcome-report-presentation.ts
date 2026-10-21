/**
 * `outcome-report/v1` typed extension: whether a Result v0 bundle opts into
 * the outcome-report card in place of the generic Result page, and its
 * display settings. Kept separate from `presentation/v1`
 * (presentation.ts) deliberately: that block's chrome rule -- "presentation
 * can never touch verification chrome" -- is enforced there by reading
 * exactly three fields and nothing else; this block selects a different
 * renderer for VERIFIED data, never bundle-supplied markup, so it does not
 * violate that rule, but it is a distinct concern and gets its own
 * namespace rather than smuggled fields onto the chrome block.
 *
 * Every setting is a display input, not evidence, and the view labels it as
 * such: `percentages` switches the card between counts (the default,
 * matching this engine's native output) and percentages. The block carries
 * no money: the card reports outcomes, and any pricing over them belongs to
 * whatever product consumes the report, outside this package.
 */

export interface OutcomeReportPresentation {
  readonly enabled: boolean;
  readonly percentages: boolean;
  /**
   * `producer_note`: the producer's own plain-text note about this bundle
   * (e.g. "what changed in this run" on a rerun report). Text only -- every
   * line reaches the DOM through textContent, never as markup -- and the view
   * labels it the producer's note, not evidence: no claim backs it and no
   * number on the page is computed from it. All-or-nothing: a note with any
   * non-string, empty or over-long line, or too many lines, is dropped whole
   * rather than half-shown.
   */
  readonly producerNote?: {
    readonly title: string;
    readonly lines: readonly string[];
  };
  /**
   * `edited_criteria`: criteria the producer says were edited in this pack
   * version, each with the short badge text to show beside it ("edited in
   * v1.5.0"). Presentation only, labelled as the producer's note; the
   * wording actually judged is still read from the sealed reports.
   */
  readonly editedCriteria?: readonly {
    readonly criterion: string;
    readonly badge: string;
  }[];
}
function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

const CRITERION_REF = /^[a-z0-9_]+\.[a-z0-9_]+$/u;
const MAX_NOTE_LINES = 12;
const MAX_NOTE_LINE = 600;
const MAX_NOTE_TITLE = 120;
const MAX_BADGE = 40;
function text(value: unknown, max: number): string | undefined {
  return typeof value === "string" &&
    value.trim().length > 0 &&
    value.length <= max
    ? value
    : undefined;
}
function readProducerNote(
  value: unknown,
): OutcomeReportPresentation["producerNote"] {
  const note = object(value);
  if (note === undefined || !Array.isArray(note.lines)) return undefined;
  const raw: unknown[] = note.lines;
  if (raw.length === 0 || raw.length > MAX_NOTE_LINES) return undefined;
  const lines = raw.map((line) => text(line, MAX_NOTE_LINE));
  if (lines.some((line) => line === undefined)) return undefined;
  return {
    title: text(note.title, MAX_NOTE_TITLE) ?? "Producer's note",
    lines: lines as string[],
  };
}
function readEditedCriteria(
  value: unknown,
): OutcomeReportPresentation["editedCriteria"] {
  if (!Array.isArray(value)) return undefined;
  const entries: unknown[] = value;
  const edited = entries.flatMap((entry) => {
    const item = object(entry);
    const criterion =
      typeof item?.criterion === "string" && CRITERION_REF.test(item.criterion)
        ? item.criterion
        : undefined;
    const badge = text(item?.badge, MAX_BADGE);
    return criterion === undefined || badge === undefined
      ? []
      : [{ criterion, badge }];
  });
  return edited.length === 0 ? undefined : edited;
}

export function readOutcomeReportPresentation(
  bundle: unknown,
): OutcomeReportPresentation | undefined {
  const top = object(bundle);
  const extensions = object(top?.extensions);
  const block = object(extensions?.["outcome-report/v1"]);
  if (block === undefined || block.enabled !== true) return undefined;
  const percentages = block.percentages === true;
  const producerNote = readProducerNote(block.producer_note);
  const editedCriteria = readEditedCriteria(block.edited_criteria);
  return {
    enabled: true,
    percentages,
    ...(producerNote === undefined ? {} : { producerNote }),
    ...(editedCriteria === undefined ? {} : { editedCriteria }),
  };
}
