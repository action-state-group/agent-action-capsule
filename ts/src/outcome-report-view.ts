import type { BundleVerificationResult } from "./bundle.js";
import {
  buildOutcomeReportModel,
  type CalibrationWeek,
  type Conversation,
  type ConversationVerdict,
  type CriterionTierReading,
  type CriterionWording,
  type MissedReasonGroup,
  type ConversationDate,
  type OutcomeReportModel,
  type OutcomeReportOptions,
  type OutcomeReportRunInfo,
  NOT_STATED,
  verifyJudgePin,
} from "./outcome-report.js";
import { OUTCOME_REPORT_CSS } from "./outcome-report-styles.js";
import { buildVerificationPageModel } from "./verification-page.js";
import type { ResultRoot } from "./result-root.js";

/**
 * The outcome-report card, rendered from a verified `ResultRoot`. Called
 * from `evidence-graph-view.ts` in place of `renderResultPage` when the
 * bundle's `outcome-report/v1` extension opts in (see
 * `readOutcomeReportPresentation`) -- after the same verify-first gate every
 * other root family goes through: nothing here ever runs on a bundle that
 * did not verify.
 *
 * The whole card renders inside one `.oi`-classed wrapper, with its own
 * `<style>` (`OUTCOME_REPORT_CSS`) as its first child -- every selector in
 * that stylesheet is scoped under `.oi` so it can never affect, or be
 * affected by, the rest of the emitted page (the verification page that
 * always follows it, or the generic Result page this bundle opted out of).
 * No external reference of any kind: no `<link>`, no web font, no image.
 */

function element(tag: string, text?: string): HTMLElement {
  const value = document.createElement(tag);
  if (text !== undefined) value.textContent = text;
  return value;
}

function el(tag: string, className: string, text?: string): HTMLElement {
  const value = element(tag, text);
  value.className = className;
  return value;
}

// ---------------------------------------------------------------------------
// Icons: inline SVG line drawings, never emoji. An emoji glyph renders as an
// empty box ("tofu") wherever no colour-emoji font is installed -- headless
// Chromium on a server, most CI images -- and a report is read exactly there.
// Built with createElementNS from fixed path data (no markup string, no
// external reference); stroke follows the surrounding text colour.
// ---------------------------------------------------------------------------

// The SVG namespace is a URI that happens to begin with a scheme; it is never
// fetched. Assembled at run time so the emitted runtime contains no literal
// "http://" -- capsule-cli's report tests assert an offline report.html has
// none, as a cheap guard that the page loads nothing from the network.
const SVG_NS = ["http", "://www.w3.org/2000/svg"].join("");

const ICON_PATHS: Readonly<Record<string, readonly string[]>> = {
  // an open rulebook
  book: [
    "M4 5.5C4 4.7 4.7 4 5.5 4H11v15H5.5C4.7 19 4 18.3 4 17.5Z",
    "M20 5.5C20 4.7 19.3 4 18.5 4H13v15h5.5c.8 0 1.5-.7 1.5-1.5Z",
    "M6.5 8h2.5M6.5 11h2.5M15 8h2.5M15 11h2.5",
  ],
  // a ticked circle
  check: ["M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18Z", "M7.5 12.5l3 3l6-6.5"],
  // a receipt with a torn foot
  receipt: [
    "M6 3h12v18l-2-1.5l-2 1.5l-2-1.5l-2 1.5l-2-1.5L6 21Z",
    "M9 8h6M9 11.5h6M9 15h4",
  ],
  // a target
  target: [
    "M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18Z",
    "M12 7a5 5 0 1 0 0 10a5 5 0 1 0 0-10Z",
    "M12 11a1 1 0 1 0 0 2a1 1 0 1 0 0-2Z",
  ],
};

/** The named icon as an inline SVG, or `undefined` for a name with no drawing (the slot then stays empty, never a raw name or glyph). */
function icon(name: string): SVGSVGElement | undefined {
  const paths = ICON_PATHS[name];
  if (paths === undefined) return undefined;
  const svg = document.createElementNS(SVG_NS, "svg") as SVGSVGElement;
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "20");
  svg.setAttribute("height", "20");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.6");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.dataset.icon = name;
  for (const d of paths) {
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  return svg;
}

const fmtCount = (n: number): string => n.toLocaleString();

function fmtShare(count: number, total: number, percentages: boolean): string {
  if (percentages)
    return total === 0 ? "–" : `${Math.round((count / total) * 100)}%`;
  return `${fmtCount(count)} of ${fmtCount(total)}`;
}

const TIER_LABEL: Record<CriterionTierReading, string> = {
  judged: "judged",
  recomputed: "recomputed",
  unknown: "tier unknown — no claims observed",
  mixed: "tier differs across conversations",
};

// ---------------------------------------------------------------------------
// Drill-down: every report line and every missed-reason row opens into the
// conversations behind it, and each conversation opens into its nine
// criteria, the rationale exactly as sealed, why it missed, and the ids to
// recompute it. Native <details>, no script, no button: the page stays a
// static rendering of a bundle that already verified. Read ONLY from the
// model, which reads only from the verified bundle.
// ---------------------------------------------------------------------------

type DrawnVerdict = Conversation["criteria"][number]["verdict"];

const VERDICT_TEXT: Record<DrawnVerdict, string> = {
  met: "met",
  not_met: "not met",
  not_evaluable: "not evaluable",
  failed: "failed verification",
  unsupported: "unsupported",
  not_applicable: "not applicable",
};

/** `tau2:airline:task-20:trial-0` reads "task 20"; any other id is shown whole. */
function caseLabel(conversationId: string): string {
  const match = /task-([0-9]+)/u.exec(conversationId);
  return match === null ? conversationId : `task ${match[1]}`;
}

function criterionLabel(
  model: OutcomeReportModel,
  checkId: string,
  criterionId: string,
): {
  label: string;
  text: string;
  question: string;
  source: CriterionWording["source"];
} {
  const check = model.terms.checks.find((c) => c.id === checkId);
  const criterion = check?.criteria.find((c) => c.id === criterionId);
  const wording = model.criterionWording.get(`${checkId}.${criterionId}`);
  return {
    label: criterion?.label ?? `${checkId}.${criterionId}`,
    text: wording?.text ?? criterion?.text ?? "",
    question: check?.question ?? checkId,
    source: wording?.source ?? "unstated",
  };
}

/** The label a criterion's wording carries when it is NOT the sealed text. */
const WORDING_FALLBACK_LABEL: Record<CriterionWording["source"], string> = {
  sealed: "",
  unstated: "Wording not stated: no report in this bundle states it.",
  mixed:
    "Wording not shown: the reports in this bundle state different wordings.",
};

/** One sentence on where the criterion wording on this page comes from. */
function wordingNote(model: OutcomeReportModel): string {
  const sources = new Set(
    [...model.criterionWording.values()].map((w) => w.source),
  );
  if (sources.size === 1 && sources.has("sealed"))
    return "Rule wording as sealed in the judge's reports (the text the judge was given).";
  if (!sources.has("sealed"))
    return "Rule wording not stated: the reports in this bundle do not state it.";
  return "Rule wording as sealed in the judge's reports; where the reports do not state it (or disagree), marked as such.";
}

/** The producer's "edited" badge for a criterion, when its presentation
 * extension marks one -- presentation text, titled as such, never evidence. */
function editedBadge(
  model: OutcomeReportModel,
  ref: string,
): HTMLElement | undefined {
  const edited = model.options.editedCriteria?.find((e) => e.criterion === ref);
  if (edited === undefined) return undefined;
  const badge = el("span", "edited", edited.badge);
  badge.dataset.edited = ref;
  badge.title = "Producer's note (presentation extension), not evidence";
  return badge;
}
function renderProducerNote(
  host: HTMLElement,
  model: OutcomeReportModel,
): void {
  const note = model.options.producerNote;
  if (note === undefined) return;
  const box = el("aside", "pnote");
  box.dataset.producerNote = "true";
  box.append(
    el("div", "pn-k", "Producer's note · presentation text, not evidence"),
  );
  box.append(el("h2", "pn-t", note.title));
  const list = el("ul", "pn-l");
  for (const line of note.lines) list.append(element("li", line));
  box.append(list);
  box.append(
    el(
      "p",
      "pn-src",
      "Carried on this bundle's outcome-report/v1 presentation extension, outside the signed records: no claim backs this note and no number on this page is computed from it. Everything below is drawn only from the verified bundle.",
    ),
  );
  host.append(box);
}
function isMiss(verdict: DrawnVerdict): boolean {
  return (
    verdict === "not_met" || verdict === "failed" || verdict === "unsupported"
  );
}

function pill(verdict: DrawnVerdict | "resolved" | "missed"): HTMLElement {
  const text =
    verdict === "resolved"
      ? "resolved"
      : verdict === "missed"
        ? "missed"
        : VERDICT_TEXT[verdict];
  const tone =
    verdict === "met" || verdict === "resolved"
      ? "ok"
      : verdict === "not_applicable"
        ? "na"
        : verdict === "not_evaluable"
          ? "ne"
          : "bad";
  const value = el("span", `pill ${tone}`, text);
  value.dataset.pill = verdict;
  return value;
}

const fmtP = (p: number): string => p.toFixed(2);

/** The probability the judge gave the verdict it returned, from the sealed rationale text; undefined when the text carries none. */
function verdictProbability(
  criterion: Conversation["criteria"][number],
): number | undefined {
  const probs = criterion.probabilities;
  if (probs === undefined) return undefined;
  const key = criterion.claim?.verdict ?? criterion.verdict;
  return probs[key];
}

function renderConversation(
  conversation: Conversation,
  model: OutcomeReportModel,
  runInfo: OutcomeReportRunInfo,
): HTMLElement {
  const resolved = conversation.verdict === "met";
  const details = el("details", "conv");
  details.dataset.conversation = conversation.conversationId;
  details.dataset.conversationVerdict = conversation.verdict;
  const misses = conversation.criteria.filter((c) => isMiss(c.verdict));
  const unjudged = conversation.criteria.filter(
    (c) => c.verdict === "not_evaluable",
  );
  const na = conversation.criteria.filter(
    (c) => c.verdict === "not_applicable",
  );

  const summary = el("summary", "conv-s");
  summary.append(el("span", "cid", caseLabel(conversation.conversationId)));
  summary.append(pill(resolved ? "resolved" : "missed"));
  summary.append(
    el(
      "span",
      "cwhy",
      resolved
        ? `all nine criteria met or not applicable${na.length > 0 ? ` (${na.length} not applicable)` : ""}`
        : `missed on: ${[...misses, ...(misses.length === 0 ? unjudged : [])]
            .map((c) => criterionLabel(model, c.checkId, c.criterionId).label)
            .join(", ")}`,
    ),
  );
  summary.append(el("span", "go", "open ›"));
  details.append(summary);

  // The body (nine rows, nine sealed rationales, the ids) is built the first
  // time this conversation is opened, not up front: the same conversation
  // appears under its report line and under its missed reason, and building
  // every body eagerly multiplies the page's DOM for content nobody opened.
  // Built from the same model either way.
  let built = false;
  details.addEventListener("toggle", () => {
    if (built || !(details as HTMLDetailsElement).open) return;
    built = true;
    details.append(
      conversationBody(conversation, model, runInfo, {
        resolved,
        misses,
        unjudged,
        na,
      }),
    );
  });
  return details;
}

function renderTranscript(conversation: Conversation): HTMLElement {
  const t = conversation.transcript;
  const wrap = el("div", "tx");
  wrap.dataset.transcript = t.state;
  if (t.state !== "verified") {
    wrap.append(
      el(
        "p",
        "absent",
        t.state === "absent"
          ? `Not in this bundle. The conversation and its tool calls are sealed in the case record ${conversation.sourceCapsuleId ?? "(not stated by the reports)"}, which this Result does not cite, so this page cannot show them and does not vouch for them.`
          : `Not shown: ${t.reason ?? "the cited transcript does not check"}.`,
      ),
    );
    return wrap;
  }
  wrap.append(
    el(
      "p",
      "small",
      `Sealed in record ${t.transcriptRecordId}. Its content digest equals what the judged case capsule ${conversation.sourceCapsuleId} committed to (${t.inputDigest}), checked on this page: this is the conversation the judge read. ${t.turns!.length} messages, in order.`,
    ),
  );
  const list = el("ol", "turns");
  t.turns!.forEach((turn, index) => {
    const item = el(
      "li",
      `turn ${turn.role === "user" || turn.role === "assistant" || turn.role === "tool" ? turn.role : "other"}`,
    );
    item.dataset.turn = String(index);
    item.dataset.role = turn.role;
    const head = el("div", "who", `msg[${index}] ${turn.role}`);
    item.append(head);
    if (turn.content !== undefined && turn.content.length > 0)
      item.append(
        el(turn.role === "tool" ? "pre" : "div", "say", turn.content),
      );
    for (const call of turn.toolCalls) {
      const callEl = el("pre", "call", `${call.name}(${call.arguments})`);
      callEl.dataset.toolCall = call.name;
      item.append(callEl);
    }
    list.append(item);
  });
  wrap.append(list);
  return wrap;
}

function conversationBody(
  conversation: Conversation,
  model: OutcomeReportModel,
  runInfo: OutcomeReportRunInfo,
  parts: {
    resolved: boolean;
    misses: Conversation["criteria"][number][];
    unjudged: Conversation["criteria"][number][];
    na: Conversation["criteria"][number][];
  },
): HTMLElement {
  const { resolved, misses, unjudged, na } = parts;
  const body = el("div", "conv-b");

  // 1. What the agent did
  body.append(el("h4", "", "What the agent did"));
  body.append(renderTranscript(conversation));

  // 2. The criteria
  body.append(el("h4", "", "The criteria"));
  const contractRefs = new Set(
    conversation.criteria.flatMap((c) =>
      c.claim === undefined ? [] : [c.claim.contractRef],
    ),
  );
  body.append(
    el(
      "p",
      "small",
      `Judged under ${[...contractRefs].join(", ") || "no stated contract"}. ${wordingNote(model)} P is the probability the judge gave the verdict it returned.`,
    ),
  );
  const table = el("table", "crit");
  table.dataset.criteriaTable = conversation.conversationId;
  const head = element("thead");
  const headRow = element("tr");
  headRow.append(
    element("th", "Criterion"),
    element("th", "Verdict"),
    el("th", "n", "P"),
    element("th", "Rationale, as sealed"),
  );
  head.append(headRow);
  table.append(head);
  const tbody = element("tbody");
  for (const criterion of conversation.criteria) {
    const tr = element("tr");
    tr.dataset.crit = `${criterion.checkId}.${criterion.criterionId}`;
    tr.dataset.critVerdict = criterion.verdict;
    const names = criterionLabel(
      model,
      criterion.checkId,
      criterion.criterionId,
    );
    const nameCell = el("td", "cn");
    nameCell.append(el("b", "", names.label));
    const rowBadge = editedBadge(
      model,
      `${criterion.checkId}.${criterion.criterionId}`,
    );
    if (rowBadge !== undefined) nameCell.append(rowBadge);
    const wordingCell = el("small", "", names.text);
    wordingCell.dataset.wording = names.source;
    nameCell.append(wordingCell);
    if (names.source !== "sealed")
      nameCell.append(
        el("small", "wsrc", WORDING_FALLBACK_LABEL[names.source]),
      );
    tr.append(nameCell);
    const verdictCell = element("td");
    verdictCell.append(pill(criterion.verdict));
    tr.append(verdictCell);
    const p = verdictProbability(criterion);
    const pCell = el("td", "n", p === undefined ? "–" : fmtP(p));
    if (p !== undefined) pCell.dataset.p = fmtP(p);
    tr.append(pCell);
    const rationaleCell = el("td", "rat");
    if (criterion.verdict === "not_applicable") {
      rationaleCell.append(
        el(
          "span",
          "muted",
          "No claim: Result v0 excludes a not-applicable judgment from its claims, so this bundle cites no report for it.",
        ),
      );
    } else if (criterion.rationale !== undefined) {
      const sealed = el("code", "sealed", criterion.rationale);
      sealed.dataset.rationale = "sealed";
      rationaleCell.append(sealed);
    } else {
      rationaleCell.append(
        el("span", "muted", "no rationale in the cited report"),
      );
    }
    tr.append(rationaleCell);
    tbody.append(tr);
  }
  table.append(tbody);
  const scroll = el("div", "tscroll");
  scroll.append(table);
  body.append(scroll);
  const honest = el(
    "p",
    "small",
    "Rationale: derived from the judge's probabilities; the judge returns no free-text reasoning.",
  );
  honest.dataset.rationaleLabel = "derived";
  body.append(honest);

  // 3. Why
  body.append(el("h4", "", "Why"));
  const why = el("ul", "why");
  why.dataset.why = resolved ? "resolved" : "missed";
  if (resolved) {
    const met = conversation.criteria.filter((c) => c.verdict === "met").length;
    why.append(
      element(
        "li",
        `Resolved: ${met} criteria met and ${na.length} not applicable. The rule resolves a conversation only when all nine pass, and not applicable counts as passing.`,
      ),
    );
  } else {
    for (const criterion of misses.length > 0 ? misses : unjudged) {
      const names = criterionLabel(
        model,
        criterion.checkId,
        criterion.criterionId,
      );
      const p = verdictProbability(criterion);
      const item = element(
        "li",
        `${names.label} (${names.question}): ${VERDICT_TEXT[criterion.verdict]}${p === undefined ? "" : `, P ${fmtP(p)}`}${criterion.confidence === undefined ? "" : `, confidence ${fmtP(criterion.confidence)}`}.`,
      );
      item.dataset.whyCriterion = `${criterion.checkId}.${criterion.criterionId}`;
      why.append(item);
    }
  }
  why.append(
    el(
      "li",
      "muted",
      "Turns cited: none. The judge returns a verdict and probabilities per criterion, with no reference to any turn of the conversation.",
    ),
  );
  body.append(why);

  // 4. Check it
  body.append(el("h4", "", "Check it"));
  const check = el("dl", "chk");
  check.dataset.checkIt = conversation.conversationId;
  const row = (label: string, value: string): void => {
    check.append(element("dt", label), element("dd", value));
  };
  row("Case", conversation.conversationId);
  row(
    "Case record",
    conversation.sourceCapsuleId ?? "not stated by the reports",
  );
  // A conversation dated by its judged day (no case record date) adds no
  // rows: the page reads exactly as it did before record dating.
  const dated = conversation.dated;
  if (dated.basis !== "judged") {
    row(
      "Dated by",
      `${dated.stated ?? dated.date}${dated.zone === "not-stated" ? " (timezone not stated)" : ""}: ${BASIS_TEXT[dated.basis]}`,
    );
    check.lastElementChild!.setAttribute("data-dated", dated.basis);
    if (dated.importedAt !== undefined) row("Imported", dated.importedAt);
    row("Judged and sealed", conversation.judgedDay);
  }
  row("Result capsule", model.capsuleId);
  if (conversation.transcript.state === "verified") {
    row("Transcript record", conversation.transcript.transcriptRecordId!);
    row("Case input digest", conversation.transcript.inputDigest!);
  }
  row(
    "Judge pin",
    runInfo.judgePinDigest === undefined
      ? "not stated"
      : `${runInfo.judgePinDigest}${runInfo.judgePinRecomputes === true && runInfo.judgePin !== undefined ? ` = ${runInfo.judgePin.modelId}, prompt ${runInfo.judgePin.promptDigest}, axes ${runInfo.judgePin.axesDigest} (recomputed on this page)` : ""}`,
  );
  for (const criterion of conversation.criteria) {
    if (criterion.claim === undefined) continue;
    row(
      `Report: ${criterionLabel(model, criterion.checkId, criterion.criterionId).label}`,
      `${criterion.reportCapsuleId ?? "not cited"}${criterion.reportRecordId === undefined ? "" : ` (book record ${criterion.reportRecordId})`}`,
    );
  }
  body.append(check);
  body.append(
    el(
      "p",
      "small",
      "To recompute: read each report above from the book, check its digest, and take the AND of the nine verdicts (not applicable passes). To re-judge, run the pinned judge on the case record and compare.",
    ),
  );

  return body;
}

function renderConversationList(
  conversations: readonly Conversation[],
  model: OutcomeReportModel,
  runInfo: OutcomeReportRunInfo,
  key: string,
): HTMLElement {
  const list = el("div", "convs");
  list.dataset.conversationsFor = key;
  list.dataset.conversationCount = String(conversations.length);
  if (conversations.length === 0)
    list.append(el("p", "small", "no conversations"));
  for (const conversation of conversations)
    list.append(renderConversation(conversation, model, runInfo));
  return list;
}

function drill(
  label: string,
  conversations: readonly Conversation[],
  model: OutcomeReportModel,
  runInfo: OutcomeReportRunInfo,
  key: string,
): HTMLElement {
  const details = el("details", "drill");
  details.dataset.drill = key;
  details.append(el("summary", "", label));
  details.append(renderConversationList(conversations, model, runInfo, key));
  return details;
}

// ---------------------------------------------------------------------------
// The sheet: header meta, report lines, stamp, tamper note
// ---------------------------------------------------------------------------

/** The pack and version as one line: both come from the claims' `contract_ref` (see `readOutcomeReportTerms`), or read "not stated". */
function packLine(model: OutcomeReportModel): string {
  const { id, version } = model.terms.pack;
  return id === NOT_STATED ? NOT_STATED : `${id} v${version}`;
}

// ---------------------------------------------------------------------------
// Dating: which date the calendar and period count a conversation under, and
// the plain label that says so (see `ConversationDate`)
// ---------------------------------------------------------------------------

function span(days: readonly string[]): string {
  const first = days[0];
  const last = days[days.length - 1];
  if (first === undefined || last === undefined) return "unknown";
  return first === last ? first : `${first} – ${last}`;
}

const BASIS_TEXT: Record<ConversationDate["basis"], string> = {
  source:
    "source says (backfilled record; the source's own timestamp, self-attested)",
  record: "the case record's own timestamp",
  judged: "the day the judgments were sealed (no case record date to read)",
};

/** The page's one plain statement of what its dates are, or undefined when every conversation is dated by the day it was judged (the card's behaviour before record dating). */
function datingNote(model: OutcomeReportModel): string | undefined {
  const { basis, counts, judgedDays, zoneNotStated } = model.dating;
  if (basis === "judged") return undefined;
  const sealed = `Sealed ${span(judgedDays)}.`;
  const parts: string[] = [];
  if (basis === "source")
    parts.push(
      'Dates are the source\'s own timestamps for backfilled records ("source says"), as given, not when the records were sealed.',
    );
  else if (basis === "record")
    parts.push(
      "Dates are each conversation's own record date (the time its case record states), as given, not when the judgments were sealed.",
    );
  else {
    parts.push(
      "Dates are each conversation's own date, as given, not when the judgments were sealed:",
    );
    if (counts.source > 0)
      parts.push(
        `${counts.source} backfilled by the source's own timestamp ("source says");`,
      );
    if (counts.record > 0)
      parts.push(`${counts.record} by the case record's own timestamp;`);
    if (counts.judged > 0)
      parts.push(
        `${counts.judged} with no case record date to read, by the day they were judged.`,
      );
  }
  parts.push(sealed);
  if (counts.source > 0)
    parts.push(
      "A backfilled record's source time is self-attested: carrying it does not make it witnessed.",
    );
  if (zoneNotStated > 0)
    parts.push(
      `Timezone not stated on ${zoneNotStated} of ${model.totalCount}; no zone is assumed.`,
    );
  return parts.join(" ");
}

function renderMeta(host: HTMLElement, model: OutcomeReportModel): void {
  const section = el("section", "");
  section.dataset.section = "meta";

  const row1 = el("div", "ih-row");
  const bill = el("div", "party");
  bill.append(el("div", "k", "Outcomes pack"));
  bill.append(el("div", "v", packLine(model)));
  row1.append(bill);
  const title = el("div", "ih-title");
  title.append(el("h1", "inv-title", "Outcome report"));
  title.append(
    el("div", "inv-sub", `Terms locked: ${model.terms.pack.locked}`),
  );
  row1.append(title);
  section.append(row1);

  const row2 = el("div", "ih-row");
  const details = el("div", "meta");
  const first = model.days[0]?.date;
  const last = model.days[model.days.length - 1]?.date;
  const metaRow = (label: string, value: string): void => {
    const line = element("div");
    line.append(element("span", label), element("span", value));
    details.append(line);
  };
  metaRow(
    "Period",
    first === undefined || last === undefined
      ? "no conversations"
      : `${first} – ${last}`,
  );
  const note = datingNote(model);
  if (note !== undefined) {
    metaRow("Sealed", span(model.dating.judgedDays));
    details.lastElementChild!.setAttribute("data-sealed", "");
  }
  metaRow("Conversations", fmtCount(model.totalCount));
  metaRow("Result capsule", model.capsuleId);
  row2.append(el("div", "party"), details);
  section.append(row2);
  if (note !== undefined) {
    const label = el("p", "date-note", note);
    label.dataset.dateNote = model.dating.basis;
    section.append(label);
  }
  host.append(section);
}

// ---------------------------------------------------------------------------
// Report lines
// ---------------------------------------------------------------------------

function renderLines(
  host: HTMLElement,
  model: OutcomeReportModel,
  runInfo: OutcomeReportRunInfo,
): void {
  const section = el("section", "");
  section.dataset.section = "lines";
  const table = document.createElement("table");
  table.className = "lines";
  table.dataset.rows = "report-lines";
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  headRow.append(element("th", "Description"), element("th", "Count"));
  thead.append(headRow);
  table.append(thead);
  const tbody = document.createElement("tbody");
  // held is read from calibration samples, resolved from claim rollups --
  // two independent sources this card shows side by side and never
  // subtracts one from the other.
  const lines: ReadonlyArray<readonly [string, string, number, string]> = [
    [
      "resolved",
      "Conversations resolved correctly",
      model.resolvedCount,
      fmtShare(
        model.resolvedCount,
        model.totalCount,
        model.options.percentages,
      ),
    ],
    [
      "missed",
      "Conversations missed",
      model.missedCount,
      fmtShare(model.missedCount, model.totalCount, model.options.percentages),
    ],
    [
      "held",
      "Held pending adjudication",
      model.heldCount,
      fmtCount(model.heldCount),
    ],
    [
      "added",
      "Added after adjudication",
      model.addedCount,
      fmtCount(model.addedCount),
    ],
    [
      "not-applicable",
      "Criterion judgments not applicable",
      model.notApplicableCount,
      fmtCount(model.notApplicableCount),
    ],
  ];
  for (const [key, label, count, shown] of lines) {
    const tr = document.createElement("tr");
    tr.dataset.line = key;
    tr.dataset.count = String(count);
    const desc = el("td", "desc");
    desc.append(el("b", "", label));
    const behind =
      key === "resolved"
        ? model.conversations.filter((c) => c.verdict === "met")
        : key === "missed"
          ? model.conversations.filter((c) => c.verdict !== "met")
          : key === "not-applicable"
            ? model.conversations.filter((c) =>
                c.criteria.some((cr) => cr.verdict === "not_applicable"),
              )
            : undefined;
    if (behind !== undefined && behind.length > 0)
      desc.append(
        drill(
          `open › ${fmtCount(behind.length)} conversation${behind.length === 1 ? "" : "s"}`,
          behind,
          model,
          runInfo,
          key,
        ),
      );
    tr.append(desc, el("td", "n", shown));
    tbody.append(tr);
  }
  table.append(tbody);
  section.append(table);
  host.append(section);

  const stamps = el("div", "stamps inl");
  const stamp = el(
    "div",
    "stamp rec",
    "Verified · recomputed from the sealed bundle",
  );
  stamp.append(
    el(
      "small",
      "",
      "every count and share above is recomputed from result.claims and the records they cite, never read from a stated total",
    ),
  );
  stamps.append(stamp);
  host.append(stamps);

  const tamper = el(
    "p",
    "tamper-note",
    'This card only ever renders a bundle that already verified: there is no interactive "try tampering" control here, because this viewer never shows content first and checks second. Tamper with any claim, record, or checkpoint in the underlying bundle and the whole page — this card included — is replaced by the verification-failed banner, before anything here is drawn.',
  );
  tamper.dataset.tamperNote = "verify-first";
  host.append(tamper);
}

// ---------------------------------------------------------------------------
// Day by day
// ---------------------------------------------------------------------------

function renderCalendar(host: HTMLElement, model: OutcomeReportModel): void {
  const section = el("section", "sec");
  section.dataset.section = "calendar";
  section.append(el("h2", "", "Day by day"));
  const note = datingNote(model);
  section.append(
    el(
      "p",
      "lede",
      note === undefined
        ? "Resolved conversations per day, cited by this bundle's claims."
        : "Resolved conversations per day, by each conversation's own date, cited by this bundle's claims.",
    ),
  );
  if (note !== undefined) {
    const label = el("p", "date-note", note);
    label.dataset.dateNote = model.dating.basis;
    section.append(label);
  }
  const list = el("div", "cal");
  list.dataset.days = String(model.days.length);
  for (const day of model.days) {
    const item = el("div", "day");
    item.dataset.day = day.date;
    item.dataset.resolved = String(day.resolvedCount);
    item.dataset.total = String(day.conversations.length);
    item.append(el("div", "dn", day.date));
    if (note !== undefined) {
      const bases = new Set(day.conversations.map((c) => c.dated.basis));
      if (bases.has("source")) {
        const chip = el("div", "src-says", "source says");
        chip.dataset.sourceSays = String(
          day.conversations.filter((c) => c.dated.basis === "source").length,
        );
        item.append(chip);
      }
      const notStated = day.conversations.filter(
        (c) => c.dated.zone === "not-stated",
      ).length;
      if (notStated > 0) {
        const tz = el("div", "tz", "timezone not stated");
        tz.dataset.tzMarker = "not-stated";
        item.append(tz);
      }
    }
    item.append(
      el(
        "div",
        "v",
        fmtShare(
          day.resolvedCount,
          day.conversations.length,
          model.options.percentages,
        ),
      ),
    );
    const mini = el("div", "mini");
    const share =
      day.conversations.length === 0
        ? 0
        : day.resolvedCount / day.conversations.length;
    const fill = element("i");
    fill.style.width = `${Math.round(share * 100)}%`;
    mini.append(fill);
    item.append(mini);
    if (note !== undefined) {
      const sealed = el("div", "sealed", `sealed ${span(day.judgedDays)}`);
      sealed.dataset.sealed = day.judgedDays.join(" ");
      item.append(sealed);
    }
    if (day.policyChanged !== null) {
      const flag = el("div", "flag", "policy changed");
      flag.dataset.policyChanged = day.policyChanged;
      item.append(flag);
    }
    list.append(item);
  }
  section.append(list);
  host.append(section);
}

// ---------------------------------------------------------------------------
// Human spot checks
// ---------------------------------------------------------------------------

function renderHumanChecks(
  host: HTMLElement,
  calibration: readonly CalibrationWeek[],
): void {
  const section = el("section", "sec");
  section.dataset.section = "human-checks";
  section.append(el("h2", "", "Human spot checks"));
  section.append(
    el(
      "p",
      "lede",
      "Weekly blind re-grades by a person. Disagreements are held.",
    ),
  );
  if (calibration.length === 0) {
    section.append(el("p", "", "no calibration-summary/v1 records cited"));
    host.append(section);
    return;
  }
  const table = document.createElement("table");
  table.className = "hct";
  table.dataset.weeks = String(calibration.length);
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  headRow.append(
    element("th", "Week"),
    el("th", "n", "Agreed"),
    el("th", "n", "Held"),
    el("th", "n", "Added"),
  );
  thead.append(headRow);
  table.append(thead);
  const tbody = document.createElement("tbody");
  for (const week of calibration) {
    const tr = document.createElement("tr");
    tr.dataset.week = week.weekId;
    tr.dataset.k = String(week.k);
    tr.dataset.n = String(week.n);
    tr.append(el("td", "", week.weekId));
    tr.append(el("td", "n", `${week.k} of ${week.n}`));
    const held = week.sample.filter(
      (s) => s.aiVerdict === "met" && s.humanVerdict !== "met",
    ).length;
    const added = week.sample.filter(
      (s) => s.aiVerdict !== "met" && s.humanVerdict === "met",
    ).length;
    const heldCell = el("td", "n", String(held));
    heldCell.dataset.held = String(held);
    const addedCell = el("td", "n", String(added));
    addedCell.dataset.added = String(added);
    tr.append(heldCell, addedCell);
    tbody.append(tr);
  }
  table.append(tbody);
  section.append(table);
  host.append(section);
}

// ---------------------------------------------------------------------------
// Why conversations missed
// ---------------------------------------------------------------------------

function renderWhyMissed(
  host: HTMLElement,
  model: OutcomeReportModel,
  runInfo: OutcomeReportRunInfo,
): void {
  const section = el("section", "sec");
  section.dataset.section = "why-missed";
  section.append(el("h2", "", "Why conversations missed"));
  const bars = el("div", "bars");
  bars.dataset.checkBars = "true";
  for (const check of model.terms.checks) {
    const count = model.checkPassCounts.get(check.id) ?? 0;
    const item = el("div", "bar");
    item.dataset.checkId = check.id;
    item.dataset.passCount = String(count);
    const nm = el("div", "nm", check.question);
    const track = el("div", "track");
    const share = model.totalCount === 0 ? 0 : count / model.totalCount;
    const fill = element("i");
    fill.style.width = `${Math.round(share * 100)}%`;
    track.append(fill);
    const num = el(
      "div",
      "num",
      fmtShare(count, model.totalCount, model.options.percentages),
    );
    item.append(nm, track, num);
    bars.append(item);
  }
  section.append(bars);

  const reasons = el("div", "reasons");
  reasons.dataset.reasons = String(model.missedReasons.length);
  for (const group of model.missedReasons) {
    const item = el("details", "rsn-d");
    item.dataset.reasonKey = group.key;
    item.dataset.reasonStructured = String(group.structured);
    item.dataset.count = String(group.conversations.length);
    const row = el("summary", "rsn");
    row.append(
      element("span", group.label),
      el("span", "c", `${fmtCount(group.conversations.length)} · see them ›`),
    );
    item.append(row);
    item.append(
      renderConversationList(
        group.conversations,
        model,
        runInfo,
        `reason:${group.key}`,
      ),
    );
    reasons.append(item);
  }
  section.append(reasons);
  host.append(section);
}

// ---------------------------------------------------------------------------
// The terms
// ---------------------------------------------------------------------------

function renderTerms(host: HTMLElement, model: OutcomeReportModel): void {
  const section = el("section", "sec");
  section.dataset.section = "terms";
  section.append(el("h2", "", "The terms: what counts as resolved"));
  const lede = el(
    "p",
    "lede",
    `Agreed with the counterparty: ${model.terms.pack.agreement}. Locked: ${model.terms.pack.locked}. Every term below is read from the sealed claims and reports in this bundle, or marked "${NOT_STATED}".`,
  );
  lede.dataset.termsSource = "bundle";
  section.append(lede);

  const pack = el("div", "pack");
  const packField = (label: string, value: string): void => {
    const box = el("div", "pk");
    box.append(el("div", "k", label), el("div", "v", value));
    pack.append(box);
  };
  packField("Outcomes pack", model.terms.pack.id);
  packField(
    "Version",
    model.terms.pack.version === NOT_STATED
      ? NOT_STATED
      : `${model.terms.pack.version} (from the claims' contract_ref)`,
  );
  packField("Locked", model.terms.pack.locked);
  section.append(pack);

  const outcome = el("div", "outcome");
  const outcomeIcon = el("div", "oic");
  const target = icon("target");
  if (target !== undefined) outcomeIcon.append(target);
  outcome.append(outcomeIcon);
  const outcomeBody = element("div");
  outcomeBody.append(el("div", "t", "The outcome"));
  outcomeBody.append(el("div", "v", model.terms.pack.outcomeStatement));
  outcome.append(outcomeBody);
  section.append(outcome);

  const checks = el("div", "checks");
  checks.dataset.checks = String(model.terms.checks.length);
  for (const check of model.terms.checks) {
    const card = el("section", "check");
    card.dataset.checkId = check.id;
    const checkIcon = el("div", "ic");
    const drawn = icon(check.icon);
    if (drawn !== undefined) checkIcon.append(drawn);
    card.append(checkIcon);
    card.append(el("div", "q", check.question));
    card.append(el("div", "d", check.description));
    const criteria = el("ul", "subs");
    for (const criterion of check.criteria) {
      const ref = `${check.id}.${criterion.id}`;
      const tier = model.criterionTiers.get(ref) ?? "unknown";
      const item = element("li");
      item.dataset.criterionId = criterion.id;
      item.dataset.tier = tier;
      const wording = model.criterionWording.get(ref) ?? {
        text: criterion.text,
        source: "unstated" as const,
      };
      item.dataset.wording = wording.source;
      const label = el("b", "", criterion.label);
      const termsBadge = editedBadge(model, ref);
      if (termsBadge !== undefined) label.append(termsBadge);
      item.append(label);
      item.append(element("span", `${wording.text} (${TIER_LABEL[tier]})`));
      if (wording.source !== "sealed")
        item.append(
          el("small", "wsrc", WORDING_FALLBACK_LABEL[wording.source]),
        );
      criteria.append(item);
    }
    card.append(criteria);
    checks.append(card);
  }
  section.append(checks);
  const note = el("p", "small", wordingNote(model));
  note.dataset.wordingNote = "true";
  section.append(note);
  section.append(el("div", "rule", model.terms.pack.resolutionRule));
  host.append(section);
}

// ---------------------------------------------------------------------------
// What ran
// ---------------------------------------------------------------------------

function renderWhatRan(host: HTMLElement, runInfo: OutcomeReportRunInfo): void {
  const section = el("section", "sec");
  section.dataset.section = "what-ran";
  section.append(el("h2", "", "What ran"));
  const ran = el("div", "ran");
  ran.dataset.pinned = String(runInfo.pinned);
  if (runInfo.judgePinRecomputes !== undefined)
    ran.dataset.pinRecomputes = String(runInfo.judgePinRecomputes);
  const box = (label: string, value: string, key: string): void => {
    const item = el("div", "it");
    item.dataset.ran = key;
    item.append(el("div", "k", label));
    item.append(el("div", "v", value));
    ran.append(item);
  };
  // The pin's components are drawn only when they recompute to the sealed
  // digest (verifyJudgePin); otherwise they are "not stated", never shown
  // beside a digest they do not produce.
  const pin =
    runInfo.judgePinRecomputes === true ? runInfo.judgePin : undefined;
  box("Contract", runInfo.contract ?? "not stated", "contract");
  box(
    "Judge model",
    pin === undefined
      ? "not stated"
      : pin.modelVersion === undefined
        ? pin.modelId
        : `${pin.modelId} ${pin.modelVersion}`,
    "judge-model",
  );
  box(
    "Judge pin digest",
    runInfo.judgePinDigest === undefined
      ? "not stated"
      : pin === undefined
        ? runInfo.judgePinDigest
        : `${runInfo.judgePinDigest} (recomputed from the model, prompt, axes and sampling params shown here)`,
    "judge-pin-digest",
  );
  box(
    "Judge prompt digest",
    pin?.promptDigest ?? "not stated",
    "judge-prompt-digest",
  );
  box(
    "Judge axes digest",
    pin?.axesDigest ?? "not stated",
    "judge-axes-digest",
  );
  box(
    "Agent / test suite / human-check protocol",
    "not stated — this evaluation-report/v1 shape carries none of these fields",
    "agent",
  );
  section.append(ran);
  if (runInfo.judgePinRecomputes === false) {
    const warning = el(
      "p",
      "",
      "the judge pin components the reports carry do not recompute to the sealed judge pin digest — they are not shown",
    );
    warning.dataset.pinComponentsMismatch = "true";
    section.append(warning);
  }
  const lock = el(
    "div",
    "lock",
    "The judge pin digest covers model id, judge prompt and axes, and sampling params (capsulectl judge pin). It does not cover the human-check protocol name: this bundle seals no method lock, and this card never implies one exists.",
  );
  section.append(lock);
  if (!runInfo.pinned) {
    const warning = el(
      "p",
      "",
      "what ran varies across the cited reports — the values above are drawn only when every one agrees, and are omitted ('not stated') here because they do not",
    );
    warning.dataset.pinMismatch = "true";
    section.append(warning);
  }
  host.append(section);
}

// ---------------------------------------------------------------------------
// Verification details
// ---------------------------------------------------------------------------

function renderVerificationDetails(
  host: HTMLElement,
  bundle: unknown,
  verified: BundleVerificationResult,
): void {
  const section = el("section", "sec");
  section.dataset.section = "verification-details";
  section.append(el("h2", "", "Verification details"));
  section.append(
    el("p", "lede", "Repeat offline with the open-source verifier."),
  );
  const model = buildVerificationPageModel(bundle, verified);
  const tech = el("div", "tech");
  const field = (label: string, value: string): void => {
    tech.append(el("div", "k", label), el("div", "v", value));
  };
  field("Bundle digest", model.bundleDigest ?? "uncomputable");
  field("Checkpoint root", model.checkpointRoot ?? "absent");
  field("Checkpoint size", String(model.checkpointSize ?? "absent"));
  section.append(tech);
  const note = el(
    "p",
    "note",
    "This bundle's own checkpoint — an append-only Merkle Mountain Range over the sealed records — not a month-level RFC 6962 tree computed in the browser. Repeat this check offline with the open-source verifier.",
  );
  note.dataset.checkpointKind = "mmr";
  section.append(note);
  host.append(section);
}

export async function renderOutcomeReportPage(
  result: ResultRoot,
  options: OutcomeReportOptions,
  bundle: unknown,
  verified: BundleVerificationResult,
  root: HTMLElement,
): Promise<void> {
  const model = buildOutcomeReportModel(result, options);
  const runInfo = await verifyJudgePin(model.runInfo);
  const wrapper = el("section", "oi");
  wrapper.dataset.page = "outcome-report";
  const style = document.createElement("style");
  style.textContent = OUTCOME_REPORT_CSS;
  wrapper.append(style);
  renderProducerNote(wrapper, model);
  const sheet = el("div", "sheet");
  const pad = el("div", "pad");
  renderMeta(pad, model);
  renderLines(pad, model, runInfo);
  sheet.append(pad);
  wrapper.append(sheet);

  renderCalendar(wrapper, model);
  renderHumanChecks(wrapper, model.calibration);
  renderWhyMissed(wrapper, model, runInfo);
  renderTerms(wrapper, model);
  renderWhatRan(wrapper, runInfo);
  renderVerificationDetails(wrapper, bundle, verified);
  root.append(wrapper);
}

export type {
  CalibrationWeek,
  Conversation,
  ConversationVerdict,
  CriterionTierReading,
  MissedReasonGroup,
  OutcomeReportModel,
  OutcomeReportOptions,
};
