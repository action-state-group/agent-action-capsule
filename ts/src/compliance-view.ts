import type { BundleVerificationResult } from "./bundle.js";
import {
  buildComplianceModel,
  type ComplianceModel,
  type ComplianceFindingModel,
  type ObligationModel,
  type ObligationRowModel,
  type Session,
  type SessionTest,
  type TierReading,
} from "./compliance.js";
import type { CompliancePresentation } from "./compliance-presentation.js";
import { COMPLIANCE_CSS } from "./compliance-styles.js";
import { NOT_STATED } from "./outcome-report.js";
import { BASIS_TEXT, datingStatement, span } from "./outcome-report-view.js";
import type { ResultRoot } from "./result-root.js";

/**
 * The EU AI Act obligations-report card. Called from
 * `evidence-graph-view.ts` in place of `renderResultPage` when the bundle's
 * `eu-ai-act-compliance/v1` extension opts in, after the same verify-first
 * gate every other root family goes through -- nothing here ever runs on a
 * bundle that did not verify. See compliance.ts for where every value on the
 * page comes from: counts, verdicts, test wording, tiers and the pack from
 * the sealed records (or "not stated"); the regulatory mapping from the
 * producer's extension, labelled as such.
 *
 * The whole card renders inside one `.cc`-classed wrapper with its own
 * `<style>` (`COMPLIANCE_CSS`) as its first child. Drill-down uses native
 * `<details>`/`<summary>`: keyboard-accessible, no script-driven modal.
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

/**
 * Producer text: the eu-ai-act-compliance/v1 mapping, carried beside the
 * signed records and signed by no one. Set in italics (`<i>`, the browser's
 * own style) and tagged `data-source="producer"`, so it never reads as a
 * sealed finding; the header's basis line says what the italics mean.
 */
function producerText(text: string): HTMLElement {
  const value = element("i", text);
  value.dataset.source = "producer";
  value.title = "The producer's mapping, not a sealed record";
  return value;
}

/** `text` in an element of its own, as producer text when `producer` is true. */
function maybeProducer(
  tag: string,
  className: string,
  text: string,
  producer: boolean,
): HTMLElement {
  if (!producer) return el(tag, className, text);
  const value = el(tag, className);
  value.append(producerText(text));
  return value;
}

const fmt = (n: number): string => n.toLocaleString();

const SEVERITY_CLASS: Record<string, string> = {
  High: "high",
  Medium: "medium",
  Low: "low",
};

function severityPill(severity: string): HTMLElement {
  const cls = SEVERITY_CLASS[severity] ?? "medium";
  return el("span", `sev ${cls}`, severity);
}

function tierBadge(tier: TierReading): HTMLElement {
  const text =
    tier === "judged"
      ? "judged"
      : tier === "recomputed"
        ? "recomputed"
        : tier === "mixed"
          ? "tier differs across reports"
          : "tier not stated";
  const badge = el(
    "span",
    `kind ${tier === "judged" || tier === "recomputed" ? tier : "unstated"}`,
    text,
  );
  badge.dataset.tier = tier;
  return badge;
}

function statusPill(statusClass: string, text: string): HTMLElement {
  return el("span", `st ${statusClass}`, text);
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

function renderHeader(host: HTMLElement, model: ComplianceModel): void {
  const hd = el("div", "hd");
  hd.dataset.section = "header";
  hd.append(el("div", "kicker", "EU AI Act obligations report"));
  hd.append(el("h1", "", model.regulation));
  const pack =
    model.pack.id === NOT_STATED
      ? `Pack ${NOT_STATED}`
      : `Pack ${model.pack.id} v${model.pack.version}`;
  hd.append(
    el(
      "div",
      "sub",
      `${pack} · ${fmt(model.obligations.length)} obligations · ${fmt(model.totalSessions)} sessions · Result capsule ${model.capsuleId}`,
    ),
  );
  const basis = el(
    "p",
    "na",
    `Counts, verdicts, test wording, tiers and the pack are read from the sealed claims and reports in this bundle, or marked "${NOT_STATED}". Obligation titles, test names, the article, the plain-language summary, applicability, method, finding recommendations and owners, and the notes on undecided tests and quality checks are the producer's mapping, set in italics: carried on this bundle's eu-ai-act-compliance/v1 extension outside the signed records.`,
  );
  basis.dataset.basis = "terms";
  hd.append(basis);
  host.append(hd);
}

// ---------------------------------------------------------------------------
// Section 1: summary
// ---------------------------------------------------------------------------

function obligationStatus(obligation: ObligationModel): {
  cls: string;
  text: string;
} {
  const exceptions = obligation.rows.reduce((sum, r) => sum + r.notMetCount, 0);
  // Absent is never pass: an obligation whose rows were never actually
  // evaluated (no met, no not_met -- the same all-not_evaluable shape
  // renderTests() already detects per row) reads "Not evaluable", never
  // "No exceptions". Checked before the exception count: a not-yet-applicable
  // obligation keeps saying so, alongside "not evaluable".
  const evaluated = obligation.rows.some(
    (r) => r.metCount > 0 || r.notMetCount > 0,
  );
  if (!evaluated)
    return {
      cls: "ne",
      text:
        obligation.applicability.status === "future"
          ? "Not yet applicable · not evaluable"
          : "Not evaluable",
    };
  if (obligation.applicability.status === "not stated")
    return exceptions > 0
      ? { cls: "exc", text: `Exceptions noted (${fmt(exceptions)})` }
      : { cls: "ok", text: "No exceptions" };
  if (obligation.applicability.status === "future")
    return exceptions > 0
      ? {
          cls: "future",
          text: `Not yet applicable · ${fmt(exceptions)} exceptions (readiness)`,
        }
      : { cls: "future", text: "Not yet applicable · no exceptions" };
  return exceptions > 0
    ? { cls: "exc", text: `Exceptions noted (${fmt(exceptions)})` }
    : { cls: "ok", text: "No exceptions" };
}

function renderSummary(host: HTMLElement, model: ComplianceModel): void {
  const section = el("section", "");
  section.dataset.section = "summary";
  section.append(el("h2", "", "1. Summary"));
  section.append(
    el(
      "p",
      "lede",
      "Results are stated as counts of sessions; no overall compliance percentage is given.",
    ),
  );
  const table = document.createElement("table");
  table.className = "grid";
  table.dataset.rows = "summary";
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  headRow.append(
    element("th", "Article"),
    element("th", "Obligation"),
    element("th", "Applicability"),
    element("th", "Status"),
  );
  thead.append(headRow);
  table.append(thead);
  const tbody = document.createElement("tbody");
  for (const obligation of model.obligations) {
    const row = document.createElement("tr");
    row.dataset.obligation = obligation.key;
    const status = obligationStatus(obligation);
    row.append(
      maybeProducer("td", "b", obligation.article, obligation.mapped),
      maybeProducer("td", "", obligation.title, obligation.mapped),
      maybeProducer("td", "", obligation.applicability.note, obligation.mapped),
    );
    const statusCell = document.createElement("td");
    statusCell.append(statusPill(status.cls, status.text));
    row.append(statusCell);
    tbody.append(row);
  }
  table.append(tbody);
  section.append(table);
  host.append(section);
}

// ---------------------------------------------------------------------------
// Sessions drill-down (shared by test rows and findings)
// ---------------------------------------------------------------------------

function checkItBlock(test: SessionTest): HTMLElement {
  const box = el("div", "ck");
  box.dataset.crit = test.criterionId;
  box.dataset.critVerdict = test.verdict;
  const head = el("div", "h");
  const label =
    test.verdict === "met"
      ? "✓ met"
      : test.verdict === "not_met"
        ? "✗ not met"
        : test.verdict === "not_applicable"
          ? "— not applicable"
          : test.verdict === "failed"
            ? "✗ failed verification (counted as an exception)"
            : test.verdict === "unsupported"
              ? "✗ unsupported: its evidence is not in this bundle (counted as an exception)"
              : "– not evaluable";
  head.append(element("span", label));
  head.append(tierBadge(test.tier));
  box.append(head);
  if (test.rationale !== undefined)
    box.append(el("div", "why", test.rationale));
  const ev = el("div", "ev");
  ev.append(element("span", "Evidence: "));
  if (test.reportDigest !== undefined)
    ev.append(element("code", test.reportDigest));
  if (test.contract !== undefined) ev.append(element("code", test.contract));
  if (test.judgePinDigest !== undefined)
    ev.append(element("code", test.judgePinDigest));
  if (test.reportDigest === undefined) ev.append(element("span", "absent"));
  box.append(ev);
  return box;
}

function renderTranscript(session: Session): HTMLElement {
  const t = session.transcript;
  const wrap = el("div", "tx");
  wrap.dataset.transcript = t.state;
  if (t.state !== "verified") {
    wrap.append(
      el(
        "div",
        "ev",
        t.state === "absent"
          ? `Transcript: not in this bundle. The conversation is sealed in the case record ${session.sourceCapsuleId ?? "(not stated by the reports)"}; this page cannot show it and does not vouch for it.`
          : `Transcript: not shown: ${t.reason ?? "the cited transcript does not check"}.`,
      ),
    );
    return wrap;
  }
  wrap.append(
    el(
      "div",
      "ev",
      `Transcript: sealed in record ${t.transcriptRecordId}; its digest equals what the judged case capsule committed to (${t.inputDigest}), checked on this page. ${t.turns!.length} messages, in order.`,
    ),
  );
  for (const turn of t.turns!) {
    const line = el("div", `turn ${turn.role}`);
    line.append(el("b", "", `${turn.role}: `));
    if (turn.content !== undefined) line.append(element("span", turn.content));
    for (const call of turn.toolCalls)
      line.append(el("code", "", ` ${call.name}(${call.arguments})`));
    wrap.append(line);
  }
  return wrap;
}

function renderSessionDetails(session: Session): HTMLElement {
  const details = document.createElement("details");
  details.className = "session";
  details.dataset.session = session.conversationId;
  const summary = document.createElement("summary");
  summary.textContent = `${session.conversationId} · ${session.day}`;
  details.append(summary);
  // Which date the session is counted under, verbatim, beside the sealed day:
  // the outcome card's drill-down line, so a backfilled session never reads
  // as if it happened on the day it was sealed.
  const dated = session.dated;
  if (dated.basis !== "judged") {
    const line = el(
      "div",
      "",
      `${dated.stated ?? dated.date}${dated.zone === "not-stated" ? " (timezone not stated)" : ""}: ${BASIS_TEXT[dated.basis]}`,
    );
    line.dataset.dated = dated.basis;
    details.append(line);
    if (dated.importedAt !== undefined) {
      const imported = el("div", "", `Imported ${dated.importedAt}`);
      imported.dataset.imported = "";
      details.append(imported);
    }
    const sealed = el("div", "", `Judged and sealed ${session.judgedDay}`);
    sealed.dataset.sealed = "";
    details.append(sealed);
  }
  for (const test of session.tests) details.append(checkItBlock(test));
  details.append(renderTranscript(session));
  return details;
}

function renderSessionList(
  host: HTMLElement,
  conversationIds: readonly string[],
  sessions: readonly Session[],
): void {
  const byId = new Map(sessions.map((s) => [s.conversationId, s]));
  const details = document.createElement("details");
  details.dataset.records = "sessions";
  const summary = document.createElement("summary");
  summary.textContent = `${fmt(conversationIds.length)} sessions`;
  details.append(summary);
  for (const id of conversationIds) {
    const session = byId.get(id);
    if (session !== undefined) details.append(renderSessionDetails(session));
  }
  host.append(details);
}

// ---------------------------------------------------------------------------
// Section 2: test results
// ---------------------------------------------------------------------------

function renderTests(host: HTMLElement, model: ComplianceModel): void {
  const section = el("section", "");
  section.dataset.section = "tests";
  section.append(el("h2", "", "2. Test results"));
  section.append(
    el(
      "p",
      "lede",
      "Population is the sessions a test has a sealed result for; a session with none for a test is not applicable to it and is not counted. Recomputed tests are deterministic checks anyone " +
        "can repeat from the records. Judged tests apply a frozen rubric with a pinned model.",
    ),
  );
  const table = document.createElement("table");
  table.className = "grid";
  table.dataset.rows = "tests";
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  headRow.append(
    element("th", "Test"),
    element("th", "Requirement"),
    element("th", "Type"),
    el("th", "n", "Population"),
    el("th", "n", "Exceptions"),
    el("th", "n", "Not evaluable"),
    element("th", "Result"),
  );
  thead.append(headRow);
  table.append(thead);
  const tbody = document.createElement("tbody");
  for (const obligation of model.obligations)
    for (const row of obligation.rows) {
      const tr = document.createElement("tr");
      tr.dataset.criterion = row.criterionId;
      const typeCell = document.createElement("td");
      typeCell.append(tierBadge(row.tier));
      const resultCell = document.createElement("td");
      const population = model.totalSessions - row.notApplicableCount;
      if (
        population > 0 &&
        row.notEvaluableCount === population &&
        row.notMetCount === 0 &&
        row.metCount === 0
      ) {
        resultCell.append(statusPill("ne", "Not evaluable"));
        if (row.notEvaluableNote !== undefined)
          resultCell.append(
            maybeProducer("div", "applic", row.notEvaluableNote, true),
          );
      } else {
        resultCell.append(
          statusPill(
            row.notMetCount > 0 ? "exc" : "ok",
            row.notMetCount > 0 ? "Exceptions" : "No exceptions",
          ),
        );
      }
      tr.append(
        maybeProducer("td", "b", obligation.article, obligation.mapped),
        maybeProducer("td", "", row.name, row.producerName),
        typeCell,
        el("td", "n", fmt(population)),
        el("td", "n", fmt(row.notMetCount)),
        el("td", "n", fmt(row.notEvaluableCount)),
        resultCell,
      );
      tbody.append(tr);
      const drill = document.createElement("tr");
      const drillCell = document.createElement("td");
      drillCell.colSpan = 7;
      const sessionIds = [
        ...(row.sessionsByVerdict.get("not_met") ?? []),
        ...(row.sessionsByVerdict.get("not_evaluable") ?? []),
      ];
      if (sessionIds.length > 0)
        renderSessionList(drillCell, sessionIds, model.sessions);
      drill.append(drillCell);
      tbody.append(drill);
    }
  table.append(tbody);
  section.append(table);
  host.append(section);
}

// ---------------------------------------------------------------------------
// Section 3: findings
// ---------------------------------------------------------------------------

function renderFindings(host: HTMLElement, model: ComplianceModel): void {
  const section = el("section", "");
  section.dataset.section = "findings";
  section.append(el("h2", "", "3. Findings"));
  if (model.findings.length === 0) {
    section.append(
      el(
        "p",
        "lede",
        "No findings: every test with a not-met session count above zero would have produced one.",
      ),
    );
    host.append(section);
    return;
  }
  for (const finding of model.findings) {
    const box = el("div", "fnd");
    box.dataset.finding = finding.id;
    const fh = el("div", "fh");
    fh.append(
      el("b", "", finding.id),
      severityPill(finding.severity),
      producerText(finding.article),
      producerText(finding.testName),
    );
    box.append(fh);
    const table = document.createElement("table");
    table.className = "fk";
    const evRow = document.createElement("tr");
    evRow.append(
      element("th", "Evidence"),
      element("td", `${fmt(finding.sessionIds.length)} sessions`),
    );
    const recRow = document.createElement("tr");
    recRow.append(
      element("th", "Recommendation"),
      maybeProducer("td", "", finding.recommendation, true),
    );
    const ownerRow = document.createElement("tr");
    ownerRow.append(
      element("th", "Owner · due"),
      maybeProducer("td", "", finding.ownerDue, true),
    );
    table.append(evRow, recRow, ownerRow);
    box.append(table);
    renderSessionList(box, finding.sessionIds, model.sessions);
    section.append(box);
  }
  host.append(section);
}

// ---------------------------------------------------------------------------
// Section 4: quality of judged results
// ---------------------------------------------------------------------------

function renderQuality(host: HTMLElement, model: ComplianceModel): void {
  const section = el("section", "");
  section.dataset.section = "quality";
  section.append(el("h2", "", "4. Quality of judged results"));
  const protocol = model.qualityProtocol;
  if (protocol === undefined) {
    section.append(
      el("p", "lede", "No quality protocol declared in this pack."),
    );
    host.append(section);
    return;
  }
  const line = el("p", "lede", "Protocol ");
  line.append(
    protocol.protocol === undefined
      ? "unspecified"
      : producerText(protocol.protocol),
  );
  if (protocol.cadence !== undefined)
    line.append(", ", producerText(protocol.cadence));
  line.append(". Recomputed tests are not sampled.");
  section.append(line);
  if (protocol.note !== undefined)
    section.append(maybeProducer("p", "na", protocol.note, true));
  host.append(section);
}

// ---------------------------------------------------------------------------
// Section 5: methodology / what ran
// ---------------------------------------------------------------------------

function renderWhatRan(host: HTMLElement, model: ComplianceModel): void {
  const section = el("section", "");
  section.dataset.section = "methodology";
  section.append(el("h2", "", "5. Methodology"));
  const ran = el("div", "ran");
  const field = (label: string, value: string): void => {
    const it = el("div", "it");
    it.append(el("div", "k", label), el("div", "v", value));
    ran.append(it);
  };
  field(
    "Contract",
    model.runInfo.contract ??
      (model.runInfo.pinned ? "no conversations" : "disagrees across sessions"),
  );
  field(
    "Judge pin digest",
    model.runInfo.judgePinDigest ??
      (model.runInfo.pinned
        ? "no judged sessions cited"
        : "disagrees across sessions"),
  );
  field("Sessions", fmt(model.totalSessions));
  const { dating } = model;
  if (dating.from !== undefined && dating.to !== undefined) {
    field("Period", span([dating.from, dating.to]));
    ran.lastElementChild!.setAttribute("data-period", "");
  }
  if (dating.basis !== "judged") {
    field("Sealed", span(dating.judgedDays));
    ran.lastElementChild!.setAttribute("data-sealed", "");
  }
  section.append(ran);
  const note = datingStatement(dating, model.totalSessions);
  if (note !== undefined) {
    const p = el("p", "na", note);
    p.dataset.dateNote = dating.basis;
    section.append(p);
  }
  host.append(section);
}

// ---------------------------------------------------------------------------
// Per-obligation detail (plain-language text, method, judged terms)
// ---------------------------------------------------------------------------

function renderObligationDetail(
  host: HTMLElement,
  obligation: ObligationModel,
): void {
  const details = document.createElement("details");
  details.dataset.obligationDetail = obligation.key;
  const summary = document.createElement("summary");
  const heading = `${obligation.article} · ${obligation.title}`;
  if (obligation.mapped) summary.append(producerText(heading));
  else summary.textContent = heading;
  details.append(summary);
  details.dataset.mapped = String(obligation.mapped);
  details.append(
    el(
      "p",
      "na",
      obligation.mapped
        ? "Title, article, summary, method, test names and the undecided-session note: the producer's mapping, in italics, not a sealed record."
        : `The producer's extension does not map this obligation: article, summary and method ${NOT_STATED}.`,
    ),
  );
  details.append(maybeProducer("p", "", obligation.plain, obligation.mapped));
  if (obligation.judgedTerms.length > 0) {
    const terms = el("p", "applic", "Judged terms: ");
    terms.append(producerText(obligation.judgedTerms.join(", ")));
    details.append(terms);
  }
  details.append(maybeProducer("p", "", obligation.method, obligation.mapped));
  for (const row of obligation.rows) {
    const rowBox = el("div", "ck");
    rowBox.dataset.wording = row.wording.source;
    const h = el("div", "h");
    h.append(
      maybeProducer("span", "", row.name, row.producerName),
      tierBadge(row.tier),
    );
    rowBox.append(h);
    rowBox.append(
      el(
        "div",
        "why",
        row.wording.source === "sealed"
          ? `Wording run (sealed): ${row.wording.text}`
          : row.wording.source === "mixed"
            ? `Wording ${NOT_STATED}: the cited reports state different wordings.`
            : `Wording ${NOT_STATED}: no cited report states it.`,
      ),
    );
    if (row.notEvaluableNote !== undefined)
      rowBox.append(maybeProducer("div", "ev", row.notEvaluableNote, true));
    details.append(rowBox);
  }
  host.append(details);
}

function renderObligationDetails(
  host: HTMLElement,
  model: ComplianceModel,
): void {
  const section = el("section", "");
  section.dataset.section = "obligation-detail";
  section.append(el("h2", "", "Obligation detail"));
  for (const obligation of model.obligations)
    renderObligationDetail(section, obligation);
  host.append(section);
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

export function renderCompliancePage(
  result: ResultRoot,
  presentation: CompliancePresentation,
  _bundle: unknown,
  _verified: BundleVerificationResult,
  root: HTMLElement,
): void {
  const model = buildComplianceModel(result, presentation);
  const wrapper = el("div", "cc");
  wrapper.dataset.page = "compliance";
  const style = document.createElement("style");
  style.textContent = COMPLIANCE_CSS;
  wrapper.append(style);

  renderHeader(wrapper, model);
  renderSummary(wrapper, model);
  renderObligationDetails(wrapper, model);
  renderTests(wrapper, model);
  renderFindings(wrapper, model);
  renderQuality(wrapper, model);
  renderWhatRan(wrapper, model);
  root.append(wrapper);
}

export type {
  ComplianceModel,
  ComplianceFindingModel,
  ObligationModel,
  ObligationRowModel,
  Session,
  SessionTest,
};
