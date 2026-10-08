import {
  buildVerifiedBundleContext,
  isVerifiedBundleContext,
  withCountersigners,
  type BundleVerificationResult,
  type VerifiedBundleContext,
} from "./bundle.js";
import {
  classifyCountersignatures,
  declaredProducerKeys,
  type CountersignatureStamp,
  type CountersignerSource,
  type CountersignStatementView,
} from "./countersignature-stamp.js";
import {
  buildEvidenceGraph,
  EvidenceGraphError,
  type ActNode,
  type AxisJudgment,
  type CalibrationCount,
  type CalibrationNode,
  type CaseNode,
  type EvidenceGraph,
  type RecordTimes,
  type ReportNode,
  zoneStatement,
} from "./evidence-graph.js";
import { renderOutcomeReportPage } from "./outcome-report-view.js";
import { readOutcomeReportPresentation } from "./outcome-report-presentation.js";
import { renderCompliancePage } from "./compliance-view.js";
import { readCompliancePresentation } from "./compliance-presentation.js";
import { readPresentationBlock } from "./presentation.js";
import {
  buildReportRows,
  type ReportRow,
  type ReportRowCitation,
  type ReportRows,
} from "./report-rows.js";
import {
  buildResultRoot,
  isResultRoot,
  UNVERIFIED_KEY_LABEL,
  type CountMismatch,
  type ResultClose,
  type CitedRecord,
  type ResultClaim,
  type ResultRoot,
} from "./result-root.js";
import {
  buildVerificationPageModel,
  type CheckSummary,
  type CompletenessStatement,
  type CoverageStatement,
  type ReceiptEntry,
  type RecordCoverage,
  type RecordCoverageStatus,
  unboundRecordIds,
} from "./verification-page.js";

function element(tag: string, text?: string): HTMLElement {
  const value = document.createElement(tag);
  if (text !== undefined) value.textContent = text;
  return value;
}

function display(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function appendValue(parent: HTMLElement, label: string, value: unknown): void {
  parent.append(element("dt", label));
  parent.append(element("dd", display(value)));
}

// A written time is printed exactly as the source wrote it. When it states no
// zone, a visible marker follows it; no zone is ever assigned and no `Z` or
// UTC label is ever printed on a time that did not carry one.
function renderTime(value: string): HTMLElement {
  const zone = zoneStatement(value);
  const time = element("span", value);
  time.dataset.tz = zone;
  if (zone === "not-stated") {
    const marker = element("span", " (timezone not stated)");
    marker.dataset.tzMarker = "not-stated";
    time.append(marker);
  }
  return time;
}

function appendTime(
  parent: HTMLElement,
  label: string,
  value: string | undefined,
  absent: string,
): void {
  parent.append(element("dt", label));
  const cell = element("dd");
  if (value === undefined) {
    cell.textContent = absent;
    cell.dataset.time = "not-stated";
  } else {
    cell.append(renderTime(value));
  }
  parent.append(cell);
}

// Per-record membership may fail solely because some supplied records are
// bound to no log position (the verifier's `membership_record_unbound`): real
// records that sit outside any checkpoint. That is coverage, not a broken
// proof -- every other record's inclusion proof still verified -- so the
// bundle renders, each such record carries its own `uncheckpointed` status,
// and the banner and verification page state how many there are. Any other
// membership finding (an invalid proof, bad coordinates, a missing sequence)
// still fails the bundle as a whole: `unboundRecordIds` leaves out a record
// whose supplied entry was rejected, so the counts below can only agree when
// every finding is a clean unbound record.
function membershipProvenOrUnbound(result: BundleVerificationResult): boolean {
  return (
    result.perRecordMembership.status === "pass" ||
    (result.perRecordMembership.status === "fail" &&
      result.perRecordMembership.findings.length > 0 &&
      result.perRecordMembership.findings.length ===
        unboundRecordIds(result).length)
  );
}

function bundleVerified(result: BundleVerificationResult): boolean {
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

const recordsWord = (count: number): string =>
  `${count} ${count === 1 ? "record" : "records"}`;

// The banner is drawn from the verification result alone and precedes every
// row in the DOM; an unverified bundle gets the refusal line here and no
// rows at all, so a reader never meets a payload before the verdict on the
// bundle that carries it. It says what IS proven: a verified bundle with
// records outside the checkpoint names their count up front.
function renderVerificationBanner(
  root: HTMLElement,
  verified: boolean,
  coverage: { uncheckpointed: number; total: number },
  styled = false,
): void {
  const banner = element(
    "p",
    verified
      ? coverage.uncheckpointed === 0
        ? "Bundle verification passed"
        : `Bundle verification passed; ${coverage.uncheckpointed} of ${recordsWord(coverage.total)} uncheckpointed`
      : "Bundle verification failed",
  );
  banner.dataset.verify = verified ? "verified" : "failed";
  banner.dataset.uncheckpointed = String(coverage.uncheckpointed);
  // Drawn in the outcome-report card's own look when that card renders
  // (OUTCOME_REPORT_CSS's .oi-banner rules); the words and data attributes
  // above are identical either way -- the class is presentation only.
  if (styled)
    banner.className = `oi oi-banner ${verified ? "oi-banner-ok" : "oi-banner-failed"}`;
  root.append(banner);
  if (verified) return;
  const refusal = element(
    "p",
    "This bundle did not verify. Its records, rows and payloads are not shown; the verification page below lists which checks failed.",
  );
  refusal.dataset.refusal = "unverified-bundle";
  root.append(refusal);
}

// presentation/v1 is rendered here, in the header only, and nowhere else in
// this module. Only readPresentationBlock's three known fields ever reach
// the DOM -- the chrome rule holds structurally, not by a rendering-site
// convention that a future edit could bypass.
function renderPresentationHeader(root: HTMLElement, bundle: unknown): void {
  const presentation = readPresentationBlock(bundle);
  if (presentation === undefined) return;
  const header = element("header");
  header.dataset.presentation = "header";
  if (presentation.logoDataUrl !== undefined) {
    const logo = document.createElement("img");
    logo.src = presentation.logoDataUrl;
    logo.alt = presentation.producerDisplayName ?? "producer logo";
    header.append(logo);
  }
  if (presentation.producerDisplayName !== undefined) {
    const name = element("span", presentation.producerDisplayName);
    name.dataset.presentationField = "producer-display-name";
    header.append(name);
  }
  if (presentation.title !== undefined) {
    const title = element("strong", presentation.title);
    title.dataset.presentationField = "title";
    header.append(title);
  }
  root.append(header);
}

function stampText(stamp: CountersignatureStamp): string {
  switch (stamp.kind) {
    case "hollow":
      return "Countersigned: none";
    case "unverified":
      return `a ${stamp.type} countersignature is present; this viewer does not verify that type`;
    case "invalid":
      return "a countersignature is present but failed to verify";
    case "not-independent":
      return `countersigned by the producer — not independent · recomputed ${stamp.statement.recomputedAt}`;
    case "unresolved-signer":
      return `countersigned by an unlisted signer, not in any countersigner list consulted · recomputed ${stamp.statement.recomputedAt}`;
    case "resolved":
      return `Countersigned by ${stamp.name} · recomputed ${stamp.statement.recomputedAt}`;
  }
}

// Each check and result is the signer's statement, listed as the signer gave
// it: never totalled, never presented as this viewer's own finding.
function renderSignerStatement(
  item: HTMLElement,
  signer: string,
  statement: CountersignStatementView,
): void {
  const label = element("p", `${signer}'s statement of what it recomputed:`);
  item.append(label);
  const checks = element("ul");
  checks.dataset.countersignStatement = "checks";
  statement.checks.forEach((check) => {
    const row = element("li", `${check.name}: ${check.result}`);
    row.dataset.checkResult = check.result;
    checks.append(row);
  });
  item.append(checks);
  if (statement.receipt === "unverified") {
    const receipt = element(
      "p",
      "receipt present, not verified by this viewer",
    );
    receipt.dataset.countersignReceipt = "unverified";
    item.append(receipt);
  }
}

function renderStamps(
  host: HTMLElement,
  stamps: readonly CountersignatureStamp[],
): void {
  host.append(element("h4", "Countersignatures"));
  const list = element("ul");
  stamps.forEach((stamp) => {
    const item = element("li");
    item.dataset.stampKind = stamp.kind;
    item.append(element("span", stampText(stamp)));
    if (stamp.kind === "resolved") {
      renderSignerStatement(item, stamp.name, stamp.statement);
    } else if (stamp.kind === "not-independent") {
      renderSignerStatement(item, "The producer", stamp.statement);
    } else if (stamp.kind === "unresolved-signer") {
      renderSignerStatement(item, "The unlisted signer", stamp.statement);
    }
    list.append(item);
  });
  host.append(list);
}

function renderReceipts(
  host: HTMLElement,
  receipts: readonly ReceiptEntry[],
): void {
  host.append(element("h4", "Receipts"));
  if (receipts.length === 0) {
    host.append(element("p", "no receipts disclosed"));
    return;
  }
  const list = element("ul");
  receipts.forEach((receipt) => {
    const item = element("li", `${receipt.witness} · ${receipt.grade} · `);
    item.append(renderTime(receipt.time));
    list.append(item);
  });
  host.append(list);
}

const COVERAGE_LABEL: Readonly<Record<RecordCoverageStatus, string>> =
  Object.freeze({
    checkpointed: "checkpointed",
    uncheckpointed: "uncheckpointed",
    membership_invalid: "membership invalid",
    unverified: "membership unverified",
  });

// One row per supplied record, in bundle order, each with its own standing
// under the checkpoint. When the claim established coverage the count is
// stated in words above the list. When it did not, the line says so and
// names the verifier's reason -- never "0 records uncheckpointed" on a
// bundle whose memberships were never verified -- and when the claim was
// withheld (no checkpoint to stand under) there is no list at all.
function renderCheckpointCoverage(
  host: HTMLElement,
  records: readonly RecordCoverage[],
  uncheckpointed: number,
  coverage: CoverageStatement,
): void {
  host.append(element("h4", "Checkpoint coverage"));
  if (coverage.status === "established") {
    const count = element(
      "p",
      `${recordsWord(uncheckpointed)} uncheckpointed of ${recordsWord(records.length)} supplied`,
    );
    count.dataset.coverage = "uncheckpointed";
    count.dataset.count = String(uncheckpointed);
    host.append(count);
  } else {
    const line = element("p", `coverage not established: ${coverage.reason}`);
    line.dataset.coverage = "not-established";
    line.dataset.claim = coverage.status;
    host.append(line);
    if (coverage.status === "withheld") return;
  }
  host.append(renderCoverageStatusCounts(records));
  const details = element("details");
  details.dataset.records = "coverage-detail";
  const summary = element(
    "summary",
    `${recordsWord(records.length)}, by capsule id`,
  );
  details.append(summary);
  const list = element("ul");
  list.dataset.records = "coverage";
  for (const record of records) {
    const item = element("li", `${record.capsuleId} · `);
    const status = element("span", COVERAGE_LABEL[record.status]);
    status.dataset.recordStatus = record.status;
    status.className = `seal-${record.status}`;
    item.dataset.capsuleId = record.capsuleId;
    item.append(status);
    list.append(item);
  }
  details.append(list);
  host.append(details);
}

// Counts by seal status -- the line a reader actually needs (how many of
// each) without scrolling a list that is one row per record (500+ rows on a
// real day's book: 50 cases x 9 criteria + 50 cases + 1 Close). The full,
// per-capsule-id list stays available (renderCheckpointCoverage wraps it in
// a collapsed <details>), never removed, just not the first thing rendered.
function renderCoverageStatusCounts(
  records: readonly RecordCoverage[],
): HTMLElement {
  const counts = new Map<RecordCoverageStatus, number>();
  for (const record of records) {
    counts.set(record.status, (counts.get(record.status) ?? 0) + 1);
  }
  const list = element("ul");
  list.dataset.records = "coverage-summary";
  for (const status of Object.keys(COVERAGE_LABEL) as RecordCoverageStatus[]) {
    const count = counts.get(status) ?? 0;
    if (count === 0) continue;
    const item = element(
      "li",
      `${recordsWord(count)} ${COVERAGE_LABEL[status]}`,
    );
    item.dataset.coverageStatus = status;
    item.dataset.count = String(count);
    list.append(item);
  }
  return list;
}

function renderCompletenessStatement(
  host: HTMLElement,
  completeness?: CompletenessStatement,
): void {
  host.append(element("h4", "Completeness statement"));
  const details = element("dl");
  appendValue(
    details,
    "closure depth",
    completeness?.closureDepth ?? "unstated",
  );
  appendValue(details, "records mode", completeness?.recordsMode ?? "unstated");
  appendValue(
    details,
    "payloads mode",
    completeness?.payloadsMode ?? "unstated",
  );
  appendValue(
    details,
    "suppressed fields",
    completeness?.suppressedFields ?? [],
  );
  host.append(details);
}

function renderChecks(
  host: HTMLElement,
  checks: readonly CheckSummary[],
): void {
  host.append(element("h4", "The ten checks"));
  const list = element("ol");
  checks.forEach((check) => {
    const item = element("li");
    item.dataset.checkStatus = check.status;
    item.append(element("strong", check.name));
    item.append(element("span", `: ${check.result}`));
    list.append(item);
  });
  host.append(list);
}

// The viewer-owned verification page: the last page of the rendering, drawn
// entirely from VERIFIED data (the already-computed BundleVerificationResult
// and the countersignature stamp classification), never from bundle-supplied
// markup. It is never labeled a certificate.
//
// `styled` (true only when the outcome-report card rendered above it) draws
// this same page in that card's look: the section takes the card's `.oi`
// scope plus `.oi-vp`, and its content goes inside one `.sec` panel like
// every card section. Content, order and data attributes are identical
// either way, and it stays the last element of the rendering.
async function renderVerificationPage(
  root: HTMLElement,
  context: VerifiedBundleContext,
  styled = false,
): Promise<void> {
  const { bundle, verification: verified, countersigners } = context;
  const section = element("section");
  section.dataset.page = "verification";
  let page = section;
  if (styled) {
    section.className = "oi oi-vp";
    page = element("div");
    page.className = "sec";
    section.append(page);
  }
  page.append(element("h2", "Verification"));
  const model = buildVerificationPageModel(bundle, verified);
  const summary = element("dl");
  appendValue(summary, "bundle digest", model.bundleDigest ?? "uncomputable");
  appendValue(summary, "checkpoint root", model.checkpointRoot ?? "absent");
  appendValue(summary, "checkpoint size", model.checkpointSize ?? "absent");
  page.append(summary);
  renderReceipts(page, model.receipts);
  if (model.selfWitnessed) {
    // A checkpoint with no transparency-service receipt was witnessed by
    // nobody but the log that produced it -- stated here in those words.
    const witness = element(
      "p",
      "self-witnessed: no transparency-service receipt",
    );
    witness.dataset.witness = "self";
    page.append(witness);
  }
  renderCheckpointCoverage(
    page,
    model.records,
    model.uncheckpointedCount,
    model.coverage,
  );
  const stamps = await classifyCountersignatures(
    context.countersignatures.map((entry) => entry.value),
    verified.bundleDigest,
    declaredProducerKeys(bundle),
    countersigners,
  );
  renderStamps(page, stamps);
  renderCompletenessStatement(page, model.completeness);
  renderChecks(page, model.checks);
  page.append(element("p", model.verifyIndependentlyLine));
  root.append(section);
}

function metRate(report: ReportNode): string {
  const required = report.outcomes.filter(
    (outcome) => outcome.role === "required",
  );
  if (required.length === 0) return "met rate unavailable";
  const passed = required.filter(
    (outcome) => outcome.aggregate === "pass",
  ).length;
  return `met rate ${passed}/${required.length}`;
}

function renderCalibration(calibration?: CalibrationNode): HTMLElement {
  const section = element("section");
  section.append(element("h2", "Human check"));
  if (calibration === undefined) {
    section.append(element("p", "no human-check data"));
    return section;
  }
  const details = element("dl");
  appendValue(details, "confusion matrix", calibration.confusion);
  appendCount(details, "agreement", calibration.agreement);
  appendCount(details, "corrected rate", calibration.correctedRate);
  appendValue(details, "period window", calibration.periodWindow);
  section.append(details);
  return section;
}

// A calibration figure is printed as the integers it is made of, "k of n";
// no rate is computed from them here, and a figure the producer stated only
// as a rate is said to be that, not converted.
function appendCount(
  parent: HTMLElement,
  label: string,
  count: CalibrationCount | undefined,
): void {
  parent.append(element("dt", label));
  const cell = element("dd");
  if (count === undefined) {
    cell.textContent = "not stated";
    cell.dataset.count = "not-stated";
  } else if ("rate" in count) {
    cell.textContent = "rate given, k and n not stated";
    cell.dataset.count = "not-stated";
  } else {
    cell.textContent = `${count.k} of ${count.n}`;
    cell.dataset.k = String(count.k);
    cell.dataset.n = String(count.n);
  }
  parent.append(cell);
}

// Both of a record's times are shown, each labelled and each as written. The
// action time is the source's own; when the record states none it says so --
// the seal time (the capsule's registration timestamp) never stands in for it.
function renderProvenance(
  capsuleId: string,
  coordinates: ActNode["logCoordinates"],
  times: RecordTimes,
): HTMLElement {
  const panel = element("section");
  panel.append(element("h4", "Provenance"));
  const details = element("dl");
  appendValue(details, "capsule ID", capsuleId);
  if (times.provenanceMode !== undefined)
    appendValue(details, "provenance", times.provenanceMode);
  appendTime(
    details,
    "action time",
    times.actionTime,
    "action time not stated",
  );
  appendTime(details, "seal time", times.sealTime, "seal time not stated");
  // The seal status is this record's own: coordinates exist only for a
  // record whose inclusion proof verified (the bundle renders only then), so
  // a record without them sits outside the checkpoint and says so.
  details.append(element("dt", "seal status"));
  const seal = element(
    "dd",
    coordinates === undefined ? "uncheckpointed" : "checkpointed",
  );
  seal.dataset.seal =
    coordinates === undefined ? "uncheckpointed" : "checkpointed";
  seal.className = `seal-${seal.dataset.seal}`;
  details.append(seal);
  if (coordinates !== undefined) {
    appendValue(details, "log ID", coordinates.logId);
    appendValue(details, "sequence", coordinates.seq);
    appendValue(details, "leaf", coordinates.leafIndex);
  }
  panel.append(details);
  return panel;
}

function renderJudgment(judgment: AxisJudgment): HTMLElement {
  const item = element("li");
  item.append(element("strong", `${judgment.axisId}: ${judgment.status}`));
  item.append(element("p", judgment.rationale));
  item.append(element("p", `evidence: ${judgment.evidenceIds.join(", ")}`));
  return item;
}

function renderAct(act: ActNode): HTMLElement {
  const section = element("section");
  section.append(element("h4", `Turn ${act.turnIdx}`));
  if (act.agentInput !== undefined)
    section.append(element("pre", display(act.agentInput)));
  if (act.agentOutput !== undefined)
    section.append(element("pre", display(act.agentOutput)));
  section.append(renderProvenance(act.capsuleId, act.logCoordinates, act));
  return section;
}

function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function renderWithheldActs(acts: ActNode[], host: HTMLElement): void {
  for (const act of acts) {
    if (act.agentInput !== undefined && act.agentOutput !== undefined) continue;
    const committed = object({
      agent_input_digest: act.agentInputDigest,
      agent_output_digest: act.agentOutputDigest,
    });
    const evidence = element("section");
    evidence.append(element("h4", "Undisclosed payload evidence"));
    const details = element("dl");
    appendValue(details, "capsule ID", act.capsuleId);
    for (const field of ["agent_input_digest", "agent_output_digest"]) {
      if (typeof committed[field] === "string")
        appendValue(details, field, committed[field]);
    }
    evidence.append(details);
    // A supplied value that does not hash to the committed digest is never
    // shown; the reader sees the digest above and this note, nothing else.
    for (const [field, state] of [
      ["agent_input", act.agentInputDisclosure],
      ["agent_output", act.agentOutputDisclosure],
    ] as const) {
      if (state !== "disclosure_mismatch") continue;
      const note = element(
        "p",
        `${field}: the disclosed value does not match the committed digest and is withheld`,
      );
      note.dataset.disclosure = state;
      evidence.append(note);
    }
    host.append(evidence);
  }
}

function renderCase(caseNode: CaseNode, host: HTMLElement): void {
  host.replaceChildren();
  host.append(element("h3", `Case ${caseNode.caseId}`));
  const judgments = element("ul");
  caseNode.judgments.forEach((judgment) =>
    judgments.append(renderJudgment(judgment)),
  );
  host.append(element("h4", "Axis judgments"), judgments);
  host.append(element("h4", "Disclosed transcript"));
  caseNode.acts.forEach((act) => host.append(renderAct(act)));
  renderWithheldActs(caseNode.acts, host);
}

function renderReport(
  report: ReportNode,
  host: HTMLElement,
  _records: unknown[],
): void {
  host.replaceChildren();
  const heading = element("h2", "Cases for ");
  heading.append(renderTime(report.date));
  host.append(heading);
  const outcomes = element("ul");
  report.outcomes.forEach((outcome) => {
    outcomes.append(
      element(
        "li",
        `${outcome.outcomeId} (${outcome.role}): ${outcome.aggregate ?? "unrated"}`,
      ),
    );
  });
  host.append(element("h3", "Outcome rollup"), outcomes);
  renderWithheldActs(report.withheldActs, host);

  const cases = element("section");
  const detail = element("section");
  report.cases.forEach((caseNode) => {
    const item = element(
      "button",
      `${caseNode.taskId}, trial ${caseNode.trial}: ${caseNode.aggregate ?? "unrated"}`,
    );
    item.setAttribute("type", "button");
    item.dataset.caseId = caseNode.caseId;
    item.addEventListener("click", () => renderCase(caseNode, detail));
    cases.append(item);
  });
  host.append(
    cases,
    detail,
    renderProvenance(report.capsuleId, report.logCoordinates, report),
  );
}

// report/v1: the generic row path. Every row is rendered from its own data
// -- label, status, reason, citations -- never from report-specific markup,
// so a pack this module has never heard of (obligations, Consumer Duty,
// anything else) renders the same way an outcomes report does.
function renderCitation(citation: ReportRowCitation): HTMLElement {
  const section = element("section");
  section.append(
    renderProvenance(citation.capsuleId, citation.logCoordinates, citation),
  );
  if (citation.disclosure === "disclosed") {
    section.append(element("pre", display(citation.disclosedPayload)));
  } else {
    const note = element(
      "p",
      citation.disclosure === "disclosure_mismatch"
        ? "withheld: the disclosed value does not match the committed digest"
        : "withheld",
    );
    note.dataset.disclosure = citation.disclosure;
    section.append(note);
  }
  return section;
}

function renderReportRow(row: ReportRow, host: HTMLElement): void {
  host.replaceChildren();
  host.append(element("h3", row.label));
  const status = element("p", row.status.replaceAll("_", " "));
  status.dataset.rowStatus = row.status;
  host.append(status);
  if (row.reason !== undefined) host.append(element("p", row.reason));
  host.append(element("h4", "Evidence"));
  if (row.citations.length === 0) {
    host.append(element("p", "no citation"));
  } else {
    row.citations.forEach((citation) => host.append(renderCitation(citation)));
  }
}

function renderReportRowsTable(
  reportRows: ReportRows,
  root: HTMLElement,
): void {
  const section = element("section");
  section.dataset.page = "report-rows";
  section.append(element("h1", reportRows.title ?? "Report"));
  const table = document.createElement("table");
  const detail = element("section");
  reportRows.rows.forEach((row) => {
    const tr = document.createElement("tr");
    const labelCell = document.createElement("td");
    const button = element("button", row.label);
    button.setAttribute("type", "button");
    button.dataset.rowId = row.rowId;
    button.addEventListener("click", () => renderReportRow(row, detail));
    labelCell.append(button);
    const statusCell = element("td", row.status.replaceAll("_", " "));
    statusCell.dataset.rowStatus = row.status;
    tr.append(labelCell, statusCell);
    table.append(tr);
  });
  section.append(
    table,
    detail,
    renderProvenance(
      reportRows.capsuleId,
      reportRows.logCoordinates,
      reportRows,
    ),
  );
  root.append(section);
}

// Result v0 root: headlines from the root Result, drill-downs from the
// records it cites. A cited record is drawn from its own data -- provenance,
// each committed member as disclosed or as `withheld · <digest>`, and the
// records it cites in turn -- so aggregate → daily → case → act is a walk
// over citations, never report-specific markup.
function renderCitedMember(
  host: HTMLElement,
  field: "agent_input" | "agent_output",
  resolution: CitedRecord["agentInput"],
  committed: string | undefined,
): void {
  if (resolution.state !== "disclosed" && committed === undefined) return;
  host.append(element("h5", field));
  if (resolution.state === "disclosed") {
    host.append(element("pre", display(resolution.payload)));
    return;
  }
  // A withheld member shows the digest the record committed to; a supplied
  // value that does not hash to it is never shown, only noted.
  const note = element(
    "p",
    resolution.state === "disclosure_mismatch"
      ? `withheld · ${committed}: the disclosed value does not match the committed digest`
      : `withheld · ${committed}`,
  );
  note.dataset.disclosure = resolution.state;
  host.append(note);
}

function renderCitedRecord(
  record: CitedRecord,
  records: ReadonlyMap<string, CitedRecord>,
  host: HTMLElement,
): void {
  const section = element("section");
  section.dataset.citedRecord = record.capsuleId;
  section.append(
    renderProvenance(record.capsuleId, record.logCoordinates, record),
  );
  renderCitedMember(
    section,
    "agent_input",
    record.agentInput,
    record.agentInputDigest,
  );
  renderCitedMember(
    section,
    "agent_output",
    record.agentOutput,
    record.agentOutputDigest,
  );
  if (record.cites.length > 0) {
    section.append(element("h5", "Cites"));
    renderCitationList(record.cites, records, section);
  }
  host.append(section);
}

// One row per cited id, in citation order: a record supplied in this bundle
// opens under the list on click; one that is not says so and stays.
function renderCitationList(
  ids: readonly string[],
  records: ReadonlyMap<string, CitedRecord>,
  host: HTMLElement,
): HTMLElement {
  const list = element("ul");
  const detail = element("section");
  for (const id of ids) {
    const item = element("li");
    const target = records.get(id);
    if (target === undefined) {
      item.textContent = `${id} · not in this bundle`;
      item.dataset.citation = "missing";
    } else {
      const button = element("button", id);
      button.setAttribute("type", "button");
      button.dataset.citedId = id;
      button.addEventListener("click", () => {
        detail.replaceChildren();
        renderCitedRecord(target, records, detail);
      });
      item.append(button);
    }
    list.append(item);
  }
  host.append(list, detail);
  return list;
}

const CLAIM_TYPE_LABEL = (claim: ResultClaim): string =>
  claim.recognized ? claim.type : `unrecognized (${claim.type})`;

// A recomputed headline number never wears the producer's value. When the
// two disagree the recomputed value is drawn and a `count mismatch` marker
// sits beside it; the stated value is kept on the marker's data attribute,
// never in the text a reader takes as the number.
function countMismatchMarker(
  result: ResultRoot,
  field: CountMismatch["field"],
): HTMLElement | undefined {
  const mismatch = result.countMismatches.find(
    (entry) => entry.field === field,
  );
  if (mismatch === undefined) return undefined;
  const marker = element("span", "count mismatch");
  marker.dataset.countMismatch = field;
  marker.dataset.stated = String(mismatch.stated);
  marker.dataset.recomputed = String(mismatch.recomputed);
  return marker;
}

// The close state a reader sees is the one this bundle's links read
// whenever the cited Close is supplied; the Result's own value is drawn
// only when it is not, and then under a `producer-asserted` marker. When
// the two disagree the recomputed state is drawn with a `state mismatch`
// marker; the asserted value stays on the data attribute, never in the
// text. AGREED carries no mark of its own -- its label and the
// acknowledging peer's record are the whole affordance.
function appendCloseState(
  parent: HTMLElement,
  close: ResultClose,
  tag: "span" | "dd",
): HTMLElement {
  const cell = element(tag, close.state);
  cell.dataset.closeState = close.state;
  cell.dataset.closeDerivation = close.derivation;
  cell.dataset.assertedState = close.asserted;
  if (close.stateMismatch) {
    const marker = element("span", "state mismatch");
    marker.dataset.stateMismatch = "close_state";
    marker.dataset.asserted = close.asserted;
    marker.dataset.recomputed = close.state;
    cell.append(" ", marker);
  } else if (close.derivation === "producer-asserted") {
    const marker = element("span", "producer-asserted");
    marker.dataset.producerAsserted = "close_state";
    cell.append(" ", marker);
  }
  if (close.peerRefMismatch) {
    const marker = element("span", "peer_close_ref carries no such link");
    marker.dataset.peerRefMismatch = "peer_close_ref";
    cell.append(" ", marker);
  }
  parent.append(cell);
  return cell;
}

function renderClose(
  close: ResultClose,
  result: ResultRoot,
  host: HTMLElement,
): void {
  host.append(element("h4", "Close"));
  const details = element("dl");
  if (close.period !== undefined)
    appendValue(
      details,
      "period",
      `${close.period.start} → ${close.period.end}`,
    );
  details.append(element("dt", "state"));
  appendCloseState(details, close, "dd");
  details.append(element("dt", "derivation"));
  const derivation = element(
    "dd",
    close.derivation === "recomputed"
      ? `recomputed from ${close.links.length} counterparty ${close.links.length === 1 ? "link" : "links"} to the cited Close in this bundle${close.ignored.length === 0 ? "" : ` (${close.ignored.length} other ${close.ignored.length === 1 ? "link" : "links"} ignored)`}`
      : "producer-asserted: the cited Close is not a record in this bundle, so its links could not be read",
  );
  derivation.dataset.closeDerivationNote = close.derivation;
  details.append(derivation);
  if (close.peer !== undefined) appendValue(details, "peer", close.peer);
  if (close.bookId !== undefined) appendValue(details, "book", close.bookId);
  // A signer is drawn as verified only when its Producer Envelope verified
  // under the key_id (result-root.ts `signerOf`); otherwise it carries the
  // label, never a bare key.
  if (close.keyId !== undefined) {
    details.append(element("dt", "signer"));
    const signer = element(
      "dd",
      close.keyVerified === true
        ? `${close.keyId} (verified)`
        : `${close.keyId} · ${UNVERIFIED_KEY_LABEL}`,
    );
    signer.dataset.keyVerified = String(close.keyVerified === true);
    details.append(signer);
  }
  host.append(details);
  host.append(element("h5", "Cited Close"));
  renderCitationList([close.closeRef], result.records, host);
  if (close.peerCloseRef !== undefined) {
    host.append(element("h5", "Peer record"));
    renderCitationList([close.peerCloseRef], result.records, host);
  }
  if (close.links.length > 0) {
    host.append(element("h5", "Links to the cited Close"));
    const list = element("ul");
    for (const link of close.links) {
      const item = element(
        "li",
        `${link.type} · ${link.recordId} · signer ${link.keyId} (verified)`,
      );
      item.dataset.closeLink = link.type;
      item.dataset.linkRecord = link.recordId;
      list.append(item);
    }
    host.append(list);
  }
  // Inbound links that made no state -- from the Close's own book, a book
  // that is not the named peer, or the Close's own key -- are listed with
  // the reason, never counted: a reader sees why AGREED was not read.
  if (close.ignored.length > 0) {
    host.append(element("h5", "Links ignored (not from the counterparty)"));
    const list = element("ul");
    for (const link of close.ignored) {
      const item = element(
        "li",
        `${link.type} · ${link.recordId} · ${link.reason}`,
      );
      item.dataset.ignoredLink = link.type;
      item.dataset.linkRecord = link.recordId;
      list.append(item);
    }
    host.append(list);
  }
}

// The verdict a reader sees is the Result's own only when every cited id
// resolves in this bundle and the claim stands. A claim that FAILED
// verification (its close state is not what the links read) reads
// `failed` -- never `met`, never its stated verdict, which is kept on
// `data-stated-verdict` only. Otherwise an unresolved citation reads
// `unsupported`. The row stays in every case.
function appendVerdict(parent: HTMLElement, claim: ResultClaim): HTMLElement {
  const shown = claim.failed
    ? "failed"
    : claim.support === "supported"
      ? claim.verdict
      : "unsupported";
  const cell = element(parent.tagName === "TR" ? "td" : "dd", shown);
  cell.dataset.verdict = shown;
  cell.dataset.support = claim.support;
  if (claim.failed) {
    cell.dataset.statedVerdict = claim.verdict;
    cell.className = "claim-failed";
  } else if (claim.support === "unsupported")
    cell.className = "claim-unsupported";
  parent.append(cell);
  return cell;
}

// A failed claim's sufficiency is the producer's word too: the cell reads
// `failed`, the stated value on `data-stated-sufficiency` only.
function appendSufficiency(
  parent: HTMLElement,
  claim: ResultClaim,
): HTMLElement {
  const shown = claim.failed ? "failed" : claim.sufficiency;
  const cell = element(parent.tagName === "TR" ? "td" : "dd", shown);
  cell.dataset.sufficiency = shown;
  if (claim.failed) {
    cell.dataset.statedSufficiency = claim.sufficiency;
    cell.className = "claim-failed";
  }
  parent.append(cell);
  return cell;
}

function renderClaim(
  claim: ResultClaim,
  result: ResultRoot,
  host: HTMLElement,
): void {
  host.replaceChildren();
  host.append(element("h3", `Claim ${claim.id}`));
  const details = element("dl");
  appendValue(details, "contract", claim.contractRef);
  appendValue(details, "requirement", claim.requirementRef);
  details.append(element("dt", "type"));
  const type = element("dd", CLAIM_TYPE_LABEL(claim));
  type.dataset.claimType = claim.recognized ? claim.type : "unrecognized";
  if (!claim.recognized) type.className = "claim-unrecognized";
  details.append(type);
  appendValue(details, "tier", claim.tier);
  appendValue(details, "grade", claim.grade);
  details.append(element("dt", "sufficiency"));
  appendSufficiency(details, claim);
  details.append(element("dt", "verdict"));
  appendVerdict(details, claim);
  host.append(details);
  if (claim.failed) {
    const note = element(
      "p",
      `failed: ${claim.failure ?? "verification failed"}; sufficiency and verdict withheld`,
    );
    note.dataset.claimFailed = claim.failedOn ?? "close_state";
    host.append(note);
  }
  if (claim.close !== undefined) renderClose(claim.close, result, host);
  if (claim.support === "unsupported") {
    const note = element(
      "p",
      claim.missing.length === 0
        ? "unsupported: this claim cites no evidence"
        : `unsupported: cited evidence not in this bundle: ${claim.missing.join(", ")}`,
    );
    note.dataset.claimMissing = String(claim.missing.length);
    host.append(note);
  }
  host.append(element("h4", "Presentation"));
  const carrier = element("dl");
  appendValue(carrier, "carrier", claim.presentation.kind);
  appendValue(carrier, "status", claim.presentation.status);
  if (claim.presentation.summary !== undefined)
    appendValue(carrier, "summary", claim.presentation.summary);
  if (claim.presentation.narrative !== undefined)
    appendValue(carrier, "narrative", claim.presentation.narrative);
  host.append(carrier);
  // A disclosure carrier names the digests it discloses. They are drawn in
  // the same row shape as any other citation, resolved against this bundle;
  // the claim's own `evidence[]` below is the list the verdict rests on.
  if (claim.presentation.evidence !== undefined) {
    host.append(element("h5", "Carrier evidence"));
    const list = renderCitationList(
      claim.presentation.evidence,
      result.records,
      host,
    );
    list.dataset.carrierEvidence = String(claim.presentation.evidence.length);
  }
  host.append(element("h4", "Proofs"));
  if (claim.proofs.length === 0) {
    host.append(element("p", "no proof cited"));
  } else {
    const proofs = element("ul");
    for (const proof of claim.proofs)
      proofs.append(
        element("li", `${proof.kind} · ${proof.digest} · not resolved here`),
      );
    host.append(proofs);
  }
  host.append(element("h4", "Evidence"));
  for (const ref of claim.evidence) {
    const record = result.records.get(ref.digest);
    if (record === undefined) {
      const missing = element("p", `${ref.digest} · not in this bundle`);
      missing.dataset.evidence = "missing";
      host.append(missing);
    } else {
      renderCitedRecord(record, result.records, host);
    }
  }
}

const BUCKETS: ReadonlyArray<readonly [keyof ResultRoot["buckets"], string]> = [
  ["met", "met"],
  ["notMet", "not met"],
  ["notEvaluable", "not evaluable"],
];

// Coverage is the first thing in the Result section after its heading, and
// no number precedes it within the section; then the three buckets, never a
// single figure; then one row per claim with its own tier and grade. The
// bundle-level verification banner, drawn before every section, is the one
// thing above coverage that can carry digits ("N of M records
// uncheckpointed"). Every number drawn here is the recomputed one
// (`result.coverage`, `result.bucketCounts`); a producer figure the claims
// do not bear out shows as a `count mismatch` marker beside the recomputed
// value. `excluded as not applicable` is the one figure carried as stated:
// no claim backs it, by construction.
function renderResultPage(result: ResultRoot, root: HTMLElement): void {
  const section = element("section");
  section.dataset.page = "result";
  section.append(element("h1", "Evidence result"));
  const coverage = element("p");
  coverage.append(
    `coverage: ${result.coverage.evaluatedPopulation} requirements evaluated`,
  );
  const evaluatedMarker = countMismatchMarker(result, "evaluated_population");
  if (evaluatedMarker !== undefined) coverage.append(" ", evaluatedMarker);
  coverage.append(
    ` · ${result.coverage.excludedNotApplicable} excluded as not applicable · ${result.coverage.unknownCount} unresolved`,
  );
  const unknownMarker = countMismatchMarker(result, "unknown_count");
  if (unknownMarker !== undefined) coverage.append(" ", unknownMarker);
  coverage.dataset.coverage = "result";
  coverage.dataset.evaluated = String(result.coverage.evaluatedPopulation);
  coverage.dataset.excluded = String(result.coverage.excludedNotApplicable);
  coverage.dataset.excludedBasis = "stated";
  coverage.dataset.unknown = String(result.coverage.unknownCount);
  section.append(coverage);

  const byId = new Map(result.claims.map((claim) => [claim.id, claim]));
  const buckets = element("section");
  buckets.dataset.buckets = "verdict";
  buckets.append(element("h2", "Claims by verdict"));
  for (const [key, label] of BUCKETS) {
    const count = result.bucketCounts[key];
    const heading = element("h3", `${label}: ${count === 0 ? "none" : count}`);
    heading.dataset.bucketCount = String(count);
    heading.dataset.bucketOf = key;
    const marker = countMismatchMarker(
      result,
      `buckets.${key === "notMet" ? "not_met" : key === "notEvaluable" ? "not_evaluable" : "met"}`,
    );
    if (marker !== undefined) heading.append(" ", marker);
    buckets.append(heading);
    const ids = result.buckets[key];
    if (ids.length === 0) {
      buckets.append(element("p", "none"));
      continue;
    }
    const list = element("ul");
    list.dataset.bucket = key;
    for (const id of ids) {
      const claim = byId.get(id);
      const item = element(
        "li",
        claim?.failed
          ? `${id} · failed`
          : claim?.support === "unsupported"
            ? `${id} · unsupported`
            : id,
      );
      item.dataset.claimRef = id;
      if (claim?.failed) item.className = "claim-failed";
      else if (claim?.support === "unsupported")
        item.className = "claim-unsupported";
      list.append(item);
    }
    buckets.append(list);
  }
  // The verifier's own state, after the producer's three buckets: claims
  // that failed verification (a close state the links contradict). Drawn
  // always, `none` when empty, so a reader never has to infer from an
  // absent heading that nothing failed. Not a verdict bucket: a failed
  // claim is counted here and under no verdict, whatever bucket the
  // producer listed it in (that listing stays above, marked).
  const failedHeading = element(
    "h3",
    `failed: ${result.bucketCounts.failed === 0 ? "none" : result.bucketCounts.failed}`,
  );
  failedHeading.dataset.bucketCount = String(result.bucketCounts.failed);
  failedHeading.dataset.bucketOf = "failed";
  buckets.append(failedHeading);
  const failedIds = result.claims
    .filter((claim) => claim.failed)
    .map((claim) => claim.id);
  if (failedIds.length === 0) buckets.append(element("p", "none"));
  else {
    const list = element("ul");
    list.dataset.bucket = "failed";
    for (const id of failedIds) {
      const item = element("li", id);
      item.dataset.claimRef = id;
      item.className = "claim-failed";
      list.append(item);
    }
    buckets.append(list);
  }
  section.append(buckets);

  const table = document.createElement("table");
  table.dataset.claims = "rows";
  const detail = element("section");
  for (const claim of result.claims) {
    const tr = document.createElement("tr");
    tr.dataset.claimRow = claim.id;
    tr.dataset.support = claim.support;
    if (claim.support === "unsupported") tr.className = "claim-unsupported";
    if (claim.failed) {
      tr.classList.add("claim-failed");
      tr.dataset.failed = claim.failedOn ?? "close_state";
    }
    const idCell = document.createElement("td");
    const button = element("button", claim.id);
    button.setAttribute("type", "button");
    button.dataset.claimId = claim.id;
    button.addEventListener("click", () => renderClaim(claim, result, detail));
    idCell.append(button);
    tr.append(idCell, element("td", claim.requirementRef));
    appendSufficiency(tr, claim);
    appendVerdict(tr, claim);
    const tier = element("td", claim.tier);
    tier.dataset.tier = claim.tier;
    const grade = element("td", claim.grade);
    grade.dataset.grade = claim.grade;
    const type = element("td", CLAIM_TYPE_LABEL(claim));
    type.dataset.claimType = claim.recognized ? claim.type : "unrecognized";
    if (!claim.recognized) type.className = "claim-unrecognized";
    if (claim.close !== undefined) {
      type.append(" · ");
      appendCloseState(type, claim.close, "span");
    }
    tr.append(tier, grade, type);
    table.append(tr);
  }
  section.append(
    table,
    detail,
    renderProvenance(result.capsuleId, result.logCoordinates, result),
  );
  root.append(section);
}

function renderGraph(
  graph: EvidenceGraph,
  root: HTMLElement,
  records: unknown[],
): void {
  const aggregate = element("section");
  aggregate.append(element("h1", "Evidence graph"));
  const metrics = element("dl");
  appendValue(metrics, "per-axis", graph.aggregate.perAxis);
  appendValue(metrics, "counts", graph.aggregate.counts);
  aggregate.append(metrics);
  root.append(aggregate, renderCalibration(graph.calibration));

  const calendar = element("section");
  calendar.append(element("h2", "Daily reports"));
  const detail = element("section");
  [...graph.reports]
    .sort((left, right) => left.date.localeCompare(right.date))
    .forEach((report) => {
      // The label is the report's date as the producer wrote it -- a bare
      // day stays a day, a timestamp stays a timestamp, and one that states
      // no zone is marked so rather than tiled under an assigned one.
      const tile = element("button");
      tile.append(renderTime(report.date), `: ${metRate(report)}`);
      tile.setAttribute("type", "button");
      tile.dataset.reportDate = report.date;
      tile.addEventListener("click", () =>
        renderReport(report, detail, records),
      );
      calendar.append(tile);
    });
  root.append(calendar, detail);
}

/**
 * Render a bundle into `root`. `countersigners` is the stamp's countersigner
 * source: the only way a verified, independent countersignature gets a name.
 * Omitted, the context's own source is used (see
 * `buildVerifiedBundleContext`); with neither, every independent signer
 * renders as unlisted. The emitted report.html shell passes a bare bundle
 * and no list; a host page that holds a list passes it here or builds the
 * context with it (see `pinnedCountersignerSource` to load one against a
 * pinned digest).
 *
 * Given a bundle, it is verified once here; given a context, its one
 * verification run is reused. Every builder below reads that same context.
 */
export async function renderEvidenceGraph(
  context: VerifiedBundleContext,
  root: HTMLElement,
  countersigners?: CountersignerSource,
): Promise<void>;
export async function renderEvidenceGraph(
  bundle: unknown,
  root: HTMLElement,
  countersigners?: CountersignerSource,
): Promise<void>;
export async function renderEvidenceGraph(
  input: unknown,
  root: HTMLElement,
  countersigners?: CountersignerSource,
): Promise<void> {
  // Verify first. Row models are built only from a bundle that verified,
  // and nothing reaches the DOM until the verification result is in hand.
  const context = isVerifiedBundleContext(input)
    ? countersigners === undefined
      ? input
      : withCountersigners(input, countersigners)
    : await buildVerifiedBundleContext(input, {
        ...(countersigners === undefined ? {} : { countersigners }),
      });
  const { bundle, verification } = context;
  const verified = bundleVerified(verification);
  // Root families, in order: report/v1 (the generic row model), a Result v0
  // root (throws when the document it names is not one), and only then the
  // evaluation-summary/v1 graph (which throws on anything else).
  const reportRows = verified ? await buildReportRows(context) : undefined;
  const result =
    verified && reportRows === undefined && (await isResultRoot(context))
      ? await buildResultRoot(context)
      : undefined;
  // The evaluation-summary/v1 aggregate is optional: a verified bundle whose
  // root is none of the three families (a deal root, for example) renders
  // without the aggregate panel and says so, instead of rendering nothing.
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
  const records = object(bundle).records;
  // outcome-report/v1 is a card choice over the SAME verified Result root,
  // never a different verification path: it is read only after `result` is
  // already built from a bundle that passed the verify-first gate above, and
  // it changes nothing about what `result` itself required to exist. Absent
  // or not enabled, the generic Result page stays the default -- unchanged
  // for every bundle that predates this card. Read before the banner only so
  // the banner and the verification page can take the card's look; an
  // unverified bundle never has a `result`, so it never does.
  const outcomeReport =
    result !== undefined ? readOutcomeReportPresentation(bundle) : undefined;
  const styled = result !== undefined && outcomeReport !== undefined;
  root.replaceChildren();
  renderPresentationHeader(root, bundle);
  renderVerificationBanner(
    root,
    verified,
    {
      uncheckpointed: unboundRecordIds(verification).length,
      total: Array.isArray(records) ? records.length : 0,
    },
    styled,
  );
  // compliance/v1 is read the same way: a second card choice over the SAME
  // verified Result root, after outcome-report's (a bundle that opted into
  // both renders the outcome-report card) -- never a verification path of
  // its own.
  const compliance =
    result !== undefined && outcomeReport === undefined
      ? readCompliancePresentation(bundle)
      : undefined;
  if (reportRows !== undefined) {
    renderReportRowsTable(reportRows, root);
  } else if (result !== undefined && outcomeReport !== undefined) {
    await renderOutcomeReportPage(
      result,
      outcomeReport,
      bundle,
      verification,
      root,
    );
  } else if (result !== undefined && compliance !== undefined) {
    renderCompliancePage(result, compliance, bundle, verification, root);
  } else if (result !== undefined) {
    renderResultPage(result, root);
  } else if (graph !== undefined) {
    renderGraph(graph, root, Array.isArray(records) ? records : []);
  } else if (noAggregate) {
    const note = document.createElement("p");
    note.setAttribute("data-notice", "no-aggregate");
    note.textContent =
      "This bundle carries no evaluation summary, so there is no aggregate view. The records and their verification are below.";
    root.append(note);
  }
  await renderVerificationPage(root, context, styled);
}
