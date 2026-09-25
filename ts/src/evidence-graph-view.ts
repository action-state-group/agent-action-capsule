import { verifyBundle, type BundleVerificationResult } from "./bundle.js";
import {
  classifyCountersignatures,
  type CountersignatureStamp,
  type CountersignerDirectoryEntry,
} from "./countersignature-stamp.js";
import {
  buildEvidenceGraph,
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
import { readPresentationBlock } from "./presentation.js";
import {
  buildReportRows,
  type ReportRow,
  type ReportRowCitation,
  type ReportRows,
} from "./report-rows.js";
import {
  buildVerificationPageModel,
  type CheckSummary,
  type CompletenessStatement,
  type ReceiptEntry,
  type RecordCoverage,
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
// still fails the bundle as a whole.
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

function producerPublicKeyHex(bundle: unknown): string | undefined {
  const extensions = object(object(bundle).extensions);
  const block = object(extensions["producer-key/v1"]);
  const publicKey = block.public_key;
  return typeof publicKey === "string" && /^[0-9a-f]{64}$/u.test(publicKey)
    ? publicKey
    : undefined;
}

function stampText(stamp: CountersignatureStamp): string {
  switch (stamp.kind) {
    case "hollow":
      return "Countersigned: none";
    case "producer":
      return "countersigned by the producer — not independent";
    case "directory":
      return `Countersigned by ${stamp.name} · ${stamp.checksRecomputed} of 10 checks recomputed${stamp.date === undefined ? "" : ` · ${stamp.date}`}`;
    case "unresolved":
      return "countersigned by an unlisted signer, not in the countersigner directory";
    case "invalid":
      return "a countersignature is present but failed to verify";
  }
}

function renderStamps(
  host: HTMLElement,
  stamps: readonly CountersignatureStamp[],
): void {
  host.append(element("h4", "Countersignatures"));
  const list = element("ul");
  stamps.forEach((stamp) => {
    const item = element("li", stampText(stamp));
    item.dataset.stampKind = stamp.kind;
    if (stamp.kind === "directory") {
      const logo = document.createElement("img");
      logo.src = stamp.logoDataUrl;
      logo.alt = `${stamp.name} logo`;
      item.append(logo);
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

// One row per supplied record, in bundle order, each with its own standing
// under the checkpoint. The count is stated in words above the list.
function renderCheckpointCoverage(
  host: HTMLElement,
  records: readonly RecordCoverage[],
  uncheckpointed: number,
): void {
  host.append(element("h4", "Checkpoint coverage"));
  const count = element(
    "p",
    `${recordsWord(uncheckpointed)} uncheckpointed of ${recordsWord(records.length)} supplied`,
  );
  count.dataset.coverage = "uncheckpointed";
  count.dataset.count = String(uncheckpointed);
  host.append(count);
  const list = element("ul");
  list.dataset.records = "coverage";
  for (const record of records) {
    const item = element("li", `${record.capsuleId} · `);
    const status = element("span", record.status.replaceAll("_", " "));
    status.dataset.recordStatus = record.status;
    status.className = `seal-${record.status}`;
    item.dataset.capsuleId = record.capsuleId;
    item.append(status);
    list.append(item);
  }
  host.append(list);
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
async function renderVerificationPage(
  root: HTMLElement,
  bundle: unknown,
  verified: BundleVerificationResult,
  countersignerDirectory: readonly CountersignerDirectoryEntry[],
): Promise<void> {
  const page = element("section");
  page.dataset.page = "verification";
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
  renderCheckpointCoverage(page, model.records, model.uncheckpointedCount);
  const countersignatures = object(bundle).countersignatures;
  const stamps = await classifyCountersignatures(
    Array.isArray(countersignatures) ? countersignatures : [],
    verified.bundleDigest,
    producerPublicKeyHex(bundle),
    countersignerDirectory,
  );
  renderStamps(page, stamps);
  renderCompletenessStatement(page, model.completeness);
  renderChecks(page, model.checks);
  page.append(element("p", model.verifyIndependentlyLine));
  root.append(page);
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

export async function renderEvidenceGraph(
  bundle: unknown,
  root: HTMLElement,
  countersignerDirectory: readonly CountersignerDirectoryEntry[] = [],
): Promise<void> {
  // Verify first. Row models are built only from a bundle that verified,
  // and nothing reaches the DOM until the verification result is in hand.
  const verification = await verifyBundle(bundle);
  const verified = bundleVerified(verification);
  // report/v1 is the generic root model; only fall back to the
  // evaluation-summary/v1 graph (which throws on anything else) when this
  // bundle isn't one.
  const reportRows = verified ? await buildReportRows(bundle) : undefined;
  const graph =
    verified && reportRows === undefined
      ? await buildEvidenceGraph(bundle)
      : undefined;
  const records = object(bundle).records;
  root.replaceChildren();
  renderPresentationHeader(root, bundle);
  renderVerificationBanner(root, verified, {
    uncheckpointed: unboundRecordIds(verification).length,
    total: Array.isArray(records) ? records.length : 0,
  });
  if (reportRows !== undefined) {
    renderReportRowsTable(reportRows, root);
  } else if (graph !== undefined) {
    renderGraph(graph, root, Array.isArray(records) ? records : []);
  }
  await renderVerificationPage(
    root,
    bundle,
    verification,
    countersignerDirectory,
  );
}
