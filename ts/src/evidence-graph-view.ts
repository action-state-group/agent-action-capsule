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
  type CalibrationNode,
  type CaseNode,
  type EvidenceGraph,
  type ReportNode,
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

function renderVerification(
  root: HTMLElement,
  bundle: unknown,
): Promise<BundleVerificationResult> {
  return verifyBundle(bundle).then((result) => {
    const verified =
      result.graphClosure.status === "pass" &&
      result.intervalCoverage.status === "pass" &&
      result.perRecordMembership.status === "pass" &&
      Object.values(result.capsuleResults).every((capsule) => capsule.ok) &&
      result.disclosures.every(
        (disclosure) =>
          disclosure.status === "disclosure_match" ||
          disclosure.status === "withheld",
      );
    const banner = element(
      "p",
      verified ? "Bundle verification passed" : "Bundle verification failed",
    );
    banner.dataset.verify = verified ? "verified" : "failed";
    root.append(banner);
    return result;
  });
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
    list.append(
      element("li", `${receipt.witness} · ${receipt.grade} · ${receipt.time}`),
    );
  });
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
  appendValue(details, "agreement", calibration.agreement);
  appendValue(details, "corrected rate", calibration.correctedRate);
  appendValue(details, "corrected rate CI", calibration.correctedRateCi);
  appendValue(details, "period window", calibration.periodWindow);
  section.append(details);
  return section;
}

function renderProvenance(
  capsuleId: string,
  coordinates?: ActNode["logCoordinates"],
): HTMLElement {
  const panel = element("section");
  panel.append(element("h4", "Provenance"));
  const details = element("dl");
  appendValue(details, "capsule ID", capsuleId);
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
  section.append(renderProvenance(act.capsuleId, act.logCoordinates));
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
  host.append(element("h2", `Cases for ${report.date}`));
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
    renderProvenance(report.capsuleId, report.logCoordinates),
  );
}

// report/v1: the generic row path. Every row is rendered from its own data
// -- label, status, reason, citations -- never from report-specific markup,
// so a pack this module has never heard of (obligations, Consumer Duty,
// anything else) renders the same way an outcomes report does.
function renderCitation(citation: ReportRowCitation): HTMLElement {
  const section = element("section");
  section.append(renderProvenance(citation.capsuleId, citation.logCoordinates));
  section.append(
    citation.disclosedPayload === undefined
      ? element("p", "withheld")
      : element("pre", display(citation.disclosedPayload)),
  );
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
    renderProvenance(reportRows.capsuleId, reportRows.logCoordinates),
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
      const tile = element("button", `${report.date}: ${metRate(report)}`);
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
  // report/v1 is the generic root model; only fall back to the
  // evaluation-summary/v1 graph (which throws on anything else) when this
  // bundle isn't one.
  const reportRows = buildReportRows(bundle);
  const graph =
    reportRows === undefined ? buildEvidenceGraph(bundle) : undefined;
  root.replaceChildren();
  renderPresentationHeader(root, bundle);
  if (reportRows !== undefined) {
    renderReportRowsTable(reportRows, root);
  } else if (graph !== undefined) {
    const records = object(bundle).records;
    renderGraph(graph, root, Array.isArray(records) ? records : []);
  }
  const verified = await renderVerification(root, bundle);
  await renderVerificationPage(root, bundle, verified, countersignerDirectory);
}
