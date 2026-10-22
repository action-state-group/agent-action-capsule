// @vitest-environment jsdom

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, it } from "vitest";
import { renderEvidenceGraph } from "../src/browser.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

type Obj = Record<string, unknown>;

function fixture(name: string): Obj {
  return JSON.parse(
    readFileSync(resolve(process.cwd(), "test", "testdata", name), "utf8"),
  ) as Obj;
}

async function render(bundle: unknown): Promise<HTMLElement> {
  const root = document.createElement("main");
  await renderEvidenceGraph(bundle, root);
  return root;
}

async function sealedComplianceBundle(
  mutate?: (source: Obj) => void,
): Promise<{ bundle: Obj; ids: Record<string, string> }> {
  const source = fixture("compliance-bundle.json");
  mutate?.(source);
  return sealEvidenceBundle(source);
}

// ---------------------------------------------------------------------------
// (a) card selection, after outcome-report/v1
// ---------------------------------------------------------------------------

it("renders the compliance card, not the generic Result page, when eu-ai-act-compliance/v1 opts in", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  expect(root.querySelector('[data-verify="verified"]')).not.toBeNull();
  const page = root.querySelector<HTMLElement>('[data-page="compliance"]')!;
  expect(page).not.toBeNull();
  expect(page.classList.contains("cc")).toBe(true);
  expect(root.querySelector('[data-page="result"]')).toBeNull();
  expect(root.lastElementChild).toBe(
    root.querySelector('[data-page="verification"]'),
  );
});

it("eu-ai-act-compliance/v1 present but not enabled falls back to the generic Result page", async () => {
  const { bundle } = await sealedComplianceBundle((source) => {
    ((source.extensions as Obj)["eu-ai-act-compliance/v1"] as Obj).enabled =
      false;
  });
  const root = await render(bundle);
  expect(root.querySelector('[data-page="result"]')).not.toBeNull();
  expect(root.querySelector('[data-page="compliance"]')).toBeNull();
});

it("outcome-report/v1 takes precedence over eu-ai-act-compliance/v1 when a bundle carries both", async () => {
  const { bundle } = await sealedComplianceBundle((source) => {
    (source.extensions as Obj)["outcome-report/v1"] = {
      enabled: true,
      percentages: false,
    };
  });
  const root = await render(bundle);
  expect(root.querySelector('[data-page="outcome-report"]')).not.toBeNull();
  expect(root.querySelector('[data-page="compliance"]')).toBeNull();
});

// ---------------------------------------------------------------------------
// (b) scoped stylesheet, no external reference anywhere
// ---------------------------------------------------------------------------

it("the card's styles are scoped under .cc and the page carries no external reference", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  const style = root.querySelector('[data-page="compliance"] style')!;
  expect(style.textContent).toContain(".cc ");
  expect(style.textContent).not.toMatch(/(^|[^.\w-])body\s*\{/);
  expect(root.innerHTML).not.toMatch(/https?:\/\//);
  expect(root.querySelectorAll("img, script, link, iframe")).toHaveLength(0);
});

// ---------------------------------------------------------------------------
// (c) section content
// ---------------------------------------------------------------------------

it("the summary table shows one row per obligation with its article and status", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  const rows = root.querySelectorAll<HTMLElement>(
    '[data-rows="summary"] tbody tr',
  );
  expect(rows).toHaveLength(3);
  const art26row = root.querySelector<HTMLElement>(
    'tr[data-obligation="art26"]',
  )!;
  expect(art26row.textContent).toContain("Applies 2 Dec 2027");
});

it("an obligation whose rows are all not_evaluable reads Not evaluable in the summary, never No exceptions", async () => {
  // Absent is never pass: art50 has two rows (disclosure_before_first_turn,
  // already always not_evaluable on this dataset, and
  // disclosure_clear_or_obvious, met/not_met in the base fixture). Flip
  // disclosure_clear_or_obvious's two sessions to not_evaluable too, so
  // every row under art50 has zero met and zero not_met -- the obligation
  // was never actually evaluated, and the summary must say so rather than
  // defaulting to "No exceptions" because notMetCount happened to be zero.
  const { bundle } = await sealedComplianceBundle((source) => {
    const agentInput = ((source.disclosures as Obj).result as Obj)
      .agent_input as Obj;
    const claims = agentInput.claims as Obj[];
    const flipped: string[] = [];
    for (const claim of claims)
      if (claim.requirement_ref === "art50.disclosure_clear_or_obvious") {
        claim.verdict = "not_evaluable";
        claim.sufficiency = "GAP";
        flipped.push(claim.id as string);
      }
    const buckets = (agentInput.aggregate as Obj).buckets as Obj;
    buckets.met = (buckets.met as string[]).filter(
      (id) => !flipped.includes(id),
    );
    buckets.not_met = (buckets.not_met as string[]).filter(
      (id) => !flipped.includes(id),
    );
    buckets.not_evaluable = [
      ...(buckets.not_evaluable as string[]),
      ...flipped,
    ];
  });
  const root = await render(bundle);
  const art50row = root.querySelector<HTMLElement>(
    'tr[data-obligation="art50"]',
  )!;
  expect(art50row.textContent).toContain("Not evaluable");
  expect(art50row.textContent).not.toContain("No exceptions");
});

it("a not-yet-applicable obligation whose rows are all not_evaluable says both, never no exceptions", async () => {
  const { bundle } = await sealedComplianceBundle((source) => {
    const agentInput = ((source.disclosures as Obj).result as Obj)
      .agent_input as Obj;
    const flipped: string[] = [];
    for (const claim of agentInput.claims as Obj[])
      if ((claim.requirement_ref as string).startsWith("art26.")) {
        claim.verdict = "not_evaluable";
        claim.sufficiency = "GAP";
        flipped.push(claim.id as string);
      }
    const buckets = (agentInput.aggregate as Obj).buckets as Obj;
    buckets.met = (buckets.met as string[]).filter(
      (id) => !flipped.includes(id),
    );
    buckets.not_met = (buckets.not_met as string[]).filter(
      (id) => !flipped.includes(id),
    );
    buckets.not_evaluable = [
      ...(buckets.not_evaluable as string[]),
      ...flipped,
    ];
  });
  const root = await render(bundle);
  const art26row = root.querySelector<HTMLElement>(
    'tr[data-obligation="art26"]',
  )!;
  expect(art26row.textContent).toContain("Not yet applicable · not evaluable");
  expect(art26row.textContent).not.toContain("no exceptions");
  expect(art26row.textContent).not.toContain("No exceptions");
});

it("the test-results table carries all five tests with population, exceptions and not-evaluable counts", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  const art50f = root.querySelector<HTMLElement>(
    'tr[data-criterion="art50.disclosure_before_first_turn"]',
  )!;
  expect(art50f.textContent).toContain("Not evaluable");
  const cells = art50f.querySelectorAll("td");
  expect(cells[3]!.textContent).toBe("2"); // population
  expect(cells[4]!.textContent).toBe("0"); // exceptions
  expect(cells[5]!.textContent).toBe("2"); // not evaluable
});

it("a session's drill-down shows a check-it block per test with its sealed tier", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  const session = root.querySelector<HTMLElement>(
    'details[data-session="tau2:airline:task-0:trial-0"]',
  )!;
  expect(session).not.toBeNull();
  const blocks = session.querySelectorAll("[data-crit]");
  expect(blocks).toHaveLength(5);
  const judgedBlock = session.querySelector<HTMLElement>(
    '[data-crit="art5.no_manipulation_or_deception"]',
  )!;
  expect(
    judgedBlock.querySelector("[data-tier]")!.getAttribute("data-tier"),
  ).toBe("judged");
  const recomputedBlock = session.querySelector<HTMLElement>(
    '[data-crit="art50.disclosure_before_first_turn"]',
  )!;
  expect(recomputedBlock.textContent).toContain("recomputed");
});

it("findings render for a not-met row with a finding template, never for disclosure_before_first_turn", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  expect(root.querySelector('[data-finding="F-01"]')).not.toBeNull();
  expect(root.querySelector('[data-finding="F-02"]')).not.toBeNull();
  expect(root.querySelectorAll("[data-finding]")).toHaveLength(2); // F-03/F-04 rows have zero not-met sessions here
});

it("the header states where the terms come from, and the regulatory mapping is labelled the producer's", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  const basis = root.querySelector<HTMLElement>('[data-basis="terms"]')!;
  expect(basis.textContent).toContain("sealed claims and reports");
  expect(basis.textContent).toContain("producer's mapping");
  expect(root.querySelector(".hd .sub")!.textContent).toContain(
    "Pack eu-ai-act-obligations v0.1.0",
  );
});

it("every producer-supplied field is set in italics as the producer's, and no sealed value is", async () => {
  const { bundle } = await sealedComplianceBundle((source) => {
    (
      (source.extensions as Obj)["eu-ai-act-compliance/v1"] as Obj
    ).quality_protocol = {
      protocol: "spot-check",
      cadence: "weekly",
      note: "Ten sessions a week.",
    };
  });
  const root = await render(bundle);
  const basis = root.querySelector<HTMLElement>('[data-basis="terms"]')!;
  for (const field of [
    "Obligation titles",
    "test names",
    "method",
    "notes on undecided tests and quality checks",
    "set in italics",
  ])
    expect(basis.textContent).toContain(field);
  const producer = [
    ...root.querySelectorAll<HTMLElement>('i[data-source="producer"]'),
  ].map((i) => i.textContent);
  for (const text of [
    "Art 5(1)(a)",
    "No manipulative or deceptive techniques", // obligation title
    "No manipulative or deceptive technique", // test name
    "In force since 2 Feb 2025",
    "Review flagged sessions for manufactured urgency.",
    "AirlineAgentsNow · 31 Oct 2026",
    "Not evaluable against the agent on tau2 trial-0 data.",
    "Art 5(1)(a) · No manipulative or deceptive techniques", // detail heading
    "Judged per session against a frozen rubric.",
    "spot-check",
    "weekly",
    "Ten sessions a week.",
  ])
    expect(producer).toContain(text);
  const detail = root.querySelector<HTMLElement>(
    '[data-obligation-detail="art5"]',
  )!;
  expect(detail.querySelector(".na")!.textContent).toBe(
    "Title, article, summary, method, test names and the undecided-session note: the producer's mapping, in italics, not a sealed record.",
  );
  // sealed values and the page's own words are never set as the producer's
  for (const sealed of root.querySelectorAll(
    '.st, td.n, .ck .why, [data-section="methodology"]',
  ))
    expect(sealed.querySelector('[data-source="producer"]')).toBeNull();
});

it("an obligation the producer does not map shows its sealed test id, not in italics", async () => {
  const { bundle } = await sealedComplianceBundle((source) => {
    const ext = (source.extensions as Obj)["eu-ai-act-compliance/v1"] as Obj;
    ext.obligations = (ext.obligations as Obj[]).filter(
      (o) => o.key !== "art5",
    );
  });
  const root = await render(bundle);
  const row = root.querySelector<HTMLElement>(
    '[data-rows="summary"] tr[data-obligation="art5"]',
  )!;
  expect(row).not.toBeNull();
  expect(row.querySelector('[data-source="producer"]')).toBeNull();
  const test = root.querySelector<HTMLElement>(
    'tr[data-criterion="art5.no_manipulation_or_deception"]',
  )!;
  expect(test.querySelector('[data-source="producer"]')).toBeNull();
});

it("a session without a transcript in the bundle says so, and names the case record", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  const tx = root.querySelector<HTMLElement>('[data-transcript="absent"]')!;
  expect(tx.textContent).toContain("not in this bundle");
});

it("population counts only the sessions a test has a sealed result for", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  const row = root.querySelector<HTMLElement>(
    'tr[data-criterion="art26.allowed_action_rules"]',
  )!;
  expect(row.querySelectorAll("td")[3]!.textContent).toBe("1");
});

// ---------------------------------------------------------------------------
// dating: the obligations card dates a session the way the outcome card does
// (a backfilled case record by its source's own time, labelled "source
// says"), never by the day its reports were sealed alone
// ---------------------------------------------------------------------------

/** Cites one case record per conversation, as the outcome card's tests do. */
function withCaseRecords(
  source: Obj,
  fields: (conversationId: string, index: number) => Obj,
): void {
  const result = ((source.disclosures as Obj).result as Obj).agent_input as Obj;
  const records = source.records as Obj[];
  const root = records.find((r) => r.capsule_id === "result")!;
  const references = root.references as Obj[] | undefined;
  const seen = new Map<string, string>();
  for (const claim of result.claims as Obj[]) {
    const id = claim.id as string;
    const sep = id.indexOf("::");
    if (sep === -1) continue;
    const conversationId = id.slice(0, sep);
    let alias = seen.get(conversationId);
    if (alias === undefined) {
      alias = `case:${conversationId}`;
      seen.set(conversationId, alias);
      records.push({
        capsule_id: alias,
        ...fields(conversationId, seen.size - 1),
      });
      references?.push({
        type: "agent-action-capsule",
        citation_purpose: "acted_on",
        digest: alias,
      });
    }
    (claim.evidence as Obj[]).push({ digest_alg: "SHA-256", digest: alias });
  }
  for (const entry of Object.values(source.disclosures as Obj)) {
    const input = (entry as Obj).agent_input as Obj | undefined;
    if (input !== undefined && typeof input.case_id === "string")
      input.source_capsule_id = `case:${input.case_id}`;
  }
}

const BACKFILLED = (sourceAssertedAt: string): Obj => ({
  timestamp: "2026-10-20T10:00:00Z",
  provenance_mode: {
    mode: "backfilled",
    source_ref: {
      type: "tau2-simulation",
      digest_alg: "SHA-256",
      digest: "0".repeat(64),
    },
    source_asserted_at: sourceAssertedAt,
    import_batch: "tau2-airline-replay-2025-09",
    imported_at: "2026-10-20T10:00:00Z",
    time_rung: "self_attested",
  },
});

it("dating: a backfilled session is dated by its source's own time, labelled 'source says', with the import and sealed days beside it", async () => {
  const { bundle } = await sealedComplianceBundle((source) =>
    withCaseRecords(source, (_, i) =>
      BACKFILLED(`2025-09-0${i + 3}T16:06:37Z`),
    ),
  );
  const root = await render(bundle);
  expect(root.querySelector('[data-verify="verified"]')).not.toBeNull();
  const session = root.querySelector<HTMLElement>("details.session")!;
  expect(session.querySelector("summary")!.textContent).toMatch(
    / · 2025-09-0\d$/,
  );
  const dated = session.querySelector<HTMLElement>("[data-dated]")!;
  expect(dated.dataset.dated).toBe("source");
  expect(dated.textContent).toMatch(
    /^2025-09-0\dT16:06:37Z: source says \(backfilled record; the source's own timestamp, self-attested\)$/,
  );
  expect(session.querySelector("[data-imported]")!.textContent).toBe(
    "Imported 2026-10-20T10:00:00Z",
  );
  expect(session.querySelector("[data-sealed]")!.textContent).toBe(
    "Judged and sealed 2026-09-23",
  );
  const method = root.querySelector<HTMLElement>(
    '[data-section="methodology"]',
  )!;
  expect(method.querySelector("[data-period]")!.textContent).toMatch(
    /^Period2025-09-03( – 2025-09-0\d)?$/,
  );
  expect(method.querySelector("[data-sealed]")!.textContent).toBe(
    "Sealed2026-09-23",
  );
  const note = method.querySelector<HTMLElement>("[data-date-note]")!;
  expect(note.dataset.dateNote).toBe("source");
  expect(note.textContent).toContain(
    'Dates are the source\'s own timestamps for backfilled records ("source says")',
  );
  expect(note.textContent).toContain(
    "self-attested: carrying it does not make it witnessed",
  );
});

it("dating: with no case record cited, a session keeps the day its reports were sealed under and the page adds no date note", async () => {
  const { bundle } = await sealedComplianceBundle();
  const root = await render(bundle);
  const session = root.querySelector<HTMLElement>("details.session")!;
  expect(session.querySelector("summary")!.textContent).toMatch(
    / · 2026-09-23$/,
  );
  expect(session.querySelector("[data-dated]")).toBeNull();
  const method = root.querySelector<HTMLElement>(
    '[data-section="methodology"]',
  )!;
  expect(method.querySelector("[data-period]")!.textContent).toBe(
    "Period2026-09-23",
  );
  expect(method.querySelector("[data-date-note]")).toBeNull();
});
