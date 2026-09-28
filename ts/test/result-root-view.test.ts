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

function resultOf(source: Obj): Obj {
  return ((source.disclosures as Obj).result as Obj).agent_input as Obj;
}

const ABSENT_ID =
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

async function render(bundle: unknown): Promise<HTMLElement> {
  const root = document.createElement("main");
  await renderEvidenceGraph(bundle, root);
  return root;
}

/** All text in document order before `stop`, within `scope`. */
function textBefore(scope: HTMLElement, stop: Element): string {
  const walker = document.createTreeWalker(scope, NodeFilter.SHOW_TEXT);
  let text = "";
  for (let node = walker.nextNode(); node !== null; node = walker.nextNode()) {
    if (
      !(stop.compareDocumentPosition(node) & Node.DOCUMENT_POSITION_PRECEDING)
    )
      break;
    text += node.textContent ?? "";
  }
  return text;
}

function tamperCheckpoint(bundle: Obj): Obj {
  const checkpoint = bundle.checkpoint as { mmr_size: number };
  return {
    ...bundle,
    checkpoint: { ...checkpoint, mmr_size: checkpoint.mmr_size + 1 },
  };
}

it("(e) renders the Result root: banner, then coverage before any number, buckets, one row per claim, verification page last", async () => {
  const { bundle, ids } = await sealEvidenceBundle(
    fixture("result-root-bundle.json"),
  );
  const root = await render(bundle);

  const banner = root.querySelector<HTMLElement>('[data-verify="verified"]')!;
  expect(banner).not.toBeNull();
  const page = root.querySelector<HTMLElement>('[data-page="result"]')!;
  expect(page).not.toBeNull();
  expect(
    banner.compareDocumentPosition(page) & Node.DOCUMENT_POSITION_FOLLOWING,
  ).toBeTruthy();
  // not the other two root families
  expect(root.querySelector("[data-report-date]")).toBeNull();
  expect(root.querySelector("[data-row-id]")).toBeNull();

  const coverage = page.querySelector<HTMLElement>('[data-coverage="result"]')!;
  expect(coverage).not.toBeNull();
  expect(coverage.textContent).toBe(
    "coverage: 3 requirements evaluated · 1 excluded as not applicable · 0 unresolved",
  );
  // coverage is the first thing after the heading, and nothing before it,
  // anywhere on the rendered page, carries a number
  expect(page.firstElementChild!.tagName).toBe("H1");
  expect(page.firstElementChild!.nextElementSibling).toBe(coverage);
  expect(textBefore(root, coverage)).not.toMatch(/\d/u);

  const buckets = page.querySelector<HTMLElement>('[data-buckets="verdict"]')!;
  expect(
    coverage.compareDocumentPosition(buckets) &
      Node.DOCUMENT_POSITION_FOLLOWING,
  ).toBeTruthy();
  expect(
    Array.from(buckets.querySelectorAll("[data-bucket]"), (list) => [
      (list as HTMLElement).dataset.bucket,
      Array.from(list.querySelectorAll("li"), (item) => item.textContent),
    ]),
  ).toEqual([
    ["met", ["claim-1"]],
    ["notMet", ["claim-2"]],
    ["notEvaluable", ["claim-3"]],
  ]);
  // no percentage, no single score, anywhere above the rows
  expect(textBefore(page, page.querySelector("table")!)).not.toMatch(
    /%|\d+ of \d+/u,
  );

  const rows = page.querySelectorAll<HTMLElement>("[data-claim-row]");
  expect(rows).toHaveLength(3);
  expect(
    Array.from(rows, (row) => [
      row.dataset.claimRow,
      row.querySelector<HTMLElement>("[data-sufficiency]")!.dataset.sufficiency,
      row.querySelector<HTMLElement>("[data-verdict]")!.dataset.verdict,
      row.querySelector<HTMLElement>("[data-tier]")!.dataset.tier,
      row.querySelector<HTMLElement>("[data-grade]")!.dataset.grade,
      row.querySelector<HTMLElement>("[data-claim-type]")!.dataset.claimType,
    ]),
  ).toEqual([
    ["claim-1", "SATISFIED", "met", "recomputed", "witnessed", "requirement"],
    [
      "claim-2",
      "SATISFIED",
      "not_met",
      "judged",
      "self-attested",
      "requirement",
    ],
    [
      "claim-3",
      "GAP",
      "not_evaluable",
      "recomputed",
      "countersigned",
      "requirement",
    ],
  ]);
  expect(page.querySelector(".claim-unsupported")).toBeNull();
  expect(page.querySelector(".claim-unrecognized")).toBeNull();
  expect(page.textContent).toContain(ids["result"]);

  const verification = root.querySelector('[data-page="verification"]');
  expect(root.lastElementChild).toBe(verification);
});

it("drills down from a claim to the records it cites, and from a daily report to the act it cites", async () => {
  const { bundle, ids } = await sealEvidenceBundle(
    fixture("result-root-bundle.json"),
  );
  const root = await render(bundle);
  const page = root.querySelector<HTMLElement>('[data-page="result"]')!;
  // nothing from a cited record is drawn before a claim is opened
  expect(page.querySelector("pre")).toBeNull();

  page.querySelector<HTMLElement>('[data-claim-id="claim-1"]')!.click();
  const cited = Array.from(
    page.querySelectorAll<HTMLElement>("[data-cited-record]"),
    (section) => section.dataset.citedRecord,
  );
  expect(cited).toEqual([ids["day-1"], ids["day-2"]]);
  const transcript = Array.from(
    page.querySelectorAll("pre"),
    (pre) => pre.textContent,
  );
  expect(transcript).toContain(
    JSON.stringify(
      (fixture("result-root-bundle.json").disclosures as Record<string, Obj>)[
        "day-2"
      ]!.agent_input,
    ),
  );
  expect(page.textContent).toContain("Claim claim-1");
  expect(page.textContent).toContain("inclusion_proof · 0123456789abcdef");
  expect(page.textContent).not.toContain("change my flight");

  // the daily report cites an act: one more click, one more record
  const actButton = page.querySelector<HTMLElement>(
    `[data-cited-id="${ids["act-1"]}"]`,
  )!;
  expect(actButton).not.toBeNull();
  actButton.click();
  expect(page.textContent).toContain("change my flight to the fourteenth");
  expect(page.textContent).toContain("your flight is now on the fourteenth");

  // claim-3: analysis carrier, its summary shown, its evidence a daily report
  page.querySelector<HTMLElement>('[data-claim-id="claim-3"]')!.click();
  expect(page.textContent).toContain(
    "the counterparty confirmed the record exists",
  );
  expect(page.textContent).toContain("WITHHELD");
  expect(page.textContent).toContain("no proof cited");
});

it("renders a disclosure carrier's own evidence list, in the citation row shape, resolved against this bundle", async () => {
  const source = fixture("result-root-bundle.json");
  // the carrier discloses a different list from the claim's evidence: one
  // cited record and one digest this bundle does not carry
  const claim = (resultOf(source).claims as Obj[])[0]!;
  (claim.presentation as Obj).evidence = [
    { digest_alg: "SHA-256", digest: "case-1" },
    { digest_alg: "SHA-256", digest: ABSENT_ID },
  ];
  const { bundle, ids } = await sealEvidenceBundle(source);
  const root = await render(bundle);
  const page = root.querySelector<HTMLElement>('[data-page="result"]')!;
  expect(page.querySelector("[data-carrier-evidence]")).toBeNull();

  page.querySelector<HTMLElement>('[data-claim-id="claim-1"]')!.click();
  // the verdict still rests on the claim's own evidence, which resolves
  expect(
    page.querySelector<HTMLElement>('[data-claim-row="claim-1"]')!.dataset
      .support,
  ).toBe("supported");
  const list = page.querySelector<HTMLElement>("[data-carrier-evidence]")!;
  expect(list.dataset.carrierEvidence).toBe("2");
  const rows = Array.from(list.querySelectorAll("li"));
  expect(rows).toHaveLength(2);
  expect(
    rows[0]!.querySelector<HTMLElement>("[data-cited-id]")!.dataset.citedId,
  ).toBe(ids["case-1"]);
  expect(rows[1]!.textContent).toBe(`${ABSENT_ID} · not in this bundle`);
  expect(rows[1]!.dataset.citation).toBe("missing");
  // the resolved row opens the cited record; the claim's own drill-down
  // still draws its cited daily reports, not the carrier's case
  expect(page.textContent).not.toContain("the quoted fee did not match");
  rows[0]!.querySelector<HTMLElement>("button")!.click();
  expect(page.textContent).toContain("the quoted fee did not match");
  expect(
    Array.from(
      page.querySelectorAll<HTMLElement>("[data-cited-record]"),
      (section) => section.dataset.citedRecord,
    ),
  ).toEqual([ids["case-1"], ids["day-1"], ids["day-2"]]);

  // a non-disclosure carrier draws no carrier list
  page.querySelector<HTMLElement>('[data-claim-id="claim-3"]')!.click();
  expect(page.querySelector("[data-carrier-evidence]")).toBeNull();
});

it("renders a cited record outside the checkpoint as uncheckpointed under the Result, with the bundle-level count above coverage", async () => {
  const { bundle, ids } = await sealEvidenceBundle(
    fixture("result-root-bundle.json"),
    { uncheckpointed: ["day-2"] },
  );
  expect(
    Object.keys(
      (bundle.completeness_certificate as { memberships: Obj }).memberships,
    ),
  ).not.toContain(ids["day-2"]);
  const root = await render(bundle);

  // verified, with the count said up front: this is the bundle-level banner,
  // above every section, and the one number that precedes coverage
  const banner = root.querySelector<HTMLElement>("[data-verify]")!;
  expect(banner.dataset.verify).toBe("verified");
  expect(banner.dataset.uncheckpointed).toBe("1");
  expect(banner.textContent).toBe(
    "Bundle verification passed; 1 of 5 records uncheckpointed",
  );
  const page = root.querySelector<HTMLElement>('[data-page="result"]')!;
  expect(page).not.toBeNull();
  const coverage = page.querySelector<HTMLElement>('[data-coverage="result"]')!;
  expect(textBefore(page, coverage)).not.toMatch(/\d/u);
  expect(textBefore(root, coverage)).toMatch(/1 of 5 records uncheckpointed/u);
  expect(page.querySelectorAll("[data-claim-row]")).toHaveLength(3);

  // the root's own panel is checkpointed; nothing cited is drawn yet
  expect(page.querySelectorAll("[data-seal]")).toHaveLength(1);
  expect(page.querySelector<HTMLElement>("[data-seal]")!.dataset.seal).toBe(
    "checkpointed",
  );

  // claim-1 cites day-1 (checkpointed) and day-2 (uncheckpointed): each
  // cited record carries ITS OWN seal status, and the claim stays supported
  page.querySelector<HTMLElement>('[data-claim-id="claim-1"]')!.click();
  const sealOf = (capsuleId: string): string =>
    page
      .querySelector<HTMLElement>(`[data-cited-record="${capsuleId}"]`)!
      .querySelector<HTMLElement>("[data-seal]")!.dataset.seal!;
  expect(sealOf(ids["day-1"]!)).toBe("checkpointed");
  expect(sealOf(ids["day-2"]!)).toBe("uncheckpointed");
  const row = page.querySelector<HTMLElement>('[data-claim-row="claim-1"]')!;
  expect(row.dataset.support).toBe("supported");
  expect(
    row.querySelector<HTMLElement>("[data-verdict]")!.dataset.verdict,
  ).toBe("met");
  expect(page.querySelectorAll('[data-seal="uncheckpointed"]')).toHaveLength(1);

  // the verification page counts it, in words, and marks the one record
  const verification = root.querySelector<HTMLElement>(
    '[data-page="verification"]',
  )!;
  const count = verification.querySelector<HTMLElement>(
    '[data-coverage="uncheckpointed"]',
  )!;
  expect(count.dataset.count).toBe("1");
  expect(count.textContent).toBe(
    "1 record uncheckpointed of 5 records supplied",
  );
  expect(
    Array.from(
      verification.querySelectorAll<HTMLElement>(
        '[data-records="coverage"] > li',
      ),
    )
      .filter((item) =>
        item.querySelector('[data-record-status="uncheckpointed"]'),
      )
      .map((item) => item.dataset.capsuleId),
  ).toEqual([ids["day-2"]]);
});

it("(b) renders a claim whose cited id is missing from the bundle as unsupported, never met, and keeps the row", async () => {
  const source = fixture("result-root-bundle.json");
  ((resultOf(source).claims as Obj[])[0]!.evidence as Obj[])[1]!.digest =
    ABSENT_ID;
  const { bundle } = await sealEvidenceBundle(source);
  const root = await render(bundle);
  expect(root.querySelector('[data-verify="verified"]')).not.toBeNull();
  const page = root.querySelector<HTMLElement>('[data-page="result"]')!;

  const rows = page.querySelectorAll<HTMLElement>("[data-claim-row]");
  expect(rows).toHaveLength(3);
  const row = page.querySelector<HTMLElement>('[data-claim-row="claim-1"]')!;
  expect(row.dataset.support).toBe("unsupported");
  expect(row.className).toBe("claim-unsupported");
  const verdict = row.querySelector<HTMLElement>("[data-verdict]")!;
  expect(verdict.dataset.verdict).toBe("unsupported");
  expect(verdict.textContent).toBe("unsupported");
  expect(row.textContent).not.toMatch(/\bmet\b/u);
  // the bucket the Result put it in still lists it, marked
  const bucket = page.querySelector<HTMLElement>('[data-bucket="met"]')!;
  expect(bucket.querySelector('[data-claim-ref="claim-1"]')!.textContent).toBe(
    "claim-1 · unsupported",
  );
  // the drill-down says which id did not resolve
  page.querySelector<HTMLElement>('[data-claim-id="claim-1"]')!.click();
  expect(page.querySelector('[data-claim-missing="1"]')!.textContent).toBe(
    `unsupported: cited evidence not in this bundle: ${ABSENT_ID}`,
  );
  expect(page.querySelector('[data-evidence="missing"]')!.textContent).toBe(
    `${ABSENT_ID} · not in this bundle`,
  );
  const openVerdict = page.querySelector<HTMLElement>("dd[data-verdict]")!;
  expect(openVerdict.textContent).toBe("unsupported");
  // the other claims are untouched
  expect(
    page.querySelector<HTMLElement>(
      '[data-claim-row="claim-2"] [data-verdict]',
    )!.dataset.verdict,
  ).toBe("not_met");
});

it("renders a claim of an unknown type as unrecognized, with its axes, never dropped", async () => {
  const source = fixture("result-root-bundle.json");
  (resultOf(source).claims as Obj[])[2]!.type = "reconcile";
  const { bundle } = await sealEvidenceBundle(source);
  const root = await render(bundle);
  const page = root.querySelector<HTMLElement>('[data-page="result"]')!;
  expect(page.querySelectorAll("[data-claim-row]")).toHaveLength(3);
  const row = page.querySelector<HTMLElement>('[data-claim-row="claim-3"]')!;
  const type = row.querySelector<HTMLElement>("[data-claim-type]")!;
  expect(type.dataset.claimType).toBe("unrecognized");
  expect(type.className).toBe("claim-unrecognized");
  expect(type.textContent).toBe("unrecognized (reconcile)");
  expect(
    row.querySelector<HTMLElement>("[data-verdict]")!.dataset.verdict,
  ).toBe("not_evaluable");
  expect(row.querySelector<HTMLElement>("[data-grade]")!.dataset.grade).toBe(
    "countersigned",
  );
  expect(row.dataset.support).toBe("supported");
});

it("(c) a tampered claim in the root Result fails verification: no Result page, no rows, no payloads", async () => {
  const { bundle, ids } = await sealEvidenceBundle(
    fixture("result-root-bundle.json"),
  );
  const disclosures = bundle.disclosures as Record<string, Obj>;
  const tampered = structuredClone(
    disclosures[ids["result"]!]!.agent_input,
  ) as Obj;
  (tampered.claims as Obj[])[1]!.verdict = "met";
  (tampered.claims as Obj[])[1]!.requirement_ref = "req-2-tampered";
  ((tampered.aggregate as Obj).buckets as Obj) = {
    met: ["claim-1", "claim-2"],
    not_met: [],
    not_evaluable: ["claim-3"],
  };
  const root = await render({
    ...bundle,
    disclosures: {
      ...disclosures,
      [ids["result"]!]: { agent_input: tampered },
    },
  });
  expect(root.querySelector('[data-verify="failed"]')).not.toBeNull();
  expect(
    root.querySelector('[data-refusal="unverified-bundle"]'),
  ).not.toBeNull();
  expect(root.querySelector('[data-page="result"]')).toBeNull();
  expect(root.querySelectorAll("[data-claim-row]")).toHaveLength(0);
  expect(root.querySelectorAll("pre")).toHaveLength(0);
  expect(root.textContent).not.toContain("req-2-tampered");
  expect(root.querySelector('[data-coverage="result"]')).toBeNull();
  expect(root.textContent).not.toContain("requirements evaluated");
  expect(root.lastElementChild).toBe(
    root.querySelector('[data-page="verification"]'),
  );
});

it("H2: an unverified Result-root bundle renders no Result page", async () => {
  const { bundle } = await sealEvidenceBundle(
    fixture("result-root-bundle.json"),
  );
  const root = await render(tamperCheckpoint(bundle));
  expect(root.querySelector('[data-verify="failed"]')).not.toBeNull();
  expect(root.querySelector('[data-page="result"]')).toBeNull();
  expect(root.querySelectorAll("[data-claim-row]")).toHaveLength(0);
});

it("(a) a verified bundle whose root names itself a Result v0 but is malformed is refused, never rendered as one", async () => {
  const source = fixture("result-root-bundle.json");
  (resultOf(source).claims as Obj[])[2]!.verdict = "met";
  const { bundle } = await sealEvidenceBundle(source);
  const root = document.createElement("main");
  await expect(renderEvidenceGraph(bundle, root)).rejects.toThrow(
    /root is not a Result v0/u,
  );
});

it("still renders the evaluation-summary and report/v1 root families", async () => {
  const week = await render(fixture("week-bundle.json"));
  expect(week.querySelector('[data-verify="verified"]')).not.toBeNull();
  expect(week.querySelectorAll("[data-report-date]").length).toBeGreaterThan(0);
  expect(week.querySelector('[data-page="result"]')).toBeNull();

  const { bundle } = await sealEvidenceBundle(
    fixture("report-rows-bundle.json"),
  );
  const rows = await render(bundle);
  expect(rows.querySelector('[data-page="report-rows"]')).not.toBeNull();
  expect(rows.querySelector('[data-page="result"]')).toBeNull();
});
