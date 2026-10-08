// @vitest-environment jsdom

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, it } from "vitest";
import { renderEvidenceGraph } from "../src/browser.js";
import { jsonDigest } from "../src/json.js";
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

/** See outcome-report.test.ts's copy: result-root's shape check requires
 * aggregate.buckets to partition every claim exactly once. */
function rebuildBuckets(claims: Obj[]): Obj {
  const buckets: Record<string, string[]> = {
    met: [],
    not_met: [],
    not_evaluable: [],
  };
  for (const claim of claims)
    buckets[claim.verdict as string]!.push(claim.id as string);
  return buckets;
}

// test/testdata/outcome-report-bundle.json is the output of evidencebook-skills'
// judge pipeline (mock judge backend, 50 trial-0 tau2-bench airline tasks,
// nine rubric criteria judged) -- see outcome-report.test.ts's header comment
// and scripts/outcome-report-fixture.mjs. 50 conversations, all nine criteria
// judged, 0 resolved (expected under the mock backend's roughly uniform
// per-criterion verdicts).
async function sealedOutcomeReportBundle(
  mutate?: (source: Obj) => void,
): Promise<{ bundle: Obj; ids: Record<string, string> }> {
  const source = fixture("outcome-report-bundle.json");
  mutate?.(source);
  return sealEvidenceBundle(source);
}

// ---------------------------------------------------------------------------
// (a) the card renders in place of the generic Result page, after the same
// verify-first gate, and the generic report stays the default elsewhere
// ---------------------------------------------------------------------------

it("renders the outcome-report card, not the generic Result page, when outcome-report/v1 opts in", async () => {
  const { bundle } = await sealedOutcomeReportBundle();
  const root = await render(bundle);
  expect(root.querySelector('[data-verify="verified"]')).not.toBeNull();
  const page = root.querySelector<HTMLElement>('[data-page="outcome-report"]')!;
  expect(page).not.toBeNull();
  expect(page.classList.contains("oi")).toBe(true);
  expect(root.querySelector('[data-page="result"]')).toBeNull();
  // verification page still runs last, same chrome as every other root family
  expect(root.lastElementChild).toBe(
    root.querySelector('[data-page="verification"]'),
  );
});

it("the generic Result page stays the default for a Result-root bundle that does not carry outcome-report/v1", async () => {
  const { bundle } = await sealEvidenceBundle(
    fixture("result-root-bundle.json"),
  );
  const root = await render(bundle);
  expect(root.querySelector('[data-page="result"]')).not.toBeNull();
  expect(root.querySelector('[data-page="outcome-report"]')).toBeNull();
});

it("outcome-report/v1 present but not enabled also falls back to the generic Result page", async () => {
  const { bundle } = await sealedOutcomeReportBundle((source) => {
    ((source.extensions as Obj)["outcome-report/v1"] as Obj).enabled = false;
  });
  const root = await render(bundle);
  expect(root.querySelector('[data-page="result"]')).not.toBeNull();
  expect(root.querySelector('[data-page="outcome-report"]')).toBeNull();
});

// ---------------------------------------------------------------------------
// LOOK: the card's own scoped stylesheet, no external reference anywhere
// ---------------------------------------------------------------------------

it("carries its own scoped <style>, every selector prefixed .oi, no external reference anywhere on the page", async () => {
  const { bundle } = await sealedOutcomeReportBundle();
  const root = await render(bundle);
  const page = root.querySelector<HTMLElement>('[data-page="outcome-report"]')!;
  const style = page.querySelector("style")!;
  expect(style).not.toBeNull();
  expect(style.textContent).toContain(".oi ");
  expect(style.textContent).toContain("table.lines");
  expect(style.textContent).toContain(".cal{");
  // nothing unscoped (a bare "body{" or a bare "h1,h2,h3{" with no .oi
  // prefix) reached the page: the verification page below the card takes
  // this look only through its own explicit .oi.oi-vp class (see the
  // verification-page test below), never by a stylesheet leak
  expect(style.textContent).not.toMatch(/(^|\n)body\{/u);
  expect(style.textContent).not.toMatch(/(^|\n)h1,h2,h3\{/u);
  expect(root.innerHTML).not.toMatch(/https?:\/\//u);
  expect(
    Array.from(root.querySelectorAll("img, script, link, iframe")),
  ).toHaveLength(0);
});

// ---------------------------------------------------------------------------
// meta
// ---------------------------------------------------------------------------

it("renders the header meta: pack id/version, period, conversation count, result capsule", async () => {
  const { bundle, ids } = await sealedOutcomeReportBundle();
  const root = await render(bundle);
  const meta = root.querySelector<HTMLElement>('[data-section="meta"]')!;
  // pack and version from the claims' contract_ref; the lock date is stated
  // by nothing in the bundle, so it reads "not stated"
  expect(meta.textContent).toContain("tau2-airline-outcomes/v1 v1");
  expect(meta.textContent).toContain("Terms locked: not stated");
  expect(meta.textContent).not.toContain("2026-08-31");
  expect(meta.textContent).toContain("2026-09-23 – 2026-09-23");
  expect(meta.textContent).toContain("50");
  expect(meta.textContent).toContain(ids["result"]);
});

// ---------------------------------------------------------------------------
// report lines
// ---------------------------------------------------------------------------

it("renders report lines with counts recomputed from the claims, and held/added from calibration (zero when none is cited)", async () => {
  const { bundle } = await sealedOutcomeReportBundle();
  const root = await render(bundle);
  const table = root.querySelector<HTMLElement>('[data-rows="report-lines"]')!;
  const line = (key: string) =>
    table.querySelector<HTMLElement>(`[data-line="${key}"]`)!;
  expect(line("resolved").dataset.count).toBe("0");
  expect(line("missed").dataset.count).toBe("50");
  expect(line("held").dataset.count).toBe("0");
  expect(line("added").dataset.count).toBe("0");
  expect(line("resolved").textContent).toContain("0 of 50");
});

it("shows counts by default, never a percentage, unless the presentation flag asks for one", async () => {
  const { bundle } = await sealedOutcomeReportBundle();
  const root = await render(bundle);
  const table = root.querySelector<HTMLElement>('[data-rows="report-lines"]')!;
  expect(table.textContent).not.toMatch(/%/u);

  const { bundle: pctBundle } = await sealedOutcomeReportBundle((source) => {
    ((source.extensions as Obj)["outcome-report/v1"] as Obj).percentages = true;
  });
  const pctRoot = await render(pctBundle);
  const pctTable = pctRoot.querySelector<HTMLElement>(
    '[data-rows="report-lines"]',
  )!;
  expect(pctTable.querySelector('[data-line="missed"]')!.textContent).toContain(
    "100%",
  );
});

it("renders a static verified stamp and the verify-first tamper note, never an interactive tamper control", async () => {
  const { bundle } = await sealedOutcomeReportBundle();
  const root = await render(bundle);
  expect(root.querySelector(".stamp.rec")).not.toBeNull();
  const note = root.querySelector<HTMLElement>("[data-tamper-note]")!;
  expect(note.dataset.tamperNote).toBe("verify-first");
  expect(root.querySelectorAll("button")).toHaveLength(0);
});

// ---------------------------------------------------------------------------
// day by day
// ---------------------------------------------------------------------------

it("renders one tile per day, resolved of total", async () => {
  const { bundle } = await sealedOutcomeReportBundle();
  const root = await render(bundle);
  const list = root.querySelector<HTMLElement>("[data-days]")!;
  expect(list.dataset.days).toBe("1");
  const day = list.querySelector<HTMLElement>('[data-day="2026-09-23"]')!;
  expect(day).not.toBeNull();
  expect(day.dataset.resolved).toBe("0");
  expect(day.dataset.total).toBe("50");
  // no evaluation-report/v1 record carries a day-level policy-change flag,
  // so none is drawn
  expect(day.querySelector("[data-policy-changed]")).toBeNull();
});

// ---------------------------------------------------------------------------
// human spot checks
// ---------------------------------------------------------------------------

it("renders 'no calibration-summary/v1 records cited' when the bundle cites none -- the real pipeline's own shape today", async () => {
  const { bundle } = await sealedOutcomeReportBundle();
  const root = await render(bundle);
  const section = root.querySelector<HTMLElement>(
    '[data-section="human-checks"]',
  )!;
  expect(section.textContent).toContain(
    "no calibration-summary/v1 records cited",
  );
  expect(section.querySelector("[data-weeks]")).toBeNull();
});

it("renders human spot checks: k of n per week, from an injected calibration-summary/v1, with held and added split out", async () => {
  const { bundle } = await sealedOutcomeReportBundle((source) => {
    const resultDoc = ((source.disclosures as Obj).result as Obj)
      .agent_input as Obj;
    const claims = resultDoc.claims as Obj[];
    const conversationId = (claims[0]!.id as string).split("::")[0]!;
    (source.records as Obj[]).push({ capsule_id: "cal-2026-W39" });
    const calClaim = {
      id: "cal::2026-W39",
      type: "calibration",
      contract_ref: (claims[0] as Obj).contract_ref,
      requirement_ref: "human-spot-check",
      tier: "recomputed",
      grade: "self-attested",
      sufficiency: "SATISFIED",
      verdict: "not_met",
      evidence: [{ digest_alg: "SHA-256", digest: "cal-2026-W39" }],
      proofs: [],
      presentation: {
        kind: "disclosure",
        status: "SATISFIED",
        evidence: [{ digest_alg: "SHA-256", digest: "cal-2026-W39" }],
      },
    };
    const allClaims = [...claims, calClaim];
    (source.disclosures as Obj).result = {
      agent_input: {
        ...resultDoc,
        claims: allClaims,
        aggregate: {
          ...(resultDoc.aggregate as Obj),
          buckets: rebuildBuckets(allClaims),
        },
      },
    };
    (source.disclosures as Obj)["cal-2026-W39"] = {
      agent_input: {
        spec_version: "calibration-summary/v1",
        week: "2026-W39",
        sample: [
          {
            conversation_id: conversationId,
            ai_verdict: "met",
            human_verdict: "not_met",
          },
          { conversation_id: "x", ai_verdict: "not_met", human_verdict: "met" },
          { conversation_id: "y", ai_verdict: "met", human_verdict: "met" },
        ],
      },
    };
  });
  const root = await render(bundle);
  const list = root.querySelector<HTMLElement>("[data-weeks]")!;
  expect(list.dataset.weeks).toBe("1");
  const week = list.querySelector<HTMLElement>('[data-week="2026-W39"]')!;
  expect(week.dataset.k).toBe("1");
  expect(week.dataset.n).toBe("3");
  expect(week.querySelector<HTMLElement>("[data-held]")!.dataset.held).toBe(
    "1",
  );
  expect(week.querySelector<HTMLElement>("[data-added]")!.dataset.added).toBe(
    "1",
  );
});

// ---------------------------------------------------------------------------
// why conversations missed
// ---------------------------------------------------------------------------

it("renders per-check pass counts and missed-reason groups, grouped by criterion when no reason_code is cited", async () => {
  const { bundle } = await sealedOutcomeReportBundle();
  const root = await render(bundle);
  const bars = root.querySelector<HTMLElement>("[data-check-bars]")!;
  expect(
    bars.querySelector<HTMLElement>('[data-check-id="policy_compliance"]')!
      .dataset.passCount,
  ).toBe("4");
  expect(
    bars.querySelector<HTMLElement>('[data-check-id="task_resolution"]')!
      .dataset.passCount,
  ).toBe("2");
  expect(
    bars.querySelector<HTMLElement>('[data-check-id="grounded_communication"]')!
      .dataset.passCount,
  ).toBe("2");

  const reasons = root.querySelector<HTMLElement>("[data-reasons]")!;
  const fallback = reasons.querySelector<HTMLElement>(
    '[data-reason-key="policy_compliance.confirmed_before_acting"]',
  )!;
  expect(fallback.dataset.reasonStructured).toBe("false");
  expect(fallback.dataset.count).toBe("17");
  // the fallback label is the criterion id made readable, never parsed from
  // the judge's free-text rationale, and never a raw snake_case id
  expect(fallback.textContent).toContain("Confirmed before acting");
  expect(fallback.textContent).toContain("(Policy compliance)");
  const total = Array.from(
    reasons.querySelectorAll("[data-reason-key]"),
  ).reduce((sum, el) => sum + Number((el as HTMLElement).dataset.count), 0);
  expect(total).toBe(50);
});

it("never shows a raw reason_code: with no sealed label, the miss is named by its failing criterion", async () => {
  const source = fixture("outcome-report-bundle.json");
  const resultDoc = ((source.disclosures as Obj).result as Obj)
    .agent_input as Obj;
  const claims = resultDoc.claims as Obj[];
  const notMet = claims.find((c) => c.verdict === "not_met")!;
  const digest = (notMet.evidence as Obj[])[0]!.digest as string;
  (source.disclosures as Obj)[digest] = {
    agent_input: {
      ...(((source.disclosures as Obj)[digest] as Obj).agent_input as Obj),
      reason_code: "acted_without_confirmation",
    },
  };
  const { bundle } = await sealEvidenceBundle(source);
  const root = await render(bundle);
  const reasons = root.querySelector<HTMLElement>("[data-reasons]")!;
  expect(
    reasons.querySelector('[data-reason-key="acted_without_confirmation"]'),
  ).toBeNull();
  expect(reasons.querySelector('[data-reason-structured="true"]')).toBeNull();
  expect(reasons.textContent).not.toContain("acted_without_confirmation");
});

// ---------------------------------------------------------------------------
// the terms
// ---------------------------------------------------------------------------

it("renders the terms from the bundle: unstated terms marked, the resolution rule, 3 checks x 3 criteria, tier read from the claims", async () => {
  const { bundle } = await sealedOutcomeReportBundle();
  const root = await render(bundle);
  const terms = root.querySelector<HTMLElement>('[data-section="terms"]')!;
  expect(terms.textContent).toContain("what counts as resolved");
  expect(terms.textContent).toContain(
    "Agreed with the counterparty: not stated. Locked: not stated.",
  );
  expect(terms.textContent).not.toContain("airline policy");
  expect(terms.textContent).toContain(
    "A conversation resolves only when every criterion judged for it is met or does not apply, and at least one is met.",
  );
  expect(terms.querySelectorAll("[data-check-id]")).toHaveLength(3);
  expect(terms.querySelectorAll("[data-criterion-id]")).toHaveLength(9);
  // every one of rubric v3.2's nine clauses is tier:judged in the real
  // compiled contract this fixture's claims came from -- read from the
  // claims, not from a hard-coded "deterministic" flag in terms data
  const judged = terms.querySelector<HTMLElement>(
    '[data-criterion-id="prices_from_system"]',
  )!;
  expect(judged.dataset.tier).toBe("judged");
  expect(judged.textContent).toContain("(judged)");
  const alsoJudged = terms.querySelector<HTMLElement>(
    '[data-criterion-id="confirmed_before_acting"]',
  )!;
  expect(alsoJudged.dataset.tier).toBe("judged");
});

it("lists only the criteria the claims name: one no claim cites is not drawn as a term", async () => {
  const source = fixture("outcome-report-bundle.json");
  const resultDoc = ((source.disclosures as Obj).result as Obj)
    .agent_input as Obj;
  const kept = (resultDoc.claims as Obj[]).filter(
    (c) =>
      (c.requirement_ref as string) !==
      "grounded_communication.no_invented_policy",
  );
  (source.disclosures as Obj).result = {
    agent_input: {
      ...resultDoc,
      claims: kept,
      aggregate: {
        ...(resultDoc.aggregate as Obj),
        buckets: rebuildBuckets(kept),
      },
    },
  };
  const { bundle } = await sealEvidenceBundle(source);
  const root = await render(bundle);
  const terms = root.querySelector<HTMLElement>('[data-section="terms"]')!;
  expect(
    terms.querySelector('[data-criterion-id="no_invented_policy"]'),
  ).toBeNull();
  expect(terms.querySelectorAll("[data-criterion-id]")).toHaveLength(8);
});

// ---------------------------------------------------------------------------
// what ran
// ---------------------------------------------------------------------------

it("renders what ran: contract and judge pin digest from the cited reports, pinned when every one agrees", async () => {
  const { bundle } = await sealedOutcomeReportBundle();
  const root = await render(bundle);
  const section = root.querySelector<HTMLElement>('[data-section="what-ran"]')!;
  expect(section.textContent).toContain("tau2-airline-outcomes/v1");
  expect(section.textContent).toContain(
    "d1eb15a561a0eb31fb4bb6be88ce239aa903a77e79985291429065e83c305b96",
  );
  expect(section.textContent).toContain("not stated");
  const ran = section.querySelector<HTMLElement>(".ran")!;
  expect(ran.dataset.pinned).toBe("true");
  expect(section.querySelector("[data-pin-mismatch]")).toBeNull();
});

it("flags what-ran as not pinned, and omits the value, when the cited reports disagree on judge pin digest", async () => {
  const { bundle } = await sealedOutcomeReportBundle((source) => {
    const resultDoc = ((source.disclosures as Obj).result as Obj)
      .agent_input as Obj;
    const claims = resultDoc.claims as Obj[];
    const firstDigest = (claims[0]!.evidence as Obj[])[0]!.digest as string;
    (source.disclosures as Obj)[firstDigest] = {
      agent_input: {
        ...(((source.disclosures as Obj)[firstDigest] as Obj)
          .agent_input as Obj),
        judge_pin_digest: "a-different-pin",
      },
    };
  });
  const root = await render(bundle);
  const section = root.querySelector<HTMLElement>('[data-section="what-ran"]')!;
  expect(section.querySelector<HTMLElement>(".ran")!.dataset.pinned).toBe(
    "false",
  );
  expect(section.querySelector("[data-pin-mismatch]")).not.toBeNull();
  expect(section.textContent).not.toContain("a-different-pin");
});

it("renders the judge model and prompt/axes digests only when they recompute to the sealed judge pin digest", async () => {
  const components = {
    model_id: "jev-1.13.0",
    prompt_digest: "aa".repeat(32),
    axes_digest: "bb".repeat(32),
    sampling_params: { temperature: 0 },
  };
  const good = await jsonDigest({ ...components, model_version: null });
  const withPin = (digest: string) =>
    sealedOutcomeReportBundle((source) => {
      for (const [key, entry] of Object.entries(source.disclosures as Obj)) {
        if (key === "result") continue;
        const report = (entry as Obj).agent_input as Obj;
        report.judge_pin = components;
        report.judge_pin_digest = digest;
      }
    });

  const shown = await render((await withPin(good)).bundle);
  const section = shown.querySelector<HTMLElement>(
    '[data-section="what-ran"]',
  )!;
  const value = (key: string): string =>
    section.querySelector<HTMLElement>(`[data-ran="${key}"] .v`)!.textContent!;
  expect(
    section.querySelector<HTMLElement>(".ran")!.dataset.pinRecomputes,
  ).toBe("true");
  expect(value("judge-model")).toBe("jev-1.13.0");
  expect(value("judge-prompt-digest")).toBe("aa".repeat(32));
  expect(value("judge-axes-digest")).toBe("bb".repeat(32));
  expect(value("judge-pin-digest")).toContain(good);
  expect(value("judge-pin-digest")).toContain("recomputed");

  const bad = await render((await withPin("cd".repeat(32))).bundle);
  const badSection = bad.querySelector<HTMLElement>(
    '[data-section="what-ran"]',
  )!;
  expect(
    badSection.querySelector<HTMLElement>(".ran")!.dataset.pinRecomputes,
  ).toBe("false");
  expect(badSection.textContent).not.toContain("jev-1.13.0");
  expect(badSection.textContent).not.toContain("aa".repeat(32));
  expect(
    badSection.querySelector("[data-pin-components-mismatch]"),
  ).not.toBeNull();
});

// ---------------------------------------------------------------------------
// icons: inline SVG, never emoji (emoji render as tofu boxes in headless
// Chromium with no colour-emoji font)
// ---------------------------------------------------------------------------

it("draws every icon as inline SVG and puts no emoji or pictographic glyph anywhere on the page", async () => {
  const { bundle } = await sealedOutcomeReportBundle();
  const root = await render(bundle);
  const page = root.querySelector<HTMLElement>('[data-page="outcome-report"]')!;
  const icons = Array.from(page.querySelectorAll<SVGElement>("svg[data-icon]"));
  // one target for the outcome, then one generic check mark per check: no
  // sealed record says which picture fits a check, so none is chosen
  expect(icons.map((svg) => svg.dataset.icon)).toEqual([
    "target",
    "check",
    "check",
    "check",
  ]);
  for (const svg of icons) expect(svg.querySelector("path")).not.toBeNull();
  expect(root.textContent).not.toMatch(/\p{Extended_Pictographic}/u);
  expect(root.textContent).not.toMatch(/[\u25C6\u25E6]/u);
  const style = page.querySelector("style")!.textContent!;
  expect(style).not.toMatch(/\p{Extended_Pictographic}/u);
  expect(style).not.toMatch(/[\u25C6\u25E6]/u);
});

// ---------------------------------------------------------------------------
// verification details
// ---------------------------------------------------------------------------

it("renders verification details: bundle digest, checkpoint root/size, and names its own checkpoint kind (not RFC 6962)", async () => {
  const { bundle } = await sealedOutcomeReportBundle();
  const root = await render(bundle);
  const section = root.querySelector<HTMLElement>(
    '[data-section="verification-details"]',
  )!;
  const checkpoint = bundle.checkpoint as { root: string; mmr_size: number };
  expect(section.textContent).toContain(checkpoint.root);
  expect(section.textContent).toContain(String(checkpoint.mmr_size));
  const note = section.querySelector<HTMLElement>("[data-checkpoint-kind]")!;
  expect(note.dataset.checkpointKind).toBe("mmr");
  expect(note.textContent).toContain("Merkle Mountain Range");
  // this engine's own checkpoint, explicitly distinguished from the design's
  // RFC 6962 month-root -- never claimed as the same proof
  expect(note.textContent).toContain("not a month-level RFC 6962 tree");
});

it("draws the verification banner and the verification page in the card's look -- banner first, verification page still last", async () => {
  const { bundle } = await sealedOutcomeReportBundle();
  const root = await render(bundle);
  const banner = root.querySelector<HTMLElement>('[data-verify="verified"]')!;
  expect(banner.classList.contains("oi-banner")).toBe(true);
  // an unsigned checkpoint and unsigned records: INCOMPLETE, drawn as such
  expect(banner.dataset.verdict).toBe("incomplete");
  expect(banner.classList.contains("oi-banner-incomplete")).toBe(true);
  const card = root.querySelector('[data-page="outcome-report"]')!;
  expect(
    banner.compareDocumentPosition(card) & Node.DOCUMENT_POSITION_FOLLOWING,
  ).toBeTruthy();
  const verification = root.querySelector<HTMLElement>(
    '[data-page="verification"]',
  )!;
  expect(root.lastElementChild).toBe(verification);
  expect(verification.classList.contains("oi")).toBe(true);
  expect(verification.classList.contains("oi-vp")).toBe(true);
  const panel = verification.querySelector<HTMLElement>(":scope > .sec")!;
  expect(panel).not.toBeNull();
  expect(panel.querySelector("h2")!.textContent).toBe("Verification");
  expect(panel.querySelectorAll("ol > li")).toHaveLength(10);
  // the card's stylesheet carries the rules the classes name
  const style = root.querySelector(
    '[data-page="outcome-report"] style',
  )!.textContent!;
  expect(style).toContain(".oi.oi-vp");
  expect(style).toContain(".oi.oi-banner-ok");
});

it("leaves the banner and verification page unstyled for every other root family", async () => {
  const { bundle } = await sealedOutcomeReportBundle((source) => {
    ((source.extensions as Obj)["outcome-report/v1"] as Obj).enabled = false;
  });
  const root = await render(bundle);
  expect(root.querySelector<HTMLElement>("[data-verify]")!.className).toBe("");
  const verification = root.querySelector<HTMLElement>(
    '[data-page="verification"]',
  )!;
  expect(verification.className).toBe("");
  expect(verification.querySelector(":scope > .sec")).toBeNull();
});

// ---------------------------------------------------------------------------
// (c) verify-first gate / tamper demo: tampering hides the whole card
// ---------------------------------------------------------------------------

it("tamper demo: a tampered claim fails verification -- no outcome-report page, no report lines, nothing from the card reaches the DOM", async () => {
  const { bundle } = await sealedOutcomeReportBundle();
  const disclosures = bundle.disclosures as Record<string, Obj>;
  const resultId = Object.keys(disclosures).find(
    (id) =>
      (disclosures[id]!.agent_input as Obj)?.result_version ===
      "evidence-result-v0",
  )!;
  const tampered = structuredClone(disclosures[resultId]!.agent_input) as Obj;
  const claims = tampered.claims as Obj[];
  const flipped = claims.find(
    (claim) => claim.verdict === "not_met" && claim.type === undefined,
  )!;
  flipped.verdict = "met";
  const buckets = (tampered.aggregate as Obj).buckets as Obj;
  buckets.not_met = (buckets.not_met as string[]).filter(
    (id) => id !== flipped.id,
  );
  buckets.met = [...(buckets.met as string[]), flipped.id as string];

  const root = await render({
    ...bundle,
    disclosures: { ...disclosures, [resultId]: { agent_input: tampered } },
  });
  expect(root.querySelector('[data-verify="failed"]')).not.toBeNull();
  expect(
    root.querySelector('[data-refusal="unverified-bundle"]'),
  ).not.toBeNull();
  expect(root.querySelector('[data-page="outcome-report"]')).toBeNull();
  expect(root.querySelector('[data-rows="report-lines"]')).toBeNull();
  expect(root.querySelectorAll("[data-day]")).toHaveLength(0);
  expect(root.textContent).not.toContain("Outcome statement");
  expect(root.lastElementChild).toBe(
    root.querySelector('[data-page="verification"]'),
  );
});

it("tamper demo: tampering the checkpoint itself also hides the card, same as any other bundle", async () => {
  const { bundle } = await sealedOutcomeReportBundle();
  const checkpoint = bundle.checkpoint as { mmr_size: number };
  const root = await render({
    ...bundle,
    checkpoint: { ...checkpoint, mmr_size: checkpoint.mmr_size + 1 },
  });
  expect(root.querySelector('[data-verify="failed"]')).not.toBeNull();
  expect(root.querySelector('[data-page="outcome-report"]')).toBeNull();
});

// ---------------------------------------------------------------------------
// this card never changes the generic Result-page/report/v1/evaluation-summary
// goldens: the emitter's other tests already pin those; this is a belt-and-
// braces check that a non-outcome-report bundle is completely unaffected.
// ---------------------------------------------------------------------------

it("still renders report/v1 and evaluation-summary/v1 root families exactly as before", async () => {
  const week = await render(fixture("week-bundle.json"));
  expect(week.querySelectorAll("[data-report-date]").length).toBeGreaterThan(0);
  expect(week.querySelector('[data-page="outcome-report"]')).toBeNull();

  const { bundle } = await sealEvidenceBundle(
    fixture("report-rows-bundle.json"),
  );
  const rows = await render(bundle);
  expect(rows.querySelector('[data-page="report-rows"]')).not.toBeNull();
  expect(rows.querySelector('[data-page="outcome-report"]')).toBeNull();
});

// ---------------------------------------------------------------------------
// drill-down: every line and every missed-reason row opens into the
// conversations behind it; each conversation opens into its nine criteria,
// the rationale exactly as sealed, why, and the ids to recompute it
// ---------------------------------------------------------------------------

/** Open a conversation the way a reader does: its body is built on first open. */
function open(conv: HTMLElement): HTMLElement {
  (conv as HTMLDetailsElement).open = true;
  conv.dispatchEvent(new Event("toggle"));
  return conv;
}

/** The fixture's sealed report payloads, keyed by the claim id that cites them. */
function reportsByClaim(source: Obj): Map<string, Obj> {
  const resultDoc = ((source.disclosures as Obj).result as Obj)
    .agent_input as Obj;
  const out = new Map<string, Obj>();
  for (const claim of resultDoc.claims as Obj[]) {
    const digest = (claim.evidence as Obj[])[0]!.digest as string;
    const disclosed = (source.disclosures as Obj)[digest] as Obj | undefined;
    if (disclosed !== undefined)
      out.set(claim.id as string, disclosed.agent_input as Obj);
  }
  return out;
}

it("drill-down: the missed line opens into every missed conversation, each with nine criteria, verdicts and the judge's P", async () => {
  const source = fixture("outcome-report-bundle.json");
  const reports = reportsByClaim(source);
  const { bundle } = await sealEvidenceBundle(source);
  const root = await render(bundle);
  const line = root.querySelector<HTMLElement>('[data-line="missed"]')!;
  const drill = line.querySelector<HTMLElement>(
    'details[data-drill="missed"]',
  )!;
  expect(drill).not.toBeNull();
  expect(drill.querySelector("summary")!.textContent).toContain(
    "open › 50 conversations",
  );
  const convs = drill.querySelectorAll<HTMLElement>("details.conv");
  expect(convs).toHaveLength(50);
  // the resolved line has nothing behind it in this fixture: no empty drill
  expect(
    root.querySelector('[data-line="resolved"] details[data-drill]'),
  ).toBeNull();

  // closed, a conversation carries only its summary row
  expect(convs[0]!.querySelector("tr[data-crit]")).toBeNull();
  const conv = open(convs[0]!);
  const id = conv.dataset.conversation!;
  expect(conv.querySelector("summary")!.textContent).toContain("missed");
  const rows = conv.querySelectorAll<HTMLElement>("tr[data-crit]");
  expect(rows).toHaveLength(9);
  for (const row of rows) {
    const claimId = `${id}::${row.dataset.crit}`;
    const report = reports.get(claimId)!;
    expect(report).toBeDefined();
    // the rationale is drawn exactly as sealed, never rewritten
    expect(
      row.querySelector<HTMLElement>('[data-rationale="sealed"]')!.textContent,
    ).toBe(report.rationale);
    // P is read back from the sealed rationale's probabilities for the verdict returned
    const probs = /'([a-z_]+)': ([0-9.]+)/gu;
    const table = new Map<string, number>();
    for (const m of (report.rationale as string).matchAll(probs))
      table.set(m[1]!, Number(m[2]));
    expect(row.querySelector<HTMLElement>("[data-p]")!.dataset.p).toBe(
      table.get(report.verdict as string)!.toFixed(2),
    );
    expect(row.dataset.critVerdict).toBe(report.verdict);
  }
  expect(
    conv.querySelector<HTMLElement>('[data-rationale-label="derived"]')!
      .textContent,
  ).toBe(
    "Rationale: derived from the judge's probabilities; the judge returns no free-text reasoning.",
  );
});

it("drill-down: says plainly the transcript is absent, and gives the record ids and judge pin to recompute", async () => {
  const source = fixture("outcome-report-bundle.json");
  const reports = reportsByClaim(source);
  const { bundle, ids } = await sealEvidenceBundle(source);
  const root = await render(bundle);
  const conv = open(
    root.querySelector<HTMLElement>('[data-drill="missed"] details.conv')!,
  );
  const id = conv.dataset.conversation!;
  const anyReport = [...reports.entries()].find(([claimId]) =>
    claimId.startsWith(`${id}::`),
  )![1];
  const absent = conv.querySelector<HTMLElement>('[data-transcript="absent"]')!;
  expect(absent.textContent).toContain("Not in this bundle");
  expect(absent.textContent).toContain(anyReport.source_capsule_id as string);
  const check = conv.querySelector<HTMLElement>("[data-check-it]")!;
  expect(check.textContent).toContain(ids["result"]);
  expect(check.textContent).toContain(anyReport.source_capsule_id as string);
  expect(check.textContent).toContain(
    "d1eb15a561a0eb31fb4bb6be88ce239aa903a77e79985291429065e83c305b96",
  );
  expect(check.querySelectorAll("dt")).toHaveLength(4 + 9);
  const why = conv.querySelector<HTMLElement>('[data-why="missed"]')!;
  expect(why.textContent).toContain("Turns cited: none");
  expect(why.querySelectorAll("[data-why-criterion]").length).toBeGreaterThan(
    0,
  );
  // still a static page: no button, no script
  expect(root.querySelectorAll("button, script")).toHaveLength(0);
});

it("drill-down: a not_applicable criterion is its own state -- no claim, no P, never drawn as met or missed", async () => {
  const source = fixture("outcome-report-bundle.json");
  const resultDoc = ((source.disclosures as Obj).result as Obj)
    .agent_input as Obj;
  // drop this criterion's claim in ONE conversation: the other 49 still name
  // it, so it is a term, and in that conversation it reads not_applicable
  const all = resultDoc.claims as Obj[];
  const dropped = all.find(
    (c) =>
      (c.requirement_ref as string) ===
      "grounded_communication.refunds_match_payment_records",
  )!;
  const kept = all.filter((c) => c !== dropped);
  (source.disclosures as Obj).result = {
    agent_input: {
      ...resultDoc,
      claims: kept,
      aggregate: {
        ...(resultDoc.aggregate as Obj),
        buckets: rebuildBuckets(kept),
      },
    },
  };
  const { bundle } = await sealEvidenceBundle(source);
  const root = await render(bundle);
  const naLine = root.querySelector<HTMLElement>(
    '[data-line="not-applicable"] details[data-drill="not-applicable"]',
  )!;
  expect(naLine.querySelectorAll("details.conv")).toHaveLength(1);
  open(naLine.querySelector<HTMLElement>("details.conv")!);
  const row = naLine.querySelector<HTMLElement>(
    'tr[data-crit="grounded_communication.refunds_match_payment_records"]',
  )!;
  expect(row.dataset.critVerdict).toBe("not_applicable");
  expect(
    row.querySelector<HTMLElement>('[data-pill="not_applicable"]')!.textContent,
  ).toBe("not applicable");
  expect(row.querySelector("[data-p]")).toBeNull();
  expect(row.textContent).toContain("No claim");
});

it("drill-down: every missed-reason row opens into exactly the conversations it counts, and a resolved conversation says why it billed", async () => {
  const source = fixture("outcome-report-bundle.json");
  const resultDoc = ((source.disclosures as Obj).result as Obj)
    .agent_input as Obj;
  const claims = resultDoc.claims as Obj[];
  const first = (claims[0]!.id as string).split("::")[0]!;
  const flipped = claims.map((c) =>
    (c.id as string).startsWith(`${first}::`)
      ? {
          ...c,
          verdict: "met",
          sufficiency: "SATISFIED",
          presentation: { ...(c.presentation as Obj), status: "SATISFIED" },
        }
      : c,
  );
  (source.disclosures as Obj).result = {
    agent_input: {
      ...resultDoc,
      claims: flipped,
      aggregate: {
        ...(resultDoc.aggregate as Obj),
        buckets: rebuildBuckets(flipped),
      },
    },
  };
  const { bundle } = await sealEvidenceBundle(source);
  const root = await render(bundle);
  for (const reason of root.querySelectorAll<HTMLElement>(
    "[data-reasons] [data-reason-key]",
  )) {
    expect(reason.tagName).toBe("DETAILS");
    expect(reason.querySelector("summary")!.textContent).toContain(
      "see them ›",
    );
    expect(reason.querySelectorAll("details.conv")).toHaveLength(
      Number(reason.dataset.count),
    );
  }
  const resolved = root.querySelector<HTMLElement>('[data-drill="resolved"]')!;
  const convs = resolved.querySelectorAll<HTMLElement>("details.conv");
  expect(convs).toHaveLength(1);
  expect(convs[0]!.dataset.conversation).toBe(first);
  open(convs[0]!);
  expect(
    convs[0]!.querySelector('[data-why="resolved"]')!.textContent,
  ).toContain("Resolved: 9 criteria met");
});

it("drill-down: a tampered bundle draws no conversation at all (verify-first holds)", async () => {
  const { bundle } = await sealedOutcomeReportBundle();
  const disclosures = bundle.disclosures as Record<string, Obj>;
  const resultId = Object.keys(disclosures).find(
    (id) =>
      (disclosures[id]!.agent_input as Obj)?.result_version ===
      "evidence-result-v0",
  )!;
  const tampered = structuredClone(disclosures[resultId]!.agent_input) as Obj;
  const claim = (tampered.claims as Obj[]).find(
    (c) => c.verdict === "not_met",
  )!;
  claim.verdict = "met";
  const buckets = (tampered.aggregate as Obj).buckets as Obj;
  buckets.not_met = (buckets.not_met as string[]).filter(
    (id) => id !== claim.id,
  );
  buckets.met = [...(buckets.met as string[]), claim.id as string];
  const root = await render({
    ...bundle,
    disclosures: { ...disclosures, [resultId]: { agent_input: tampered } },
  });
  expect(root.querySelector('[data-verify="failed"]')).not.toBeNull();
  expect(root.querySelectorAll("details.conv")).toHaveLength(0);
});

it("reads the pack version from the claims' contract_ref, so the header and terms panel show the version judged under", async () => {
  const source = fixture("outcome-report-bundle.json");
  const resultDoc = ((source.disclosures as Obj).result as Obj)
    .agent_input as Obj;
  const claims = (resultDoc.claims as Obj[]).map((c) => ({
    ...c,
    contract_ref: "airline-support-outcomes@1.4.0",
  }));
  (source.disclosures as Obj).result = {
    agent_input: { ...resultDoc, claims },
  };
  const { bundle } = await sealEvidenceBundle(source);
  const root = await render(bundle);
  const meta = root.querySelector<HTMLElement>('[data-section="meta"]')!;
  expect(meta.textContent).toContain("airline-support-outcomes v1.4.0");
  expect(meta.textContent).not.toContain("v1.3.0");
  const terms = root.querySelector<HTMLElement>('[data-section="terms"]')!;
  expect(terms.textContent).toContain("1.4.0 (from the claims' contract_ref)");
  expect(terms.textContent).not.toContain("1.3.0");
});

// ---------------------------------------------------------------------------
// criterion wording: from the sealed reports' clause_claim (the text the judge
// was given), never from the card's own table when the evidence states it
// ---------------------------------------------------------------------------

const NEW_FARE_WORDING =
  "No change or cancellation the fare rules forbid. For a cancellation, do the date math yourself.";
const TABLE_FARE_WORDING =
  "No change the fare class forbids (e.g. basic economy flight changes, over-limit certificates).";

/** Give every sealed report a clause_claim; `wording` decides the text per report. */
function withClauseClaims(
  source: Obj,
  wording: (clauseId: string, index: number) => string | undefined,
): void {
  let index = 0;
  for (const disclosed of Object.values(source.disclosures as Obj)) {
    const report = (disclosed as Obj).agent_input as Obj | undefined;
    if (report === undefined || typeof report.clause_id !== "string") continue;
    const text = wording(report.clause_id, index++);
    if (text !== undefined) report.clause_claim = text;
  }
}

function fareRow(root: HTMLElement): HTMLElement {
  const conv = open(
    root.querySelector<HTMLElement>('[data-drill="missed"] details.conv')!,
  );
  return conv.querySelector<HTMLElement>(
    'tr[data-crit="policy_compliance.within_fare_rules"]',
  )!;
}

it("producer note and edited badges: rendered from outcome-report/v1 as presentation text, labelled not evidence, absent otherwise", async () => {
  const { bundle } = await sealedOutcomeReportBundle((source) => {
    const block = (source.extensions as Obj)["outcome-report/v1"] as Obj;
    block.producer_note = {
      title: "What changed in this run",
      lines: ["Line one <b>not markup</b>.", "Line two."],
    };
    block.edited_criteria = [
      {
        criterion: "policy_compliance.within_fare_rules",
        badge: "edited in v1.5.0",
      },
      { criterion: "not a ref", badge: "dropped" },
    ];
  });
  const root = await render(bundle);
  expect(root.querySelector('[data-verify="verified"]')).not.toBeNull();
  const page = root.querySelector<HTMLElement>('[data-page="outcome-report"]')!;
  const note = page.querySelector<HTMLElement>("[data-producer-note]")!;
  // first thing after the card's own <style>: directly under the banner
  expect(page.children[1]).toBe(note);
  expect(note.textContent).toContain("not evidence");
  expect(note.querySelector("h2")!.textContent).toBe(
    "What changed in this run",
  );
  const lines = [...note.querySelectorAll("li")].map((li) => li.textContent);
  expect(lines).toEqual(["Line one <b>not markup</b>.", "Line two."]);
  expect(note.querySelector("b")).toBeNull();
  const terms = root.querySelector<HTMLElement>('[data-section="terms"]')!;
  const badges = terms.querySelectorAll<HTMLElement>("span.edited");
  expect(badges).toHaveLength(1);
  expect(badges[0]!.textContent).toBe("edited in v1.5.0");
  expect(badges[0]!.closest<HTMLElement>("li")!.dataset.criterionId).toBe(
    "within_fare_rules",
  );
  const row = fareRow(root);
  expect(row.querySelector("span.edited")!.textContent).toBe(
    "edited in v1.5.0",
  );
  const table = row.closest("table")!;
  expect(table.querySelectorAll("span.edited")).toHaveLength(1);
  const { bundle: plain } = await sealedOutcomeReportBundle();
  const plainRoot = await render(plain);
  expect(plainRoot.querySelector("[data-producer-note]")).toBeNull();
  expect(plainRoot.querySelector("span.edited")).toBeNull();
});
it("producer note: a note with any non-text line is dropped whole, never half-shown", async () => {
  const { bundle } = await sealedOutcomeReportBundle((source) => {
    const block = (source.extensions as Obj)["outcome-report/v1"] as Obj;
    block.producer_note = { title: "T", lines: ["ok", 42] };
  });
  const root = await render(bundle);
  expect(root.querySelector('[data-page="outcome-report"]')).not.toBeNull();
  expect(root.querySelector("[data-producer-note]")).toBeNull();
});
it("wording: each criterion prints the clause_claim its sealed reports carry, not the card's terms table", async () => {
  const { bundle } = await sealedOutcomeReportBundle((source) =>
    withClauseClaims(source, (clauseId) =>
      clauseId === "policy_compliance.within_fare_rules"
        ? NEW_FARE_WORDING
        : `Sealed wording for ${clauseId}.`,
    ),
  );
  const root = await render(bundle);
  expect(root.querySelector('[data-verify="verified"]')).not.toBeNull();
  const terms = root.querySelector<HTMLElement>('[data-section="terms"]')!;
  const item = terms.querySelector<HTMLElement>(
    'li[data-criterion-id="within_fare_rules"]',
  )!;
  expect(item.dataset.wording).toBe("sealed");
  expect(item.textContent).toContain(NEW_FARE_WORDING);
  expect(item.textContent).not.toContain(TABLE_FARE_WORDING);
  expect(terms.querySelectorAll('li[data-wording="sealed"]')).toHaveLength(9);
  expect(terms.querySelector(".wsrc")).toBeNull();
  expect(
    terms.querySelector<HTMLElement>("[data-wording-note]")!.textContent,
  ).toBe(
    "Rule wording as sealed in the judge's reports (the text the judge was given).",
  );
  const row = fareRow(root);
  const cell = row.querySelector<HTMLElement>("small[data-wording]")!;
  expect(cell.dataset.wording).toBe("sealed");
  expect(cell.textContent).toBe(NEW_FARE_WORDING);
  expect(row.querySelector(".wsrc")).toBeNull();
});

it("wording: a report whose clause_id names another criterion never supplies this criterion's wording", async () => {
  const { bundle } = await sealedOutcomeReportBundle((source) => {
    withClauseClaims(source, () => undefined);
    for (const disclosed of Object.values(source.disclosures as Obj)) {
      const report = (disclosed as Obj).agent_input as Obj | undefined;
      if (report?.clause_id === "policy_compliance.within_fare_rules") {
        report.clause_claim = NEW_FARE_WORDING;
        report.clause_id = "policy_compliance.no_unrequested_actions";
      }
    }
  });
  const root = await render(bundle);
  const item = root.querySelector<HTMLElement>(
    '[data-section="terms"] li[data-criterion-id="within_fare_rules"]',
  )!;
  expect(item.dataset.wording).toBe("unstated");
  expect(item.textContent).not.toContain(NEW_FARE_WORDING);
});

it("wording: a bundle whose reports state none says so -- no wording is supplied from anywhere else", async () => {
  const { bundle } = await sealedOutcomeReportBundle();
  const root = await render(bundle);
  const terms = root.querySelector<HTMLElement>('[data-section="terms"]')!;
  const item = terms.querySelector<HTMLElement>(
    'li[data-criterion-id="within_fare_rules"]',
  )!;
  expect(item.dataset.wording).toBe("unstated");
  expect(item.textContent).toContain("not stated");
  expect(item.textContent).not.toContain(TABLE_FARE_WORDING);
  expect(item.querySelector(".wsrc")!.textContent).toBe(
    "Wording not stated: no report in this bundle states it.",
  );
  expect(
    terms.querySelector<HTMLElement>("[data-wording-note]")!.textContent,
  ).toContain("Rule wording not stated");
  const row = fareRow(root);
  expect(
    row.querySelector<HTMLElement>("small[data-wording]")!.dataset.wording,
  ).toBe("unstated");
  expect(row.querySelector(".wsrc")).not.toBeNull();
});

it("wording: reports that disagree on a criterion's wording are not resolved by picking one", async () => {
  const { bundle } = await sealedOutcomeReportBundle((source) =>
    withClauseClaims(source, (clauseId, index) =>
      clauseId === "policy_compliance.within_fare_rules"
        ? index % 2 === 0
          ? NEW_FARE_WORDING
          : "Some other wording."
        : `Sealed wording for ${clauseId}.`,
    ),
  );
  const root = await render(bundle);
  const terms = root.querySelector<HTMLElement>('[data-section="terms"]')!;
  const item = terms.querySelector<HTMLElement>(
    'li[data-criterion-id="within_fare_rules"]',
  )!;
  expect(item.dataset.wording).toBe("mixed");
  expect(item.textContent).not.toContain(TABLE_FARE_WORDING);
  expect(item.textContent).not.toContain(NEW_FARE_WORDING);
  expect(item.querySelector(".wsrc")!.textContent).toContain(
    "state different wordings",
  );
  // the other eight still come from the evidence
  expect(terms.querySelectorAll('li[data-wording="sealed"]')).toHaveLength(8);
  expect(
    terms.querySelector<HTMLElement>("[data-wording-note]")!.textContent,
  ).toContain("where the reports do not state it");
});

// ---------------------------------------------------------------------------
// Dating: the calendar and period count each
// conversation under its own record date -- the source's own timestamp for a
// backfilled record ("source says", AAC -05 provenance_mode), the case
// record's own timestamp otherwise -- not the day the judgments were sealed,
// and the page says so, with the sealed day alongside.
// ---------------------------------------------------------------------------

/** Cite a case record per conversation: each report names it as its
 * `source_capsule_id`, each claim cites it, and the root references it. */
function withCaseRecords(
  source: Obj,
  fields: (conversationId: string, index: number) => Obj,
): void {
  const result = ((source.disclosures as Obj).result as Obj).agent_input as Obj;
  const claims = result.claims as Obj[];
  const records = source.records as Obj[];
  const root = records.find((r) => r.capsule_id === "result")!;
  const references = root.references as Obj[];
  const seen = new Map<string, string>();
  for (const claim of claims) {
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
      references.push({
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
  timestamp: "2026-09-22T10:00:00Z",
  provenance_mode: {
    mode: "backfilled",
    source_ref: {
      type: "tau2-simulation",
      digest_alg: "SHA-256",
      digest: "0".repeat(64),
    },
    source_asserted_at: sourceAssertedAt,
    import_batch: "tau2-airline-trial0",
    imported_at: "2026-09-22T10:00:00Z",
  },
});

it("dating: backfilled case records put the calendar and period on the source's own date, labelled 'source says', with the sealed day alongside", async () => {
  const { bundle } = await sealedOutcomeReportBundle((source) =>
    withCaseRecords(source, () => BACKFILLED("2025-06-05T16:06:37.787845")),
  );
  const root = await render(bundle);
  expect(root.querySelector('[data-verify="verified"]')).not.toBeNull();
  const calendar = root.querySelector<HTMLElement>(
    '[data-section="calendar"]',
  )!;
  const tiles = calendar.querySelectorAll<HTMLElement>("[data-day]");
  expect([...tiles].map((t) => t.dataset.day)).toEqual(["2025-06-05"]);
  expect(tiles[0]!.dataset.total).toBe("50");
  expect(
    tiles[0]!.querySelector<HTMLElement>("[data-sealed]")!.textContent,
  ).toBe("sealed 2026-09-23");
  expect(
    tiles[0]!.querySelector<HTMLElement>("[data-source-says]")!.dataset
      .sourceSays,
  ).toBe("50");
  // the source wrote no zone: the page says so and assumes none
  expect(
    tiles[0]!.querySelector('[data-tz-marker="not-stated"]'),
  ).not.toBeNull();
  const note = calendar.querySelector<HTMLElement>("[data-date-note]")!;
  expect(note.dataset.dateNote).toBe("source");
  expect(note.textContent).toContain(
    'Dates are the source\'s own timestamps for backfilled records ("source says"), as given, not when the records were sealed. Sealed 2026-09-23.',
  );
  expect(note.textContent).toContain("Timezone not stated on 50 of 50");
  const meta = root.querySelector<HTMLElement>('[data-section="meta"]')!;
  expect(meta.textContent).toContain("2025-06-05 – 2025-06-05");
  expect(meta.querySelector<HTMLElement>("[data-sealed]")!.textContent).toBe(
    "Sealed2026-09-23",
  );
  expect(meta.querySelector("[data-date-note]")).not.toBeNull();
  // the drill-down says which date it used, verbatim, and the sealed day
  const conv = open(root.querySelector<HTMLElement>("details.conv")!);
  const dated = conv.querySelector<HTMLElement>("[data-dated]")!;
  expect(dated.dataset.dated).toBe("source");
  expect(dated.textContent).toBe(
    "2025-06-05T16:06:37.787845 (timezone not stated): source says (backfilled record; the source's own timestamp, self-attested)",
  );
  expect(conv.textContent).toContain("Imported2026-09-22T10:00:00Z");
  expect(conv.textContent).toContain("Judged and sealed2026-09-23");
});

it("dating: case records with no backfill are dated by their own timestamp, as given, one tile per record day", async () => {
  const { bundle } = await sealedOutcomeReportBundle((source) =>
    withCaseRecords(source, (_, index) => ({
      timestamp:
        index % 2 === 0 ? "2026-09-21T23:30:00Z" : "2026-09-22T00:30:00+02:00",
    })),
  );
  const root = await render(bundle);
  const calendar = root.querySelector<HTMLElement>(
    '[data-section="calendar"]',
  )!;
  const tiles = [...calendar.querySelectorAll<HTMLElement>("[data-day]")];
  // the day is the written date: +02:00 is NOT converted to 2026-09-21 UTC
  expect(tiles.map((t) => [t.dataset.day, t.dataset.total])).toEqual([
    ["2026-09-21", "25"],
    ["2026-09-22", "25"],
  ]);
  expect(calendar.querySelector("[data-source-says]")).toBeNull();
  expect(calendar.querySelector('[data-tz-marker="not-stated"]')).toBeNull();
  const note = calendar.querySelector<HTMLElement>("[data-date-note]")!;
  expect(note.dataset.dateNote).toBe("record");
  expect(note.textContent).toBe(
    "Dates are each conversation's own record date (the time its case record states), as given, not when the judgments were sealed. Sealed 2026-09-23.",
  );
  const meta = root.querySelector<HTMLElement>('[data-section="meta"]')!;
  expect(meta.textContent).toContain("2026-09-21 – 2026-09-22");
});

it("dating: with no case record cited, the calendar keeps the judged day and the page adds no dating label", async () => {
  const { bundle } = await sealedOutcomeReportBundle();
  const root = await render(bundle);
  const days = [...root.querySelectorAll<HTMLElement>("[data-day]")];
  expect(days.map((d) => d.dataset.day)).toEqual(["2026-09-23"]);
  expect(root.querySelector("[data-date-note]")).toBeNull();
  expect(root.querySelector("[data-sealed]")).toBeNull();
  const conv = open(root.querySelector<HTMLElement>("details.conv")!);
  expect(conv.querySelector("[data-check-it]")).not.toBeNull();
  expect(conv.querySelector("[data-dated]")).toBeNull();
  expect(conv.textContent).not.toContain("Judged and sealed");
});
