// @vitest-environment jsdom

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  createCardRegistry,
  defaultCardRegistry,
  frozenCopy,
  readCardDeclarations,
  renderEvidenceGraph,
  sealCardView,
  type CardDefinition,
  type CardRegistry,
  type PresentationBlock,
  type ResultRoot,
  type VerifiedBundle,
} from "../src/browser.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

type Obj = Record<string, unknown>;

function fixture(name: string): Obj {
  return JSON.parse(
    readFileSync(resolve(process.cwd(), "test", "testdata", name), "utf8"),
  ) as Obj;
}

async function sealedBundle(mutate?: (source: Obj) => void): Promise<Obj> {
  const source = fixture("compliance-bundle.json");
  mutate?.(source);
  return (await sealEvidenceBundle(source)).bundle;
}

function extensions(source: Obj): Obj {
  return source.extensions as Obj;
}

async function render(
  bundle: unknown,
  cards?: CardRegistry,
  attach = false,
): Promise<HTMLElement> {
  const root = document.createElement("main");
  if (attach) document.body.append(root);
  await renderEvidenceGraph(bundle, root, undefined, cards);
  return root;
}

afterEach(() => {
  document.body.replaceChildren();
});

interface Seen {
  calls: number;
  result?: ResultRoot;
  bundle?: VerifiedBundle;
  chrome?: PresentationBlock;
  settings?: unknown;
  block?: unknown;
}

/** A host-registered card that records what the shell handed it. */
function spyCard(
  seen: Seen,
  draw?: (
    view: HTMLElement,
    result: ResultRoot,
    bundle: VerifiedBundle,
  ) => void,
): CardDefinition<{ readonly month: string }> {
  return {
    label: "month view",
    readSettings(block) {
      seen.block = block;
      return typeof block.month === "string"
        ? { month: block.month }
        : undefined;
    },
    render(result, bundle, chrome, settings) {
      seen.calls += 1;
      seen.result = result;
      seen.bundle = bundle;
      seen.chrome = chrome;
      seen.settings = settings;
      const view = document.createElement("section");
      view.dataset.page = "month-view";
      const heading = document.createElement("h2");
      heading.textContent = `Month ${settings.month}: ${result.claims.length} claims`;
      view.append(heading);
      draw?.(view, result, bundle);
      return view;
    },
  };
}

function hostRegistry(seen: Seen, draw?: Parameters<typeof spyCard>[1]) {
  const registry = defaultCardRegistry();
  registry.registerCard("x-month-view/v1", spyCard(seen, draw));
  return registry;
}

function tamperedResult(bundle: Obj): Obj {
  const disclosures = bundle.disclosures as Record<string, Obj>;
  const resultId = Object.keys(disclosures).find(
    (id) =>
      (disclosures[id]!.agent_input as Obj)?.result_version ===
      "evidence-result-v0",
  )!;
  const tampered = structuredClone(disclosures[resultId]!.agent_input) as Obj;
  (tampered.claims as Obj[])[0]!.verdict = "not_evaluable";
  return {
    ...bundle,
    disclosures: { ...disclosures, [resultId]: { agent_input: tampered } },
  };
}

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

describe("registry", () => {
  const noop: CardDefinition<true> = {
    label: "noop",
    readSettings: () => true,
    render: () => document.createElement("div"),
  };

  it("the default registry registers the built-in cards in precedence order", () => {
    expect(defaultCardRegistry().kinds()).toEqual([
      "outcome-report/v1",
      "eu-ai-act-compliance/v1",
    ]);
  });

  it("each defaultCardRegistry() is a fresh registry: a host's card never leaks into another's", () => {
    const one = defaultCardRegistry();
    one.registerCard("x-a/v1", noop);
    expect(defaultCardRegistry().kinds()).not.toContain("x-a/v1");
  });

  it("rejects a malformed kind, a duplicate kind, and a non-card extension kind", () => {
    const registry = createCardRegistry();
    expect(() => registry.registerCard("Month View", noop)).toThrow();
    expect(() => registry.registerCard("month-view", noop)).toThrow();
    registry.registerCard("month-view/v1", noop);
    expect(() => registry.registerCard("month-view/v1", noop)).toThrow(
      /already registered/u,
    );
    for (const kind of ["presentation/v1", "producer-key/v1", "composed/v1"])
      expect(() => registry.registerCard(kind, noop)).toThrow(
        /not a card extension kind/u,
      );
  });

  it("a card declaration is an extension block with enabled: true, read in sorted order", () => {
    expect(
      readCardDeclarations({
        extensions: {
          "z-card/v1": { enabled: true },
          "a-card/v1": { enabled: true },
          "off-card/v1": { enabled: false },
          "producer-key/v1": { public_key: "00" },
          "presentation/v1": { enabled: true, title: "t" },
          "array/v1": [{ enabled: true }],
        },
      }),
    ).toEqual(["a-card/v1", "z-card/v1"]);
    expect(readCardDeclarations({})).toEqual([]);
    expect(readCardDeclarations(null)).toEqual([]);
  });
});

describe("resolveCard", () => {
  const card = (accept: boolean): CardDefinition<true> => ({
    label: "c",
    readSettings: () => (accept ? true : undefined),
    render: () => document.createElement("div"),
  });

  it("no card extension: no card, no notice", () => {
    const resolution = defaultCardRegistry().resolveCard({ extensions: {} });
    expect(resolution.card).toBeUndefined();
    expect(resolution.notices).toEqual([]);
  });

  it("an unknown kind: no card, a notice naming it", () => {
    const resolution = defaultCardRegistry().resolveCard({
      extensions: { "x-unknown/v3": { enabled: true } },
    });
    expect(resolution.card).toBeUndefined();
    expect(resolution.notices).toEqual([
      { reason: "unrecognized-kind", kind: "x-unknown/v3" },
    ]);
  });

  it("several declared kinds: the first REGISTERED wins, whatever the bundle's member order", () => {
    const registry = createCardRegistry();
    registry.registerCard("b-card/v1", card(true));
    registry.registerCard("a-card/v1", card(true));
    for (const extensionsBlock of [
      { "a-card/v1": { enabled: true }, "b-card/v1": { enabled: true } },
      { "b-card/v1": { enabled: true }, "a-card/v1": { enabled: true } },
    ]) {
      const resolution = registry.resolveCard({ extensions: extensionsBlock });
      expect(resolution.card?.kind).toBe("b-card/v1");
      expect(resolution.notices).toEqual([
        { reason: "not-selected", kind: "a-card/v1", selected: "b-card/v1" },
      ]);
    }
  });

  it("a known kind whose block its reader rejects: the next declared card, with a notice", () => {
    const registry = createCardRegistry();
    registry.registerCard("a-card/v1", card(false));
    registry.registerCard("b-card/v1", card(true));
    const resolution = registry.resolveCard({
      extensions: {
        "a-card/v1": { enabled: true },
        "b-card/v1": { enabled: true },
      },
    });
    expect(resolution.card?.kind).toBe("b-card/v1");
    expect(resolution.notices).toEqual([
      { reason: "unreadable-block", kind: "a-card/v1" },
    ]);
  });

  it("an overlong declared kind is capped in the notice", () => {
    const kind = `x-${"a".repeat(400)}/v1`;
    const resolution = createCardRegistry().resolveCard({
      extensions: { [kind]: { enabled: true } },
    });
    expect(resolution.notices[0]!.kind.length).toBeLessThanOrEqual(121);
  });
});

// ---------------------------------------------------------------------------
// Dispatch through the page shell
// ---------------------------------------------------------------------------

describe("dispatch", () => {
  it("adding a card is one registration: the bundle's declared card renders, not the generic Result page", async () => {
    const seen: Seen = { calls: 0 };
    const bundle = await sealedBundle((source) => {
      delete extensions(source)["eu-ai-act-compliance/v1"];
      extensions(source)["x-month-view/v1"] = {
        enabled: true,
        month: "2026-09",
      };
    });
    const root = await render(bundle, hostRegistry(seen));
    expect(seen.calls).toBe(1);
    const view = root.querySelector<HTMLElement>('[data-page="month-view"]')!;
    expect(view).not.toBeNull();
    expect(view.dataset.card).toBe("x-month-view/v1");
    expect(view.textContent).toContain("Month 2026-09");
    expect(root.querySelector('[data-page="result"]')).toBeNull();
    expect(root.querySelector("[data-card-notices]")).toBeNull();
    // the shell's banner first, the shell's verification page last
    const banner = root.querySelector<HTMLElement>("[data-verify]")!;
    expect(banner.dataset.verify).toBe("verified");
    expect(
      banner.compareDocumentPosition(view) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(root.lastElementChild).toBe(
      root.querySelector('[data-page="verification"]'),
    );
  });

  it("an UNKNOWN card kind falls back to the generic Result page with a visible notice naming the kind", async () => {
    const bundle = await sealedBundle((source) => {
      delete extensions(source)["eu-ai-act-compliance/v1"];
      extensions(source)["x-month-view/v1"] = {
        enabled: true,
        month: "2026-09",
      };
    });
    const root = await render(bundle); // default registry: kind unknown
    expect(root.querySelector('[data-verify="verified"]')).not.toBeNull();
    expect(root.querySelector('[data-page="result"]')).not.toBeNull();
    const notice = root.querySelector<HTMLElement>(
      '[data-card-notice="unrecognized-kind"]',
    )!;
    expect(notice).not.toBeNull();
    expect(notice.dataset.cardKind).toBe("x-month-view/v1");
    expect(notice.textContent).toContain('"x-month-view/v1"');
    expect(notice.textContent).toContain("standard Result page");
  });

  it("no card extension: the generic Result page, no notice, as before", async () => {
    const bundle = await sealedBundle((source) => {
      delete extensions(source)["eu-ai-act-compliance/v1"];
    });
    const root = await render(bundle);
    expect(root.querySelector('[data-page="result"]')).not.toBeNull();
    expect(root.querySelector("[data-card-notices]")).toBeNull();
    expect(root.querySelector("[data-card]")).toBeNull();
  });

  it("two built-in cards declared: outcome-report/v1 renders, and the page says the compliance card was not shown", async () => {
    const bundle = await sealedBundle((source) => {
      extensions(source)["outcome-report/v1"] = { enabled: true };
    });
    const root = await render(bundle);
    expect(root.querySelector('[data-page="outcome-report"]')).not.toBeNull();
    expect(root.querySelector('[data-page="compliance"]')).toBeNull();
    const notice = root.querySelector<HTMLElement>(
      '[data-card-notice="not-selected"]',
    )!;
    expect(notice.dataset.cardKind).toBe("eu-ai-act-compliance/v1");
  });

  it("a built-in card the host's registry dropped is just an unknown kind", async () => {
    const bundle = await sealedBundle();
    const root = await render(bundle, createCardRegistry());
    expect(root.querySelector('[data-page="compliance"]')).toBeNull();
    expect(root.querySelector('[data-page="result"]')).not.toBeNull();
    expect(
      root.querySelector('[data-card-notice="unrecognized-kind"]'),
    ).not.toBeNull();
  });

  it("an unverified bundle never reaches a card, and draws no notice", async () => {
    const seen: Seen = { calls: 0 };
    const sealed = await sealedBundle((source) => {
      extensions(source)["x-month-view/v1"] = {
        enabled: true,
        month: "2026-09",
      };
      extensions(source)["x-unknown/v1"] = { enabled: true };
    });
    const root = await render(tamperedResult(sealed), hostRegistry(seen));
    expect(seen.calls).toBe(0);
    expect(root.querySelector('[data-verify="failed"]')).not.toBeNull();
    expect(root.querySelector("[data-card]")).toBeNull();
    expect(root.querySelector("[data-card-notices]")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The boundary
// ---------------------------------------------------------------------------

describe("boundary", () => {
  const MARKER = "INJECTED-MARKER-7f3a";
  const hostile = {
    html: `<div id="${MARKER}">${MARKER}</div>`,
    script: `<script>window.__pwned = "${MARKER}"</script>`,
    template: `<img src="x" onerror="window.__pwned='${MARKER}'">`,
    renderer: `function () { return "${MARKER}"; }`,
    badge: `<p data-verify="verified">Bundle verification passed ${MARKER}</p>`,
  };

  it("a card extension's HTML, script and extra members render nowhere -- built-in card", async () => {
    const bundle = await sealedBundle((source) => {
      Object.assign(
        extensions(source)["eu-ai-act-compliance/v1"] as Obj,
        hostile,
      );
      // markup inside a member the card DOES read stays text
      const obligation = (
        (extensions(source)["eu-ai-act-compliance/v1"] as Obj)
          .obligations as Obj[]
      )[0]!;
      obligation.title = `<script>window.__pwned=1</script><b>${"bold"}</b>`;
      extensions(source)["presentation/v1"] = {
        title: "Report",
        badge_html: `<img src=x onerror=alert(1)>${MARKER}`,
        verified: true,
      };
    });
    const root = await render(bundle, undefined, true);
    expect(root.querySelector('[data-page="compliance"]')).not.toBeNull();
    expect(root.innerHTML).not.toContain(MARKER);
    expect(root.querySelectorAll("script")).toHaveLength(0);
    expect(root.querySelectorAll("[onerror]")).toHaveLength(0);
    expect(
      [...root.querySelectorAll("b")].some((b) => b.textContent === "bold"),
    ).toBe(false);
    expect(root.textContent).toContain("<script>window.__pwned=1</script>");
    expect(root.querySelectorAll("[data-verify]")).toHaveLength(1);
    expect((window as unknown as Obj).__pwned).toBeUndefined();
  });

  it("an unknown card kind's HTML and script render nowhere; only its kind name, as text", async () => {
    const bundle = await sealedBundle((source) => {
      delete extensions(source)["eu-ai-act-compliance/v1"];
      extensions(source)["x-evil<b>/v1"] = { enabled: true, ...hostile };
    });
    const root = await render(bundle);
    expect(root.innerHTML).not.toContain(MARKER);
    expect(root.querySelectorAll("script, img, b")).toHaveLength(0);
    const notice = root.querySelector<HTMLElement>(
      '[data-card-notice="unrecognized-kind"]',
    )!;
    expect(notice.textContent).toContain('"x-evil<b>/v1"');
  });

  it("a card gets only verified data, chrome's three members, and its reader's typed settings", async () => {
    const seen: Seen = { calls: 0 };
    const bundle = await sealedBundle((source) => {
      delete extensions(source)["eu-ai-act-compliance/v1"];
      extensions(source)["x-month-view/v1"] = {
        enabled: true,
        month: "2026-09",
        ...hostile,
      };
      extensions(source)["presentation/v1"] = {
        producer_display_name: "EXAMPLE-ORG",
        title: "Month",
        badge_html: MARKER,
      };
    });
    const root = await render(bundle, hostRegistry(seen));
    expect(seen.calls).toBe(1);
    // the verified document, with every extension removed
    expect(seen.bundle!.document.extensions).toBeUndefined();
    expect(seen.bundle!.document.records).toBeDefined();
    expect(JSON.stringify(seen.bundle!.document)).not.toContain(MARKER);
    // chrome: the three presentation/v1 members, nothing else
    expect(seen.chrome).toEqual({
      producerDisplayName: "EXAMPLE-ORG",
      title: "Month",
    });
    // settings: what the card's own typed reader returned, nothing more
    expect(seen.settings).toEqual({ month: "2026-09" });
    expect(root.innerHTML).not.toContain(MARKER);
  });

  it("everything a card receives is frozen: a write throws, and the shell redraws without the card", async () => {
    for (const attempt of [
      (_v: HTMLElement, result: ResultRoot) => {
        (result.claims[0] as { verdict: string }).verdict = "met";
      },
      (_v: HTMLElement, result: ResultRoot) => {
        (result.bucketCounts as { failed: number }).failed = 0;
      },
      (_v: HTMLElement, result: ResultRoot) => {
        (result.records as Map<string, unknown>).clear();
      },
      (_v: HTMLElement, _r: ResultRoot, bundle: VerifiedBundle) => {
        (bundle.verification.graphClosure as { status: string }).status =
          "pass";
      },
      (_v: HTMLElement, _r: ResultRoot, bundle: VerifiedBundle) => {
        (bundle.document as Obj).root = "forged";
      },
    ]) {
      const seen: Seen = { calls: 0 };
      const bundle = await sealedBundle((source) => {
        delete extensions(source)["eu-ai-act-compliance/v1"];
        extensions(source)["x-month-view/v1"] = {
          enabled: true,
          month: "2026-09",
        };
      });
      const root = await render(bundle, hostRegistry(seen, attempt));
      expect(seen.calls).toBe(1);
      expect(root.querySelector('[data-page="month-view"]')).toBeNull();
      expect(root.querySelector('[data-page="result"]')).not.toBeNull();
      expect(
        root.querySelector<HTMLElement>('[data-card-notice="card-failed"]')!
          .dataset.cardKind,
      ).toBe("x-month-view/v1");
      expect(root.querySelector('[data-verify="verified"]')).not.toBeNull();
    }
  });

  it("a card's own fake verdict, script and handlers are stripped from its view", async () => {
    const seen: Seen = { calls: 0 };
    const bundle = await sealedBundle((source) => {
      delete extensions(source)["eu-ai-act-compliance/v1"];
      extensions(source)["x-month-view/v1"] = {
        enabled: true,
        month: "2026-09",
      };
    });
    const root = await render(
      bundle,
      hostRegistry(seen, (view) => {
        const fake = document.createElement("p");
        fake.dataset.verify = "verified";
        fake.textContent = "Bundle verification passed";
        const script = document.createElement("script");
        script.textContent = "window.__pwned = 1";
        const link = document.createElement("a");
        link.setAttribute("href", "javascript:alert(1)");
        link.setAttribute("onclick", "alert(1)");
        link.textContent = "details";
        view.append(fake, script, link);
      }),
    );
    const view = root.querySelector<HTMLElement>('[data-page="month-view"]')!;
    expect(view).not.toBeNull();
    expect(view.querySelector("[data-verify]")).toBeNull();
    expect(view.querySelector("script")).toBeNull();
    const link = view.querySelector("a")!;
    expect(link.hasAttribute("href")).toBe(false);
    expect(link.hasAttribute("onclick")).toBe(false);
    expect(Number(view.dataset.cardSealed)).toBe(4);
    expect(root.querySelectorAll("[data-verify]")).toHaveLength(1);
  });

  it("a card that rewrites the shell's banner is dropped and the banner is redrawn from the verifier", async () => {
    const seen: Seen = { calls: 0 };
    const bundle = await sealedBundle((source) => {
      delete extensions(source)["eu-ai-act-compliance/v1"];
      extensions(source)["x-month-view/v1"] = {
        enabled: true,
        month: "2026-09",
      };
    });
    const root = await render(
      bundle,
      hostRegistry(seen, () => {
        const banner = document.querySelector<HTMLElement>("[data-verify]")!;
        banner.dataset.verify = "failed";
        banner.textContent = "Bundle verification failed (forged by card)";
      }),
      true,
    );
    expect(seen.calls).toBe(1);
    const banner = root.querySelector<HTMLElement>("[data-verify]")!;
    expect(banner.dataset.verify).toBe("verified");
    expect(banner.textContent).toBe("Bundle verification passed");
    expect(root.querySelector('[data-page="month-view"]')).toBeNull();
    expect(root.querySelector('[data-page="result"]')).not.toBeNull();
    expect(
      root.querySelector('[data-card-notice="card-failed"]'),
    ).not.toBeNull();
  });
});

describe("guards", () => {
  it("frozenCopy is deep and leaves the original untouched", () => {
    const original = {
      a: [{ b: 1 }],
      m: new Map([["k", { v: 1 }]]),
      s: new Set(["x"]),
    };
    const copy = frozenCopy(original);
    expect(Object.isFrozen(copy.a[0])).toBe(true);
    expect(() => {
      (copy.a[0] as { b: number }).b = 2;
    }).toThrow();
    expect(() => copy.m.set("k2", { v: 2 })).toThrow();
    expect(() => copy.s.add("y")).toThrow();
    expect(Object.isFrozen(copy.m.get("k"))).toBe(true);
    original.a[0]!.b = 3;
    expect(copy.a[0]!.b).toBe(1);
  });

  it("sealCardView keeps fragments and data: images, drops other URLs", () => {
    const view = document.createElement("div");
    const ok = document.createElement("a");
    ok.setAttribute("href", "#row-1");
    const img = document.createElement("img");
    img.setAttribute("src", "data:image/png;base64,AAAA");
    const remote = document.createElement("img");
    remote.setAttribute("src", "https://example.org/pixel.png");
    view.append(ok, img, remote);
    expect(sealCardView(view)).toBe(1);
    expect(ok.getAttribute("href")).toBe("#row-1");
    expect(img.getAttribute("src")).toBe("data:image/png;base64,AAAA");
    expect(remote.hasAttribute("src")).toBe(false);
  });
});
