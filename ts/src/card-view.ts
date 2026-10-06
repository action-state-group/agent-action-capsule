/**
 * DOM side of the card registry (card-registry.ts): the built-in cards, the
 * notices the shell draws when it falls back, and the guards on a card's
 * view. The shell (evidence-graph-view.ts) owns the verification banner and
 * the verification page; a card only ever produces the view between them.
 */
import {
  createCardRegistry,
  type CardNotice,
  type CardRegistry,
} from "./card-registry.js";
import { readCompliancePresentation } from "./compliance-presentation.js";
import { renderCompliancePage } from "./compliance-view.js";
import { readOutcomeReportPresentation } from "./outcome-report-presentation.js";
import { renderOutcomeReportPage } from "./outcome-report-view.js";

/** Read one card's block through the card's existing whole-bundle reader. */
function asBundle(kind: string, block: unknown): unknown {
  return { extensions: { [kind]: block } };
}

/** The single element a page renderer appended to a detached host. */
function onlyChild(host: HTMLElement): HTMLElement {
  const view = host.firstElementChild;
  if (host.childElementCount !== 1 || !(view instanceof HTMLElement))
    throw new Error("a card renders exactly one view element");
  return view;
}

/**
 * A new registry holding the built-in cards, in precedence order:
 * `outcome-report/v1`, then `eu-ai-act-compliance/v1`. A host adds its own
 * card with one `registerCard` call on the registry this returns; nothing in
 * the shell or the report build changes.
 */
export function defaultCardRegistry(): CardRegistry {
  const registry = createCardRegistry();
  registry.registerCard("outcome-report/v1", {
    label: "outcome report",
    styledChrome: true,
    readSettings: (block) =>
      readOutcomeReportPresentation(asBundle("outcome-report/v1", block)),
    async render(result, bundle, _chrome, settings) {
      const host = document.createElement("div");
      await renderOutcomeReportPage(
        result,
        settings,
        bundle.document,
        bundle.verification,
        host,
      );
      return onlyChild(host);
    },
  });
  registry.registerCard("eu-ai-act-compliance/v1", {
    label: "EU AI Act obligations report",
    readSettings: (block) =>
      readCompliancePresentation(asBundle("eu-ai-act-compliance/v1", block)),
    render(result, bundle, _chrome, settings) {
      const host = document.createElement("div");
      renderCompliancePage(
        result,
        settings,
        bundle.document,
        bundle.verification,
        host,
      );
      return onlyChild(host);
    },
  });
  return registry;
}

// ---------------------------------------------------------------------------
// Guards on a card's view
// ---------------------------------------------------------------------------

/** Elements a card view may never carry: active content and document-level tags. */
const BLOCKED_ELEMENTS =
  "script,iframe,frame,frameset,object,embed,applet,base,meta,link,template,noscript,portal";
/**
 * Markers only the shell may draw: the verification verdict, the refusal
 * line, the verification page, and the fallback notices. A card that draws
 * one has its copy removed, so a view can never present a second verdict.
 */
const SHELL_MARKERS =
  "[data-verify],[data-refusal],[data-page='verification'],[data-card-notice],[data-card-notices]";
const URL_ATTRIBUTES = new Set([
  "href",
  "xlink:href",
  "src",
  "srcset",
  "action",
  "formaction",
  "poster",
  "background",
  "data",
]);

function allowedUrl(value: string): boolean {
  const url = value.trim().toLowerCase();
  return url.startsWith("#") || url.startsWith("data:image/");
}

/**
 * Strip from a card's view anything that is not static, escaped content:
 * blocked elements, shell-owned markers, event-handler and `srcdoc`
 * attributes, and any URL attribute other than a fragment or a data: image
 * (a card page loads nothing and runs nothing). Returns how many nodes or
 * attributes were removed; the view records it as `data-card-sealed`.
 */
export function sealCardView(view: HTMLElement): number {
  let removed = 0;
  for (const node of [
    ...view.querySelectorAll(BLOCKED_ELEMENTS),
    ...view.querySelectorAll(SHELL_MARKERS),
  ]) {
    if (!view.contains(node)) continue; // already gone with an ancestor
    node.remove();
    removed += 1;
  }
  for (const node of [view, ...view.querySelectorAll("*")]) {
    for (const attribute of [...node.attributes]) {
      const name = attribute.name.toLowerCase();
      const strip =
        name.startsWith("on") ||
        name === "srcdoc" ||
        (URL_ATTRIBUTES.has(name) && !allowedUrl(attribute.value));
      if (!strip) continue;
      node.removeAttribute(attribute.name);
      removed += 1;
    }
  }
  if (view.matches(SHELL_MARKERS)) {
    for (const name of [
      "data-verify",
      "data-refusal",
      "data-card-notice",
      "data-card-notices",
    ])
      view.removeAttribute(name);
    if (view.dataset.page === "verification") delete view.dataset.page;
    removed += 1;
  }
  view.dataset.cardSealed = String(removed);
  return removed;
}

// ---------------------------------------------------------------------------
// Fallback notices
// ---------------------------------------------------------------------------

function noticeText(notice: CardNotice): string {
  switch (notice.reason) {
    case "unrecognized-kind":
      return `This bundle asks for a report card this viewer does not recognize: "${notice.kind}". It is shown as the standard Result page instead.`;
    case "unreadable-block":
      return `This bundle asks for the "${notice.kind}" card, but its settings could not be read. It is shown as the standard Result page instead.`;
    case "not-selected":
      return `This bundle also asks for the "${notice.kind}" card. One card is shown per bundle, by this viewer's fixed card order: "${notice.selected ?? ""}".`;
    case "not-a-result-root":
      return `This bundle asks for the "${notice.kind}" card, but cards apply only to a Result v0 root. It is shown as its standard page instead.`;
    case "card-failed":
      return `The "${notice.kind}" card could not be drawn from this bundle. It is shown as the standard Result page instead.`;
  }
}

/**
 * Draw the notices as plain text (the declared kind is bundle text and goes
 * through textContent like everything else). Not a verification finding:
 * the banner above is unchanged by any of them.
 */
export function renderCardNotices(
  root: HTMLElement,
  notices: readonly CardNotice[],
): void {
  if (notices.length === 0) return;
  const section = document.createElement("section");
  section.dataset.cardNotices = String(notices.length);
  section.setAttribute("role", "note");
  for (const notice of notices) {
    const line = document.createElement("p");
    line.textContent = noticeText(notice);
    line.dataset.cardNotice = notice.reason;
    line.dataset.cardKind = notice.kind;
    section.append(line);
  }
  root.append(section);
}
