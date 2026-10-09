import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { COMPLIANCE_CSS } from "./compliance-styles.js";
import { jcs } from "./json.js";
import { OUTCOME_REPORT_CSS } from "./outcome-report-styles.js";

const cspSlot = "__CSP_SLOT__";
const titleSlot = "__TITLE_SLOT__";
const themeSlot = "__THEME_SLOT__";
const bundleSlot = "__BUNDLE_SLOT__";
const coreRuntimeSlot = "__CORE_RUNTIME_SLOT__";
const moduleSlot = "__MODULE_SLOT__";
const bootstrapSlot = "__BOOTSTRAP_SLOT__";
const slots = [
  cspSlot,
  titleSlot,
  themeSlot,
  bundleSlot,
  coreRuntimeSlot,
  moduleSlot,
  bootstrapSlot,
] as const;

/** The page title used when the caller supplies none. */
export const DEFAULT_EVIDENCE_GRAPH_TITLE = "Evidence Graph";
/** The bootstrap script used when the caller supplies none. */
export const DEFAULT_EVIDENCE_GRAPH_BOOTSTRAP =
  'renderEvidenceGraph(window.__BUNDLE__, document.getElementById("app"));';

/**
 * The stylesheets the reference core runtime inserts as `<style>` elements
 * at render time. They are not inline in the emitted bytes, so the CSP lists
 * their hashes explicitly; go/emitter/runtime-style-hashes.txt carries the
 * same list for the Go emitter (a test keeps the two equal).
 */
export const CORE_RUNTIME_STYLES: readonly string[] = [
  OUTCOME_REPORT_CSS,
  COMPLIANCE_CSS,
];

const shell = readFileSync(
  new URL("./emitter-shell.html", import.meta.url),
  "utf8",
);

/** A digest-pinned script the builder knowingly incorporates. */
export interface EmitterModule {
  /** The script source, inlined byte for byte. */
  readonly code: string;
  /** Lowercase hex SHA-256 of the UTF-8 bytes of `code` (a `.sha256` pin). */
  readonly sha256: string;
  /**
   * Lowercase hex SHA-256 of each stylesheet the module inserts at render
   * time (the manifest's `style_sha256`). Each is added to the page's
   * `style-src`.
   */
  readonly styleSha256?: readonly string[];
}

export interface EmitterOptions {
  /** Page title; HTML-escaped. Empty or absent uses "Evidence Graph". */
  readonly title?: string;
  /** CSS placed in the theme `<style>` element (token overrides). */
  readonly themeCss?: string;
  /** Lowercase hex SHA-256 pin for the core runtime; checked when given. */
  readonly coreRuntimeSha256?: string;
  /** Zero or more digest-pinned module scripts, run after the core runtime. */
  readonly modules?: readonly EmitterModule[];
  /** Bootstrap script; empty or absent uses the renderEvidenceGraph call. */
  readonly bootstrap?: string;
}

function replaceSingle(
  template: string,
  placeholder: string,
  value: string,
): string {
  const parts = template.split(placeholder);
  if (parts.length !== 2) {
    throw new Error(
      `emitter shell must contain exactly one ${placeholder} slot`,
    );
  }
  return `${parts[0]}${value}${parts[1]}`;
}

/** JSON embedded in a script element must not be able to terminate that element. */
export function escapeJsonForHtmlScript(json: string): string {
  return json
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
}

function escapeHtmlText(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&#34;")
    .replaceAll("'", "&#39;");
}

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

/** The CSP hash source for a lowercase hex SHA-256 digest (a `.sha256` pin). */
export function cspHashSourceFromHex(hex: string): string {
  if (!/^[0-9a-f]{64}$/u.test(hex)) {
    throw new Error("SHA-256 pin must be 64 lowercase hex characters");
  }
  return `'sha256-${Buffer.from(hex, "hex").toString("base64")}'`;
}

function cspHashSource(value: string): string {
  return `'sha256-${sha256(value).toString("base64")}'`;
}

// Inline content must reach the browser as the exact bytes hashed: no end
// tag or comment opener that changes where the element ends, and no CR or
// NUL that the HTML parser rewrites before the CSP check hashes the text.
function checkInline(name: string, value: string, endTag: string): void {
  const lower = value.toLowerCase();
  if (lower.includes(endTag) || lower.includes("<!--")) {
    throw new Error(`${name} must not contain ${endTag} or <!--`);
  }
  if (value.includes("\r") || value.includes("\0")) {
    throw new Error(`${name} must not contain CR or NUL characters`);
  }
}

// Collect the text of every <script> and <style> element in document order.
// The shell writes both start tags bare, and checkInline guarantees each
// element's text runs to the first matching end tag.
function inlineElements(html: string): { script: string[]; style: string[] } {
  const found = { script: [] as string[], style: [] as string[] };
  let offset = 0;
  for (;;) {
    const script = html.indexOf("<script>", offset);
    const style = html.indexOf("<style>", offset);
    if (script === -1 && style === -1) return found;
    const kind =
      style === -1 || (script !== -1 && script < style) ? "script" : "style";
    const start = (kind === "script" ? script : style) + kind.length + 2;
    const end = html.indexOf(`</${kind}>`, start);
    if (end === -1) throw new Error(`unterminated ${kind} element`);
    found[kind].push(html.slice(start, end));
    offset = end + kind.length + 3;
  }
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}

export function emitEvidenceGraphHtml(
  bundle: unknown,
  browserIIFE: string,
  options: EmitterOptions = {},
): string {
  const bundleJson = new TextDecoder().decode(jcs(bundle));
  const title =
    options.title === undefined || options.title === ""
      ? DEFAULT_EVIDENCE_GRAPH_TITLE
      : options.title;
  const themeCss = options.themeCss ?? "";
  const modules = options.modules ?? [];
  const bootstrap =
    options.bootstrap === undefined || options.bootstrap === ""
      ? DEFAULT_EVIDENCE_GRAPH_BOOTSTRAP
      : options.bootstrap;

  const inputs: [string, string][] = [
    ["bundle JSON", bundleJson],
    ["browser IIFE", browserIIFE],
    ["title", title],
    ["theme CSS", themeCss],
    ["bootstrap", bootstrap],
    ...modules.map((module, index): [string, string] => [
      `module ${index}`,
      module.code,
    ]),
  ];
  for (const [name, value] of inputs) {
    if (slots.some((slot) => value.includes(slot))) {
      throw new Error(`${name} must not contain emitter placeholders`);
    }
  }
  checkInline("browser IIFE", browserIIFE, "</script");
  checkInline("bootstrap", bootstrap, "</script");
  checkInline("theme CSS", themeCss, "</style");
  if (
    options.coreRuntimeSha256 !== undefined &&
    cspHashSourceFromHex(options.coreRuntimeSha256) !==
      cspHashSource(browserIIFE)
  ) {
    throw new Error("browser IIFE does not match its SHA-256 pin");
  }
  const moduleStyleSources: string[] = [];
  modules.forEach((module, index) => {
    checkInline(`module ${index}`, module.code, "</script");
    if (cspHashSourceFromHex(module.sha256) !== cspHashSource(module.code)) {
      throw new Error(`module ${index} does not match its SHA-256 pin`);
    }
    (module.styleSha256 ?? []).forEach((pin, styleIndex) => {
      try {
        moduleStyleSources.push(cspHashSourceFromHex(pin));
      } catch (error) {
        throw new Error(
          `module ${index} style ${styleIndex}: ${(error as Error).message}`,
        );
      }
    });
  });

  const embeddedBundleJson = escapeJsonForHtmlScript(bundleJson);
  let html = replaceSingle(shell, titleSlot, escapeHtmlText(title));
  html = replaceSingle(html, themeSlot, themeCss);
  html = replaceSingle(html, bundleSlot, embeddedBundleJson);
  html = replaceSingle(html, coreRuntimeSlot, browserIIFE);
  html = replaceSingle(
    html,
    moduleSlot,
    modules.map((module) => `<script>${module.code}</script>`).join("\n    "),
  );
  html = replaceSingle(html, bootstrapSlot, bootstrap);

  const inline = inlineElements(html);
  const scriptSources = unique(inline.script.map(cspHashSource));
  const styleSources = unique([
    ...inline.style.map(cspHashSource),
    ...CORE_RUNTIME_STYLES.map(cspHashSource),
    ...moduleStyleSources,
  ]);
  const csp = [
    "default-src 'none'",
    `script-src ${scriptSources.join(" ")}`,
    `style-src ${styleSources.join(" ")}`,
    "img-src data:",
    "connect-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
  ].join("; ");
  html = replaceSingle(html, cspSlot, csp);

  const bundleOffset = html.indexOf(embeddedBundleJson);
  if (
    slots.some((slot) => html.includes(slot)) ||
    bundleOffset === -1 ||
    html.indexOf(
      embeddedBundleJson,
      bundleOffset + embeddedBundleJson.length,
    ) !== -1
  ) {
    throw new Error("emitter shell embed invariant failed");
  }

  return html;
}

/**
 * The stylesheet of the static page's notice (the statement that the page
 * is not self-verifying). Hashed into the static page's CSP like the shell's
 * own stylesheet.
 */
export const STATIC_NOTICE_CSS =
  ":where(.aac-static-notice){display:block;margin:0 0 1rem;padding:0.75rem 1rem;border:1px solid var(--aac-line);border-radius:var(--aac-radius);color:var(--aac-warn);background:var(--aac-warn-bg)}:where(.aac-static-notice p){margin:0.25rem 0}";

/** What a static page carries: markup already rendered, and no code. */
export interface StaticPageInput {
  /** The rendered page: the children of `#app`, serialized as HTML. */
  readonly appHtml: string;
  /** The text of every `<style>` element in `appHtml`. */
  readonly appStyles: readonly string[];
  /** The value of every `style` attribute in `appHtml`. */
  readonly appStyleAttributes: readonly string[];
  /** The notice placed before `#app`, as HTML. */
  readonly noticeHtml: string;
}

/**
 * Write a static page: the same shell, base stylesheet, title and theme as
 * {@link emitEvidenceGraphHtml}, with already rendered markup in `#app` and
 * no script at all: no bundle element, no runtime, no module, no bootstrap.
 * The CSP allows no script (`script-src 'none'`) and lists every style it
 * carries by hash (style attributes through `'unsafe-hashes'`).
 *
 * The caller guarantees the markup has no script element and no event
 * handler attribute; the CSP would block either anyway.
 */
export function emitStaticEvidenceGraphHtml(
  input: StaticPageInput,
  options: Pick<EmitterOptions, "title" | "themeCss"> = {},
): string {
  const title =
    options.title === undefined || options.title === ""
      ? DEFAULT_EVIDENCE_GRAPH_TITLE
      : options.title;
  const themeCss = options.themeCss ?? "";
  for (const [name, value] of [
    ["title", title],
    ["theme CSS", themeCss],
  ] as const) {
    if (slots.some((slot) => value.includes(slot))) {
      throw new Error(`${name} must not contain emitter placeholders`);
    }
  }
  checkInline("theme CSS", themeCss, "</style");
  input.appStyles.forEach((style, index) =>
    checkInline(`static style ${index}`, style, "</style"),
  );

  // The head is the shell's, with the notice stylesheet added; the body is
  // replaced whole, so none of the shell's script elements is written. The
  // rendered markup is spliced in last, after every slot is filled, so text
  // in it is never read as a slot.
  let page = replaceSingle(shell, titleSlot, escapeHtmlText(title));
  page = replaceSingle(page, themeSlot, themeCss);
  const headEnd = page.indexOf("</head>");
  const bodyStart = page.indexOf("<body>");
  const bodyEnd = page.lastIndexOf("</body>");
  if (headEnd === -1 || bodyStart < headEnd || bodyEnd < bodyStart) {
    throw new Error("emitter shell has no head or body");
  }
  let head = `${page.slice(0, headEnd)}  <style>${STATIC_NOTICE_CSS}</style>\n  ${page.slice(headEnd, bodyStart)}`;
  const inline = inlineElements(head);
  if (inline.script.length > 0) {
    throw new Error("static page head must carry no script");
  }
  const styleSources = unique([
    ...inline.style.map(cspHashSource),
    ...input.appStyles.map(cspHashSource),
  ]);
  const attributeSources = unique(input.appStyleAttributes.map(cspHashSource));
  const csp = [
    "default-src 'none'",
    "script-src 'none'",
    `style-src ${[
      ...styleSources,
      ...(attributeSources.length === 0
        ? []
        : ["'unsafe-hashes'", ...attributeSources]),
    ].join(" ")}`,
    "img-src data:",
    "connect-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
  ].join("; ");
  head = replaceSingle(head, cspSlot, csp);
  if (slots.some((slot) => head.includes(slot))) {
    throw new Error("emitter shell embed invariant failed");
  }
  const html =
    `${head}<body>\n    ${input.noticeHtml}\n    ` +
    `<div id="app">${input.appHtml}</div>\n  ${page.slice(bodyEnd)}`;
  return html;
}
