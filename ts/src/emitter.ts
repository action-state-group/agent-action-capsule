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

// JSON embedded in a script element must not be able to terminate that element.
function escapeJsonForHtmlScript(json: string): string {
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
  modules.forEach((module, index) => {
    checkInline(`module ${index}`, module.code, "</script");
    if (cspHashSourceFromHex(module.sha256) !== cspHashSource(module.code)) {
      throw new Error(`module ${index} does not match its SHA-256 pin`);
    }
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
