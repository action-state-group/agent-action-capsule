import { readFileSync } from "node:fs";

const bundlePlaceholder = "__BUNDLE_JSON__";
const browserPlaceholder = "__BROWSER_IIFE__";
const shell = readFileSync(
  new URL("./emitter-shell.html", import.meta.url),
  "utf8",
);

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

export function emitEvidenceGraphHtml(
  bundle: unknown,
  browserIIFE: string,
): string {
  const bundleJson = JSON.stringify(bundle);
  if (bundleJson === undefined) {
    throw new TypeError("bundle must be JSON-serializable");
  }
  if (
    bundleJson.includes(bundlePlaceholder) ||
    bundleJson.includes(browserPlaceholder)
  ) {
    throw new Error("bundle JSON must not contain emitter placeholders");
  }
  if (
    browserIIFE.includes(bundlePlaceholder) ||
    browserIIFE.includes(browserPlaceholder)
  ) {
    throw new Error("browser IIFE must not contain emitter placeholders");
  }

  const withBundle = replaceSingle(shell, bundlePlaceholder, bundleJson);
  const html = replaceSingle(withBundle, browserPlaceholder, browserIIFE);
  const bundleOffset = html.indexOf(bundleJson);

  if (
    html.includes(bundlePlaceholder) ||
    html.includes(browserPlaceholder) ||
    bundleOffset === -1 ||
    html.indexOf(bundleJson, bundleOffset + bundleJson.length) !== -1
  ) {
    throw new Error("emitter shell embed invariant failed");
  }

  return html;
}
