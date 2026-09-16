import { readFileSync } from "node:fs";
import { jcs } from "./json.js";

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

// JSON embedded in a script element must not be able to terminate that element.
function escapeJsonForHtmlScript(json: string): string {
  return json
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
}

export function emitEvidenceGraphHtml(
  bundle: unknown,
  browserIIFE: string,
): string {
  const bundleJson = new TextDecoder().decode(jcs(bundle));
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

  const embeddedBundleJson = escapeJsonForHtmlScript(bundleJson);
  const withBundle = replaceSingle(
    shell,
    bundlePlaceholder,
    embeddedBundleJson,
  );
  const html = replaceSingle(withBundle, browserPlaceholder, browserIIFE);
  const bundleOffset = html.indexOf(embeddedBundleJson);

  if (
    html.includes(bundlePlaceholder) ||
    html.includes(browserPlaceholder) ||
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
