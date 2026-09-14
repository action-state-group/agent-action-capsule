#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const repo = resolve(import.meta.dirname, "..");
const ts = join(repo, "ts");
const work = mkdtempSync(join(tmpdir(), "aac-browser-conformance-"));
const environment = {
  ...process.env,
  npm_config_cache: join(work, "npm-cache"),
  PLAYWRIGHT_BROWSERS_PATH: join(work, "browsers"),
};
const run = (command, args, options = {}) =>
  execFileSync(command, args, { stdio: "inherit", env: environment, ...options });
const vectors = (root) => {
  const manifest = JSON.parse(readFileSync(join(root, "vectors.json"), "utf8"));
  return manifest.cases.map((item) => ({
    ...item,
    input: readFileSync(join(root, item.name, "input.json"), "utf8"),
    expected: JSON.parse(readFileSync(join(root, item.name, "expected.json"), "utf8")),
  }));
};

try {
  // Consume a package tarball, not the source tree, so export resolution and the
  // browser bundle see the artifact that readers install.
  run("npm", ["pack", "--pack-destination", work], { cwd: ts });
  const archives = readdirSync(work).filter((name) => name.endsWith(".tgz"));
  if (archives.length !== 1)
    throw new Error(`expected one packed artifact, found ${archives.join(", ")}`);
  const tarball = join(work, archives[0]);

  writeFileSync(join(work, "package.json"), '{"private":true}\n');
  run(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--no-package-lock",
      tarball,
      "@playwright/test@1.55.0",
      "esbuild@0.25.10",
    ],
    { cwd: work },
  );
  run(join(work, "node_modules", ".bin", "playwright"), ["install", "chromium"], {
    cwd: work,
  });

  const capsuleVectors = vectors(join(repo, "vectors", "capsule"));
  const disclosureVectors = vectors(join(repo, "vectors", "disclosure-envelope"));
  const entry = `
import {
  computeCapsuleId,
  decodeStrictJson,
  verifyClass1,
  verifyDisclosureEnvelope,
  verifyStore,
} from "@action-state-group/agent-action-capsule";

const capsuleVectors = ${JSON.stringify(capsuleVectors)};
const disclosureVectors = ${JSON.stringify(disclosureVectors)};
const failures = [];
// Publish the result object BEFORE any work so a later throw cannot leave the
// global undefined (which the harness would only see as an opaque poll timeout).
// failures is mutated in place, so the reference stays live as cases run.
window.__aacBrowserConformance = { failures };
window.addEventListener("error", (e) => failures.push("window error: " + String(e.message || e.error)));
window.addEventListener("unhandledrejection", (e) => failures.push("unhandled rejection: " + String(e.reason)));
const equal = (actual, expected) => JSON.stringify(actual) === JSON.stringify(expected);
const check = (name, actual, expected) => {
  if (!equal(actual, expected)) failures.push(name + ": got " + JSON.stringify(actual) + ", expected " + JSON.stringify(expected));
};

for (const item of capsuleVectors) {
  try {
    const input = decodeStrictJson(item.input);
    if (item.kind === "canonical") {
      let capsuleId = null;
      let exception = null;
      try { capsuleId = await computeCapsuleId(input); } catch (error) { exception = error?.name ?? String(error); }
      check(item.name + " canonical id", capsuleId, item.expected.capsule_id_recomputed ?? null);
      check(item.name + " canonical exception", exception !== null, item.expected.exception !== null);
    } else if (item.kind === "store") {
      const actual = await verifyStore(input.ledger);
      check(item.name + " store ok", actual.map((result) => result.ok), item.expected.results.map((result) => result.ok));
      check(item.name + " store ids", actual.map((result) => result.capsuleId ?? null), item.expected.results.map((result) => result.capsule_id_recomputed ?? null));
      check(item.name + " store findings", actual.map((result) => result.findings.map((finding) => finding.code)), item.expected.results.map((result) => result.findings.map((finding) => finding.code)));
    } else {
      const actual = await verifyClass1(input);
      check(item.name + " ok", actual.ok, item.expected.ok);
      check(item.name + " capsule id", actual.capsuleId ?? null, item.expected.capsule_id_recomputed ?? null);
      check(item.name + " findings", actual.findings.map((finding) => finding.code), (item.expected.findings ?? []).map((finding) => finding.code));
    }
  } catch (error) {
    failures.push(item.name + ": threw " + String(error));
  }
}

for (const item of disclosureVectors) {
  try {
    const input = decodeStrictJson(item.input);
    const actual = await verifyDisclosureEnvelope(input.envelope);
    check(item.name + " disclosure ok", actual.ok, item.expected.ok);
    check(item.name + " disclosure capsule ok", actual.capsuleResult.ok, item.expected.capsule.ok);
    check(item.name + " disclosure findings", actual.disclosureFindings, item.expected.disclosure_findings);
  } catch (error) {
    failures.push(item.name + ": threw " + String(error));
  }
}

if (document.body) document.body.textContent = failures.length ? failures.join("\\n") : "AAC browser conformance passed";
window.__aacBrowserConformance.done = true;
`;
  writeFileSync(join(work, "entry.mjs"), entry);
  const bundle = join(work, "aac-browser.bundle.js");
  run(
    join(work, "node_modules", ".bin", "esbuild"),
    [
      join(work, "entry.mjs"),
      "--bundle",
      "--minify",
      "--platform=browser",
      "--conditions=browser",
      "--format=esm",
      `--outfile=${bundle}`,
    ],
    { cwd: work },
  );
  const bundleCode = readFileSync(bundle, "utf8");
  if (bundleCode.includes("node:"))
    throw new Error("browser bundle contains a node: import");

  // Inline the ESM bundle as a module script rather than referencing it by src.
  // A module <script src> is fetched with CORS, which a file:// page (origin
  // "null") rejects; an INLINE module needs no fetch and still supports the
  // top-level await the WebCrypto path uses. Escape any </script> in the code.
  const html = join(work, "index.html");
  writeFileSync(
    html,
    '<!doctype html><html><body></body><script type="module">' +
      bundleCode.replace(/<\/script/gi, "<\\/script") +
      "</script></html>",
  );
  const test = join(work, "browser-conformance.spec.mjs");
  writeFileSync(
    test,
    `import { expect, test } from "@playwright/test";
test("built browser bundle accepts and rejects the frozen corpus", async ({ page }) => {
  const pageErrors = [];
  page.on("pageerror", (e) => pageErrors.push(String(e && e.stack || e)));
  page.on("console", (m) => { if (m.type() === "error") pageErrors.push("console: " + m.text()); });
  await page.goto(${JSON.stringify(pathToFileURL(html).href)});
  let result = null;
  try {
    await expect.poll(() => page.evaluate(() => (window.__aacBrowserConformance && window.__aacBrowserConformance.done) ? "done" : false), { timeout: 30000 }).toBe("done");
    result = await page.evaluate(() => window.__aacBrowserConformance);
  } catch (e) {
    const body = await page.evaluate(() => document.body ? document.body.textContent : "(no body)").catch(() => "(eval failed)");
    throw new Error("module never finished. pageErrors:\\n" + pageErrors.join("\\n") + "\\nbody:\\n" + body);
  }
  if (result.failures.length) throw new Error("conformance failures:\\n" + result.failures.join("\\n"));
});
`,
  );
  run(join(work, "node_modules", ".bin", "playwright"), ["test", test], {
    cwd: work,
  });
} finally {
  rmSync(work, { recursive: true, force: true });
}
