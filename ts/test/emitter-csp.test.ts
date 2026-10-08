import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  CORE_RUNTIME_STYLES,
  DEFAULT_EVIDENCE_GRAPH_TITLE,
  cspHashSourceFromHex,
  emitEvidenceGraphHtml,
} from "../src/emitter.js";

const bundle = JSON.parse(
  readFileSync(
    resolve(import.meta.dirname, "testdata", "week-bundle.json"),
    "utf8",
  ),
) as unknown;
const iife = "/*IIFE_MARKER*/";

const hex = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");
const source = (value: string): string =>
  `'sha256-${createHash("sha256").update(value, "utf8").digest("base64")}'`;

function csp(html: string): Map<string, string[]> {
  const match =
    /<meta http-equiv="Content-Security-Policy" content="([^"]*)" \/>/u.exec(
      html,
    );
  if (match?.[1] === undefined) throw new Error("no CSP meta");
  return new Map(
    match[1].split("; ").map((directive) => {
      const [name, ...values] = directive.split(" ");
      return [name!, values];
    }),
  );
}

// An independent extraction of every inline element's text, used to check
// that the emitter hashed exactly the bytes it wrote.
function inline(html: string, tag: "script" | "style"): string[] {
  return [
    ...html.matchAll(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, "gu")),
  ].map((match) => match[1]!);
}

describe("emitter Content-Security-Policy", () => {
  it("carries a CSP meta that denies everything not hashed", () => {
    const policy = csp(emitEvidenceGraphHtml(bundle, iife));
    expect(policy.get("default-src")).toEqual(["'none'"]);
    expect(policy.get("connect-src")).toEqual(["'none'"]);
    expect(policy.get("img-src")).toEqual(["data:"]);
    expect(policy.get("base-uri")).toEqual(["'none'"]);
    expect(policy.get("form-action")).toEqual(["'none'"]);
    for (const value of [
      ...policy.get("script-src")!,
      ...policy.get("style-src")!,
    ])
      expect(value).toMatch(/^'sha256-[A-Za-z0-9+/]{43}='$/u);
  });

  it("lists the hash of every inline script and style actually emitted", () => {
    const html = emitEvidenceGraphHtml(bundle, iife, {
      themeCss: ":root{--aac-accent:#123456}",
      modules: [
        {
          code: "window.moduleRan=true;",
          sha256: hex("window.moduleRan=true;"),
        },
      ],
    });
    const policy = csp(html);
    const scripts = inline(html, "script");
    expect(scripts).toHaveLength(4);
    expect(policy.get("script-src")).toEqual(scripts.map(source));
    expect(policy.get("style-src")).toEqual([
      ...inline(html, "style").map(source),
      ...CORE_RUNTIME_STYLES.map(source),
    ]);
  });

  it("the core runtime hash is the base64 form of its hex .sha256 pin", () => {
    const pin = hex(iife);
    const html = emitEvidenceGraphHtml(bundle, iife, {
      coreRuntimeSha256: pin,
    });
    const listed = cspHashSourceFromHex(pin);
    expect(csp(html).get("script-src")).toContain(listed);
    const base64 = /^'sha256-(.*)'$/u.exec(listed)![1]!;
    expect(Buffer.from(base64, "base64").toString("hex")).toBe(pin);
    expect(() =>
      emitEvidenceGraphHtml(bundle, iife, { coreRuntimeSha256: hex("other") }),
    ).toThrow("browser IIFE does not match its SHA-256 pin");
  });

  it("go/emitter/runtime-style-hashes.txt matches the core runtime stylesheets", () => {
    const listed = readFileSync(
      resolve(process.cwd(), "..", "go", "emitter", "runtime-style-hashes.txt"),
      "utf8",
    )
      .split("\n")
      .filter((line) => line.trim() !== "" && !line.startsWith("#"))
      .map((line) => `'${line.split(" ")[0]!}'`);
    expect(listed).toEqual(CORE_RUNTIME_STYLES.map(source));
  });
});

describe("emitter slots", () => {
  it("keeps the default title when none is supplied", () => {
    expect(emitEvidenceGraphHtml(bundle, iife)).toContain(
      `<title>${DEFAULT_EVIDENCE_GRAPH_TITLE}</title>`,
    );
    expect(emitEvidenceGraphHtml(bundle, iife, { title: "" })).toContain(
      "<title>Evidence Graph</title>",
    );
  });

  it("HTML-escapes a supplied title", () => {
    const html = emitEvidenceGraphHtml(bundle, iife, {
      title: `Receipt <b>"A" & 'B'</b>`,
    });
    expect(html).toContain(
      "<title>Receipt &lt;b&gt;&#34;A&#34; &amp; &#39;B&#39;&lt;/b&gt;</title>",
    );
  });

  it("inlines digest-pinned modules after the core runtime, in order", () => {
    const first = "window.first=1;";
    const second = "window.second=2;";
    const html = emitEvidenceGraphHtml(bundle, iife, {
      modules: [
        { code: first, sha256: hex(first) },
        { code: second, sha256: hex(second) },
      ],
      bootstrap: "window.booted=true;",
    });
    expect(inline(html, "script").slice(1)).toEqual([
      iife,
      first,
      second,
      "window.booted=true;",
    ]);
  });

  it("refuses a module whose bytes do not match its pin", () => {
    expect(() =>
      emitEvidenceGraphHtml(bundle, iife, {
        modules: [{ code: "window.x=1;", sha256: hex("window.x=2;") }],
      }),
    ).toThrow("module 0 does not match its SHA-256 pin");
  });

  it("refuses inline content that would change where its element ends", () => {
    expect(() => emitEvidenceGraphHtml(bundle, "a</SCRIPT>b")).toThrow(
      "browser IIFE must not contain",
    );
    expect(() => emitEvidenceGraphHtml(bundle, "a<!--b")).toThrow(
      "browser IIFE must not contain",
    );
    expect(() =>
      emitEvidenceGraphHtml(bundle, iife, { themeCss: "a</style>" }),
    ).toThrow("theme CSS must not contain");
    expect(() => emitEvidenceGraphHtml(bundle, "a\rb")).toThrow(
      "browser IIFE must not contain CR or NUL",
    );
  });

  it("refuses any input carrying a slot placeholder", () => {
    expect(() =>
      emitEvidenceGraphHtml({ note: "__TITLE_SLOT__" }, iife),
    ).toThrow("bundle JSON must not contain emitter placeholders");
    expect(() =>
      emitEvidenceGraphHtml(bundle, iife, { title: "__CSP_SLOT__" }),
    ).toThrow("title must not contain emitter placeholders");
  });

  it("references nothing outside the page", () => {
    const html = emitEvidenceGraphHtml(bundle, iife);
    const shell = html.replace(/<script>[\s\S]*?<\/script>/gu, "");
    expect(shell).not.toMatch(/\b(?:src|href)=|<link|url\(|https?:/iu);
  });
});
