// @vitest-environment jsdom
// The shared resolution vectors (vectors/presentation-resolution/). The
// committed files must equal what the generator writes from this registry,
// byte for byte, and every vector must pass when read back from disk alone.
// The Go package go/presentation runs the same files.
//
//   AAC_WRITE_VECTORS=1 npx vitest run test/presentation-resolution-vectors.test.ts
//
// rewrites the corpus (and its SHA256SUMS) instead of comparing it.
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { resolve as resolvePath } from "node:path";
import { expect, it } from "vitest";
import { buildVerifiedBundleContext } from "../src/bundle.js";
import {
  BUILTIN_MANIFESTS,
  BUILTIN_SECTION_MANIFESTS,
} from "../src/builtin-manifests.js";
import {
  describeContext,
  type PresentationFormat,
  type PresentationManifest,
  type PresentationModule,
  type PresentationRefusal,
} from "../src/presentation-registry.js";
import {
  fromWire,
  generateResolutionVectors,
  overlayExtensions,
  registerAll,
  resolveWire,
  runtimeRefusal,
  stub,
  toRuntime,
  VECTOR_FILES,
  wireDescriptor,
  wireRefusal,
  type WireDescriptor,
  type WireRuntime,
} from "./helpers/presentation-resolution-vectors.js";

type Obj = Record<string, unknown>;
const VECTORS = resolvePath(process.cwd(), "..", "vectors");
const DIR = resolvePath(VECTORS, "presentation-resolution");
const read = (name: string): Obj =>
  JSON.parse(readFileSync(resolvePath(DIR, name), "utf8")) as Obj;
const sha256 = (bytes: Buffer | string): string =>
  createHash("sha256").update(bytes).digest("hex");

function checksums(): string {
  const lines = readdirSync(DIR)
    .filter((name) => name !== "SHA256SUMS")
    .sort()
    .map((name) => `${sha256(readFileSync(resolvePath(DIR, name)))}  ${name}`);
  return `${lines.join("\n")}\n`;
}

it("the committed corpus is exactly what the generator writes", async () => {
  const files = await generateResolutionVectors();
  if (process.env.AAC_WRITE_VECTORS === "1") {
    mkdirSync(DIR, { recursive: true });
    for (const [name, text] of Object.entries(files))
      writeFileSync(resolvePath(DIR, name), text);
    writeFileSync(resolvePath(DIR, "SHA256SUMS"), checksums());
  }
  for (const [name, text] of Object.entries(files))
    expect(readFileSync(resolvePath(DIR, name), "utf8"), name).toBe(text);
}, 120_000);

it("SHA256SUMS and the top-level index list every file", () => {
  expect(readFileSync(resolvePath(DIR, "SHA256SUMS"), "utf8")).toBe(
    checksums(),
  );
  const top = readFileSync(resolvePath(VECTORS, "SHA256SUMS"), "utf8");
  for (const line of checksums().trimEnd().split("\n")) {
    const [digest, name] = line.split("  ");
    expect(top).toContain(`${digest}  presentation-resolution/${name}`);
  }
  const index = JSON.parse(
    readFileSync(resolvePath(VECTORS, "manifest.json"), "utf8"),
  ) as { corpora: Record<string, string> };
  expect(index.corpora.presentation_resolution).toBe(
    "presentation-resolution/manifest.json",
  );
  const manifest = read("manifest.json") as {
    files: { path: string; sha256: string }[];
  };
  for (const file of manifest.files)
    expect(sha256(readFileSync(resolvePath(DIR, file.path))), file.path).toBe(
      file.sha256,
    );
});

it("the corpus carries the built-in manifests exactly as this package defines them", () => {
  const manifest = read("manifest.json");
  expect(manifest.builtin_manifests).toEqual(
    JSON.parse(JSON.stringify(BUILTIN_MANIFESTS)),
  );
  expect(manifest.builtin_section_manifests).toEqual(
    JSON.parse(JSON.stringify(BUILTIN_SECTION_MANIFESTS)),
  );
});

interface Probe {
  descriptor: WireDescriptor;
  audience: string;
  format: PresentationFormat;
  declines: string[];
  expect: Obj;
}

it("every table vector resolves as recorded", async () => {
  const file = read("table.json") as {
    runtime: WireRuntime;
    count: number;
    cases: Probe[];
  };
  expect(file.cases).toHaveLength(1536);
  expect(file.count).toBe(1536);
  const built = registerAll(BUILTIN_MANIFESTS, toRuntime(file.runtime));
  expect(built.error).toBeNull();
  for (const c of file.cases)
    expect(
      await resolveWire(
        built.modules,
        fromWire(c.descriptor),
        c.audience,
        c.format,
        c.declines,
        (m) => built.refusals.get(m),
      ),
    ).toEqual(c.expect);
});

it("every registration vector registers and resolves as recorded", async () => {
  const file = read("registration.json") as {
    cases: Array<{
      id: string;
      runtime: WireRuntime;
      register: boolean;
      manifests: PresentationManifest[];
      expect: Obj;
      probes: Probe[];
    }>;
  };
  const reasons = new Set<string>();
  const errors = new Set<string>();
  for (const c of file.cases) {
    const runtime = toRuntime(c.runtime);
    let modules: PresentationModule[];
    let refuse: (m: PresentationModule) => PresentationRefusal | undefined;
    if (c.register) {
      const built = registerAll(c.manifests, runtime);
      expect(
        {
          registrations: built.registrations,
          error: built.error,
          list:
            built.error === null
              ? built.registry.list().map((m) => m.manifest.id)
              : null,
          refused:
            built.error === null
              ? built.registry.refused().map(wireRefusal)
              : null,
        },
        c.id,
      ).toEqual(c.expect);
      if (built.error !== null) errors.add(String(built.error.kind));
      for (const refusal of built.registry.refused())
        reasons.add(refusal.reason);
      modules = built.modules;
      refuse = (m) => built.refusals.get(m);
    } else {
      modules = c.manifests.map(stub);
      refuse = (m) => runtimeRefusal(m.manifest, runtime);
    }
    for (const p of c.probes)
      expect(
        await resolveWire(
          modules,
          fromWire(p.descriptor),
          p.audience,
          p.format,
          p.declines,
          refuse,
        ),
        c.id,
      ).toEqual(p.expect);
  }
  expect([...reasons].sort()).toEqual([
    "presentation_api_unsupported",
    "runtime_too_old",
  ]);
  expect([...errors].sort()).toEqual(["ambiguity", "registration"]);
});

it("every descriptor vector: describeContext and resolution over the built-ins", async () => {
  const file = read("descriptors.json") as {
    bundles: Obj;
    cases: Array<{
      id: string;
      source: {
        bundle?: string;
        vector?: { file: string; key: string; case: string; member: string };
      };
      extensions?: Obj;
      expect: { descriptor: WireDescriptor; page: Obj; section: Obj };
    }>;
  };
  const pages = BUILTIN_MANIFESTS.map(stub);
  const sections = BUILTIN_SECTION_MANIFESTS.map(stub);
  for (const c of file.cases) {
    let base: unknown;
    if (c.source.bundle !== undefined) base = file.bundles[c.source.bundle];
    else {
      const v = c.source.vector!;
      const path = resolvePath(VECTORS, v.file);
      expect(existsSync(path), c.id).toBe(true);
      base = (
        (JSON.parse(readFileSync(path, "utf8")) as Obj).cases as Obj[]
      ).find((x) => x[v.key] === v.case)![v.member];
    }
    const context = await buildVerifiedBundleContext(
      overlayExtensions(base, c.extensions),
    );
    const descriptor = describeContext(context);
    expect(wireDescriptor(descriptor), c.id).toEqual(c.expect.descriptor);
    expect(
      await resolveWire(pages, descriptor, "*", "html", [], () => undefined),
      c.id,
    ).toEqual(c.expect.page);
    expect(
      await resolveWire(sections, descriptor, "*", "html", [], () => undefined),
      c.id,
    ).toEqual(c.expect.section);
  }
}, 120_000);

it("the descriptor vectors reach every built-in page shape and the section", () => {
  const file = read("descriptors.json") as {
    cases: Array<{ expect: { page: Obj; section: Obj } }>;
  };
  const pages = new Set(
    file.cases.map((c) => String(c.expect.page.module ?? c.expect.page.kind)),
  );
  for (const m of BUILTIN_MANIFESTS) expect(pages).toContain(m.id);
  expect(pages).toContain("refusal");
  expect(
    file.cases.some(
      (c) => c.expect.section.module === BUILTIN_SECTION_MANIFESTS[0]!.id,
    ),
  ).toBe(true);
});
