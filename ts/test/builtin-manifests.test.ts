// The six built-in manifests are vendored as TS constants
// (src/builtin-manifests.ts). This compares each, as a JSON value, with the
// committed JSON file the presentation contract ships under
// schemas/examples/presentation-manifest-v0/. AAC_PRESENTATION_MANIFESTS_DIR
// points it at another copy of that directory.
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, it } from "vitest";
import { BUILTIN_MANIFESTS } from "../src/builtin-manifests.js";
import {
  PresentationAmbiguityError,
  PresentationRegistrationError,
  PresentationRegistry,
  type PresentationManifest,
  type PresentationModule,
} from "../src/presentation-registry.js";

const FILES = [
  "builtin-report-rows",
  "builtin-result-outcome-report",
  "builtin-result-compliance",
  "builtin-result",
  "builtin-evaluation-summary-graph",
  "builtin-no-aggregate",
];
const dir =
  process.env.AAC_PRESENTATION_MANIFESTS_DIR ??
  resolve(
    process.cwd(),
    "..",
    "schemas",
    "examples",
    "presentation-manifest-v0",
  );
const present = FILES.every((name) => existsSync(resolve(dir, `${name}.json`)));
const SKIP_REASON =
  `skipped: the presentation contract's manifest files are not at ${dir} ` +
  "(they land with the presentation contract change); set AAC_PRESENTATION_MANIFESTS_DIR to compare against a copy";
if (!present) console.warn(SKIP_REASON);

it.skipIf(!present)(
  present
    ? "each vendored built-in manifest equals the contract's JSON file as a value"
    : SKIP_REASON,
  () => {
    expect(BUILTIN_MANIFESTS.map((m) => m.id)).toHaveLength(FILES.length);
    FILES.forEach((name, i) => {
      const file: unknown = JSON.parse(
        readFileSync(resolve(dir, `${name}.json`), "utf8"),
      );
      expect(JSON.parse(JSON.stringify(BUILTIN_MANIFESTS[i])), name).toEqual(
        file,
      );
      // Same members, same order: a byte-level match after re-serializing.
      expect(JSON.stringify(BUILTIN_MANIFESTS[i]), name).toBe(
        JSON.stringify(file),
      );
    });
  },
);

const stub = (manifest: unknown): PresentationModule => ({
  manifest: manifest as PresentationManifest,
  canRender: () => true,
  buildModel: () => null,
  render: () => undefined,
});
const load = (name: string): unknown =>
  JSON.parse(readFileSync(resolve(dir, `${name}.json`), "utf8"));

it.skipIf(!present)(
  present
    ? "the registry applies the contract's example and negative manifests as its checker does"
    : SKIP_REASON,
  () => {
    const examples = new PresentationRegistry();
    for (const name of [
      "example-unilateral",
      "example-composition-aware",
      "example-generic-fallback",
      "example-declarative-rules",
      "example-declarative-outcome",
    ])
      examples.register(stub(load(name)));
    expect(examples.list()).toHaveLength(5);
    for (const name of [
      "neg-unknown-field",
      "neg-fallback-with-priority",
      "neg-missing-id",
      "neg-presentation-v1-namespace",
    ])
      expect(
        () => new PresentationRegistry().register(stub(load(name))),
        name,
      ).toThrow(PresentationRegistrationError);
    const pair = new PresentationRegistry();
    pair.register(stub(load("neg-ambiguous-pair/a")));
    expect(() => pair.register(stub(load("neg-ambiguous-pair/b")))).toThrow(
      PresentationAmbiguityError,
    );
  },
);
