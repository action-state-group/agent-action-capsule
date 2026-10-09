// The generator of vectors/presentation-resolution/: shared resolution
// vectors every implementation of spec/presentation-contract-v0.md runs (the
// TypeScript registry here, the Go package go/presentation). This registry is
// the reference: every expected value below is what it computes.
//
// Regenerate with
//
//   AAC_WRITE_VECTORS=1 npx vitest run test/presentation-resolution-vectors.test.ts
//
// Output is deterministic: the same tree always writes the same bytes.
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { buildVerifiedBundleContext } from "../../src/bundle.js";
import {
  BUILTIN_MANIFESTS,
  BUILTIN_SECTION_MANIFESTS,
} from "../../src/builtin-manifests.js";
import {
  describeContext,
  PRESENTATION_FORMATS,
  presentationRefusalLine,
  presentationRefusalReason,
  presentationRefusalRow,
  PresentationAmbiguityError,
  PresentationRegistrationError,
  PresentationRegistry,
  REFERENCE_PRESENTATION_RUNTIME,
  resolveModules,
  type PresentationDescriptor,
  type PresentationFormat,
  type PresentationManifest,
  type PresentationModule,
  type PresentationRefusal,
  type PresentationResolution,
  type PresentationRuntime,
} from "../../src/presentation-registry.js";
import { sealEvidenceBundle } from "./sealed-bundle.js";

type Obj = Record<string, unknown>;

export const VECTOR_FILES = [
  "table.json",
  "registration.json",
  "descriptors.json",
] as const;

const ROOT = resolvePath(process.cwd(), "..");
const TESTDATA = resolvePath(process.cwd(), "test", "testdata");
const MANIFESTS = resolvePath(
  ROOT,
  "schemas",
  "examples",
  "presentation-manifest-v0",
);
const json = (path: string): Obj =>
  JSON.parse(readFileSync(path, "utf8")) as Obj;
const manifestFile = (name: string): PresentationManifest =>
  json(resolvePath(MANIFESTS, name)) as unknown as PresentationManifest;

const ID_GRAPH = "aac.builtin.evaluation-summary-graph/v0";

// ---------------------------------------------------------------------------
// Shared encodings
// ---------------------------------------------------------------------------

/** A descriptor as the vectors carry it: sets as sorted arrays. */
export interface WireDescriptor {
  readonly verified: boolean;
  readonly bundle_kind: string | null;
  readonly profiles: readonly string[];
  readonly extensions: readonly string[];
}

export function wireDescriptor(d: PresentationDescriptor): WireDescriptor {
  return {
    verified: d.verified,
    bundle_kind: d.bundle_kind ?? null,
    profiles: [...d.profiles].sort(),
    extensions: [...d.extensions].sort(),
  };
}

export function fromWire(d: WireDescriptor): PresentationDescriptor {
  return {
    verified: d.verified,
    bundle_kind: d.bundle_kind ?? undefined,
    profiles: new Set(d.profiles),
    extensions: new Set(d.extensions),
  };
}

export interface WireRuntime {
  readonly presentation_apis: readonly string[];
  readonly runtime_version: string;
}

export const toRuntime = (r: WireRuntime): PresentationRuntime => ({
  presentationApis: r.presentation_apis,
  runtimeVersion: r.runtime_version,
});

const REFERENCE_WIRE_RUNTIME: WireRuntime = {
  presentation_apis: [...REFERENCE_PRESENTATION_RUNTIME.presentationApis],
  runtime_version: REFERENCE_PRESENTATION_RUNTIME.runtimeVersion,
};

/** A refusal with the exact section 3.2 wording for it. */
export function wireRefusal(r: PresentationRefusal): Obj {
  return {
    id: r.id,
    presentation_api: r.presentation_api,
    runtime_min: r.runtime_min,
    reason: r.reason,
    extensions: [...r.extensions],
    runtime_version: r.runtimeVersion,
    row_covered: presentationRefusalRow(r, true),
    row_uncovered: presentationRefusalRow(r, false),
    line: presentationRefusalLine(r),
  };
}

export function wireResolution(r: PresentationResolution): Obj {
  if (r.kind === "refusal") return { kind: "refusal" };
  if (r.kind === "no-presentation")
    return { kind: "no-presentation", refused: r.refused.map(wireRefusal) };
  return {
    kind: "module",
    module: r.module.manifest.id,
    refused: r.refused.map(wireRefusal),
  };
}

export function wireError(err: unknown): Obj {
  if (err instanceof PresentationAmbiguityError)
    return { kind: "ambiguity", ids: [...err.ids], message: err.message };
  if (err instanceof PresentationRegistrationError)
    return { kind: "registration", message: err.message };
  throw err;
}

export const stub = (manifest: PresentationManifest): PresentationModule => ({
  manifest,
  canRender: () => true,
  buildModel: () => null,
  render: () => undefined,
});

/**
 * Section 4.3 with `declines` the ids whose canRender is false (every other
 * module renders); the error kind when resolution raises one.
 */
export async function resolveWire(
  modules: readonly PresentationModule[],
  descriptor: PresentationDescriptor,
  audience: string,
  format: PresentationFormat,
  declines: readonly string[],
  refuse: (m: PresentationModule) => PresentationRefusal | undefined,
): Promise<Obj> {
  try {
    return wireResolution(
      await resolveModules(
        modules,
        descriptor,
        audience,
        format,
        (m) => !declines.includes(m.manifest.id),
        refuse,
      ),
    );
  } catch (err) {
    return wireError(err);
  }
}

/** A registry built from a list, stopping at the first error. */
export function registerAll(
  manifests: readonly PresentationManifest[],
  runtime: PresentationRuntime,
): {
  registrations: Obj[];
  error: Obj | null;
  modules: PresentationModule[];
  refusals: Map<PresentationModule, PresentationRefusal>;
  registry: PresentationRegistry;
} {
  const registry = new PresentationRegistry(runtime);
  const registrations: Obj[] = [];
  const modules: PresentationModule[] = [];
  const refusals = new Map<PresentationModule, PresentationRefusal>();
  for (const manifest of manifests) {
    const module = stub(manifest);
    try {
      const outcome = registry.register(module);
      modules.push(module);
      if (outcome.status === "refused") {
        refusals.set(module, outcome.refusal);
        registrations.push({
          status: "refused",
          refusal: wireRefusal(outcome.refusal),
        });
      } else registrations.push({ status: "registered" });
    } catch (err) {
      return {
        registrations,
        error: wireError(err),
        modules,
        refusals,
        registry,
      };
    }
  }
  return { registrations, error: null, modules, refusals, registry };
}

/** The refusal a runtime gives a manifest, built as the registry builds it. */
export function runtimeRefusal(
  manifest: PresentationManifest,
  runtime: PresentationRuntime,
): PresentationRefusal | undefined {
  const reason = presentationRefusalReason(manifest, runtime);
  return reason === undefined
    ? undefined
    : {
        id: manifest.id,
        presentation_api: manifest.presentation_api,
        runtime_min: manifest.runtime_min,
        reason,
        extensions: [...(manifest.requires.extensions?.required ?? [])],
        runtimeVersion: runtime.runtimeVersion,
      };
}

// ---------------------------------------------------------------------------
// table.json: appendix A.3's 1,536 cases
// ---------------------------------------------------------------------------

const SPEC_TOKENS = [
  undefined,
  "report/v1",
  "evaluation-summary/v1",
  "org.example.other/v1",
];
const READ_EXTENSIONS = [
  "outcome-report/v1",
  "eu-ai-act-compliance/v1",
  "composed/v1",
];

async function table(): Promise<Obj> {
  const modules = BUILTIN_MANIFESTS.map(stub);
  const cases: Obj[] = [];
  for (const verified of [true, false])
    for (const spec of SPEC_TOKENS)
      for (const result of [false, true])
        for (let mask = 0; mask < 1 << READ_EXTENSIONS.length; mask += 1)
          for (const graphBuilds of [true, false]) {
            const profiles: string[] = [];
            if (spec !== undefined) profiles.push(`spec_version:${spec}`);
            if (result) profiles.push("result_version:evidence-result-v0");
            const descriptor: WireDescriptor = {
              verified,
              bundle_kind: "evidence-bundle/v2",
              profiles: profiles.sort(),
              extensions: READ_EXTENSIONS.filter(
                (_, i) => mask & (1 << i),
              ).sort(),
            };
            const declines = graphBuilds ? [] : [ID_GRAPH];
            for (const audience of ["owner", "counterparty"])
              for (const format of PRESENTATION_FORMATS)
                cases.push({
                  id: `t${String(cases.length).padStart(4, "0")}`,
                  descriptor,
                  audience,
                  format,
                  declines,
                  expect: await resolveWire(
                    modules,
                    fromWire(descriptor),
                    audience,
                    format,
                    declines,
                    () => undefined,
                  ),
                });
          }
  return {
    description:
      "Appendix A.3 of spec/presentation-contract-v0.md: every (descriptor, audience, format) the built-in page shapes distinguish -- verified or not; four spec_version states; a Result carrier or not; every subset of outcome-report/v1, eu-ai-act-compliance/v1 and composed/v1; whether the evaluation-summary graph renders (declines); two audiences; three formats -- resolved over the six built-in manifests registered under the reference runtime.",
    registry: "builtin",
    runtime: REFERENCE_WIRE_RUNTIME,
    count: cases.length,
    cases,
  };
}

// ---------------------------------------------------------------------------
// registration.json: section 3.2 refusals, section 4.5 and malformed manifests
// ---------------------------------------------------------------------------

const EXAMPLES = [
  "example-unilateral.json",
  "example-composition-aware.json",
  "example-generic-fallback.json",
  "example-declarative-rules.json",
].map(manifestFile);
const UNSUPPORTED = manifestFile("neg-unsupported-presentation-api.json");
const AMBIGUOUS_A = manifestFile("neg-ambiguous-pair/a.json");
const AMBIGUOUS_B = manifestFile("neg-ambiguous-pair/b.json");

const with_ = (m: PresentationManifest, patch: Obj): PresentationManifest => {
  const copy: Obj = { ...structuredClone(m), ...patch };
  for (const [k, v] of Object.entries(patch))
    if (v === undefined) delete copy[k];
  return copy as unknown as PresentationManifest;
};

const d = (
  profiles: string[],
  extensions: string[],
  verified = true,
  bundle_kind: string | null = "evidence-bundle/v2",
): WireDescriptor => ({
  verified,
  bundle_kind,
  profiles: [...profiles].sort(),
  extensions: [...extensions].sort(),
});

interface Probe {
  readonly descriptor: WireDescriptor;
  readonly audience?: string;
  readonly format?: PresentationFormat;
  readonly declines?: readonly string[];
}

interface RegistrationCase {
  readonly id: string;
  readonly description: string;
  readonly runtime?: WireRuntime;
  /** false: no registration test; resolve over the list as given. */
  readonly register?: boolean;
  readonly manifests: readonly PresentationManifest[];
  readonly probes?: readonly Probe[];
}

/** The section 4.5 mutants of appendix A: one load-bearing forbid removed. */
function dropForbid(
  id: string,
  field: "profiles" | "extensions",
  token: string,
): PresentationManifest[] {
  return BUILTIN_MANIFESTS.map((manifest) => {
    if (manifest.id !== id) return manifest;
    const forbids: Obj = { ...manifest.forbids };
    const kept = ((forbids[field] as string[] | undefined) ?? []).filter(
      (t) => t !== token,
    );
    if (kept.length === 0) delete forbids[field];
    else forbids[field] = kept;
    const copy: Obj = { ...manifest, forbids };
    if (Object.keys(forbids).length === 0) delete copy.forbids;
    return copy as unknown as PresentationManifest;
  });
}

const EXCHANGE = "spec_version:org.example.exchange/v0";
const RULES = "spec_version:org.example.rules-comparison/v0";
const UNSUPPORTED_PROFILE =
  UNSUPPORTED.requires.profiles?.[0] ?? "spec_version:missing";
const UNSUPPORTED_EXTENSIONS = [
  ...(UNSUPPORTED.requires.extensions?.required ?? []),
];

function registrationCases(): RegistrationCase[] {
  const builtinProbes: Probe[] = [
    { descriptor: d(["spec_version:report/v1"], []) },
    {
      descriptor: d(
        ["result_version:evidence-result-v0"],
        ["outcome-report/v1"],
      ),
    },
    { descriptor: d(["result_version:evidence-result-v0"], []) },
    { descriptor: d(["spec_version:evaluation-summary/v1"], []) },
    {
      descriptor: d(["spec_version:evaluation-summary/v1"], []),
      declines: [ID_GRAPH],
    },
    { descriptor: d([], []) },
    { descriptor: d([], [], false) },
    { descriptor: d([], [], true, "evidence-bundle/v3") },
    { descriptor: d([], [], true, null) },
  ];
  const exampleProbes: Probe[] = [
    { descriptor: d([EXCHANGE], []) },
    { descriptor: d([EXCHANGE], ["composed/v1"]) },
    {
      descriptor: d([RULES], []),
      audience: "counterparty",
      format: "embedded",
    },
    { descriptor: d([RULES], []), declines: ["org.example.rules-table/v0"] },
    { descriptor: d([], []) },
    { descriptor: d([], [], false) },
  ];
  const unsupportedProbes: Probe[] = [
    { descriptor: d([UNSUPPORTED_PROFILE], UNSUPPORTED_EXTENSIONS) },
    { descriptor: d([UNSUPPORTED_PROFILE], []) },
    ...exampleProbes,
  ];
  const tooNew = with_(UNSUPPORTED, {
    presentation_api: "aac.presentation-api/v0",
    runtime_min: "0.2.0",
  });
  const noExtension = (
    m: PresentationManifest,
    patch: Obj,
  ): PresentationManifest => {
    const copy = with_(m, patch) as unknown as Obj;
    const requires = { ...(copy.requires as Obj) };
    delete requires.extensions;
    copy.requires = requires;
    return copy as unknown as PresentationManifest;
  };
  const versioned = (runtime_min: string, i: number): PresentationManifest =>
    with_(EXAMPLES[0]!, {
      id: `org.example.versioned-${i}/v0`,
      requires: {
        bundle_kind: "evidence-bundle/v2",
        profiles: [`spec_version:org.example.versioned-${i}/v0`],
      },
      forbids: undefined,
      runtime_min,
    });
  const ladder = ["0.0.9", "0.1.0", "0.1.1", "0.2.0", "0.10.0", "1.0.0"];
  const cases: RegistrationCase[] = [
    {
      id: "builtin",
      description:
        "The six built-in page manifests under the reference runtime: all registered; one probe per page shape.",
      manifests: BUILTIN_MANIFESTS,
      probes: builtinProbes,
    },
    {
      id: "builtin-sections",
      description:
        "The built-in section registry (the composition section) under the reference runtime.",
      manifests: BUILTIN_SECTION_MANIFESTS,
      probes: [
        { descriptor: d([], ["composed/v1"]) },
        {
          descriptor: d(
            ["result_version:evidence-result-v0"],
            ["composed/v1", "outcome-report/v1"],
          ),
        },
        { descriptor: d([], []) },
        { descriptor: d([], ["composed/v1"], false) },
      ],
    },
    {
      id: "builtin-sections-in-page-registry",
      description:
        "Why the composition section is not a page manifest: in one registry with the page manifests, section 4.5 refuses it.",
      manifests: [...BUILTIN_MANIFESTS, ...BUILTIN_SECTION_MANIFESTS],
    },
    {
      id: "builtin-sections-refused",
      description:
        "The section registry under a runtime that implements no presentation API: the section is refused and named, never selected.",
      runtime: { presentation_apis: [], runtime_version: "0.1.0" },
      manifests: BUILTIN_SECTION_MANIFESTS,
      probes: [
        { descriptor: d([], ["composed/v1"]) },
        { descriptor: d([], []) },
      ],
    },
    {
      id: "examples",
      description: "Appendix B's four example manifests as one registry.",
      manifests: EXAMPLES,
      probes: exampleProbes,
    },
    {
      id: "examples-plus-unsupported-api",
      description:
        "Appendix B's negative neg-unsupported-presentation-api.json registered beside the examples: refused (presentation_api_unsupported), never selected, carried in every resolution it matches.",
      manifests: [...EXAMPLES, UNSUPPORTED],
      probes: unsupportedProbes,
    },
    {
      id: "examples-plus-runtime-too-old",
      description:
        "The same module with a supported API and runtime_min 0.2.0: refused as runtime_too_old by the 0.1.0 runtime.",
      manifests: [...EXAMPLES, tooNew],
      probes: unsupportedProbes,
    },
    {
      id: "examples-plus-runtime-too-old-no-extension",
      description:
        "A refused module that requires no extension: its refusal is worded as a line, not a row.",
      manifests: [
        ...EXAMPLES,
        noExtension(tooNew, { id: "org.example.no-extension/v0" }),
      ],
      probes: [{ descriptor: d([UNSUPPORTED_PROFILE], []) }],
    },
    {
      id: "refusal-precedence",
      description:
        "Unsupported API and a runtime_min above the runtime: presentation_api_unsupported is reported, the first reason in section 3.2's order.",
      manifests: [with_(UNSUPPORTED, { runtime_min: "9.9.9" })],
      probes: [
        { descriptor: d([UNSUPPORTED_PROFILE], UNSUPPORTED_EXTENSIONS) },
      ],
    },
    {
      id: "runtime-version-ladder",
      description:
        "runtime_min compared numerically, component by component, against runtime 0.9.0.",
      runtime: {
        presentation_apis: ["aac.presentation-api/v0"],
        runtime_version: "0.9.0",
      },
      manifests: ladder.map(versioned),
      probes: ladder.map((_, i) => ({
        descriptor: d([`spec_version:org.example.versioned-${i}/v0`], []),
      })),
    },
    {
      id: "runtime-several-apis",
      description:
        "A runtime that implements v0 and v1: a v1 module is registered, a v2 one refused.",
      runtime: {
        presentation_apis: [
          "aac.presentation-api/v0",
          "aac.presentation-api/v1",
        ],
        runtime_version: "1.4.2",
      },
      manifests: [
        with_(versioned("1.4.2", 0), {
          presentation_api: "aac.presentation-api/v1",
        }),
        with_(versioned("0.1.0", 1), {
          presentation_api: "aac.presentation-api/v2",
        }),
      ],
      probes: [
        { descriptor: d(["spec_version:org.example.versioned-0/v0"], []) },
        { descriptor: d(["spec_version:org.example.versioned-1/v0"], []) },
      ],
    },
    {
      id: "builtin-under-empty-runtime",
      description:
        "The built-ins under a runtime that implements no presentation API: every module refused; each resolution names the refused modules it matched and selects nothing.",
      runtime: { presentation_apis: [], runtime_version: "0.1.0" },
      manifests: BUILTIN_MANIFESTS,
      probes: builtinProbes,
    },
    {
      id: "ambiguous-pair",
      description:
        "neg-ambiguous-pair/a.json and b.json: both specific (priorities 1 and 9); section 4.5 rejects b at registration.",
      manifests: [AMBIGUOUS_A, AMBIGUOUS_B],
    },
    {
      id: "ambiguous-pair-unregistered",
      description:
        "The same pair resolved without the registration test (a resolver that skipped it): the witness descriptor raises the ambiguity error before canRender, whatever the priorities.",
      register: false,
      manifests: [AMBIGUOUS_A, AMBIGUOUS_B],
      probes: [
        {
          descriptor: d(
            [
              ...(AMBIGUOUS_A.requires.profiles ?? []),
              ...(AMBIGUOUS_B.requires.profiles ?? []),
            ].filter((t, i, all) => all.indexOf(t) === i),
            [
              ...(AMBIGUOUS_A.requires.extensions?.required ?? []),
              ...(AMBIGUOUS_B.requires.extensions?.required ?? []),
            ].filter((t, i, all) => all.indexOf(t) === i),
          ),
          declines: [AMBIGUOUS_A.id, AMBIGUOUS_B.id],
        },
      ],
    },
    {
      id: "ambiguous-with-refused",
      description:
        "A refused module still counts for section 4.5: a co-matchable module of its tier is rejected after it.",
      manifests: [
        UNSUPPORTED,
        with_(UNSUPPORTED, {
          id: "org.example.supported-twin/v0",
          presentation_api: "aac.presentation-api/v0",
        }),
      ],
    },
    {
      id: "two-fallbacks",
      description: "Two fallbacks with overlapping audiences: rejected.",
      manifests: [
        EXAMPLES[2]!,
        with_(EXAMPLES[2]!, {
          id: "org.example.second-fallback/v0",
          audiences: ["owner"],
        }),
      ],
    },
    {
      id: "disjoint-audiences-and-formats",
      description:
        "Manifests that differ only in disjoint audiences, or only in disjoint formats, are not ambiguous.",
      manifests: [
        with_(EXAMPLES[2]!, {
          id: "org.example.owner-view/v0",
          audiences: ["owner"],
        }),
        with_(EXAMPLES[2]!, {
          id: "org.example.counterparty-view/v0",
          audiences: ["counterparty"],
          formats: ["html"],
        }),
        with_(EXAMPLES[2]!, {
          id: "org.example.counterparty-embed/v0",
          audiences: ["counterparty"],
          formats: ["fragment", "embedded"],
        }),
      ],
      probes: [
        { descriptor: d([], []), audience: "owner", format: "html" },
        { descriptor: d([], []), audience: "counterparty", format: "html" },
        { descriptor: d([], []), audience: "counterparty", format: "embedded" },
        { descriptor: d([], []), audience: "auditor", format: "html" },
        { descriptor: d([], []), audience: "*", format: "html" },
      ],
    },
    {
      id: "different-values-of-one-key",
      description:
        "Two specific modules requiring different values of one profile key cannot co-match.",
      manifests: [
        versioned("0.1.0", 0),
        with_(versioned("0.1.0", 1), {
          requires: {
            bundle_kind: "evidence-bundle/v2",
            profiles: ["spec_version:org.example.other/v1"],
          },
        }),
        with_(versioned("0.1.0", 2), {
          requires: {
            bundle_kind: "evidence-bundle/v2",
            profiles: ["spec_version:org.example.third/v1"],
          },
        }),
      ],
      probes: [
        { descriptor: d(["spec_version:org.example.versioned-0/v0"], []) },
        { descriptor: d(["spec_version:org.example.other/v1"], []) },
      ],
    },
    {
      id: "different-keys-co-match",
      description:
        "Two specific modules requiring tokens of different profile keys can co-match (a root can carry both): rejected.",
      manifests: [
        versioned("0.1.0", 0),
        with_(versioned("0.1.0", 1), {
          requires: {
            bundle_kind: "evidence-bundle/v2",
            profiles: ["result_version:evidence-result-v0"],
          },
        }),
      ],
    },
    {
      id: "duplicate-id",
      description: "Registering an id twice is an error.",
      manifests: [
        EXAMPLES[0]!,
        with_(EXAMPLES[0]!, { audiences: ["owner"], formats: ["html"] }),
      ],
    },
    ...[
      [
        "neg-unknown-field.json",
        "a title member: unknown members are an error",
      ],
      ["neg-fallback-with-priority.json", "a fallback carrying priority"],
      ["neg-missing-id.json", "no id"],
      ["neg-presentation-v1-namespace.json", "spec_version presentation/v1"],
      [
        "neg-missing-presentation-api.json",
        "no presentation_api: malformed, not refused",
      ],
    ].map(([file, why]) => ({
      id: `malformed-${file!.replace(/^neg-|\.json$/gu, "")}`,
      description: `Appendix B's ${file}: rejected at registration (${why}).`,
      manifests: [manifestFile(file!)],
    })),
    ...(
      [
        ["specific-without-priority", { priority: undefined }],
        ["priority-zero", { priority: 0 }],
        ["priority-fraction", { priority: 1.5 }],
        ["runtime-min-malformed", { runtime_min: "0.1" }],
        [
          "presentation-api-malformed",
          { presentation_api: "aac.presentation-api/0" },
        ],
        ["id-malformed", { id: "Example/v0" }],
        ["trust-class-unknown", { trust_class: "sandboxed" }],
        ["declarative-without-block", { trust_class: "declarative" }],
        ["no-audience", { audiences: [] }],
        ["audience-malformed", { audiences: ["Owner"] }],
        ["format-unknown", { formats: ["pdf"] }],
        ["fallback-not-boolean", { fallback: "no" }],
        [
          "profile-token-malformed",
          {
            requires: {
              bundle_kind: "evidence-bundle/v2",
              profiles: ["locale:en"],
            },
          },
        ],
        [
          "requires-forbids-profile",
          {
            forbids: { profiles: [EXCHANGE] },
          },
        ],
        [
          "requires-forbids-extension",
          {
            requires: {
              bundle_kind: "evidence-bundle/v2",
              profiles: [EXCHANGE],
              extensions: { required: ["composed/v1"] },
            },
          },
        ],
        [
          "two-tokens-one-key",
          {
            requires: {
              bundle_kind: "evidence-bundle/v2",
              profiles: [EXCHANGE, "spec_version:org.example.other/v1"],
            },
          },
        ],
        ["no-bundle-kind", { requires: { profiles: [EXCHANGE] } }],
        [
          "several-problems",
          {
            spec_version: "presentation/v1",
            runtime_min: "1",
            audiences: ["*", "Owner"],
            extra: true,
          },
        ],
      ] as Array<[string, Obj]>
    ).map(([name, patch]) => ({
      id: `malformed-${name}`,
      description: `example-unilateral.json with ${JSON.stringify(patch)}: rejected at registration.`,
      manifests: [with_(EXAMPLES[0]!, patch)],
    })),
  ];
  for (const [id, field, token] of [
    ["aac.builtin.result-compliance/v0", "extensions", "outcome-report/v1"],
    ["aac.builtin.result/v0", "extensions", "eu-ai-act-compliance/v1"],
    ["aac.builtin.result/v0", "extensions", "outcome-report/v1"],
    [ID_GRAPH, "profiles", "result_version:evidence-result-v0"],
    [
      "aac.builtin.result-outcome-report/v0",
      "profiles",
      "spec_version:report/v1",
    ],
  ] as const) {
    const mutated = dropForbid(id, field, token);
    const slug = `${id.replace(/^aac\.builtin\.|\/v0$/gu, "")}-${token.replace(/[^a-z0-9]+/gu, "-")}`;
    cases.push({
      id: `mutant-${slug}`,
      description: `Appendix A with ${id} no longer forbidding ${token}: section 4.5 rejects the set.`,
      manifests: mutated,
    });
    cases.push({
      id: `mutant-${slug}-unregistered`,
      description: `The same set resolved without the registration test: the descriptor the forbid excluded raises the ambiguity error.`,
      register: false,
      manifests: mutated,
      probes: [
        {
          descriptor: d(
            [
              ...(field === "profiles" ? [token] : []),
              ...(mutated.find((m) => m.id === id)!.requires.profiles ?? []),
            ],
            [
              ...(field === "extensions" ? [token] : []),
              ...(mutated.find((m) => m.id === id)!.requires.extensions
                ?.required ?? []),
            ],
          ),
        },
      ],
    });
  }
  return cases;
}

async function registration(): Promise<Obj> {
  const out: Obj[] = [];
  for (const c of registrationCases()) {
    const wireRuntime = c.runtime ?? REFERENCE_WIRE_RUNTIME;
    const runtime = toRuntime(wireRuntime);
    const register = c.register ?? true;
    let expectObj: Obj;
    let modules: PresentationModule[];
    let refuse: (m: PresentationModule) => PresentationRefusal | undefined;
    if (register) {
      const built = registerAll(c.manifests, runtime);
      expectObj = {
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
      };
      modules = built.modules;
      refuse = (m) => built.refusals.get(m);
    } else {
      modules = c.manifests.map(stub);
      refuse = (m) => runtimeRefusal(m.manifest, runtime);
      expectObj = {};
    }
    const probes: Obj[] = [];
    if (!register || expectObj.error === null)
      for (const p of c.probes ?? []) {
        const audience = p.audience ?? "*";
        const format = p.format ?? "html";
        const declines = [...(p.declines ?? [])];
        probes.push({
          descriptor: p.descriptor,
          audience,
          format,
          declines,
          expect: await resolveWire(
            modules,
            fromWire(p.descriptor),
            audience,
            format,
            declines,
            refuse,
          ),
        });
      }
    out.push({
      id: c.id,
      description: c.description,
      runtime: wireRuntime,
      register,
      manifests: c.manifests,
      expect: expectObj,
      probes,
    });
  }
  return {
    description:
      "Registration (section 4.5 and the malformed and dead manifest rules), the presentation ABI (section 3.2: refusal reasons, their order and exact wording) and resolution (section 4.3) over small registries. With register true, manifests are registered in order and the run stops at the first error; probes then resolve over the registered modules. With register false, the probes resolve over the list as given, without the registration test, each module refused or not by the runtime.",
    count: out.length,
    cases: out,
  };
}

// ---------------------------------------------------------------------------
// descriptors.json: section 4.2 over real, verified bundles
// ---------------------------------------------------------------------------

// Fixtures too large to carry in a vector file; the overlays below on the
// small Result fixture cover the extension blocks they exercise.
const SKIP_FIXTURES = new Set([
  "bundle-vectors.json",
  "countersign-v1-anchor-golden.json",
  "countersigners.json",
  "witnesses-with-placeholder.json",
  "outcome-report-bundle.json",
  "week-bundle.json",
]);

// Fixtures whose sealed form the TypeScript record verifier accepts and the
// Python authority and the Go verifier reject: their records carry a
// non-object `provenance_mode`, which ts/src/verify.ts does not yet type-check
// (block_not_object). Only their unsealed form is carried until the
// verifiers agree, since a vector must pass in every implementation.
const RECORD_VERIFIER_DIVERGENCE = new Set([
  "report-mixed-tz-bundle.json",
  "report-rows-uncheckpointed-bundle.json",
]);

interface BundleSource {
  /** A bundle carried in this file, under `bundles`. */
  readonly bundle?: string;
  /** A bundle in another vector file: `file` (relative to vectors/), the case whose `key` equals `case`, its member `member`. */
  readonly vector?: { file: string; key: string; case: string; member: string };
}

function loadVector(source: NonNullable<BundleSource["vector"]>): unknown {
  const cases = json(resolvePath(ROOT, "vectors", source.file)).cases as Obj[];
  const c = cases.find((x) => x[source.key] === source.case);
  if (c === undefined)
    throw new Error(`no case ${source.case} in ${source.file}`);
  return c[source.member];
}

/** Apply an extensions overlay: each member replaces the kind; null removes it. */
export function overlayExtensions(
  bundle: unknown,
  overlay: Obj | undefined,
): unknown {
  if (overlay === undefined) return bundle;
  const copy = structuredClone(bundle) as Obj;
  const extensions: Obj =
    copy.extensions !== null &&
    typeof copy.extensions === "object" &&
    !Array.isArray(copy.extensions)
      ? { ...(copy.extensions as Obj) }
      : {};
  for (const [kind, block] of Object.entries(overlay))
    if (block === null) delete extensions[kind];
    else extensions[kind] = block;
  copy.extensions = extensions;
  return copy;
}

const sha256 = (text: string): string =>
  createHash("sha256").update(text).digest("hex");

async function descriptors(): Promise<Obj> {
  const bundles: Obj = {};
  const sources: Array<[string, BundleSource]> = [];
  for (const file of readdirSync(TESTDATA)
    .filter((f) => f.endsWith(".json") && !SKIP_FIXTURES.has(f))
    .sort()) {
    const raw = json(resolvePath(TESTDATA, file));
    const name = file.replace(/\.json$/u, "");
    bundles[name] = raw;
    sources.push([name, { bundle: name }]);
    if (RECORD_VERIFIER_DIVERGENCE.has(file)) continue;
    try {
      bundles[`${name}#sealed`] = (await sealEvidenceBundle(raw)).bundle;
      sources.push([`${name}#sealed`, { bundle: `${name}#sealed` }]);
    } catch {
      /* not sealable: the raw form still counts */
    }
  }
  // The Result fixture with its root's agent_input withheld (no spec_version
  // token, the Result carried in agent_output) and with one disclosure
  // tampered (unverified).
  const result = bundles["result-root-bundle#sealed"] as Obj;
  const root = result.root as string;
  const withheld = structuredClone(result);
  delete ((withheld.disclosures as Obj)[root] as Obj).agent_input;
  bundles["result-root-bundle#sealed-input-withheld"] = withheld;
  sources.push([
    "result-root-bundle#sealed-input-withheld",
    { bundle: "result-root-bundle#sealed-input-withheld" },
  ]);
  const tampered = structuredClone(result);
  ((tampered.disclosures as Obj)[root] as Obj).agent_output = {
    tampered: true,
  };
  bundles["result-root-bundle#sealed-tampered"] = tampered;
  sources.push([
    "result-root-bundle#sealed-tampered",
    { bundle: "result-root-bundle#sealed-tampered" },
  ]);
  for (const [file, key, member] of [
    ["bundle/producer-key/vectors.json", "id", "bundle"],
    ["bundle/report-single-record.json", "name", "bundle"],
    ["bundle/composed/vectors.json", "id", "container"],
  ] as const) {
    for (const c of json(resolvePath(ROOT, "vectors", file)).cases as Obj[]) {
      const id = String(c[key]);
      sources.push([
        `vectors/${file}#${id}`,
        { vector: { file, key, case: id, member } },
      ]);
    }
  }

  const complianceBlock = (
    json(resolvePath(TESTDATA, "compliance-bundle.json")).extensions as Obj
  )["eu-ai-act-compliance/v1"];
  const OUTCOME: Array<[string, unknown]> = [
    ["outcome:absent", null],
    ["outcome:enabled", { enabled: true }],
    ["outcome:declined", { enabled: false }],
  ];
  const COMPLIANCE: Array<[string, unknown]> = [
    ["compliance:absent", null],
    ["compliance:enabled", complianceBlock],
    ["compliance:declined", { enabled: true, obligations: [] }],
  ];
  const COMPOSED: Array<[string, unknown]> = [
    ["composed:absent", null],
    ["composed:present", { kind: "composed/v1" }],
  ];

  const pages = BUILTIN_MANIFESTS.map(stub);
  const sections = BUILTIN_SECTION_MANIFESTS.map(stub);
  const cases: Obj[] = [];
  const one = async (
    name: string,
    source: BundleSource,
    overlay: Obj | undefined,
  ): Promise<boolean> => {
    const base =
      source.bundle !== undefined
        ? bundles[source.bundle]
        : loadVector(source.vector!);
    const context = await buildVerifiedBundleContext(
      overlayExtensions(base, overlay),
    );
    const descriptor = describeContext(context);
    cases.push({
      id: name,
      source,
      ...(overlay === undefined ? {} : { extensions: overlay }),
      expect: {
        descriptor: wireDescriptor(descriptor),
        page: await resolveWire(
          pages,
          descriptor,
          "*",
          "html",
          [],
          () => undefined,
        ),
        section: await resolveWire(
          sections,
          descriptor,
          "*",
          "html",
          [],
          () => undefined,
        ),
      },
    });
    return descriptor.verified;
  };
  for (const [name, source] of sources) {
    if (!(await one(name, source, undefined))) continue;
    for (const [o, outcome] of OUTCOME)
      for (const [c, compliance] of COMPLIANCE)
        for (const [m, composed] of COMPOSED)
          await one(`${name} {${o} ${c} ${m}}`, source, {
            "outcome-report/v1": outcome,
            "eu-ai-act-compliance/v1": compliance,
            "composed/v1": composed,
          });
  }
  return {
    description:
      "Section 4.2: the descriptor of each bundle after verification, and what it resolves to over the built-in page manifests and the built-in section manifests (audience *, format html, every module rendering). A case's bundle is `source.bundle` (a member of `bundles`) or a case of another vector file (`source.vector`, relative to vectors/); `extensions`, when present, is applied first: each member replaces that kind in the bundle's extensions object (which is created when absent), and null removes it.",
    bundles,
    count: cases.length,
    cases,
  };
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/** One case per line inside `cases` and `probes`, two-space indentation elsewhere. */
function render(value: Obj): string {
  const lines: string[] = ["{"];
  const entries = Object.entries(value);
  entries.forEach(([key, member], i) => {
    const comma = i === entries.length - 1 ? "" : ",";
    if (key === "cases" && Array.isArray(member)) {
      lines.push(`  ${JSON.stringify(key)}: [`);
      member.forEach((item, j) =>
        lines.push(
          `    ${JSON.stringify(item)}${j === member.length - 1 ? "" : ","}`,
        ),
      );
      lines.push(`  ]${comma}`);
    } else if (
      key === "bundles" &&
      typeof member === "object" &&
      member !== null
    ) {
      const inner = Object.entries(member as Obj);
      lines.push(`  ${JSON.stringify(key)}: {`);
      inner.forEach(([k, v], j) =>
        lines.push(
          `    ${JSON.stringify(k)}: ${JSON.stringify(v)}${j === inner.length - 1 ? "" : ","}`,
        ),
      );
      lines.push(`  }${comma}`);
    } else
      lines.push(
        `  ${JSON.stringify(key)}: ${JSON.stringify(member, null, 2).replaceAll("\n", "\n  ")}${comma}`,
      );
  });
  lines.push("}");
  return `${lines.join("\n")}\n`;
}

/** Every generated file of the corpus, by name, as bytes to write. */
export async function generateResolutionVectors(): Promise<
  Record<string, string>
> {
  const files: Record<string, string> = {
    "table.json": render(await table()),
    "registration.json": render(await registration()),
    "descriptors.json": render(await descriptors()),
  };
  const counts: Record<string, number> = {};
  for (const name of VECTOR_FILES)
    counts[name] = (JSON.parse(files[name]!) as { count: number }).count;
  files["manifest.json"] = `${JSON.stringify(
    {
      contract:
        "spec/presentation-contract-v0.md (sections 3.2, 4.2-4.5, appendix A)",
      provenance: "reference-derived",
      generator: "ts/test/helpers/presentation-resolution-vectors.ts",
      normative_for: ["ts/src/presentation-registry.ts", "go/presentation"],
      builtin_manifests: BUILTIN_MANIFESTS,
      builtin_section_manifests: BUILTIN_SECTION_MANIFESTS,
      reference_runtime: REFERENCE_WIRE_RUNTIME,
      files: VECTOR_FILES.map((path) => ({
        path,
        sha256: sha256(files[path]!),
        count: counts[path],
      })),
    },
    null,
    2,
  )}\n`;
  return files;
}
