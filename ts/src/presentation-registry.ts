import type {
  BundleVerificationResult,
  VerifiedBundleContext,
} from "./bundle.js";
import { verifiedPayload } from "./bundle.js";
import { readCompliancePresentation } from "./compliance-presentation.js";
import type { DisclosureState } from "./evidence-graph.js";
import { readOutcomeReportPresentation } from "./outcome-report-presentation.js";
import { carriesResultDocument, RESULT_VERSION } from "./result-root.js";
import { unboundRecordIds } from "./verification-page.js";

/**
 * The presentation registry of spec/presentation-contract-v0.md: module
 * manifests (`aac.presentation-manifest/v0`), the resolution descriptor a
 * verified bundle context yields (section 4.2), the static ambiguity test
 * applied at registration (section 4.5) and `resolve` (section 4.3).
 *
 * Precedence lives in the manifests: a registry never orders two modules of
 * one tier. Two that can match one descriptor are rejected when the second
 * is registered, and a runtime tie (only reachable by a resolver that skipped
 * that test) raises {@link PresentationAmbiguityError}, never first-wins.
 */

export const PRESENTATION_MANIFEST_VERSION = "aac.presentation-manifest/v0";

export type PresentationFormat = "html" | "fragment" | "embedded";
export const PRESENTATION_FORMATS: readonly PresentationFormat[] = [
  "html",
  "fragment",
  "embedded",
];

export interface PresentationManifest {
  readonly spec_version: typeof PRESENTATION_MANIFEST_VERSION;
  readonly id: string;
  readonly trust_class: "trusted-executable" | "declarative";
  readonly requires: {
    readonly bundle_kind: string;
    readonly profiles?: readonly string[];
    readonly extensions?: { readonly required: readonly string[] };
  };
  readonly forbids?: {
    readonly profiles?: readonly string[];
    readonly extensions?: readonly string[];
  };
  readonly audiences: readonly string[];
  readonly formats: readonly PresentationFormat[];
  readonly fallback: boolean;
  readonly priority?: number;
  readonly executable?: {
    readonly carrier: "core-runtime" | "module-slot";
    readonly script_sha256?: string;
    readonly style_sha256?: readonly string[];
    readonly wording_sha256?: string;
  };
  readonly declarative?: {
    readonly renderer: string;
    readonly wording_sha256: string;
    readonly fields: readonly unknown[];
  };
}

/**
 * What a module writes into. The depth regions are, for now, one element:
 * the built-in modules are whole report applications that predate the
 * depth levels, and the core writes its verification section after them.
 */
export interface PresentationHost {
  readonly L0: HTMLElement;
  readonly L1: HTMLElement;
  readonly L2: HTMLElement;
  readonly depth: "L0" | "L1" | "L2";
  /**
   * Restyle the banner and the verification section by class only. The one
   * chrome class the core knows is `"oi"` (the outcome-report look); any
   * other name is an error. Words, order and data attributes never change.
   */
  setChromeClass(name: string): void;
}

/** The closed badge vocabulary the core owns; a module cannot add a state. */
export type PresentationBadgeState =
  | "verified"
  | "failed"
  | "withheld"
  | "mismatch"
  | "producer-asserted";

/**
 * DOM primitives a module may use. Not a router: no navigation, no fetch, no
 * timers. Section, citation, formatting, countersigner naming and wording
 * arrive with wording packs and the depth regions.
 */
export interface PresentationServices {
  /** A native `<details>`/`<summary>` disclosure. */
  details(summary: string, open?: boolean): HTMLDetailsElement;
  /** A state badge from the core's closed vocabulary. */
  badge(state: PresentationBadgeState): HTMLElement;
  /** A member's disclosure state as the verifier resolved it. */
  disclosure(
    capsuleId: string,
    member: "agent_input" | "agent_output",
  ): DisclosureState;
}

export interface PresentationModule<Model = unknown> {
  readonly manifest: PresentationManifest;
  /**
   * Pure. True exactly when `buildModel(context)` would produce a model.
   * Called only on a verified context whose descriptor the manifest matched.
   * May be asynchronous: building a model can need a digest.
   */
  canRender(context: VerifiedBundleContext): boolean | Promise<boolean>;
  buildModel(context: VerifiedBundleContext): Model | Promise<Model>;
  render(
    model: Model,
    host: PresentationHost,
    services: PresentationServices,
  ): void | Promise<void>;
}

/** The resolution inputs (spec section 4.2); never the audience or format. */
export interface PresentationDescriptor {
  readonly verified: boolean;
  readonly bundle_kind: string | undefined;
  readonly profiles: ReadonlySet<string>;
  readonly extensions: ReadonlySet<string>;
}

export type PresentationResolution<Model = unknown> =
  | { readonly kind: "refusal" }
  | { readonly kind: "no-presentation" }
  | { readonly kind: "module"; readonly module: PresentationModule<Model> };

/** Something that resolves a context to one presentation. */
export interface PresentationResolver {
  resolve(
    context: VerifiedBundleContext,
    audience: string,
    format: PresentationFormat,
  ): Promise<PresentationResolution>;
}

export class PresentationAmbiguityError extends Error {
  readonly ids: readonly string[];
  constructor(ids: readonly string[], message?: string) {
    super(
      message ??
        `presentation is ambiguous: ${ids.join(", ")} all match; a tie is an error, never first-wins`,
    );
    this.name = "PresentationAmbiguityError";
    this.ids = ids;
  }
}

export class PresentationRegistrationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PresentationRegistrationError";
  }
}

// ---------------------------------------------------------------------------
// The verification gate and the descriptor
// ---------------------------------------------------------------------------

// Per-record membership may fail solely because some supplied records are
// bound to no log position (the verifier's `membership_record_unbound`): real
// records that sit outside any checkpoint. That is coverage, not a broken
// proof -- every other record's inclusion proof still verified -- so the
// bundle renders, each such record carries its own `uncheckpointed` status,
// and the banner and verification page state how many there are. Any other
// membership finding (an invalid proof, bad coordinates, a missing sequence)
// still fails the bundle as a whole: `unboundRecordIds` leaves out a record
// whose supplied entry was rejected, so the counts below can only agree when
// every finding is a clean unbound record.
function membershipProvenOrUnbound(result: BundleVerificationResult): boolean {
  return (
    result.perRecordMembership.status === "pass" ||
    (result.perRecordMembership.status === "fail" &&
      result.perRecordMembership.findings.length > 0 &&
      result.perRecordMembership.findings.length ===
        unboundRecordIds(result).length)
  );
}

/** The viewer's verification gate: what "verified" means for resolution. */
export function bundleVerified(result: BundleVerificationResult): boolean {
  return (
    result.graphClosure.status === "pass" &&
    result.intervalCoverage.status === "pass" &&
    membershipProvenOrUnbound(result) &&
    Object.values(result.capsuleResults).every((capsule) => capsule.ok) &&
    result.disclosures.every(
      (disclosure) =>
        disclosure.status === "disclosure_match" ||
        disclosure.status === "withheld",
    )
  );
}

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

/**
 * Extension kinds whose core reader can decline a present block. A kind not
 * listed here is engaged whenever it is present.
 */
const EXTENSION_READERS: Readonly<
  Record<string, (bundle: unknown) => boolean>
> = {
  "outcome-report/v1": (bundle) =>
    readOutcomeReportPresentation(bundle) !== undefined,
  "eu-ai-act-compliance/v1": (bundle) =>
    readCompliancePresentation(bundle) !== undefined,
};

/**
 * The descriptor of spec section 4.2, derived from the context alone. It is
 * a helper, not a context field: the context stays the one verification
 * run, and resolution reads it through this function.
 *
 * - `profiles`: `spec_version:<v>` when the root's `agent_input` is disclosed
 *   and carries a string `spec_version`; `result_version:evidence-result-v0`
 *   when the root carries an Evidence Result v0 in a disclosed member (the
 *   same test `isResultRoot` runs).
 * - `extensions`: every member of the bundle's `extensions` object that the
 *   core's reader accepts; a present block its reader declines is absent.
 */
export function describeContext(
  context: VerifiedBundleContext,
): PresentationDescriptor {
  const bundle = isPlainObject(context.bundle) ? context.bundle : {};
  const verified = bundleVerified(context.verification);
  const bundleKind =
    typeof bundle.bundle_kind === "string" ? bundle.bundle_kind : undefined;
  // Resolution refuses an unverified context before matching anything, so
  // nothing in an unverified bundle is read to describe it.
  if (!verified)
    return {
      verified,
      bundle_kind: bundleKind,
      profiles: new Set(),
      extensions: new Set(),
    };
  const profiles = new Set<string>();
  if (context.root !== undefined && context.recordIndex.has(context.root)) {
    const input = verifiedPayload(context, context.root, "agent_input");
    if (isPlainObject(input) && typeof input.spec_version === "string")
      profiles.add(`spec_version:${input.spec_version}`);
  }
  if (carriesResultDocument(context))
    profiles.add(`result_version:${RESULT_VERSION}`);
  const extensions = new Set<string>();
  if (isPlainObject(bundle.extensions))
    for (const kind of Object.keys(bundle.extensions)) {
      const reader = EXTENSION_READERS[kind];
      if (reader === undefined || reader(context.bundle)) extensions.add(kind);
    }
  return { verified, bundle_kind: bundleKind, profiles, extensions };
}

// ---------------------------------------------------------------------------
// Matching, the static test and resolution
// ---------------------------------------------------------------------------

const requiredProfiles = (m: PresentationManifest): readonly string[] =>
  m.requires.profiles ?? [];
const requiredExtensions = (m: PresentationManifest): readonly string[] =>
  m.requires.extensions?.required ?? [];
const forbiddenProfiles = (m: PresentationManifest): readonly string[] =>
  m.forbids?.profiles ?? [];
const forbiddenExtensions = (m: PresentationManifest): readonly string[] =>
  m.forbids?.extensions ?? [];

const profileKey = (token: string): string => token.split(":", 1)[0]!;

function onePerKey(tokens: Iterable<string>): boolean {
  const keys = new Set<string>();
  for (const token of tokens) {
    const key = profileKey(token);
    if (keys.has(key)) return false;
    keys.add(key);
  }
  return true;
}

/** Section 4.3 step 2: the declarative match, nothing else. */
export function manifestMatches(
  manifest: PresentationManifest,
  descriptor: PresentationDescriptor,
  audience: string,
  format: PresentationFormat,
): boolean {
  return (
    manifest.requires.bundle_kind === descriptor.bundle_kind &&
    requiredProfiles(manifest).every((t) => descriptor.profiles.has(t)) &&
    requiredExtensions(manifest).every((k) => descriptor.extensions.has(k)) &&
    !forbiddenProfiles(manifest).some((t) => descriptor.profiles.has(t)) &&
    !forbiddenExtensions(manifest).some((k) => descriptor.extensions.has(k)) &&
    (manifest.audiences.includes("*") ||
      manifest.audiences.includes(audience)) &&
    manifest.formats.includes(format)
  );
}

/**
 * Section 4.5: true exactly when some descriptor matches both manifests,
 * whatever their tiers (the caller compares tiers).
 */
export function manifestsCoMatchable(
  a: PresentationManifest,
  b: PresentationManifest,
): boolean {
  if (a.requires.bundle_kind !== b.requires.bundle_kind) return false;
  if (
    !a.audiences.includes("*") &&
    !b.audiences.includes("*") &&
    !a.audiences.some((x) => b.audiences.includes(x))
  )
    return false;
  if (!a.formats.some((f) => b.formats.includes(f))) return false;
  const reqP = new Set([...requiredProfiles(a), ...requiredProfiles(b)]);
  const reqE = new Set([...requiredExtensions(a), ...requiredExtensions(b)]);
  const forbP = [...forbiddenProfiles(a), ...forbiddenProfiles(b)];
  const forbE = [...forbiddenExtensions(a), ...forbiddenExtensions(b)];
  if (forbP.some((t) => reqP.has(t))) return false;
  if (forbE.some((k) => reqE.has(k))) return false;
  return onePerKey(reqP);
}

const MANIFEST_MEMBERS = new Set([
  "spec_version",
  "id",
  "trust_class",
  "requires",
  "forbids",
  "audiences",
  "formats",
  "fallback",
  "priority",
  "executable",
  "declarative",
]);
const MANIFEST_ID = /^[a-z0-9]+(\.[a-z0-9_-]+)+\/v[0-9]+$/u;
const PROFILE_TOKEN =
  /^(spec_version|result_version):[A-Za-z0-9][A-Za-z0-9._/@+-]*$/u;
const AUDIENCE = /^(\*|[a-z][a-z0-9_-]*)$/u;

/**
 * The structural rules of `$defs/PresentationManifest` a registry relies on,
 * plus the dead-manifest rule of section 4.5. The JSON Schema stays the full
 * definition; this refuses what would make resolution wrong.
 */
export function manifestProblems(manifest: PresentationManifest): string[] {
  const problems: string[] = [];
  const raw = manifest as unknown as Record<string, unknown>;
  if (!isPlainObject(raw)) return ["manifest is not an object"];
  for (const member of Object.keys(raw))
    if (!MANIFEST_MEMBERS.has(member))
      problems.push(`unknown member ${JSON.stringify(member)}`);
  if (manifest.spec_version !== PRESENTATION_MANIFEST_VERSION)
    problems.push(`spec_version is not ${PRESENTATION_MANIFEST_VERSION}`);
  if (typeof manifest.id !== "string" || !MANIFEST_ID.test(manifest.id))
    problems.push("id is not <dotted name>/v<major>");
  if (
    manifest.trust_class !== "trusted-executable" &&
    manifest.trust_class !== "declarative"
  )
    problems.push("trust_class is neither trusted-executable nor declarative");
  if (
    !isPlainObject(manifest.requires) ||
    typeof manifest.requires.bundle_kind !== "string"
  )
    problems.push("requires.bundle_kind is missing");
  for (const token of [
    ...requiredProfiles(manifest),
    ...forbiddenProfiles(manifest),
  ])
    if (!PROFILE_TOKEN.test(token))
      problems.push(`profile token ${JSON.stringify(token)} is malformed`);
  if (
    !Array.isArray(manifest.audiences) ||
    manifest.audiences.length === 0 ||
    manifest.audiences.some((a) => typeof a !== "string" || !AUDIENCE.test(a))
  )
    problems.push("audiences is not a non-empty list of audience tokens");
  if (
    !Array.isArray(manifest.formats) ||
    manifest.formats.length === 0 ||
    manifest.formats.some((f) => !PRESENTATION_FORMATS.includes(f))
  )
    problems.push("formats is not a non-empty list of html/fragment/embedded");
  if (typeof manifest.fallback !== "boolean")
    problems.push("fallback is not a boolean");
  else if (manifest.fallback && manifest.priority !== undefined)
    problems.push("a fallback carries no priority");
  else if (
    !manifest.fallback &&
    !(Number.isInteger(manifest.priority) && manifest.priority! >= 1)
  )
    problems.push("a specific module needs an integer priority >= 1");
  if (
    (manifest.trust_class === "trusted-executable") !==
    (manifest.executable !== undefined && manifest.declarative === undefined)
  )
    problems.push(
      "trusted-executable carries executable, declarative carries declarative",
    );
  // Dead manifests (section 4.5): they can never match.
  if (
    forbiddenProfiles(manifest).some((t) =>
      requiredProfiles(manifest).includes(t),
    )
  )
    problems.push("requires and forbids share a profile");
  if (
    forbiddenExtensions(manifest).some((k) =>
      requiredExtensions(manifest).includes(k),
    )
  )
    problems.push("requires and forbids share an extension");
  if (!onePerKey(requiredProfiles(manifest)))
    problems.push("requires two tokens of one profile key");
  return problems;
}

/**
 * Section 4.3 over an explicit module list, exactly. Exported so the
 * algorithm can be exercised without a registry's registration test.
 */
export async function resolveModules(
  modules: readonly PresentationModule[],
  descriptor: PresentationDescriptor,
  audience: string,
  format: PresentationFormat,
  canRender: (module: PresentationModule) => boolean | Promise<boolean>,
): Promise<PresentationResolution> {
  // 1. Verification gate: no manifest is matched, no module is called.
  if (!descriptor.verified) return { kind: "refusal" };
  // 2. Match.
  const matched = modules.filter((m) =>
    manifestMatches(m.manifest, descriptor, audience, format),
  );
  // 3. Specific tier, then 4. fallback tier. Ambiguity is decided on the
  // declarative match, before any canRender is called.
  for (const fallback of [false, true]) {
    const tier = matched.filter((m) => m.manifest.fallback === fallback);
    if (tier.length > 1)
      throw new PresentationAmbiguityError(
        tier.map((m) => m.manifest.id).sort(),
      );
    const only = tier[0];
    if (only !== undefined && (await canRender(only)))
      return { kind: "module", module: only };
  }
  // 5. Nothing.
  return { kind: "no-presentation" };
}

export class PresentationRegistry implements PresentationResolver {
  readonly #modules: PresentationModule[] = [];

  /**
   * Register a module. Refuses a malformed or dead manifest, a duplicate id,
   * and any module whose manifest some descriptor could match together with
   * an already registered module of the same tier (section 4.5).
   */
  register(module: PresentationModule): void {
    const manifest = module.manifest;
    const problems = manifestProblems(manifest);
    if (problems.length > 0)
      throw new PresentationRegistrationError(
        `manifest ${JSON.stringify(manifest?.id)} refused: ${problems.join("; ")}`,
      );
    for (const other of this.#modules) {
      if (other.manifest.id === manifest.id)
        throw new PresentationRegistrationError(
          `manifest ${manifest.id} is already registered`,
        );
      if (
        other.manifest.fallback === manifest.fallback &&
        manifestsCoMatchable(other.manifest, manifest)
      )
        throw new PresentationAmbiguityError(
          [other.manifest.id, manifest.id].sort(),
          `manifests ${other.manifest.id} and ${manifest.id} are both ${manifest.fallback ? "fallbacks" : "specific"} and one descriptor can match both; state precedence with forbids`,
        );
    }
    this.#modules.push(module);
  }

  /** Every registered module, in registration order (which decides nothing). */
  list(): readonly PresentationModule[] {
    return [...this.#modules];
  }

  /** Section 4.3: the one module for this context, audience and format. */
  resolve(
    context: VerifiedBundleContext,
    audience: string,
    format: PresentationFormat,
  ): Promise<PresentationResolution> {
    return resolveModules(
      this.#modules,
      describeContext(context),
      audience,
      format,
      (module) => module.canRender(context),
    );
  }
}
