import {
  buildVerifiedBundleContext,
  isVerifiedBundleContext,
  type VerifiedBundleContext,
} from "./bundle.js";
import {
  DEFAULT_EVIDENCE_GRAPH_BOOTSTRAP,
  emitEvidenceGraphHtml,
  emitStaticEvidenceGraphHtml,
  escapeJsonForHtmlScript,
  type EmitterModule,
} from "./emitter.js";
import {
  createPresentationRegistry,
  renderEvidenceGraph,
} from "./evidence-graph-view.js";
import { isHex64, jcs, sha256Hex } from "./json.js";
import {
  bundleVerified,
  manifestProblems,
  PresentationAmbiguityError,
  presentationRefusalReason,
  PresentationRegistry,
  REFERENCE_PRESENTATION_RUNTIME,
  type PresentationFormat,
  type PresentationManifest,
  type PresentationRefusalReason,
  type PresentationResolution,
  type PresentationResolver,
  type PresentationRuntime,
} from "./presentation-registry.js";
import {
  decodePresentationFragment,
  encodePresentationFragment,
  FRAGMENT_TOKEN_DEFAULT_BUDGET,
  FragmentTooLargeError,
  PRESENTATION_DEPTHS,
  PRESENTATION_FRAGMENT_VERSION,
  scopeDisclosures,
  type DisclosureScope,
  type PresentationDepth,
  type PresentationFragment,
  type WordingPackInput,
} from "./presentation-fragment.js";
import { mountPresentation } from "./presentation-mount.js";

/**
 * One builder, four packagings (spec/presentation-builder-v0.md):
 * `buildPresentation(context, {presentation, audience, format})` scopes the
 * bundle for the audience, resolves the one module the registry selects,
 * and packages the same scoped bundle and settings as
 *
 * - `html`: one self-contained offline file with its per-page CSP;
 * - `fragment`: a permalink token for the URL fragment, which a browser
 *   never sends; the offline file is rebuilt from it byte for byte by
 *   {@link offlineHtmlFromFragment};
 * - `embedded`: a mount function for a host element;
 * - `static`: the page rendered at build time into HTML that runs no
 *   script at all, and says it is not self-verifying.
 *
 * A packaging can be unavailable for a bundle (a fragment over the link
 * budget, for one); {@link availablePackagings} reports which, and why,
 * without packaging anything. For one (bundle, audience) every SUPPORTED
 * packaging shows the same module, the same verified content and the same
 * verification state (contract I4).
 */

export class PresentationBuildError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PresentationBuildError";
  }
}

/** A packaging target: the three contract formats, and the static page. */
export type PackagingTarget = PresentationFormat | "static";
export const PACKAGING_TARGETS: readonly PackagingTarget[] = Object.freeze([
  "html",
  "fragment",
  "embedded",
  "static",
]);

/** Why a packaging target is unavailable for one (bundle, audience). */
export type PackagingUnavailableReason =
  | {
      /** The token, or the whole URL, is over the link budget. */
      readonly code: "fragment-too-large";
      readonly subject: string;
      readonly length: number;
      readonly limit: number;
      readonly message: string;
    }
  | {
      /** `html` and `fragment` need the core runtime, and none was given. */
      readonly code: "runtime-missing";
      readonly message: string;
    }
  | {
      /** `static` renders at build time and needs a DOM `document`. */
      readonly code: "no-document";
      readonly message: string;
    }
  | {
      /** The rendered page carries a script, so it cannot be static. */
      readonly code: "static-carries-script";
      readonly message: string;
    };

/** One target's availability: available, or unavailable with its reason. */
export type PackagingAvailability =
  | { readonly target: PackagingTarget; readonly available: true }
  | {
      readonly target: PackagingTarget;
      readonly available: false;
      readonly reason: PackagingUnavailableReason;
    };

/**
 * A direct build of a packaging that is unavailable. (A fragment over the
 * budget keeps throwing {@link FragmentTooLargeError}, as it always has.)
 */
export class PackagingUnavailableError extends PresentationBuildError {
  readonly reason: PackagingUnavailableReason;
  constructor(reason: PackagingUnavailableReason) {
    super(reason.message);
    this.name = "PackagingUnavailableError";
    this.reason = reason;
  }
}

/**
 * What the static page says, word for word. It runs no code, so it shows
 * the verification result the builder computed and cannot re-verify.
 */
export const STATIC_NOT_SELF_VERIFYING =
  "Not self-verifying; verify the bundle separately.";
/** The static page's second statement, before the build-time result. */
export const STATIC_BUILD_TIME_STATEMENT =
  "This page runs no code. It shows the verification result computed when it was built and cannot re-verify anything in your browser.";

/**
 * The core runtime script (the browser IIFE) and, optionally, its pin. Not
 * the presentation runtime's ABI declaration (`PresentationRuntime`, contract
 * section 3.2): this is the code the page carries.
 */
export interface CoreRuntimeScript {
  readonly code: string;
  /** Lowercase hex SHA-256 of `code`; checked when given. */
  readonly sha256?: string;
}

/**
 * A module-slot script the page inlines. With its `manifest`, the builder
 * checks the module against the page's runtime before writing anything
 * (contract section 3.2); the manifest must pin this script
 * (`executable.carrier` `module-slot`, `script_sha256` equal to `sha256`).
 */
export interface PresentationModuleScript extends EmitterModule {
  readonly manifest?: PresentationManifest;
}

/**
 * The builder was asked to put into a page a module the page's runtime
 * would refuse (contract section 3.2). No page is written; the error names
 * both sides: the module (id, `presentation_api`, `runtime_min`) and the
 * runtime's declaration.
 */
export class PresentationModuleRefusedError extends PresentationBuildError {
  readonly module: {
    readonly id: string;
    readonly presentation_api: string;
    readonly runtime_min: string;
  };
  readonly reason: PresentationRefusalReason;
  readonly runtime: PresentationRuntime;
  constructor(
    module: {
      readonly id: string;
      readonly presentation_api: string;
      readonly runtime_min: string;
    },
    reason: PresentationRefusalReason,
    runtime: PresentationRuntime,
  ) {
    const apis =
      runtime.presentationApis.length === 0
        ? "no presentation API"
        : runtime.presentationApis.join(", ");
    super(
      `presentation module ${module.id} (presentation_api ${module.presentation_api}, runtime_min ${module.runtime_min}) would be refused by the page's runtime (implements ${apis}; runtime version ${runtime.runtimeVersion}): ${reason}; no page is written`,
    );
    this.name = "PresentationModuleRefusedError";
    this.module = Object.freeze({
      id: module.id,
      presentation_api: module.presentation_api,
      runtime_min: module.runtime_min,
    });
    this.reason = reason;
    this.runtime = runtime;
  }
}

export interface BuildPresentationOptions {
  /** `"auto"`, or the module id the caller expects; a mismatch is an error. */
  readonly presentation: string;
  /** The audience token; `"*"` is no particular audience. */
  readonly audience: string;
  readonly format: PackagingTarget;
  /** The core runtime; required for `html` and `fragment`. */
  readonly runtime?: CoreRuntimeScript;
  /**
   * Digest-pinned module-slot scripts the page runs after the runtime. A
   * script given with its manifest is refused at build time when the page's
   * runtime would refuse the module.
   */
  readonly modules?: readonly PresentationModuleScript[];
  /**
   * The registry the builder resolves with; the built-ins when omitted.
   * It must hold the modules whose code `modules` carries.
   */
  readonly registry?: PresentationResolver;
  /**
   * What this audience may see (an allow-list of disclosures). Omitted, the
   * bundle's disclosures are packaged as they are.
   */
  readonly disclose?: DisclosureScope;
  readonly depth?: PresentationDepth;
  /** Page title; otherwise the wording pack's `page.title`; otherwise the default. */
  readonly title?: string;
  /** Theme CSS for the THEME_SLOT (presentation only). */
  readonly themeCss?: string;
  readonly wording?: WordingPackInput;
  /**
   * `fragment` only: the token budget. Omitted, it is
   * FRAGMENT_TOKEN_DEFAULT_BUDGET; it may be lowered, or raised up to
   * FRAGMENT_TOKEN_MAX_LENGTH, never above.
   */
  readonly maxFragmentLength?: number;
  /** `fragment` only: the viewer address the token is appended to. */
  readonly viewerUrl?: string;
}

interface BuiltCommon {
  readonly audience: string;
  /** The module the registry selected, or null for a refusal or no presentation. */
  readonly module: string | null;
  readonly resolution: "module" | "refusal" | "no-presentation";
  /** The bundle as scoped for the audience: what every packaging carries. */
  readonly bundle: unknown;
}

export type BuiltPresentation =
  | (BuiltCommon & { readonly format: "html"; readonly html: string })
  | (BuiltCommon & {
      readonly format: "fragment";
      readonly fragment: string;
      readonly url?: string;
      readonly payload: PresentationFragment;
    })
  | (BuiltCommon & {
      readonly format: "embedded";
      mount(element: HTMLElement): Promise<void>;
    })
  | (BuiltCommon & {
      readonly format: "static";
      readonly html: string;
      /** The verification result the builder computed and the page states. */
      readonly verification: "verified" | "failed";
    });

/** The wording key the builder reads for the page title. */
export const WORDING_TITLE_KEY = "page.title";
const WORDING_PACK_VERSION = "aac.wording-pack/v0";
const WORDING_KEY = /^[a-z0-9][a-z0-9._-]*$/u;
const LOCALE = /^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$/u;

/**
 * Check a wording pack against its digest and its shape (contract 7.4) and
 * return its entries. The bytes are hashed exactly as given.
 */
export async function checkWordingPack(
  wording: WordingPackInput,
): Promise<Readonly<Record<string, string>>> {
  if (!isHex64(wording.sha256))
    throw new PresentationBuildError(
      "wording sha256 is not a lowercase hex SHA-256",
    );
  const digest = await sha256Hex(new TextEncoder().encode(wording.pack));
  if (digest !== wording.sha256)
    throw new PresentationBuildError(
      "wording pack bytes do not hash to its wording_sha256",
    );
  let pack: unknown;
  try {
    pack = JSON.parse(wording.pack);
  } catch {
    throw new PresentationBuildError("wording pack is not JSON");
  }
  const p = pack as Record<string, unknown>;
  const entries = p?.entries as Record<string, unknown> | undefined;
  if (
    pack === null ||
    typeof pack !== "object" ||
    Array.isArray(pack) ||
    Object.keys(p).some(
      (k) => !["wording_pack_version", "id", "locale", "entries"].includes(k),
    ) ||
    p.wording_pack_version !== WORDING_PACK_VERSION ||
    typeof p.id !== "string" ||
    typeof p.locale !== "string" ||
    !LOCALE.test(p.locale) ||
    entries === null ||
    typeof entries !== "object" ||
    Array.isArray(entries) ||
    Object.keys(entries).length === 0 ||
    Object.entries(entries).some(
      ([k, v]) => !WORDING_KEY.test(k) || typeof v !== "string" || v === "",
    )
  )
    throw new PresentationBuildError(
      `wording pack is not an ${WORDING_PACK_VERSION} object`,
    );
  return entries as Record<string, string>;
}

/** The offline file's settings: everything but the code. */
interface OfflineSettings {
  readonly bundle: unknown;
  readonly audience: string;
  readonly depth: PresentationDepth | undefined;
  readonly title: string | undefined;
  readonly themeCss: string | undefined;
  readonly wording: WordingPackInput | undefined;
}

// The one offline packager: the direct path and the fragment hand-back both
// end here, so equal settings give equal bytes. The default settings
// (audience "*", nothing else) give exactly emitEvidenceGraphHtml's page.
async function packageOffline(
  settings: OfflineSettings,
  runtime: CoreRuntimeScript,
  modules: readonly EmitterModule[],
): Promise<string> {
  const entries =
    settings.wording === undefined
      ? undefined
      : await checkWordingPack(settings.wording);
  const title =
    settings.title !== undefined && settings.title !== ""
      ? settings.title
      : entries?.[WORDING_TITLE_KEY];
  const isDefault =
    settings.audience === "*" &&
    settings.depth === undefined &&
    settings.wording === undefined;
  const renderOptions: Record<string, unknown> = {
    audience: settings.audience,
    format: "html",
  };
  if (settings.depth !== undefined) renderOptions.depth = settings.depth;
  if (settings.wording !== undefined)
    renderOptions.wording = {
      pack: settings.wording.pack,
      sha256: settings.wording.sha256,
    };
  const bootstrap = isDefault
    ? DEFAULT_EVIDENCE_GRAPH_BOOTSTRAP
    : `renderEvidenceGraph(window.__BUNDLE__, document.getElementById("app"), undefined, ${escapeJsonForHtmlScript(new TextDecoder().decode(jcs(renderOptions)))});`;
  return emitEvidenceGraphHtml(settings.bundle, runtime.code, {
    ...(title === undefined ? {} : { title }),
    ...(settings.themeCss === undefined ? {} : { themeCss: settings.themeCss }),
    ...(runtime.sha256 === undefined
      ? {}
      : { coreRuntimeSha256: runtime.sha256 }),
    modules,
    bootstrap,
  });
}

function requireRuntime(
  runtime: CoreRuntimeScript | undefined,
  format: PackagingTarget,
): CoreRuntimeScript {
  if (runtime === undefined)
    throw new PackagingUnavailableError({
      code: "runtime-missing",
      message: `format ${format} needs the core runtime`,
    });
  return runtime;
}

/** Everything every packaging shares: scoped, verified and resolved once. */
interface Prepared {
  readonly common: BuiltCommon;
  readonly context: VerifiedBundleContext;
  readonly registry: PresentationResolver;
}

// Check the settings, then scope and verify the scoped bundle: once for
// every packaging.
async function scopeAndVerify(
  input: VerifiedBundleContext | unknown,
  options: Omit<BuildPresentationOptions, "format">,
): Promise<VerifiedBundleContext> {
  const { audience } = options;
  if (typeof audience !== "string" || audience === "")
    throw new PresentationBuildError("audience is required");
  if (
    options.depth !== undefined &&
    !PRESENTATION_DEPTHS.includes(options.depth)
  )
    throw new PresentationBuildError("depth is not L0, L1 or L2");
  if (options.wording !== undefined) await checkWordingPack(options.wording);

  const given = isVerifiedBundleContext(input)
    ? input
    : await buildVerifiedBundleContext(input);
  if (options.disclose === undefined) return given;
  if (!bundleVerified(given.verification))
    throw new PresentationBuildError(
      "refusing to scope a bundle that did not verify: removing a disclosure could hide the failure",
    );
  return buildVerifiedBundleContext(
    scopeDisclosures(given.bundle, options.disclose),
    given.countersigners === undefined
      ? {}
      : { countersigners: given.countersigners },
  );
}

/**
 * The page's runtime declaration (contract section 3.2): the registry's,
 * when the builder resolves with a PresentationRegistry (the default one is
 * the reference runtime, which the core runtime script also is); otherwise
 * the reference runtime's.
 */
function pageRuntime(registry: PresentationResolver): PresentationRuntime {
  return registry instanceof PresentationRegistry
    ? registry.runtime
    : REFERENCE_PRESENTATION_RUNTIME;
}

// Contract section 3.2: a builder asked to put into a page a module the
// page's runtime would refuse writes no page and names both sides. Two ways
// to ask: inline a module-slot script whose manifest the runtime refuses,
// or request by id a module the registry holds as refused (or that matched
// this resolution and was refused).
function refuseRefusedModules(
  options: Omit<BuildPresentationOptions, "format">,
  registry: PresentationResolver,
  resolution: PresentationResolution,
): void {
  const runtime = pageRuntime(registry);
  for (const script of options.modules ?? []) {
    const manifest = script.manifest;
    if (manifest === undefined) continue;
    const problems = manifestProblems(manifest);
    if (problems.length > 0)
      throw new PresentationBuildError(
        `module manifest ${JSON.stringify(manifest.id)} is malformed: ${problems.join("; ")}`,
      );
    if (
      manifest.executable?.carrier !== "module-slot" ||
      manifest.executable.script_sha256 !== script.sha256
    )
      throw new PresentationBuildError(
        `module manifest ${manifest.id} does not pin this module-slot script (sha256 ${script.sha256})`,
      );
    const reason = presentationRefusalReason(manifest, runtime);
    if (reason !== undefined)
      throw new PresentationModuleRefusedError(manifest, reason, runtime);
  }
  if (options.presentation === "auto") return;
  const refused = [
    ...(resolution.kind === "refusal" ? [] : resolution.refused),
    ...(registry instanceof PresentationRegistry ? registry.refused() : []),
  ].find((refusal) => refusal.id === options.presentation);
  if (refused !== undefined)
    throw new PresentationModuleRefusedError(refused, refused.reason, runtime);
}

// Resolve for one contract format. The static page is the html page
// rendered at build time, so it is resolved, and rendered, as html.
async function resolveFor(
  context: VerifiedBundleContext,
  options: Omit<BuildPresentationOptions, "format">,
  format: PresentationFormat,
): Promise<Prepared> {
  const { audience } = options;
  const registry = options.registry ?? createPresentationRegistry();
  let resolution: PresentationResolution;
  try {
    resolution = await registry.resolve(context, audience, format);
  } catch (err) {
    if (err instanceof PresentationAmbiguityError)
      throw new PresentationBuildError(
        `presentation is ambiguous for this bundle: ${err.ids.join(", ")}`,
      );
    throw err;
  }
  refuseRefusedModules(options, registry, resolution);
  const module =
    resolution.kind === "module" ? resolution.module.manifest.id : null;
  if (options.presentation !== "auto" && options.presentation !== module)
    throw new PresentationBuildError(
      `presentation ${options.presentation} was requested but the registry selected ${module ?? resolution.kind} for audience ${audience} and format ${format}`,
    );
  return {
    common: {
      audience,
      module,
      resolution: resolution.kind,
      bundle: context.bundle,
    },
    context,
    registry,
  };
}

const contractFormat = (target: PackagingTarget): PresentationFormat =>
  target === "static" ? "html" : target;

/**
 * Build one presentation of a bundle for one audience in one packaging.
 * `input` is a verified context or a bundle (verified here).
 *
 * Steps, in order: scope the bundle for the audience (only when `disclose`
 * is given, and never for a bundle that did not verify, since removing a
 * disclosure could hide the failure); verify the scoped bundle; resolve the
 * module through the registry (an ambiguity is an error; an explicit
 * `presentation` that the registry does not select is an error); package.
 *
 * A packaging that is unavailable throws: {@link FragmentTooLargeError} for
 * a fragment over its budget, {@link PackagingUnavailableError} otherwise.
 * Ask {@link availablePackagings} first to learn which are available.
 */
export async function buildPresentation(
  input: VerifiedBundleContext | unknown,
  options: BuildPresentationOptions,
): Promise<BuiltPresentation> {
  const { format } = options;
  if (!PACKAGING_TARGETS.includes(format))
    throw new PresentationBuildError(
      `format ${JSON.stringify(format)} is not html, fragment, embedded or static`,
    );
  const context = await scopeAndVerify(input, options);
  const prepared = await resolveFor(context, options, contractFormat(format));
  return packageAs(prepared, format, options);
}

/**
 * Report, for one (bundle, audience) and these settings, which packaging
 * targets are available and why each other one is not, without returning
 * any packaging: an unusable link is never handed out. Errors of the
 * request itself (no audience, a bad wording pack, an ambiguous registry,
 * scoping a bundle that did not verify) are thrown as buildPresentation
 * throws them, since no packaging of it exists.
 *
 * Available here means buildPresentation succeeds for that target with the
 * same settings: every target is packaged and the result discarded.
 */
export async function availablePackagings(
  input: VerifiedBundleContext | unknown,
  options: Omit<BuildPresentationOptions, "format">,
): Promise<readonly PackagingAvailability[]> {
  const context = await scopeAndVerify(input, options);
  const out: PackagingAvailability[] = [];
  for (const target of PACKAGING_TARGETS) {
    const prepared = await resolveFor(context, options, contractFormat(target));
    try {
      await packageAs(prepared, target, options);
      out.push({ target, available: true });
    } catch (err) {
      if (err instanceof FragmentTooLargeError)
        out.push({
          target,
          available: false,
          reason: {
            code: "fragment-too-large",
            subject: err.subject,
            length: err.length,
            limit: err.maxLength,
            message: err.message,
          },
        });
      else if (err instanceof PackagingUnavailableError)
        out.push({ target, available: false, reason: err.reason });
      else throw err;
    }
  }
  return out;
}

async function packageAs(
  prepared: Prepared,
  format: PackagingTarget,
  options: Omit<BuildPresentationOptions, "format">,
): Promise<BuiltPresentation> {
  const { common, registry } = prepared;
  const { audience, bundle } = common;
  const modules = options.modules ?? [];

  if (format === "html") {
    const html = await packageOffline(
      {
        bundle,
        audience,
        depth: options.depth,
        title: options.title,
        themeCss: options.themeCss,
        wording: options.wording,
      },
      requireRuntime(options.runtime, format),
      modules,
    );
    return { ...common, format, html };
  }

  if (format === "fragment") {
    const runtime = requireRuntime(options.runtime, format);
    const runtimePin = await sha256Hex(new TextEncoder().encode(runtime.code));
    if (runtime.sha256 !== undefined && runtime.sha256 !== runtimePin)
      throw new PresentationBuildError(
        "browser IIFE does not match its SHA-256 pin",
      );
    const payload: PresentationFragment = {
      fragment_version: PRESENTATION_FRAGMENT_VERSION,
      audience,
      presentation: common.module ?? "auto",
      ...(options.depth === undefined ? {} : { depth: options.depth }),
      ...(options.title === undefined ? {} : { title: options.title }),
      ...(options.themeCss === undefined
        ? {}
        : { theme_css: options.themeCss }),
      ...(options.wording === undefined
        ? {}
        : {
            wording: {
              pack: options.wording.pack,
              sha256: options.wording.sha256,
            },
          }),
      core_runtime_sha256: runtimePin,
      module_sha256: modules.map((m) => m.sha256),
      bundle,
    };
    const encoded = encodePresentationFragment(payload, {
      maxLength: options.maxFragmentLength ?? FRAGMENT_TOKEN_DEFAULT_BUDGET,
      ...(options.viewerUrl === undefined
        ? {}
        : { viewerUrl: options.viewerUrl }),
    });
    return {
      ...common,
      format,
      fragment: encoded.fragment,
      ...(encoded.url === undefined ? {} : { url: encoded.url }),
      payload,
    };
  }

  if (format === "static") {
    const page = await packageStatic(prepared, options);
    return { ...common, format, ...page };
  }

  return {
    ...common,
    format,
    mount: (element: HTMLElement) =>
      mountPresentation(element, {
        bundle,
        audience,
        format: "embedded",
        ...(options.depth === undefined ? {} : { depth: options.depth }),
        ...(options.wording === undefined ? {} : { wording: options.wording }),
        registry,
      }),
  };
}

const escapeText = (value: string): string =>
  value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&#34;");

/**
 * The static page: render the scoped bundle at build time exactly as the
 * offline file renders it in the reader's browser (same bundle, audience,
 * html format, depth, wording and registry), then write the markup with no
 * script. The page states that it is not self-verifying and gives the
 * verification result the builder computed.
 */
async function packageStatic(
  prepared: Prepared,
  options: Omit<BuildPresentationOptions, "format">,
): Promise<{ html: string; verification: "verified" | "failed" }> {
  if (typeof document === "undefined")
    throw new PackagingUnavailableError({
      code: "no-document",
      message:
        "format static renders at build time and needs a DOM document (in node, a jsdom document as globalThis.document)",
    });
  const { common, context, registry } = prepared;
  const root = document.createElement("div");
  // From the bundle, as the offline file does: the page there verifies the
  // bundle it carries and names no countersigner, so this does the same.
  await renderEvidenceGraph(common.bundle, root, undefined, {
    audience: common.audience,
    format: "html",
    ...(options.depth === undefined ? {} : { depth: options.depth }),
    ...(options.wording === undefined ? {} : { wording: options.wording }),
    registry,
  });
  const verification = bundleVerified(context.verification)
    ? "verified"
    : "failed";
  const shown = [...root.querySelectorAll("[data-verify]")].map((e) =>
    e.getAttribute("data-verify"),
  );
  if (shown.length !== 1 || shown[0] !== verification)
    throw new Error(
      "the rendered verification state differs from the builder's",
    );
  const all = [...root.querySelectorAll("*")];
  if (
    all.some(
      (e) =>
        e.localName === "script" ||
        [...e.attributes].some((a) => a.name.toLowerCase().startsWith("on")),
    )
  )
    throw new PackagingUnavailableError({
      code: "static-carries-script",
      message:
        "the rendered page carries a script element or an event-handler attribute, so it cannot be packaged as static",
    });
  const appStyles = all
    .filter((e) => e.localName === "style")
    .map((e) => e.textContent ?? "");
  const appStyleAttributes = all
    .map((e) => e.getAttribute("style"))
    .filter((v): v is string => v !== null);

  const entries =
    options.wording === undefined
      ? undefined
      : await checkWordingPack(options.wording);
  const title =
    options.title !== undefined && options.title !== ""
      ? options.title
      : entries?.[WORDING_TITLE_KEY];
  const noticeHtml =
    `<aside class="aac-static-notice" data-static-notice="not-self-verifying" data-built-verification="${verification}">` +
    `<p><strong>${escapeText(STATIC_NOT_SELF_VERIFYING)}</strong></p>` +
    `<p>${escapeText(STATIC_BUILD_TIME_STATEMENT)}</p>` +
    `<p>Verification result when this page was built: <strong>${verification === "verified" ? "verified" : "did not verify"}</strong>.</p>` +
    `</aside>`;
  const html = emitStaticEvidenceGraphHtml(
    { appHtml: root.innerHTML, appStyles, appStyleAttributes, noticeHtml },
    {
      ...(title === undefined ? {} : { title }),
      ...(options.themeCss === undefined ? {} : { themeCss: options.themeCss }),
    },
  );
  return { html, verification };
}

/**
 * The hand-back: rebuild the exact offline .html a fragment was made from.
 * The fragment carries pins, not code; the runtime and modules given here
 * must match them, or this refuses rather than build a different file.
 * It never scopes: the fragment's bundle was scoped before encoding.
 */
export async function offlineHtmlFromFragment(
  token: string,
  runtime: CoreRuntimeScript,
  modules: readonly EmitterModule[] = [],
  maxLength?: number,
): Promise<string> {
  const payload = decodePresentationFragment(token, maxLength);
  const runtimePin = await sha256Hex(new TextEncoder().encode(runtime.code));
  if (runtimePin !== payload.core_runtime_sha256)
    throw new PresentationBuildError(
      "this runtime is not the one the fragment was built with",
    );
  const pins = modules.map((m) => m.sha256);
  if (
    pins.length !== payload.module_sha256.length ||
    pins.some((pin, i) => pin !== payload.module_sha256[i])
  )
    throw new PresentationBuildError(
      "these modules are not the ones the fragment was built with",
    );
  return packageOffline(
    {
      bundle: payload.bundle,
      audience: payload.audience,
      depth: payload.depth,
      title: payload.title,
      themeCss: payload.theme_css,
      wording: payload.wording,
    },
    { code: runtime.code, sha256: runtimePin },
    modules,
  );
}

const FRAGMENT_VIEWER_MARKER = {
  aac_fragment_viewer: PRESENTATION_FRAGMENT_VERSION,
};
/** The fragment viewer's bootstrap. */
export const FRAGMENT_VIEWER_BOOTSTRAP =
  'EvidenceGraph.mountPresentationFragment(location.hash, document.getElementById("app"));';

/**
 * A serverless fragment viewer: an offline page, with the same shell and
 * CSP, whose data is the URL fragment it is opened with. Open it as
 * `viewer.html#<token>`; nothing is fetched. It applies no theme CSS from
 * the fragment (its CSP admits only the styles hashed into it); the theme
 * comes back in the offline file {@link offlineHtmlFromFragment} rebuilds.
 */
export function buildFragmentViewerHtml(
  runtime: CoreRuntimeScript,
  modules: readonly EmitterModule[] = [],
): string {
  return emitEvidenceGraphHtml(FRAGMENT_VIEWER_MARKER, runtime.code, {
    ...(runtime.sha256 === undefined
      ? {}
      : { coreRuntimeSha256: runtime.sha256 }),
    modules,
    bootstrap: FRAGMENT_VIEWER_BOOTSTRAP,
  });
}
