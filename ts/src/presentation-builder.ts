import {
  buildVerifiedBundleContext,
  isVerifiedBundleContext,
  type VerifiedBundleContext,
} from "./bundle.js";
import {
  DEFAULT_EVIDENCE_GRAPH_BOOTSTRAP,
  emitEvidenceGraphHtml,
  escapeJsonForHtmlScript,
  type EmitterModule,
} from "./emitter.js";
import { createPresentationRegistry } from "./evidence-graph-view.js";
import { isHex64, jcs, sha256Hex } from "./json.js";
import {
  bundleVerified,
  PresentationAmbiguityError,
  type PresentationFormat,
  type PresentationResolver,
} from "./presentation-registry.js";
import {
  decodePresentationFragment,
  encodePresentationFragment,
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
 * One builder, three packagings (spec/presentation-builder-v0.md):
 * `buildPresentation(context, {presentation, audience, format})` scopes the
 * bundle for the audience, resolves the one module the registry selects,
 * and packages the same scoped bundle and settings as
 *
 * - `html`: one self-contained offline file with its per-page CSP;
 * - `fragment`: a permalink token for the URL fragment, which a browser
 *   never sends; the offline file is rebuilt from it byte for byte by
 *   {@link offlineHtmlFromFragment};
 * - `embedded`: a mount function for a host element.
 *
 * For one (bundle, audience) the three show the same module, the same
 * verified content and the same verification state (contract I4).
 */

export class PresentationBuildError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PresentationBuildError";
  }
}

/** The core runtime (the browser IIFE) and, optionally, its pin. */
export interface PresentationRuntime {
  readonly code: string;
  /** Lowercase hex SHA-256 of `code`; checked when given. */
  readonly sha256?: string;
}

export interface BuildPresentationOptions {
  /** `"auto"`, or the module id the caller expects; a mismatch is an error. */
  readonly presentation: string;
  /** The audience token; `"*"` is no particular audience. */
  readonly audience: string;
  readonly format: PresentationFormat;
  /** The core runtime; required for `html` and `fragment`. */
  readonly runtime?: PresentationRuntime;
  /** Digest-pinned module-slot scripts the page runs after the runtime. */
  readonly modules?: readonly EmitterModule[];
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
  /** `fragment` only: lower the token limit (never above the maximum). */
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
  runtime: PresentationRuntime,
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
  runtime: PresentationRuntime | undefined,
  format: PresentationFormat,
): PresentationRuntime {
  if (runtime === undefined)
    throw new PresentationBuildError(`format ${format} needs the core runtime`);
  return runtime;
}

/**
 * Build one presentation of a bundle for one audience in one format.
 * `input` is a verified context or a bundle (verified here).
 *
 * Steps, in order: scope the bundle for the audience (only when `disclose`
 * is given, and never for a bundle that did not verify, since removing a
 * disclosure could hide the failure); verify the scoped bundle; resolve the
 * module through the registry (an ambiguity is an error; an explicit
 * `presentation` that the registry does not select is an error); package.
 */
export async function buildPresentation(
  input: VerifiedBundleContext | unknown,
  options: BuildPresentationOptions,
): Promise<BuiltPresentation> {
  const { audience, format } = options;
  if (typeof audience !== "string" || audience === "")
    throw new PresentationBuildError("audience is required");
  if (format !== "html" && format !== "fragment" && format !== "embedded")
    throw new PresentationBuildError(
      `format ${JSON.stringify(format)} is not html, fragment or embedded`,
    );
  if (
    options.depth !== undefined &&
    !PRESENTATION_DEPTHS.includes(options.depth)
  )
    throw new PresentationBuildError("depth is not L0, L1 or L2");
  if (options.wording !== undefined) await checkWordingPack(options.wording);

  const given = isVerifiedBundleContext(input)
    ? input
    : await buildVerifiedBundleContext(input);
  let context = given;
  if (options.disclose !== undefined) {
    if (!bundleVerified(given.verification))
      throw new PresentationBuildError(
        "refusing to scope a bundle that did not verify: removing a disclosure could hide the failure",
      );
    context = await buildVerifiedBundleContext(
      scopeDisclosures(given.bundle, options.disclose),
      given.countersigners === undefined
        ? {}
        : { countersigners: given.countersigners },
    );
  }
  const bundle = context.bundle;

  const registry = options.registry ?? createPresentationRegistry();
  let resolution;
  try {
    resolution = await registry.resolve(context, audience, format);
  } catch (err) {
    if (err instanceof PresentationAmbiguityError)
      throw new PresentationBuildError(
        `presentation is ambiguous for this bundle: ${err.ids.join(", ")}`,
      );
    throw err;
  }
  const module =
    resolution.kind === "module" ? resolution.module.manifest.id : null;
  if (options.presentation !== "auto" && options.presentation !== module)
    throw new PresentationBuildError(
      `presentation ${options.presentation} was requested but the registry selected ${module ?? resolution.kind} for audience ${audience} and format ${format}`,
    );
  const common: BuiltCommon = {
    audience,
    module,
    resolution: resolution.kind,
    bundle,
  };
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
      presentation: module ?? "auto",
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
      ...(options.maxFragmentLength === undefined
        ? {}
        : { maxLength: options.maxFragmentLength }),
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

/**
 * The hand-back: rebuild the exact offline .html a fragment was made from.
 * The fragment carries pins, not code; the runtime and modules given here
 * must match them, or this refuses rather than build a different file.
 * It never scopes: the fragment's bundle was scoped before encoding.
 */
export async function offlineHtmlFromFragment(
  token: string,
  runtime: PresentationRuntime,
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
  runtime: PresentationRuntime,
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
