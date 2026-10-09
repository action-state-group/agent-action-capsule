import { decodeFragment, encodeFragment } from "./bundle.js";
import { isHex64 } from "./json.js";

/**
 * The presentation fragment payload and the share-side scoping step
 * (spec/presentation-builder-v0.md). No DOM, no network: it runs the same
 * in a builder and in a viewer page.
 *
 * The token is base64url (no padding) of the payload's JSON text, the same
 * model as capsule-viewer's fragment codec and the Evidence Bundle
 * permalink codec it reuses. A browser never sends the fragment to a
 * server, so the link needs no host to hold the data. The encoding is NOT a
 * security mechanism: the payload is encoded, not encrypted, and anyone
 * holding the link can read all of it. What an audience may see is decided
 * by {@link scopeDisclosures} before encoding.
 */

export const PRESENTATION_FRAGMENT_VERSION = "aac.presentation-fragment/v0";

/**
 * The longest URL this codec plans for: 1 MiB, the smallest limit among the
 * major browsers' documented URL limits (Chromium allows 2 MiB). A link
 * pasted into chat or email is often cut far shorter; pass a lower
 * `maxLength` for those.
 */
export const FRAGMENT_URL_MAX_LENGTH = 1_048_576;
/** Characters kept free for the viewer's address and the `#`. */
export const FRAGMENT_ADDRESS_ALLOWANCE = 2_048;
/** The longest token encoded or decoded: the URL limit less the allowance. */
export const FRAGMENT_TOKEN_MAX_LENGTH =
  FRAGMENT_URL_MAX_LENGTH - FRAGMENT_ADDRESS_ALLOWANCE;

export class FragmentTooLargeError extends Error {
  readonly length: number;
  readonly maxLength: number;
  constructor(length: number, maxLength: number, what = "fragment token") {
    super(
      `${what} is ${length} characters, over the ${maxLength}-character maximum; it is refused, never truncated. Share the offline .html instead.`,
    );
    this.name = "FragmentTooLargeError";
    this.length = length;
    this.maxLength = maxLength;
  }
}

export class FragmentDecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FragmentDecodeError";
  }
}

/**
 * Encode a JSON value as a fragment token with the Evidence Bundle
 * permalink codec (`encodeFragment` in bundle.ts; the "Fragment Codec"
 * section of draft-mih-zhang-agent-disclosure-bundle): the RFC 8785 JCS
 * text, UTF-8, base64url without padding. capsule-viewer's
 * `encode_fragment` writes the same token for the same JSON object read in
 * JCS member order whenever the JSON text is ASCII; for non-ASCII text it
 * writes `\uXXXX` escapes (Python's `ensure_ascii`) where this writes UTF-8.
 * Each decoder reads the other's tokens.
 */
export function encodeFragmentToken(value: unknown): string {
  return encodeFragment(value);
}

/**
 * Decode a fragment token (with or without its leading `#`) to the JSON
 * value it carries. A token over `maxLength` is refused before decoding.
 * Stricter than capsule-viewer's `decode_fragment` in one way: a character
 * outside the base64url alphabet is an error, where Python's lenient
 * decoder drops it.
 */
export function decodeFragmentToken(
  token: string,
  maxLength: number = FRAGMENT_TOKEN_MAX_LENGTH,
): unknown {
  const body = token.replace(/^#+/u, "");
  if (body.length > maxLength)
    throw new FragmentTooLargeError(body.length, maxLength);
  try {
    return decodeFragment(body);
  } catch (err) {
    throw new FragmentDecodeError(
      err instanceof Error && err.message === "fragment base64url"
        ? "fragment token has a character outside the base64url alphabet"
        : "fragment token is not UTF-8 JSON",
    );
  }
}

// ---------------------------------------------------------------------------
// The presentation fragment payload
// ---------------------------------------------------------------------------

export type PresentationDepth = "L0" | "L1" | "L2";
export const PRESENTATION_DEPTHS: readonly PresentationDepth[] = [
  "L0",
  "L1",
  "L2",
];

/** A wording pack as distributed: its exact text and its digest. */
export interface WordingPackInput {
  /** The pack's exact UTF-8 text. It is hashed as it is, never re-serialized. */
  readonly pack: string;
  /** Lowercase hex SHA-256 of the pack's UTF-8 bytes (`wording_sha256`). */
  readonly sha256: string;
}

/**
 * Everything the offline builder needs except the code it runs: the scoped
 * bundle, the audience, and the presentation-only settings. Code travels by
 * pin, so a viewer that holds the same runtime and modules can rebuild the
 * exact offline file, and one that does not refuses.
 */
export interface PresentationFragment {
  readonly fragment_version: typeof PRESENTATION_FRAGMENT_VERSION;
  readonly audience: string;
  /** The module id the builder resolved, or "auto". Informational. */
  readonly presentation: string;
  readonly depth?: PresentationDepth;
  readonly title?: string;
  readonly theme_css?: string;
  readonly wording?: WordingPackInput;
  readonly core_runtime_sha256: string;
  readonly module_sha256: readonly string[];
  /** The bundle as scoped for the audience, before encoding. */
  readonly bundle: unknown;
}

const FRAGMENT_MEMBERS = new Set([
  "fragment_version",
  "audience",
  "presentation",
  "depth",
  "title",
  "theme_css",
  "wording",
  "core_runtime_sha256",
  "module_sha256",
  "bundle",
]);

const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

/** Throws unless `value` is a well-formed presentation fragment payload. */
export function checkPresentationFragment(
  value: unknown,
): asserts value is PresentationFragment {
  const fail = (why: string): never => {
    throw new FragmentDecodeError(`presentation fragment: ${why}`);
  };
  if (!isObject(value)) fail("not a JSON object");
  const v = value as Record<string, unknown>;
  for (const key of Object.keys(v))
    if (!FRAGMENT_MEMBERS.has(key))
      fail(`unknown member ${JSON.stringify(key)}`);
  if (v.fragment_version !== PRESENTATION_FRAGMENT_VERSION)
    fail(`fragment_version is not ${PRESENTATION_FRAGMENT_VERSION}`);
  if (typeof v.audience !== "string" || v.audience === "")
    fail("audience is not a non-empty string");
  if (typeof v.presentation !== "string" || v.presentation === "")
    fail("presentation is not a non-empty string");
  if (
    v.depth !== undefined &&
    !PRESENTATION_DEPTHS.includes(v.depth as PresentationDepth)
  )
    fail("depth is not L0, L1 or L2");
  if (v.title !== undefined && typeof v.title !== "string")
    fail("title is not a string");
  if (v.theme_css !== undefined && typeof v.theme_css !== "string")
    fail("theme_css is not a string");
  if (v.wording !== undefined) {
    const w = v.wording;
    if (
      !isObject(w) ||
      Object.keys(w).some((k) => k !== "pack" && k !== "sha256") ||
      typeof w.pack !== "string" ||
      !isHex64(w.sha256)
    )
      fail("wording is not {pack, sha256}");
  }
  if (!isHex64(v.core_runtime_sha256))
    fail("core_runtime_sha256 is not a lowercase hex SHA-256");
  if (
    !Array.isArray(v.module_sha256) ||
    !v.module_sha256.every((pin) => isHex64(pin))
  )
    fail("module_sha256 is not a list of lowercase hex SHA-256 pins");
  if (!("bundle" in v)) fail("bundle is missing");
}

/**
 * Encode a presentation fragment payload. Refuses a token longer than
 * `maxLength` (at most {@link FRAGMENT_TOKEN_MAX_LENGTH}); with a
 * `viewerUrl`, also refuses a whole URL longer than
 * {@link FRAGMENT_URL_MAX_LENGTH}. Nothing is ever truncated.
 */
export function encodePresentationFragment(
  payload: PresentationFragment,
  options: { readonly maxLength?: number; readonly viewerUrl?: string } = {},
): { readonly fragment: string; readonly url?: string } {
  checkPresentationFragment(payload);
  const maxLength = options.maxLength ?? FRAGMENT_TOKEN_MAX_LENGTH;
  if (
    !Number.isInteger(maxLength) ||
    maxLength < 1 ||
    maxLength > FRAGMENT_TOKEN_MAX_LENGTH
  )
    throw new RangeError(
      `maxLength must be an integer from 1 to ${FRAGMENT_TOKEN_MAX_LENGTH}`,
    );
  const fragment = encodeFragmentToken(payload);
  if (fragment.length > maxLength)
    throw new FragmentTooLargeError(fragment.length, maxLength);
  if (options.viewerUrl === undefined) return { fragment };
  if (options.viewerUrl.includes("#"))
    throw new Error("viewerUrl must not already carry a fragment");
  const url = `${options.viewerUrl}#${fragment}`;
  if (url.length > FRAGMENT_URL_MAX_LENGTH)
    throw new FragmentTooLargeError(
      url.length,
      FRAGMENT_URL_MAX_LENGTH,
      "permalink URL",
    );
  return { fragment, url };
}

/** Decode and check a presentation fragment (leading `#` allowed). */
export function decodePresentationFragment(
  token: string,
  maxLength: number = FRAGMENT_TOKEN_MAX_LENGTH,
): PresentationFragment {
  const value = decodeFragmentToken(token, maxLength);
  checkPresentationFragment(value);
  return value;
}

// ---------------------------------------------------------------------------
// Scoping: what one audience may see, decided before anything is encoded
// ---------------------------------------------------------------------------

/** A disclosable member of a record. */
export type DisclosureMember = "agent_input" | "agent_output";

/**
 * An allow-list: capsule_id -> the members this audience may see. Every
 * disclosure not listed is removed, so the recipient's verifier reads it as
 * withheld. An empty object withholds everything.
 */
export type DisclosureScope = Readonly<
  Record<string, readonly DisclosureMember[]>
>;

/**
 * The bundle with every disclosure outside `scope` removed. Scoping only
 * removes: it never adds, rewrites or reorders anything, and the records,
 * checkpoints and proofs are untouched, so the result verifies wherever the
 * input did, with the removed members reported as withheld.
 *
 * This is the share builder's step, done before encoding. A viewer never
 * scopes: it shows the bundle it was given. Scoping is not a security
 * mechanism either; it decides what is put in the artifact, and whoever
 * holds the artifact can read everything in it.
 */
export function scopeDisclosures(
  bundle: unknown,
  scope: DisclosureScope,
): unknown {
  if (!isObject(bundle)) return bundle;
  const supplied = bundle.disclosures;
  if (!isObject(supplied)) return { ...bundle };
  const kept: Record<string, unknown> = {};
  for (const [id, members] of Object.entries(supplied)) {
    const allowed = Object.hasOwn(scope, id) ? scope[id]! : [];
    if (!isObject(members) || allowed.length === 0) continue;
    const entry: Record<string, unknown> = {};
    for (const [member, value] of Object.entries(members))
      if (allowed.includes(member as DisclosureMember)) entry[member] = value;
    if (Object.keys(entry).length > 0) kept[id] = entry;
  }
  return { ...bundle, disclosures: kept };
}
