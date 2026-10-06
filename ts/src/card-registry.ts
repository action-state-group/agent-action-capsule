/**
 * Card registry: which renderer draws a verified Result v0 bundle.
 *
 * A bundle selects a card by carrying a card extension: an `extensions`
 * member whose block is a JSON object with `enabled: true` (the opt-in marker
 * `outcome-report/v1` and `eu-ai-act-compliance/v1` already use). The member
 * name is the card's kind. A bundle can only NAME a card; the code that draws
 * it is registered by the host page, never supplied by the bundle.
 *
 * Dispatch (resolveCard):
 * - no card extension: the generic Result page, no notice;
 * - one or more declared kinds: the FIRST REGISTERED kind (registration
 *   order, not the bundle's member order) that the bundle declares and whose
 *   reader accepts its block is drawn; every other declared kind gets a
 *   notice. Registration order is used because the bundle's member order is
 *   not a producer signal: a JCS-canonical bundle sorts its members, so the
 *   viewer's fixed order is the only deterministic one;
 * - a declared kind this registry does not know: the generic Result page
 *   plus a notice naming the kind. Never a failure, never silently another
 *   card's view;
 * - a known kind whose block the card's reader rejects: the same fallback,
 *   with a notice saying the block could not be read.
 *
 * The boundary: a card's render receives only the outputs of verification
 * (the Result root model and the bundle verification result), the bundle's
 * verified document with its `extensions` removed, the three `presentation/v1`
 * chrome members, and the typed settings its own reader extracted from its
 * own block. Every one of those is a deep-frozen copy (frozenCopy below), so
 * a card can neither alter a verification result nor reach the shell's own
 * objects. The verification banner and verification page are drawn by the
 * shell from the verifier's result, outside the card (evidence-graph-view.ts,
 * card-view.ts).
 *
 * This module is DOM-free; the default registry and the DOM-side guards live
 * in card-view.ts.
 */
import type { BundleVerificationResult } from "./bundle.js";
import type { PresentationBlock } from "./presentation.js";
import type { ResultRoot } from "./result-root.js";

/** The bundle as verified, minus `extensions` (outside the signed records). */
export interface VerifiedBundle {
  readonly document: Readonly<Record<string, unknown>>;
  readonly verification: BundleVerificationResult;
}

/**
 * A card definition. `readSettings` is handed ONLY the card's own extension
 * block and must return typed values (strings, numbers, booleans, arrays and
 * objects of those) or `undefined` to reject the block. Strings it returns
 * are display text: a renderer writes them with textContent, never as
 * markup. `render` returns the card's view; the shell mounts it after the
 * verification banner and before the verification page.
 */
export interface CardDefinition<S> {
  /** Short human name used in notices, e.g. "outcome report". */
  readonly label: string;
  /**
   * Whether the shell draws the banner and verification page in this card's
   * look. Class names only: the banner's words and data attributes are the
   * shell's and identical either way.
   */
  readonly styledChrome?: boolean;
  readSettings(block: Readonly<Record<string, unknown>>): S | undefined;
  render(
    result: ResultRoot,
    bundle: VerifiedBundle,
    chrome: PresentationBlock,
    settings: S,
  ): HTMLElement | Promise<HTMLElement>;
}

/** What the shell hands a selected card: everything already frozen. */
export interface CardInput {
  readonly result: ResultRoot;
  readonly bundle: VerifiedBundle;
  readonly chrome: PresentationBlock;
}

export interface SelectedCard {
  readonly kind: string;
  readonly label: string;
  readonly styledChrome: boolean;
  /** Draws the card from frozen verified inputs and its own frozen settings. */
  render(input: CardInput): Promise<HTMLElement>;
}

export type CardNoticeReason =
  | "unrecognized-kind"
  | "unreadable-block"
  | "not-selected"
  | "not-a-result-root"
  | "card-failed";

export interface CardNotice {
  readonly reason: CardNoticeReason;
  readonly kind: string;
  /** The card drawn instead, for `not-selected`. */
  readonly selected?: string;
}

export interface CardResolution {
  /** The card to draw; absent means the generic Result page. */
  readonly card?: SelectedCard;
  readonly notices: readonly CardNotice[];
}

export interface CardRegistry {
  /** Register a card under its extension kind. Throws on a duplicate kind. */
  registerCard<S>(kind: string, definition: CardDefinition<S>): void;
  /** Registered kinds, in registration (= precedence) order. */
  kinds(): readonly string[];
  /** Dispatch a bundle to a card (see the module comment for the rules). */
  resolveCard(bundle: unknown): CardResolution;
}

/**
 * Kinds that are extension kinds but never cards: the chrome block (whose
 * rule is that it never selects or carries a renderer) and the registered or
 * in-repo data extensions. Registering any of them as a card throws.
 */
export const NON_CARD_EXTENSION_KINDS: readonly string[] = Object.freeze([
  "presentation/v1",
  "producer-key/v1",
  "composed/v1",
  "disclosure-policy-decisions/v1",
  "sd-jwt-issuers/v1",
  "evidencebook/payloads",
]);

const KIND = /^(x-)?[a-z0-9][a-z0-9._-]*\/v[1-9][0-9]*$/u;
/** A declared kind is bundle text: shown capped, never as markup. */
export const MAX_NOTICE_KIND_LENGTH = 120;

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/**
 * The card kinds a bundle declares: every `extensions` member whose block is
 * an object with `enabled: true`, sorted (member order is not a signal).
 */
export function readCardDeclarations(bundle: unknown): readonly string[] {
  const extensions = object(object(bundle)?.extensions);
  if (extensions === undefined) return [];
  return Object.keys(extensions)
    .filter((kind) => !NON_CARD_EXTENSION_KINDS.includes(kind))
    .filter((kind) => object(extensions[kind])?.enabled === true)
    .sort();
}

function noticeKind(kind: string): string {
  return kind.length > MAX_NOTICE_KIND_LENGTH
    ? `${kind.slice(0, MAX_NOTICE_KIND_LENGTH)}…`
    : kind;
}

class ReadOnlyMap<K, V> extends Map<K, V> {
  #sealed = false;
  constructor(entries: Iterable<readonly [K, V]>) {
    super();
    for (const [key, value] of entries) super.set(key, value);
    this.#sealed = true;
    Object.freeze(this);
  }
  override set(key: K, value: V): this {
    if (this.#sealed) throw new TypeError("read-only verified data");
    return super.set(key, value);
  }
  override delete(): boolean {
    throw new TypeError("read-only verified data");
  }
  override clear(): void {
    throw new TypeError("read-only verified data");
  }
}

class ReadOnlySet<T> extends Set<T> {
  #sealed = false;
  constructor(values: Iterable<T>) {
    super();
    for (const value of values) super.add(value);
    this.#sealed = true;
    Object.freeze(this);
  }
  override add(value: T): this {
    if (this.#sealed) throw new TypeError("read-only verified data");
    return super.add(value);
  }
  override delete(): boolean {
    throw new TypeError("read-only verified data");
  }
  override clear(): void {
    throw new TypeError("read-only verified data");
  }
}

/**
 * A deep, frozen copy: what a card receives in place of the shell's own
 * objects. Writing to it throws (ES modules are strict), and even a bypass
 * would only touch the copy, never the object the shell draws the banner and
 * verification page from. Functions are dropped: verified data is data.
 */
export function frozenCopy<T>(value: T): T {
  return copy(value, new Map()) as T;
}

function copy(value: unknown, seen: Map<object, unknown>): unknown {
  if (value === null || typeof value !== "object")
    return typeof value === "function" ? undefined : value;
  const known = seen.get(value);
  if (known !== undefined) return known;
  if (ArrayBuffer.isView(value)) {
    // A typed array cannot be frozen; a copy is all a card ever gets.
    const bytes = value as unknown as Uint8Array;
    return bytes.slice();
  }
  if (value instanceof Map) {
    const out = new ReadOnlyMap<unknown, unknown>(
      [...(value as Map<unknown, unknown>)].map(
        ([k, v]) => [copy(k, seen), copy(v, seen)] as const,
      ),
    );
    seen.set(value, out);
    return out;
  }
  if (value instanceof Set) {
    const out = new ReadOnlySet<unknown>(
      [...(value as Set<unknown>)].map((v) => copy(v, seen)),
    );
    seen.set(value, out);
    return out;
  }
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    seen.set(value, out);
    for (const item of value) out.push(copy(item, seen));
    return Object.freeze(out);
  }
  const out: Record<string, unknown> = {};
  seen.set(value, out);
  for (const [key, item] of Object.entries(value)) {
    if (typeof item === "function") continue;
    out[key] = copy(item, seen);
  }
  return Object.freeze(out);
}

/** The verified bundle a card sees: frozen, `extensions` removed. */
export function verifiedBundle(
  bundle: unknown,
  verification: BundleVerificationResult,
): VerifiedBundle {
  const top = object(bundle) ?? {};
  const document = Object.fromEntries(
    Object.entries(top).filter(([key]) => key !== "extensions"),
  );
  return Object.freeze({
    document: frozenCopy(document),
    verification: frozenCopy(verification),
  });
}

interface Entry {
  readonly kind: string;
  readonly label: string;
  readonly styledChrome: boolean;
  /** Reads the block; on success returns the card bound to its settings. */
  prepare(
    block: Readonly<Record<string, unknown>>,
  ): ((input: CardInput) => Promise<HTMLElement>) | undefined;
}

export function createCardRegistry(): CardRegistry {
  const entries: Entry[] = [];
  return {
    registerCard<S>(kind: string, definition: CardDefinition<S>): void {
      if (!KIND.test(kind))
        throw new TypeError(
          `card kind must look like "name/v1" (or "x-name/v1"): ${kind}`,
        );
      if (NON_CARD_EXTENSION_KINDS.includes(kind))
        throw new TypeError(`${kind} is not a card extension kind`);
      if (entries.some((entry) => entry.kind === kind))
        throw new TypeError(`card kind already registered: ${kind}`);
      entries.push({
        kind,
        label: definition.label,
        styledChrome: definition.styledChrome === true,
        prepare(block) {
          // The reader sees only a frozen copy of this card's own block; its
          // output is frozen too before render ever sees it.
          const read = definition.readSettings(frozenCopy(block));
          if (read === undefined) return undefined;
          const settings = frozenCopy(read);
          return async (input) =>
            definition.render(
              input.result,
              input.bundle,
              input.chrome,
              settings,
            );
        },
      });
    },
    kinds(): readonly string[] {
      return Object.freeze(entries.map((entry) => entry.kind));
    },
    resolveCard(bundle: unknown): CardResolution {
      const declared = readCardDeclarations(bundle);
      if (declared.length === 0) return { notices: [] };
      const extensions = object(object(bundle)?.extensions) ?? {};
      const notices: CardNotice[] = [];
      let card: SelectedCard | undefined;
      for (const entry of entries) {
        if (!declared.includes(entry.kind)) continue;
        if (card !== undefined) {
          notices.push({
            reason: "not-selected",
            kind: entry.kind,
            selected: card.kind,
          });
          continue;
        }
        const render = entry.prepare(object(extensions[entry.kind]) ?? {});
        if (render === undefined) {
          notices.push({ reason: "unreadable-block", kind: entry.kind });
          continue;
        }
        card = {
          kind: entry.kind,
          label: entry.label,
          styledChrome: entry.styledChrome,
          render,
        };
      }
      for (const kind of declared)
        if (!entries.some((entry) => entry.kind === kind))
          notices.push({ reason: "unrecognized-kind", kind: noticeKind(kind) });
      return card === undefined ? { notices } : { card, notices };
    },
  };
}
