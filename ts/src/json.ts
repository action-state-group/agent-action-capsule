import { hexToBytes, producerPublicKeySpki } from "./producer-envelope-wire.js";
import { MAX_NESTING_DEPTH } from "./nesting.js";
import { sha256 } from "./sha256.js";

export type JsonPrimitive = null | boolean | string | number;
export type JsonValue =
  | JsonPrimitive
  | JsonValue[]
  | { [key: string]: JsonValue };

const utf8 = new TextDecoder("utf-8", { fatal: true });
const encoder = new TextEncoder();
const numberToken = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/;

/** A JSON number whose original spelling must survive parsing for validation. */
export class JsonNumber {
  public constructor(public readonly raw: string) {}
}

/** JCS cannot render a floating-point value in the AAC integer-only profile. */
export class JcsFloatError extends TypeError {
  public constructor(public readonly path: string) {
    super(`float at ${path}`);
    this.name = "TypeError";
  }
}

/** JCS cannot render an integer outside JavaScript's exactly safe range. */
export class JcsUnsafeIntegerError extends TypeError {
  public constructor(public readonly path: string) {
    super(`unsafe integer at ${path}`);
    this.name = "TypeError";
  }
}

export type ParsedJson =
  | null
  | boolean
  | string
  | JsonNumber
  | ParsedJson[]
  | { [key: string]: ParsedJson };

/** Distinguish JSON objects from arrays and lossless number wrappers. */
export function asJsonObject(
  value: ParsedJson | undefined,
): Record<string, ParsedJson> | undefined {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !(value instanceof JsonNumber)
    ? value
    : undefined;
}
/** AAC SHA-256 identifiers use exactly 64 lowercase hexadecimal digits. */
export function isHex64(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
}

/**
 * Add an own enumerable member. Plain assignment would treat a member named
 * `__proto__` as the object's prototype and drop it from the value.
 */
export function setMember<T>(
  target: Record<string, T>,
  key: string,
  value: T,
): void {
  Object.defineProperty(target, key, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

export interface DecodeJsonOptions {
  /**
   * Keep the last value of a repeated object name instead of rejecting it, as
   * the Go, Python and Rust Bundle fragment decoders do.
   */
  readonly lastDuplicateWins?: boolean;
}

/** Decode strict JSON without losing number spelling or accepting duplicate names. */
export function decodeStrictJson(
  input: Uint8Array | string,
  options: DecodeJsonOptions = {},
): ParsedJson {
  let text: string;
  try {
    text = typeof input === "string" ? input : utf8.decode(input);
  } catch (error) {
    throw new SyntaxError(`invalid UTF-8: ${String(error)}`);
  }
  let offset = 0;
  const ws = (): void => {
    while (
      text[offset] === " " ||
      text[offset] === "\t" ||
      text[offset] === "\n" ||
      text[offset] === "\r"
    )
      offset += 1;
  };
  /** One value, enclosed by `depth` objects and arrays. */
  const parse = (depth: number): ParsedJson => {
    ws();
    const c = text[offset];
    if (c === '"') return parseString();
    if ((c === "{" || c === "[") && depth >= MAX_NESTING_DEPTH)
      throw new SyntaxError(`JSON nesting exceeds ${MAX_NESTING_DEPTH}`);
    if (c === "{") {
      offset += 1;
      const value: Record<string, ParsedJson> = {};
      const seen = new Set<string>();
      ws();
      if (text[offset] === "}") {
        offset += 1;
        return value;
      }
      while (true) {
        ws();
        if (text[offset] !== '"')
          throw new SyntaxError(`object name expected at byte ${offset}`);
        const key = parseString();
        if (seen.has(key) && !options.lastDuplicateWins)
          throw new SyntaxError(`duplicate object name ${JSON.stringify(key)}`);
        seen.add(key);
        ws();
        if (text[offset] !== ":")
          throw new SyntaxError(`':' expected at byte ${offset}`);
        offset += 1;
        setMember(value, key, parse(depth + 1));
        ws();
        if (text[offset] === "}") {
          offset += 1;
          return value;
        }
        if (text[offset] !== ",")
          throw new SyntaxError(`',' expected at byte ${offset}`);
        offset += 1;
      }
    }
    if (c === "[") {
      offset += 1;
      const value: ParsedJson[] = [];
      ws();
      if (text[offset] === "]") {
        offset += 1;
        return value;
      }
      while (true) {
        value.push(parse(depth + 1));
        ws();
        if (text[offset] === "]") {
          offset += 1;
          return value;
        }
        if (text[offset] !== ",")
          throw new SyntaxError(`',' expected at byte ${offset}`);
        offset += 1;
      }
    }
    for (const [token, value] of [
      ["true", true],
      ["false", false],
      ["null", null],
    ] as const) {
      if (text.startsWith(token, offset)) {
        offset += token.length;
        return value;
      }
    }
    const match = numberToken.exec(text.slice(offset));
    if (match !== null) {
      offset += match[0].length;
      return new JsonNumber(match[0]);
    }
    throw new SyntaxError(`JSON value expected at byte ${offset}`);
  };
  const parseString = (): string => {
    const start = offset;
    offset += 1;
    while (offset < text.length) {
      const c = text[offset];
      if (c === '"') {
        offset += 1;
        const value = JSON.parse(text.slice(start, offset)) as string;
        for (let i = 0; i < value.length; i += 1) {
          const unit = value.charCodeAt(i);
          if (unit >= 0xd800 && unit <= 0xdbff) {
            const next = value.charCodeAt(++i);
            if (!(next >= 0xdc00 && next <= 0xdfff))
              throw new SyntaxError("unpaired high surrogate");
          } else if (unit >= 0xdc00 && unit <= 0xdfff)
            throw new SyntaxError("unpaired low surrogate");
        }
        return value;
      }
      if (c === "\\") {
        offset += 2;
        continue;
      }
      if (c === undefined || c.charCodeAt(0) < 0x20)
        throw new SyntaxError(`invalid JSON string at byte ${offset}`);
      offset += 1;
    }
    throw new SyntaxError("unterminated JSON string");
  };
  const value = parse(0);
  ws();
  if (offset !== text.length)
    throw new SyntaxError(`trailing data at byte ${offset}`);
  return value;
}

function assertString(value: string): void {
  for (let i = 0; i < value.length; i += 1) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff))
        throw new TypeError("unpaired high surrogate");
    } else if (unit >= 0xdc00 && unit <= 0xdfff)
      throw new TypeError("unpaired low surrogate");
  }
}

function renderString(value: string): string {
  assertString(value);
  return JSON.stringify(value);
}

function render(
  value: unknown,
  path: string,
  seen: Set<object>,
  depth: number,
): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return renderString(value);
  if (value instanceof JsonNumber) {
    if (/[.eE]/u.test(value.raw)) throw new JcsFloatError(path);
    const integer = BigInt(value.raw);
    if (
      integer > BigInt(Number.MAX_SAFE_INTEGER) ||
      integer < BigInt(Number.MIN_SAFE_INTEGER)
    )
      throw new JcsUnsafeIntegerError(path);
    return integer === 0n ? "0" : value.raw;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isInteger(value))
      throw new JcsFloatError(path);
    if (!Number.isSafeInteger(value)) throw new JcsUnsafeIntegerError(path);
    return Object.is(value, -0) ? "0" : String(value);
  }
  if (typeof value !== "object" || value === undefined)
    throw new TypeError(`unsupported JSON value at ${path}`);
  if (depth >= MAX_NESTING_DEPTH)
    throw new TypeError(`JSON nesting exceeds ${MAX_NESTING_DEPTH}`);
  if (seen.has(value)) throw new TypeError(`cyclic JSON value at ${path}`);
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i += 1)
        if (!(i in value)) throw new TypeError(`sparse array at ${path}[${i}]`);
      return `[${value.map((item, i) => render(item, `${path}[${i}]`, seen, depth + 1)).join(",")}]`;
    }
    const proto = Object.getPrototypeOf(value) as object | null;
    if (proto !== Object.prototype && proto !== null)
      throw new TypeError(`non-plain object at ${path}`);
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys.map((key) => `${renderString(key)}:${render(record[key], `${path}.${key}`, seen, depth + 1)}`).join(",")}}`;
  } finally {
    seen.delete(value);
  }
}

/** RFC 8785 JCS bytes for the AAC integer-only profile. */
export function jcs(value: unknown): Uint8Array {
  return encoder.encode(render(value, "$", new Set<object>(), 0));
}

/**
 * Where this runtime's SHA-256 comes from: "webcrypto" (SubtleCrypto, which
 * a browser gives only a secure context), "fallback" (the plain
 * implementation in sha256.ts, e.g. a page in a non-secure or opaque
 * origin such as some apps' attachment viewers), or "none" (neither, which happens only when the
 * fallback is switched off with {@link setSha256FallbackForTesting}).
 */
export type DigestCapability = "webcrypto" | "fallback" | "none";

/**
 * Thrown in place of a verification result when the runtime has no SHA-256:
 * nothing could be checked, which is not a failed check.
 */
export class Sha256UnavailableError extends Error {
  public constructor() {
    super("no SHA-256 implementation is available in this runtime");
    this.name = "Sha256UnavailableError";
  }
}

let sha256Fallback = true;

/**
 * Switch the plain SHA-256 off (false) or back on (true). A test hook: it
 * stands in for a runtime with neither WebCrypto nor the fallback, so the
 * "unable to verify in this viewer" state can be exercised.
 */
export function setSha256FallbackForTesting(enabled: boolean): void {
  sha256Fallback = enabled;
}

function webCrypto(): SubtleCrypto | undefined {
  const subtle = (globalThis as { crypto?: { subtle?: SubtleCrypto } }).crypto
    ?.subtle;
  return typeof subtle?.digest === "function" ? subtle : undefined;
}

export function digestCapability(): DigestCapability {
  if (webCrypto() !== undefined) return "webcrypto";
  return sha256Fallback ? "fallback" : "none";
}

// RFC 8032 section 7.1, test 1: a valid Ed25519 public key to probe with.
const PROBE_KEY =
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const ed25519Probes = new WeakMap<SubtleCrypto, boolean>();

/**
 * Whether this runtime can check an Ed25519 signature: it has SubtleCrypto
 * (the only Ed25519 verifier here) and that SubtleCrypto accepts an Ed25519
 * key. The answer is cached per SubtleCrypto. A signature this runtime
 * cannot check is not checked in this viewer, never failed.
 */
export async function probeEd25519(): Promise<boolean> {
  const subtle = webCrypto();
  if (subtle === undefined) return false;
  let supported = ed25519Probes.get(subtle);
  if (supported === undefined) {
    try {
      await subtle.importKey(
        "spki",
        producerPublicKeySpki(hexToBytes(PROBE_KEY)) as BufferSource,
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      supported = true;
    } catch (error) {
      supported =
        (error as { name?: unknown } | null)?.name !== "NotSupportedError";
    }
    ed25519Probes.set(subtle, supported);
  }
  return supported;
}

/**
 * The synchronous reading of {@link probeEd25519}: false without
 * SubtleCrypto or once a probe found no Ed25519, true otherwise.
 * `buildVerifiedBundleContext` runs the probe, so a reader of a built
 * context gets the probed answer.
 */
export function ed25519Available(): boolean {
  const subtle = webCrypto();
  return subtle !== undefined && ed25519Probes.get(subtle) !== false;
}

/**
 * SHA-256 with the platform WebCrypto implementation, or the plain one
 * where the page has no SubtleCrypto. Throws {@link Sha256UnavailableError}
 * when neither is available.
 */
export async function sha256Hex(value: Uint8Array): Promise<string> {
  const subtle = webCrypto();
  let digest: Uint8Array;
  if (subtle !== undefined)
    digest = new Uint8Array(
      await subtle.digest("SHA-256", value as BufferSource),
    );
  else if (sha256Fallback) digest = sha256(value);
  else throw new Sha256UnavailableError();
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

export async function jsonDigest(value: unknown): Promise<string> {
  return sha256Hex(jcs(value));
}
