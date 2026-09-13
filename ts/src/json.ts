import { createHash } from "node:crypto";

export type JsonPrimitive = null | boolean | string | number;
export type JsonValue =
  | JsonPrimitive
  | JsonValue[]
  | { [key: string]: JsonValue };

const utf8 = new TextDecoder("utf-8", { fatal: true });
const encoder = new TextEncoder();
const MAX_DEPTH = 1_000;
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

/** Decode strict JSON without losing number spelling or accepting duplicate names. */
export function decodeStrictJson(input: Uint8Array | string): ParsedJson {
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
  const parse = (depth: number): ParsedJson => {
    if (depth > MAX_DEPTH)
      throw new SyntaxError(`JSON nesting exceeds ${MAX_DEPTH}`);
    ws();
    const c = text[offset];
    if (c === '"') return parseString();
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
        if (seen.has(key))
          throw new SyntaxError(`duplicate object name ${JSON.stringify(key)}`);
        seen.add(key);
        ws();
        if (text[offset] !== ":")
          throw new SyntaxError(`':' expected at byte ${offset}`);
        offset += 1;
        value[key] = parse(depth + 1);
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
  if (depth > MAX_DEPTH)
    throw new TypeError(`JSON nesting exceeds ${MAX_DEPTH}`);
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

export function sha256Hex(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export function jsonDigest(value: unknown): string {
  return sha256Hex(jcs(value));
}

/** Vintage format-2 absent-field normalization. */
export function normalizeAbsent(value: ParsedJson): ParsedJson {
  if (Array.isArray(value)) return value.map(normalizeAbsent);
  const record = asJsonObject(value);
  if (record === undefined) return value;
  const result: Record<string, ParsedJson> = {};
  for (const [key, child] of Object.entries(record)) {
    const normalized = normalizeAbsent(child);
    if (normalized === null) continue;
    if (Array.isArray(normalized) && normalized.length === 0) continue;
    const normalizedObject = asJsonObject(normalized);
    if (
      normalizedObject !== undefined &&
      Object.keys(normalizedObject).length === 0
    )
      continue;
    result[key] = normalized;
  }
  return result;
}

/** Verification-only format-2 JSON-DIGEST. */
export function vintageJsonDigest(value: ParsedJson): string {
  return jsonDigest(normalizeAbsent(value));
}
