import { jcs, JsonNumber, sha256Hex } from "./json.js";
import {
  CONTENT_TYPE,
  equalBytes,
  hex64,
  hexToBytes,
  producerEnvelopeSigningBytes,
  producerPublicKeySpki,
} from "./producer-envelope-wire.js";

export interface EnvelopeFinding {
  readonly code: string;
  readonly detail: string;
}

export interface EnvelopeVerificationResult {
  readonly ok: boolean;
  readonly findings: readonly EnvelopeFinding[];
  readonly capsuleId: string;
  readonly publicKey?: Uint8Array;
}

class Reader {
  public offset = 0;
  public constructor(private readonly data: Uint8Array) {}
  public byte(): number {
    const value = this.data[this.offset++];
    if (value === undefined) throw new SyntaxError("truncated CBOR");
    return value;
  }
  public length(major: number): number {
    const first = this.byte();
    if (first >>> 5 !== major) throw new SyntaxError("unexpected CBOR type");
    return Number(this.argument(first & 31));
  }
  public bytes(): Uint8Array {
    return this.take(this.length(2));
  }
  private take(length: number): Uint8Array {
    const end = this.offset + length;
    if (end > this.data.length) throw new SyntaxError("truncated CBOR bytes");
    const value = this.data.slice(this.offset, end);
    this.offset = end;
    return value;
  }
  /**
   * A definite-length argument of any width in its shortest form, refusing
   * indefinite lengths and an argument a narrower head could carry.
   */
  private argument(add: number): bigint {
    if (add < 24) return BigInt(add);
    const width =
      add === 24 ? 1 : add === 25 ? 2 : add === 26 ? 4 : add === 27 ? 8 : 0;
    if (width === 0)
      throw new SyntaxError("unsupported or indefinite CBOR length");
    let value = 0n;
    for (let i = 0; i < width; i += 1)
      value = (value << 8n) | BigInt(this.byte());
    if (value < [24n, 1n << 8n, 1n << 16n, 1n << 32n][add - 24]!)
      throw new SyntaxError("CBOR argument is not in its shortest form");
    return value;
  }
  /**
   * One header value, typed only as far as the envelope checks need: integers,
   * text and byte strings keep their CBOR type, so a float or a boolean never
   * compares equal to an integer label or algorithm. Anything else is kept
   * only as an opaque value identity, for map-key equality. Every item is held to the profile's encoding
   * rules: the shortest form of each argument and float, unique map keys, and
   * no tag, which only the outer COSE_Sign1 carries.
   */
  public item(depth = 0): HeaderValue {
    if (depth > 8) throw new SyntaxError("CBOR nesting too deep");
    const first = this.byte(),
      major = first >>> 5,
      add = first & 31;
    if (major === 7) {
      // Simple values 0-23 inline, 24 with a one-byte value of at least 32,
      // then half, single and double floats. 28-30 are reserved and 31 is a
      // break, which a definite-length map never contains.
      if (add >= 28) throw new SyntaxError("reserved or break CBOR value");
      const start = this.offset - 1;
      if (add === 24 && this.byte() < 32)
        throw new SyntaxError("non-preferred CBOR simple value");
      if (add > 24) {
        const raw = this.take(add === 25 ? 2 : add === 26 ? 4 : 8);
        const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
        if (
          add === 26
            ? notShortest(view.getFloat32(0), fitsHalf)
            : add === 27 &&
              notShortest(view.getFloat64(0), (v) => Math.fround(v) === v)
        )
          throw new SyntaxError("CBOR float is not in its shortest form");
      }
      return { opaque: `s${this.data.subarray(start, this.offset).join()}` };
    }
    const argument = this.argument(add);
    if (major === 0 || major === 1)
      return { int: major === 0 ? argument : -1n - argument };
    const length = Number(argument);
    if (major === 2) return this.take(length);
    if (major === 3) return utf8.decode(this.take(length));
    if (major === 6)
      throw new SyntaxError("only the outer COSE_Sign1 may carry a CBOR tag");
    const entries: string[] = [];
    const keys = new Set<string>();
    for (let i = 0; i < length; i += 1) {
      const entry = identity(this.item(depth + 1));
      if (major === 4) entries.push(entry);
      else {
        if (keys.has(entry)) throw new SyntaxError("duplicate CBOR map key");
        keys.add(entry);
        entries.push(JSON.stringify([entry, identity(this.item(depth + 1))]));
      }
    }
    // Map identity ignores entry order, as CBOR map equality does.
    if (major === 5) entries.sort();
    return { opaque: JSON.stringify([major === 4 ? "a" : "m", entries]) };
  }
}

/** A NaN, or a value a narrower float encodes exactly, is not shortest. */
function notShortest(value: number, fitsNarrower: (v: number) => boolean) {
  return Number.isNaN(value) || fitsNarrower(value);
}

/** Whether a float is exactly representable in IEEE 754 half precision. */
function fitsHalf(value: number): boolean {
  const magnitude = Math.abs(value);
  if (magnitude === 0 || magnitude === Infinity) return true;
  if (magnitude > 65504) return false;
  // Normal halves (at least 2^-14) carry 11 significant bits; subnormals are
  // multiples of 2^-24. Every float32 is a normal float64, so its exponent
  // field is exact.
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, magnitude);
  const exponent = ((view.getUint16(0) >>> 4) & 0x7ff) - 1023;
  return Number.isInteger(
    magnitude * 2 ** (exponent >= -14 ? 10 - exponent : 24),
  );
}

type HeaderValue =
  | { readonly int: bigint }
  | string
  | Uint8Array
  | { readonly opaque: string };

/** A string equal for two items exactly when they are the same CBOR value. */
function identity(value: HeaderValue): string {
  if (typeof value === "string") return `t${value}`;
  if (value instanceof Uint8Array) return `b${value.join()}`;
  return "int" in value ? `i${value.int}` : value.opaque;
}
// ignoreBOM: a leading U+FEFF is part of the signed text, not a marker to drop.
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Decode the protected header map: definite length, integer labels only, each
 * label once, no trailing bytes. These match the Go and Python decoders, which
 * reject a non-integer or repeated label as a malformed envelope.
 */
function protectedHeaderMap(data: Uint8Array): Map<bigint, HeaderValue> {
  const reader = new Reader(data);
  const pairs = reader.length(5);
  if (pairs > 16) throw new SyntaxError("protected header has too many labels");
  const headers = new Map<bigint, HeaderValue>();
  for (let i = 0; i < pairs; i += 1) {
    const label = reader.item(1);
    if (typeof label !== "object" || !("int" in label))
      throw new SyntaxError("protected header label MUST be an integer");
    if (headers.has(label.int))
      throw new SyntaxError("duplicate protected header label");
    headers.set(label.int, reader.item(1));
  }
  if (reader.offset !== data.length)
    throw new SyntaxError("trailing CBOR data in protected header");
  return headers;
}

/** Verify an attached AAC Producer Envelope with platform WebCrypto. */
export async function verifyProducerEnvelope(
  capsuleId: string,
  data: Uint8Array,
): Promise<EnvelopeVerificationResult> {
  const fail = (code: string, detail: string): EnvelopeVerificationResult => ({
    ok: false,
    findings: [{ code, detail }],
    capsuleId,
  });
  if (!hex64.test(capsuleId))
    return fail(
      "capsule_id_malformed",
      "capsule_id MUST be 64 lowercase hexadecimal characters",
    );
  if (data.length > 4096)
    return fail(
      "envelope_too_large",
      `producer envelope is ${data.length} bytes; maximum is 4096`,
    );
  try {
    const reader = new Reader(data);
    if (reader.byte() !== 0xd2 || reader.length(4) !== 4)
      throw new SyntaxError(
        "top-level value MUST be tagged COSE_Sign1 with four array elements",
      );
    const protectedBytes = reader.bytes();
    if (reader.byte() !== 0xa0)
      throw new SyntaxError("unprotected header MUST be an empty map");
    const payload = reader.bytes();
    const signature = reader.bytes();
    if (reader.offset !== data.length)
      throw new SyntaxError("trailing CBOR data");
    const protectedHeaders = protectedHeaderMap(protectedBytes);
    // Same order as Go and Python, so one malformed header yields one code.
    const algorithm = protectedHeaders.get(1n);
    if (
      typeof algorithm !== "object" ||
      !("int" in algorithm) ||
      algorithm.int !== -8n
    )
      return fail(
        "envelope_algorithm_mismatch",
        "protected alg (label 1) MUST be EdDSA (-8)",
      );
    if (protectedHeaders.get(3n) !== CONTENT_TYPE)
      return fail(
        "envelope_content_type_mismatch",
        `protected content type MUST be ${CONTENT_TYPE}`,
      );
    const publicKey = protectedHeaders.get(4n);
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32)
      return fail(
        "envelope_kid_invalid",
        "protected kid (label 4) MUST be the raw 32-byte Ed25519 public key",
      );
    if (protectedHeaders.size !== 3)
      return fail(
        "envelope_protected_headers_invalid",
        "protected header MUST contain exactly alg, content type, and kid",
      );
    if (!equalBytes(payload, hexToBytes(capsuleId)))
      return fail(
        "envelope_payload_mismatch",
        "attached payload MUST equal the raw 32-byte Capsule ID",
      );
    if (signature.length !== 64)
      return fail(
        "envelope_signature_invalid",
        "Ed25519 signature MUST be 64 bytes",
      );
    const key = await globalThis.crypto.subtle.importKey(
      "spki",
      producerPublicKeySpki(publicKey) as BufferSource,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    if (
      !(await globalThis.crypto.subtle.verify(
        { name: "Ed25519" },
        key,
        signature as BufferSource,
        producerEnvelopeSigningBytes(protectedBytes, payload) as BufferSource,
      ))
    )
      return fail(
        "envelope_signature_invalid",
        "Ed25519 signature verification failed",
      );
    return {
      ok: true,
      findings: [],
      capsuleId,
      publicKey: Uint8Array.from(publicKey),
    };
  } catch (error) {
    return fail("envelope_malformed", String(error));
  }
}

/**
 * A record's producer signature: `authored` (its envelope verifies), `unclaimed`
 * (neither `signature` nor `key_id`: an unsigned record, not a forgery) or
 * `invalid`.
 */
export type RecordSignatureVerdict = "authored" | "unclaimed" | "invalid";

const plainObject = (value: unknown): value is Record<string, unknown> =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  !(value instanceof JsonNumber);

/**
 * Remove null, empty-array and empty-object members bottom-up: the vintage
 * `jcs-n` absent-field normalization.
 */
function normalized(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalized);
  if (!plainObject(value)) return value;
  const out: Record<string, unknown> = {};
  for (const [key, member] of Object.entries(value)) {
    const next = normalized(member);
    if (
      next === null ||
      (Array.isArray(next) && next.length === 0) ||
      (plainObject(next) && Object.keys(next).length === 0)
    )
      continue;
    Object.defineProperty(out, key, {
      value: next,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return out;
}

/**
 * The Capsule ID a record declares by its `canonicalization_id`: `jcs`
 * commits every member but `capsule_id` and the local-only `signature` and
 * `key_id`; `jcs-n`, declared or implied by a record without the member (or
 * with JSON null), is the vintage reading, which also drops `chain` and
 * normalizes absent fields. Any other value throws.
 */
async function recordCapsuleId(
  record: Record<string, unknown>,
): Promise<string> {
  const algorithm = record.canonicalization_id ?? "jcs-n";
  if (algorithm !== "jcs-n" && algorithm !== "jcs")
    throw new TypeError("cannot recompute this canonicalization_id");
  const vintage = algorithm === "jcs-n";
  const canonical: Record<string, unknown> = {};
  for (const [key, member] of Object.entries(record))
    if (
      key !== "capsule_id" &&
      key !== "signature" &&
      key !== "key_id" &&
      !(vintage && key === "chain")
    )
      Object.defineProperty(canonical, key, {
        value: member,
        enumerable: true,
        writable: true,
        configurable: true,
      });
  return sha256Hex(jcs(vintage ? normalized(canonical) : canonical));
}

/** One or more hex digit pairs, in either case, with no whitespace. */
function digitPairs(value: unknown, member: string): Uint8Array {
  if (typeof value !== "string" || !/^(?:[0-9A-Fa-f]{2})+$/u.test(value))
    throw new TypeError(`${member} is not hex`);
  return hexToBytes(value.toLowerCase());
}

/**
 * Grade a record's producer signature. `record.signature` is the hex Producer
 * Envelope and `record.key_id` the hex raw Ed25519 public key; the envelope
 * must verify under `key_id` over the Capsule ID recomputed from the record's
 * own content (`jcs`, or vintage `jcs-n`). The carried `capsule_id` is not
 * read. `messages` is empty unless `invalid`. Never throws.
 */
export async function verifyRecordSignature(record: unknown): Promise<{
  readonly verdict: RecordSignatureVerdict;
  readonly messages: readonly string[];
}> {
  try {
    return await gradeRecordSignature(record);
  } catch (error) {
    // Input this verifier cannot read at all (nested beyond the stack, say)
    // is an invalid claim, never a rejected promise.
    return {
      verdict: "invalid",
      messages: [`unreadable record: ${errorText(error)}`],
    };
  }
}

/** An error's text, never throwing (for an error that is not an Error). */
function errorText(error: unknown): string {
  return error instanceof Error
    ? `${error.name}: ${error.message}`
    : typeof error;
}

/** A record's `capsule_id` for a message: the string, or its JSON type. */
function idText(record: Record<string, unknown>): string {
  const id = record.capsule_id;
  if (typeof id === "string") return id;
  if (id === undefined) return "<none>";
  return `<${id === null ? "null" : Array.isArray(id) ? "array" : typeof id}>`;
}

async function gradeRecordSignature(record: unknown): Promise<{
  readonly verdict: RecordSignatureVerdict;
  readonly messages: readonly string[];
}> {
  if (!plainObject(record))
    return { verdict: "invalid", messages: ["not a JSON object"] };
  const id = idText(record);
  const hasSignature = Object.hasOwn(record, "signature"),
    hasKeyId = Object.hasOwn(record, "key_id");
  if (!hasSignature && !hasKeyId) return { verdict: "unclaimed", messages: [] };
  if (hasSignature !== hasKeyId)
    return {
      verdict: "invalid",
      messages: [
        `capsule_id=${id}: only one of signature/key_id present -- malformed producer envelope`,
      ],
    };
  try {
    const signature = digitPairs(record.signature, "signature"),
      keyId = digitPairs(record.key_id, "key_id");
    const result = await verifyProducerEnvelope(
      await recordCapsuleId(record),
      signature,
    );
    if (
      result.ok &&
      result.publicKey !== undefined &&
      equalBytes(result.publicKey, keyId)
    )
      return { verdict: "authored", messages: [] };
  } catch (error) {
    return {
      verdict: "invalid",
      messages: [
        `capsule_id=${id}: producer envelope malformed: ${errorText(error)}`,
      ],
    };
  }
  return {
    verdict: "invalid",
    messages: [
      `capsule_id=${id}: self-attested Ed25519 signature does not verify against key_id`,
    ],
  };
}
