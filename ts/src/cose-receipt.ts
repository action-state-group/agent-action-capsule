// Offline verification of a COSE Receipt (RFC 9942 shape, RFC 9162 SHA-256
// inclusion proof) under one pinned key: the part of scitt-cose's
// `verify_receipt` (scitt_cose/receipt.py, rust/scitt-cose/src/receipt.rs)
// that witness receipts need. Only `vds` 1 (RFC9162_SHA256), EdDSA and ES256,
// and a detached payload, as the Rust verifier accepts. WebCrypto only, so it
// runs wherever SubtleCrypto does.

import { strictEd25519 } from "./ed25519-strict.js";
import { sha256Hex } from "./json.js";
import {
  concat,
  hexToBytes,
  producerEnvelopeSigningBytes,
} from "./producer-envelope-wire.js";

const COSE_SIGN1_TAG = 18n;
const HDR_ALG = 1n;
const HDR_CRIT = 2n;
/** Protected label of the CWT claims map (RFC 9597). */
export const HDR_CWT_CLAIMS = 15n;
const HDR_VDS = 395n;
const HDR_VDP = 396n;
const VDP_INCLUSION_PROOFS = -1n;
const VDS_RFC9162_SHA256 = 1n;
const ALG_EDDSA = -8n;
const ALG_ES256 = -7n;
/** Private-use protected label of a witness's receipt grade. */
export const HDR_GRADE = -65537n;
// Protected labels this verifier processes, for RFC 9052 crit enforcement.
const UNDERSTOOD = new Set([HDR_ALG, HDR_CRIT, HDR_VDS, HDR_CWT_CLAIMS]);
const MAX_MESSAGE_BYTES = 10 * 1024 * 1024;
const MAX_INCLUSION_PROOFS = 16;
const MAX_AUDIT_PATH = 64;
const MAX_TREE_SIZE = 1n << 62n;
const MAX_DEPTH = 32;

/** A decoded CBOR item. Integers are bigints, floats are numbers. */
export type CborValue =
  | bigint
  | number
  | boolean
  | null
  | undefined
  | string
  | Uint8Array
  | readonly CborValue[]
  | CborMap
  | CborTag
  | CborSimple;
export class CborMap {
  public constructor(
    public readonly entries: readonly (readonly [CborValue, CborValue])[],
  ) {}
  public has(key: bigint | string): boolean {
    return this.entries.some(([k]) => k === key);
  }
  public get(key: bigint | string): CborValue {
    return this.entries.find(([k]) => k === key)?.[1];
  }
}
export class CborTag {
  public constructor(
    public readonly tag: bigint,
    public readonly value: CborValue,
  ) {}
}
export class CborSimple {
  public constructor(public readonly value: number) {}
}

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Decode one CBOR item under the deterministic-encoding rules scitt-cose's
 * `strict_decode` applies: definite lengths, the shortest form of every
 * argument and float, no repeated map key and no trailing bytes. Map order is
 * not checked.
 */
export function decodeStrictCbor(data: Uint8Array): CborValue {
  return decodeCbor(data, true);
}

/**
 * Decode one CBOR item. With `shortest`, every length is definite and every
 * argument and float in its shortest form. Without it (an inclusion-proof
 * blob, which both scitt-cose verifiers decode with a plain decoder:
 * Python's `_decode_inclusion_proof` uses cbor2, Rust uses ciborium), a
 * non-shortest argument or float and indefinite-length strings, arrays and
 * maps are accepted. Unique map keys and no trailing bytes hold either way.
 */
function decodeCbor(data: Uint8Array, shortest: boolean): CborValue {
  let offset = 0;
  const byte = (): number => {
    const value = data[offset++];
    if (value === undefined) throw new SyntaxError("truncated CBOR");
    return value;
  };
  const take = (length: bigint): Uint8Array => {
    if (BigInt(offset) + length > BigInt(data.length))
      throw new SyntaxError("truncated CBOR");
    const value = data.slice(offset, offset + Number(length));
    offset += Number(length);
    return value;
  };
  const argument = (add: number): bigint => {
    if (add < 24) return BigInt(add);
    const width = [1, 2, 4, 8][add - 24];
    if (width === undefined)
      throw new SyntaxError("indefinite or reserved CBOR length");
    let value = 0n;
    for (let i = 0; i < width; i += 1) value = (value << 8n) | BigInt(byte());
    if (shortest && value < [24n, 1n << 8n, 1n << 16n, 1n << 32n][add - 24]!)
      throw new SyntaxError("CBOR argument is not in its shortest form");
    return value;
  };
  const item = (depth: number): CborValue => {
    if (depth > MAX_DEPTH) throw new SyntaxError("CBOR nesting too deep");
    const first = byte(),
      major = first >>> 5,
      add = first & 31;
    if (major === 7) {
      if (add === 20) return false;
      if (add === 21) return true;
      if (add === 22) return null;
      if (add === 23) return undefined;
      if (add < 20) return new CborSimple(add);
      if (add === 24) {
        const value = byte();
        if (value < 32) throw new SyntaxError("non-preferred simple value");
        return new CborSimple(value);
      }
      if (add >= 28) throw new SyntaxError("reserved or break CBOR value");
      const raw = take(add === 25 ? 2n : add === 26 ? 4n : 8n);
      const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
      if (add === 25) return halfFloat(view.getUint16(0));
      const value = add === 26 ? view.getFloat32(0) : view.getFloat64(0);
      if (
        shortest &&
        (Number.isNaN(value) ||
          fitsHalf(value) ||
          (add === 27 && Math.fround(value) === value))
      )
        throw new SyntaxError("CBOR float is not in its shortest form");
      return value;
    }
    // Lenient mode reads indefinite-length strings, arrays and maps, as
    // cbor2 and ciborium do: items until the 0xff break.
    if (!shortest && add === 31 && major >= 2 && major <= 5) {
      const atBreak = (): boolean => {
        if (data[offset] !== 0xff) return false;
        offset += 1;
        return true;
      };
      if (major === 2 || major === 3) {
        // Each chunk is a definite-length string of the same major type.
        const chunks: Uint8Array[] = [];
        while (!atBreak()) {
          const head = byte();
          if (head >>> 5 !== major || (head & 31) === 31)
            throw new SyntaxError("invalid indefinite-length string chunk");
          chunks.push(take(argument(head & 31)));
        }
        const joined = new Uint8Array(
          chunks.reduce((sum, chunk) => sum + chunk.length, 0),
        );
        let at = 0;
        for (const chunk of chunks) {
          if (major === 3) utf8.decode(chunk); // each chunk is valid UTF-8
          joined.set(chunk, at);
          at += chunk.length;
        }
        return major === 2 ? joined : utf8.decode(joined);
      }
      if (major === 4) {
        const out: CborValue[] = [];
        while (!atBreak()) out.push(item(depth + 1));
        return out;
      }
      const entries: [CborValue, CborValue][] = [],
        keys = new Set<string>();
      while (!atBreak()) {
        const key = item(depth + 1),
          identity = identityOf(key);
        if (keys.has(identity)) throw new SyntaxError("duplicate CBOR map key");
        keys.add(identity);
        entries.push([key, item(depth + 1)]);
      }
      return new CborMap(entries);
    }
    const length = argument(add);
    if (major === 0) return length;
    if (major === 1) return -1n - length;
    if (major === 2) return take(length);
    if (major === 3) return utf8.decode(take(length));
    if (major === 6) return new CborTag(length, item(depth + 1));
    // Every element takes at least one byte: refuse a count the rest of the
    // input cannot hold before looping over it.
    if (length > BigInt(data.length - offset))
      throw new SyntaxError("truncated CBOR");
    if (major === 4) {
      const out: CborValue[] = [];
      for (let i = 0n; i < length; i += 1n) out.push(item(depth + 1));
      return out;
    }
    const entries: [CborValue, CborValue][] = [],
      keys = new Set<string>();
    for (let i = 0n; i < length; i += 1n) {
      const key = item(depth + 1),
        identity = identityOf(key);
      if (keys.has(identity)) throw new SyntaxError("duplicate CBOR map key");
      keys.add(identity);
      entries.push([key, item(depth + 1)]);
    }
    return new CborMap(entries);
  };
  const value = item(0);
  if (offset !== data.length) throw new SyntaxError("trailing CBOR bytes");
  return value;
}

function halfFloat(bits: number): number {
  const exponent = (bits >>> 10) & 0x1f,
    fraction = bits & 0x3ff,
    sign = bits & 0x8000 ? -1 : 1;
  if (exponent === 0) return sign * fraction * 2 ** -24;
  if (exponent === 31) return fraction ? Number.NaN : sign * Infinity;
  return sign * (1 + fraction / 1024) * 2 ** (exponent - 15);
}

/** Whether a float is exactly representable in IEEE 754 half precision. */
function fitsHalf(value: number): boolean {
  const magnitude = Math.abs(value);
  if (magnitude === 0 || magnitude === Infinity) return true;
  if (magnitude > 65504) return false;
  const exponent = Math.floor(Math.log2(magnitude));
  return Number.isInteger(
    magnitude * 2 ** (exponent >= -14 ? 10 - exponent : 24),
  );
}

function identityOf(value: CborValue): string {
  if (typeof value === "bigint") return `i${value}`;
  if (typeof value === "number") return `f${value}`;
  if (typeof value === "string") return `t${JSON.stringify(value)}`;
  if (value instanceof Uint8Array) return `b${value.join()}`;
  if (Array.isArray(value)) return `a[${value.map(identityOf).join(",")}]`;
  if (value instanceof CborMap)
    return `m{${value.entries
      .map(([k, v]) => `${identityOf(k)}:${identityOf(v)}`)
      .sort()
      .join(",")}}`;
  if (value instanceof CborTag)
    return `g${value.tag}(${identityOf(value.value)})`;
  if (value instanceof CborSimple) return `s${value.value}`;
  return `s${String(value)}`;
}

const sha256 = async (bytes: Uint8Array): Promise<Uint8Array> =>
  hexToBytes(await sha256Hex(bytes));

function largestPowerOfTwoBelow(n: bigint): bigint {
  let k = 1n;
  while (k * 2n < n) k *= 2n;
  return k;
}

/** The number of audit-path siblings of `index` in a tree of `size` leaves. */
function expectedPathLength(size: bigint, index: bigint): number {
  let count = 0;
  while (size > 1n) {
    const k = largestPowerOfTwoBelow(size);
    if (index < k) size = k;
    else [size, index] = [size - k, index - k];
    count += 1;
  }
  return count;
}

/** Fold a leaf entry up its RFC 6962 section 2.1.1 audit path to the root. */
async function rootFromInclusion(
  entry: Uint8Array,
  index: bigint,
  size: bigint,
  path: readonly Uint8Array[],
): Promise<Uint8Array> {
  // The path length was checked against (size, index), so every level has
  // its sibling; the outermost sibling is last.
  const siblings = [...path];
  const fold = async (n: bigint, m: bigint): Promise<Uint8Array> => {
    if (n === 1n) return sha256(concat(Uint8Array.of(0), entry));
    const k = largestPowerOfTwoBelow(n);
    const sibling = siblings.pop()!;
    return m < k
      ? sha256(concat(Uint8Array.of(1), await fold(k, m), sibling))
      : sha256(concat(Uint8Array.of(1), sibling, await fold(n - k, m - k)));
  };
  return fold(size, index);
}

function inclusionProof(blob: Uint8Array): {
  size: bigint;
  index: bigint;
  path: Uint8Array[];
} {
  const value = decodeCbor(blob, false);
  if (!Array.isArray(value) || value.length !== 3)
    throw new SyntaxError(
      "inclusion proof must be [tree_size, leaf_index, [path]]",
    );
  const [size, index, path] = value as readonly CborValue[];
  if (typeof size !== "bigint" || typeof index !== "bigint")
    throw new SyntaxError("inclusion proof sizes must be integers");
  if (!Array.isArray(path) || path.length > MAX_AUDIT_PATH)
    throw new SyntaxError("inclusion proof path must be a short array");
  const nodes = path as readonly CborValue[];
  if (!nodes.every((node) => node instanceof Uint8Array && node.length === 32))
    throw new SyntaxError("inclusion proof path nodes must be 32 bytes");
  if (index < 0n || index >= size || size > MAX_TREE_SIZE)
    throw new SyntaxError("invalid tree size or leaf index");
  if (nodes.length !== expectedPathLength(size, index))
    throw new SyntaxError("invalid inclusion proof path length");
  return { size, index, path: nodes as Uint8Array[] };
}

// DER AlgorithmIdentifiers: id-ecPublicKey with prime256v1, and id-Ed25519.
const P256_ALGORITHM = hexToBytes("301306072a8648ce3d020106082a8648ce3d030107");
const ED25519_ALGORITHM = hexToBytes("300506032b6570");

/**
 * The key type a DER SubjectPublicKeyInfo names by its AlgorithmIdentifier:
 * `p256` (ECDSA over P-256), `ed25519`, or `other` for any other key, curve
 * or unreadable bytes.
 */
export function spkiKeyType(spki: Uint8Array): "p256" | "ed25519" | "other" {
  // SEQUENCE { AlgorithmIdentifier, BIT STRING }, with a short- or
  // long-form outer length; the AlgorithmIdentifiers above are short.
  if (spki[0] !== 0x30 || spki[1] === undefined) return "other";
  const lengthBytes = spki[1] & 0x80 ? spki[1] & 0x7f : 0;
  if (lengthBytes > 2) return "other";
  let length = lengthBytes ? 0 : spki[1];
  for (let i = 0; i < lengthBytes; i += 1)
    length = length * 256 + (spki[2 + i] ?? 0);
  const start = 2 + lengthBytes;
  if (start + length !== spki.length) return "other";
  const algorithmLength = spki[start + 1];
  if (
    spki[start] !== 0x30 ||
    algorithmLength === undefined ||
    algorithmLength & 0x80
  )
    return "other";
  const algorithm = spki.subarray(start, start + 2 + algorithmLength);
  const same = (expected: Uint8Array) =>
    algorithm.length === expected.length &&
    algorithm.every((byte, i) => byte === expected[i]);
  return same(P256_ALGORITHM)
    ? "p256"
    : same(ED25519_ALGORITHM)
      ? "ed25519"
      : "other";
}

/**
 * The outcome of {@link verifyCoseReceipt}. `protectedHeaders` is the signed
 * protected header, surfaced only when the receipt verified. `unavailable`
 * marks a receipt this runtime could not check at all (no WebCrypto, or no
 * support for its algorithm): not checked, rather than refused.
 */
export type ReceiptVerification =
  | { readonly ok: true; readonly protectedHeaders: CborMap }
  | {
      readonly ok: false;
      readonly reason: string;
      readonly unavailable?: true;
    };

/**
 * Verify a COSE Receipt for the leaf entry `leaf` (its raw bytes, not its
 * RFC 6962 leaf hash) under `publicKeySpki` (DER SubjectPublicKeyInfo, an
 * Ed25519 key for EdDSA or a P-256 key for ES256). The receipt must be a
 * tag-18 COSE_Sign1 with a detached payload, protected `vds` 1
 * (RFC9162_SHA256) and `alg` EdDSA (-8) or ES256 (-7), and the alg fixes the
 * key type (ES256 only under a P-256 key, EdDSA only under Ed25519), as
 * vectors/bundle/strict/README.md "COSE Receipts" states. Never throws.
 */
export async function verifyCoseReceipt(
  receipt: Uint8Array,
  leaf: Uint8Array,
  publicKeySpki: Uint8Array,
): Promise<ReceiptVerification> {
  const fail = (reason: string): ReceiptVerification => ({
    ok: false,
    reason,
  });
  try {
    if (receipt.length > MAX_MESSAGE_BYTES) return fail("receipt too large");
    const outer = decodeStrictCbor(receipt);
    if (
      !(outer instanceof CborTag) ||
      outer.tag !== COSE_SIGN1_TAG ||
      !Array.isArray(outer.value) ||
      outer.value.length !== 4
    )
      return fail("receipt is not a COSE_Sign1 message");
    const [protectedBytes, unprotected, payload, signature] =
      outer.value as readonly CborValue[];
    if (!(protectedBytes instanceof Uint8Array))
      return fail("receipt is not a COSE_Sign1 message");
    // An attached payload would be signed in place of the root the proof
    // rebuilds, binding nothing to the leaf: refused even when it verifies.
    if (payload !== null)
      return fail(
        "receipt payload is attached; a receipt's payload must be detached",
      );
    const headers = protectedBytes.length
      ? decodeStrictCbor(protectedBytes)
      : new CborMap([]);
    if (!(headers instanceof CborMap))
      return fail("protected header is not a map");
    if (headers.get(HDR_VDS) !== VDS_RFC9162_SHA256)
      return fail("receipt vds is not RFC9162_SHA256 (1)");
    const alg = headers.get(HDR_ALG);
    if (alg !== ALG_EDDSA && alg !== ALG_ES256)
      return fail("receipt alg is not EdDSA (-8) or ES256 (-7)");
    // The algorithm fixes the key type, read from the key itself so that a
    // key WebCrypto cannot import (secp256k1, say) fails rather than going
    // unchecked.
    const keyType = spkiKeyType(publicKeySpki);
    if (alg === ALG_ES256 && keyType !== "p256")
      return fail("receipt alg ES256 needs an ECDSA P-256 key");
    if (alg === ALG_EDDSA && keyType !== "ed25519")
      return fail("receipt alg EdDSA needs an Ed25519 key");
    if (headers.has(HDR_CRIT)) {
      const crit = headers.get(HDR_CRIT);
      if (
        !Array.isArray(crit) ||
        crit.length === 0 ||
        !(crit as readonly CborValue[]).every(
          (label) =>
            typeof label === "bigint" &&
            headers.has(label) &&
            UNDERSTOOD.has(label),
        )
      )
        return fail("crit (label 2) names a header this verifier rejects");
    }
    if (!(unprotected instanceof CborMap))
      return fail("unprotected header is not a map");
    const vdp = unprotected.get(HDR_VDP);
    const proofs = vdp instanceof CborMap ? vdp.get(VDP_INCLUSION_PROOFS) : [];
    if (!Array.isArray(proofs) || proofs.length === 0)
      return fail("vdp has no inclusion proofs (key -1)");
    if (proofs.length > MAX_INCLUSION_PROOFS)
      return fail("too many inclusion proofs");
    // Parse every candidate first: a valid proof must not hide a malformed
    // later entry in this unauthenticated array.
    const candidates = (proofs as readonly CborValue[]).map((proof) => {
      if (!(proof instanceof Uint8Array))
        throw new SyntaxError("inclusion proof entry is not a byte string");
      return inclusionProof(proof);
    });
    if (!(signature instanceof Uint8Array))
      return fail("signature is not a byte string");
    for (const { size, index, path } of candidates) {
      const root = await rootFromInclusion(leaf, index, size, path);
      const verified = await verifySignature(
        alg,
        publicKeySpki,
        signature,
        producerEnvelopeSigningBytes(protectedBytes, root),
      );
      if (verified === "unavailable")
        return {
          ok: false,
          reason: "this runtime cannot verify the receipt's algorithm",
          unavailable: true,
        };
      if (verified) return { ok: true, protectedHeaders: headers };
    }
    return fail("receipt signature did not verify under the key");
  } catch (error) {
    return fail(`unreadable receipt: ${String(error)}`);
  }
}

async function verifySignature(
  alg: bigint,
  spki: Uint8Array,
  signature: Uint8Array,
  signed: Uint8Array,
): Promise<boolean | "unavailable"> {
  if (alg === ALG_EDDSA && !strictEd25519(spki.subarray(-32), signature))
    return false;
  const subtle = (globalThis as { crypto?: { subtle?: SubtleCrypto } }).crypto
    ?.subtle;
  if (subtle === undefined) return "unavailable";
  const [importAlgorithm, verifyAlgorithm] =
    alg === ALG_EDDSA
      ? [{ name: "Ed25519" }, { name: "Ed25519" }]
      : alg === ALG_ES256 && signature.length === 64
        ? [
            { name: "ECDSA", namedCurve: "P-256" },
            { name: "ECDSA", hash: "SHA-256" },
          ]
        : [];
  if (importAlgorithm === undefined || verifyAlgorithm === undefined)
    return false;
  let key: CryptoKey;
  try {
    key = await subtle.importKey(
      "spki",
      spki as BufferSource,
      importAlgorithm,
      false,
      ["verify"],
    );
  } catch {
    // The key type already matches the algorithm. If this runtime imports a
    // known-good key of that type, the refusal is about this key (an
    // Ed25519 key that is not a curve point, say): nothing verifies under
    // it. Only a runtime without the algorithm leaves the receipt unchecked.
    return (await canImport(subtle, alg, importAlgorithm))
      ? false
      : "unavailable";
  }
  try {
    return await subtle.verify(
      verifyAlgorithm,
      key,
      signature as BufferSource,
      signed as BufferSource,
    );
  } catch {
    return false;
  }
}

// Valid public keys, one per algorithm, to tell a runtime that lacks the
// algorithm from a key the runtime refuses.
const REFERENCE_KEYS: ReadonlyMap<bigint, Uint8Array> = new Map([
  [
    ALG_EDDSA,
    // RFC 8032 section 7.1, TEST 1 public key.
    hexToBytes(
      "302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    ),
  ],
  [
    ALG_ES256,
    hexToBytes(
      "3059301306072a8648ce3d020106082a8648ce3d030107034200046b71eb63d74b4e1796e296f523109ef03a86ff4eab8c912dda8ce08eaf9147e0f9af809305d94023605d22a4273b64848f851d1f9d95c01b4bd472c65e890455",
    ),
  ],
]);

async function canImport(
  subtle: SubtleCrypto,
  alg: bigint,
  algorithm: AlgorithmIdentifier | EcKeyImportParams,
): Promise<boolean> {
  try {
    await subtle.importKey(
      "spki",
      REFERENCE_KEYS.get(alg)! as BufferSource,
      algorithm,
      false,
      ["verify"],
    );
    return true;
  } catch {
    return false;
  }
}
