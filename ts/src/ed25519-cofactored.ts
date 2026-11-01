// Ed25519 under the cofactored equation, for the settlement
// `wrapped_resigned` test (draft-mih-agent-settlement-records-01, Section
// "Wrapping Existing Signed Objects", rule 3): A a canonical encoding (RFC
// 8032, Section 5.1.3) of a point not of small order, R a canonical encoding
// of any point, S < L, and [8][S]B = [8]R + [8][k]A.
//
// This is deliberately not strict Ed25519 (./ed25519-strict.ts). The test
// looks for the leg key's own signature, and only that key's holder can make
// one whose R has small or mixed order, so refusing those would let a
// re-signer evade it. WebCrypto offers neither the cofactored equation nor
// point arithmetic, so this module does the arithmetic on bigints, in
// extended coordinates (RFC 8032, Section 5.1.4). It handles public values
// only and is not constant-time.

import { hexToBytes } from "./producer-envelope-wire.js";

const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

const mod = (n: bigint): bigint => ((n % P) + P) % P;

function pow(base: bigint, exp: bigint): bigint {
  let out = 1n;
  base = mod(base);
  while (exp > 0n) {
    if (exp & 1n) out = (out * base) % P;
    base = (base * base) % P;
    exp >>= 1n;
  }
  return out;
}

const D = mod(-121665n * pow(121666n, P - 2n));
const SQRT_M1 = pow(2n, (P - 1n) / 4n);

/** (X, Y, Z, T): x = X/Z, y = Y/Z, xy = T/Z. */
type Point = readonly [bigint, bigint, bigint, bigint];
const IDENTITY: Point = [0n, 1n, 1n, 0n];

function add(p: Point, q: Point): Point {
  const a = mod((p[1] - p[0]) * (q[1] - q[0]));
  const b = mod((p[1] + p[0]) * (q[1] + q[0]));
  const c = mod(2n * p[3] * q[3] * D);
  const d = mod(2n * p[2] * q[2]);
  const [e, f, g, h] = [b - a, d - c, d + c, b + a];
  return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
}

const neg = (p: Point): Point => [mod(-p[0]), p[1], p[2], mod(-p[3])];

function mul(scalar: bigint, p: Point): Point {
  let out = IDENTITY;
  while (scalar > 0n) {
    if (scalar & 1n) out = add(out, p);
    p = add(p, p);
    scalar >>= 1n;
  }
  return out;
}

const isIdentity = (p: Point): boolean => p[0] === 0n && p[1] === p[2];

const littleEndian = (bytes: Uint8Array): bigint =>
  bytes.reduceRight((acc, byte) => (acc << 8n) | BigInt(byte), 0n);

/** RFC 8032 Section 5.1.3 decoding: undefined when y is not below p, when no
 * x exists, or when x is zero and the sign bit is set. */
function decode(encoded: Uint8Array): Point | undefined {
  if (encoded.length !== 32) return undefined;
  const raw = littleEndian(encoded);
  const sign = raw >> 255n;
  const y = raw & ((1n << 255n) - 1n);
  if (y >= P) return undefined;
  const u = mod(y * y - 1n);
  const v = mod(D * y * y + 1n);
  let x = mod(u * pow(v, 3n) * pow(u * pow(v, 7n), (P - 5n) / 8n));
  if (mod(v * x * x) === mod(-u)) x = mod(x * SQRT_M1);
  else if (mod(v * x * x) !== u) return undefined;
  if (x === 0n && sign === 1n) return undefined;
  if ((x & 1n) !== sign) x = P - x;
  return [x, y, 1n, mod(x * y)];
}

const BASE = decode(
  hexToBytes(
    "5866666666666666666666666666666666666666666666666666666666666666",
  ),
)!;

/**
 * Whether `signature` is `publicKey`'s over `message` under the conditions
 * above. Throws only what SubtleCrypto's SHA-512 throws.
 */
export async function verifyEd25519Cofactored(
  publicKey: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  const a = decode(publicKey);
  const r = decode(signature.subarray(0, 32));
  if (a === undefined || r === undefined || isIdentity(mul(8n, a)))
    return false;
  const s = littleEndian(signature.subarray(32));
  if (s >= L) return false;
  const input = new Uint8Array(64 + message.length);
  input.set(signature.subarray(0, 32));
  input.set(publicKey, 32);
  input.set(message, 64);
  const k =
    littleEndian(
      new Uint8Array(await globalThis.crypto.subtle.digest("SHA-512", input)),
    ) % L;
  return isIdentity(mul(8n, add(mul(s, BASE), neg(add(r, mul(k, a))))));
}
