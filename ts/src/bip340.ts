// BIP-340 Schnorr signature verification over secp256k1, for the `bip340` key
// type of Controller Binding v0 (CB §4.1). Verification only, with public
// inputs only: nothing here is constant-time, and nothing here signs.

import { sha256 } from "./sha256.js";

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

type Point = readonly [bigint, bigint] | null;

const mod = (a: bigint, m: bigint): bigint => ((a % m) + m) % m;

function modPow(base: bigint, exponent: bigint, m: bigint): bigint {
  let result = 1n;
  let b = mod(base, m);
  for (let e = exponent; e > 0n; e >>= 1n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
  }
  return result;
}

function invert(a: bigint, m: bigint): bigint {
  let [r0, r1] = [mod(a, m), m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  return mod(s0, m);
}

function add(a: Point, b: Point): Point {
  if (a === null) return b;
  if (b === null) return a;
  const [x1, y1] = a;
  const [x2, y2] = b;
  let lambda: bigint;
  if (x1 === x2) {
    if (mod(y1 + y2, P) === 0n) return null;
    lambda = mod(3n * x1 * x1 * invert(2n * y1, P), P);
  } else lambda = mod((y2 - y1) * invert(x2 - x1, P), P);
  const x3 = mod(lambda * lambda - x1 - x2, P);
  return [x3, mod(lambda * (x1 - x3) - y1, P)];
}

function multiply(point: Point, scalar: bigint): Point {
  let result: Point = null;
  let addend = point;
  for (let k = scalar; k > 0n; k >>= 1n) {
    if (k & 1n) result = add(result, addend);
    addend = add(addend, addend);
  }
  return result;
}

const bytesToInt = (bytes: Uint8Array): bigint =>
  bytes.reduce((n, byte) => (n << 8n) | BigInt(byte), 0n);

function hexBytes(hex: string): Uint8Array | undefined {
  if (!/^(?:[0-9a-f]{2})*$/iu.test(hex)) return undefined;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

const encoder = new TextEncoder();

function taggedHash(tag: string, ...parts: Uint8Array[]): Uint8Array {
  const tagHash = sha256(encoder.encode(tag));
  const data = new Uint8Array(
    64 + parts.reduce((total, part) => total + part.length, 0),
  );
  data.set(tagHash, 0);
  data.set(tagHash, 32);
  let offset = 64;
  for (const part of parts) {
    data.set(part, offset);
    offset += part.length;
  }
  return sha256(data);
}

/**
 * Whether `signatureHex` (64 bytes, hex) is a BIP-340 signature over the
 * 32-byte `message` under the x-only public key `keyHex` (32 bytes, hex).
 * Malformed input is false.
 */
export function verifyBip340(
  keyHex: string,
  message: Uint8Array,
  signatureHex: string,
): boolean {
  const key = hexBytes(keyHex);
  const signature = hexBytes(signatureHex);
  if (
    key === undefined ||
    signature === undefined ||
    key.length !== 32 ||
    signature.length !== 64 ||
    message.length !== 32
  )
    return false;
  const x = bytesToInt(key);
  if (x >= P) return false;
  const ySquared = mod(x * x * x + 7n, P);
  let y = modPow(ySquared, (P + 1n) / 4n, P);
  if (mod(y * y, P) !== ySquared) return false;
  if (y & 1n) y = P - y;
  const r = bytesToInt(signature.subarray(0, 32));
  const s = bytesToInt(signature.subarray(32));
  if (r >= P || s >= N) return false;
  const e = mod(
    bytesToInt(
      taggedHash("BIP0340/challenge", signature.subarray(0, 32), key, message),
    ),
    N,
  );
  const sG = multiply([GX, GY], s);
  const eP = multiply([x, y], e);
  const result = add(sG, eP === null ? null : [eP[0], mod(-eP[1], P)]);
  return result !== null && (result[1] & 1n) === 0n && result[0] === r;
}
