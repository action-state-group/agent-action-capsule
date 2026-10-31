// Strict Ed25519, the one rule every verify path here applies before
// WebCrypto's `subtle.verify` when it checks a signature under a pinned,
// registered or trusted key.

import { hexToBytes } from "./producer-envelope-wire.js";

// The y coordinates, little-endian, of the eight small-order points of
// edwards25519: order 4 (0), the identity (1), order 2 (p - 1) and order 8
// (Y8, p - Y8). Either sign of x gives the same set.
const SMALL_ORDER_Y = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
];
// The group order L, little-endian.
const ED25519_L = hexToBytes(
  "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
);

/** Whether a point encoding is canonical (y < p) and not of small order. */
function strictPoint(encoded: Uint8Array): boolean {
  const y = Uint8Array.from(encoded);
  y[31]! &= 0x7f;
  const canonical = !(
    y[0]! >= 0xed &&
    y.subarray(1, 31).every((b) => b === 0xff) &&
    y[31] === 0x7f
  );
  const hex = Array.from(y, (b) => b.toString(16).padStart(2, "0")).join("");
  return canonical && !SMALL_ORDER_Y.includes(hex);
}

/**
 * The strict Ed25519 conditions of checkpointed-local-log's
 * `ed25519-vectors.json` that do not need the message: A and R canonical
 * (y < p) and not of small order, and S < L. Whether WebCrypto refuses a
 * small-order A depends on the runtime (Node's does), and a small-order A
 * verifies a forged signature over any message. Every path that verifies an
 * Ed25519 signature under a pinned, registered or trusted key runs this
 * before `subtle.verify`, so its verdict does not depend on the engine.
 */
export function strictEd25519(
  publicKey: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  if (!strictPoint(publicKey) || !strictPoint(signature.subarray(0, 32)))
    return false;
  for (let i = 31; i >= 0; i--) {
    const s = signature[32 + i]!;
    if (s !== ED25519_L[i]) return s < ED25519_L[i]!;
  }
  return false;
}

/**
 * Whether `signature` is a strict Ed25519 signature by the raw 32-octet
 * `publicKey` over `message`: {@link strictEd25519}, then WebCrypto's
 * `subtle.verify`. Throws only what SubtleCrypto throws (for example no
 * Ed25519 support); a malformed key or signature is false.
 */
export async function verifyEd25519Strict(
  publicKey: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  if (!strictEd25519(publicKey, signature)) return false;
  const subtle = globalThis.crypto.subtle;
  const key = await subtle.importKey(
    "raw",
    publicKey as BufferSource,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  return await subtle.verify(
    { name: "Ed25519" },
    key,
    signature as BufferSource,
    message as BufferSource,
  );
}
