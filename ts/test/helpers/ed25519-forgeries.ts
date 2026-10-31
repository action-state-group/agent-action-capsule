// The two kinds of signature in checkpointed-local-log's ed25519-vectors.json
// that a cofactorless verifier accepts and strict Ed25519 refuses, built over
// any message: a small-order key A ("small-order A identity") and a
// small-order R ("identity R"). Tests of a verify path use them to show the
// path is strict. Whether the runtime's WebCrypto accepts them depends on
// its version, so these tests also stub subtle.verify to pass everything:
// what is refused then is refused by the strict pre-check. The Go, Python
// and Rust tests show a cofactorless verifier accepts the same constructions.

import { createHash, createPrivateKey, createPublicKey } from "node:crypto";

const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const PKCS8_ED25519_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

/** The identity point, the small-order A of "small-order A identity". */
export const IDENTITY = Uint8Array.from([1, ...new Uint8Array(31)]);
/** R the identity and S = 0: under IDENTITY it verifies over any message. */
export const IDENTITY_FORGERY = Uint8Array.from([1, ...new Uint8Array(63)]);

const littleEndian = (bytes: Uint8Array): bigint =>
  bytes.reduceRight((acc, byte) => (acc << 8n) | BigInt(byte), 0n);

/** The raw public key of the Ed25519 key with this 32-octet seed. */
export function publicKeyOf(seed: Uint8Array): Uint8Array {
  const key = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const spki = createPublicKey(key).export({ format: "der", type: "spki" });
  return new Uint8Array(spki.subarray(-32));
}

/**
 * The seed's key signing `message` with R the identity, as the "identity R"
 * case: S = k * a mod L with k = SHA-512(R || A || M). Then [S]B = [k]A =
 * R + [k]A, so the cofactorless equation holds, but R has small order. Only
 * the key's holder can make it.
 */
export function identityR(seed: Uint8Array, message: Uint8Array): Uint8Array {
  const h = createHash("sha512").update(seed).digest().subarray(0, 32);
  h[0]! &= 248;
  h[31]! &= 127;
  h[31]! |= 64;
  const a = littleEndian(h);
  const k = littleEndian(
    createHash("sha512")
      .update(IDENTITY)
      .update(publicKeyOf(seed))
      .update(message)
      .digest(),
  );
  let s = (k * a) % L;
  const out = new Uint8Array(64);
  out.set(IDENTITY);
  for (let i = 32; i < 64; i++) {
    out[i] = Number(s & 0xffn);
    s >>= 8n;
  }
  return out;
}
