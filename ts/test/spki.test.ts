import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import { directoryKeyCounts } from "../src/spki.js";

const spki = (key: KeyObject): Uint8Array =>
  new Uint8Array(key.export({ format: "der", type: "spki" }));

/** DER: a tag, a minimal length and the contents. */
function tlv(tag: number, body: Uint8Array): Uint8Array {
  const length =
    body.length < 128
      ? [body.length]
      : body.length < 256
        ? [0x81, body.length]
        : [0x82, body.length >> 8, body.length & 0xff];
  return Uint8Array.from([tag, ...length, ...body]);
}

/** The same SubjectPublicKeyInfo with its BIT STRING replaced by `point`. */
function withPoint(der: Uint8Array, point: Uint8Array): Uint8Array {
  // SEQUENCE { AlgorithmIdentifier, BIT STRING }: copy the algorithm.
  const headerWidth = der[1]! & 0x80 ? 2 + (der[1]! & 0x7f) : 2;
  const algorithmEnd = headerWidth + 2 + der[headerWidth + 1]!;
  const algorithm = der.subarray(headerWidth, algorithmEnd);
  return tlv(
    0x30,
    Uint8Array.from([
      ...algorithm,
      ...tlv(0x03, Uint8Array.from([0, ...point])),
    ]),
  );
}

describe("directoryKeyCounts", () => {
  it.each([1, 2, 3, 4, 5])(
    "counts a P-256 key (%i), uncompressed or compressed, only on the curve",
    () => {
      const der = spki(
        generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey,
      );
      expect(directoryKeyCounts(der)).toBe(true);
      // The BIT STRING holds 04 || x || y.
      const start = lastPointStart(der);
      const width = (der.length - start - 1) / 2;
      const x = der.subarray(start + 1, start + 1 + width),
        y = der.subarray(start + 1 + width);
      expect(der[start]).toBe(0x04);
      const compressed = Uint8Array.from([2 + (y[width - 1]! & 1), ...x]);
      expect(directoryKeyCounts(withPoint(der, compressed))).toBe(true);
      // y with its low bit flipped is off the curve (only p - y also is).
      const offCurve = Uint8Array.from(der);
      offCurve[offCurve.length - 1] = der[der.length - 1]! ^ 1;
      expect(directoryKeyCounts(offCurve)).toBe(false);
      // The point at infinity, and a truncated point.
      expect(directoryKeyCounts(withPoint(der, Uint8Array.of(0)))).toBe(false);
      expect(
        directoryKeyCounts(withPoint(der, der.subarray(start, der.length - 1))),
      ).toBe(false);
    },
  );

  it.each([
    "prime192v1",
    "secp224r1",
    "secp384r1",
    "secp521r1",
    "secp256k1",
    "brainpoolP256r1",
  ])("skips an EC key on %s", (namedCurve) => {
    expect(
      directoryKeyCounts(
        spki(generateKeyPairSync("ec", { namedCurve }).publicKey),
      ),
    ).toBe(false);
  });

  it("counts an Ed25519 key, not other algorithms", () => {
    expect(
      directoryKeyCounts(spki(generateKeyPairSync("ed25519").publicKey)),
    ).toBe(true);
    for (const key of [
      generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey,
      generateKeyPairSync("ed448").publicKey,
      generateKeyPairSync("x25519").publicKey,
    ])
      expect(directoryKeyCounts(spki(key))).toBe(false);
    // An EC key on a curve outside the table, an unknown OID, bytes that are
    // not DER, and trailing bytes after the SubjectPublicKeyInfo.
    const p256 = spki(
      generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey,
    );
    const otherCurve = Uint8Array.from(p256);
    otherCurve[otherCurve.indexOf(0x07, 10)] = 0x08; // ...3.1.7 -> ...3.1.8
    expect(directoryKeyCounts(otherCurve)).toBe(false);
    const unknownOid = Uint8Array.from(p256);
    unknownOid[12] = p256[12]! ^ 0x01; // inside the id-ecPublicKey OID
    expect(directoryKeyCounts(unknownOid)).toBe(false);
    expect(directoryKeyCounts(new TextEncoder().encode("not a key"))).toBe(
      false,
    );
    expect(directoryKeyCounts(Uint8Array.from([...p256, 0]))).toBe(false);
  });
});

/** Where the SEC 1 point starts: after the BIT STRING's unused-bits byte. */
function lastPointStart(der: Uint8Array): number {
  const headerWidth = der[1]! & 0x80 ? 2 + (der[1]! & 0x7f) : 2;
  const algorithmEnd = headerWidth + 2 + der[headerWidth + 1]!;
  const lengthByte = der[algorithmEnd + 1]!;
  const bitHeader = lengthByte & 0x80 ? 2 + (lengthByte & 0x7f) : 2;
  return algorithmEnd + bitHeader + 1;
}
