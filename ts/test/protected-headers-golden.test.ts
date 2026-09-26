import { describe, expect, it } from "vitest";
import { BUNDLE_DIGEST_CONTENT_TYPE } from "../src/countersignature-stamp.js";
import {
  producerProtectedHeaders,
  protectedHeadersFor,
} from "../src/producer-envelope-wire.js";

// The producer envelope's protected header is signed, so its bytes are part of
// every capsule's signature. The map is encoded in key order 3, 4, 1 (content
// type, kid, alg) with kid = the raw 32-byte public key. Deterministic CBOR
// would sort it 1, 3, 4, but changing the order alters the signed bytes of
// every capsule: that is a spec change with a version bump, never a refactor.
// These tests pin the bytes so a "tidy-up" fails loudly.

const pk = Uint8Array.from({ length: 32 }, (_, i) => i);
const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
const tstrHex = (s: string): string => {
  const b = Buffer.from(s, "utf8");
  if (b.length >= 256) throw new RangeError("test helper covers < 256 bytes");
  return (
    (b.length < 24
      ? (0x60 | b.length).toString(16)
      : `78${b.length.toString(16).padStart(2, "0")}`) + b.toString("hex")
  );
};

describe("producer protected headers (golden)", () => {
  it("equal the pre-refactor bytes exactly", () => {
    // Produced by origin/main's producerProtectedHeaders before the
    // protectedHeadersFor extraction, for pk = 00..1f.
    expect(hex(producerProtectedHeaders(pk))).toBe(
      "a30378236170706c69636174696f6e2f6167656e742d616374696f6e2d63617073756c652d6964" +
        "045820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "0127",
    );
  });

  it("countersign headers differ from producer headers only in the content type", () => {
    const producer = hex(producerProtectedHeaders(pk));
    const countersign = hex(
      protectedHeadersFor(BUNDLE_DIGEST_CONTENT_TYPE, pk),
    );
    const tail = `0458 20${hex(pk)}0127`.replace(" ", "");
    expect(producer).toBe(
      `a303${tstrHex("application/agent-action-capsule-id")}${tail}`,
    );
    expect(countersign).toBe(
      `a303${tstrHex(BUNDLE_DIGEST_CONTENT_TYPE)}${tail}`,
    );
  });
});
