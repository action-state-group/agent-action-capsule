import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { verifyCountersignV1Signature } from "../src/countersignature-stamp.js";
import { strictEd25519, verifyEd25519Strict } from "../src/ed25519-strict.js";
import { hexToBytes } from "../src/producer-envelope-wire.js";

// The identity key and its forgery (R the identity, S = 0), which plain
// cofactorless verification accepts over any message, and the
// non-canonical encoding of y = p + 2, which strict verification refuses
// as an R.
const IDENTITY = hexToBytes("01" + "00".repeat(31));
const FORGERY = hexToBytes("01" + "00".repeat(63));
const NON_CANONICAL_R = hexToBytes("ef" + "ff".repeat(30) + "7f");

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

async function honest(
  message: Uint8Array,
): Promise<{ publicKey: Uint8Array; signature: Uint8Array }> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const publicKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", pair.publicKey),
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "Ed25519" },
      pair.privateKey,
      message as BufferSource,
    ),
  );
  return { publicKey, signature };
}

const withR = (signature: Uint8Array, r: Uint8Array): Uint8Array =>
  Uint8Array.from([...r, ...signature.subarray(32)]);

// An engine that checks nothing: whatever reaches subtle.verify passes, so
// only the strict pre-check can refuse.
function lenientEngine(): void {
  vi.spyOn(globalThis.crypto.subtle, "verify").mockResolvedValue(true);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("verifyEd25519Strict", () => {
  it("accepts exactly the valid checkpointed-local-log cases", async () => {
    // vectors/cross-language/cll-ed25519-vectors.json, a verbatim copy.
    const cases = (
      JSON.parse(
        readFileSync(
          resolve(
            import.meta.dirname,
            "..",
            "..",
            "vectors",
            "cross-language",
            "cll-ed25519-vectors.json",
          ),
          "utf8",
        ),
      ) as {
        ed25519_cases: {
          name: string;
          public_key_hex: string;
          message_hex: string;
          signature_hex: string;
          valid: boolean;
        }[];
      }
    ).ed25519_cases;
    expect(cases).toHaveLength(54);
    for (const c of cases) {
      let verifies = false;
      try {
        verifies = await verifyEd25519Strict(
          hexToBytes(c.public_key_hex),
          hexToBytes(c.signature_hex),
          hexToBytes(c.message_hex),
        );
      } catch {
        verifies = false;
      }
      expect(verifies, c.name).toBe(c.valid);
    }
  });

  it("refuses the identity forgery and a non-canonical R on any engine", async () => {
    const message = new TextEncoder().encode("any message");
    const { publicKey, signature } = await honest(message);
    lenientEngine();
    expect(strictEd25519(IDENTITY, FORGERY)).toBe(false);
    expect(await verifyEd25519Strict(IDENTITY, FORGERY, message)).toBe(false);
    expect(
      await verifyEd25519Strict(
        publicKey,
        withR(signature, NON_CANONICAL_R),
        message,
      ),
    ).toBe(false);
    expect(await verifyEd25519Strict(publicKey, signature, message)).toBe(true);
  });

  it("refuses wrong lengths", async () => {
    expect(
      await verifyEd25519Strict(new Uint8Array(31), FORGERY, new Uint8Array()),
    ).toBe(false);
    expect(
      await verifyEd25519Strict(IDENTITY, new Uint8Array(63), new Uint8Array()),
    ).toBe(false);
  });
});

describe("countersign/v1 signatures are strict", () => {
  const entry = {
    over: "ab".repeat(32),
    signer: { id: "witness", key_id: toHex(IDENTITY) },
    statement: { recomputed_at: "2026-10-16T00:00:00Z", checks: [] },
    type: "countersign/v1",
  };

  it("refuses the identity forgery even where the engine would pass it", async () => {
    lenientEngine();
    expect(
      await verifyCountersignV1Signature(
        entry,
        toHex(IDENTITY),
        toHex(FORGERY),
      ),
    ).toBe(false);
  });

  it("refuses a non-canonical R even where the engine would pass it", async () => {
    const { publicKey, signature } = await honest(new Uint8Array([1]));
    lenientEngine();
    expect(
      await verifyCountersignV1Signature(
        { ...entry, signer: { id: "witness", key_id: toHex(publicKey) } },
        toHex(publicKey),
        toHex(withR(signature, NON_CANONICAL_R)),
      ),
    ).toBe(false);
  });
});
