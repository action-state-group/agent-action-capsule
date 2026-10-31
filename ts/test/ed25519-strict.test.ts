import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  countersignV1SigningInput,
  verifyCountersignV1Signature,
} from "../src/countersignature-stamp.js";
import { strictEd25519, verifyEd25519Strict } from "../src/ed25519-strict.js";
import { hexToBytes } from "../src/producer-envelope-wire.js";
import {
  IDENTITY,
  IDENTITY_FORGERY as FORGERY,
  identityR,
  publicKeyOf,
} from "./helpers/ed25519-forgeries.js";

// The two kinds of signature a cofactorless verifier accepts and strict
// Ed25519 refuses (the "small-order A" and "identity R" cases of
// cll-ed25519-vectors.json), over each path's own message.
const SEED = new Uint8Array(32).fill(5);
const PUBLIC = publicKeyOf(SEED);

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

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

  it("builds the identity-R signature the Python helper builds", () => {
    // python/tests/_ed25519_forgeries.py identity_r for this seed and "m",
    // which cryptography's cofactorless verify accepts.
    expect(toHex(identityR(SEED, new TextEncoder().encode("m")))).toBe(
      "0100000000000000000000000000000000000000000000000000000000000000" +
        "4663dfe46ad618523ff47a170312fc53e49d16b3107a01bbc38f599830d0fa0d",
    );
  });

  it("refuses a small-order key or R on any engine", async () => {
    const message = new TextEncoder().encode("any message");
    lenientEngine();
    expect(strictEd25519(IDENTITY, FORGERY)).toBe(false);
    expect(await verifyEd25519Strict(IDENTITY, FORGERY, message)).toBe(false);
    expect(
      await verifyEd25519Strict(PUBLIC, identityR(SEED, message), message),
    ).toBe(false);
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
  const entry = (keyId: string) => ({
    over: "ab".repeat(32),
    signer: { id: "witness", key_id: keyId },
    statement: { recomputed_at: "2026-10-16T00:00:00Z", checks: [] },
    type: "countersign/v1",
  });

  it("refuses the identity forgery even where the engine would pass it", async () => {
    lenientEngine();
    expect(
      await verifyCountersignV1Signature(
        entry(toHex(IDENTITY)),
        toHex(IDENTITY),
        toHex(FORGERY),
      ),
    ).toBe(false);
  });

  it("refuses a small-order R by the signer's key even where the engine would pass it", async () => {
    const signed = entry(toHex(PUBLIC));
    const smallR = identityR(SEED, countersignV1SigningInput(signed));
    lenientEngine();
    expect(
      await verifyCountersignV1Signature(signed, toHex(PUBLIC), toHex(smallR)),
    ).toBe(false);
  });
});
