import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { verifyEd25519Cofactored } from "../src/ed25519-cofactored.js";
import { hexToBytes } from "../src/producer-envelope-wire.js";
import {
  IDENTITY,
  IDENTITY_FORGERY,
  identityR,
  publicKeyOf,
} from "./helpers/ed25519-forgeries.js";
import { createPrivateKey, sign } from "node:crypto";

// The settlement re-signing test (-01 §8 rule 3): the cofactored equation
// with any canonical R, A canonical and not of small order, S < L. The
// Python tests check the same function against an independent reading over
// cll-ed25519-vectors.json; the settlement vectors pin it across languages.

const SEED = new Uint8Array(32).fill(5);
const PUBLIC = publicKeyOf(SEED);
const MESSAGE = new TextEncoder().encode("any message");
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

const honest = (message: Uint8Array): Uint8Array =>
  new Uint8Array(
    sign(
      null,
      message,
      createPrivateKey({
        key: Buffer.concat([
          Buffer.from("302e020100300506032b657004220420", "hex"),
          SEED,
        ]),
        format: "der",
        type: "pkcs8",
      }),
    ),
  );

describe("verifyEd25519Cofactored", () => {
  it("accepts an honest signature and the key holder's identity R", async () => {
    expect(
      await verifyEd25519Cofactored(PUBLIC, honest(MESSAGE), MESSAGE),
    ).toBe(true);
    expect(
      await verifyEd25519Cofactored(PUBLIC, identityR(SEED, MESSAGE), MESSAGE),
    ).toBe(true);
  });

  it("accepts the key holder's mixed-order R from the settlement vectors", async () => {
    const corpus = JSON.parse(
      readFileSync(
        resolve(process.cwd(), "..", "vectors", "settlement", "cases.json"),
        "utf8",
      ),
    ) as {
      cases: { id: string; wrapped_objects: { octets_b64u: string }[] }[];
      keys: Record<string, { public_key_hex: string }>;
    };
    const c = corpus.cases.find(
      (x) => x.id === "neg-wrapped-object-resigned-mixed-order-r",
    )!;
    const jws = Buffer.from(c.wrapped_objects[1]!.octets_b64u, "base64url")
      .toString("ascii")
      .split(".");
    const signature = new Uint8Array(Buffer.from(jws[2]!, "base64url"));
    const signed = new TextEncoder().encode(`${jws[0]}.${jws[1]}`);
    const payee = hexToBytes(corpus.keys.payee!.public_key_hex);
    expect(await verifyEd25519Cofactored(payee, signature, signed)).toBe(true);
    signed[0]! ^= 1;
    expect(await verifyEd25519Cofactored(payee, signature, signed)).toBe(false);
  });

  it("refuses what someone other than the key holder can make", async () => {
    // The identity key's forgery verifies over any message for anyone.
    expect(
      await verifyEd25519Cofactored(IDENTITY, IDENTITY_FORGERY, MESSAGE),
    ).toBe(false);
    expect(
      await verifyEd25519Cofactored(
        publicKeyOf(new Uint8Array(32).fill(6)),
        honest(MESSAGE),
        MESSAGE,
      ),
    ).toBe(false);
  });

  it("refuses a non-canonical R and S at or above L", async () => {
    const smallR = identityR(SEED, MESSAGE);
    const signBit = Uint8Array.from(smallR);
    signBit[31]! |= 0x80;
    expect(await verifyEd25519Cofactored(PUBLIC, signBit, MESSAGE)).toBe(false);
    const aboveP = Uint8Array.from(smallR);
    aboveP.set(
      hexToBytes(
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      ),
    );
    expect(await verifyEd25519Cofactored(PUBLIC, aboveP, MESSAGE)).toBe(false);
    let s =
      smallR.subarray(32).reduceRight((acc, b) => (acc << 8n) | BigInt(b), 0n) +
      L;
    const sPlusL = Uint8Array.from(smallR);
    for (let i = 32; i < 64; i++) {
      sPlusL[i] = Number(s & 0xffn);
      s >>= 8n;
    }
    expect(await verifyEd25519Cofactored(PUBLIC, sPlusL, MESSAGE)).toBe(false);
  });

  it("refuses wrong lengths", async () => {
    expect(
      await verifyEd25519Cofactored(
        new Uint8Array(31),
        new Uint8Array(64),
        MESSAGE,
      ),
    ).toBe(false);
    expect(
      await verifyEd25519Cofactored(PUBLIC, new Uint8Array(63), MESSAGE),
    ).toBe(false);
  });
});
