import {
  createHash,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Ed25519UnavailableError, verifyBundle } from "../src/bundle.js";
import {
  HDR_GRADE,
  spkiKeyType,
  verifyCoseReceipt,
} from "../src/cose-receipt.js";
import {
  concat,
  hexToBytes,
  producerEnvelopeSigningBytes,
} from "../src/producer-envelope-wire.js";
import { decodeStrictJson } from "../src/json.js";
import {
  base64Canonical,
  bindingOf,
  checkpointDigest,
  endpointOf,
  fromHex,
  verifyReceipt,
  verifyRekorReceipt,
  verifyScrapiReceipt,
  witnessRowFor,
  witnessRowKeys,
  type SignedCheckpointFields,
} from "../src/witness.js";

const spki = (key: KeyObject): Uint8Array =>
  new Uint8Array(key.export({ format: "der", type: "spki" }));
const leaf = new TextEncoder().encode("leaf entry");
const root = new Uint8Array(
  createHash("sha256")
    .update(concat(Uint8Array.of(0), leaf))
    .digest(),
);
// A one-leaf receipt: unprotected {396: {-1: [<< [1, 0, []] >>]}}.
const unprotected = hexToBytes("a119018ca120814483010080");

/** A COSE Receipt over `root`, its protected header given as CBOR hex. */
function receipt(
  protectedHex: string,
  key: KeyObject,
  { payload = "f6", es256 = true } = {},
): Uint8Array {
  const protectedBytes = hexToBytes(protectedHex);
  const signature = new Uint8Array(
    es256
      ? sign("sha256", producerEnvelopeSigningBytes(protectedBytes, root), {
          key,
          dsaEncoding: "ieee-p1363",
        })
      : sign(null, producerEnvelopeSigningBytes(protectedBytes, root), key),
  );
  return concat(
    Uint8Array.of(0xd2, 0x84),
    protectedBytes.length < 24
      ? Uint8Array.of(0x40 + protectedBytes.length)
      : Uint8Array.of(0x58, protectedBytes.length),
    protectedBytes,
    unprotected,
    hexToBytes(payload),
    Uint8Array.of(0x58, signature.length),
    signature,
  );
}

const p256 = generateKeyPairSync("ec", { namedCurve: "P-256" });
const ed25519 = generateKeyPairSync("ed25519");
// {1: -7 (ES256), 395: 1}
const ES256_HEADERS = "a201261901 8b01".replace(" ", "");

describe("COSE Receipt", () => {
  it("verifies an ES256 receipt under its P-256 key", async () => {
    const result = await verifyCoseReceipt(
      receipt(ES256_HEADERS, p256.privateKey),
      leaf,
      spki(p256.publicKey),
    );
    expect(result.ok).toBe(true);
  });

  it("surfaces the grade label only from a verified receipt", async () => {
    // {1: -7, 395: 1, -65537: "mmr-verified"}
    const headers = `a3012619018b013a00010000${Buffer.from("lmmr-verified").toString("hex")}`;
    const result = await verifyCoseReceipt(
      receipt(headers, p256.privateKey),
      leaf,
      spki(p256.publicKey),
    );
    expect(result.ok && result.protectedHeaders.get(HDR_GRADE)).toBe(
      "mmr-verified",
    );
  });

  it("fails under another key, another leaf, or a key of another type", async () => {
    const good = receipt(ES256_HEADERS, p256.privateKey);
    const other = generateKeyPairSync("ec", { namedCurve: "P-256" });
    for (const [bytes, key] of [
      [leaf, spki(other.publicKey)],
      [new TextEncoder().encode("other leaf"), spki(p256.publicKey)],
      [leaf, spki(ed25519.publicKey)],
    ] as const)
      expect((await verifyCoseReceipt(good, bytes, key)).ok).toBe(false);
  });

  it("verifies EdDSA, and refuses an attached payload", async () => {
    const headers = "a20127190 18b01".replace(" ", ""); // {1: -8, 395: 1}
    const key = spki(ed25519.publicKey);
    expect(
      (
        await verifyCoseReceipt(
          receipt(headers, ed25519.privateKey, { es256: false }),
          leaf,
          key,
        )
      ).ok,
    ).toBe(true);
    const attached = receipt(headers, ed25519.privateKey, {
      es256: false,
      payload: `5820${Buffer.from(root).toString("hex")}`,
    });
    expect(await verifyCoseReceipt(attached, leaf, key)).toMatchObject({
      ok: false,
      reason: expect.stringContaining("attached"),
    });
  });

  it("lets the alg fix the key type, and fails a key WebCrypto cannot import", async () => {
    const secp256k1 = generateKeyPairSync("ec", { namedCurve: "secp256k1" });
    const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" });
    expect(spkiKeyType(spki(p256.publicKey))).toBe("p256");
    expect(spkiKeyType(spki(ed25519.publicKey))).toBe("ed25519");
    for (const key of [secp256k1, p384, generateKeyPairSync("ed448")])
      expect(spkiKeyType(spki(key.publicKey))).toBe("other");
    expect(spkiKeyType(new Uint8Array([0x30, 0x00]))).toBe("other");
    // ES256 signed by a secp256k1 key under that key: refused, not withheld.
    const k1 = await verifyCoseReceipt(
      receipt(ES256_HEADERS, secp256k1.privateKey),
      leaf,
      spki(secp256k1.publicKey),
    );
    expect(k1).toEqual({
      ok: false,
      reason: "receipt alg ES256 needs an ECDSA P-256 key",
    });
    // ES256 under P-384 or Ed25519 keys, EdDSA under a P-256 key.
    const es256 = receipt(ES256_HEADERS, p256.privateKey);
    for (const key of [p384, ed25519])
      expect(await verifyCoseReceipt(es256, leaf, spki(key.publicKey))).toEqual(
        {
          ok: false,
          reason: "receipt alg ES256 needs an ECDSA P-256 key",
        },
      );
    const eddsa = receipt("a2012719018b01", ed25519.privateKey, {
      es256: false,
    });
    expect(await verifyCoseReceipt(eddsa, leaf, spki(p256.publicKey))).toEqual({
      ok: false,
      reason: "receipt alg EdDSA needs an Ed25519 key",
    });
  });

  it("refuses a critical header it does not understand, an unknown vds and non-canonical CBOR", async () => {
    const key = spki(p256.publicKey);
    for (const headers of [
      "a3012619018b0102813a00010000", // crit [-65537]: not understood
      "a2012619018b02", // vds 2
      "a201261a0000018b01", // label 395 in a non-shortest form
    ])
      expect(
        (await verifyCoseReceipt(receipt(headers, p256.privateKey), leaf, key))
          .ok,
      ).toBe(false);
    // An alg other than EdDSA or ES256 ({1: -35 (ES384), 395: 1}), and a
    // COSE_Sign1 array without its tag 18.
    expect(
      await verifyCoseReceipt(
        receipt("a201382219018b01", p256.privateKey),
        leaf,
        key,
      ),
    ).toMatchObject({ ok: false, reason: expect.stringContaining("alg") });
    expect(
      (
        await verifyCoseReceipt(
          receipt(ES256_HEADERS, p256.privateKey).subarray(1),
          leaf,
          key,
        )
      ).ok,
    ).toBe(false);
    // crit naming an understood label passes.
    expect(
      (
        await verifyCoseReceipt(
          receipt(
            "a3012619018b010281190 18b".replace(" ", ""),
            p256.privateKey,
          ),
          leaf,
          key,
        )
      ).ok,
    ).toBe(true);
  });
});

describe("receipt checks", () => {
  afterEach(() => vi.unstubAllGlobals());

  const cose = new TextEncoder().encode("checkpoint COSE statement");
  const coseHex = createHash("sha256").update(cose).digest("hex");
  const rekorSpki = spki(p256.publicKey);
  const logID = createHash("sha256").update(rekorSpki).digest("hex");
  const checkpointSpki = spki(ed25519.publicKey);
  const checkpointKeyId = Buffer.from(checkpointSpki.subarray(12)).toString(
    "hex",
  );
  const pem = `-----BEGIN PUBLIC KEY-----\n${Buffer.from(checkpointSpki).toString("base64")}\n-----END PUBLIC KEY-----\n`;
  const bodyWith = (payloadHash: Record<string, unknown>) =>
    Buffer.from(
      JSON.stringify({
        apiVersion: "0.0.1",
        kind: "dsse",
        spec: {
          payloadHash,
          signatures: [
            {
              signature: "c2ln",
              verifier: Buffer.from(pem).toString("base64"),
            },
          ],
        },
      }),
    ).toString("base64");
  const body = bodyWith({ algorithm: "sha256", value: coseHex });
  /** A Rekor entry's JSON text; `time` is integratedTime as spelled, while
   * the Signed Entry Timestamp always covers the integer. */
  const entryText = (time = "1792022400", entryBody: string = body) => {
    const signed = `{"body":${JSON.stringify(entryBody)},"integratedTime":1792022400,"logID":"${logID}","logIndex":7}`;
    const set = sign("sha256", Buffer.from(signed), p256.privateKey).toString(
      "base64",
    );
    return `{"body":${JSON.stringify(entryBody)},"integratedTime":${time},"logID":"${logID}","logIndex":7,"verification":{"signedEntryTimestamp":"${set}"}}`;
  };
  const options = {
    checkpointCose: cose,
    checkpointKeyId,
    rekorPublicKeySpki: rekorSpki,
  };

  it("refuses a Rekor key that is not ECDSA P-256", async () => {
    const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" });
    for (const other of [spki(p384.publicKey), spki(ed25519.publicKey)])
      expect(
        await verifyRekorReceipt(decodeStrictJson(entryText()), {
          ...options,
          rekorPublicKeySpki: other,
        }),
      ).toMatchObject({
        ok: false,
        reason: "the Rekor key is not an ECDSA P-256 key",
      });
  });

  it("refuses base64 with non-zero trailing bits in every receipt field", async () => {
    const alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    /** The same bytes spelled with non-zero trailing bits (padded input). */
    const nonCanonical = (text: string): string => {
      const at = text.length - 1 - (text.match(/=+$/u)?.[0].length ?? 0);
      expect(at).toBeLessThan(text.length - 1); // there is padding
      const next = alphabet[alphabet.indexOf(text[at]!) + 1]!;
      return `${text.slice(0, at)}${next}${text.slice(at + 1)}`;
    };
    const padded = (bytes: Buffer): Buffer =>
      bytes.length % 3 ? bytes : Buffer.concat([bytes, Buffer.from(" ")]);
    // signedEntryTimestamp: DER signatures vary in length, so find one whose
    // base64 is padded.
    let entry = JSON.parse(entryText()) as Record<string, unknown> & {
      verification: { signedEntryTimestamp: string };
    };
    while (!entry.verification.signedEntryTimestamp.endsWith("="))
      entry = JSON.parse(entryText());
    const set = entry.verification.signedEntryTimestamp;
    expect(
      (
        await verifyRekorReceipt(
          {
            ...entry,
            verification: { signedEntryTimestamp: nonCanonical(set) },
          },
          options,
        )
      ).ok,
    ).toBe(false);
    // body (padded with a trailing space if needed; JSON allows it).
    const bodyText = padded(Buffer.from(body, "base64")).toString("base64");
    expect(
      (
        await verifyRekorReceipt(
          decodeStrictJson(entryText(undefined, bodyText)),
          options,
        )
      ).ok,
    ).toBe(true);
    expect(
      (
        await verifyRekorReceipt(
          decodeStrictJson(entryText(undefined, nonCanonical(bodyText))),
          options,
        )
      ).ok,
    ).toBe(false);
    // receipt_b64 through verifyReceipt.
    const receiptB64 = padded(Buffer.from(entryText())).toString("base64");
    const record = { ts_url: "rekor+https://rekor.example" };
    expect(
      (
        await verifyReceipt(
          signed,
          { ...record, receipt_b64: receiptB64 },
          rekorSpki,
          cose,
        )
      ).ok,
    ).toBe(true);
    expect(
      (
        await verifyReceipt(
          signed,
          { ...record, receipt_b64: nonCanonical(receiptB64) },
          rekorSpki,
          cose,
        )
      ).ok,
    ).toBe(false);
    // A directory public_keys entry is skipped, so a rekor row has no key.
    const der = Buffer.from(rekorSpki).toString("base64"); // 91 bytes: padded
    const row = { binding: "rekor", key_ids: [logID] };
    expect(await witnessRowKeys({ ...row, public_keys: [der] })).toEqual([
      rekorSpki,
    ]);
    await expect(
      witnessRowKeys({ ...row, public_keys: [nonCanonical(der)] }),
    ).rejects.toThrow(TypeError);
  });

  it("verifies a Rekor entry with JSON integer times", async () => {
    expect(
      await verifyRekorReceipt(decodeStrictJson(entryText()), options),
    ).toMatchObject({ ok: true, grade: "observed-only" });
    // A plain JSON.parse value works too, for safe integers.
    expect(
      (await verifyRekorReceipt(JSON.parse(entryText()), options)).ok,
    ).toBe(true);
  });

  it("requires the Rekor payloadHash algorithm to be sha256", async () => {
    for (const payloadHash of [
      { algorithm: "sha512", value: coseHex },
      { algorithm: "SHA256", value: coseHex },
      { value: coseHex },
    ])
      expect(
        await verifyRekorReceipt(
          decodeStrictJson(entryText(undefined, bodyWith(payloadHash))),
          options,
        ),
      ).toMatchObject({
        ok: false,
        reason: expect.stringContaining("payloadHash"),
      });
  });

  it("refuses a Rekor time that is not a JSON integer, and loose base64", async () => {
    for (const time of ['"1792022400"', "1792022400.0", "17920224e5", "true"])
      expect(
        await verifyRekorReceipt(decodeStrictJson(entryText(time)), options),
      ).toMatchObject({ ok: false });
    // A body with a newline: signed as it is, but not canonical base64.
    expect(
      await verifyRekorReceipt(
        decodeStrictJson(entryText(undefined, `${body}\n`)),
        options,
      ),
    ).toMatchObject({ ok: false, reason: expect.stringContaining("base64") });
  });

  const signed: SignedCheckpointFields = {
    log_id: "log:test",
    mmr_size: 1,
    root: "00".repeat(32),
    key_id: checkpointKeyId,
    timestamp: "2026-10-15T00:00:00Z",
    prev_size: 0,
    prev_root: "",
  };

  it("reads a rekor receipt_b64 as canonical base64 of the entry", async () => {
    const record = {
      ts_url: "rekor+https://rekor.example",
      receipt_b64: Buffer.from(entryText()).toString("base64"),
    };
    expect((await verifyReceipt(signed, record, rekorSpki, cose)).ok).toBe(
      true,
    );
    expect(
      (
        await verifyReceipt(
          signed,
          { ...record, receipt_b64: ` ${record.receipt_b64}` },
          rekorSpki,
          cose,
        )
      ).ok,
    ).toBe(false);
  });

  it("fails a receipt under a raw key that is not an Ed25519 point", async () => {
    // The vectors' "Off-curve witness" key id.
    const [key] = await witnessRowKeys({ key_ids: ["ff".repeat(32)] });
    const eddsa = receipt("a2012719018b01", ed25519.privateKey, {
      es256: false,
    });
    const result = await verifyCoseReceipt(eddsa, leaf, key!);
    expect(result.ok).toBe(false);
    expect(result).not.toHaveProperty("unavailable");
    // Even when WebCrypto refuses to import it: a runtime that imports a
    // valid Ed25519 key refused this one.
    const subtle = globalThis.crypto.subtle;
    const offCurve = Buffer.from(key!).toString("hex");
    vi.stubGlobal("crypto", {
      subtle: {
        digest: subtle.digest.bind(subtle),
        verify: subtle.verify.bind(subtle),
        importKey: (
          format: "spki",
          data: Uint8Array,
          ...rest: [AlgorithmIdentifier, boolean, KeyUsage[]]
        ) =>
          Buffer.from(data).toString("hex") === offCurve
            ? Promise.reject(
                Object.assign(new Error("not a point"), {
                  name: "DataError",
                }),
              )
            : subtle.importKey(format, data as BufferSource, ...rest),
      },
    });
    const refused = await verifyCoseReceipt(eddsa, leaf, key!);
    expect(refused.ok).toBe(false);
    expect(refused).not.toHaveProperty("unavailable");
  });

  it("fails deeply nested JSON in a Rekor receipt, never throws", async () => {
    const deep = `${"[".repeat(200_000)}${"]".repeat(200_000)}`;
    const record = {
      ts_url: "rekor+https://rekor.example",
      receipt_b64: Buffer.from(deep).toString("base64"),
    };
    expect(await verifyReceipt(signed, record, rekorSpki, cose)).toMatchObject({
      ok: false,
    });
    // A body nesting that deep, under a valid Signed Entry Timestamp.
    const deepBody = Buffer.from(deep).toString("base64");
    expect(
      await verifyRekorReceipt(
        decodeStrictJson(entryText(undefined, deepBody)),
        options,
      ),
    ).toMatchObject({ ok: false });
  });

  it("does not check what it cannot run", async () => {
    // No checkpoint COSE statement for a rekor or scrapi receipt, no key.
    expect(
      await verifyReceipt(
        signed,
        { ts_url: "scrapi+https://s.example", receipt_b64: "" },
        rekorSpki,
        undefined,
      ),
    ).toMatchObject({ ok: false, notChecked: true });
    expect(
      await verifyScrapiReceipt(new Uint8Array(), {
        checkpointCose: cose,
        servicePublicKeySpki: undefined,
      }),
    ).toMatchObject({ ok: false, notChecked: true });
    // A runtime without the receipt's algorithm.
    const good = receipt(ES256_HEADERS, p256.privateKey);
    const subtle = globalThis.crypto.subtle;
    vi.stubGlobal("crypto", {
      subtle: {
        digest: subtle.digest.bind(subtle),
        importKey: () =>
          Promise.reject(
            Object.assign(new Error("unsupported"), {
              name: "NotSupportedError",
            }),
          ),
      },
    });
    expect(await verifyCoseReceipt(good, leaf, rekorSpki)).toMatchObject({
      ok: false,
      unavailable: true,
    });
  });
});

describe("witness helpers", () => {
  it("escapes the checkpoint digest's strings as Python's json.dumps does", async () => {
    // A log_id holding "&<>/", DEL, "é" and an astral character. CLL refuses
    // such an identifier, but the digest must still escape exactly. The value
    // is Python's: json.dumps(body, sort_keys=True, separators=(",", ":")).
    const checkpoint: SignedCheckpointFields = {
      log_id: "log:a&b<c>/\u007fé\u{1f600}",
      mmr_size: 4,
      root: "fbeaa9c465d418241a4c7c7dfd13b8c73040eb39c16761b10b488cc4858ca8a9",
      key_id:
        "9475c6cf0eda34057528d8694781ecc92ad639d7e2bd27761ed3ef74924beb07",
      timestamp: "2026-10-15T00:00:00Z",
      prev_size: 0,
      prev_root: "",
    };
    expect(await checkpointDigest(checkpoint)).toBe(
      "bec8b05079b72840010d5fe4017c771e5986464946dc3ab56b318c406e268afd",
    );
  });

  it("reads base64 only in its canonical spelling", () => {
    const decoded = (text: string) =>
      Buffer.from(base64Canonical(text)).toString("hex");
    expect(decoded("AA==")).toBe("00");
    expect(decoded("AAA=")).toBe("0000");
    expect(decoded("AQID")).toBe("010203");
    expect(decoded("")).toBe("");
    for (const bad of [
      "QR",
      "AA",
      "AA=",
      "AA=A",
      "AA==BB",
      "AA =",
      "A-_=",
      5,
      // Non-zero trailing bits: Python's validate=True alone accepts these.
      "AB==",
      "AAB=",
      "AQJ=",
    ])
      expect(() => base64Canonical(bad)).toThrow(TypeError);
  });

  it("reads hex as Python's bytes.fromhex does", () => {
    expect(Array.from(fromHex(" 0a 0B  "))).toEqual([10, 11]);
    for (const bad of ["0 a", "0a 0", "zz", 5])
      expect(() => fromHex(bad)).toThrow(TypeError);
  });

  it("names a witness's binding and endpoint by its URL", () => {
    expect(bindingOf("REKOR+https://r.example/")).toBe("rekor");
    expect(bindingOf("scrapi+https://s.example")).toBe("scrapi");
    expect(bindingOf("https://w.example")).toBe("cll");
    expect(endpointOf("rekor+https://r.example//")).toBe("https://r.example");
    const rows = [
      { endpoint: "https://w.example/", key_ids: [] },
      { endpoint: "https://r.example", binding: "rekor", key_ids: [] },
    ];
    // A directory is the parsed witnesses.json or its row list.
    for (const directory of [rows, { witnesses: rows }]) {
      expect(witnessRowFor(directory, "https://w.example")).toBe(rows[0]);
      expect(witnessRowFor(directory, "rekor+https://r.example/")).toBe(
        rows[1],
      );
      expect(witnessRowFor(directory, "https://r.example")).toBeUndefined();
    }
    expect(
      witnessRowFor([{ endpoint: null }], "https://w.example"),
    ).toBeUndefined();
    // Every trailing "/" is removed on both sides, and the binding's scheme
    // is compared without case.
    const scrapi = { endpoint: "https://s.example///", binding: "scrapi" };
    expect(witnessRowFor([scrapi], "ScRaPi+https://s.example//")).toBe(scrapi);
    expect(endpointOf("https://w.example///")).toBe("https://w.example");
  });

  it("refuses a row whose key cannot be read", async () => {
    const raw = "11".repeat(32);
    expect(await witnessRowKeys({ key_ids: [raw] })).toHaveLength(1);
    for (const row of [
      { key_ids: ["11"] }, // not a 32-byte key
      { key_ids: [["list"]] },
      { key_ids: [raw], binding: "rekor" }, // a log ID with no public key
      { key_ids: 5 },
      { key_ids: raw }, // a string is not a list
      { key_ids: ["AB".repeat(32)] }, // key ids are lowercase hex
      { key_ids: [` ${raw}`] },
      { key_ids: [raw], public_keys: null },
      { key_ids: [raw], public_keys: "AA==" },
    ])
      await expect(witnessRowKeys(row)).rejects.toThrow(TypeError);
    expect(await witnessRowKeys({})).toEqual([]);
    // A public_keys entry is found by the SHA-256 of its DER; one that is
    // not canonical base64 is skipped, leaving the row usable.
    const der = spki(p256.publicKey); // 91 bytes: its base64 is padded
    const id = createHash("sha256").update(der).digest("hex");
    const padded = Buffer.from(der).toString("base64"),
      unpadded = padded.replace(/=+$/u, "");
    expect(unpadded).not.toBe(padded);
    expect(
      await witnessRowKeys({
        binding: "rekor",
        key_ids: [id],
        public_keys: ["not base64!", unpadded, padded],
      }),
    ).toEqual([der]);
    // Unpadded, the only entry is skipped and the rekor key id has no key.
    await expect(
      witnessRowKeys({
        binding: "rekor",
        key_ids: [id],
        public_keys: [unpadded],
      }),
    ).rejects.toThrow(TypeError);
  });

  it("counts only Ed25519 and on-curve P-256 public_keys entries", async () => {
    const entry = (key: KeyObject) => {
      const der = spki(key);
      return {
        der,
        id: createHash("sha256").update(der).digest("hex"),
        b64: Buffer.from(der).toString("base64"),
      };
    };
    // An on-curve P-256 key and an Ed25519 key count.
    for (const counted of [entry(p256.publicKey), entry(ed25519.publicKey)])
      expect(
        await witnessRowKeys({
          binding: "rekor",
          key_ids: [counted.id],
          public_keys: [counted.b64],
        }),
      ).toEqual([counted.der]);
    // An RSA, secp256k1 or P-384 key, or a P-256 key whose point is off the
    // curve, is skipped: a rekor row naming only it has no key.
    const rsa = entry(
      generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey,
    );
    const k1 = entry(
      generateKeyPairSync("ec", { namedCurve: "secp256k1" }).publicKey,
    );
    const p384 = entry(
      generateKeyPairSync("ec", { namedCurve: "secp384r1" }).publicKey,
    );
    const off = Uint8Array.from(spki(p256.publicKey));
    off[off.length - 1] = off[off.length - 1]! ^ 1;
    const offEntry = {
      id: createHash("sha256").update(off).digest("hex"),
      b64: Buffer.from(off).toString("base64"),
    };
    for (const skipped of [rsa, k1, p384, offEntry])
      await expect(
        witnessRowKeys({
          binding: "rekor",
          key_ids: [skipped.id],
          public_keys: [skipped.b64],
        }),
      ).rejects.toThrow(TypeError);
  });

  it("skips a public_keys entry that decodes but is not a SubjectPublicKeyInfo", async () => {
    const notSpki = Buffer.from("not a key, but canonical base64");
    const notSpkiId = createHash("sha256").update(notSpki).digest("hex");
    const der = spki(p256.publicKey);
    const id = createHash("sha256").update(der).digest("hex");
    const entries = [
      notSpki.toString("base64"),
      Buffer.from(der).toString("base64"),
    ];
    // Beside a good entry, the bad one is skipped.
    expect(
      await witnessRowKeys({
        binding: "rekor",
        key_ids: [id],
        public_keys: entries,
      }),
    ).toEqual([der]);
    // Named by its own digest in a rekor row: no public key for that log ID.
    await expect(
      witnessRowKeys({
        binding: "rekor",
        key_ids: [notSpkiId],
        public_keys: entries,
      }),
    ).rejects.toThrow(TypeError);
    // In a cll row the key id then reads as a raw Ed25519 key.
    expect(
      await witnessRowKeys({ key_ids: [notSpkiId], public_keys: entries }),
    ).toEqual([
      new Uint8Array([
        ...Buffer.from("302a300506032b6570032100", "hex"),
        ...Buffer.from(notSpkiId, "hex"),
      ]),
    ]);
  });
});

describe("strict verification without Ed25519", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("throws instead of returning a verdict", async () => {
    const bundle = (
      JSON.parse(
        readFileSync(
          resolve(
            process.cwd(),
            "..",
            "vectors",
            "bundle",
            "strict",
            "vectors.json",
          ),
          "utf8",
        ),
      ) as { cases: { bundle: unknown }[] }
    ).cases[0]!.bundle;
    vi.stubGlobal("crypto", undefined);
    await expect(verifyBundle(bundle, { strict: true })).rejects.toBeInstanceOf(
      Ed25519UnavailableError,
    );
    expect((await verifyBundle(bundle)).graphClosure.status).toBe("pass");
  });
});
