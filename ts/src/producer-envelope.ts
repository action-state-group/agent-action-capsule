import {
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";
import { decode } from "cborg";
import {
  CONTENT_TYPE,
  type EnvelopeVerificationResult,
  type SigningIdentity,
} from "./types.js";

const hex64 = /^[0-9a-f]{64}$/u;
const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");

function head(major: number, length: number): Uint8Array {
  if (length < 24) return Uint8Array.of((major << 5) | length);
  if (length < 256) return Uint8Array.of((major << 5) | 24, length);
  if (length < 65536)
    return Uint8Array.of((major << 5) | 25, length >>> 8, length & 255);
  throw new RangeError("CBOR value too large");
}
function concat(...parts: readonly Uint8Array[]): Uint8Array {
  return Buffer.concat(parts);
}
function bstr(value: Uint8Array): Uint8Array {
  return concat(head(2, value.length), value);
}
function tstr(value: string): Uint8Array {
  const bytes = Buffer.from(value);
  return concat(head(3, bytes.length), bytes);
}
function array(parts: readonly Uint8Array[]): Uint8Array {
  return concat(head(4, parts.length), ...parts);
}

function protectedHeaders(publicKey: Uint8Array): Uint8Array {
  return concat(
    Uint8Array.of(0xa3, 0x03),
    tstr(CONTENT_TYPE),
    Uint8Array.of(0x04),
    bstr(publicKey),
    Uint8Array.of(0x01, 0x27),
  );
}
function sigStructure(
  protectedBytes: Uint8Array,
  payload: Uint8Array,
): Uint8Array {
  return array([
    tstr("Signature1"),
    bstr(protectedBytes),
    bstr(new Uint8Array()),
    bstr(payload),
  ]);
}

/** Construct an immutable Ed25519 identity from a 32-byte seed or PKCS#8 key. */
export function createEd25519Identity(
  privateKey: Uint8Array | KeyObject,
): SigningIdentity {
  const key =
    privateKey instanceof Uint8Array
      ? createPrivateKey({
          key: Buffer.from(concat(pkcs8Prefix, privateKey)),
          format: "der",
          type: "pkcs8",
        })
      : privateKey;
  if (key.asymmetricKeyType !== "ed25519")
    throw new TypeError("Producer Envelope signer must use Ed25519");
  const der = createPublicKey(key).export({ format: "der", type: "spki" });
  const publicKey = new Uint8Array(der.subarray(der.length - 32));
  return Object.freeze({ privateKey: key, publicKey });
}

export function createSigningIdentity(
  privateKey: KeyObject,
  rawPublicKey: Uint8Array,
): SigningIdentity {
  if (privateKey.asymmetricKeyType !== "ed25519" || rawPublicKey.length !== 32)
    throw new TypeError("valid Ed25519 key pair required");
  const derived = createEd25519Identity(privateKey);
  if (!Buffer.from(derived.publicKey).equals(Buffer.from(rawPublicKey)))
    throw new TypeError("signer does not match public key");
  return Object.freeze({
    privateKey,
    publicKey: Uint8Array.from(rawPublicKey),
  });
}

export function signCapsuleId(
  capsuleId: string,
  identity: SigningIdentity,
): Uint8Array {
  if (!hex64.test(capsuleId))
    throw new TypeError(
      "Capsule ID must be 64 lowercase hexadecimal characters",
    );
  if (
    identity.publicKey.length !== 32 ||
    identity.privateKey.asymmetricKeyType !== "ed25519"
  )
    throw new TypeError("valid Ed25519 signing identity is required");
  const payload = Buffer.from(capsuleId, "hex");
  const protectedBytes = protectedHeaders(identity.publicKey);
  const signature = edSign(
    null,
    sigStructure(protectedBytes, payload),
    identity.privateKey,
  );
  return concat(
    Uint8Array.of(0xd2),
    array([
      bstr(protectedBytes),
      Uint8Array.of(0xa0),
      bstr(payload),
      bstr(signature),
    ]),
  );
}

class Reader {
  public offset = 0;
  public constructor(private readonly data: Uint8Array) {}
  public byte(): number {
    const value = this.data[this.offset++];
    if (value === undefined) throw new SyntaxError("truncated CBOR");
    return value;
  }
  public length(major: number): number {
    const first = this.byte();
    if (first >>> 5 !== major) throw new SyntaxError("unexpected CBOR type");
    const add = first & 31;
    if (add < 24) return add;
    if (add === 24) return this.byte();
    if (add === 25) return (this.byte() << 8) | this.byte();
    throw new SyntaxError("unsupported or indefinite CBOR length");
  }
  public bytes(): Uint8Array {
    const length = this.length(2);
    const end = this.offset + length;
    if (end > this.data.length) throw new SyntaxError("truncated CBOR bytes");
    const value = this.data.slice(this.offset, end);
    this.offset = end;
    return value;
  }
}

export function verifyProducerEnvelope(
  capsuleId: string,
  data: Uint8Array,
): EnvelopeVerificationResult {
  const fail = (code: string, detail: string): EnvelopeVerificationResult => ({
    ok: false,
    findings: [{ code, detail }],
    capsuleId,
  });
  if (!hex64.test(capsuleId))
    return fail(
      "capsule_id_malformed",
      "capsule_id MUST be 64 lowercase hexadecimal characters",
    );
  if (data.length > 4096)
    return fail(
      "envelope_too_large",
      `producer envelope is ${data.length} bytes; maximum is 4096`,
    );
  try {
    const reader = new Reader(data);
    if (reader.byte() !== 0xd2 || reader.length(4) !== 4)
      throw new SyntaxError(
        "top-level value MUST be tagged COSE_Sign1 with four array elements",
      );
    const protectedBytes = reader.bytes();
    if (reader.byte() !== 0xa0)
      throw new SyntaxError("unprotected header MUST be an empty map");
    const payload = reader.bytes();
    const signature = reader.bytes();
    if (reader.offset !== data.length)
      throw new SyntaxError("trailing CBOR data");
    const protectedHeaders = decode(protectedBytes, {
      allowIndefinite: false,
      coerceUndefinedToNull: false,
      useMaps: true,
    }) as unknown;
    if (!(protectedHeaders instanceof Map) || protectedHeaders.size !== 3)
      return fail(
        "envelope_protected_headers_invalid",
        "protected header MUST contain exactly content type, kid, and alg",
      );
    if (protectedHeaders.get(3) !== CONTENT_TYPE)
      return fail(
        "envelope_content_type_mismatch",
        `protected content type MUST be ${CONTENT_TYPE}`,
      );
    const publicKey = protectedHeaders.get(4);
    if (!(publicKey instanceof Uint8Array))
      return fail(
        "envelope_kid_invalid",
        "protected kid (label 4) MUST be raw 32-byte Ed25519 public key",
      );
    if (publicKey.length !== 32)
      return fail(
        "envelope_kid_invalid",
        "protected kid (label 4) MUST be the raw 32-byte Ed25519 public key",
      );
    if (protectedHeaders.get(1) !== -8)
      return fail(
        "envelope_algorithm_mismatch",
        "protected alg (label 1) MUST be EdDSA (-8)",
      );
    if (!Buffer.from(payload).equals(Buffer.from(capsuleId, "hex")))
      return fail(
        "envelope_payload_mismatch",
        "attached payload MUST equal the raw 32-byte Capsule ID",
      );
    if (signature.length !== 64)
      return fail(
        "envelope_signature_invalid",
        "Ed25519 signature MUST be 64 bytes",
      );
    const key = createPublicKey({
      key: Buffer.from(concat(spkiPrefix, publicKey)),
      format: "der",
      type: "spki",
    });
    if (!edVerify(null, sigStructure(protectedBytes, payload), key, signature))
      return fail(
        "envelope_signature_invalid",
        "Ed25519 signature verification failed",
      );
    return {
      ok: true,
      findings: [],
      capsuleId,
      publicKey: Uint8Array.from(publicKey),
    };
  } catch (error) {
    return fail("envelope_malformed", String(error));
  }
}
