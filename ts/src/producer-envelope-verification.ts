import { decode } from "cborg";
import {
  CONTENT_TYPE,
  equalBytes,
  hex64,
  hexToBytes,
  producerEnvelopeSigningBytes,
  producerPublicKeySpki,
} from "./producer-envelope-wire.js";

export interface EnvelopeFinding {
  readonly code: string;
  readonly detail: string;
}

export interface EnvelopeVerificationResult {
  readonly ok: boolean;
  readonly findings: readonly EnvelopeFinding[];
  readonly capsuleId: string;
  readonly publicKey?: Uint8Array;
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

/** Verify an attached AAC Producer Envelope with platform WebCrypto. */
export async function verifyProducerEnvelope(
  capsuleId: string,
  data: Uint8Array,
): Promise<EnvelopeVerificationResult> {
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
    if (!equalBytes(payload, hexToBytes(capsuleId)))
      return fail(
        "envelope_payload_mismatch",
        "attached payload MUST equal the raw 32-byte Capsule ID",
      );
    if (signature.length !== 64)
      return fail(
        "envelope_signature_invalid",
        "Ed25519 signature MUST be 64 bytes",
      );
    const key = await globalThis.crypto.subtle.importKey(
      "spki",
      producerPublicKeySpki(publicKey) as BufferSource,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    if (
      !(await globalThis.crypto.subtle.verify(
        { name: "Ed25519" },
        key,
        signature as BufferSource,
        producerEnvelopeSigningBytes(protectedBytes, payload) as BufferSource,
      ))
    )
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
