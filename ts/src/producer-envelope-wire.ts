const encoder = new TextEncoder();

export const CONTENT_TYPE = "application/agent-action-capsule-id";
export const hex64 = /^[0-9a-f]{64}$/u;

export function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(
    parts.reduce((length, part) => length + part.length, 0),
  );
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

export function hexToBytes(value: string): Uint8Array {
  const result = new Uint8Array(value.length / 2);
  for (let i = 0; i < result.length; i += 1)
    result[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return result;
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.length === right.length &&
    left.every((byte, index) => byte === right[index])
  );
}

function head(major: number, length: number): Uint8Array {
  if (length < 24) return Uint8Array.of((major << 5) | length);
  if (length < 256) return Uint8Array.of((major << 5) | 24, length);
  if (length < 65536)
    return Uint8Array.of((major << 5) | 25, length >>> 8, length & 255);
  throw new RangeError("CBOR value too large");
}

function bstr(value: Uint8Array): Uint8Array {
  return concat(head(2, value.length), value);
}

function tstr(value: string): Uint8Array {
  const bytes = encoder.encode(value);
  return concat(head(3, bytes.length), bytes);
}

function array(parts: readonly Uint8Array[]): Uint8Array {
  return concat(head(4, parts.length), ...parts);
}

export function producerProtectedHeaders(publicKey: Uint8Array): Uint8Array {
  return concat(
    Uint8Array.of(0xa3, 0x03),
    tstr(CONTENT_TYPE),
    Uint8Array.of(0x04),
    bstr(publicKey),
    Uint8Array.of(0x01, 0x27),
  );
}

/** Bytes covered by the Producer Envelope Ed25519 signature. */
export function producerEnvelopeSigningBytes(
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

export function encodeProducerEnvelope(
  protectedBytes: Uint8Array,
  payload: Uint8Array,
  signature: Uint8Array,
): Uint8Array {
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

const spkiPrefix = hexToBytes("302a300506032b6570032100");

export function producerPublicKeySpki(publicKey: Uint8Array): Uint8Array {
  return concat(spkiPrefix, publicKey);
}
