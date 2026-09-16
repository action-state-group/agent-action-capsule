import { decode } from "cborg";
import {
  equalBytes,
  hexToBytes,
  producerEnvelopeSigningBytes,
  producerPublicKeySpki,
} from "./producer-envelope-wire.js";

/** Content type for a COSE_Sign1 countersignature over a bundle digest. */
export const BUNDLE_DIGEST_CONTENT_TYPE =
  "application/agent-action-capsule-bundle-digest";

/** A public countersigner directory entry. Display fields never come from the bundle. */
export interface CountersignerDirectoryEntry {
  readonly publicKey: string;
  readonly name: string;
  readonly logoDataUrl: string;
  readonly checksRecomputed: number;
}

/**
 * The stamp's rendered state. It draws only after a countersignature's COSE
 * signature over the bundle digest has independently verified:
 * - "hollow": no countersignatures[] entries -- the default.
 * - "producer": the verified signer is the producer's own key -- not independent.
 * - "directory": the verified signer resolves in the public countersigner
 *   directory; name/logo/checksRecomputed come from the directory, never the bundle.
 * - "unresolved": the signature verifies but the signer is neither the
 *   producer nor in the directory -- shown plainly rather than hidden.
 * - "invalid": an entry is present but malformed or fails to verify.
 */
export type CountersignatureStamp =
  | { readonly kind: "hollow" }
  | { readonly kind: "producer" }
  | {
      readonly kind: "directory";
      readonly name: string;
      readonly logoDataUrl: string;
      readonly checksRecomputed: number;
      readonly date?: string;
    }
  | { readonly kind: "unresolved" }
  | { readonly kind: "invalid" };

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

function decodeBase64Url(value: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]*$/u.test(value)) return undefined;
  try {
    const padded = `${value}${"=".repeat((4 - (value.length % 4)) % 4)}`;
    const binary = atob(padded.replaceAll("-", "+").replaceAll("_", "/"));
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    return undefined;
  }
}

/** Verify a tagged COSE_Sign1 countersignature over a 32-byte digest. */
async function verifyCoseSign1OverDigest(
  digestHex: string,
  cose: Uint8Array,
): Promise<Uint8Array | undefined> {
  try {
    const reader = new Reader(cose);
    if (reader.byte() !== 0xd2 || reader.length(4) !== 4) return undefined;
    const protectedBytes = reader.bytes();
    if (reader.byte() !== 0xa0) return undefined;
    const payload = reader.bytes();
    const signature = reader.bytes();
    if (reader.offset !== cose.length) return undefined;
    const protectedHeaders = decode(protectedBytes, {
      allowIndefinite: false,
      coerceUndefinedToNull: false,
      useMaps: true,
    }) as unknown;
    if (!(protectedHeaders instanceof Map) || protectedHeaders.size !== 3)
      return undefined;
    if (protectedHeaders.get(3) !== BUNDLE_DIGEST_CONTENT_TYPE)
      return undefined;
    const publicKey = protectedHeaders.get(4);
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32)
      return undefined;
    if (protectedHeaders.get(1) !== -8) return undefined;
    if (!equalBytes(payload, hexToBytes(digestHex))) return undefined;
    if (signature.length !== 64) return undefined;
    const key = await globalThis.crypto.subtle.importKey(
      "spki",
      producerPublicKeySpki(publicKey) as BufferSource,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const valid = await globalThis.crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      signature as BufferSource,
      producerEnvelopeSigningBytes(protectedBytes, payload) as BufferSource,
    );
    return valid ? Uint8Array.from(publicKey) : undefined;
  } catch {
    return undefined;
  }
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

interface RawCountersignature {
  readonly type?: unknown;
  readonly signature?: unknown;
  readonly signed_at?: unknown;
}

function object(value: unknown): RawCountersignature | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as RawCountersignature)
    : undefined;
}

/**
 * Classify countersignatures[] into stamp states. A bundle with no entries
 * (absent or empty) always classifies as a single hollow stamp.
 */
export async function classifyCountersignatures(
  entries: readonly unknown[],
  bundleDigest: string | undefined,
  producerPublicKeyHex: string | undefined,
  directory: readonly CountersignerDirectoryEntry[],
): Promise<readonly CountersignatureStamp[]> {
  if (entries.length === 0) return [{ kind: "hollow" }];
  if (bundleDigest === undefined)
    return entries.map(() => ({ kind: "invalid" }) as CountersignatureStamp);
  const byPublicKey = new Map(
    directory.map((entry) => [entry.publicKey, entry] as const),
  );
  const results: CountersignatureStamp[] = [];
  for (const raw of entries) {
    const entry = object(raw);
    if (
      entry === undefined ||
      entry.type !== "cose-sign1" ||
      typeof entry.signature !== "string"
    ) {
      results.push({ kind: "invalid" });
      continue;
    }
    const cose = decodeBase64Url(entry.signature);
    const publicKey =
      cose === undefined
        ? undefined
        : await verifyCoseSign1OverDigest(bundleDigest, cose);
    if (publicKey === undefined) {
      results.push({ kind: "invalid" });
      continue;
    }
    const keyHex = toHex(publicKey);
    if (producerPublicKeyHex !== undefined && keyHex === producerPublicKeyHex) {
      results.push({ kind: "producer" });
      continue;
    }
    const directoryEntry = byPublicKey.get(keyHex);
    if (directoryEntry !== undefined) {
      results.push({
        kind: "directory",
        name: directoryEntry.name,
        logoDataUrl: directoryEntry.logoDataUrl,
        checksRecomputed: directoryEntry.checksRecomputed,
        ...(typeof entry.signed_at === "string"
          ? { date: entry.signed_at }
          : {}),
      });
      continue;
    }
    results.push({ kind: "unresolved" });
  }
  return results;
}
