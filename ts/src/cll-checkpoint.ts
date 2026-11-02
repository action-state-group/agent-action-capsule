// Readers for CLL checkpoints and inclusion proofs shared by the strict
// Bundle checks (bundle.ts) and the parent-log-witness/v1 check
// (parent-witness.ts). Internal: the package entry points do not re-export it.
import {
  rootFromPeaks,
  verifyHexInclusion,
  type MmrInclusionProof,
} from "@action-state-group/cll";
import { isHex64, JsonNumber } from "./json.js";
import type { SignedCheckpointFields } from "./witness.js";

// A JsonNumber (a decoded number kept with its spelling) is a value, not a
// Bundle object.
export const object = (value: unknown): value is Record<string, unknown> =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  !(value instanceof JsonNumber);
export const integer = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value);
export const hex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../gu)!, (byte) => Number.parseInt(byte, 16));

export const encodeBase64Url = (bytes: Uint8Array): string =>
  btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
/**
 * Decode unpadded base64url, refusing non-zero trailing bits so each byte
 * string has one spelling, as the Go (strict), Python and Rust decoders do.
 */
export function base64UrlDecode(value: string): Uint8Array {
  const padded = `${value}${"=".repeat((4 - (value.length % 4)) % 4)}`;
  const binary = atob(padded.replaceAll("-", "+").replaceAll("_", "/"));
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  if (encodeBase64Url(bytes) !== value)
    throw new TypeError("non-canonical base64url");
  return bytes;
}
/** A `cose` member's octets, or undefined when it is not unpadded canonical base64url. */
export function decodeCose(encoded: unknown): Uint8Array | undefined {
  if (typeof encoded !== "string" || !/^[A-Za-z0-9_-]*$/u.test(encoded))
    return undefined;
  try {
    return base64UrlDecode(encoded);
  } catch {
    return undefined;
  }
}

// Load cll's COSE checkpoint authenticator through a dynamic import, so that a
// cll without it resolves to undefined instead of failing to load. The pinned
// cll exports it from both its Node and its browser entry.
export type CheckpointMetadata = (cose: Uint8Array) => Promise<
  | {
      logId: string;
      size: bigint;
      root: string;
      keyId: string;
      timestamp: string;
      previousSize: bigint;
      previousRoot: string;
    }
  | undefined
>;
export async function loadCheckpointMetadata(): Promise<
  CheckpointMetadata | undefined
> {
  try {
    const module = (await import("@action-state-group/cll")) as {
      checkpointMetadata?: CheckpointMetadata;
    };
    return typeof module.checkpointMetadata === "function"
      ? module.checkpointMetadata
      : undefined;
  } catch {
    return undefined;
  }
}
/**
 * The signed fields of a CLL COSE checkpoint that verifies under its own key,
 * or undefined when it does not verify (or no authenticator is available).
 */
export async function signedCheckpointFields(
  cose: Uint8Array,
  checkpointMetadata?: CheckpointMetadata,
): Promise<SignedCheckpointFields | undefined> {
  const verify = checkpointMetadata ?? (await loadCheckpointMetadata());
  if (verify === undefined) return undefined;
  let metadata: Awaited<ReturnType<CheckpointMetadata>>;
  try {
    metadata = await verify(cose);
  } catch {
    return undefined;
  }
  return metadata === undefined
    ? undefined
    : {
        log_id: metadata.logId,
        mmr_size: Number(metadata.size),
        root: metadata.root,
        key_id: metadata.keyId,
        timestamp: metadata.timestamp,
        prev_size: Number(metadata.previousSize),
        prev_root: metadata.previousRoot,
      };
}

/** A membership's `inclusion_proof`, or undefined when it is malformed. */
export function parseProof(raw: unknown): MmrInclusionProof | undefined {
  if (
    !object(raw) ||
    raw.v !== 1 ||
    raw.kind !== "inclusion" ||
    !integer(raw.size) ||
    !integer(raw.leaf_index) ||
    raw.size < 0 ||
    raw.leaf_index < 0
  )
    return undefined;
  const hashes = (value: unknown): string[] | undefined =>
    Array.isArray(value) && value.every(isHex64) ? value : undefined;
  const witness = hashes(raw.witness),
    left = hashes(raw.peaks_left),
    right = hashes(raw.peaks_right);
  return witness && left && right
    ? {
        v: 1,
        kind: "inclusion",
        size: raw.size,
        leaf_index: raw.leaf_index,
        witness,
        peaks_left: left,
        peaks_right: right,
      }
    : undefined;
}
/** Whether `proof` proves the leaf of `identity` (hex) at `leafIndex` under `root`. */
export async function verifyProof(
  root: Uint8Array,
  identity: string,
  proof: MmrInclusionProof,
  leafIndex = proof.leaf_index,
): Promise<boolean> {
  const flattened = proof.witness.map(hex);
  if (proof.peaks_right.length)
    flattened.push(await rootFromPeaks(proof.peaks_right.map(hex)));
  flattened.push(...proof.peaks_left.map(hex).toReversed());
  return verifyHexInclusion(
    root,
    BigInt(proof.size),
    BigInt(leafIndex),
    identity,
    flattened,
  );
}
