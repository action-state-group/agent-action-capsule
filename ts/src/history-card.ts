// history_card/2 of draft-mih-agent-evidence-request-03 §8.1.2: the
// positions a card lists, and whether a card in Checkpointed Local Log form
// verifies. Checkpoints are the interop profile's COSE_Sign1 cll-checkpoint
// statements (§6.2.1 step 7) and proofs cll-consistency-proof octets (MMR -02
// §7.1), both as lowercase hex. Receipts are read in the form
// vectors/evidence-request/history-card-2.json fixes: {checkpoint, witness,
// sig}, Ed25519 by witness over UTF-8 of JCS of {checkpoint, witness}.

import {
  CborMap,
  CborTag,
  decodeReceiptItem,
  decodeWellFormedItem,
  type CborValue,
} from "./cose-receipt.js";
import { verifyEd25519Strict } from "./ed25519-strict.js";
import { jcs } from "./json.js";
import { sha256 } from "./sha256.js";

/** The bounded history card (§8.1.2). */
export const DERIVATION_HISTORY_CARD_2 = "history_card/2";
/** The largest window a card may state (§8.1.2). */
export const MAX_HISTORY_WINDOW = 64;
/** The findings of {@link checkHistoryCard2}, in check order. */
export const HISTORY_CARD_FINDINGS = [
  "card_malformed",
  "window_out_of_range",
  "positions_not_increasing_from_zero",
  "position_missing",
  "position_unexpected",
  "checkpoint_invalid",
  "first_checkpoint_has_predecessor",
  "checkpoint_shrinks",
  "proof_invalid",
  "receipt_invalid",
  "anchor_mismatch",
] as const;
export type HistoryCardFinding = (typeof HISTORY_CARD_FINDINGS)[number];

/**
 * P(n, W) (§8.1.2): 0, n - 2^k for every 2^k <= n, and max(0, n - W + 1)
 * through n, ascending, each once. n and W are safe integers.
 */
export function historyPositions(n: number, window: number): number[] {
  if (
    !Number.isSafeInteger(n) ||
    !Number.isSafeInteger(window) ||
    n < 0 ||
    window < 0
  )
    throw new RangeError("n and window are unsigned safe integers");
  const out = new Set<number>([0]);
  for (let step = 1; step <= n; step *= 2) out.add(n - step);
  for (let p = Math.max(0, n - window + 1); p <= n; p++) out.add(p);
  return [...out].sort((a, b) => a - b);
}

const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const MAX_PATH = 64;
const MAX_HEIGHT = 52n;

const isUint = (v: unknown): v is number =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const isMap = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);

function lowerHex(v: unknown): Uint8Array | undefined {
  if (typeof v !== "string" || v.length % 2 !== 0 || !/^[0-9a-f]*$/u.test(v))
    return undefined;
  const out = new Uint8Array(v.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = Number.parseInt(v.slice(2 * i, 2 * i + 2), 16);
  return out;
}

const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

const equal = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i]);

// --- MMR -02, the functions the interop profile's CLL material uses ---------

const bitLength = (x: bigint): bigint => BigInt(x.toString(2).length);
const allOnes = (pos: bigint): boolean =>
  pos !== 0n && (pos & (pos + 1n)) === 0n;

function indexHeight(i: bigint): bigint {
  let pos = i + 1n;
  while (!allOnes(pos)) pos = pos - (1n << (bitLength(pos) - 1n)) + 1n;
  return bitLength(pos) - 1n;
}

function hashPosPair(
  pos: bigint,
  left: Uint8Array,
  right: Uint8Array,
): Uint8Array {
  const data = new Uint8Array(8 + left.length + right.length);
  new DataView(data.buffer).setBigUint64(0, pos);
  data.set(left, 8);
  data.set(right, 8 + left.length);
  return sha256(data);
}

function includedRoot(
  i: bigint,
  node: Uint8Array,
  path: readonly Uint8Array[],
): Uint8Array {
  let root = node;
  let g = indexHeight(i);
  for (const sibling of path) {
    if (indexHeight(i + 1n) > g) {
      i += 1n;
      root = hashPosPair(i + 1n, sibling, root);
    } else {
      i += 2n << g;
      root = hashPosPair(i + 1n, root, sibling);
    }
    g += 1n;
  }
  return root;
}

function peakIndices(i: bigint): bigint[] {
  const out: bigint[] = [];
  let peak = 0n;
  let size = i + 1n;
  while (size > 0n) {
    const highest = (1n << (bitLength(size + 1n) - 1n)) - 1n;
    peak += highest;
    out.push(peak - 1n);
    size -= highest;
  }
  return out;
}

const nodeList = (v: CborValue): Uint8Array[] | undefined =>
  Array.isArray(v) &&
  v.length <= MAX_PATH &&
  v.every((x) => x instanceof Uint8Array && x.length === 32)
    ? (v as Uint8Array[])
    : undefined;

/** Whether cll-consistency-proof `octets`, between tree sizes `from` and `to`, prove `newPeaks` extends `oldPeaks`. */
function consistencyHolds(
  octets: Uint8Array,
  from: bigint,
  to: bigint,
  oldPeaks: readonly Uint8Array[],
  newPeaks: readonly Uint8Array[],
): boolean {
  let proof: CborValue;
  try {
    proof = decodeReceiptItem(octets, false);
  } catch {
    return false;
  }
  if (!Array.isArray(proof) || proof.length !== 4) return false;
  const [size1, size2, rawPaths, rawRight] = proof as CborValue[];
  const right = nodeList(rawRight!);
  if (
    typeof size1 !== "bigint" ||
    typeof size2 !== "bigint" ||
    size1 !== from ||
    size2 !== to ||
    size1 < 1n ||
    size1 > size2 ||
    !Array.isArray(rawPaths) ||
    rawPaths.length > MAX_PATH ||
    right === undefined
  )
    return false;
  const paths = (rawPaths as CborValue[]).map(nodeList);
  if (paths.some((p) => p === undefined)) return false;
  const oldIndices = peakIndices(size1 - 1n);
  if (
    oldIndices.length !== paths.length ||
    oldIndices.length !== oldPeaks.length
  )
    return false;
  const roots: Uint8Array[] = [];
  for (let k = 0; k < oldIndices.length; k++) {
    const path = paths[k]!;
    if (indexHeight(oldIndices[k]!) + BigInt(path.length) > MAX_HEIGHT)
      return false;
    const root = includedRoot(oldIndices[k]!, oldPeaks[k]!, path);
    if (roots.length === 0 || !equal(roots[roots.length - 1]!, root))
      roots.push(root);
  }
  if (roots.length + right.length !== peakIndices(size2 - 1n).length)
    return false;
  const reached = [...roots, ...right];
  return (
    reached.length === newPeaks.length &&
    reached.every((r, k) => equal(r, newPeaks[k]!))
  );
}

// --- the cll-checkpoint statement ---------------------------------------------

interface Checkpoint {
  key: Uint8Array;
  logSize: bigint;
  prevSize: bigint;
  commitment: Uint8Array[];
  verified: boolean;
}

// RFC 3339 date-time, read as the profile's other checkers read issued_at:
// T and Z in either case, a real calendar date, hours below 24, minutes
// below 60 and seconds up to 60 (a leap second).
const RFC3339 =
  /^(\d{4})-(\d\d)-(\d\d)[Tt](\d\d):(\d\d):(\d\d)(\.\d+)?([Zz]|[+-]\d\d:\d\d)$/u;

function isRfc3339(value: string): boolean {
  const m = RFC3339.exec(value);
  if (m === null) return false;
  const [year, month, day, hour, minute, second] = m
    .slice(1, 7)
    .map(Number) as [number, number, number, number, number, number];
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return (
    year >= 1 &&
    month >= 1 &&
    month <= 12 &&
    day >= 1 &&
    day <= days[month - 1]! &&
    hour < 24 &&
    minute < 60 &&
    second <= 60
  );
}

function peakList(v: CborValue): Uint8Array[] | undefined {
  if (!(v instanceof Uint8Array)) return undefined;
  try {
    const list = nodeList(decodeReceiptItem(v, false));
    return list !== undefined && list.length > 0 ? list : undefined;
  } catch {
    return undefined;
  }
}

function textBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function bstrHead(length: number): Uint8Array {
  if (length < 24) return Uint8Array.of(0x40 | length);
  if (length < 0x100) return Uint8Array.of(0x58, length);
  if (length < 0x10000) return Uint8Array.of(0x59, length >> 8, length & 0xff);
  return Uint8Array.of(
    0x5a,
    length >>> 24,
    (length >> 16) & 0xff,
    (length >> 8) & 0xff,
    length & 0xff,
  );
}

/** The Signature1 Sig_structure with an empty external AAD (RFC 9052 §4.4). */
function sigStructure(
  protectedHeader: Uint8Array,
  payload: Uint8Array,
): Uint8Array {
  const parts = [
    Uint8Array.of(0x84, 0x6a),
    textBytes("Signature1"),
    bstrHead(protectedHeader.length),
    protectedHeader,
    Uint8Array.of(0x40),
    bstrHead(payload.length),
    payload,
  ];
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** The checkpoint, or undefined when it is not a well-formed EdDSA cll-checkpoint with no crit. */
async function readCheckpoint(
  octets: Uint8Array,
): Promise<Checkpoint | undefined> {
  let outer: CborValue;
  try {
    outer = decodeWellFormedItem(octets, true);
  } catch {
    return undefined;
  }
  if (
    !(outer instanceof CborTag) ||
    outer.tag !== 18n ||
    !Array.isArray(outer.value)
  )
    return undefined;
  const body = outer.value as CborValue[];
  if (body.length !== 4) return undefined;
  const [protectedHeader, unprotected, payload, signature] = body;
  if (
    !(protectedHeader instanceof Uint8Array) ||
    !(unprotected instanceof CborMap) ||
    unprotected.entries.length !== 0 ||
    !(payload instanceof Uint8Array) ||
    !(signature instanceof Uint8Array)
  )
    return undefined;
  let header: CborValue, claims: CborValue;
  try {
    header = decodeWellFormedItem(protectedHeader, false);
    claims = decodeWellFormedItem(payload, false);
  } catch {
    return undefined;
  }
  if (!(header instanceof CborMap) || !(claims instanceof CborMap))
    return undefined;
  const cwt = header.get(15n);
  const kid = header.get(4n);
  if (
    header.get(1n) !== -8n ||
    header.has(2n) ||
    !(cwt instanceof CborMap) ||
    !cwt.has(1n) ||
    !cwt.has(2n) ||
    !(kid instanceof Uint8Array) ||
    kid.length !== 32
  )
    return undefined;
  const logSize = claims.get("log_size");
  const prevSize = claims.get("prev_size");
  const issuedAt = claims.get("issued_at");
  if (
    claims.get("kind") !== "cll-checkpoint" ||
    typeof logSize !== "bigint" ||
    typeof prevSize !== "bigint" ||
    logSize < 0n ||
    prevSize < 0n ||
    prevSize > logSize ||
    logSize > BigInt(MAX_SAFE) ||
    typeof issuedAt !== "string" ||
    !isRfc3339(issuedAt)
  )
    return undefined;
  const commitment = peakList(claims.get("commitment"));
  if (commitment === undefined) return undefined;
  const prev = claims.get("prev_commitment");
  if (
    prevSize === 0n
      ? !(prev instanceof Uint8Array && prev.length === 0)
      : peakList(prev) === undefined
  )
    return undefined;
  let verified = false;
  try {
    verified = await verifyEd25519Strict(
      kid,
      signature,
      sigStructure(protectedHeader, payload),
    );
  } catch {
    verified = false;
  }
  return { key: kid, logSize, prevSize, commitment, verified };
}

async function receiptCovers(
  receipt: unknown,
  checkpoint: Uint8Array,
): Promise<boolean> {
  if (!isMap(receipt) || Object.keys(receipt).length !== 3) return false;
  const { checkpoint: covered, witness, sig } = receipt;
  const key = lowerHex(witness);
  const signature = lowerHex(sig);
  if (
    typeof covered !== "string" ||
    covered !== toHex(sha256(checkpoint)) ||
    key === undefined ||
    key.length !== 32 ||
    signature === undefined ||
    signature.length !== 64
  )
    return false;
  try {
    return await verifyEd25519Strict(
      key,
      signature,
      jcs({ checkpoint: covered, witness }),
    );
  } catch {
    return false;
  }
}

interface Entry {
  position: number;
  checkpoint: Uint8Array;
  receipts: unknown[];
  proof: Uint8Array | null;
}

function readCard(
  card: unknown,
): { window: number; entries: Entry[] } | undefined {
  if (!isMap(card) || !isUint(card.window) || !Array.isArray(card.history))
    return undefined;
  const entries: Entry[] = [];
  for (const raw of card.history as unknown[]) {
    if (!isMap(raw)) return undefined;
    if (
      ![
        "position",
        "checkpoint",
        "receipts",
        "consistency_from_previous",
      ].every((m) => m in raw)
    )
      return undefined;
    const checkpoint = lowerHex(raw.checkpoint);
    const proof =
      raw.consistency_from_previous === null
        ? null
        : lowerHex(raw.consistency_from_previous);
    if (
      !isUint(raw.position) ||
      checkpoint === undefined ||
      !Array.isArray(raw.receipts) ||
      proof === undefined
    )
      return undefined;
    entries.push({
      position: raw.position,
      checkpoint,
      receipts: raw.receipts as unknown[],
      proof,
    });
  }
  return { window: card.window, entries };
}

/**
 * Check `card`, the result map of a history_card/2 in Checkpointed Local Log
 * form, against `anchor` (SHA-256 of the octets of the checkpoint the
 * response resolved, lowercase hex) and the log keys the requester accepts
 * for the stream (lowercase hex). Resolves to null when every check of
 * §8.1.2 "Verifying" passes, else the first finding: card_malformed, then
 * checks 1 to 7 in order. Members a profile adds are ignored.
 */
export async function checkHistoryCard2(
  card: unknown,
  anchor: string,
  logKeys: readonly string[],
): Promise<HistoryCardFinding | null> {
  const read = readCard(card);
  if (read === undefined) return "card_malformed";
  const { window, entries } = read;
  if (window < 1 || window > MAX_HISTORY_WINDOW) return "window_out_of_range";
  const listed = entries.map((e) => e.position);
  if (
    listed.length === 0 ||
    listed[0] !== 0 ||
    listed.some((p, i) => i > 0 && p <= listed[i - 1]!)
  )
    return "positions_not_increasing_from_zero";
  const expected = historyPositions(listed[listed.length - 1]!, window);
  const have = new Set(listed);
  if (expected.some((p) => !have.has(p))) return "position_missing";
  if (listed.length !== expected.length) return "position_unexpected";

  const checkpoints: Checkpoint[] = [];
  for (const e of entries) {
    const cp = await readCheckpoint(e.checkpoint);
    if (cp === undefined || !cp.verified || !logKeys.includes(toHex(cp.key)))
      return "checkpoint_invalid";
    const prev = checkpoints[checkpoints.length - 1];
    if (prev === undefined && cp.prevSize !== 0n)
      return "first_checkpoint_has_predecessor";
    if (prev !== undefined && cp.logSize < prev.logSize)
      return "checkpoint_shrinks";
    checkpoints.push(cp);
  }

  for (let i = 0; i < entries.length; i++) {
    const proof = entries[i]!.proof;
    if (i === 0) {
      if (proof !== null) return "proof_invalid";
      continue;
    }
    const prev = checkpoints[i - 1]!;
    const cur = checkpoints[i]!;
    if (
      proof === null ||
      !consistencyHolds(
        proof,
        prev.logSize,
        cur.logSize,
        prev.commitment,
        cur.commitment,
      )
    )
      return "proof_invalid";
  }

  for (const e of entries)
    for (const r of e.receipts)
      if (!(await receiptCovers(r, e.checkpoint))) return "receipt_invalid";

  if (toHex(sha256(entries[entries.length - 1]!.checkpoint)) !== anchor)
    return "anchor_mismatch";
  return null;
}
