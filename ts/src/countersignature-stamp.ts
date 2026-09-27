import { jcs } from "./json.js";
import { hexToBytes, producerPublicKeySpki } from "./producer-envelope-wire.js";

/** The countersignatures[] entry type this stamp verifies. */
export const COUNTERSIGN_V1 = "countersign/v1";

/** The five check results a countersign/v1 statement may carry. */
export const COUNTERSIGN_RESULTS = [
  "established",
  "failed",
  "not present",
  "not checked",
  "inconclusive",
] as const;

export type CountersignResult = (typeof COUNTERSIGN_RESULTS)[number];

export interface CountersignCheck {
  readonly name: string;
  readonly result: CountersignResult;
}

/**
 * One `countersigners[]` row of a `witnesses.json` directory (capsule-emit),
 * narrowed to the fields the stamp reads. The directory's other fields
 * (`endpoint`, `statement_types_issued`, `since`, `independent_of`) are
 * never read: independence is computed per entry, never taken from a row.
 */
export interface CountersignerDirectoryRow {
  readonly name: string;
  readonly key_ids: readonly string[];
}

/**
 * A `witnesses.json` directory. Only `countersigners[]` resolves a
 * countersignature; a key listed under `witnesses[]` never does.
 */
export interface CountersignerDirectory {
  readonly countersigners: readonly CountersignerDirectoryRow[];
}

/** What the signer said, as the signer's statement -- never the viewer's finding. */
export interface CountersignStatementView {
  readonly checks: readonly CountersignCheck[];
  readonly recomputedAt: string;
  /** The viewer cannot verify a Transparency Service receipt; a present one is shown as unverified. */
  readonly receipt: "absent" | "unverified";
}

/**
 * The stamp's rendered state, per the Evidence Bundle -01 countersign/v1
 * verification rules:
 * - "hollow": no countersignatures[] entries -- the default.
 * - "unverified": an entry of a type this viewer does not implement,
 *   including the reserved `cose-sign1` slot. It changes no other result.
 * - "invalid": a countersign/v1 entry that is malformed, signs a different
 *   bundle digest, or whose signature fails. Its checks are never shown.
 * - "not-independent": the signer key is the producer's own key.
 * - "unresolved-signer": independent, but the key is in no directory row.
 * - "resolved": independent, and the key is in a `countersigners[]` row;
 *   the name comes from the directory, never the bundle.
 */
export type CountersignatureStamp =
  | { readonly kind: "hollow" }
  | { readonly kind: "unverified"; readonly type: string }
  | { readonly kind: "invalid" }
  | {
      readonly kind: "not-independent";
      readonly keyId: string;
      readonly statement: CountersignStatementView;
    }
  | {
      readonly kind: "unresolved-signer";
      readonly keyId: string;
      readonly statement: CountersignStatementView;
    }
  | {
      readonly kind: "resolved";
      readonly keyId: string;
      readonly name: string;
      readonly statement: CountersignStatementView;
    };

const KEY_ID = /^[0-9a-f]{64}$/u;
const SIGNATURE = /^[0-9a-f]{128}$/u;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u;
const RESULTS: ReadonlySet<string> = new Set(COUNTERSIGN_RESULTS);

type Obj = Record<string, unknown>;

function object(value: unknown): Obj | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Obj)
    : undefined;
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/**
 * Index a `witnesses.json` document's `countersigners[]` by key id. Rows
 * without a usable name, and key ids that are not a full 64-hex Ed25519 key
 * (such as a directory placeholder), are skipped. A key listed in more than
 * one row resolves to no row rather than to an arbitrary one.
 */
export function readCountersignerDirectory(
  directory: unknown,
): ReadonlyMap<string, string> {
  const rows = object(directory)?.countersigners;
  const names = new Map<string, string>();
  const ambiguous = new Set<string>();
  if (!Array.isArray(rows)) return names;
  for (const raw of rows) {
    const row = object(raw);
    if (row === undefined || !nonEmptyString(row.name)) continue;
    if (!Array.isArray(row.key_ids)) continue;
    for (const key of row.key_ids) {
      if (typeof key !== "string" || !KEY_ID.test(key)) continue;
      const existing = names.get(key);
      if (existing !== undefined && existing !== row.name) ambiguous.add(key);
      names.set(key, row.name);
    }
  }
  ambiguous.forEach((key) => names.delete(key));
  return names;
}

function readChecks(value: unknown): CountersignCheck[] | undefined {
  if (!Array.isArray(value) || value.length === 0) return undefined;
  const checks: CountersignCheck[] = [];
  const seen = new Set<string>();
  for (const raw of value) {
    const check = object(raw);
    if (check === undefined || !nonEmptyString(check.name)) return undefined;
    if (typeof check.result !== "string" || !RESULTS.has(check.result))
      return undefined;
    if (seen.has(check.name)) return undefined;
    seen.add(check.name);
    checks.push({
      name: check.name,
      result: check.result as CountersignResult,
    });
  }
  return checks;
}

function scopeIsWellFormed(value: unknown): boolean {
  const scope = object(value);
  if (scope === undefined || !nonEmptyString(scope.ledger_id)) return false;
  if (
    typeof scope.closure_depth !== "number" ||
    !Number.isInteger(scope.closure_depth) ||
    scope.closure_depth < 0
  )
    return false;
  if (scope.period === undefined) return true;
  const period = object(scope.period);
  return (
    period !== undefined &&
    typeof period.from === "string" &&
    typeof period.to === "string"
  );
}

/**
 * The countersign/v1 signing input:
 * `UTF8(JCS({"over": over, "statement": statement, "type": type}))`.
 * The statement is signed as it appears on the wire, unknown members included.
 */
export function countersignV1SigningInput(entry: {
  readonly over: string;
  readonly statement: unknown;
  readonly type: string;
}): Uint8Array {
  return jcs({
    over: entry.over,
    statement: entry.statement,
    type: entry.type,
  });
}

/** Verify a countersign/v1 Ed25519 signature (128 hex) under `keyId` (64 hex). */
export async function verifyCountersignV1Signature(
  entry: {
    readonly over: string;
    readonly statement: unknown;
    readonly type: string;
  },
  keyId: string,
  signatureHex: string,
): Promise<boolean> {
  if (!KEY_ID.test(keyId) || !SIGNATURE.test(signatureHex)) return false;
  try {
    const key = await globalThis.crypto.subtle.importKey(
      "spki",
      producerPublicKeySpki(hexToBytes(keyId)) as BufferSource,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await globalThis.crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      hexToBytes(signatureHex) as BufferSource,
      countersignV1SigningInput(entry) as BufferSource,
    );
  } catch {
    return false;
  }
}

async function classifyCountersignV1(
  entry: Obj,
  bundleDigest: string,
  producerKeys: ReadonlySet<string>,
  directoryNames: ReadonlyMap<string, string>,
): Promise<CountersignatureStamp> {
  const signer = object(entry.signer);
  const statement = object(entry.statement);
  const keyId = signer?.key_id;
  if (
    signer === undefined ||
    !nonEmptyString(signer.id) ||
    typeof keyId !== "string" ||
    !KEY_ID.test(keyId) ||
    typeof entry.over !== "string" ||
    typeof entry.signature !== "string" ||
    statement === undefined ||
    typeof statement.recomputed_at !== "string" ||
    !UTC_TIMESTAMP.test(statement.recomputed_at) ||
    !scopeIsWellFormed(statement.scope)
  )
    return { kind: "invalid" };
  const checks = readChecks(statement.checks);
  if (checks === undefined) return { kind: "invalid" };
  // Step 1: an entry over a different digest is not a countersignature of
  // this bundle. Step 2: the signature covers the statement, so a result
  // edited after signing fails here and its checks are never shown.
  if (entry.over !== bundleDigest) return { kind: "invalid" };
  const signed = await verifyCountersignV1Signature(
    { over: entry.over, statement: entry.statement, type: COUNTERSIGN_V1 },
    keyId,
    entry.signature,
  );
  if (!signed) return { kind: "invalid" };
  const view: CountersignStatementView = {
    checks,
    recomputedAt: statement.recomputed_at,
    receipt: entry.receipt === undefined ? "absent" : "unverified",
  };
  // Step 3: independence is computed here from the signer key; no entry
  // member (e.g. a self-reported `independent`) and no directory row can
  // change it.
  if (producerKeys.has(keyId))
    return { kind: "not-independent", keyId, statement: view };
  const name = directoryNames.get(keyId);
  if (name === undefined)
    return { kind: "unresolved-signer", keyId, statement: view };
  return { kind: "resolved", keyId, name, statement: view };
}

/**
 * Classify countersignatures[] into stamp states. A bundle with no entries
 * (absent or empty) always classifies as a single hollow stamp.
 *
 * `producerKeys` are the producer's Ed25519 public keys (64 hex) the viewer
 * holds; `directory` is a parsed `witnesses.json` (or undefined when none
 * was consulted).
 */
export async function classifyCountersignatures(
  entries: readonly unknown[],
  bundleDigest: string | undefined,
  producerKeys: readonly string[],
  directory: unknown,
): Promise<readonly CountersignatureStamp[]> {
  if (entries.length === 0) return [{ kind: "hollow" }];
  const producers = new Set(producerKeys.filter((key) => KEY_ID.test(key)));
  const directoryNames = readCountersignerDirectory(directory);
  const results: CountersignatureStamp[] = [];
  for (const raw of entries) {
    const entry = object(raw);
    if (entry === undefined || !nonEmptyString(entry.type)) {
      results.push({ kind: "invalid" });
    } else if (entry.type !== COUNTERSIGN_V1) {
      results.push({ kind: "unverified", type: entry.type });
    } else if (bundleDigest === undefined) {
      results.push({ kind: "invalid" });
    } else {
      results.push(
        await classifyCountersignV1(
          entry,
          bundleDigest,
          producers,
          directoryNames,
        ),
      );
    }
  }
  return results;
}
