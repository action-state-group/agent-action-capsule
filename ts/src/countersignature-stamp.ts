import { jcs, sha256Hex } from "./json.js";
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
 * One countersigner the caller recognises: a name and the full 64-hex
 * Ed25519 public keys it signs under (more than one after a rotation).
 * Independence is never taken from a listing; it is computed per entry.
 */
export interface CountersignerListing {
  readonly name: string;
  readonly key_ids: readonly string[];
}

/**
 * The stamp's countersigner source: a list the caller passes in, or one
 * loaded by {@link pinnedCountersignerSource} against a digest the caller
 * pinned. Countersigners are not rows of the neutral witness directory, so a
 * `witnesses.json` document is never a source; where the list itself is
 * published is decided outside this library.
 */
export type CountersignerSource = readonly CountersignerListing[];

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
 * - "unresolved-signer": independent, but the key is in no countersigner listing.
 * - "resolved": independent, and the key is in a countersigner listing;
 *   the name comes from the caller's countersigner source, never the bundle.
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
 * Index a countersigner source by key id. Anything that is not a list reads
 * as empty, so a `witnesses.json` object never resolves a signer. Listings
 * without a usable name, and key ids that are not a full 64-hex Ed25519 key,
 * are skipped. A key listed under two names resolves to neither rather than
 * to an arbitrary one.
 */
export function indexCountersigners(
  source: unknown,
): ReadonlyMap<string, string> {
  const names = new Map<string, string>();
  const ambiguous = new Set<string>();
  if (!Array.isArray(source)) return names;
  for (const raw of source) {
    const listing = object(raw);
    if (listing === undefined || !nonEmptyString(listing.name)) continue;
    if (!Array.isArray(listing.key_ids)) continue;
    for (const key of listing.key_ids) {
      if (typeof key !== "string" || !KEY_ID.test(key)) continue;
      const existing = names.get(key);
      if (existing !== undefined && existing !== listing.name)
        ambiguous.add(key);
      names.set(key, listing.name);
    }
  }
  ambiguous.forEach((key) => names.delete(key));
  return names;
}

/**
 * Load a countersigner list from its bytes only if their SHA-256 equals the
 * digest the caller pinned (64 lowercase hex). The bytes must be a JSON
 * array of listings. Returns undefined on a digest mismatch or any other
 * shape, so an unpinned or altered list never names a signer.
 */
export async function pinnedCountersignerSource(
  bytes: Uint8Array,
  expectedSha256: string,
): Promise<CountersignerSource | undefined> {
  if (!KEY_ID.test(expectedSha256)) return undefined;
  if ((await sha256Hex(bytes)) !== expectedSha256) return undefined;
  try {
    const parsed: unknown = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    );
    return Array.isArray(parsed) ? (parsed as CountersignerSource) : undefined;
  } catch {
    return undefined;
  }
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

interface CountersignV1Signed {
  readonly over: string;
  readonly signer: unknown;
  readonly statement: unknown;
  readonly type: string;
}

/**
 * The countersign/v1 signing input:
 * `UTF8(JCS({"over": over, "signer": signer, "statement": statement, "type": type}))`.
 * `signer` and `statement` are signed as they appear on the wire, every
 * member included, so neither `signer.id` nor a result can be edited after
 * signing.
 */
export function countersignV1SigningInput(
  entry: CountersignV1Signed,
): Uint8Array {
  return jcs({
    over: entry.over,
    signer: entry.signer,
    statement: entry.statement,
    type: entry.type,
  });
}

/** Verify a countersign/v1 Ed25519 signature (128 hex) under `keyId` (64 hex). */
export async function verifyCountersignV1Signature(
  entry: CountersignV1Signed,
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
  countersignerNames: ReadonlyMap<string, string>,
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
  // this bundle. Step 2: the signature covers the signer and the statement,
  // so a result or signer.id edited after signing fails here and its checks
  // are never shown. An absent or empty `type` is verified as countersign/v1:
  // the signing input binds "countersign/v1", so a signature over "" fails.
  if (entry.over !== bundleDigest) return { kind: "invalid" };
  const signed = await verifyCountersignV1Signature(
    {
      over: entry.over,
      signer: entry.signer,
      statement: entry.statement,
      type: COUNTERSIGN_V1,
    },
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
  // member (e.g. a self-reported `independent`) and no countersigner
  // listing can change it.
  if (producerKeys.has(keyId))
    return { kind: "not-independent", keyId, statement: view };
  const name = countersignerNames.get(keyId);
  if (name === undefined)
    return { kind: "unresolved-signer", keyId, statement: view };
  return { kind: "resolved", keyId, name, statement: view };
}

/**
 * Classify countersignatures[] into stamp states. A bundle with no entries
 * (absent or empty) always classifies as a single hollow stamp.
 *
 * `producerKeys` are the producer's Ed25519 public keys (64 hex) the viewer
 * holds; `countersigners` is the caller's countersigner source (undefined
 * when none was consulted, which leaves every independent signer unresolved).
 */
export async function classifyCountersignatures(
  entries: readonly unknown[],
  bundleDigest: string | undefined,
  producerKeys: readonly string[],
  countersigners: CountersignerSource | undefined,
): Promise<readonly CountersignatureStamp[]> {
  if (entries.length === 0) return [{ kind: "hollow" }];
  const producers = new Set(producerKeys.filter((key) => KEY_ID.test(key)));
  const countersignerNames = indexCountersigners(countersigners);
  const results: CountersignatureStamp[] = [];
  for (const raw of entries) {
    const entry = object(raw);
    const type = entry?.type === undefined ? "" : entry.type;
    if (entry === undefined || typeof type !== "string") {
      results.push({ kind: "invalid" });
    } else if (type !== "" && type !== COUNTERSIGN_V1) {
      results.push({ kind: "unverified", type });
    } else if (bundleDigest === undefined) {
      results.push({ kind: "invalid" });
    } else {
      results.push(
        await classifyCountersignV1(
          entry,
          bundleDigest,
          producers,
          countersignerNames,
        ),
      );
    }
  }
  return results;
}
