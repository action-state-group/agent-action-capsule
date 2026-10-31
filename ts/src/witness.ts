// Offline checks of the witness receipts an Evidence Bundle's checkpoint
// carries (`checkpoint.witnesses`, CLL WitnessRecord objects), for strict
// `verifyBundle`. The Bundle draft defines no witness member: this is a
// verifier extension, pinned by vectors/bundle/strict/README.md and ported
// from the Python reference (python/agent_action_capsule/witness.py).
//
// No witness is trusted by default. The caller supplies a witness directory
// (a parsed `witnesses.json`, `{"witnesses": [row, ...]}`, or the row list).
// A receipt whose witness has no row, or whose row has no usable key, is not
// checked (`withheld`), never failed. WebCrypto only.

import {
  CborMap,
  CborTag,
  type CborValue,
  decodeStrictCbor,
  HDR_CWT_CLAIMS,
  HDR_GRADE,
  spkiKeyType,
  verifyCoseReceipt,
  type ReceiptVerification,
} from "./cose-receipt.js";
import { decodeStrictJson, JsonNumber, sha256Hex } from "./json.js";
import { concat, hexToBytes } from "./producer-envelope-wire.js";
import { directoryKeyCounts } from "./spki.js";

// The generic COSE Receipt verifier (leaf bytes and a public key), for
// callers that check receipts outside a Bundle.
export {
  HDR_GRADE,
  spkiKeyType,
  verifyCoseReceipt,
  type ReceiptVerification,
} from "./cose-receipt.js";
export { directoryKeyCounts } from "./spki.js";

export const BINDING_CLL = "cll";
export const BINDING_REKOR = "rekor";
export const BINDING_SCRAPI = "scrapi";
export type WitnessBinding = "cll" | "rekor" | "scrapi";
export const GRADE_OBSERVED_ONLY = "observed-only";
export const GRADE_MMR_VERIFIED = "mmr-verified";
export type WitnessGrade = "observed-only" | "mmr-verified";
// `countersigned-observed` is the pre-rename spelling of `observed-only`.
const GRADES: ReadonlyMap<string, WitnessGrade> = new Map([
  [GRADE_OBSERVED_ONLY, GRADE_OBSERVED_ONLY],
  ["countersigned-observed", GRADE_OBSERVED_ONLY],
  [GRADE_MMR_VERIFIED, GRADE_MMR_VERIFIED],
]);
/**
 * Why a receipt result has no `registrationTime`: the receipt did not pass;
 * it passed with no `iat` in its protected CWT claims; its protected `iat` is
 * not an integer number of seconds from 0 to 2^53 - 1; or its binding
 * (`rekor`) is no COSE Receipt and so carries no `iat`.
 */
export const REGISTRATION_TIME_REASONS = [
  "receipt_not_passed",
  "iat_absent",
  "iat_invalid",
  "binding_without_iat",
] as const;
export type RegistrationTimeReason = (typeof REGISTRATION_TIME_REASONS)[number];
const CWT_IAT = 6n;
const MAX_IAT = 2n ** 53n - 1n;
const RECORD_FIELDS = [
  "ts_url",
  "entry_hash",
  "receipt_b64",
  "leaf_index",
  "tree_size",
] as const;

/**
 * One receipt's outcome. `reason` explains it and is not part of the
 * cross-language contract; `grade` is the verified receipt grade, or null.
 * `keyId` is the directory key id a passing receipt verified under, else
 * null. `registrationTime` is the `iat` the witness signed into a passing
 * COSE Receipt's protected header, in seconds since the epoch; when it is
 * null, `registrationTimeReason` says why.
 */
export interface WitnessReceiptResult {
  readonly tsUrl: string;
  readonly binding: WitnessBinding;
  readonly status: "pass" | "withheld" | "fail";
  readonly reason: string;
  readonly grade: WitnessGrade | null;
  readonly keyId: string | null;
  readonly registrationTime: number | null;
  readonly registrationTimeReason: RegistrationTimeReason | null;
}

/** The checkpoint fields the signed COSE checkpoint states. */
export interface SignedCheckpointFields {
  readonly log_id: string;
  readonly mmr_size: number;
  readonly root: string;
  readonly key_id: string;
  readonly timestamp: string;
  readonly prev_size: number;
  readonly prev_root: string;
}

type Row = Record<string, unknown>;
const object = (value: unknown): value is Row =>
  value !== null && typeof value === "object" && !Array.isArray(value);

/** `rekor+...` is `rekor`, `scrapi+...` is `scrapi`, anything else `cll`. */
export function bindingOf(url: string): WitnessBinding {
  const separator = url.indexOf("://");
  const scheme = separator < 0 ? "" : url.slice(0, separator).toLowerCase();
  if (scheme.startsWith(`${BINDING_REKOR}+`)) return BINDING_REKOR;
  if (scheme.startsWith(`${BINDING_SCRAPI}+`)) return BINDING_SCRAPI;
  return BINDING_CLL;
}

/** The URL with any binding prefix removed and no trailing slash. */
export function endpointOf(url: string): string {
  const base =
    bindingOf(url) === BINDING_CLL ? url : url.slice(url.indexOf("+") + 1);
  return base.replace(/\/+$/u, "");
}

/**
 * The directory row of a witness URL: the same binding (a row without
 * `binding` is `cll`) and the same endpoint, trailing slash ignored.
 */
export function witnessRowFor(
  directory: unknown,
  tsUrl: string,
): Readonly<Record<string, unknown>> | undefined {
  const rows = object(directory) ? directory.witnesses : directory;
  if (!Array.isArray(rows)) return undefined;
  const binding = bindingOf(tsUrl),
    endpoint = endpointOf(tsUrl);
  return rows.find(
    (row): row is Row =>
      object(row) &&
      (Object.hasOwn(row, "binding") ? row.binding : BINDING_CLL) === binding &&
      endpointMatches(
        Object.hasOwn(row, "endpoint") ? row.endpoint : "",
        endpoint,
      ),
  );
}

const endpointMatches = (value: unknown, endpoint: string): boolean =>
  typeof value === "string" && value.replace(/\/+$/u, "") === endpoint;

/**
 * Canonical RFC 4648 standard base64 with padding: a character outside the
 * alphabet, missing padding, or non-zero trailing bits in the last symbol
 * (the bytes must re-encode to `value`) throws a TypeError.
 */
export function base64Canonical(value: unknown): Uint8Array {
  if (
    typeof value !== "string" ||
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]*={0,2}$/u.test(value)
  )
    throw new TypeError("not canonical base64");
  const raw = Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  if (btoa(latin1(raw)) !== value) throw new TypeError("non-canonical base64");
  return raw;
}

const ED25519_SPKI_PREFIX = hexToBytes("302a300506032b6570032100");
const ed25519Spki = (raw: Uint8Array): Uint8Array =>
  concat(ED25519_SPKI_PREFIX, raw);
const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

/**
 * Python's `bytes.fromhex`: hex digit pairs in either case, with ASCII
 * whitespace allowed between pairs.
 */
export function fromHex(value: unknown): Uint8Array {
  if (typeof value !== "string" || !/^(?:\s*[0-9A-Fa-f]{2})*\s*$/u.test(value))
    throw new TypeError("not hex");
  return Uint8Array.from(value.match(/[0-9A-Fa-f]{2}/gu) ?? [], (pair) =>
    Number.parseInt(pair, 16),
  );
}

/** Python's iteration of a JSON value: an array's items, a string's
 * characters, an object's keys; a falsy value is empty. */
function pyIterate(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (typeof value === "string") return [...value];
  if (object(value)) return Object.keys(value);
  if (value === null || value === undefined || value === false || value === 0)
    return [];
  throw new TypeError("not iterable");
}

/**
 * Every key a row lists, as DER SubjectPublicKeyInfo, in `key_ids` order: the
 * `public_keys` entry (base64 DER) the key id names by the SHA-256 of its
 * DER, or an Ed25519 entry by its raw key; else the key id read as a raw
 * Ed25519 key (a curve point or not). A `public_keys` entry counts only when
 * it is canonical base64 of a DER SubjectPublicKeyInfo holding an Ed25519 key
 * or an EC key that loads ({@link directoryKeyCounts}); any other is skipped.
 * The row is unusable, and this throws, when `key_ids` or `public_keys` is not
 * a list, a key id is not 64 lowercase hex characters, or a `rekor` row's key
 * id has no `public_keys` entry.
 */
export async function witnessRowKeys(row: Row): Promise<Uint8Array[]> {
  const publicKeys = Object.hasOwn(row, "public_keys") ? row.public_keys : [],
    keyIds = Object.hasOwn(row, "key_ids") ? row.key_ids : [];
  if (!Array.isArray(publicKeys) || !Array.isArray(keyIds))
    throw new TypeError("key_ids and public_keys must be lists");
  const byId = new Map<string, Uint8Array>();
  // An entry that does not count is skipped, not fatal.
  for (const encoded of publicKeys as unknown[]) {
    let der: Uint8Array;
    try {
      der = base64Canonical(encoded);
    } catch {
      continue;
    }
    if (!directoryKeyCounts(der)) continue;
    byId.set(await sha256Hex(der), der);
    if (
      der.length === 44 &&
      der.subarray(0, 12).every((b, i) => b === ED25519_SPKI_PREFIX[i])
    )
      byId.set(hex(der.subarray(12)), der);
  }
  const keys: Uint8Array[] = [];
  for (const keyId of keyIds as unknown[]) {
    if (typeof keyId !== "string" || !/^[0-9a-f]{64}$/u.test(keyId))
      throw new TypeError("a key id is not 64 lowercase hex characters");
    const der = byId.get(keyId);
    if (der !== undefined) keys.push(der);
    else if (row.binding === BINDING_REKOR)
      throw new TypeError("rekor row: no public key for its log ID");
    // Any 32 bytes are a raw Ed25519 key, a curve point or not: under one
    // that is not, nothing verifies and the receipt fails.
    else keys.push(ed25519Spki(fromHex(keyId)));
  }
  return keys;
}

/**
 * CLL's checkpoint digest: SHA-256 of the signing body, the JSON object of
 * `v` (1), `kind` (`mmr_checkpoint`) and the signed fields, keys sorted, no
 * whitespace, strings escaped as Python's `json.dumps` does by default:
 * `JSON.stringify`'s escapes (`\"`, `\\`, the short control escapes, other
 * controls and lone surrogates as lowercase `\u00XX`), then DEL and every
 * non-ASCII UTF-16 unit as `\uXXXX`, so an astral character becomes its
 * surrogate pair. `/`, `<`, `>` and `&` stay as they are.
 */
export async function checkpointDigest(
  signed: SignedCheckpointFields,
): Promise<string> {
  const body: Record<string, unknown> = {
    v: 1,
    kind: "mmr_checkpoint",
    log_id: signed.log_id,
    mmr_size: signed.mmr_size,
    root: signed.root,
    prev_size: signed.prev_size,
    prev_root: signed.prev_root,
    key_id: signed.key_id,
    timestamp: signed.timestamp,
  };
  const text = `{${Object.keys(body)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${JSON.stringify(body[key])}`)
    .join(",")}}`.replace(
    // No `u` flag: match UTF-16 code units, not code points.
    /[\u007f-￿]/g,
    (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
  return sha256Hex(new TextEncoder().encode(text));
}

/**
 * One receipt checked under one key. `notChecked` marks a check this verifier
 * could not run at all (a missing key, COSE statement or WebCrypto
 * algorithm): the receipt is then `withheld`, never `fail`. `reason` is not
 * part of the cross-language contract.
 */
export type ReceiptOutcome =
  | {
      readonly ok: true;
      readonly reason: string;
      readonly grade: WitnessGrade | null;
      readonly registrationTime: number | null;
      readonly registrationTimeReason: RegistrationTimeReason | null;
    }
  | {
      readonly ok: false;
      readonly reason: string;
      readonly notChecked?: true;
    };

const failed = (reason: string): ReceiptOutcome => ({ ok: false, reason });
const notChecked = (reason: string): ReceiptOutcome => ({
  ok: false,
  reason: `not checked: ${reason}`,
  notChecked: true,
});
const fromCoseResult = (
  result: ReceiptVerification & { ok: false },
): ReceiptOutcome =>
  result.unavailable ? notChecked(result.reason) : failed(result.reason);

function gradeOf(label: unknown): WitnessGrade | null {
  return typeof label === "string" ? (GRADES.get(label) ?? null) : null;
}

/**
 * The `iat` (claim 6) of a verified COSE Receipt's protected CWT claims
 * (label 15): absent with no claims map or no `iat` in it, invalid when the
 * claims are not a map or `iat` is not an integer from 0 to 2^53 - 1.
 */
function registrationTimeOf(headers: CborMap): {
  readonly registrationTime: number | null;
  readonly registrationTimeReason: RegistrationTimeReason | null;
} {
  const none = (reason: RegistrationTimeReason) => ({
    registrationTime: null,
    registrationTimeReason: reason,
  });
  if (!headers.has(HDR_CWT_CLAIMS)) return none("iat_absent");
  const claims = headers.get(HDR_CWT_CLAIMS);
  if (!(claims instanceof CborMap)) return none("iat_invalid");
  if (!claims.has(CWT_IAT)) return none("iat_absent");
  const iat = claims.get(CWT_IAT);
  if (typeof iat !== "bigint" || iat < 0n || iat > MAX_IAT)
    return none("iat_invalid");
  return { registrationTime: Number(iat), registrationTimeReason: null };
}

/** A CLL witness stamp: bound to this checkpoint by `entry_hash`, then a COSE
 * Receipt over that leaf. */
async function verifyCll(
  signed: SignedCheckpointFields,
  record: Row,
  key: Uint8Array,
): Promise<ReceiptOutcome> {
  const expected = await sha256Hex(hexToBytes(await checkpointDigest(signed)));
  if (record.entry_hash !== expected)
    return failed("entry_hash is not this checkpoint's digest");
  let receipt: Uint8Array;
  try {
    receipt = base64Canonical(record.receipt_b64);
  } catch {
    return failed("receipt_b64 is not canonical base64");
  }
  const result = await verifyCoseReceipt(receipt, hexToBytes(expected), key);
  if (!result.ok) return fromCoseResult(result);
  const label = result.protectedHeaders.get(HDR_GRADE);
  return {
    ok: true,
    reason: "ok",
    grade: gradeOf(label),
    ...registrationTimeOf(result.protectedHeaders),
  };
}

/**
 * Offline check of a SCRAPI receipt (`scitt_cose` receipt bytes): a SCITT
 * COSE Receipt (RFC 9162) over the leaf SHA-256(`checkpointCose`), signed
 * under `servicePublicKeySpki` (DER SubjectPublicKeyInfo). Without a key
 * nothing is checked. The grade is the receipt's label -65537, and no label or
 * an unknown one reads as `observed-only`. Never throws.
 */
export async function verifyScrapiReceipt(
  receipt: Uint8Array,
  options: {
    readonly checkpointCose: Uint8Array;
    readonly servicePublicKeySpki: Uint8Array | undefined;
  },
): Promise<ReceiptOutcome> {
  if (options.servicePublicKeySpki === undefined)
    return notChecked("no key pinned for this service");
  try {
    const leaf = hexToBytes(await sha256Hex(options.checkpointCose));
    const result = await verifyCoseReceipt(
      receipt,
      leaf,
      options.servicePublicKeySpki,
    );
    if (!result.ok) return fromCoseResult(result);
    const label = result.protectedHeaders.get(HDR_GRADE);
    return {
      ok: true,
      reason: "ok",
      grade: gradeOf(label) ?? GRADE_OBSERVED_ONLY,
      ...registrationTimeOf(result.protectedHeaders),
    };
  } catch (error) {
    return failed(`unreadable receipt: ${String(error)}`);
  }
}

const latin1 = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");
// Python's bytes.strip(): ASCII whitespace.
const pyStrip = (text: string): string =>
  text.replace(/^[ \t\n\r\v\f]+|[ \t\n\r\v\f]+$/gu, "");

/**
 * A JSON integer as its canonical decimal text, or undefined for anything
 * else (a string, a boolean, `1.0`, `1e3`). A {@link JsonNumber} keeps its
 * spelling, so it is read exactly; a plain number must be a safe integer.
 */
function jsonInteger(value: unknown): string | undefined {
  if (value instanceof JsonNumber)
    return /^-?(?:0|[1-9][0-9]*)$/u.test(value.raw)
      ? BigInt(value.raw).toString()
      : undefined;
  return typeof value === "number" && Number.isSafeInteger(value)
    ? String(value)
    : undefined;
}

/**
 * A DER ECDSA-Sig-Value as the IEEE P1363 `r || s` WebCrypto verifies. Only
 * strict DER is read: a SEQUENCE spanning every byte of two INTEGERs, each
 * positive and minimally encoded (no negative value, no redundant leading
 * zero) and fitting in 32 bytes. Anything else throws, so a re-encoded
 * signature does not verify.
 */
function p1363(der: Uint8Array): Uint8Array {
  const malformed = () => new TypeError("malformed ECDSA signature");
  const integer = (at: number): [Uint8Array, number] => {
    const length = der[at + 1];
    if (der[at] !== 0x02 || length === undefined || length > 33 || length < 1)
      throw malformed();
    let value = der.subarray(at + 2, at + 2 + length);
    if (value.length !== length) throw malformed();
    // The high bit of the first octet is the sign: a negative value.
    if (value[0]! & 0x80) throw malformed();
    // A leading zero only where the next octet would read as negative.
    if (value.length > 1 && value[0] === 0 && !(value[1]! & 0x80))
      throw malformed();
    // 33 octets only as a zero then a 32-octet value with its high bit set.
    if (value.length === 33) {
      if (value[0] !== 0) throw malformed();
      value = value.subarray(1);
    }
    if (value.every((byte) => byte === 0)) throw malformed();
    const out = new Uint8Array(32);
    out.set(value, 32 - value.length);
    return [out, at + 2 + length];
  };
  if (der[0] !== 0x30 || der[1] !== der.length - 2)
    throw new TypeError("malformed ECDSA signature");
  const [r, next] = integer(2);
  const [s, end] = integer(next);
  if (end !== der.length) throw new TypeError("malformed ECDSA signature");
  return concat(r, s);
}

function ed25519Pem(raw: Uint8Array): string {
  const body = btoa(latin1(ed25519Spki(raw)));
  return `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----`;
}

/**
 * Offline check of one Rekor `dsse` log entry (`receipt`, a parsed entry; use
 * {@link decodeStrictJson} so `integratedTime` and `logIndex` keep their JSON
 * types) against the checkpoint it claims: the Signed Entry Timestamp
 * verifies under `rekorPublicKeySpki` (DER P-256) and `logID` is that key's,
 * the entry's `payloadHash` is algorithm `sha256` with the value SHA-256 of
 * `checkpointCose`, and its only
 * verifier key is the Ed25519 key `checkpointKeyId` names. Every base64 field
 * is canonical standard base64. Never throws.
 */
export async function verifyRekorReceipt(
  receipt: unknown,
  options: {
    readonly checkpointCose: Uint8Array;
    readonly checkpointKeyId: string;
    readonly rekorPublicKeySpki: Uint8Array;
  },
): Promise<ReceiptOutcome> {
  const cose = options.checkpointCose,
    key = options.rekorPublicKeySpki;
  const fail = failed;
  const subtle = (globalThis as { crypto?: { subtle?: SubtleCrypto } }).crypto
    ?.subtle;
  if (subtle === undefined) return notChecked("WebCrypto is unavailable");
  // The Rekor key must be ECDSA P-256, read from the key itself so that a
  // key WebCrypto cannot import fails rather than going unchecked.
  if (spkiKeyType(key) !== "p256")
    return fail("the Rekor key is not an ECDSA P-256 key");
  let rekorKey: CryptoKey;
  try {
    rekorKey = await subtle.importKey(
      "spki",
      key as BufferSource,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch {
    return fail("the Rekor key is not an ECDSA P-256 key");
  }
  try {
    if (!object(receipt)) return fail("receipt is not an object");
    if (receipt.logID !== (await sha256Hex(key)))
      return fail("logID is not the pinned Rekor key");
    const verification = receipt.verification;
    const timestamp = object(verification)
      ? verification.signedEntryTimestamp
      : undefined;
    if (!timestamp) return fail("no signedEntryTimestamp");
    const integratedTime = jsonInteger(receipt.integratedTime),
      logIndex = jsonInteger(receipt.logIndex);
    if (integratedTime === undefined || logIndex === undefined)
      return fail("integratedTime and logIndex must be JSON integers");
    if (typeof receipt.body !== "string") return fail("body must be a string");
    // Rekor's canonical JSON: keys sorted, no whitespace; logID matched the
    // key's hex above.
    const signed = new TextEncoder().encode(
      `{"body":${JSON.stringify(receipt.body)},"integratedTime":${integratedTime},"logID":${JSON.stringify(receipt.logID)},"logIndex":${logIndex}}`,
    );
    if (
      !(await subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        rekorKey,
        p1363(base64Canonical(timestamp)) as BufferSource,
        signed as BufferSource,
      ))
    )
      return fail("signedEntryTimestamp does not verify under the Rekor key");
    const entry: unknown = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(
        base64Canonical(receipt.body),
      ),
    );
    if (!object(entry) || entry.kind !== "dsse")
      return fail("entry kind is not dsse");
    const spec = entry.spec || {};
    if (!object(spec)) return fail("entry spec is not an object");
    const payloadHash = spec.payloadHash || {};
    if (
      !object(payloadHash) ||
      payloadHash.algorithm !== "sha256" ||
      payloadHash.value !== (await sha256Hex(cose))
    )
      return fail("entry payloadHash is not this checkpoint's bytes");
    const verifiers = new Set<string>();
    for (const signature of pyIterate(spec.signatures)) {
      if (!object(signature)) return fail("entry signature is not an object");
      // Python's `s.get("verifier", "")`: absent is "", null is unreadable.
      const verifier = Object.hasOwn(signature, "verifier")
        ? signature.verifier
        : "";
      verifiers.add(
        pyStrip(latin1(base64Canonical(verifier)).replaceAll("\r", "")),
      );
    }
    const raw = fromHex(options.checkpointKeyId);
    if (raw.length !== 32) return fail("checkpoint key is not Ed25519");
    const expected = ed25519Pem(raw);
    if (verifiers.size !== 1 || !verifiers.has(expected))
      return fail("entry is not signed by the checkpoint's key");
    return {
      ok: true,
      reason: "ok",
      grade: GRADE_OBSERVED_ONLY,
      registrationTime: null,
      registrationTimeReason: "binding_without_iat",
    };
  } catch (error) {
    // Verification degrades to "no", never throws.
    return fail(`unreadable receipt: ${String(error)}`);
  }
}

/**
 * One receipt (a CLL `WitnessRecord` object) under one key (DER
 * SubjectPublicKeyInfo, as {@link witnessRowKeys} returns), for the
 * checkpoint whose signed fields are `signed` and whose COSE statement is
 * `checkpointCose`. The binding comes from `record.ts_url`. Never throws.
 */
export async function verifyReceipt(
  signed: SignedCheckpointFields,
  record: Readonly<Record<string, unknown>>,
  key: Uint8Array,
  checkpointCose: Uint8Array | undefined,
): Promise<ReceiptOutcome> {
  if (typeof record.ts_url !== "string")
    return failed("ts_url is not a string");
  const binding = bindingOf(record.ts_url);
  if (binding === BINDING_CLL) return verifyCll(signed, record, key);
  if (checkpointCose === undefined)
    return notChecked("checkpoint COSE statement not available");
  let receipt: Uint8Array;
  try {
    receipt = base64Canonical(record.receipt_b64);
  } catch (error) {
    return failed(`unreadable receipt: ${String(error)}`);
  }
  if (binding === BINDING_SCRAPI)
    return verifyScrapiReceipt(receipt, {
      checkpointCose,
      servicePublicKeySpki: key,
    });
  let entry: unknown;
  try {
    entry = decodeStrictJson(receipt, { lastDuplicateWins: true });
  } catch (error) {
    return failed(`unreadable receipt: ${String(error)}`);
  }
  return verifyRekorReceipt(entry, {
    checkpointCose,
    checkpointKeyId: signed.key_id,
    rekorPublicKeySpki: key,
  });
}

/**
 * A WitnessRecord: every member present; `ts_url`, `entry_hash` and
 * `receipt_b64` non-empty strings; `receipt_b64` canonical standard base64.
 * Anything else is malformed, never merely not checked.
 */
const isRecord = (entry: unknown): entry is Row => {
  if (
    !object(entry) ||
    !RECORD_FIELDS.every((name) => Object.hasOwn(entry, name))
  )
    return false;
  if (
    !(["ts_url", "entry_hash", "receipt_b64"] as const).every(
      (name) => typeof entry[name] === "string" && entry[name] !== "",
    )
  )
    return false;
  try {
    base64Canonical(entry.receipt_b64);
  } catch {
    return false;
  }
  return true;
};

/**
 * Check every receipt in `receipts` (a Bundle's `checkpoint.witnesses`)
 * against the SIGNED checkpoint (`signed`, undefined when it did not verify)
 * and its COSE bytes, under the keys of `directory` (undefined trusts no
 * witness). `status` is `fail` when an entry is malformed or a receipt does
 * not verify, else `pass` when one verifies, else `withheld`. Never throws.
 */
export async function verifyWitnessReceipts(
  receipts: unknown,
  signed: SignedCheckpointFields | undefined,
  cose: Uint8Array | undefined,
  directory?: unknown,
): Promise<{
  readonly status: "pass" | "withheld" | "fail";
  readonly findings: readonly string[];
  readonly receipts: readonly WitnessReceiptResult[];
}> {
  if (!Array.isArray(receipts) || receipts.length === 0)
    return {
      status: "withheld",
      findings: ["witness_receipt_absent"],
      receipts: [],
    };
  if (signed === undefined || cose === undefined)
    return {
      status: "withheld",
      findings: ["checkpoint_unverified"],
      receipts: [],
    };
  // Malformed entries are listed first, then one finding per checked receipt.
  const findings = receipts.flatMap((entry, index) =>
    isRecord(entry) ? [] : [`witness_receipt_malformed:${index}`],
  );
  const malformed = findings.length > 0;
  const results: WitnessReceiptResult[] = [];
  for (const record of receipts) {
    if (!isRecord(record)) continue;
    const tsUrl = record.ts_url as string;
    const row = witnessRowFor(directory, tsUrl);
    let outcome: ReceiptOutcome | undefined,
      withheld: string | undefined,
      keyId: string | null = null;
    if (record.is_stub === true)
      withheld = "stub receipt (never reached a witness)";
    else if (row === undefined)
      withheld = "not checked: no directory row for this witness";
    else {
      let keys: Uint8Array[] = [];
      try {
        keys = await witnessRowKeys(row);
      } catch (error) {
        withheld = `not checked: unusable key in directory row (${String(error)})`;
      }
      for (const [index, key] of keys.entries()) {
        outcome = await verifyReceipt(signed, record, key, cose);
        if (outcome.ok) {
          // witnessRowKeys returns one key per key id, in order.
          keyId = (row.key_ids as string[])[index]!;
          break;
        }
      }
      // A check that could not run at all withholds the receipt.
      if (outcome !== undefined && !outcome.ok && outcome.notChecked) {
        withheld = outcome.reason;
        outcome = undefined;
      }
      if (outcome === undefined)
        withheld ??=
          "not checked: no key in the directory row for this witness";
    }
    const binding = bindingOf(tsUrl);
    if (outcome?.ok) {
      results.push({
        tsUrl,
        binding,
        status: "pass",
        reason: outcome.reason,
        grade: outcome.grade,
        keyId,
        registrationTime: outcome.registrationTime,
        registrationTimeReason: outcome.registrationTimeReason,
      });
    } else if (outcome === undefined) {
      findings.push(`witness_unverified:${tsUrl}`);
      results.push({
        tsUrl,
        binding,
        status: "withheld",
        reason: withheld ?? "not checked",
        grade: null,
        keyId: null,
        registrationTime: null,
        registrationTimeReason: "receipt_not_passed",
      });
    } else {
      findings.push(`witness_receipt_invalid:${tsUrl}`);
      results.push({
        tsUrl,
        binding,
        status: "fail",
        reason: outcome.reason,
        grade: null,
        keyId: null,
        registrationTime: null,
        registrationTimeReason: "receipt_not_passed",
      });
    }
  }
  const statuses = new Set(results.map((result) => result.status));
  return {
    status:
      malformed || statuses.has("fail")
        ? "fail"
        : statuses.has("pass")
          ? "pass"
          : "withheld",
    findings,
    receipts: results,
  };
}

/**
 * The verification-material kind of a witness Receipt over a Checkpointed
 * Local Log anchor, and the check over it (spec/interop-profile-v1.md
 * §6.2.2). `anchor_witnessed` is not an envelope property and never enters
 * the profile's §8 mapping: it says when a witness the relying party accepts
 * registered the anchor, and nothing about any artifact under it.
 */
export const ANCHOR_WITNESS_KIND = "cll-witness-receipt";
export const ANCHOR_WITNESS_PROPERTY = "anchor_witnessed";

export type AnchorWitnessStatus =
  | "PASS"
  | "FAIL"
  | "NOT_PRESENT"
  | "NOT_CHECKED";

/**
 * The relying party's witness list: each witness's name and the hex DER
 * SubjectPublicKeyInfo keys it signs Receipts under (Ed25519 for EdDSA,
 * ECDSA P-256 for ES256). An entry of any other shape lists no key.
 */
export interface AnchorWitnessPolicy {
  readonly witnesses: readonly {
    readonly name: string;
    readonly keys: readonly string[];
  }[];
}

/** One Receipt's status, its witness when it passed, and its registration
 * time (a NumericDate) when it passed with a protected `iat`. */
export interface AnchorReceiptReport {
  readonly status: Exclude<AnchorWitnessStatus, "NOT_PRESENT">;
  readonly witness: string | null;
  readonly registration_time: number | null;
}

/** `anchor_witnessed` over every Receipt for one anchor. `witness` and
 * `witnessed_time` always come from the same Receipt. */
export interface AnchorWitnessReport {
  readonly status: AnchorWitnessStatus;
  readonly receipts: readonly AnchorReceiptReport[];
  readonly witness: string | null;
  readonly witnessed_time: number | null;
}

const ANCHOR_DIGEST = /^[0-9a-f]{64}$/u;
const LOWER_HEX = /^(?:[0-9a-f]{2})*$/u;
const ANCHOR_ED25519_PREFIX = "302a300506032b6570032100";
const P256_SPKI_PREFIX =
  "3059301306072a8648ce3d020106082a8648ce3d03010703420004";
const MAX_ANCHOR_RECEIPT_OCTETS = 10 * 1024 * 1024;
const MAX_ANCHOR_PROOFS = 16;
const MAX_ANCHOR_DEPTH = 16;
const MAX_ANCHOR_TREE_SIZE = 1n << 62n;
// Labels below this are private use (RFC 9052 section 16.4).
const PRIVATE_LABEL = -65536n;

/** A Receipt in the one form of §6.2.2. */
interface AnchorReceipt {
  readonly alg: "ed25519" | "p256";
  readonly proofs: readonly {
    readonly size: bigint;
    readonly index: bigint;
    readonly path: readonly Uint8Array[];
  }[];
  readonly time: number | null;
}

/** One CBOR item under the §6.2.2 rules: decodeStrictCbor's, with no float,
 * no simple value but false, true and null, no tag but an outer 18 when
 * `topTag`, and no item more than 16 levels deep. Throws otherwise. */
function strictAnchorItem(data: Uint8Array, topTag: boolean): CborValue {
  const value = decodeStrictCbor(data);
  const walk = (item: CborValue, depth: number): void => {
    if (depth > MAX_ANCHOR_DEPTH) throw new SyntaxError("nested too deep");
    if (typeof item === "bigint" && item < -(1n << 63n))
      throw new SyntaxError("an integer below -2^63");
    if (item instanceof CborTag) {
      if (!(depth === 0 && topTag && item.tag === 18n))
        throw new SyntaxError("a tag other than the outer tag 18");
      walk(item.value, depth + 1);
    } else if (Array.isArray(item)) {
      for (const inner of item as readonly CborValue[]) walk(inner, depth + 1);
    } else if (item instanceof CborMap) {
      for (const [key, inner] of item.entries) {
        if (typeof key !== "bigint" && typeof key !== "string")
          throw new SyntaxError("a map key that is not an integer or text");
        walk(key, depth + 1);
        walk(inner, depth + 1);
      }
    } else if (
      !(
        item === null ||
        typeof item === "boolean" ||
        typeof item === "bigint" ||
        typeof item === "string" ||
        item instanceof Uint8Array
      )
    )
      throw new SyntaxError("a float or a simple value");
  };
  walk(value, 0);
  return value;
}

function anchorPathLength(size: bigint, index: bigint): number {
  let count = 0;
  while (size > 1n) {
    let k = 1n;
    while (k * 2n < size) k *= 2n;
    if (index < k) size = k;
    else [size, index] = [size - k, index - k];
    count += 1;
  }
  return count;
}

/** Step 1 of profile v1 §6.2.2, or null when the octets are not in the form. */
function parseAnchorReceipt(receipt: Uint8Array): AnchorReceipt | null {
  try {
    if (receipt.length === 0 || receipt.length > MAX_ANCHOR_RECEIPT_OCTETS)
      return null;
    const outer = strictAnchorItem(receipt, true);
    if (
      !(outer instanceof CborTag) ||
      outer.tag !== 18n ||
      !Array.isArray(outer.value) ||
      outer.value.length !== 4
    )
      return null;
    const [protectedBytes, unprotected, payload, signature] =
      outer.value as readonly CborValue[];
    if (
      !(protectedBytes instanceof Uint8Array) ||
      protectedBytes.length === 0 ||
      payload !== null ||
      !(signature instanceof Uint8Array) ||
      signature.length !== 64
    )
      return null;
    const headers = strictAnchorItem(protectedBytes, false);
    if (!(headers instanceof CborMap)) return null;
    let time: number | null = null;
    for (const [label, value] of headers.entries) {
      if (label === 1n) {
        if (value !== -8n && value !== -7n) return null;
      } else if (label === 395n) {
        if (value !== 1n) return null;
      } else if (label === 4n) {
        if (!(value instanceof Uint8Array)) return null;
      } else if (label === HDR_CWT_CLAIMS) {
        if (!(value instanceof CborMap)) return null;
        const iat = value.get(CWT_IAT);
        if (typeof iat === "bigint" && iat >= 0n && iat <= MAX_IAT)
          time = Number(iat);
      } else if (!(typeof label === "bigint" && label < PRIVATE_LABEL))
        return null;
    }
    const alg = headers.get(1n);
    if (alg === undefined || !headers.has(395n)) return null;
    if (!(unprotected instanceof CborMap) || unprotected.entries.length !== 1)
      return null;
    const vdp = unprotected.get(396n);
    if (!(vdp instanceof CborMap) || vdp.entries.length !== 1) return null;
    const raw = vdp.get(-1n);
    if (
      !Array.isArray(raw) ||
      raw.length === 0 ||
      raw.length > MAX_ANCHOR_PROOFS
    )
      return null;
    const proofs = [];
    for (const blob of raw as readonly CborValue[]) {
      if (!(blob instanceof Uint8Array)) return null;
      const proof = strictAnchorItem(blob, false);
      if (!Array.isArray(proof) || proof.length !== 3) return null;
      const [size, index, path] = proof as readonly CborValue[];
      if (
        typeof size !== "bigint" ||
        typeof index !== "bigint" ||
        index < 0n ||
        index >= size ||
        size > MAX_ANCHOR_TREE_SIZE ||
        !Array.isArray(path) ||
        path.length !== anchorPathLength(size, index) ||
        !(path as readonly CborValue[]).every(
          (node) => node instanceof Uint8Array && node.length === 32,
        )
      )
        return null;
      proofs.push({ size, index, path: path as readonly Uint8Array[] });
    }
    return { alg: alg === -8n ? "ed25519" : "p256", proofs, time };
  } catch {
    return null;
  }
}

/** The policy's listed keys in order (§6.2.2 step 2): lowercase hex of one
 * of two exact SubjectPublicKeyInfo shapes. */
function anchorPolicyKeys(policy: unknown): {
  readonly name: string;
  readonly type: "ed25519" | "p256";
  readonly spki: Uint8Array;
}[] {
  const rows =
    typeof policy === "object" && policy !== null
      ? (policy as { witnesses?: unknown }).witnesses
      : undefined;
  const out: { name: string; type: "ed25519" | "p256"; spki: Uint8Array }[] =
    [];
  for (const row of Array.isArray(rows) ? rows : []) {
    if (typeof row !== "object" || row === null) continue;
    const { name, keys } = row as { name?: unknown; keys?: unknown };
    if (typeof name !== "string" || !Array.isArray(keys)) continue;
    for (const key of keys) {
      if (typeof key !== "string" || !LOWER_HEX.test(key)) continue;
      const type =
        key.length === 88 && key.startsWith(ANCHOR_ED25519_PREFIX)
          ? "ed25519"
          : key.length === 182 && key.startsWith(P256_SPKI_PREFIX)
            ? "p256"
            : null;
      if (type !== null) out.push({ name, type, spki: hexToBytes(key) });
    }
  }
  return out;
}

/**
 * Steps 1 to 5 of profile v1 §6.2.2 for one Receipt over the anchor whose
 * digest is `anchorDigest` (64 lowercase hex characters). The signature is
 * checked by {@link verifyCoseReceipt} with the anchor digest's 32 octets as
 * the leaf entry. A runtime that cannot verify the Receipt's algorithm
 * reports it `NOT_CHECKED`. Never throws.
 */
export async function checkAnchorReceipt(
  anchorDigest: string,
  receipt: Uint8Array,
  policy: AnchorWitnessPolicy | unknown,
): Promise<AnchorReceiptReport> {
  const report = (
    status: AnchorReceiptReport["status"],
    witness: string | null = null,
    time: number | null = null,
  ): AnchorReceiptReport => ({
    status,
    witness,
    registration_time: time,
  });
  if (!ANCHOR_DIGEST.test(anchorDigest) || !(receipt instanceof Uint8Array))
    return report("FAIL");
  const parsed = parseAnchorReceipt(receipt);
  if (parsed === null) return report("FAIL");
  const keys = anchorPolicyKeys(policy).filter(
    ({ type }) => type === parsed.alg,
  );
  if (keys.length === 0) return report("NOT_CHECKED");
  const leaf = hexToBytes(anchorDigest);
  let unavailable = false;
  for (const { name, spki } of keys) {
    const result = await verifyCoseReceipt(receipt, leaf, spki);
    if (result.ok) return report("PASS", name, parsed.time);
    if (result.unavailable) unavailable = true;
  }
  return report(unavailable ? "NOT_CHECKED" : "FAIL");
}

/**
 * `anchor_witnessed` over `receipts`, in the order received, for the anchor
 * `anchorDigest` under the relying party's witness `policy` (profile v1
 * §6.2.2). The anchor's witnessed time is the earliest registration time of a
 * passing Receipt, with that Receipt's witness; the first received wins a
 * tie. With no timed passing Receipt, the first passing one names the
 * witness. A failing Receipt takes nothing from a passing one. Never throws.
 */
export async function checkAnchorWitnessed(
  anchorDigest: string,
  receipts: readonly Uint8Array[],
  policy: AnchorWitnessPolicy | unknown,
): Promise<AnchorWitnessReport> {
  const reports: AnchorReceiptReport[] = [];
  for (const receipt of receipts)
    reports.push(await checkAnchorReceipt(anchorDigest, receipt, policy));
  const statuses = new Set(reports.map((r) => r.status));
  const status: AnchorWitnessStatus =
    reports.length === 0
      ? "NOT_PRESENT"
      : statuses.has("PASS")
        ? "PASS"
        : statuses.has("FAIL")
          ? "FAIL"
          : "NOT_CHECKED";
  let chosen: AnchorReceiptReport | undefined;
  for (const r of reports) {
    if (r.status !== "PASS") continue;
    if (
      chosen === undefined ||
      (r.registration_time !== null &&
        (chosen.registration_time === null ||
          r.registration_time < chosen.registration_time))
    )
      chosen = r;
  }
  return {
    status,
    receipts: reports,
    witness: chosen?.witness ?? null,
    witnessed_time: chosen?.registration_time ?? null,
  };
}
