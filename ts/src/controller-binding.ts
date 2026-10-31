import { verifyBip340 } from "./bip340.js";
import { verifyEd25519Strict } from "./ed25519-strict.js";
import {
  asJsonObject,
  decodeStrictJson,
  jcs,
  JsonNumber,
  type ParsedJson,
} from "./json.js";
import { sha256 } from "./sha256.js";

/**
 * The Controller Binding v0 record verifier (spec/controller-binding-v0.md,
 * cited as CB), a port of `go/controllerbinding`: the record's form (§3),
 * both signatures over the one signing input, each by its key's type (§4,
 * §4.1), its window, the revocation statements the caller received (§5), a
 * revocation list a using profile declared complete (§5.1), and, for
 * `same_organization_credentialed`, a credential through a verifier the caller
 * passes. It reports the binding properties of §6.1, what the binding proves
 * (§7 item 2), whether it applies to a pair of keys (§6.2) and the
 * `issuer_independence` that gives (§7 item 4).
 *
 * A binding shows only that whoever held each private key signed the record.
 * Nothing here establishes who controls a key. No trust anchors, accepted
 * credential issuers or credential verifier ship here: accepting an issuer is
 * the caller's trust policy.
 *
 * This is the one verifier of a binding record in this package: the
 * `composed/v1` `controller_binding` join (`composed.ts`) reads its report and
 * adds only Bundle -02's own rules.
 */

export const BINDING_VERSION = "controller-binding/0";
export const REVOCATION_VERSION = "controller-binding-revocation/0";
export const REVOCATION_METHOD = "revocation_statement/0";

export const CLAIM_SAME_CONTROLLER = "same_controller_asserted";
export const CLAIM_DELEGATED_BY = "delegated_by";
export const CLAIM_SAME_ORGANIZATION = "same_organization_credentialed";
export const METHOD_DUAL_SIGNATURE = "dual_signature/0";
export const METHOD_DUAL_SIGNATURE_CREDENTIAL = "dual_signature_credential/0";

export const KEY_ED25519 = "ed25519";
export const KEY_BIP340 = "bip340";
const NOSTR_KIND = 3374;
/** The largest `created_at` a bip340 signature may carry: 2^53 - 1. */
const MAX_CREATED_AT = 2n ** 53n - 1n;

export const PROPERTY_FORM = "controller_binding_form";
export const PROPERTY_SIGNATURES = "controller_binding_signatures";
export const PROPERTY_WINDOW = "controller_binding_window";
export const PROPERTY_REVOCATION = "controller_binding_revocation";
export const PROPERTY_CREDENTIAL = "controller_binding_credential";

export const STATUS_PASS = "PASS";
export const STATUS_FAIL = "FAIL";
export const STATUS_NOT_PRESENT = "NOT_PRESENT";
export const STATUS_NOT_CHECKED = "NOT_CHECKED";
export const STATUS_INCONCLUSIVE = "INCONCLUSIVE";

const PROVES_CONTROL = "control of both keys at the ceremony";
const PROVES_CREDENTIALED =
  "a trusted issuer key states that both keys are held within one organization";

const CLAIMS: Readonly<
  Record<string, { method: string; added: string; states: string }>
> = {
  [CLAIM_SAME_CONTROLLER]: {
    method: METHOD_DUAL_SIGNATURE,
    added: "",
    states: "both key holders state that one controller holds both keys",
  },
  [CLAIM_DELEGATED_BY]: {
    method: METHOD_DUAL_SIGNATURE,
    added: "delegator",
    states:
      "both key holders state that the delegator delegated to the other key",
  },
  [CLAIM_SAME_ORGANIZATION]: {
    method: METHOD_DUAL_SIGNATURE_CREDENTIAL,
    added: "credential",
    states:
      "both key holders state that both keys are held within one organization",
  },
};

const COMMON = [
  "binding_version",
  "claim",
  "method",
  "keys",
  "issued_at",
  "not_before",
  "not_after",
  "revocation",
  "nonce",
  "sigs",
];

const HEX128 = /^[0-9a-f]{128}$/u;
const HEX64 = /^[0-9a-f]{64}$/u;
/** The nonce of a record naming a bip340 key (CB §3.1, §9.3). */
const NONCE32 = /^[0-9a-f]{32,}$/u;
const PROFILE_TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/u;
const RECORD_TIME =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z$/u;

/** A time as nanoseconds since the Unix epoch. Times compare as instants. */
export type Instant = bigint;

const NS = 1_000_000_000n;

function daysFromCivil(y: number, m: number, d: number): number {
  const year = m <= 2 ? y - 1 : y;
  const era = Math.floor(year / 400);
  const yoe = year - era * 400;
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}

function daysInMonth(y: number, m: number): number {
  if (m === 2) return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0 ? 29 : 28;
  return [4, 6, 9, 11].includes(m) ? 30 : 31;
}

function parseTime(text: unknown, form: RegExp): Instant | undefined {
  if (typeof text !== "string") return undefined;
  const match = form.exec(text);
  if (match === null) return undefined;
  const [y, mo, d, h, mi, s] = match.slice(1, 7).map(Number) as [
    number,
    number,
    number,
    number,
    number,
    number,
  ];
  if (
    mo < 1 ||
    mo > 12 ||
    d < 1 ||
    d > daysInMonth(y, mo) ||
    h > 23 ||
    mi > 59 ||
    s > 59
  )
    return undefined;
  const seconds =
    BigInt(daysFromCivil(y, mo, d)) * 86400n + BigInt(h * 3600 + mi * 60 + s);
  // Go reads at most nine fractional digits.
  const fraction = (match[7] ?? "").slice(0, 9).padEnd(9, "0");
  return seconds * NS + BigInt(fraction);
}

/** A §5.2 time: RFC 3339, UTC, "Z", seconds precision. */
export const parseProfileTime = (text: unknown): Instant | undefined =>
  parseTime(text, PROFILE_TIME);

/** A root record's `timestamp`, which may carry fractional seconds. */
export const parseRecordTime = (text: unknown): Instant | undefined =>
  parseTime(text, RECORD_TIME);

type Obj = Record<string, ParsedJson>;
const isObject = (value: unknown): value is Obj =>
  asJsonObject(value as ParsedJson) !== undefined;
const isKey = (value: unknown): value is string =>
  typeof value === "string" && HEX64.test(value);

function hasMembers(value: Obj, names: readonly string[]): boolean {
  const own = Object.keys(value);
  return (
    own.length === names.length && names.every((n) => Object.hasOwn(value, n))
  );
}

function without(value: Obj, name: string): Obj {
  const out: Obj = {};
  for (const [k, v] of Object.entries(value))
    if (k !== name)
      Object.defineProperty(out, k, {
        value: v,
        writable: true,
        enumerable: true,
        configurable: true,
      });
  return out;
}

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function hexToBytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(text.slice(2 * i, 2 * i + 2), 16);
  return out;
}

const encoder = new TextEncoder();
const toBytes = (value: Uint8Array | string): Uint8Array =>
  typeof value === "string" ? encoder.encode(value) : value;

/** The credential member of a `same_organization_credentialed` record (CB §3.2). */
export interface Credential {
  readonly issuer: string;
  readonly method: string;
  readonly digest: string;
}

/**
 * Checks a delivered credential, given as the octets transmitted, against the
 * record's credential member and its two bound keys. It owns the credential's
 * native method and the caller's trust policy, and returns a §7.1 status: PASS
 * only when the credential verifies under `credential.issuer`, the trust
 * policy accepts that issuer and the credential names both keys; FAIL when
 * any of these fails; INCONCLUSIVE when the trust policy cannot decide. The
 * digest has already been checked.
 */
export type CredentialVerifier = (
  octets: Uint8Array,
  credential: Credential,
  keys: readonly [string, string],
) => string | Promise<string>;

/**
 * What a using profile gives the verifier beside a revocation list it
 * declares complete (CB §5.1). It is the asserting party's statement, not a
 * finding.
 */
export interface Declaration {
  readonly profile: string;
  readonly assertedBy: string;
  readonly binding: string;
  readonly listDigest: string;
  readonly asOf: string;
  /** The profile's freshness bound, in seconds. */
  readonly maxAge: bigint;
}

const DECLARATION_MEMBERS = [
  "profile",
  "asserted_by",
  "binding",
  "list_digest",
  "as_of",
  "max_age",
];

/**
 * Read a declaration (CB §5.1) from its JSON object: exactly the six members,
 * each in its form. With `error`, the declaration does not count; the returned
 * fields still hold profile, asserted_by and as_of where each is a text
 * string, so it can be reported as delivered.
 */
export function parseDeclaration(octets: Uint8Array | string): {
  declaration: Declaration;
  error?: string;
} {
  const d = {
    profile: "",
    assertedBy: "",
    binding: "",
    listDigest: "",
    asOf: "",
    maxAge: 0n,
  };
  let value: ParsedJson;
  try {
    value = decodeStrictJson(octets);
  } catch (error) {
    return {
      declaration: d,
      error: `the declaration is not one JSON value: ${String(error)}`,
    };
  }
  if (!isObject(value))
    return { declaration: d, error: "the declaration is not a JSON object" };
  if (typeof value.profile === "string") d.profile = value.profile;
  if (typeof value.asserted_by === "string") d.assertedBy = value.asserted_by;
  if (typeof value.as_of === "string") d.asOf = value.as_of;
  if (!hasMembers(value, DECLARATION_MEMBERS))
    return {
      declaration: d,
      error:
        "the declaration does not have exactly profile, asserted_by, binding, " +
        "list_digest, as_of and max_age",
    };
  if (typeof value.profile !== "string")
    return { declaration: d, error: "profile is not a text string" };
  if (typeof value.asserted_by !== "string")
    return { declaration: d, error: "asserted_by is not a text string" };
  const binding = typeof value.binding === "string" ? value.binding : "";
  const listDigest =
    typeof value.list_digest === "string" ? value.list_digest : "";
  const out = { ...d, binding, listDigest };
  if (!HEX64.test(binding) || !HEX64.test(listDigest))
    return {
      declaration: out,
      error: "binding or list_digest is not 64 lowercase hex characters",
    };
  if (parseProfileTime(value.as_of) === undefined)
    return { declaration: out, error: "as_of is not a time" };
  const number = value.max_age;
  if (!(number instanceof JsonNumber) || !/^-?[0-9]+$/u.test(number.raw))
    return { declaration: out, error: "max_age is not an integer" };
  const maxAge = BigInt(number.raw);
  if (maxAge < 0n || maxAge > MAX_CREATED_AT)
    return {
      declaration: out,
      error: "max_age is not an integer from 0 to 2^53 - 1",
    };
  return { declaration: { ...out, maxAge } };
}

/**
 * A revocation list with the declaration a using profile gave beside it
 * (CB §5.1). The caller takes the declaration only through the using
 * profile's own channel, never from the party presenting the evidence: it is
 * unsigned, and `assertedBy` is reported as delivered, not as authenticated.
 */
export interface RevocationList {
  /** The declaration's JSON object as received. */
  readonly declaration: Uint8Array | string;
  /** The list's octets as transmitted: a JSON array of statements. */
  readonly list: Uint8Array | string;
  /** The evaluation time E the freshness bound is checked at. */
  readonly evaluatedAt: Instant;
}

/** What the caller received beside the binding record, and how it checks a credential. */
export interface BindingOptions {
  /** Revocation statements as received (CB §5); one that does not apply is ignored. */
  readonly revocations?: readonly (Uint8Array | string)[];
  readonly revocationList?: RevocationList;
  /** The credential as transmitted, when one was delivered. */
  readonly credential?: Uint8Array | string;
  /** Checks a credential by its `credential.method`; a method with no entry is NOT_CHECKED. */
  readonly credentialVerifiers?: Readonly<Record<string, CredentialVerifier>>;
}

/** How a verifier reports a declaration (CB §5.1). */
export interface ListReport {
  readonly profile: string;
  readonly assertedBy: string;
  readonly listDigest: string;
  readonly asOf: string;
  /** Whether the declaration counts for this binding at the times asked about. */
  readonly counts: boolean;
  /** Why it does not count; a diagnostic. */
  readonly reason?: string;
}

/** What a verifier reports for one binding record (CB §7). */
export interface BindingReport {
  readonly claim?: string;
  readonly keys?: readonly [string, string];
  readonly delegator?: string;
  readonly notBefore?: string;
  readonly notAfter?: string;
  readonly bindingDigest?: string;
  readonly properties: Readonly<Record<string, string>>;
  readonly proves: readonly string[];
  readonly revocationList?: ListReport;
}

function wellFormed(r: Obj): boolean {
  const claim = r.claim;
  if (typeof claim !== "string" || !Object.hasOwn(CLAIMS, claim)) return false;
  const spec = CLAIMS[claim]!;
  const names = [...COMMON];
  if (spec.added !== "") names.push(spec.added);
  if (Object.hasOwn(r, "key_types")) names.push("key_types"); // OPTIONAL (§3.1)
  if (!hasMembers(r, names) || r.binding_version !== BINDING_VERSION)
    return false;
  // A method that §3.2 defines for another claim type is malformed; one it
  // does not define at all is well formed and NOT_CHECKED.
  const method = r.method;
  if (typeof method !== "string") return false;
  for (const other of Object.values(CLAIMS))
    if (other.method === method && method !== spec.method) return false;
  const keys = r.keys;
  if (
    !Array.isArray(keys) ||
    keys.length !== 2 ||
    !isKey(keys[0]) ||
    !isKey(keys[1]) ||
    keys[0] >= keys[1]
  )
    return false; // ascending, so also distinct
  const issued = parseProfileTime(r.issued_at);
  const notBefore = parseProfileTime(r.not_before);
  const notAfter = parseProfileTime(r.not_after);
  if (
    issued === undefined ||
    notBefore === undefined ||
    notAfter === undefined ||
    notBefore > issued ||
    !(issued < notAfter)
  )
    return false;
  if (r.revocation !== REVOCATION_METHOD) return false;
  const nonce = r.nonce;
  if (typeof nonce !== "string") return false;
  if (Object.hasOwn(r, "key_types")) {
    const list = r.key_types;
    if (
      !Array.isArray(list) ||
      list.length !== 2 ||
      typeof list[0] !== "string" ||
      typeof list[1] !== "string"
    )
      return false;
    // A bip340 key is often a public Nostr identity, so the nonce alone keeps
    // a listed binding digest from being matched to guessed keys.
    if (list.includes(KEY_BIP340) && !NONCE32.test(nonce)) return false;
  }
  if (!Array.isArray(r.sigs)) return false;
  for (const entry of r.sigs)
    if (!isObject(entry) || !hasMembers(entry, ["key_id", "sig"])) return false;
  if (spec.added === "delegator")
    return r.delegator === keys[0] || r.delegator === keys[1];
  if (spec.added === "credential") {
    const c = r.credential;
    return (
      isObject(c) &&
      hasMembers(c, ["issuer", "method", "digest"]) &&
      isKey(c.issuer) &&
      typeof c.method === "string" &&
      isKey(c.digest)
    );
  }
  return true;
}

/** Each key's type, in the order of keys (CB §3.1): both ed25519 when absent. */
function keyTypes(r: Obj): [string, string] {
  const list = r.key_types;
  if (!Array.isArray(list)) return [KEY_ED25519, KEY_ED25519];
  return [list[0] as string, list[1] as string];
}

/** Check an ed25519 key's hex sig with strict Ed25519. */
async function verifyHex(
  key: string,
  sig: unknown,
  message: Uint8Array,
): Promise<boolean> {
  if (typeof sig !== "string" || !HEX128.test(sig) || !HEX64.test(key))
    return false;
  return verifyEd25519Strict(hexToBytes(key), hexToBytes(sig), message);
}

/**
 * Check a bip340 key's sig, {created_at, sig}: the BIP-340 signature over the
 * id of the Nostr event (NIP-01) of kind 3374, no tags, and content
 * `<version>:<SHA-256 of signed>` (CB §4.1).
 */
function verifyNostr(
  key: string,
  sig: unknown,
  version: string,
  signed: Uint8Array,
): boolean {
  if (!isObject(sig) || !hasMembers(sig, ["created_at", "sig"])) return false;
  const text = sig.sig;
  if (typeof text !== "string" || !HEX128.test(text)) return false;
  // created_at is an integer token: a fraction or an exponent is not one.
  const number = sig.created_at;
  if (!(number instanceof JsonNumber) || !/^-?[0-9]+$/u.test(number.raw))
    return false;
  const createdAt = BigInt(number.raw);
  if (createdAt < 0n || createdAt > MAX_CREATED_AT) return false;
  if (!HEX64.test(key)) return false;
  // key is 64 lowercase hex characters and version and the digest are ASCII
  // with nothing JSON escapes, so this is NIP-01's serialization.
  const event = `[0,"${key}",${createdAt},${NOSTR_KIND},[],"${version}:${hex(sha256(signed))}"]`;
  return verifyBip340(key, sha256(encoder.encode(event)), text);
}

/** A key type §3.3 does not list never verifies (CB §4.1). */
async function verifySig(
  key: string,
  keyType: string,
  sig: unknown,
  version: string,
  signed: Uint8Array,
): Promise<boolean> {
  if (keyType === KEY_ED25519) return verifyHex(key, sig, signed);
  if (keyType === KEY_BIP340) return verifyNostr(key, sig, version, signed);
  return false;
}

/** controller_binding_signatures (CB §4). */
async function signatures(
  r: Obj,
  keys: readonly [string, string],
  types: readonly [string, string],
): Promise<string> {
  if (r.method !== CLAIMS[r.claim as string]!.method) return STATUS_NOT_CHECKED;
  for (const t of types)
    if (t !== KEY_ED25519 && t !== KEY_BIP340) return STATUS_NOT_CHECKED;
  let input: Uint8Array;
  try {
    input = jcs(without(r, "sigs"));
  } catch {
    return STATUS_FAIL;
  }
  const sigs = r.sigs as ParsedJson[];
  if (sigs.length !== 2) return STATUS_FAIL;
  for (let i = 0; i < 2; i++) {
    const entry = sigs[i] as Obj;
    if (
      entry.key_id !== keys[i] ||
      !(await verifySig(keys[i]!, types[i]!, entry.sig, BINDING_VERSION, input))
    )
      return STATUS_FAIL;
  }
  return STATUS_PASS;
}

/**
 * controller_binding_revocation (CB §5, §6.1) before any declaration: FAIL
 * when a received statement applies with `revoked_at` at or before some T,
 * otherwise NOT_CHECKED, since a statement not received cannot be excluded.
 */
async function revocation(
  digest: string,
  keys: readonly [string, string],
  types: readonly [string, string],
  ts: readonly Instant[],
  statements: readonly Uint8Array[],
): Promise<string> {
  for (const octets of statements) {
    let s: ParsedJson;
    try {
      s = decodeStrictJson(octets);
    } catch {
      continue;
    }
    if (
      !isObject(s) ||
      !hasMembers(s, [
        "revocation_version",
        "binding",
        "key_id",
        "revoked_at",
        "sig",
      ]) ||
      s.revocation_version !== REVOCATION_VERSION ||
      s.binding !== digest ||
      (s.key_id !== keys[0] && s.key_id !== keys[1])
    )
      continue;
    const keyType = s.key_id === keys[1] ? types[1] : types[0];
    let signed: Uint8Array;
    try {
      signed = jcs(without(s, "sig"));
    } catch {
      continue;
    }
    if (
      !(await verifySig(
        s.key_id as string,
        keyType,
        s.sig,
        REVOCATION_VERSION,
        signed,
      ))
    )
      continue;
    const revokedAt = parseProfileTime(s.revoked_at);
    if (revokedAt === undefined) continue;
    for (const t of ts) if (revokedAt <= t) return STATUS_FAIL;
  }
  return STATUS_NOT_CHECKED;
}

/** A list's entries, each re-encoded as its own octets; undefined if not an array. */
function listEntries(list: Uint8Array | string): Uint8Array[] | undefined {
  let value: ParsedJson;
  try {
    value = decodeStrictJson(list);
  } catch {
    return undefined;
  }
  if (!Array.isArray(value)) return undefined;
  const entries: Uint8Array[] = [];
  for (const item of value)
    try {
      entries.push(jcs(item));
    } catch {
      /* an entry that cannot be encoded is not a statement */
    }
  return entries;
}

const floorSeconds = (t: Instant): bigint =>
  t >= 0n ? t / NS : -((-t + NS - 1n) / NS);

function whyNot(
  declared: { declaration: Declaration; error?: string },
  received: string,
  l: RevocationList,
  digest: string,
  ts: readonly Instant[],
): string {
  if (declared.error !== undefined) return declared.error;
  const d = declared.declaration;
  if (d.binding !== digest) return "the declaration names another binding";
  if (d.listDigest !== received)
    return "list_digest is not the digest of the list received";
  if (listEntries(l.list) === undefined) return "the list is not a JSON array";
  if (ts.length === 0) return "no time T was asked about";
  const asOf = parseProfileTime(d.asOf)!;
  for (const t of ts)
    if (asOf < t) return "as_of is earlier than a time asked about";
  if (asOf > l.evaluatedAt) return "as_of is later than the evaluation time";
  if (floorSeconds(l.evaluatedAt) - floorSeconds(asOf) > d.maxAge)
    return "the evaluation time is more than max_age after as_of";
  return "";
}

function listReport(
  l: RevocationList,
  digest: string,
  ts: readonly Instant[],
): ListReport {
  const received = hex(sha256(toBytes(l.list)));
  const declared = parseDeclaration(l.declaration);
  const d = declared.declaration;
  const reason = whyNot(declared, received, l, digest, ts);
  return {
    profile: d.profile,
    assertedBy: d.assertedBy,
    listDigest: received,
    asOf: d.asOf,
    counts: reason === "",
    ...(reason === "" ? {} : { reason }),
  };
}

/** controller_binding_credential (CB §6.1). */
async function credentialStatus(
  c: Credential,
  keys: readonly [string, string],
  opts: BindingOptions,
): Promise<string> {
  if (opts.credential === undefined) return STATUS_NOT_PRESENT;
  const verify = opts.credentialVerifiers?.[c.method];
  if (
    verify === undefined ||
    !Object.hasOwn(opts.credentialVerifiers!, c.method)
  )
    return STATUS_NOT_CHECKED;
  const octets = toBytes(opts.credential);
  if (hex(sha256(octets)) !== c.digest) return STATUS_FAIL;
  const status = await verify(octets, c, keys);
  return status === STATUS_PASS ||
    status === STATUS_FAIL ||
    status === STATUS_INCONCLUSIVE
    ? status
    : STATUS_FAIL; // a verifier that returns no status vouches for nothing
}

/**
 * Check one binding record, given as the octets received, at the times `ts`:
 * for a pair under IP §6.7.4, each member's `issued_at`. With no time the
 * window is NOT_CHECKED, so the binding does not apply.
 */
export async function verifyBinding(
  record: Uint8Array | string,
  ts: readonly Instant[],
  opts: BindingOptions = {},
): Promise<BindingReport> {
  const properties: Record<string, string> = {};
  const proves: string[] = [];
  let value: ParsedJson;
  try {
    value = decodeStrictJson(record);
  } catch {
    properties[PROPERTY_FORM] = STATUS_FAIL;
    return { properties, proves };
  }
  if (!isObject(value)) {
    properties[PROPERTY_FORM] = STATUS_FAIL;
    return { properties, proves };
  }
  const r = value;
  let bindingDigest: string | undefined;
  try {
    bindingDigest = hex(sha256(jcs(without(r, "sigs"))));
  } catch {
    /* no digest for a record that cannot be serialized */
  }
  const claim = typeof r.claim === "string" ? r.claim : undefined;
  // The keys a record names are reported even when it is malformed, so a pair
  // can be told it is named by a binding that does not apply (§6.2).
  let named: [string, string] | undefined;
  if (
    Array.isArray(r.keys) &&
    r.keys.length === 2 &&
    typeof r.keys[0] === "string" &&
    typeof r.keys[1] === "string"
  )
    named = [r.keys[0], r.keys[1]];
  const head = {
    ...(claim === undefined ? {} : { claim }),
    ...(named === undefined ? {} : { keys: named }),
    ...(bindingDigest === undefined ? {} : { bindingDigest }),
  };
  if (!wellFormed(r)) {
    properties[PROPERTY_FORM] = STATUS_FAIL;
    return { ...head, properties, proves };
  }
  properties[PROPERTY_FORM] = STATUS_PASS;
  const keys = named!;
  const delegator = typeof r.delegator === "string" ? r.delegator : undefined;
  const notBeforeText = r.not_before as string;
  const notAfterText = r.not_after as string;

  const types = keyTypes(r);
  properties[PROPERTY_SIGNATURES] = await signatures(r, keys, types);
  properties[PROPERTY_WINDOW] =
    ts.length === 0 ? STATUS_NOT_CHECKED : STATUS_PASS;
  const notBefore = parseProfileTime(notBeforeText)!;
  const notAfter = parseProfileTime(notAfterText)!;
  for (const t of ts)
    if (t < notBefore || !(t < notAfter))
      properties[PROPERTY_WINDOW] = STATUS_FAIL;

  let statements = (opts.revocations ?? []).map(toBytes);
  if (opts.revocationList !== undefined)
    statements = [
      ...statements,
      ...(listEntries(opts.revocationList.list) ?? []),
    ];
  properties[PROPERTY_REVOCATION] = await revocation(
    bindingDigest ?? "",
    keys,
    types,
    ts,
    statements,
  );
  let list: ListReport | undefined;
  if (opts.revocationList !== undefined) {
    list = listReport(opts.revocationList, bindingDigest ?? "", ts);
    if (list.counts && properties[PROPERTY_REVOCATION] !== STATUS_FAIL)
      properties[PROPERTY_REVOCATION] = STATUS_PASS;
  }
  if (claim === CLAIM_SAME_ORGANIZATION) {
    const c = r.credential as Obj;
    properties[PROPERTY_CREDENTIAL] = await credentialStatus(
      {
        issuer: c.issuer as string,
        method: c.method as string,
        digest: c.digest as string,
      },
      keys,
      opts,
    );
  }
  if (properties[PROPERTY_SIGNATURES] === STATUS_PASS) {
    proves.push(PROVES_CONTROL, CLAIMS[claim!]!.states);
    if (properties[PROPERTY_CREDENTIAL] === STATUS_PASS)
      proves.push(PROVES_CREDENTIALED);
  }
  return {
    ...head,
    ...(delegator === undefined ? {} : { delegator }),
    notBefore: notBeforeText,
    notAfter: notAfterText,
    properties,
    proves,
    ...(list === undefined ? {} : { revocationList: list }),
  };
}

/**
 * Whether the binding applies to the pair of its own two keys (CB §6.2): form,
 * signatures and window PASS, and revocation not FAIL. The credential never
 * decides it. {@link bindingAppliesTo} asks about a given pair.
 */
export function bindingApplies(report: BindingReport): boolean {
  const p = report.properties;
  return (
    p[PROPERTY_FORM] === STATUS_PASS &&
    p[PROPERTY_SIGNATURES] === STATUS_PASS &&
    p[PROPERTY_WINDOW] === STATUS_PASS &&
    p[PROPERTY_REVOCATION] !== STATUS_FAIL
  );
}

/** Whether the record's two keys are exactly a and b, in either order (CB §6.2). */
export function bindingBindsPair(
  report: BindingReport,
  a: string,
  b: string,
): boolean {
  const keys = report.keys;
  return (
    keys !== undefined &&
    ((keys[0] === a && keys[1] === b) || (keys[0] === b && keys[1] === a))
  );
}

/** Whether the binding applies to the pair of keys a and b (CB §6.2). */
export const bindingAppliesTo = (
  report: BindingReport,
  a: string,
  b: string,
): boolean => bindingBindsPair(report, a, b) && bindingApplies(report);

/** The issuer_independence a pair gets (CB §7 item 4). */
export interface IssuerIndependence {
  readonly status: string;
  readonly shownAs: string;
  readonly reason: string | null;
}

/**
 * The issuer_independence of a pair signed under keys a and b, given every
 * binding report the verifier received for it (CB §9.1). A binding never
 * gives PASS (§6.2).
 */
export function pairIndependence(
  a: string,
  b: string,
  ...reports: BindingReport[]
): IssuerIndependence {
  if (a === b)
    return {
      status: STATUS_FAIL,
      shownAs: "redundant, not corroborating",
      reason: "same key",
    };
  for (const r of reports)
    if (bindingAppliesTo(r, a, b))
      return {
        status: STATUS_FAIL,
        shownAs: "redundant, not corroborating",
        reason: `controller binding ${r.claim} ${r.bindingDigest}`,
      };
  return {
    status: STATUS_NOT_CHECKED,
    shownAs: "not corroborating",
    reason: null,
  };
}
