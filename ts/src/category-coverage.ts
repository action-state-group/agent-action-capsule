/**
 * The Evidence Bundle `category_coverage` member (Bundle -02).
 *
 * A producer's signed declaration of what it offers in each category of a
 * named category set. It declares; it does not prove. A verifier reports
 * five properties, each on its own, and never combines them:
 *
 * - `category_coverage_form`: the member is well formed;
 * - `category_coverage_signature`: its Ed25519 signature verifies;
 * - `category_coverage_set_registered`: its set, and every name in it, is
 *   known to the verifier;
 * - `category_coverage_request`: it declares every category the Evidence
 *   Request asked for;
 * - `category_coverage_consistency`: no category declared `ABSENT` or
 *   `WITHHELD` has a record in the Bundle.
 *
 * Each property is `PASS`, `FAIL`, `NOT_PRESENT`, `NOT_CHECKED` or
 * `INCONCLUSIVE`.
 */
import {
  decodeStrictJson,
  isHex64,
  jcs,
  JsonNumber,
  probeEd25519,
  sha256Hex,
} from "./json.js";
import { hexToBytes, producerPublicKeySpki } from "./producer-envelope-wire.js";

export type CategoryCoverageValue =
  | "PASS"
  | "FAIL"
  | "NOT_PRESENT"
  | "NOT_CHECKED"
  | "INCONCLUSIVE";

/**
 * The per-category statuses: the Evidence Layer -00 retention states
 * AVAILABLE, PARTIAL, WITHHELD and DELETED, and UNDISCLOSED and ABSENT, which
 * Bundle -02 defines.
 */
export const CATEGORY_STATUSES = [
  "AVAILABLE",
  "PARTIAL",
  "WITHHELD",
  "DELETED",
  "ABSENT",
  "UNDISCLOSED",
] as const;

/** The five properties, in report order. */
export const CATEGORY_COVERAGE_PROPERTIES = [
  "category_coverage_form",
  "category_coverage_signature",
  "category_coverage_set_registered",
  "category_coverage_request",
  "category_coverage_consistency",
] as const;

export type CategoryCoverageProperty =
  (typeof CATEGORY_COVERAGE_PROPERTIES)[number];

/** The five properties, in report order. */
export type CategoryCoverageResult = Readonly<
  Record<CategoryCoverageProperty, CategoryCoverageValue>
>;

/** The properties whose `FAIL` makes a strict verdict INVALID. */
export const CATEGORY_COVERAGE_GATING: readonly CategoryCoverageProperty[] = [
  "category_coverage_form",
  "category_coverage_signature",
  "category_coverage_consistency",
];

/** The inputs a Bundle cannot carry for its `category_coverage` member. */
export interface CategoryCoverageInputs {
  /**
   * Each category set the caller knows, to its names. A set starting `x-`
   * is never looked up.
   */
  readonly categorySets?: Readonly<Record<string, readonly string[]>> | null;
  /** The Evidence Request's octets as received. */
  readonly categoryRequest?: Uint8Array | null;
  /**
   * Each carried record's category by `capsule_id`, as the set's rule
   * assigns it (null for a record in no category). Without it, or when a
   * carried record is not in it, consistency is `NOT_CHECKED`.
   */
  readonly recordCategories?: Readonly<Record<string, string | null>> | null;
}

type JsonObject = Record<string, unknown>;

const object = (value: unknown): value is JsonObject =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  !(value instanceof JsonNumber);

const HEX128 = /^[0-9a-f]{128}$/u;
// RFC 3986 Section 4.3 absolute-URI, checked at the character level: a
// scheme, ":", then only unreserved, sub-delims, ":", "@", "/", "?" and
// well-formed percent-encodings. ASCII only; no fragment ("#"), so no
// relative reference.
const ABSOLUTE_URI =
  /^[A-Za-z][A-Za-z0-9+.-]*:(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})*$/u;
const PRIVATE_SET = "x-";
// A record in one of these categories contradicts the declaration.
const CONTRADICTED_BY_A_RECORD: readonly unknown[] = ["ABSENT", "WITHHELD"];

/**
 * `UTF8(JCS({"category_coverage": <member without signature>, "root": root}))`.
 */
export function categoryCoverageSigningInput(
  member: Readonly<JsonObject>,
  root: unknown,
): Uint8Array {
  const unsigned: JsonObject = {};
  for (const [name, value] of Object.entries(member))
    if (name !== "signature")
      Object.defineProperty(unsigned, name, {
        value,
        enumerable: true,
        writable: true,
        configurable: true,
      });
  return jcs({ category_coverage: unsigned, root });
}

function wellFormed(member: unknown): member is JsonObject {
  if (!object(member)) return false;
  if (typeof member.set !== "string" || member.set === "") return false;
  const categories = member.categories;
  if (!object(categories) || Object.keys(categories).length === 0) return false;
  for (const [name, entry] of Object.entries(categories)) {
    if (
      name === "" ||
      !object(entry) ||
      !(CATEGORY_STATUSES as readonly unknown[]).includes(entry.status)
    )
      return false;
    const hasUri = Object.hasOwn(entry, "policy_uri");
    if (
      hasUri &&
      !(
        typeof entry.policy_uri === "string" &&
        ABSOLUTE_URI.test(entry.policy_uri)
      )
    )
      return false;
    if (entry.status === "UNDISCLOSED" && !hasUri) return false;
  }
  if (
    Object.hasOwn(member, "request_digest") &&
    !isHex64(member.request_digest)
  )
    return false;
  const hasSigner = Object.hasOwn(member, "signer");
  if (hasSigner !== Object.hasOwn(member, "signature")) return false;
  if (hasSigner) {
    const signer = member.signer;
    if (!object(signer) || !isHex64(signer.key_id)) return false;
    if (typeof member.signature !== "string" || !HEX128.test(member.signature))
      return false;
  }
  return true;
}

const P25519 = (1n << 255n) - 19n;
const littleEndian = (bytes: Uint8Array): bigint =>
  bytes.reduceRight((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
const Y8 = littleEndian(
  hexToBytes(
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  ),
);
const SMALL_ORDER_Y = new Set([0n, 1n, P25519 - 1n, Y8, P25519 - Y8]);

/**
 * Whether `key` encodes a small-order point, canonically or not. Such a key
 * "verifies" signatures over any message, so it is refused, as strict
 * verification (RFC 8032 with a small-order check) does.
 */
function smallOrder(key: Uint8Array): boolean {
  const y = littleEndian(key) & ((1n << 255n) - 1n);
  return SMALL_ORDER_Y.has(y % P25519);
}

async function signature(
  member: JsonObject,
  root: unknown,
): Promise<CategoryCoverageValue> {
  if (!Object.hasOwn(member, "signature")) return "NOT_PRESENT";
  let signingInput: Uint8Array;
  try {
    signingInput = categoryCoverageSigningInput(member, root);
  } catch {
    return "FAIL"; // no canonical signing input, so nothing the signature can cover
  }
  // The form check has made both 64 and 128 lowercase hex digits.
  const key = hexToBytes((member.signer as JsonObject).key_id as string);
  if (smallOrder(key)) return "FAIL";
  if (!(await probeEd25519())) return "NOT_CHECKED"; // no Ed25519 in this runtime
  try {
    const subtle = globalThis.crypto.subtle;
    const imported = await subtle.importKey(
      "spki",
      producerPublicKeySpki(key) as BufferSource,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const verified = await subtle.verify(
      { name: "Ed25519" },
      imported,
      hexToBytes(member.signature as string) as BufferSource,
      signingInput as BufferSource,
    );
    return verified ? "PASS" : "FAIL";
  } catch {
    return "FAIL";
  }
}

function setRegistered(
  member: JsonObject,
  categorySets: CategoryCoverageInputs["categorySets"],
): CategoryCoverageValue {
  const set = member.set as string;
  if (set.startsWith(PRIVATE_SET)) return "NOT_PRESENT";
  const known =
    categorySets && Object.hasOwn(categorySets, set)
      ? categorySets[set]
      : undefined;
  if (known === undefined || known === null) return "INCONCLUSIVE";
  return Object.keys(member.categories as JsonObject).every((name) =>
    known.includes(name),
  )
    ? "PASS"
    : "FAIL";
}

async function request(
  member: JsonObject,
  octets: Uint8Array | null | undefined,
): Promise<CategoryCoverageValue> {
  if (octets === null || octets === undefined) return "NOT_CHECKED";
  // The digest is over the octets as received, so it is checked before (and
  // whether or not) they parse.
  if (
    Object.hasOwn(member, "request_digest") &&
    member.request_digest !== (await sha256Hex(octets))
  )
    return "FAIL";
  let parsed: unknown;
  try {
    // TextDecoder drops a leading byte order mark; strict JSON refuses it.
    if (octets[0] === 0xef && octets[1] === 0xbb && octets[2] === 0xbf)
      return "NOT_CHECKED";
    parsed = decodeStrictJson(octets);
  } catch {
    return "NOT_CHECKED";
  }
  if (!object(parsed)) return "NOT_CHECKED";
  if (!Object.hasOwn(parsed, "categories")) return "NOT_PRESENT";
  const asked = parsed.categories;
  const names = object(asked) ? asked.names : undefined;
  if (
    !object(asked) ||
    typeof asked.set !== "string" ||
    !Array.isArray(names) ||
    names.length === 0 ||
    !names.every((name) => typeof name === "string") ||
    new Set(names).size !== names.length
  )
    return "NOT_CHECKED"; // a malformed request is the requester's to fix, not the producer's failure
  if (asked.set !== member.set) return "FAIL";
  const categories = member.categories as JsonObject;
  return names.every((name: string) => Object.hasOwn(categories, name))
    ? "PASS"
    : "FAIL";
}

function consistency(
  member: JsonObject,
  recordIds: readonly string[],
  recordCategories: CategoryCoverageInputs["recordCategories"],
): CategoryCoverageValue {
  if (
    recordCategories === null ||
    recordCategories === undefined ||
    recordIds.some((id) => !Object.hasOwn(recordCategories, id))
  )
    return "NOT_CHECKED"; // a record the caller could not assign could be in any category
  const carried = new Set(recordIds.map((id) => recordCategories[id]));
  return Object.entries(member.categories as JsonObject).some(
    ([name, entry]) =>
      CONTRADICTED_BY_A_RECORD.includes((entry as JsonObject).status) &&
      carried.has(name),
  )
    ? "FAIL"
    : "PASS";
}

/**
 * The five properties of `bundle.category_coverage`, in report order, or
 * null when the Bundle carries no such member. When the member is malformed,
 * every other property is `NOT_CHECKED`.
 */
export async function checkCategoryCoverage(
  bundle: Readonly<JsonObject>,
  inputs: CategoryCoverageInputs = {},
): Promise<CategoryCoverageResult | null> {
  if (!Object.hasOwn(bundle, "category_coverage")) return null;
  const member = bundle.category_coverage;
  if (!wellFormed(member))
    return {
      category_coverage_form: "FAIL",
      category_coverage_signature: "NOT_CHECKED",
      category_coverage_set_registered: "NOT_CHECKED",
      category_coverage_request: "NOT_CHECKED",
      category_coverage_consistency: "NOT_CHECKED",
    };
  const records = Array.isArray(bundle.records) ? bundle.records : [];
  const recordIds = records
    .filter(object)
    .map((record) => record.capsule_id)
    .filter((id): id is string => typeof id === "string");
  return {
    category_coverage_form: "PASS",
    category_coverage_signature: await signature(
      member,
      Object.hasOwn(bundle, "root") ? bundle.root : null,
    ),
    category_coverage_set_registered: setRegistered(
      member,
      inputs.categorySets,
    ),
    category_coverage_request: await request(member, inputs.categoryRequest),
    category_coverage_consistency: consistency(
      member,
      recordIds,
      inputs.recordCategories,
    ),
  };
}

/** Whether a property whose `FAIL` gates the strict verdict failed. */
export function categoryCoverageFails(
  result: CategoryCoverageResult | null,
): boolean {
  return (
    result !== null &&
    CATEGORY_COVERAGE_GATING.some((name) => result[name] === "FAIL")
  );
}
