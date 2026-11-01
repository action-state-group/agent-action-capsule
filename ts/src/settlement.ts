// Derive settlement states from two parties' leg records (verification only):
// "Two-Party Settlement Records for Agent Payments",
// draft-mih-agent-settlement-records-01, ported from the Python reference
// (python/agent_action_capsule/settlement.py).
//
// The payer and the payee are two independent sealers; each seals only what
// its own system observed, as a Capsule with a top-level `settlement` member:
//
//   terms  <-terms_ref-  payer_observed, payee_observed, delivered
//
// verifySettlements checks each leg on its own (the Capsule checks, its
// Producer Envelope, the `settlement` structure and amounts, its wrapped
// entries and, with a key policy, that its key may seal its role), then groups
// the legs by `terms_ref` and derives the draft's payment and delivery states.
// Amounts are compared exactly, as decimal digit strings. WebCrypto only.

import { verifyEd25519Cofactored } from "./ed25519-cofactored.js";
import { JsonNumber, sha256Hex, type ParsedJson } from "./json.js";
import { nestedTooDeep } from "./nesting.js";
import { verifyProducerEnvelope } from "./producer-envelope-verification.js";
import { verifyClass1 } from "./verify.js";
import { fromHex } from "./witness.js";

export const SETTLEMENT_MEMBER = "settlement";
/** The `settlement` member's `version` for -00 and -01. */
export const SETTLEMENT_VERSION = "0";
export const SETTLEMENT_LEGS = [
  "terms",
  "payer_observed",
  "payee_observed",
  "delivered",
] as const;
export const SETTLEMENT_ROLES = ["payer", "payee"] as const;
export const SETTLEMENT_STATUSES = [
  "pending",
  "settled",
  "failed",
  "reversed",
] as const;
export type SettlementLeg = (typeof SETTLEMENT_LEGS)[number];
export type SettlementRole = (typeof SETTLEMENT_ROLES)[number];
export type SettlementStatus = (typeof SETTLEMENT_STATUSES)[number];
/** `delivery.direction` and the role that seals it. */
export const DELIVERY_DIRECTIONS: Readonly<Record<string, SettlementRole>> = {
  sent: "payee",
  received: "payer",
};
/**
 * Initial payment reference types: qualifier members, and whether a receive
 * fee may apply. `x402.transaction` is "not applicable" for the x402 `exact`
 * scheme only.
 */
export const PAYMENT_REF_TYPES: Readonly<
  Record<
    string,
    {
      readonly qualifiers: readonly string[];
      readonly receive_fee: "not_applicable" | "may_apply";
    }
  >
> = {
  "x402.transaction": {
    qualifiers: ["network"],
    receive_fee: "not_applicable",
  },
  "ln.payment_hash": { qualifiers: [], receive_fee: "may_apply" },
  "bolt12.invoice_payment_hash": { qualifiers: [], receive_fee: "may_apply" },
  "ap2.transaction_id": { qualifiers: [], receive_fee: "may_apply" },
  "ap2.payment_id": { qualifiers: [], receive_fee: "may_apply" },
  "ap2.network_confirmation_id": { qualifiers: [], receive_fee: "may_apply" },
  "acp.order_id": { qualifiers: [], receive_fee: "may_apply" },
  "ucp.order_id": { qualifiers: [], receive_fee: "may_apply" },
  "mpp.reference": { qualifiers: ["method"], receive_fee: "may_apply" },
  "iso20022.uetr": { qualifiers: [], receive_fee: "may_apply" },
  "iso20022.end_to_end_id": {
    qualifiers: ["debtor_agent"],
    receive_fee: "may_apply",
  },
  "open_payments.incoming_payment": {
    qualifiers: [],
    receive_fee: "may_apply",
  },
};
/** Initial wrapped object types and their issuer under their own spec. */
export const WRAPPED_TYPES: Readonly<Record<string, SettlementRole | "other">> =
  {
    "x402.offer": "payee",
    "x402.receipt": "payee",
    "x402.payment-payload": "payer",
    "x402.settle-response": "other",
    "ap2.checkout-mandate": "payer",
    "ap2.payment-mandate": "payer",
    "ap2.checkout-receipt": "other",
    "ap2.payment-receipt": "other",
    "bolt12.invoice": "payee",
    "bolt12.payer-proof": "payer",
    "mpp.payment-receipt": "payee",
    "iso20022.message": "other",
    "delivery.proof": "other",
  };
/** Required and optional `settlement` members per leg. */
export const SETTLEMENT_MEMBERS: Readonly<
  Record<
    SettlementLeg,
    {
      readonly required: readonly string[];
      readonly optional: readonly string[];
    }
  >
> = {
  terms: {
    required: ["version", "leg", "sealer_role", "amount"],
    optional: ["payment_ref", "deliverable", "valid_until", "wrapped"],
  },
  payer_observed: {
    required: [
      "version",
      "leg",
      "sealer_role",
      "terms_ref",
      "amount",
      "payment_ref",
      "status",
      "observed_at",
    ],
    optional: ["routing_fee", "wrapped"],
  },
  payee_observed: {
    required: [
      "version",
      "leg",
      "sealer_role",
      "terms_ref",
      "received",
      "payment_ref",
      "status",
      "observed_at",
    ],
    optional: ["receive_fee", "wrapped"],
  },
  delivered: {
    required: [
      "version",
      "leg",
      "sealer_role",
      "terms_ref",
      "observed_at",
      "delivery",
    ],
    optional: ["wrapped"],
  },
};
/**
 * The ISO 20022 code a reviewer reads for each observed status (pacs.002
 * `TxSts`; a reversal is a pacs.004 return).
 */
export const ISO20022_STATUS: Readonly<
  Record<"payer_observed" | "payee_observed", Record<SettlementStatus, string>>
> = {
  payer_observed: {
    pending: "PDNG",
    settled: "ACSC",
    failed: "RJCT",
    reversed: "pacs.004",
  },
  payee_observed: {
    pending: "PDNG",
    settled: "ACCC",
    failed: "RJCT",
    reversed: "pacs.004",
  },
};

const AMOUNT_MEMBERS = ["amount", "routing_fee", "received", "receive_fee"];
const DELIVERY_MEMBERS = [
  "direction",
  "content_digest",
  "carrier",
  "tracking_digest",
  "status",
  "shipped_at",
  "delivered_at",
  "address_digest",
];
/** `delivery.status` for physical goods (the draft's "Delivered" section). */
export const DELIVERY_STATUSES = [
  "pending",
  "in_transit",
  "delivered",
  "failed",
  "returned",
] as const;
// Each pattern matches the whole string, with ASCII digits only.
const VALUE = /^(?:0|[1-9][0-9]*)$/u;
const HEX64 = /^[0-9a-f]{64}$/u;
const B64URL = /^[A-Za-z0-9_-]*$/u;
const RFC3339_UTC =
  /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$/u;

type Json = Record<string, unknown>;
const object = (value: unknown): value is Json =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  !(value instanceof JsonNumber);
const has = (value: Json, name: string): boolean => Object.hasOwn(value, name);
const own = (table: object, key: unknown): boolean =>
  typeof key === "string" && Object.hasOwn(table, key);
const hex64 = (value: unknown): value is string =>
  typeof value === "string" && HEX64.test(value);
/**
 * An RFC 3339 UTC time that names a real instant: the pattern, a month of
 * 1-12, a day that exists in that month (proleptic Gregorian leap years),
 * hour 0-23, minute 0-59 and second 0-59 (no leap second).
 */
export function rfc3339Utc(value: unknown): boolean {
  if (typeof value !== "string" || !RFC3339_UTC.test(value)) return false;
  const field = (from: number, to: number) => Number(value.slice(from, to));
  const year = field(0, 4),
    month = field(5, 7),
    day = field(8, 10);
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return (
    month >= 1 &&
    month <= 12 &&
    day >= 1 &&
    day <= days[month - 1]! &&
    field(11, 13) <= 23 &&
    field(14, 16) <= 59 &&
    field(17, 19) <= 59
  );
}
const hexOf = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

/** An exact amount: `{value, assetCode, assetScale}`, nothing else. */
export interface Amount {
  readonly value: string;
  readonly assetCode: string;
  readonly assetScale: number;
}

/** Whether `value` is an exact amount (draft section 6). */
export function amountOk(value: unknown): value is Amount {
  return (
    object(value) &&
    sameKeys(value, ["value", "assetCode", "assetScale"]) &&
    typeof value.value === "string" &&
    VALUE.test(value.value) &&
    typeof value.assetCode === "string" &&
    value.assetCode !== "" &&
    typeof value.assetScale === "number" &&
    Number.isSafeInteger(value.assetScale) &&
    value.assetScale >= 0 &&
    value.assetScale <= 255
  );
}

function sameKeys(value: Json, names: readonly string[]): boolean {
  const keys = Object.keys(value);
  return (
    keys.length === names.length && names.every((name) => has(value, name))
  );
}

/** A payment reference compared as the draft compares it: an EVM x402
 * transaction hash is case-insensitive. */
export function normalPaymentRef(ref: Json): Json {
  const out = { ...ref };
  const network = has(ref, "network") ? ref.network : "";
  if (ref.type === "x402.transaction" && pyStr(network).startsWith("eip155:"))
    out.value = pyStr(has(ref, "value") ? ref.value : "").toLowerCase();
  return out;
}

/** Python's `str()` of a JSON value, enough for the comparisons here. */
function pyStr(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return "None";
  if (typeof value === "boolean") return value ? "True" : "False";
  return value instanceof JsonNumber ? value.raw : JSON.stringify(value);
}

/** The draft's structural failure codes for one `settlement` member. */
export function structureFailures(member: unknown): string[] {
  const s = member;
  if (
    !object(s) ||
    s.version !== SETTLEMENT_VERSION ||
    !(SETTLEMENT_LEGS as readonly unknown[]).includes(s.leg) ||
    !(SETTLEMENT_ROLES as readonly unknown[]).includes(s.sealer_role)
  )
    return ["settlement_malformed"];
  const out: string[] = [];
  const leg = s.leg as SettlementLeg,
    role = s.sealer_role as SettlementRole;
  const allowed = SETTLEMENT_MEMBERS[leg];
  const keys = Object.keys(s);
  if (
    !allowed.required.every((name) => has(s, name)) ||
    !keys.every(
      (key) => allowed.required.includes(key) || allowed.optional.includes(key),
    )
  )
    out.push("settlement_malformed");
  if (
    (leg === "payer_observed" && role !== "payer") ||
    (leg === "payee_observed" && role !== "payee")
  )
    out.push("leg_role_mismatch");
  if (AMOUNT_MEMBERS.some((name) => has(s, name) && !amountOk(s[name])))
    out.push("amount_not_exact");
  if (
    leg.endsWith("_observed") &&
    !(SETTLEMENT_STATUSES as readonly unknown[]).includes(s.status)
  )
    out.push("settlement_malformed");
  if (has(s, "terms_ref") && !hex64(s.terms_ref))
    out.push("settlement_malformed");
  if (has(s, "observed_at") && !rfc3339Utc(s.observed_at))
    out.push("settlement_malformed");
  if (leg === "delivered") {
    const d = s.delivery;
    if (
      !object(d) ||
      !own(DELIVERY_DIRECTIONS, d.direction) ||
      DELIVERY_DIRECTIONS[d.direction as string] !== role ||
      !Object.keys(d).every((key) => DELIVERY_MEMBERS.includes(key)) ||
      (!has(d, "content_digest") && !has(d, "carrier")) ||
      ["content_digest", "tracking_digest", "address_digest"].some(
        (name) => has(d, name) && !hex64(d[name]),
      ) ||
      (has(d, "carrier") && typeof d.carrier !== "string") ||
      (has(d, "status") &&
        !(DELIVERY_STATUSES as readonly unknown[]).includes(d.status)) ||
      ["shipped_at", "delivered_at"].some(
        (name) => has(d, name) && !rfc3339Utc(d[name]),
      )
    )
      out.push("settlement_malformed");
  }
  if (has(s, "valid_until") && !rfc3339Utc(s.valid_until))
    out.push("settlement_malformed");
  if (leg === "terms" && has(s, "deliverable")) {
    const dv = s.deliverable;
    if (
      !object(dv) ||
      Object.keys(dv).length === 0 ||
      !Object.keys(dv).every(
        (key) => key === "content_digest" || key === "description_digest",
      ) ||
      !Object.values(dv).every(hex64)
    )
      out.push("settlement_malformed");
  }
  // A present payment_ref, even JSON null, must be a well-formed reference.
  if (has(s, "payment_ref")) {
    const ref = s.payment_ref;
    if (
      !object(ref) ||
      typeof ref.type !== "string" ||
      typeof ref.value !== "string"
    )
      out.push("settlement_malformed");
    else if (own(PAYMENT_REF_TYPES, ref.type)) {
      // A registered type carries exactly its qualifiers, each a string.
      const qualifiers = PAYMENT_REF_TYPES[ref.type]!.qualifiers;
      if (
        !sameKeys(ref, ["type", "value", ...qualifiers]) ||
        !qualifiers.every((name) => typeof ref[name] === "string")
      )
        out.push("settlement_malformed");
    }
  }
  const wrapped = has(s, "wrapped") ? s.wrapped : [];
  for (const w of Array.isArray(wrapped) ? wrapped : [null])
    if (
      !object(w) ||
      w.digest_alg !== "SHA-256" ||
      !own(WRAPPED_TYPES, w.type) ||
      !hex64(w.digest) ||
      (has(w, "content") && typeof w.content !== "string") ||
      !Object.keys(w).every((key) =>
        ["type", "digest_alg", "digest", "content"].includes(key),
      )
    ) {
      out.push("settlement_malformed");
      break;
    }
  return [...new Set(out)];
}

/** A failure or finding: the records it concerns (their `capsule_id`s, as
 * carried) and the draft's code. */
export interface SettlementIssue {
  readonly records: readonly unknown[];
  readonly code: string;
}
export type PaymentState =
  | "terms_only"
  | "payer_stated"
  | "payee_stated"
  | "agreed"
  | "mismatch"
  | "unjoined";
export type DeliveryState = "none" | "stated" | "matched" | "mismatch";
/** One settlement: what the legs answering one terms leg derive. */
export interface Settlement {
  /** The terms leg's capsule_id. */
  readonly terms: string;
  /**
   * Null only for a conflated pair (both observed legs under one key) that
   * otherwise matches: the draft forbids `agreed` and no other state fits.
   */
  readonly paymentState: PaymentState | null;
  readonly agreedStatus?: string;
  readonly termsAmount?: "equal" | "differs";
  readonly differs?: readonly ("amount" | "status" | "payment_ref")[];
  /** The ISO 20022 code of each side whose heads state one status. */
  readonly iso20022?: Readonly<
    Partial<Record<"payer_observed" | "payee_observed", string>>
  >;
  readonly deliveryState: DeliveryState;
}
/**
 * What {@link verifySettlements} derived, in the draft's terms.
 *
 * The key result is separate from the payment state, as the draft asks:
 * `keyPolicyApplied` says whether a key policy bound each leg's key to its
 * party (false: `agreed` means two distinct keys agree, not that the keys
 * belong to the payer and the payee), and `keys` maps each authenticated
 * record (`"<capsule_id>:<key>"`) to its key. `diagnostics` carries what the
 * draft does not make a state.
 */
export interface SettlementReport {
  readonly conforming: boolean;
  readonly failures: readonly SettlementIssue[];
  readonly findings: readonly SettlementIssue[];
  readonly settlements: readonly Settlement[];
  readonly keys: Readonly<Record<string, string>>;
  readonly keyPolicyApplied: boolean;
  readonly diagnostics: readonly Readonly<Record<string, unknown>>[];
}
export interface VerifySettlementsOptions {
  /** The keys accepted for each role: `{payer: key or keys, payee: ...}`. */
  readonly keyPolicy?: Readonly<Record<string, string | readonly string[]>>;
  /**
   * The octets of wrapped objects the caller holds, by digest or as a list.
   * They are used for the re-signing check and to read the x402 scheme.
   */
  readonly wrappedObjects?:
    | Readonly<Record<string, Uint8Array>>
    | readonly Uint8Array[];
}

/** The authenticated key of a Capsule's Producer Envelope, or undefined. */
async function envelopeKey(capsule: Json): Promise<string | undefined> {
  // Hex digit pairs only, either case, no whitespace.
  if (
    typeof capsule.signature !== "string" ||
    !/^(?:[0-9a-fA-F]{2})+$/u.test(capsule.signature)
  )
    return undefined;
  try {
    const result = await verifyProducerEnvelope(
      capsule.capsule_id as string,
      fromHex(capsule.signature),
    );
    return result.ok && result.publicKey ? hexOf(result.publicKey) : undefined;
  } catch {
    // A malformed envelope is a failure, not a crash.
    return undefined;
  }
}

/**
 * Canonical unpadded base64url: no padding, only the base64url alphabet, and
 * zero trailing bits, so each byte string has one spelling. Anything else
 * throws a TypeError.
 */
export function base64UrlCanonical(text: unknown): Uint8Array {
  if (typeof text !== "string" || !B64URL.test(text) || text.length % 4 === 1)
    throw new TypeError("not unpadded base64url");
  const standard = text.replaceAll("-", "+").replaceAll("_", "/");
  const raw = Uint8Array.from(
    atob(standard.padEnd(standard.length + ((4 - (text.length % 4)) % 4), "=")),
    (char) => char.charCodeAt(0),
  );
  const again = btoa(latin1(raw))
    .replace(/=+$/u, "")
    .replaceAll("+", "-")
    .replaceAll("/", "_");
  if (again !== text) throw new TypeError("non-canonical base64url");
  return raw;
}
const b64u = base64UrlCanonical;
const ascii = (bytes: Uint8Array): string => {
  if (bytes.some((byte) => byte > 0x7f)) throw new TypeError("not ASCII");
  return String.fromCharCode(...bytes);
};

/** Whether `octets` is a JWS compact object whose Ed25519 signature counts
 * as `publicHex`'s own under the -01 re-signing test (Section "Wrapping
 * Existing Signed Objects", rule 3): the cofactored equation with any
 * canonical R, not strict Ed25519. An SD-JWT is the issuer-signed JWS, then
 * "~" and any disclosures: only the part before the first "~" is signed. */
async function jwsVerifies(
  octets: Uint8Array,
  publicHex: string,
): Promise<boolean> {
  const tilde = octets.indexOf(0x7e);
  const text = tilde === -1 ? octets : octets.subarray(0, tilde);
  const dots = [...text.keys()].filter((i) => text[i] === 0x2e);
  if (dots.length !== 2) return false;
  try {
    return await verifyEd25519Cofactored(
      fromHex(publicHex),
      b64u(ascii(text.subarray(dots[1]! + 1))),
      text.subarray(0, dots[1]),
    );
  } catch {
    return false;
  }
}

async function wrappedFailures(
  s: Json,
  kid: string | undefined,
  objects: ReadonlyMap<string, Uint8Array>,
): Promise<string[]> {
  const out: string[] = [];
  for (const w of (has(s, "wrapped") ? s.wrapped : []) as Json[]) {
    let octets = objects.get(w.digest as string);
    if (has(w, "content")) {
      let content: Uint8Array;
      try {
        content = b64u(w.content);
      } catch {
        // Content that does not decode matches no digest, the empty one
        // included.
        out.push("wrapped_digest_mismatch");
        continue;
      }
      if ((await sha256Hex(content)) !== w.digest) {
        out.push("wrapped_digest_mismatch");
        continue;
      }
      octets = content;
    }
    if (
      octets !== undefined &&
      kid !== undefined &&
      WRAPPED_TYPES[w.type as string] !== s.sealer_role &&
      (await jwsVerifies(octets, kid))
    )
      out.push("wrapped_resigned");
  }
  return out;
}

const utf8 = new TextDecoder("utf-8", { fatal: true });
/** JSON nested at most MAX_NESTING_DEPTH levels deep, as Go, Python and Rust read it. */
const parseJson = (bytes: Uint8Array): unknown => {
  const value: unknown = JSON.parse(utf8.decode(bytes));
  if (nestedTooDeep(value)) throw new SyntaxError("JSON nested too deeply");
  return value;
};
// Python's `dict.get(name, fallback)` on a parsed JSON value: anything that is
// not an object has no `get`, which ends that object's reading.
const getOr = (value: unknown, name: string, fallback: unknown): unknown => {
  if (!object(value)) throw new TypeError("not an object");
  return has(value, name) ? value[name] : fallback;
};

/**
 * The x402 scheme, from a wrapped offer or payment payload whose octets are
 * held; the first such object decides.
 */
async function x402Scheme(
  legs: readonly Json[],
  objects: ReadonlyMap<string, Uint8Array>,
): Promise<unknown> {
  for (const s of legs)
    for (const w of (has(s, "wrapped") ? s.wrapped : []) as Json[]) {
      let octets: Uint8Array | undefined;
      try {
        octets = has(w, "content")
          ? b64u(w.content)
          : objects.get(w.digest as string);
      } catch {
        continue;
      }
      if (octets === undefined || (await sha256Hex(octets)) !== w.digest)
        continue;
      try {
        if (w.type === "x402.offer") {
          const text = latin1(octets);
          if (
            [...text].filter((char) => char === ".").length === 2 &&
            !text.replace(/^[ \t\n\r\v\f]+/u, "").startsWith("{")
          )
            // JWS compact.
            return getOr(
              parseJson(
                b64u(
                  ascii(
                    octets.subarray(
                      text.indexOf(".") + 1,
                      text.lastIndexOf("."),
                    ),
                  ),
                ),
              ),
              "scheme",
              undefined,
            );
          // An EIP-712 envelope, RFC 8785 octets.
          const payload = getOr(parseJson(octets), "payload", {});
          return object(payload) ? payload.scheme : undefined;
        }
        if (w.type === "x402.payment-payload") {
          const accepted = getOr(parseJson(octets), "accepted", {});
          return object(accepted) ? accepted.scheme : undefined;
        }
      } catch {
        continue;
      }
    }
  return undefined;
}

const latin1 = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");

async function receiveFeeNotApplicable(
  refType: string,
  terms: Json,
  payer: Json,
  objects: ReadonlyMap<string, Uint8Array>,
): Promise<boolean> {
  if (
    !own(PAYMENT_REF_TYPES, refType) ||
    PAYMENT_REF_TYPES[refType]!.receive_fee !== "not_applicable"
  )
    return false;
  return (
    refType !== "x402.transaction" ||
    (await x402Scheme([terms, payer], objects)) === "exact"
  );
}

/**
 * `amount` as a count of units at `scale`: a decimal digit string with no
 * leading zeros. Kept as text, as the Python reference does, so a value of
 * any length compares without a numeric conversion that could throw.
 */
const scaled = (amount: Amount, scale: number): string =>
  `${amount.value}${"0".repeat(scale - amount.assetScale)}`.replace(
    /^0+/u,
    "",
  ) || "0";

/** The sum of two decimal digit strings, with no leading zeros. */
export function addDigitStrings(x: string, y: string): string {
  const out: number[] = [];
  let carry = 0;
  for (let i = 1; i <= Math.max(x.length, y.length); i += 1) {
    const sum =
      Number(x[x.length - i] ?? "0") + Number(y[y.length - i] ?? "0") + carry;
    out.push(sum % 10);
    carry = sum >= 10 ? 1 : 0;
  }
  if (carry) out.push(carry);
  return out.reverse().join("").replace(/^0+/u, "") || "0";
}

function amountsEqual(a: Amount, b: Amount): boolean {
  if (a.assetCode !== b.assetCode) return false;
  const scale = Math.max(a.assetScale, b.assetScale);
  return scaled(a, scale) === scaled(b, scale);
}

/** payer.amount == payee.received + payee.receive_fee, exactly, one asset.
 * Never direct equality. */
function amountRuleHolds(
  payer: Json,
  payee: Json,
  receiveFee: Amount,
): boolean {
  const amount = payer.amount as Amount,
    received = payee.received as Amount;
  if (
    amount.assetCode !== received.assetCode ||
    received.assetCode !== receiveFee.assetCode
  )
    return false;
  const scale = Math.max(
    amount.assetScale,
    received.assetScale,
    receiveFee.assetScale,
  );
  return (
    scaled(amount, scale) ===
    addDigitStrings(scaled(received, scale), scaled(receiveFee, scale))
  );
}

/** Python's `==` on parsed JSON: deep, with `true == 1` and `1 == 1.0`. */
function pyEqual(a: unknown, b: unknown): boolean {
  const scalar = (value: unknown): unknown =>
    typeof value === "boolean"
      ? Number(value)
      : value instanceof JsonNumber
        ? Number(value.raw)
        : value;
  const x = scalar(a),
    y = scalar(b);
  if (x === y) return true;
  if (Array.isArray(x) && Array.isArray(y))
    return x.length === y.length && x.every((item, i) => pyEqual(item, y[i]));
  if (object(x) && object(y)) {
    const keys = Object.keys(x);
    return (
      keys.length === Object.keys(y).length &&
      keys.every((key) => has(y, key) && pyEqual(x[key], y[key]))
    );
  }
  return false;
}

/** The capsule_id part of a record id. */
const cidOf = (rid: string): string => rid.slice(0, rid.lastIndexOf(":"));

/**
 * Derive settlement states from both parties' leg records, offline.
 *
 * Each record is checked on its own: the Capsule checks, its Producer
 * Envelope (the authenticated key), the `settlement` structure and amounts,
 * its wrapped entries, and with `keyPolicy` that its key is accepted for its
 * role. A record that fails is reported and takes no part in any state.
 * Records are grouped by `terms_ref`.
 *
 * A record is identified by its `capsule_id` AND its authenticated key: the
 * same content signed by another key is a different record, and it never
 * stands in for, or excludes, the original. Receive fees are read as zero
 * only for x402 `exact`, established from wrapped octets; otherwise an absent
 * `receive_fee` leaves the pair `unjoined` (`fee_unstated`).
 */
export async function verifySettlements(
  capsules: Iterable<unknown>,
  options: VerifySettlementsOptions = {},
): Promise<SettlementReport> {
  const objects = new Map<string, Uint8Array>();
  const wrapped = options.wrappedObjects;
  if (Array.isArray(wrapped))
    for (const octets of wrapped as readonly Uint8Array[])
      objects.set(await sha256Hex(octets), Uint8Array.from(octets));
  else if (wrapped !== undefined)
    for (const [digest, octets] of Object.entries(wrapped))
      objects.set(digest, octets);
  const policy =
    options.keyPolicy === undefined
      ? undefined
      : new Map(
          Object.entries(options.keyPolicy).map(([role, keys]) => [
            role,
            new Set(typeof keys === "string" ? [keys] : keys),
          ]),
        );

  const failures: SettlementIssue[] = [],
    findings: SettlementIssue[] = [],
    diagnostics: Record<string, unknown>[] = [],
    keys: Record<string, string> = {};
  // record id ("<capsule_id>:<key>") -> settlement member, capsule, capsule_id
  const legs = new Map<string, Json>(),
    records = new Map<string, Json>(),
    cids = new Map<string, unknown>(),
    excluded = new Set<string>();
  let n = -1;
  for (const capsule of capsules) {
    n += 1;
    if (!object(capsule)) {
      failures.push({ records: [null], code: "capsule_invalid" });
      continue;
    }
    // A capsule_id that is not a string is reported as null.
    const cid =
      typeof capsule.capsule_id === "string" ? capsule.capsule_id : null;
    if (nestedTooDeep(capsule)) {
      failures.push({ records: [cid], code: "capsule_invalid" });
      continue;
    }
    const ownFailures: string[] = [];
    let kid: string | undefined;
    let ok = false;
    try {
      ok =
        typeof cid === "string" &&
        (await verifyClass1(capsule as ParsedJson)).ok;
    } catch {
      ok = false;
    }
    if (!ok) ownFailures.push("capsule_invalid");
    else {
      kid = await envelopeKey(capsule);
      if (kid === undefined) ownFailures.push("envelope_invalid");
    }
    const rid =
      kid !== undefined ? `${pyStr(cid)}:${kid}` : `${pyStr(cid)}:#${n}`;
    // The same capsule under the same key, passed again.
    if (kid !== undefined && records.has(rid)) continue;
    const s = has(capsule, SETTLEMENT_MEMBER)
      ? capsule[SETTLEMENT_MEMBER]
      : undefined;
    const structural = structureFailures(s);
    ownFailures.push(...structural);
    if (!structural.length && object(s)) {
      ownFailures.push(...(await wrappedFailures(s, kid, objects)));
      if (
        policy !== undefined &&
        kid !== undefined &&
        !policy.get(s.sealer_role as string)?.has(kid)
      )
        ownFailures.push("sealer_not_authorized_for_role");
      const ref = s.payment_ref;
      if (object(ref) && !own(PAYMENT_REF_TYPES, ref.type))
        findings.push({ records: [cid], code: "payment_ref_type_unknown" });
    }
    // The same unauthenticated record again: report it once.
    if (
      kid === undefined &&
      failures.some(
        (f) =>
          f.records.length === 1 &&
          pyEqual(f.records[0], cid) &&
          ownFailures.includes(f.code),
      )
    )
      continue;
    for (const code of ownFailures) failures.push({ records: [cid], code });
    if (ownFailures.length) excluded.add(rid);
    legs.set(rid, object(s) ? s : {});
    records.set(rid, capsule);
    cids.set(rid, cid);
    if (kid !== undefined) keys[rid] = kid;
  }

  // Distinct keys: a payer-observed and a payee-observed leg for one terms
  // leg under the same key are not two sides. Needs no key policy.
  const observed = [...legs].filter(
    ([rid, s]) =>
      Object.hasOwn(keys, rid) && pyStr(s.leg ?? "").endsWith("_observed"),
  );
  for (const [p, ps] of observed)
    for (const [q, qs] of observed)
      if (
        ps.leg === "payer_observed" &&
        qs.leg === "payee_observed" &&
        keys[p] === keys[q] &&
        pyEqual(ps.terms_ref, qs.terms_ref)
      )
        failures.push({
          records: [cids.get(p), cids.get(q)],
          code: "sealer_conflation",
        });

  const live = new Map([...legs].filter(([rid]) => !excluded.has(rid)));
  const termsByCid = new Map<string, string>();
  // A re-signed copy of a terms leg is the same terms.
  for (const [rid, s] of live)
    if (s.leg === "terms" && !termsByCid.has(cids.get(rid) as string))
      termsByCid.set(cids.get(rid) as string, rid);
  for (const [rid, s] of live)
    if (s.leg !== "terms" && !termsByCid.has(s.terms_ref as string))
      failures.push({ records: [cids.get(rid)], code: "terms_ref_unresolved" });
  const context: Context = { records, keys, diagnostics, findings, objects };
  const settlements: Settlement[] = [];
  for (const [termsCid, termsRid] of termsByCid) {
    const answering = [...live].filter(([, s]) => s.terms_ref === termsCid);
    settlements.push(
      await settlement(
        termsCid,
        live.get(termsRid)!,
        answering,
        context,
        policy !== undefined,
      ),
    );
  }
  return {
    conforming: failures.length === 0,
    failures,
    findings,
    settlements,
    keys,
    keyPolicyApplied: policy !== undefined,
    diagnostics,
  };
}

interface Context {
  readonly records: ReadonlyMap<string, Json>;
  readonly keys: Readonly<Record<string, string>>;
  readonly diagnostics: Record<string, unknown>[];
  readonly findings: SettlementIssue[];
  readonly objects: ReadonlyMap<string, Uint8Array>;
}
type Side = readonly (readonly [string, Json])[];
const keyOf = (context: Context, rid: string): string | undefined =>
  Object.hasOwn(context.keys, rid) ? context.keys[rid] : undefined;

/**
 * Drop observed legs that a later leg of the same side supersedes. A
 * `supersedes` link counts only when the superseding record is signed by the
 * superseded record's own key: a sealer can replace its own observation,
 * never someone else's. Any other link is ignored and reported.
 */
function heads(side: Side, context: Context, termsCid: string): Side {
  const superseded = new Set<string>();
  for (const [rid] of side) {
    const record = context.records.get(rid)!;
    const chain = object(record.chain) ? record.chain : {};
    if (chain.relation !== "supersedes") continue;
    const parent = chain.parent_capsule_id;
    const key = keyOf(context, rid);
    const targets = side
      .map(([t]) => t)
      .filter(
        (t) => t !== rid && pyEqual(context.records.get(t)!.capsule_id, parent),
      );
    const ownTargets = targets.filter(
      (t) => key !== undefined && keyOf(context, t) === key,
    );
    for (const t of ownTargets) superseded.add(t);
    if (targets.length && !ownTargets.length)
      context.diagnostics.push({
        terms: termsCid,
        code: "supersedes_ignored",
        record: context.records.get(rid)!.capsule_id,
        key: key ?? null,
        parent: parent ?? null,
      });
  }
  return side.filter(([rid]) => !superseded.has(rid));
}

async function settlement(
  termsCid: string,
  terms: Json,
  legs: Side,
  context: Context,
  withPolicy: boolean,
): Promise<Settlement> {
  const payer = heads(
    legs.filter(([, s]) => s.leg === "payer_observed"),
    context,
    termsCid,
  );
  const payee = heads(
    legs.filter(([, s]) => s.leg === "payee_observed"),
    context,
    termsCid,
  );
  for (const [role, side] of [
    ["payer", payer],
    ["payee", payee],
  ] as const) {
    const sideKeys = [
      ...new Set(
        side.flatMap(([rid]) => {
          const key = keyOf(context, rid);
          return key === undefined ? [] : [key];
        }),
      ),
    ].sort();
    if (sideKeys.length > 1)
      context.diagnostics.push({
        terms: termsCid,
        code: "several_keys_for_role",
        role,
        keys: sideKeys,
        keyPolicyApplied: withPolicy,
      });
  }
  let payment: Omit<Settlement, "terms" | "deliveryState" | "iso20022">;
  if (!payer.length && !payee.length) payment = { paymentState: "terms_only" };
  else if (!payee.length) payment = { paymentState: "payer_stated" };
  else if (!payer.length) payment = { paymentState: "payee_stated" };
  else payment = await pair(termsCid, terms, payer, payee, context);

  const iso: Partial<Record<"payer_observed" | "payee_observed", string>> = {};
  for (const [leg, side] of [
    ["payer_observed", payer],
    ["payee_observed", payee],
  ] as const) {
    const statuses = new Set(side.map(([, s]) => s.status as SettlementStatus));
    if (statuses.size === 1) iso[leg] = ISO20022_STATUS[leg][[...statuses][0]!];
  }

  const deliverable = has(terms, "deliverable") ? terms.deliverable : {};
  const pinned = object(deliverable) ? deliverable.content_digest : undefined;
  const delivered = legs
    .filter(([, s]) => s.leg === "delivered")
    .map(([rid, s]) => [rid, s.delivery as Json] as const);
  const withContent = delivered.filter(([, d]) => has(d, "content_digest"));
  const values = new Set(withContent.map(([, d]) => d.content_digest));
  const directions = new Set(withContent.map(([, d]) => d.direction));
  let deliveryState: DeliveryState;
  if (!delivered.length) deliveryState = "none";
  else if (
    (pinned !== undefined &&
      pinned !== null &&
      [...values].some((v) => v !== pinned)) ||
    values.size > 1
  )
    deliveryState = "mismatch";
  else if (
    directions.size === 2 &&
    directions.has("sent") &&
    directions.has("received")
  ) {
    deliveryState = "matched";
    const sideKeys = (direction: string) =>
      new Set(
        delivered
          .filter(([, d]) => d.direction === direction)
          .map(([rid]) => keyOf(context, rid)),
      );
    const received = sideKeys("received");
    const shared = [...sideKeys("sent")].filter((k) => received.has(k));
    if (shared.length)
      context.diagnostics.push({
        terms: termsCid,
        code: "delivery_sealed_under_one_key",
        keys: shared.filter((k) => k !== undefined).sort(),
      });
  } else deliveryState = "stated";
  return {
    terms: termsCid,
    ...payment,
    ...(Object.keys(iso).length ? { iso20022: iso } : {}),
    deliveryState,
  };
}

async function pair(
  termsCid: string,
  terms: Json,
  payer: Side,
  payee: Side,
  context: Context,
): Promise<Omit<Settlement, "terms" | "deliveryState" | "iso20022">> {
  // The pair the state is derived from: one payer head and one payee head
  // under distinct keys. If every combination shares a key, it is conflated.
  const pairs = payer.flatMap((p) =>
    payee
      .filter((q) => keyOf(context, p[0]) !== keyOf(context, q[0]))
      .map((q) => [p, q] as const),
  );
  const conflated = pairs.length === 0;
  const [[aRid, a], [bRid, b]] = pairs[0] ?? [payer[0]!, payee[0]!];
  const bId = cidOf(bRid);
  const aRef = a.payment_ref as Json,
    bRef = b.payment_ref as Json;
  const refType = bRef.type as string;
  let receiveFee = has(b, "receive_fee")
    ? (b.receive_fee as Amount)
    : undefined;
  const received = b.received as Amount;
  if (
    receiveFee === undefined &&
    (await receiveFeeNotApplicable(refType, terms, a, context.objects))
  )
    receiveFee = {
      value: "0",
      assetCode: received.assetCode,
      assetScale: received.assetScale,
    };
  if (
    !own(PAYMENT_REF_TYPES, aRef.type) ||
    !own(PAYMENT_REF_TYPES, refType) ||
    aRef.type !== refType
  )
    return { paymentState: "unjoined" };
  if (receiveFee === undefined) {
    context.findings.push({ records: [bId], code: "fee_unstated" });
    return { paymentState: "unjoined" };
  }
  // fee_asset_differs names the leg or legs whose fee is in another asset:
  // the payer leg for routing_fee, the payee leg for receive_fee, payer first.
  const differ: (string | null)[] = [];
  if (
    has(a, "routing_fee") &&
    (a.routing_fee as Amount).assetCode !== (a.amount as Amount).assetCode
  )
    differ.push(cidOf(aRid));
  if (receiveFee.assetCode !== received.assetCode) differ.push(bId);
  if (differ.length > 0) {
    context.findings.push({ records: differ, code: "fee_asset_differs" });
    return { paymentState: "unjoined" };
  }
  const differs: ("amount" | "status" | "payment_ref")[] = [];
  if (!amountRuleHolds(a, b, receiveFee)) differs.push("amount");
  if (a.status !== b.status) differs.push("status");
  if (!pyEqual(normalPaymentRef(aRef), normalPaymentRef(bRef)))
    differs.push("payment_ref");
  // More than one head on a side (no supersedes chain between them): each
  // must say the same thing.
  for (const side of [payer, payee]) {
    const first = side[0]![1];
    for (const [, other] of side.slice(1)) {
      for (const name of AMOUNT_MEMBERS) {
        const x = first[name] ?? null,
          y = other[name] ?? null;
        // The same amount at another scale is the same amount (section 6).
        if (
          (x === null) !== (y === null) ||
          (x !== null && !amountsEqual(x as Amount, y as Amount))
        )
          differs.push("amount");
      }
      if (first.status !== other.status) differs.push("status");
      if (
        !pyEqual(
          normalPaymentRef(other.payment_ref as Json),
          normalPaymentRef(first.payment_ref as Json),
        )
      )
        differs.push("payment_ref");
    }
  }
  if (differs.length)
    return { paymentState: "mismatch", differs: [...new Set(differs)] };
  if (conflated) {
    // The draft: a verifier MUST NOT report agreed for such a pair; it
    // reports sealer_conflation, a failure code, not a state. No state of the
    // draft fits a conflated pair that otherwise matches, so none is
    // reported; the failure is listed and a diagnostic says why.
    context.diagnostics.push({
      terms: termsCid,
      code: "sealer_conflation",
      note: "agreed withheld; no state of the draft applies",
    });
    return { paymentState: null };
  }
  return {
    paymentState: "agreed",
    agreedStatus: a.status as string,
    termsAmount: amountsEqual(a.amount as Amount, terms.amount as Amount)
      ? "equal"
      : "differs",
  };
}
