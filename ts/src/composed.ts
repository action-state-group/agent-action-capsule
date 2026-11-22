import {
  bindingAppliesTo,
  parseRecordTime,
  PROPERTY_FORM,
  STATUS_PASS,
  verifyBinding,
  type BindingReport,
  type Instant,
} from "./controller-binding.js";
import {
  decodeCose,
  loadCheckpointMetadata,
  signedCheckpointFields,
} from "./cll-checkpoint.js";
import {
  CborMap,
  CborTag,
  decodeWellFormedItem,
  type CborValue,
} from "./cose-receipt.js";
import { verifyEd25519Strict } from "./ed25519-strict.js";
import { isHex64, jcs, jsonDigest, sha256Hex } from "./json.js";
import { verifyRecordSignature } from "./producer-envelope-verification.js";

/**
 * The `composed/v1` Evidence Bundle extension, verified
 * (draft-mih-zhang-agent-disclosure-bundle-02, "The composed/v1 Extension").
 *
 * This is a port of the Go reference, `go/bundle/composed.go`, and reports
 * the same results with the same tokens: the recomputed composed digest,
 * each member, composition closure, each join's declared and derived state,
 * and per join whether a derived agreement is redundant or corroborating on
 * declared custody. It is verification, run by the verify core
 * (`verifyBundle`), never by a presentation module.
 *
 * As in the Go core, no refusal signature profile ships here: the draft
 * leaves the signature format to the deployment, so a carried refusal is
 * `signature_unverified` (neither failed nor absent).
 */

export const COMPOSED_KIND = "composed/v1";

export type ComposedStatus = "pass" | "withheld" | "fail";

export interface ComposedDigestResult {
  readonly declared: string;
  /** Empty when the digest input cannot be serialized. */
  readonly recomputed: string;
  readonly matches: boolean;
}

/** A member Evidence Bundle's own three completeness claims. */
export interface ComposedMemberClaims {
  readonly graphClosure: ComposedClaim;
  readonly intervalCoverage: ComposedClaim;
  readonly perRecordMembership: ComposedClaim;
  /** Set for a well-formed empty-history Bundle: it shows no history. */
  readonly history?: { readonly state: "none"; readonly since: string | null };
}

/**
 * What a containing verifier is given beside the block: the Controller
 * Binding records and revocation statements delivered beside the Bundle (not
 * part of it), from which a `controller_binding` join is derived (draft -02,
 * "Controller Binding Records"). A join whose record was not delivered is not
 * derivable.
 */
export interface ComposedOptions {
  readonly controllerBindings?: readonly Record<string, unknown>[];
  readonly bindingRevocations?: readonly Record<string, unknown>[];
}

export interface ComposedClaim {
  readonly status: ComposedStatus;
  readonly findings: readonly string[];
}

export interface ComposedMemberResult {
  readonly id: string;
  readonly observer: string;
  readonly outcome: "artifact" | "refusal" | "absence";
  /** "carried", "declared_missing" or "absent" (neither carried nor listed in missing). */
  readonly body: "carried" | "declared_missing" | "absent";
  /** "reproduced", "mismatch" or "not_shown" (no body carried). */
  readonly digest: "reproduced" | "mismatch" | "not_shown";
  readonly findings: readonly string[];
  /** A carried artifact's own claims; never merged into another's. */
  readonly bundle?: ComposedMemberClaims;
  /** Set for a carried refusal. */
  readonly refusalSignature?: "verified" | "invalid" | "signature_unverified";
  /** Set for an artifact member that carries its signed response. */
  readonly responseSignature?: "verified" | "invalid" | "signature_unverified";
  /** Set for a carried History member (-03 "History Members"). */
  readonly history?: HistoryMemberResult;
}

/**
 * A carried History member's checks (-03 "History Members"): the envelope
 * signature, the artifact, request and artifact-anchor digests, and the
 * anchor checkpoint (`mismatch` when its digest is not `anchor.digest`).
 * `key` and `time` are its join view, set only when every check passed.
 */
export interface HistoryMemberResult {
  readonly derivation: unknown;
  readonly envelopeSignature: "verified" | "invalid" | "signature_unverified";
  readonly artifactDigest: "matches" | "mismatch";
  readonly requestDigest: "matches" | "mismatch";
  readonly artifactAnchor: "matches" | "mismatch";
  /** `unverified`: no CLL checkpoint verifier is available. */
  readonly anchorCheckpoint: "verified" | "mismatch" | "invalid" | "unverified";
  readonly key?: string;
  readonly time?: string;
}

/**
 * A History's time against a root record's, as facts (-03 "Joins", History
 * times): `relation` is the History's time relative to the record's.
 */
export interface HistoryTimes {
  readonly history: string;
  readonly historyTime: string;
  readonly record: string;
  readonly recordTime: string;
  readonly relation: "before" | "equal" | "after";
}

export interface CompositionClosureResult extends ComposedClaim {
  readonly missing: readonly string[];
}

export type JoinState = "agree" | "mismatch" | "unjoined" | "one_sided";

export interface JoinValue {
  readonly member: string;
  readonly resolved: boolean;
  readonly value?: unknown;
}

export interface JoinDifference {
  readonly pointer: string;
  readonly values: readonly JoinValue[];
}

export interface ComposedJoinResult {
  readonly members: readonly [string, string];
  readonly basis: string;
  readonly declared: JoinState;
  /** Absent when the state is not derivable. */
  readonly derived?: JoinState;
  readonly result: "derived_matches" | "join_state_mismatch" | "not_derivable";
  readonly differences: readonly JoinDifference[];
  /** A same_key join that derives unjoined: each member's key. */
  readonly keys?: readonly { readonly member: string; readonly key: string }[];
  readonly historyTimes?: HistoryTimes;
}

export type RedundancyReason =
  | "same_observer"
  | "same_custody_domain"
  | "same_key_id"
  | "controller_binding"
  | "same_key";

export type CorroborationResult =
  | {
      readonly members: readonly [string, string];
      readonly result: "corroborating";
      readonly qualifier: "custody_declared";
    }
  | {
      readonly members: readonly [string, string];
      readonly result: "redundant";
      readonly reason: RedundancyReason;
      readonly reasons: readonly RedundancyReason[];
      readonly report: "redundant, not corroborating";
    }
  | {
      readonly members: readonly [string, string];
      readonly result: "not_applicable";
    };

export interface ObserverDeclaration {
  readonly id: string;
  readonly role: string;
  readonly custodyDomain: string;
}

/**
 * The verification of one composed/v1 block. `status` is the block's own
 * result; member bundles' claims are reported on each member and do not
 * enter it. A malformed block reports nothing else.
 */
export type ComposedResult =
  | {
      readonly status: "fail";
      readonly malformed: true;
      readonly findings: readonly string[];
    }
  | {
      readonly status: ComposedStatus;
      readonly malformed: false;
      readonly findings: readonly string[];
      readonly composedDigest: ComposedDigestResult;
      readonly members: readonly ComposedMemberResult[];
      /** As declared, in block order (the block's own declaration, reported). */
      readonly observers: readonly ObserverDeclaration[];
      readonly compositionClosure: CompositionClosureResult;
      readonly joins: readonly ComposedJoinResult[];
      readonly corroboration: readonly CorroborationResult[];
    };

/** Verifies a carried member bundle (the containing verifier, recursively). */
export type MemberBundleVerifier = (
  bundle: Record<string, unknown>,
) => Promise<{
  readonly bundleDigest?: string;
  readonly graphClosure: ComposedClaim;
  readonly intervalCoverage: ComposedClaim;
  readonly perRecordMembership: ComposedClaim;
  readonly history?: { readonly state: "none"; readonly since: string | null };
  /** The signer and time of an empty-history-shaped Bundle's checkpoint. */
  readonly emptyHistoryCheckpoint?: {
    readonly keyId: string;
    readonly timestamp: string;
  };
}>;

type Obj = Record<string, unknown>;
const object = (value: unknown): value is Obj =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const isString = (value: unknown): value is string => typeof value === "string";

// go/bundle/composed.go:137
const LABEL = /^[A-Za-z0-9._:-]{1,128}$/u;
const isLabel = (value: unknown): value is string =>
  isString(value) && LABEL.test(value);

// go/bundle/composed.go:140-142
const OUTCOME_BODY: Readonly<Record<string, string>> = {
  artifact: "bundle",
  refusal: "refusal",
  absence: "absence",
};
/** Every member body name; an artifact member carries `bundle` or `history`. */
const BODY_KEYS = ["bundle", "history", "refusal", "absence"];
const JOIN_BASES = new Set([
  "pre_agreed_identifier",
  "shared_artifact_digest",
  "issued_receipt",
  "same_interval",
  "controller_binding",
  "same_key",
]);
/** The bases that derive with a History member (-03 "Joins"). */
const HISTORY_BASES = new Set(["controller_binding", "same_key"]);
/** The envelope profiles whose member names and signature -03 reads. */
const HISTORY_PROFILES = new Set([
  "evidence-interop/0",
  "evidence-interop/1",
  "evidence-interop/2",
]);
/** The evidence-interop envelope's signed members (IP §6.2), when present. */
const ENVELOPE_SIGNED = [
  "profile",
  "request_digest",
  "subject",
  "derivation",
  "anchor",
  "artifact_digest",
  "verification",
  "responder",
  "issued_at",
];
const JOIN_STATES = new Set(["agree", "mismatch", "unjoined", "one_sided"]);

interface Member {
  readonly id: string;
  readonly observer: string;
  readonly requestDigest: string;
  readonly outcome: "artifact" | "refusal" | "absence";
  readonly digest: string;
  readonly body?: Obj;
  /** An artifact member's signed response envelope, without the artifact. */
  readonly response?: Obj;
  /** The carried body is a History (`history`), not a Bundle. */
  readonly history?: boolean;
}
interface Join {
  readonly members: readonly [string, string];
  readonly basis: string;
  readonly state: JoinState;
  readonly pointer?: string;
  readonly identifier?: string;
  readonly compare: readonly string[];
  readonly compareCarried: boolean;
}
interface Block {
  readonly members: readonly Member[];
  readonly observers: readonly ObserverDeclaration[];
  readonly joins: readonly Join[];
  readonly notRequested: readonly string[];
  readonly missing: readonly string[];
  readonly digest: string;
}

type Parsed<T> = { ok: true; value: T } | { ok: false; reason: string };
const ok = <T>(value: T): Parsed<T> => ({ ok: true, value });
const bad = <T>(reason: string): Parsed<T> => ({ ok: false, reason });

// go/bundle/composed.go:792-807
function validPointer(pointer: string): boolean {
  if (pointer === "") return true;
  if (pointer[0] !== "/") return false;
  for (let i = 0; i < pointer.length; i++)
    if (
      pointer[i] === "~" &&
      (i + 1 >= pointer.length ||
        (pointer[i + 1] !== "0" && pointer[i + 1] !== "1"))
    )
      return false;
  return true;
}

// go/bundle/composed.go:809-842
function resolvePointer(
  document: unknown,
  pointer: string,
): { ok: true; value: unknown } | { ok: false } {
  if (!validPointer(pointer)) return { ok: false };
  if (pointer === "") return { ok: true, value: document };
  let current = document;
  for (const raw of pointer.slice(1).split("/")) {
    const token = raw.replaceAll("~1", "/").replaceAll("~0", "~");
    if (Array.isArray(current)) {
      if (!/^(0|[1-9][0-9]*)$/u.test(token)) return { ok: false };
      const index = Number(token);
      if (index >= current.length) return { ok: false };
      current = current[index];
    } else if (object(current)) {
      if (!Object.hasOwn(current, token)) return { ok: false };
      current = current[token];
    } else return { ok: false };
  }
  return { ok: true, value: current };
}

// go/bundle/composed.go:742-767
function optionalArray(value: Obj, key: string): unknown[] | undefined | null {
  if (!Object.hasOwn(value, key)) return undefined;
  const raw = value[key];
  return Array.isArray(raw) ? raw : null;
}
function labelArray(value: Obj, key: string): Parsed<string[]> {
  const list = optionalArray(value, key);
  if (list === null) return bad(key);
  const labels: string[] = [];
  for (const raw of list ?? []) {
    if (!isLabel(raw)) return bad(key);
    labels.push(raw);
  }
  return ok(labels);
}

// go/bundle/composed.go:618-680
function parseMember(
  raw: unknown,
  observers: ReadonlySet<string>,
): Parsed<Member> {
  if (!object(raw)) return bad("not_an_object");
  const { id, observer, request_digest: requestDigest, outcome, digest } = raw;
  if (!isLabel(id)) return bad("id");
  if (!isLabel(observer)) return bad("observer");
  if (!observers.has(observer)) return bad("observer_undeclared");
  if (!isHex64(requestDigest)) return bad("request_digest");
  if (!isHex64(digest)) return bad("digest");
  if (!isString(outcome) || !Object.hasOwn(OUTCOME_BODY, outcome))
    return bad("outcome");
  let bodyKey = OUTCOME_BODY[outcome]!;
  if (outcome === "artifact" && Object.hasOwn(raw, "history")) {
    if (Object.hasOwn(raw, "bundle")) return bad("artifact_body_conflict");
    bodyKey = "history";
  }
  // A body under another outcome's member name would convert one outcome
  // into another; the outcomes are never converted.
  for (const other of BODY_KEYS)
    if (other !== bodyKey && Object.hasOwn(raw, other))
      return bad("body_outcome_conflict");
  // The envelope is the History's response, and it is digest-covered; a
  // response member beside it is not.
  if (Object.hasOwn(raw, "response") && bodyKey === "history")
    return bad("history_response");
  let response: Obj | undefined;
  if (Object.hasOwn(raw, "response")) {
    const value = raw.response;
    if (
      outcome !== "artifact" ||
      !object(value) ||
      !isHex64(value.request_digest) ||
      !isHex64(value.artifact_digest)
    )
      return bad("response");
    response = value;
  }
  const member = {
    id,
    observer,
    requestDigest,
    outcome: outcome as Member["outcome"],
    digest,
    ...(response === undefined ? {} : { response }),
  };
  if (!Object.hasOwn(raw, bodyKey)) return ok(member);
  const body = raw[bodyKey];
  if (!object(body)) return bad("body");
  if (outcome === "refusal") {
    if (
      !isHex64(body.request_digest) ||
      !isString(body.reason) ||
      !isString(body.issued_at)
    )
      return bad("refusal_body");
  } else if (bodyKey === "history") {
    if (!historyShape(body)) return bad("history_body");
    return ok({ ...member, body, history: true });
  } else if (outcome === "absence") {
    const window = body.window;
    if (
      !isHex64(body.request_digest) ||
      !object(window) ||
      !isString(window.from) ||
      !isString(window.to)
    )
      return bad("absence_body");
    if (Object.hasOwn(body, "route") && !isString(body.route))
      return bad("absence_body");
    if (Object.hasOwn(body, "commitment") && !isHex64(body.commitment))
      return bad("absence_body");
  }
  return ok({ ...member, body });
}

/**
 * The `history` body's form (-03 "History Members"); a body outside it makes
 * the block malformed.
 */
function historyShape(body: Obj): boolean {
  const env = body.envelope;
  if (!object(env)) return false;
  const subject = env.subject;
  const anchor = env.anchor;
  return (
    object(subject) &&
    Object.keys(subject).length === 1 &&
    Object.hasOwn(subject, "full_history") &&
    subject.full_history === null &&
    Object.hasOwn(env, "derivation") &&
    isHex64(env.responder) &&
    isString(env.sig) &&
    decodeCose(env.artifact) !== undefined &&
    isHex64(env.artifact_digest) &&
    isHex64(env.request_digest) &&
    object(anchor) &&
    isHex64(anchor.digest) &&
    decodeCose(body.anchor_checkpoint) !== undefined
  );
}

// go/bundle/composed.go:682-740
function parseJoin(raw: unknown, members: ReadonlySet<string>): Parsed<Join> {
  if (!object(raw)) return bad("not_an_object");
  const pair = raw.members;
  if (!Array.isArray(pair) || pair.length !== 2) return bad("members");
  for (const id of pair)
    if (!isLabel(id) || !members.has(id)) return bad("members");
  const [first, second] = pair as [string, string];
  if (!(first < second)) return bad("members_order");
  const { basis, state } = raw;
  if (!isString(basis) || !JOIN_BASES.has(basis)) return bad("basis");
  if (!isString(state) || !JOIN_STATES.has(state)) return bad("state");
  let pointer: string | undefined;
  if (Object.hasOwn(raw, "pointer")) {
    if (!isString(raw.pointer) || !validPointer(raw.pointer))
      return bad("pointer");
    pointer = raw.pointer;
  }
  let identifier: string | undefined;
  if (Object.hasOwn(raw, "identifier_digest")) {
    if (!isHex64(raw.identifier_digest)) return bad("identifier_digest");
    identifier = raw.identifier_digest;
  }
  const compare: string[] = [];
  let compareCarried = false;
  if (Object.hasOwn(raw, "compare")) {
    const list = raw.compare;
    if (!Array.isArray(list) || list.length === 0) return bad("compare");
    for (const item of list) {
      if (!isString(item) || !validPointer(item)) return bad("compare");
      compare.push(item);
    }
    compareCarried = true;
  }
  // same_key reads each member's own key: nothing to select or compare.
  if (
    basis === "same_key" &&
    (pointer !== undefined || identifier !== undefined || compareCarried)
  )
    return bad("same_key_members");
  return ok({
    members: [first, second],
    basis,
    state: state as JoinState,
    ...(pointer === undefined ? {} : { pointer }),
    ...(identifier === undefined ? {} : { identifier }),
    compare,
    compareCarried,
  });
}

// go/bundle/composed.go joinKey: a join without pointer sorts before every
// join with one (so before pointer ""), and distinct joins have distinct keys.
const joinKey = (j: Join): string => {
  const key = `${j.members[0]}\u0000${j.members[1]}\u0000${j.basis}`;
  return j.pointer === undefined ? key : `${key}\u0000${j.pointer}`;
};

// go/bundle/composed.go:533-616
function parseComposed(raw: unknown): Parsed<Block> {
  if (!object(raw)) return bad("not_an_object");
  const digest = raw.composed_digest;
  if (!isHex64(digest)) return bad("composed_digest");

  const observerList = raw.observers;
  if (!Array.isArray(observerList) || observerList.length === 0)
    return bad("observers");
  const observerIds = new Set<string>();
  const observers: ObserverDeclaration[] = [];
  for (const [i, o] of observerList.entries()) {
    if (
      !object(o) ||
      !isLabel(o.id) ||
      !isString(o.role) ||
      !isString(o.custody_domain)
    )
      return bad(`observer:${i}`);
    if (observerIds.has(o.id)) return bad(`observer_id_duplicate:${o.id}`);
    observerIds.add(o.id);
    observers.push({ id: o.id, role: o.role, custodyDomain: o.custody_domain });
  }

  const memberList = raw.members;
  if (!Array.isArray(memberList) || memberList.length === 0)
    return bad("members");
  const memberIds = new Set<string>();
  const members: Member[] = [];
  for (const [i, rawMember] of memberList.entries()) {
    const parsed = parseMember(rawMember, observerIds);
    if (!parsed.ok) return bad(`member:${i}:${parsed.reason}`);
    if (memberIds.has(parsed.value.id))
      return bad(`member_id_duplicate:${parsed.value.id}`);
    memberIds.add(parsed.value.id);
    members.push(parsed.value);
  }

  const joinList = optionalArray(raw, "joins");
  if (joinList === null) return bad("joins");
  const seen = new Set<string>();
  const joins: Join[] = [];
  for (const [i, rawJoin] of (joinList ?? []).entries()) {
    const parsed = parseJoin(rawJoin, memberIds);
    if (!parsed.ok) return bad(`join:${i}:${parsed.reason}`);
    const key = joinKey(parsed.value);
    if (seen.has(key)) return bad(`join_duplicate:${i}`);
    seen.add(key);
    joins.push(parsed.value);
  }

  const notRequested = labelArray(raw, "not_requested");
  if (!notRequested.ok) return notRequested;
  for (const id of notRequested.value)
    if (memberIds.has(id)) return bad(`not_requested_is_member:${id}`);
  const missing = labelArray(raw, "missing");
  if (!missing.ok) return missing;
  return ok({
    members,
    observers,
    joins,
    notRequested: notRequested.value,
    missing: missing.value,
    digest,
  });
}

/**
 * The reason a composed/v1 block is malformed under the draft's block rules,
 * or undefined when it is well formed. A malformed block yields no
 * composition result.
 */
export function composedBlockProblem(raw: unknown): string | undefined {
  const parsed = parseComposed(raw);
  return parsed.ok ? undefined : parsed.reason;
}

// Go sorts with `<` on strings, which is UTF-8 octet order; JavaScript's `<`
// is UTF-16 code-unit order. Labels are ASCII, but a join pointer need not be.
const utf8 = new TextEncoder();
function octetCompare(a: string, b: string): number {
  const x = utf8.encode(a);
  const y = utf8.encode(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++)
    if (x[i] !== y[i]) return x[i]! - y[i]!;
  return x.length - y.length;
}

/**
 * The UTF-8 JCS bytes of the composed digest input D = {kind, members,
 * observers, joins, not_requested} (go/bundle/composed.go:461-516). Member
 * bodies, `missing` and `composed_digest` are excluded. Throws on a
 * malformed block.
 */
export function composedDigestPreimage(raw: unknown): Uint8Array {
  const parsed = parseComposed(raw);
  if (!parsed.ok)
    throw new TypeError(`composed/v1 block malformed: ${parsed.reason}`);
  const block = parsed.value;
  const byId = <T extends { readonly id: string }>(items: readonly T[]) =>
    [...items].sort((a, b) => octetCompare(a.id, b.id));
  return jcs({
    kind: COMPOSED_KIND,
    members: byId(block.members).map((m) => ({
      id: m.id,
      observer: m.observer,
      request_digest: m.requestDigest,
      outcome: m.outcome,
      digest: m.digest,
    })),
    observers: byId(block.observers).map((o) => ({
      id: o.id,
      role: o.role,
      custody_domain: o.custodyDomain,
    })),
    joins: [...block.joins]
      .sort((a, b) => octetCompare(joinKey(a), joinKey(b)))
      .map((j) => ({
        members: [j.members[0], j.members[1]],
        basis: j.basis,
        state: j.state,
        ...(j.pointer === undefined ? {} : { pointer: j.pointer }),
        ...(j.identifier === undefined
          ? {}
          : { identifier_digest: j.identifier }),
        ...(j.compareCarried ? { compare: [...j.compare] } : {}),
      })),
    not_requested: [...block.notRequested].sort(octetCompare),
  });
}

/** Recompute a composed/v1 block's composed digest from its declarations alone. */
export async function composedDigest(raw: unknown): Promise<string> {
  return sha256Hex(composedDigestPreimage(raw));
}

// go/bundle/composed.go:315-330
function rootRecord(m: Member | undefined): Obj | undefined {
  if (m?.body === undefined || m.history === true) return undefined;
  const root = m.body.root;
  if (!isString(root)) return undefined;
  const records = m.body.records;
  if (!Array.isArray(records)) return undefined;
  for (const record of records)
    if (object(record) && record.capsule_id === root) return record;
  return undefined;
}

function sameJcs(a: unknown, b: unknown): boolean {
  try {
    const x = jcs(a);
    const y = jcs(b);
    return x.length === y.length && x.every((byte, i) => byte === y[i]);
  } catch {
    return false;
  }
}

// go/bundle/composed.go:408-416
async function identifierMatches(
  record: Obj,
  pointer: string,
  digest: string,
): Promise<boolean> {
  const value = resolvePointer(record, pointer);
  if (!value.ok || !isString(value.value)) return false;
  return (await sha256Hex(utf8.encode(value.value))) === digest;
}

/** The signer and time of an empty-history member's checkpoint. */
type EmptyCheckpoint = {
  readonly keyId: string;
  readonly timestamp: string;
};

/**
 * Whether a carried Bundle has the shape of an empty-history Bundle: an empty
 * `records` list and no `root` (bundle.ts `emptyHistory`).
 */
const isEmptyHistory = (body: Obj): boolean =>
  Array.isArray(body.records) &&
  body.records.length === 0 &&
  !Object.hasOwn(body, "root");

/** One member's side of a controller_binding join. */
interface BindingSide {
  readonly key: string | undefined;
  readonly at: Instant | undefined;
}

/** A root record's side: the key identifier `pointer` selects, and its timestamp. */
function recordSide(record: Obj, pointer: string): BindingSide {
  const resolved = resolvePointer(record, pointer);
  return {
    key: resolved.ok && isString(resolved.value) ? resolved.value : undefined,
    at: parseRecordTime(record.timestamp),
  };
}

/**
 * Both bound keys are Ed25519 keys: `key_types` is absent, or names ed25519
 * twice. -02 defines no other key type, so a record under one is skipped like
 * a record under an unimplemented method.
 */
function ed25519Keys(record: Obj): boolean {
  if (!Object.hasOwn(record, "key_types")) return true;
  const types = record.key_types;
  return (
    Array.isArray(types) &&
    types.length === 2 &&
    types[0] === "ed25519" &&
    types[1] === "ed25519"
  );
}

/**
 * Whether the record's method and key types are ones this verifier
 * implements: a method -02 defines for the record's claim, and ed25519 keys.
 */
function implemented(record: Obj): boolean {
  const want =
    record.claim === "same_organization_credentialed"
      ? "dual_signature_credential/0"
      : "dual_signature/0";
  return record.method === want && ed25519Keys(record);
}

const SIGNATURE_HEX = /^[0-9a-f]{128}$/u;

/**
 * Verify one delivered record through the one binding verifier,
 * `controller-binding.ts`, at the given times. Returns the verifier's report
 * and whether the record is well formed as -02 states it.
 *
 * -02 differs from Controller Binding v0 in two places, both applied here and
 * nowhere else: an empty nonce is malformed, and a key type other than
 * ed25519 is well formed without CB v0's rule for it (the 32-character bip340
 * nonce), because -02 does not define that type.
 */
async function bindingReport(
  record: Obj,
  times: readonly Instant[],
  statements: readonly Uint8Array[],
): Promise<{ report?: BindingReport; wellFormed: boolean }> {
  let octets: Uint8Array;
  try {
    octets = jcs(record);
  } catch {
    // The digest matched, so only sigs can be unserializable (a float or an
    // integer beyond 2^53 where a sig-hex belongs): malformed under ed25519
    // keys, which -02 holds to sig-hex, and merely not implemented under any
    // other.
    const types = record.key_types;
    const shaped =
      !Object.hasOwn(record, "key_types") ||
      (Array.isArray(types) &&
        types.length === 2 &&
        isString(types[0]) &&
        isString(types[1]));
    if (!shaped || ed25519Keys(record)) return { wellFormed: false };
    // Not implemented, but still held to -02's form: read it with each sig
    // replaced by a string, which no other rule looks at.
    const standin: Obj = { ...record };
    if (Array.isArray(record.sigs))
      standin.sigs = record.sigs.map((e: unknown) =>
        object(e) && Object.hasOwn(e, "sig") ? { ...e, sig: "" } : e,
      );
    try {
      jcs(standin);
    } catch {
      return { wellFormed: false };
    }
    return bindingReport(standin, times, statements);
  }
  const report = await verifyBinding(octets, times, {
    revocations: statements,
  });
  if (Object.hasOwn(record, "key_types")) {
    const list = record.key_types;
    if (
      !Array.isArray(list) ||
      list.length !== 2 ||
      !isString(list[0]) ||
      !isString(list[1])
    )
      return { report, wellFormed: false };
  }
  if (!isString(record.nonce) || record.nonce === "")
    return { report, wellFormed: false };
  // Under ed25519 keys a sig is a sig-hex; -02 makes a record that fails this
  // malformed, where CB v0 reads it as a signature that does not verify.
  if (Array.isArray(record.sigs) && ed25519Keys(record))
    for (const entry of record.sigs)
      if (
        !object(entry) ||
        !isString(entry.sig) ||
        !SIGNATURE_HEX.test(entry.sig)
      )
        return { report, wellFormed: false };
  let formReport = report;
  if (!ed25519Keys(record)) {
    const subject: Obj = { ...record };
    delete subject.key_types;
    try {
      formReport = await verifyBinding(jcs(subject), [], {});
    } catch {
      return { report, wellFormed: false };
    }
  }
  return {
    report,
    wellFormed: formReport.properties[PROPERTY_FORM] === STATUS_PASS,
  };
}

/**
 * -02's binding digest: SHA-256 of the JCS of the record without `sigs`. A
 * join names its record by it, so a record with another digest is skipped
 * before any signature is checked.
 */
async function bindingDigest(
  record: Record<string, unknown>,
): Promise<string | undefined> {
  const { sigs: _sigs, ...rest } = record;
  try {
    return await sha256Hex(jcs(rest));
  } catch {
    return undefined;
  }
}

/**
 * The linkage of a controller_binding join between two sides. `derivable` is
 * false when no delivered binding record has the join's identifier_digest, or
 * when every one that does names a method or key type this verifier does not
 * implement. Otherwise `linked` is true when one such record applies: well
 * formed, signed by both bound keys, its keys exactly the two values
 * `pointer` selects, in effect at both timestamps, and revoked by no
 * delivered statement at or before either. The record checks are
 * `controller-binding.ts`'s; only the join's reading of its report is here.
 */
async function controllerBindingLink(
  j: Join,
  a: BindingSide,
  b: BindingSide,
  options: ComposedOptions,
): Promise<{ linked: boolean; derivable: boolean }> {
  if (j.identifier === undefined) return { linked: false, derivable: false };
  const times = a.at !== undefined && b.at !== undefined ? [a.at, b.at] : [];
  const statements: Uint8Array[] = [];
  for (const statement of options.bindingRevocations ?? [])
    try {
      statements.push(jcs(statement));
    } catch {
      /* a statement that cannot be serialized applies to nothing */
    }
  let derivable = false;
  for (const record of options.controllerBindings ?? []) {
    if (!object(record)) continue;
    if ((await bindingDigest(record)) !== j.identifier) continue;
    const { report, wellFormed } = await bindingReport(
      record,
      times,
      statements,
    );
    if (!wellFormed) {
      // A malformed record does not apply: the join derives, unjoined.
      derivable = true;
      continue;
    }
    if (!implemented(record)) continue;
    derivable = true;
    if (
      report !== undefined &&
      a.key !== undefined &&
      b.key !== undefined &&
      bindingAppliesTo(report, a.key, b.key)
    )
      return { linked: true, derivable: true };
  }
  return { linked: false, derivable };
}

/** A History member's join view: its responder key and anchor time. */
interface HistoryView {
  readonly key: string;
  readonly at: Instant;
  readonly time: string;
}

type Derived = {
  derived?: JoinState;
  differences: JoinDifference[];
  keys?: { member: string; key: string }[];
};

/**
 * A root record's same_key side: its `key_id` when its producer signature
 * verifies under that key, never a key it merely names; undefined for a
 * record that is unsigned or whose signature does not verify.
 */
async function signerSide(record: Obj): Promise<BindingSide | undefined> {
  const { verdict } = await verifyRecordSignature(record);
  const key = record.key_id;
  if (verdict !== "authored" || !isString(key)) return undefined;
  return { key, at: parseRecordTime(record.timestamp) };
}

/**
 * Each member's side of a controller_binding or same_key join, or undefined
 * when one has none (not derivable). A History member's side is its join
 * view; an empty-history Bundle's is its signed checkpoint's key and time; a
 * member Bundle with records gives, under controller_binding, the key
 * `pointer` selects in its root record and, under same_key, the key its root
 * record's producer signature verifies under.
 */
async function keySides(
  j: Join,
  members: readonly Member[],
  views: ReadonlyMap<string, HistoryView>,
  checkpoints: ReadonlyMap<string, EmptyCheckpoint>,
): Promise<BindingSide[] | undefined> {
  const sides: BindingSide[] = [];
  for (const m of members) {
    if (m.body === undefined) return undefined;
    if (m.history === true) {
      const view = views.get(m.id)!;
      sides.push({ key: view.key, at: view.at });
    } else if (isEmptyHistory(m.body)) {
      const checkpoint = checkpoints.get(m.id);
      if (checkpoint === undefined) return undefined;
      sides.push({
        key: checkpoint.keyId,
        at: parseRecordTime(checkpoint.timestamp),
      });
    } else {
      const record = rootRecord(m);
      if (record === undefined) return undefined;
      if (j.basis === "same_key") {
        const side = await signerSide(record);
        if (side === undefined) return undefined;
        sides.push(side);
      } else {
        if (j.pointer === undefined) return undefined;
        sides.push(recordSide(record, j.pointer));
      }
    }
  }
  return sides;
}

/**
 * Each member's key, in the join's member order, for a same_key join that
 * derives unjoined.
 */
function joinKeys(
  j: Join,
  members: readonly Member[],
  sides: readonly BindingSide[],
): { keys?: { member: string; key: string }[] } {
  if (j.basis !== "same_key") return {};
  const byMember = new Map(members.map((m, i) => [m.id, sides[i]!.key!]));
  return {
    keys: j.members.map((member) => ({ member, key: byMember.get(member)! })),
  };
}

/** `{linked, derivable}` for a controller_binding or same_key join. */
async function keyedLink(
  j: Join,
  a: BindingSide,
  b: BindingSide,
  options: ComposedOptions,
): Promise<{ linked: boolean; derivable: boolean }> {
  if (j.basis === "same_key")
    return {
      linked: a.key !== undefined && b.key !== undefined && a.key === b.key,
      derivable: true,
    };
  return controllerBindingLink(j, a, b, options);
}

// go/bundle/composed.go:346-406, with -02's controller_binding basis and
// empty-history members, and -03's History members and same_key basis.
async function derivedState(
  j: Join,
  byId: ReadonlyMap<string, Member>,
  missing: ReadonlySet<string>,
  checkpoints: ReadonlyMap<string, EmptyCheckpoint>,
  views: ReadonlyMap<string, HistoryView>,
  options: ComposedOptions,
): Promise<Derived> {
  const a = byId.get(j.members[0])!;
  const b = byId.get(j.members[1])!;
  // A join with a declared-missing artifact member (listed in missing and
  // carrying no body) is not derivable, whatever its other member is.
  if (
    [a, b].some(
      (m) =>
        m.outcome === "artifact" && missing.has(m.id) && m.body === undefined,
    )
  )
    return { differences: [] };
  // A History member derives only through its join view, and only on the
  // bases -03 defines a derivation for with one.
  const histories = [a, b].filter((m) => m.history === true);
  if (
    histories.length > 0 &&
    (!HISTORY_BASES.has(j.basis) || histories.some((m) => !views.has(m.id)))
  )
    return { differences: [] };
  // An artifact member counts as having records unless its carried Bundle is
  // an empty-history Bundle, which shows no history. A History member with a
  // join view counts as having records.
  const withRecords: Member[] = [];
  const empty: Member[] = [];
  for (const m of [a, b]) {
    if (m.outcome !== "artifact") continue;
    if (m.history !== true && m.body !== undefined && isEmptyHistory(m.body))
      empty.push(m);
    else withRecords.push(m);
  }
  const keyed = HISTORY_BASES.has(j.basis);
  if (withRecords.length === 0) return { derived: "unjoined", differences: [] };
  if (withRecords.length === 1) {
    if (empty.length === 0 || !keyed)
      return { derived: "one_sided", differences: [] };
    // controller_binding and same_key still derive against an empty-history
    // member, from the key that signed its checkpoint at that time.
    const sides = await keySides(
      j,
      [withRecords[0]!, empty[0]!],
      views,
      checkpoints,
    );
    if (sides === undefined) return { differences: [] };
    const { linked, derivable } = await keyedLink(
      j,
      sides[0]!,
      sides[1]!,
      options,
    );
    if (!derivable) return { differences: [] };
    if (linked) return { derived: "one_sided", differences: [] };
    return {
      derived: "unjoined",
      differences: [],
      ...joinKeys(j, [withRecords[0]!, empty[0]!], sides),
    };
  }
  if (keyed) {
    const sides = await keySides(j, [a, b], views, checkpoints);
    if (sides === undefined) return { differences: [] };
    const { linked, derivable } = await keyedLink(
      j,
      sides[0]!,
      sides[1]!,
      options,
    );
    if (!derivable) return { differences: [] };
    if (!linked)
      return {
        derived: "unjoined",
        differences: [],
        ...joinKeys(j, [a, b], sides),
      };
  } else {
    const ra = rootRecord(a);
    const rb = rootRecord(b);
    if (ra === undefined || rb === undefined) return { differences: [] };
    let linked: boolean;
    if (j.basis === "pre_agreed_identifier") {
      linked =
        j.pointer !== undefined &&
        j.identifier !== undefined &&
        (await identifierMatches(ra, j.pointer, j.identifier)) &&
        (await identifierMatches(rb, j.pointer, j.identifier));
    } else if (j.basis === "shared_artifact_digest") {
      linked = false;
      if (j.pointer !== undefined) {
        const va = resolvePointer(ra, j.pointer);
        const vb = resolvePointer(rb, j.pointer);
        linked =
          va.ok &&
          vb.ok &&
          isString(va.value) &&
          isString(vb.value) &&
          va.value === vb.value;
      }
    } else {
      // issued_receipt and same_interval are reserved: not derivable here.
      return { differences: [] };
    }
    if (!linked) return { derived: "unjoined", differences: [] };
  }
  const differences: JoinDifference[] = [];
  // A History member has no root record: no compare pointer resolves in it.
  const resolveIn = (m: Member, pointer: string) => {
    const record = rootRecord(m);
    return record === undefined
      ? ({ ok: false } as const)
      : resolvePointer(record, pointer);
  };
  for (const pointer of j.compare) {
    const va = resolveIn(a, pointer);
    const vb = resolveIn(b, pointer);
    if (va.ok && vb.ok && sameJcs(va.value, vb.value)) continue;
    differences.push({
      pointer,
      values: [
        va.ok
          ? { member: a.id, resolved: true, value: va.value }
          : { member: a.id, resolved: false },
        vb.ok
          ? { member: b.id, resolved: true, value: vb.value }
          : { member: b.id, resolved: false },
      ],
    });
  }
  return differences.length > 0
    ? { derived: "mismatch", differences }
    : { derived: "agree", differences: [] };
}

/**
 * For a join between a History member with a join view and a member with a
 * root record: both times and how they compare, as facts.
 */
function historyTimes(
  j: Join,
  byId: ReadonlyMap<string, Member>,
  views: ReadonlyMap<string, HistoryView>,
): HistoryTimes | undefined {
  const a = byId.get(j.members[0])!;
  const b = byId.get(j.members[1])!;
  for (const [history, other] of [
    [a, b],
    [b, a],
  ] as const) {
    const view = views.get(history.id);
    if (view === undefined) continue;
    const record = rootRecord(other);
    if (record === undefined) return undefined;
    const stated = record.timestamp;
    const at = parseRecordTime(stated);
    if (at === undefined || !isString(stated)) return undefined;
    return {
      history: history.id,
      historyTime: view.time,
      record: other.id,
      recordTime: stated,
      relation: view.at < at ? "before" : view.at > at ? "after" : "equal",
    };
  }
  return undefined;
}

// go/bundle/composed.go:418-445
function corroboration(
  j: Join,
  derived: JoinState | undefined,
  byId: ReadonlyMap<string, Member>,
  observers: ReadonlyMap<string, ObserverDeclaration>,
): CorroborationResult {
  if (derived !== "agree")
    return { members: j.members, result: "not_applicable" };
  const a = byId.get(j.members[0])!;
  const b = byId.get(j.members[1])!;
  const reasons: RedundancyReason[] = [];
  if (a.observer === b.observer) reasons.push("same_observer");
  if (
    observers.get(a.observer)?.custodyDomain ===
    observers.get(b.observer)?.custodyDomain
  )
    reasons.push("same_custody_domain");
  const keyA = rootRecord(a)?.key_id;
  const keyB = rootRecord(b)?.key_id;
  if (isString(keyA) && isString(keyB) && keyA === keyB)
    reasons.push("same_key_id");
  // A controller_binding agreement is the bound keys' holders agreeing: their
  // keys are not independent issuers (bundle -02).
  if (j.basis === "controller_binding") reasons.push("controller_binding");
  // A same_key agreement is one key signing or answering for both members.
  if (j.basis === "same_key") reasons.push("same_key");
  if (reasons.length > 0)
    return {
      members: j.members,
      result: "redundant",
      reason: reasons[0]!,
      reasons,
      report: "redundant, not corroborating",
    };
  return {
    members: j.members,
    result: "corroborating",
    qualifier: "custody_declared",
  };
}

// go/bundle/composed.go:256-312
async function verifyMember(
  m: Member,
  declaredMissing: boolean,
  verifyMemberBundle: MemberBundleVerifier,
  checkpoints: Map<string, EmptyCheckpoint>,
): Promise<{
  member: ComposedMemberResult;
  closure: string[];
  failed: string[];
  withheld: string[];
}> {
  const closure: string[] = [];
  const failed: string[] = [];
  const withheld: string[] = [];
  const findings: string[] = [];
  const base = { id: m.id, observer: m.observer, outcome: m.outcome };
  if (declaredMissing && m.body === undefined)
    return {
      member: {
        ...base,
        body: "declared_missing",
        digest: "not_shown",
        findings,
      },
      closure,
      failed,
      withheld,
    };
  if (m.body === undefined) {
    closure.push(`member_body_absent:${m.id}`);
    findings.push("member_body_absent");
    return {
      member: { ...base, body: "absent", digest: "not_shown", findings },
      closure,
      failed,
      withheld,
    };
  }
  if (declaredMissing) closure.push(`missing_member_carries_body:${m.id}`);

  let computed: string | undefined;
  let bundle: ComposedMemberClaims | undefined;
  let history: HistoryMemberResult | undefined;
  if (m.history === true) {
    const checked = await verifyHistory(m);
    computed = checked.computed;
    history = checked.history;
    findings.push(...checked.findings);
    failed.push(...checked.failed);
    withheld.push(...checked.withheld);
  } else if (m.outcome === "artifact") {
    const verification = await verifyMemberBundle(m.body);
    computed = verification.bundleDigest;
    bundle = {
      graphClosure: verification.graphClosure,
      intervalCoverage: verification.intervalCoverage,
      perRecordMembership: verification.perRecordMembership,
      ...(verification.history === undefined
        ? {}
        : { history: verification.history }),
    };
    if (verification.emptyHistoryCheckpoint !== undefined)
      checkpoints.set(m.id, verification.emptyHistoryCheckpoint);
    // A carried response binds the artifact to the request it answered.
    if (m.response !== undefined) {
      if (m.response.request_digest !== m.requestDigest) {
        findings.push("response_request_digest_mismatch");
        failed.push(`member_response_request_digest_mismatch:${m.id}`);
      }
      if (m.response.artifact_digest !== m.digest) {
        findings.push("response_artifact_digest_mismatch");
        failed.push(`member_response_artifact_digest_mismatch:${m.id}`);
      }
    }
  } else {
    try {
      computed = await jsonDigest(m.body);
    } catch {
      computed = undefined;
    }
    if (m.body.request_digest !== m.requestDigest) {
      findings.push("request_digest_mismatch");
      failed.push(`member_request_digest_mismatch:${m.id}`);
    }
  }
  let digest: ComposedMemberResult["digest"] = "reproduced";
  if (computed === undefined || computed !== m.digest) {
    digest = "mismatch";
    findings.push("member_digest_mismatch");
    closure.push(`member_digest_mismatch:${m.id}`);
    // An envelope that does not reproduce the declared digest is not the
    // History the composed digest names: it has no join view.
    if (history !== undefined) {
      const { key: _key, time: _time, ...rest } = history;
      history = rest;
    }
  }
  let refusalSignature: ComposedMemberResult["refusalSignature"];
  if (m.outcome === "refusal") {
    refusalSignature = "signature_unverified";
    withheld.push(`refusal_signature_unverified:${m.id}`);
  }
  // No deployment signature profile here, as for a refusal.
  let responseSignature: ComposedMemberResult["responseSignature"];
  if (m.response !== undefined) {
    responseSignature = "signature_unverified";
    withheld.push(`response_signature_unverified:${m.id}`);
  }
  return {
    member: {
      ...base,
      body: "carried",
      digest,
      findings,
      ...(bundle === undefined ? {} : { bundle }),
      ...(refusalSignature === undefined ? {} : { refusalSignature }),
      ...(responseSignature === undefined ? {} : { responseSignature }),
      ...(history === undefined ? {} : { history }),
    },
    closure,
    failed,
    withheld,
  };
}

const hexBytes = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../gu) ?? [], (byte) =>
    Number.parseInt(byte, 16),
  );

/**
 * The `anchor` member of an artifact that is the UTF-8 JCS of a JSON object,
 * or undefined when it is not exactly that serialization.
 */
function artifactAnchor(artifact: Uint8Array): unknown {
  try {
    const value: unknown = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(artifact),
    );
    if (!object(value)) return undefined;
    const again = jcs(value);
    if (
      again.length !== artifact.length ||
      !again.every((byte, i) => byte === artifact[i])
    )
      return undefined;
    return value.anchor;
  } catch {
    return undefined;
  }
}

/**
 * An anchor checkpoint's timestamp and state: `verified` when it is a CLL
 * COSE checkpoint in the one form the interop profile fixes (tagged
 * COSE_Sign1, an empty unprotected header) that verifies under its own key;
 * `invalid` otherwise; `unverified` when no CLL verifier is available.
 */
async function checkpointTime(cose: Uint8Array): Promise<{
  timestamp?: string;
  state: "verified" | "invalid" | "unverified";
}> {
  const verify = await loadCheckpointMetadata();
  if (verify === undefined) return { state: "unverified" };
  let outer: CborValue;
  try {
    outer = decodeWellFormedItem(cose, true);
  } catch {
    return { state: "invalid" };
  }
  if (
    !(outer instanceof CborTag) ||
    outer.tag !== 18n ||
    !Array.isArray(outer.value) ||
    outer.value.length !== 4 ||
    !(outer.value[1] instanceof CborMap) ||
    outer.value[1].entries.length !== 0
  )
    return { state: "invalid" };
  const stated = (await signedCheckpointFields(cose, verify))?.timestamp;
  return isString(stated) && parseRecordTime(stated) !== undefined
    ? { timestamp: stated, state: "verified" }
    : { state: "invalid" };
}

/**
 * Check a carried History member (-03 "History Members", checks 1 to 5). The
 * body's shape was checked when the block was parsed.
 */
async function verifyHistory(m: Member): Promise<{
  computed?: string;
  history: HistoryMemberResult;
  findings: string[];
  failed: string[];
  withheld: string[];
}> {
  const body = m.body!;
  const env = body.envelope as Obj;
  const anchorDigest = (env.anchor as Obj).digest as string;
  let computed: string | undefined;
  try {
    computed = await jsonDigest(env);
  } catch {
    computed = undefined;
  }
  let envelopeSignature: HistoryMemberResult["envelopeSignature"] =
    "signature_unverified";
  if (isString(env.profile) && HISTORY_PROFILES.has(env.profile)) {
    const signed: Obj = {};
    for (const name of ENVELOPE_SIGNED)
      if (Object.hasOwn(env, name)) signed[name] = env[name];
    let signingInput: Uint8Array | undefined;
    try {
      signingInput = jcs(signed);
    } catch {
      signingInput = undefined;
    }
    const sig = env.sig as string;
    if (signingInput === undefined || !SIGNATURE_HEX.test(sig))
      envelopeSignature = "invalid";
    else
      try {
        envelopeSignature = (await verifyEd25519Strict(
          hexBytes(env.responder as string),
          hexBytes(sig),
          signingInput,
        ))
          ? "verified"
          : "invalid";
      } catch {
        // Only SubtleCrypto throws here (no Ed25519): the signature is not
        // checked, which is neither failed nor absent.
        envelopeSignature = "signature_unverified";
      }
  }
  const artifact = decodeCose(env.artifact) ?? new Uint8Array();
  const artifactDigest: HistoryMemberResult["artifactDigest"] =
    (await sha256Hex(artifact)) === env.artifact_digest
      ? "matches"
      : "mismatch";
  const requestDigest: HistoryMemberResult["requestDigest"] =
    env.request_digest === m.requestDigest ? "matches" : "mismatch";
  const anchor = artifactAnchor(artifact);
  const artifactAnchorState: HistoryMemberResult["artifactAnchor"] =
    isString(anchor) && anchor === anchorDigest ? "matches" : "mismatch";
  const checkpoint = decodeCose(body.anchor_checkpoint) ?? new Uint8Array();
  let anchorCheckpoint: HistoryMemberResult["anchorCheckpoint"];
  let timestamp: string | undefined;
  if ((await sha256Hex(checkpoint)) !== anchorDigest)
    anchorCheckpoint = "mismatch";
  else
    ({ timestamp, state: anchorCheckpoint } = await checkpointTime(checkpoint));
  const findings: string[] = [];
  const failed: string[] = [];
  const withheld: string[] = [];
  for (const [state, finding] of [
    [envelopeSignature, "history_envelope_signature_invalid"],
    [artifactDigest, "history_artifact_digest_mismatch"],
    [requestDigest, "history_request_digest_mismatch"],
    [artifactAnchorState, "history_artifact_anchor_mismatch"],
    [anchorCheckpoint, `history_anchor_checkpoint_${anchorCheckpoint}`],
  ] as const)
    if (state === "invalid" || state === "mismatch") {
      findings.push(finding);
      failed.push(`${finding}:${m.id}`);
    }
  if (envelopeSignature === "signature_unverified")
    withheld.push(`history_signature_unverified:${m.id}`);
  if (anchorCheckpoint === "unverified")
    withheld.push(`history_anchor_checkpoint_unverified:${m.id}`);
  const view =
    failed.length === 0 && withheld.length === 0 && timestamp !== undefined
      ? { key: env.responder as string, time: timestamp }
      : {};
  return {
    ...(computed === undefined ? {} : { computed }),
    history: {
      derivation: env.derivation,
      envelopeSignature,
      artifactDigest,
      requestDigest,
      artifactAnchor: artifactAnchorState,
      anchorCheckpoint,
      ...view,
    },
    findings,
    failed,
    withheld,
  };
}

function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort(octetCompare);
}

/**
 * Verify a composed/v1 block as carried in a Bundle's extensions
 * (go/bundle/composed.go:170-254). Carried member bundles are verified with
 * `verifyMemberBundle`, the containing verifier.
 */
export async function verifyComposed(
  raw: unknown,
  verifyMemberBundle: MemberBundleVerifier,
  options: ComposedOptions = {},
): Promise<ComposedResult> {
  const parsed = parseComposed(raw);
  if (!parsed.ok)
    return {
      status: "fail",
      malformed: true,
      findings: [`composed_block_malformed:${parsed.reason}`],
    };
  const block = parsed.value;
  const failed: string[] = [];
  const withheld: string[] = [];

  let recomputed = "";
  try {
    recomputed = await composedDigest(raw);
  } catch {
    recomputed = "";
  }
  const composedDigestResult: ComposedDigestResult = {
    declared: block.digest,
    recomputed,
    matches: recomputed !== "" && recomputed === block.digest,
  };
  if (!composedDigestResult.matches) failed.push("composed_digest_mismatch");

  const missing = new Set<string>();
  const declared = new Set(block.members.map((m) => m.id));
  const closureFindings: string[] = [];
  for (const id of block.missing) {
    if (missing.has(id)) closureFindings.push(`missing_duplicate:${id}`);
    missing.add(id);
    if (!declared.has(id))
      closureFindings.push(`missing_names_undeclared_member:${id}`);
  }

  const byId = new Map<string, Member>();
  const checkpoints = new Map<string, EmptyCheckpoint>();
  const views = new Map<string, HistoryView>();
  const members: ComposedMemberResult[] = [];
  for (const m of block.members) {
    byId.set(m.id, m);
    const result = await verifyMember(
      m,
      missing.has(m.id),
      verifyMemberBundle,
      checkpoints,
    );
    members.push(result.member);
    const view = result.member.history;
    if (view?.key !== undefined && view.time !== undefined)
      views.set(m.id, {
        key: view.key,
        at: parseRecordTime(view.time) ?? 0n,
        time: view.time,
      });
    closureFindings.push(...result.closure);
    failed.push(...result.failed);
    withheld.push(...result.withheld);
  }

  let compositionClosure: CompositionClosureResult;
  const closureMissing = sortedUnique(block.missing);
  if (closureFindings.length > 0) {
    compositionClosure = {
      status: "fail",
      findings: closureFindings,
      missing: closureMissing,
    };
    failed.push("composition_closure_fail");
  } else if (block.missing.length > 0) {
    compositionClosure = {
      status: "withheld",
      findings: ["declared_incomplete"],
      missing: closureMissing,
    };
    withheld.push("declared_incomplete");
  } else compositionClosure = { status: "pass", findings: [], missing: [] };

  const observers = new Map(block.observers.map((o) => [o.id, o]));
  const joins: ComposedJoinResult[] = [];
  const corroborations: CorroborationResult[] = [];
  for (const j of block.joins) {
    const { derived, differences, keys } = await derivedState(
      j,
      byId,
      missing,
      checkpoints,
      views,
      options,
    );
    const times = historyTimes(j, byId, views);
    const result: ComposedJoinResult["result"] =
      derived === undefined
        ? "not_derivable"
        : derived === j.state
          ? "derived_matches"
          : "join_state_mismatch";
    joins.push({
      members: j.members,
      basis: j.basis,
      declared: j.state,
      ...(derived === undefined ? {} : { derived }),
      result,
      differences,
      ...(keys === undefined ? {} : { keys }),
      ...(times === undefined ? {} : { historyTimes: times }),
    });
    const pair = `${j.members[0]},${j.members[1]}`;
    if (result === "join_state_mismatch")
      failed.push(`join_state_mismatch:${pair}`);
    else if (result === "not_derivable")
      withheld.push(`join_not_derivable:${pair}`);
    corroborations.push(corroboration(j, derived, byId, observers));
  }

  const status: ComposedStatus =
    failed.length > 0 ? "fail" : withheld.length > 0 ? "withheld" : "pass";
  return {
    status,
    malformed: false,
    findings: status === "fail" ? [...failed, ...withheld] : withheld,
    composedDigest: composedDigestResult,
    members,
    observers: block.observers,
    compositionClosure,
    joins,
    corroboration: corroborations,
  };
}
