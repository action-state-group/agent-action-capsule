import { isHex64, jcs, jsonDigest, sha256Hex } from "./json.js";

/**
 * The `composed/v1` Evidence Bundle extension, verified
 * (draft-mih-zhang-agent-disclosure-bundle-01, "The composed/v1 Extension").
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
}

export type RedundancyReason =
  | "same_observer"
  | "same_custody_domain"
  | "same_key_id";

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
const JOIN_BASES = new Set([
  "pre_agreed_identifier",
  "shared_artifact_digest",
  "issued_receipt",
  "same_interval",
]);
const JOIN_STATES = new Set(["agree", "mismatch", "unjoined", "one_sided"]);

interface Member {
  readonly id: string;
  readonly observer: string;
  readonly requestDigest: string;
  readonly outcome: "artifact" | "refusal" | "absence";
  readonly digest: string;
  readonly body?: Obj;
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
  const bodyKey = OUTCOME_BODY[outcome]!;
  // A body under another outcome's member name would convert one outcome
  // into another; the outcomes are never converted.
  for (const other of Object.values(OUTCOME_BODY))
    if (other !== bodyKey && Object.hasOwn(raw, other))
      return bad("body_outcome_conflict");
  const member = {
    id,
    observer,
    requestDigest,
    outcome: outcome as Member["outcome"],
    digest,
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

// go/bundle/composed.go:518-527
const joinKey = (j: Join): string =>
  `${j.members[0]}\u0000${j.members[1]}\u0000${j.basis}\u0000${j.pointer ?? ""}`;

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
    let key = joinKey(parsed.value);
    if (parsed.value.pointer === undefined) key += "\u0000absent";
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
  if (m?.body === undefined) return undefined;
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

// go/bundle/composed.go:346-406
async function derivedState(
  j: Join,
  byId: ReadonlyMap<string, Member>,
  missing: ReadonlySet<string>,
): Promise<{ derived?: JoinState; differences: JoinDifference[] }> {
  const a = byId.get(j.members[0])!;
  const b = byId.get(j.members[1])!;
  const artifacts = [a, b].filter((m) => m.outcome === "artifact").length;
  if (artifacts === 0) return { derived: "unjoined", differences: [] };
  if (artifacts === 1) return { derived: "one_sided", differences: [] };
  if (missing.has(a.id) || missing.has(b.id)) return { differences: [] };
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
  const differences: JoinDifference[] = [];
  for (const pointer of j.compare) {
    const va = resolvePointer(ra, pointer);
    const vb = resolvePointer(rb, pointer);
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
  if (m.outcome === "artifact") {
    const verification = await verifyMemberBundle(m.body);
    computed = verification.bundleDigest;
    bundle = {
      graphClosure: verification.graphClosure,
      intervalCoverage: verification.intervalCoverage,
      perRecordMembership: verification.perRecordMembership,
    };
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
  }
  let refusalSignature: ComposedMemberResult["refusalSignature"];
  if (m.outcome === "refusal") {
    refusalSignature = "signature_unverified";
    withheld.push(`refusal_signature_unverified:${m.id}`);
  }
  return {
    member: {
      ...base,
      body: "carried",
      digest,
      findings,
      ...(bundle === undefined ? {} : { bundle }),
      ...(refusalSignature === undefined ? {} : { refusalSignature }),
    },
    closure,
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
  const members: ComposedMemberResult[] = [];
  for (const m of block.members) {
    byId.set(m.id, m);
    const result = await verifyMember(m, missing.has(m.id), verifyMemberBundle);
    members.push(result.member);
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
    const { derived, differences } = await derivedState(j, byId, missing);
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
