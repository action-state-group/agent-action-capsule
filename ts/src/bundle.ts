import {
  leafCount,
  rootFromPeaks,
  verifyHexInclusion,
  verifyRange,
  type MmrInclusionProof,
  type MmrRangeProof,
} from "@action-state-group/cll";
import {
  decodeStrictJson,
  isHex64,
  jcs,
  jsonDigest,
  JsonNumber,
  setMember,
  sha256Hex,
  type ParsedJson,
} from "./json.js";
import {
  DISCLOSURE_INELIGIBLE_FIELD,
  DISCLOSURE_MATCH,
  DISCLOSURE_MISMATCH,
  DISCLOSURE_NO_COMMITTED_DIGEST,
} from "./disclosure-envelope.js";
import { resolveDisclosurePath } from "./disclosure-path.js";
import {
  extensionInterpreter,
  type ExtensionInterpreterId,
} from "./extension-interpreters.js";
import {
  COMPOSED_KIND,
  verifyComposed,
  type ComposedResult,
} from "./composed.js";
import { disclosureEligibleFields } from "./registries.js";
import { verifyClass1, type VerificationResult } from "./verify.js";
import type { CountersignerSource } from "./countersignature-stamp.js";
import type {
  DisclosureField,
  DisclosureResolution,
  ObjectValue,
  RecordWithId,
} from "./evidence-graph.js";

export interface ClaimResult {
  readonly status: "pass" | "withheld" | "fail";
  readonly findings: readonly string[];
}
export interface DisclosureResult {
  readonly capsuleId: string;
  readonly member: string;
  readonly status: string;
}
/**
 * One `extensions` member, as this verifier and viewer stand towards it.
 *
 * `integrityCovered` is whether the block is bound into the computed bundle
 * digest: true exactly when `bundleDigest` was computed, because the
 * canonical form it hashes includes `extensions` (Evidence Bundle -01,
 * "Bundle Digest and Countersignatures"). It says the bytes are pinned, never
 * that their meaning is understood or correct.
 *
 * `interpreted` means this library has a module that applies the kind's
 * meaning AND that module's own reader accepts this block; `interpreter`
 * names the module. Every other block -- an unknown kind, a kind with no
 * module here, a block its reader ignores -- is `uninterpreted` and its
 * semantics are never applied (draft "Typed Extensions").
 *
 * A composed/v1 block is verified by this verifier whatever its status (as
 * the Go reference does, go/bundle/bundle.go `extensions`): `composed`
 * carries that verification. `status` says only whether a viewer module
 * applies the block's meaning; a malformed block is `uninterpreted`.
 */
export type ExtensionResult =
  | {
      readonly kind: string;
      readonly status: "interpreted";
      readonly interpreter: ExtensionInterpreterId;
      readonly integrityCovered: boolean;
      /** composed/v1 only: the block's verification (`composed.ts`). */
      readonly composed?: ComposedResult;
    }
  | {
      readonly kind: string;
      readonly status: "uninterpreted";
      readonly integrityCovered: boolean;
      /** composed/v1 only: the block's verification (`composed.ts`). */
      readonly composed?: ComposedResult;
    };
export type { ExtensionInterpreterId } from "./extension-interpreters.js";
export interface CountersignatureResult {
  readonly value: unknown;
  readonly status: "unverified";
}
export interface ProducerSelfReport {
  readonly value: unknown;
  readonly status: "producer_self_report";
}
export interface BundleVerificationResult {
  readonly bundleDigest?: string;
  readonly graphClosure: ClaimResult;
  readonly intervalCoverage: ClaimResult;
  readonly perRecordMembership: ClaimResult;
  readonly disclosures: readonly DisclosureResult[];
  readonly extensions: readonly ExtensionResult[];
  readonly countersignatures: readonly CountersignatureResult[];
  readonly verification?: ProducerSelfReport;
  readonly capsuleResults: Readonly<Record<string, VerificationResult>>;
}
type Bundle = Record<string, unknown>;
type Proof = MmrInclusionProof;
const pass = (): ClaimResult => ({ status: "pass", findings: [] });
const fail = (...findings: string[]): ClaimResult => ({
  status: "fail",
  findings,
});
const object = (value: unknown): value is Bundle =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const integer = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value);
const hex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../gu)!, (byte) => Number.parseInt(byte, 16));

/** Encode a Bundle as unpadded RFC 4648 base64url over UTF-8 JCS bytes. */
export function encodeFragment(bundle: unknown): string {
  return encodeBase64Url(jcs(bundle));
}
/**
 * Decode unpadded base64url, refusing non-zero trailing bits so each byte
 * string has one spelling, as the Go (strict), Python and Rust decoders do.
 */
function base64UrlDecode(value: string): Uint8Array {
  const padded = `${value}${"=".repeat((4 - (value.length % 4)) % 4)}`;
  const binary = atob(padded.replaceAll("-", "+").replaceAll("_", "/"));
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  if (encodeBase64Url(bytes) !== value)
    throw new TypeError("non-canonical base64url");
  return bytes;
}
const encodeBase64Url = (bytes: Uint8Array): string =>
  btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
/**
 * Decode an unpadded Evidence Bundle URL fragment without verifying its claims.
 *
 * Integers spelled as plain decimal within the safe range become numbers. Any
 * other number keeps its spelling as a {@link JsonNumber}, so a float-spelled
 * `2.0` fails the same integer checks it fails in Go, Python and Rust instead
 * of being read as `2`.
 */
export function decodeFragment(fragment: string): unknown {
  if (!/^[A-Za-z0-9_-]*$/u.test(fragment))
    throw new TypeError("fragment base64url");
  try {
    return plainIntegers(
      decodeStrictJson(base64UrlDecode(fragment), { lastDuplicateWins: true }),
    );
  } catch (error) {
    throw new TypeError("fragment UTF-8 JSON");
  }
}
function plainIntegers(value: ParsedJson): unknown {
  if (value instanceof JsonNumber) {
    if (!/^-?(?:0|[1-9]\d*)$/u.test(value.raw)) return value;
    const number = Number(value.raw);
    return Number.isSafeInteger(number) ? number : value;
  }
  if (Array.isArray(value)) return value.map(plainIntegers);
  if (value === null || typeof value !== "object") return value;
  const out: Record<string, unknown> = {};
  for (const [key, member] of Object.entries(value))
    setMember(out, key, plainIntegers(member));
  return out;
}
/** Compute SHA-256(JCS(bundle without countersignatures)). */
export async function bundleDigest(bundle: Bundle): Promise<string> {
  return sha256Hex(
    jcs(
      Object.fromEntries(
        Object.entries(bundle).filter(([key]) => key !== "countersignatures"),
      ),
    ),
  );
}
/** Verify independent Evidence Bundle claims and the disclosure overlay. */
export async function verifyBundle(
  bundle: unknown,
): Promise<BundleVerificationResult> {
  const invalid = fail("bundle_malformed");
  if (!object(bundle))
    return {
      graphClosure: invalid,
      intervalCoverage: invalid,
      perRecordMembership: invalid,
      disclosures: [],
      extensions: [],
      countersignatures: [],
      capsuleResults: {},
    };
  let digest: string | undefined;
  try {
    digest = await bundleDigest(bundle);
  } catch {
    /* claims remain independently reportable */
  }
  const collected = await collectRecords(bundle.records);
  const [intervalCoverage, perRecordMembership] = await completeness(
    bundle,
    collected.records,
  );
  return {
    ...(digest === undefined ? {} : { bundleDigest: digest }),
    graphClosure: graph(bundle, collected.records, collected.findings),
    intervalCoverage,
    perRecordMembership,
    disclosures: await disclosures(
      Object.hasOwn(bundle, "disclosures") ? bundle.disclosures : {},
      collected.records,
    ),
    extensions: await extensions(bundle, digest !== undefined),
    countersignatures: Array.isArray(bundle.countersignatures)
      ? bundle.countersignatures.map((value) => ({
          value,
          status: "unverified",
        }))
      : [],
    ...(Object.hasOwn(bundle, "verification")
      ? {
          verification: {
            value: bundle.verification,
            status: "producer_self_report" as const,
          },
        }
      : {}),
    capsuleResults: collected.results,
  };
}
async function collectRecords(raw: unknown): Promise<{
  records: Map<string, Bundle>;
  results: Record<string, VerificationResult>;
  findings: string[];
}> {
  const records = new Map<string, Bundle>(),
    results: Record<string, VerificationResult> = {},
    findings: string[] = [];
  if (!Array.isArray(raw))
    return { records, results, findings: ["records_malformed"] };
  for (const [index, record] of raw.entries()) {
    if (!object(record)) {
      findings.push(`record_malformed:${index}`);
      continue;
    }
    const id = record.capsule_id;
    if (!isHex64(id)) {
      findings.push(`record_identity_invalid:${index}`);
      continue;
    }
    if (records.has(id)) {
      findings.push(`record_duplicate:${id}`);
      continue;
    }
    const result = await verifyClass1(record as ParsedJson);
    results[id] = result;
    if (!result.ok || result.capsuleId !== id) {
      findings.push(`record_identity_invalid:${id}`);
      continue;
    }
    records.set(id, record);
  }
  return { records, results, findings };
}
function graph(
  bundle: Bundle,
  records: Map<string, Bundle>,
  recordFindings: readonly string[],
): ClaimResult {
  const findings = [...recordFindings];
  if (
    bundle.bundle_version !== "2" ||
    bundle.bundle_kind !== "evidence-bundle/v2"
  )
    findings.push("bundle_version_or_kind_invalid");
  const root = bundle.root;
  if (!isHex64(root) || !records.has(root))
    return fail(...findings, "root_not_supplied_with_matching_identity");
  const complete = bundle.completeness;
  if (!object(complete)) return fail(...findings, "completeness_malformed");
  const depth = complete.closure_depth ?? 2;
  if (!integer(depth) || depth < 0)
    return fail(...findings, "closure_depth_invalid");
  const missingRaw = complete.missing ?? [];
  if (!Array.isArray(missingRaw) || missingRaw.some((id) => !isHex64(id)))
    return fail(...findings, "missing_malformed");
  const missing = new Set(missingRaw);
  if (missing.size !== missingRaw.length) findings.push("missing_duplicate");
  if (
    complete.records_mode !==
    (missing.size ? "declared_incomplete" : "complete")
  )
    findings.push("records_mode_mismatch");
  // Breadth-first, each target once: a record first reached at its shortest
  // distance already carries the most remaining depth, and the walk stops when
  // no new record is reached, so work is bounded by the supplied records.
  let frontier = [root];
  const visited = new Set([root]),
    dangling = new Set<string>();
  for (let level = 0; level < depth && frontier.length; level += 1) {
    const next: string[] = [];
    for (const source of frontier)
      for (const target of citations(records.get(source)!))
        if (records.has(target)) {
          if (!visited.has(target)) {
            visited.add(target);
            next.push(target);
          }
        } else if (!missing.has(target) && !dangling.has(target)) {
          dangling.add(target);
          findings.push(`citation_dangling:${target}`);
        }
    frontier = next;
  }
  return findings.length
    ? fail(...findings)
    : missing.size
      ? { status: "withheld", findings: ["declared_incomplete"] }
      : pass();
}
function citations(record: Bundle): string[] {
  const targets: string[] = [],
    chain = record.chain;
  if (object(chain) && typeof chain.parent_capsule_id === "string")
    targets.push(chain.parent_capsule_id);
  if (Array.isArray(record.references))
    for (const reference of record.references)
      if (
        object(reference) &&
        reference.type === "agent-action-capsule" &&
        reference.digest_alg === "SHA-256" &&
        typeof reference.digest === "string"
      )
        targets.push(reference.digest);
  return targets;
}
async function completeness(
  bundle: Bundle,
  records: Map<string, Bundle>,
): Promise<[ClaimResult, ClaimResult]> {
  if (!object(bundle.completeness_certificate) || !object(bundle.checkpoint)) {
    const absent: ClaimResult = {
      status: "withheld",
      findings: ["completeness_evidence_absent"],
    };
    return [absent, absent];
  }
  const certificate = bundle.completeness_certificate,
    parsed = parseCertificate(certificate, bundle.checkpoint);
  if (!parsed)
    return [
      fail("completeness_certificate_invalid"),
      fail("completeness_certificate_invalid"),
    ];
  if (
    !(await rangeValid(
      parsed.root,
      parsed.firstSeq,
      parsed.lastSeq,
      certificate,
      parsed.rangeProof,
    ))
  )
    return [fail("range_proof_invalid"), fail("range_proof_invalid")];
  const checkpointStatus = await authenticateCheckpoint(
    bundle.checkpoint,
    parsed.logId,
    parsed.root,
    parsed.rangeProof.size,
  );
  if (checkpointStatus === "invalid")
    return [
      fail("checkpoint_authentication_invalid"),
      fail("checkpoint_authentication_invalid"),
    ];
  const findings = await memberships(
    parsed.root,
    parsed.logId,
    parsed.firstSeq,
    parsed.lastSeq,
    certificate.memberships,
    records,
    bundle.completeness,
    parsed.rangeProof.size,
  );
  const relative = (): ClaimResult =>
    checkpointStatus === "verified"
      ? pass()
      : { status: "pass", findings: ["checkpoint_unverified"] };
  return [relative(), findings.length ? fail(...findings) : relative()];
}
// Load cll's COSE checkpoint authenticator through a dynamic import so the
// browser build (whose cll substrate omits it) resolves to undefined at runtime
// instead of failing to bundle on a missing named export.
type CheckpointMetadata = (
  cose: Uint8Array,
) => Promise<{ logId: string; size: bigint; root: string } | undefined>;
async function loadCheckpointMetadata(): Promise<
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
async function authenticateCheckpoint(
  checkpoint: Bundle,
  logId: string,
  root: Uint8Array,
  size: number,
): Promise<"verified" | "unverified" | "invalid"> {
  if (!Object.hasOwn(checkpoint, "cose")) return "unverified";
  if (
    typeof checkpoint.cose !== "string" ||
    !/^[A-Za-z0-9_-]*$/u.test(checkpoint.cose)
  )
    return "invalid";
  // The COSE checkpoint authenticator is node-only (cll keeps checkpoint crypto
  // out of its browser substrate). When it is unavailable, a present checkpoint
  // cannot be independently authenticated here, so it degrades to producer
  // asserted (checkpoint_unverified) rather than invalid; the three completeness
  // claims are still verified from the MMR. Node retains full authentication.
  const checkpointMetadata = await loadCheckpointMetadata();
  if (!checkpointMetadata) return "unverified";
  try {
    const metadata = await checkpointMetadata(base64UrlDecode(checkpoint.cose));
    return metadata &&
      metadata.logId === logId &&
      metadata.size === BigInt(size) &&
      metadata.root ===
        Array.from(root, (byte) => byte.toString(16).padStart(2, "0")).join("")
      ? "verified"
      : "invalid";
  } catch {
    return "invalid";
  }
}
function parseCertificate(
  certificate: Bundle,
  checkpoint: Bundle,
):
  | {
      root: Uint8Array;
      logId: string;
      firstSeq: number;
      lastSeq: number;
      rangeProof: {
        fromSeq: number;
        toSeq: number;
        size: number;
        fromIndex: number;
        toIndex: number;
        proof: MmrRangeProof;
      };
    }
  | undefined {
  const logId = certificate.log_id,
    rootHex = certificate.range_root,
    firstSeq = certificate.first_seq,
    lastSeq = certificate.last_seq;
  if (
    typeof logId !== "string" ||
    !isHex64(rootHex) ||
    !integer(firstSeq) ||
    !integer(lastSeq) ||
    firstSeq < 1 ||
    lastSeq < firstSeq ||
    checkpoint.root !== rootHex
  )
    return undefined;
  const range = object(certificate.range_proof)
      ? certificate.range_proof
      : undefined,
    fromSeq = range?.from_seq,
    toSeq = range?.to_seq,
    size = range?.size,
    fromIndex = range?.from_index,
    toIndex = range?.to_index,
    witness = range?.witness;
  if (
    !integer(fromSeq) ||
    !integer(toSeq) ||
    !integer(size) ||
    !integer(fromIndex) ||
    !integer(toIndex) ||
    fromSeq < 1 ||
    toSeq < fromSeq ||
    size < 0 ||
    fromIndex < 0 ||
    toIndex < fromIndex ||
    !Array.isArray(witness) ||
    !witness.every(isHex64) ||
    checkpoint.mmr_size !== size
  )
    return undefined;
  return {
    root: hex(rootHex),
    logId,
    firstSeq,
    lastSeq,
    // The cert carries the index-shaped range proof (no v/kind); build the core
    // MmrRangeProof (v=1, kind="range") the verifier consumes.
    rangeProof: {
      fromSeq,
      toSeq,
      size,
      fromIndex,
      toIndex,
      proof: {
        v: 1,
        kind: "range",
        size,
        from_index: fromIndex,
        to_index: toIndex,
        witness,
      },
    },
  };
}
async function rangeValid(
  root: Uint8Array,
  first: number,
  last: number,
  certificate: Bundle,
  proof: {
    fromSeq: number;
    toSeq: number;
    size: number;
    fromIndex: number;
    toIndex: number;
    proof: MmrRangeProof;
  },
): Promise<boolean> {
  // CLL #13 per-record range membership: every leaf in [first, last] takes part
  // via the ordered body_digests + witness, so an altered/deleted/replaced
  // interior leaf is caught, not just the two endpoints.
  // The interval must end at the checkpointed tip: leafCount(size) === last.
  // CLL's index-level verify_range enforces this (the Python verifier uses it);
  // the core verifyRange does not, so bind it here or a sub-tip range would let
  // records after `last` be silently omitted.
  const leaves = leafCount(BigInt(proof.size));
  const raw = certificate.body_digests;
  if (
    leaves === undefined ||
    leaves !== BigInt(last) ||
    proof.fromSeq !== first ||
    proof.toSeq !== last ||
    proof.fromIndex !== first - 1 ||
    proof.toIndex !== last - 1 ||
    !Array.isArray(raw) ||
    raw.length !== last - first + 1 ||
    !raw.every(isHex64)
  )
    return false;
  return verifyRange(
    root,
    BigInt(proof.size),
    BigInt(proof.fromIndex),
    BigInt(proof.toIndex),
    raw.map(hex),
    proof.proof,
  );
}
async function memberships(
  root: Uint8Array,
  logId: string,
  first: number,
  last: number,
  raw: unknown,
  records: Map<string, Bundle>,
  completeness: unknown,
  checkpointSize: number,
): Promise<string[]> {
  if (!object(raw)) return ["memberships_absent"];
  const bySequence = new Set<number>(),
    boundRecords = new Set<string>(),
    findings: string[] = [];
  for (const [id, member] of Object.entries(raw)) {
    if (!isHex64(id) || !records.has(id) || !object(member)) {
      findings.push(`membership_record_unknown:${id}`);
      continue;
    }
    const coordinates = object(member.log_coordinates)
      ? member.log_coordinates
      : undefined;
    if (!coordinates) {
      findings.push(`membership_coordinates_missing:${id}`);
      continue;
    }
    const seq = coordinates.seq,
      leaf = coordinates.leaf_index;
    if (
      coordinates.log_id !== logId ||
      !integer(seq) ||
      !integer(leaf) ||
      seq < first ||
      seq > last ||
      leaf !== seq - 1
    ) {
      findings.push(`membership_coordinates_invalid:${id}`);
      continue;
    }
    if (bySequence.has(seq)) {
      findings.push(`membership_seq_duplicate:${seq}`);
      continue;
    }
    bySequence.add(seq);
    boundRecords.add(id);
    const proof = parseProof(member.inclusion_proof);
    if (
      !proof ||
      proof.leaf_index !== leaf ||
      proof.size !== checkpointSize ||
      !(await verifyProof(root, id, proof, leaf))
    )
      findings.push(`membership_proof_invalid:${id}`);
  }
  for (let seq = first; seq <= last; seq += 1)
    if (!bySequence.has(seq)) findings.push(`membership_record_missing:${seq}`);
  const declaredMissing =
    object(completeness) && Array.isArray(completeness.missing)
      ? new Set(completeness.missing.filter(isHex64))
      : new Set<string>();
  for (const id of records.keys())
    if (!boundRecords.has(id) && !declaredMissing.has(id))
      findings.push(`membership_record_unbound:${id}`);
  return findings;
}
function parseProof(raw: unknown): Proof | undefined {
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
async function verifyProof(
  root: Uint8Array,
  identity: string,
  proof: Proof,
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
async function disclosures(
  raw: unknown,
  records: Map<string, Bundle>,
): Promise<DisclosureResult[]> {
  if (raw === undefined) raw = {};
  if (!object(raw))
    return [{ capsuleId: "", member: "", status: DISCLOSURE_MISMATCH }];
  const findings: DisclosureResult[] = [];
  for (const [id, record] of [...records.entries()].sort(([a], [b]) =>
    a.localeCompare(b),
  )) {
    if (Object.hasOwn(raw, id) && !object(raw[id])) continue;
    const supplied = object(raw[id]) ? raw[id] : {};
    for (const [member, path] of Object.entries(disclosureEligibleFields))
      if (
        !Object.hasOwn(supplied, member) &&
        typeof resolveDisclosurePath(record as ParsedJson, path) === "string"
      )
        findings.push({ capsuleId: id, member, status: "withheld" });
  }
  for (const id of Object.keys(raw).sort()) {
    const members = raw[id],
      record = records.get(id);
    if (!object(members) || !record) {
      findings.push({ capsuleId: id, member: "", status: DISCLOSURE_MISMATCH });
      continue;
    }
    for (const member of Object.keys(members).sort()) {
      // Own members only: a disclosure named `constructor` or `__proto__` is
      // an ineligible field, not a lookup on the registry object's prototype.
      const path = Object.hasOwn(disclosureEligibleFields, member)
        ? disclosureEligibleFields[
            member as keyof typeof disclosureEligibleFields
          ]
        : undefined;
      if (!path) {
        findings.push({
          capsuleId: id,
          member,
          status: DISCLOSURE_INELIGIBLE_FIELD,
        });
        continue;
      }
      const committed = resolveDisclosurePath(record as ParsedJson, path);
      if (!isHex64(committed)) {
        findings.push({
          capsuleId: id,
          member,
          status: DISCLOSURE_NO_COMMITTED_DIGEST,
        });
        continue;
      }
      let status = DISCLOSURE_MISMATCH;
      try {
        if ((await jsonDigest(members[member])) === committed)
          status = DISCLOSURE_MATCH;
      } catch {
        /* mismatch */
      }
      findings.push({ capsuleId: id, member, status });
    }
  }
  return findings;
}
async function extensions(
  bundle: Bundle,
  covered: boolean,
): Promise<ExtensionResult[]> {
  const raw = bundle.extensions;
  if (!object(raw)) return [];
  const results: ExtensionResult[] = [];
  for (const kind of Object.keys(raw).sort()) {
    const interpreter = extensionInterpreter(kind, bundle);
    // composed/v1 is verified here, its member bundles recursively by this
    // same verifier (go/bundle/bundle.go extensions -> VerifyComposed).
    const composed =
      kind === COMPOSED_KIND
        ? { composed: await verifyComposed(raw[kind], verifyBundle) }
        : {};
    results.push(
      interpreter === undefined
        ? {
            kind,
            status: "uninterpreted",
            integrityCovered: covered,
            ...composed,
          }
        : {
            kind,
            status: "interpreted",
            interpreter,
            integrityCovered: covered,
            ...composed,
          },
    );
  }
  return results;
}

/**
 * Everything a presentation builder may read about a bundle, built ONCE from
 * one `verifyBundle` run. Builders never re-resolve a disclosure: a payload
 * reaches them only through `resolvedDisclosures`, which is derived from the
 * verifier's own `verification.disclosures`, so a member the verifier
 * classified as a mismatch (or one it never classified, because its record
 * failed identity) can never be read as a payload.
 *
 * Only {@link buildVerifiedBundleContext} makes one; a hand-built object of
 * the same shape is not a context and is treated as a raw bundle.
 *
 * A context is effectively immutable. It is built over the library's own
 * copy of the bundle, and its whole object graph (the bundle copy, the
 * verification result, `resolvedDisclosures`, `records`, `recordIndex`,
 * `countersignatures`, `countersigners`, `extensions` and `completeness`) is
 * frozen before it is returned. The two maps are read-only views with no
 * mutating methods. A builder that tries to change any part of it throws (in
 * strict mode, which every ES module is) and the next reader sees the
 * original. The caller's own bundle and countersigner list are copied, never
 * frozen.
 */
export interface VerifiedBundleContext {
  /** A frozen copy of the bundle as supplied. */
  readonly bundle: unknown;
  /** `bundle.root` when it is a string. */
  readonly root: string | undefined;
  /** The one verification run every builder shares. */
  readonly verification: BundleVerificationResult;
  /**
   * capsule_id -> both disclosable members, resolved from
   * `verification.disclosures`: `disclosed` (carrying the supplied value)
   * only for a `disclosure_match`; `disclosure_mismatch` for a mismatch or a
   * member with no committed digest; `withheld` otherwise. One entry per
   * record in `records`.
   */
  readonly resolvedDisclosures: ReadonlyMap<
    string,
    Readonly<Record<DisclosureField, DisclosureResolution>>
  >;
  /**
   * The records whose identity the verifier accepted, in bundle order. A
   * record's capsule_id is the digest every agent-action-capsule reference
   * cites it by, so `recordIndex` is the index by id and by digest alike.
   */
  readonly records: readonly RecordWithId[];
  readonly recordIndex: ReadonlyMap<string, RecordWithId>;
  /** The verifier's countersignature results (each `unverified` at this layer). */
  readonly countersignatures: readonly CountersignatureResult[];
  /**
   * The caller's countersigner source, the only thing that ever names an
   * independent countersigner. Never read from the bundle.
   */
  readonly countersigners: CountersignerSource | undefined;
  /** The verifier's extension results. */
  readonly extensions: readonly ExtensionResult[];
  readonly completeness: {
    readonly graphClosure: ClaimResult;
    readonly intervalCoverage: ClaimResult;
    readonly perRecordMembership: ClaimResult;
    /**
     * `completeness_certificate.memberships` as supplied (or empty): the log
     * coordinates builders display beside a record.
     */
    readonly memberships: ObjectValue;
  };
}

export interface VerifiedBundleContextOptions {
  readonly countersigners?: CountersignerSource;
}

const contexts = new WeakSet<object>();

/**
 * A read-only view over a map the context owns. `Object.freeze` does not stop
 * `Map.prototype.set`, so the context never hands out the `Map` itself: the
 * view exposes only the reading half of the interface and holds the map in a
 * private field.
 */
class ReadonlyMapView<K, V> implements ReadonlyMap<K, V> {
  readonly #map: ReadonlyMap<K, V>;
  constructor(map: ReadonlyMap<K, V>) {
    this.#map = map;
    Object.freeze(this);
  }
  get size(): number {
    return this.#map.size;
  }
  get(key: K): V | undefined {
    return this.#map.get(key);
  }
  has(key: K): boolean {
    return this.#map.has(key);
  }
  forEach(
    callback: (value: V, key: K, map: ReadonlyMap<K, V>) => void,
    thisArg?: unknown,
  ): void {
    this.#map.forEach((value, key) => callback.call(thisArg, value, key, this));
  }
  entries(): MapIterator<[K, V]> {
    return this.#map.entries();
  }
  keys(): MapIterator<K> {
    return this.#map.keys();
  }
  values(): MapIterator<V> {
    return this.#map.values();
  }
  [Symbol.iterator](): MapIterator<[K, V]> {
    return this.#map.entries();
  }
}
Object.freeze(ReadonlyMapView.prototype);

const plain = (value: object): boolean => {
  const prototype: unknown = Object.getPrototypeOf(value);
  return (
    Array.isArray(value) || prototype === Object.prototype || prototype === null
  );
};

/**
 * A structural copy of JSON-shaped input: arrays and plain objects are copied
 * (own enumerable string keys, each read once), primitives are kept. Keys are
 * defined, not assigned, so a parsed `__proto__` member stays a member. Any
 * other object is kept by reference and left as it is.
 */
function ownedCopy<T>(value: T, seen = new Map<object, unknown>()): T {
  if (value === null || typeof value !== "object" || !plain(value))
    return value;
  const done = seen.get(value);
  if (done !== undefined) return done as T;
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    seen.set(value, out);
    for (const item of value) out.push(ownedCopy(item, seen));
    return out as T;
  }
  const out: Record<string, unknown> = {};
  seen.set(value, out);
  for (const key of Object.keys(value))
    Object.defineProperty(out, key, {
      value: ownedCopy((value as Record<string, unknown>)[key], seen),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  return out as T;
}

/**
 * Freeze an object graph the context owns: arrays and plain objects,
 * recursively through data properties (accessors are never invoked). A
 * {@link ReadonlyMapView} freezes itself and its entries are frozen through
 * it.
 */
function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object" || seen.has(value))
    return value;
  seen.add(value);
  if (value instanceof ReadonlyMapView) {
    for (const [key, entry] of value as ReadonlyMapView<unknown, unknown>) {
      deepFreeze(key, seen);
      deepFreeze(entry, seen);
    }
    return value;
  }
  if (!plain(value)) return value;
  Object.freeze(value);
  for (const descriptor of Object.values(
    Object.getOwnPropertyDescriptors(value),
  ))
    if ("value" in descriptor) deepFreeze(descriptor.value, seen);
  return value;
}

/** True only for a context {@link buildVerifiedBundleContext} made. */
export function isVerifiedBundleContext(
  value: unknown,
): value is VerifiedBundleContext {
  return object(value) && contexts.has(value);
}

const WITHHELD: DisclosureResolution = Object.freeze({ state: "withheld" });
const MISMATCHED: DisclosureResolution = Object.freeze({
  state: "disclosure_mismatch",
});

/** Verify `bundle` once and carry the result every builder reads. */
export async function buildVerifiedBundleContext(
  bundle: unknown,
  options: VerifiedBundleContextOptions = {},
): Promise<VerifiedBundleContext> {
  // Verify the library's own frozen copy, so the bytes verified are the
  // bytes every builder reads and nothing (the caller included) can change
  // them afterwards.
  const owned = deepFreeze(ownedCopy(bundle));
  return contextFrom(
    owned,
    await verifyBundle(owned),
    options.countersigners === undefined
      ? undefined
      : deepFreeze(ownedCopy(options.countersigners)),
  );
}

/**
 * `input` itself when it is already a context, else a fresh context over it.
 * The single entry every builder's legacy `(bundle)` signature goes through.
 */
export async function verifiedBundleContext(
  input: unknown,
): Promise<VerifiedBundleContext> {
  return isVerifiedBundleContext(input)
    ? input
    : buildVerifiedBundleContext(input);
}

/** The same context with a different countersigner source. */
export function withCountersigners(
  context: VerifiedBundleContext,
  countersigners: CountersignerSource | undefined,
): VerifiedBundleContext {
  return contextFrom(
    context.bundle,
    context.verification,
    countersigners === undefined
      ? undefined
      : deepFreeze(ownedCopy(countersigners)),
    context,
  );
}

function contextFrom(
  bundle: unknown,
  verification: BundleVerificationResult,
  countersigners: CountersignerSource | undefined,
  reuse?: VerifiedBundleContext,
): VerifiedBundleContext {
  let records: readonly RecordWithId[],
    recordIndex: ReadonlyMap<string, RecordWithId>,
    resolvedDisclosures: VerifiedBundleContext["resolvedDisclosures"];
  if (reuse !== undefined) {
    ({ records, recordIndex, resolvedDisclosures } = reuse);
  } else {
    const index = new Map<string, RecordWithId>();
    if (object(bundle) && Array.isArray(bundle.records))
      for (const record of bundle.records)
        if (
          object(record) &&
          typeof record.capsule_id === "string" &&
          !index.has(record.capsule_id) &&
          verification.capsuleResults[record.capsule_id]?.ok === true &&
          verification.capsuleResults[record.capsule_id]?.capsuleId ===
            record.capsule_id
        )
          index.set(record.capsule_id, record as RecordWithId);
    records = Object.freeze([...index.values()]);
    recordIndex = new ReadonlyMapView(index);
    resolvedDisclosures = resolveFromVerification(
      bundle,
      verification.disclosures,
      index,
    );
  }
  const certificate = object(bundle)
    ? bundle.completeness_certificate
    : undefined;
  deepFreeze(verification);
  const context: VerifiedBundleContext = deepFreeze({
    bundle,
    root:
      object(bundle) && typeof bundle.root === "string"
        ? bundle.root
        : undefined,
    verification,
    resolvedDisclosures,
    records,
    recordIndex,
    countersignatures: verification.countersignatures,
    countersigners,
    extensions: verification.extensions,
    completeness: {
      graphClosure: verification.graphClosure,
      intervalCoverage: verification.intervalCoverage,
      perRecordMembership: verification.perRecordMembership,
      memberships:
        object(certificate) && object(certificate.memberships)
          ? certificate.memberships
          : {},
    },
  });
  contexts.add(context);
  return context;
}

function resolveFromVerification(
  bundle: unknown,
  results: readonly DisclosureResult[],
  index: ReadonlyMap<string, RecordWithId>,
): VerifiedBundleContext["resolvedDisclosures"] {
  const status = new Map<string, string>();
  for (const result of results)
    status.set(`${result.capsuleId}\u0000${result.member}`, result.status);
  const overlay =
    object(bundle) && object(bundle.disclosures) ? bundle.disclosures : {};
  const resolved = new Map<
    string,
    Readonly<Record<DisclosureField, DisclosureResolution>>
  >();
  const one = (id: string, field: DisclosureField): DisclosureResolution => {
    switch (status.get(`${id}\u0000${field}`)) {
      case DISCLOSURE_MATCH: {
        const entry = overlay[id];
        return object(entry) && Object.hasOwn(entry, field)
          ? Object.freeze({ state: "disclosed", payload: entry[field] })
          : MISMATCHED;
      }
      case DISCLOSURE_MISMATCH:
      case DISCLOSURE_NO_COMMITTED_DIGEST:
        return MISMATCHED;
      default:
        return WITHHELD;
    }
  };
  for (const id of index.keys())
    resolved.set(
      id,
      Object.freeze({
        agent_input: one(id, "agent_input"),
        agent_output: one(id, "agent_output"),
      }),
    );
  return new ReadonlyMapView(resolved);
}

/**
 * One record's disclosable member as the verifier resolved it. A record the
 * context does not hold (absent, or rejected by the verifier) is `withheld`.
 */
export function disclosureOf(
  context: VerifiedBundleContext,
  capsuleId: string,
  field: DisclosureField,
): DisclosureResolution {
  return context.resolvedDisclosures.get(capsuleId)?.[field] ?? WITHHELD;
}

/** The verified payload of a member, or undefined when withheld or mismatched. */
export function verifiedPayload(
  context: VerifiedBundleContext,
  capsuleId: string,
  field: DisclosureField,
): unknown {
  return disclosureOf(context, capsuleId, field).payload;
}

/**
 * Resolve one disclosable member of a record from a disclosure overlay,
 * standalone. Kept for callers outside a {@link VerifiedBundleContext};
 * no builder in this library calls it -- they read the context's
 * `resolvedDisclosures`, derived from `verifyBundle`. The overlay is keyed
 * by `capsule_id`; a supplied value is `disclosed` only when its JSON-DIGEST
 * equals the digest the record committed to (DE-3), otherwise
 * `disclosure_mismatch`; an absent value is `withheld`.
 */
export const resolveDisclosure = async (
  record: RecordWithId,
  disclosures: ObjectValue,
  field: DisclosureField,
): Promise<DisclosureResolution> => {
  const entry = disclosures[record.capsule_id];
  if (!object(entry) || !Object.hasOwn(entry, field))
    return { state: "withheld" };
  const committed = resolveDisclosurePath(
    record as ParsedJson,
    disclosureEligibleFields[field],
  );
  if (isHex64(committed)) {
    try {
      if ((await jsonDigest(entry[field])) === committed)
        return { state: "disclosed", payload: entry[field] };
    } catch {
      /* a value JCS cannot render cannot be the committed preimage */
    }
  }
  return { state: "disclosure_mismatch" };
};

/** The standalone {@link resolveDisclosure} payload, or undefined. */
export const disclosurePayload = async (
  record: RecordWithId,
  disclosures: ObjectValue,
  field: DisclosureField,
): Promise<unknown> =>
  (await resolveDisclosure(record, disclosures, field)).payload;
