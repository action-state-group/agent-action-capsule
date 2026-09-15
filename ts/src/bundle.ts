import {
  rootFromPeaks,
  verifyHexInclusion,
  verifyRange,
  type MmrInclusionProof,
  type MmrRangeProof,
} from "@action-state-group/cll";
import {
  isHex64,
  jcs,
  jsonDigest,
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
import { disclosureEligibleFields } from "./registries.js";
import { verifyClass1, type VerificationResult } from "./verify.js";

export interface ClaimResult {
  readonly status: "pass" | "withheld" | "fail";
  readonly findings: readonly string[];
}
export interface DisclosureResult {
  readonly capsuleId: string;
  readonly member: string;
  readonly status: string;
}
export interface ExtensionResult {
  readonly kind: string;
  readonly status: "uninterpreted";
  readonly integrityCovered: true;
}
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
const text = new TextDecoder("utf-8", { fatal: true });
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
  return btoa(
    Array.from(jcs(bundle), (byte) => String.fromCharCode(byte)).join(""),
  )
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}
/** Decode an unpadded Evidence Bundle URL fragment without verifying its claims. */
export function decodeFragment(fragment: string): unknown {
  if (!/^[A-Za-z0-9_-]*$/u.test(fragment))
    throw new TypeError("fragment base64url");
  try {
    const padded = `${fragment}${"=".repeat((4 - (fragment.length % 4)) % 4)}`;
    const binary = atob(padded.replaceAll("-", "+").replaceAll("_", "/"));
    const value: unknown = JSON.parse(
      text.decode(Uint8Array.from(binary, (char) => char.charCodeAt(0))),
    );
    return value;
  } catch (error) {
    throw new TypeError("fragment UTF-8 JSON");
  }
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
    extensions: extensions(bundle.extensions),
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
  let frontier = [root];
  for (let level = 0; level < depth; level += 1) {
    const next: string[] = [];
    for (const source of frontier)
      for (const target of citations(records.get(source)!))
        if (records.has(target)) next.push(target);
        else if (!missing.has(target))
          findings.push(`citation_dangling:${target}`);
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
    const padded = `${checkpoint.cose}${"=".repeat((4 - (checkpoint.cose.length % 4)) % 4)}`;
    const binary = atob(padded.replaceAll("-", "+").replaceAll("_", "/"));
    const metadata = await checkpointMetadata(
      Uint8Array.from(binary, (char) => char.charCodeAt(0)),
    );
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
  const raw = certificate.body_digests;
  if (
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
        !(member in supplied) &&
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
      const path =
        disclosureEligibleFields[
          member as keyof typeof disclosureEligibleFields
        ];
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
function extensions(raw: unknown): ExtensionResult[] {
  return object(raw)
    ? Object.keys(raw)
        .sort()
        .map((kind) => ({
          kind,
          status: "uninterpreted",
          integrityCovered: true,
        }))
    : [];
}
