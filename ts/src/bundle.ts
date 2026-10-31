import {
  inclusionProof,
  leafCount,
  MmrTree,
  rangeProof,
  rootFromPeaks,
  verifyHexInclusion,
  verifyRange,
  type MmrInclusionProof,
  type MmrRangeProof,
} from "@action-state-group/cll";
import {
  decodeStrictJson,
  digestCapability,
  isHex64,
  probeEd25519,
  jcs,
  jsonDigest,
  JsonNumber,
  setMember,
  Sha256UnavailableError,
  sha256Hex,
  type ParsedJson,
} from "./json.js";
import { MAX_NESTING_DEPTH, nestedTooDeep } from "./nesting.js";
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
import {
  verifyProducerEnvelope,
  verifyRecordSignature,
  type RecordSignatureVerdict,
} from "./producer-envelope-verification.js";
import { disclosureEligibleFields } from "./registries.js";
import { verifyClass1, type VerificationResult } from "./verify.js";
import {
  verifyWitnessReceipts,
  type SignedCheckpointFields,
  type WitnessReceiptResult,
} from "./witness.js";
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
export type {
  SignedCheckpointFields,
  WitnessBinding,
  WitnessGrade,
  WitnessReceiptResult,
} from "./witness.js";
export interface CountersignatureResult {
  readonly value: unknown;
  readonly status: "unverified";
}
export interface ProducerSelfReport {
  readonly value: unknown;
  readonly status: "producer_self_report";
}
/**
 * The result of {@link verifyBundle}. With `strict`, `intervalCoverage` and
 * `perRecordMembership` are the strict readings (with no signed checkpoint, a
 * claim that did not fail is `withheld`, `checkpoint_unverified`), and
 * `strict` carries the strict claims and the verdict.
 */
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
  /** Only with `strict`. */
  readonly strict?: StrictBundleResult;
}
export interface VerifyBundleOptions {
  /**
   * Add the checks a verifier handing a verdict to a person needs
   * (vectors/bundle/strict/README.md): each record's producer signature, the
   * checkpoint read only from its signed COSE form, producer-selected
   * Bundles, the `disclosures` overlay as one claim, the witness receipts in
   * `checkpoint.witnesses`, and a verdict.
   */
  readonly strict?: boolean;
  /** Strict only: an unsigned record fails the `signatures` claim. */
  readonly requireSignature?: boolean;
  /**
   * Strict only: the witness directory (a parsed `witnesses.json`, or its
   * row list) whose keys witness receipts are checked under. Without one no
   * witness is trusted and every receipt is `withheld`.
   */
  readonly witnessDirectory?: unknown;
}
/** The gating claims of a strict verification, in report order. */
export type StrictClaimName =
  | "records"
  | "signatures"
  | "graph_closure"
  | "checkpoint"
  | "interval_coverage"
  | "per_record_membership"
  | "disclosures";
export interface StrictClaim extends ClaimResult {
  readonly name: StrictClaimName;
}
/** One object of the Bundle's `records` list, in order. */
export interface StrictRecordResult {
  readonly capsuleId: string;
  /** The plain verifier verified the record under its carried capsule_id. */
  readonly identityOk: boolean;
  readonly signature: RecordSignatureVerdict;
  readonly keyId: string | null;
  /** `log_coordinates.seq` as the record's membership states it. */
  readonly seq: number | null;
  readonly messages: readonly string[];
}
export interface StrictWitnessesResult extends ClaimResult {
  readonly receipts: readonly WitnessReceiptResult[];
}
export interface StrictBundleResult {
  /**
   * `VALID` when every claim passed, `INVALID` when one failed or the
   * witnesses failed, `INCOMPLETE` otherwise.
   */
  readonly verdict: "VALID" | "INCOMPLETE" | "INVALID";
  /** `bundle_kind` is `evidence-bundle/v2` and `bundle_version` is `"2"`. */
  readonly kindOk: boolean;
  readonly claims: readonly StrictClaim[];
  /**
   * Reported beside the claims, never one of them: only a failing receipt
   * changes the verdict. Null for a Bundle refused by its kind.
   */
  readonly witnesses: StrictWitnessesResult | null;
  readonly records: readonly StrictRecordResult[];
  /** The `checkpoint` claim passed. */
  readonly checkpointAuthenticated: boolean;
  /**
   * The signed checkpoint's own fields (from `checkpoint.cose`) and the
   * Bundle's `witnesses` list, when it authenticated.
   */
  readonly signedCheckpoint?: SignedCheckpointFields & {
    readonly witnesses: readonly unknown[];
  };
  /**
   * Whether every record's `key_id` is the signed checkpoint's `key_id`, when
   * the checkpoint authenticated and there is a record. Reported, never gates.
   */
  readonly signerMatchesCheckpoint: boolean | null;
}
export type StrictBundleVerificationResult = BundleVerificationResult & {
  readonly strict: StrictBundleResult;
};
/**
 * Thrown by strict {@link verifyBundle} where this runtime has no Ed25519
 * verifier (no SubtleCrypto, or one without Ed25519): no strict verdict can
 * be reached, which is not a failed verification.
 */
export class Ed25519UnavailableError extends Error {
  public constructor() {
    super("strict Bundle verification needs Ed25519, which this runtime lacks");
    this.name = "Ed25519UnavailableError";
  }
}
type Bundle = Record<string, unknown>;
type Proof = MmrInclusionProof;
const pass = (): ClaimResult => ({ status: "pass", findings: [] });
const fail = (...findings: string[]): ClaimResult => ({
  status: "fail",
  findings,
});
// A JsonNumber (a decoded number kept with its spelling) is a value, not a
// Bundle object.
const object = (value: unknown): value is Bundle =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  !(value instanceof JsonNumber);
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
/**
 * Verify independent Evidence Bundle claims and the disclosure overlay.
 * `{ strict: true }` adds the strict checks and a verdict
 * ({@link VerifyBundleOptions}).
 */
export async function verifyBundle(
  bundle: unknown,
  options: VerifyBundleOptions & { readonly strict: true },
): Promise<StrictBundleVerificationResult>;
export async function verifyBundle(
  bundle: unknown,
  options?: VerifyBundleOptions,
): Promise<BundleVerificationResult>;
export async function verifyBundle(
  bundle: unknown,
  options: VerifyBundleOptions = {},
): Promise<BundleVerificationResult> {
  // Every check below hashes. With no SHA-256 nothing can be checked, and a
  // result here would read as a failed check, so there is none.
  if (digestCapability() === "none") throw new Sha256UnavailableError();
  if (options.strict === true && !(await probeEd25519()))
    throw new Ed25519UnavailableError();
  const { plain, strict } = await verifyPlainAndStrict(bundle, options);
  return strict ?? plain;
}
/**
 * The plain result and, with `strict`, the strict one computed from it, so
 * a caller that needs both runs the plain checks once.
 */
async function verifyPlainAndStrict(
  bundle: unknown,
  options: VerifyBundleOptions,
): Promise<{
  plain: BundleVerificationResult;
  strict?: StrictBundleVerificationResult;
}> {
  try {
    // A Bundle nested more than MAX_NESTING_DEPTH levels deep is refused
    // before any recursive check, as in Go, Python and Rust.
    if (nestedTooDeep(bundle))
      throw new RangeError(
        `Bundle nests more than ${MAX_NESTING_DEPTH} levels`,
      );
    const plain = await verifyPlain(bundle);
    return options.strict === true
      ? {
          plain,
          strict: await strict(
            plain,
            object(bundle) ? bundle : undefined,
            options,
          ),
        }
      : { plain };
  } catch (error) {
    // A Bundle nested too deeply, or beyond what this implementation can
    // read (a stack overflow), is a RangeError. It is refused, never raised:
    // every claim is bundle_malformed and, in strict mode, the verdict is
    // INVALID.
    if (!(error instanceof RangeError)) throw error;
    const plain = malformedBundle();
    return options.strict === true
      ? {
          plain,
          strict: {
            ...plain,
            strict: {
              verdict: "INVALID",
              kindOk: false,
              claims: [{ name: "records", ...fail("bundle_malformed") }],
              witnesses: null,
              records: [],
              checkpointAuthenticated: false,
              signerMatchesCheckpoint: null,
            },
          },
        }
      : { plain };
  }
}
/** The result for input that is not a readable Bundle. */
function malformedBundle(): BundleVerificationResult {
  const invalid = fail("bundle_malformed");
  return {
    graphClosure: invalid,
    intervalCoverage: invalid,
    perRecordMembership: invalid,
    disclosures: [],
    extensions: [],
    countersignatures: [],
    capsuleResults: {},
  };
}
async function verifyPlain(bundle: unknown): Promise<BundleVerificationResult> {
  if (!object(bundle)) return malformedBundle();
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
// The checkpoint fields a signed COSE checkpoint states; in strict mode the
// Bundle's JSON copy must match every one it carries.
const SIGNED_CHECKPOINT_FIELDS = [
  "log_id",
  "mmr_size",
  "root",
  "key_id",
  "timestamp",
  "prev_size",
  "prev_root",
] as const;
/**
 * `completeness.selection` of a producer-selected Bundle: records the
 * producer picked from its log, with no claim about the records between them.
 * Not defined by the Bundle draft; read only in strict mode.
 */
export const SELECTION_PRODUCER_SELECTED = "producer-selected";
/** The interval coverage finding of a producer-selected Bundle. */
export const SELECTION_NOT_CHECKABLE = "selection_not_checkable";

async function strict(
  plain: BundleVerificationResult,
  bundle: Bundle | undefined,
  options: VerifyBundleOptions,
): Promise<StrictBundleVerificationResult> {
  if (
    bundle === undefined ||
    bundle.bundle_kind !== "evidence-bundle/v2" ||
    bundle.bundle_version !== "2"
  )
    return {
      ...plain,
      strict: {
        verdict: "INVALID",
        kindOk: false,
        claims: [{ name: "records", ...fail("not_an_evidence_bundle_v2") }],
        witnesses: null,
        records: [],
        checkpointAuthenticated: false,
        signerMatchesCheckpoint: null,
      },
    };
  const seqs = membershipSeqs(bundle);
  const records: StrictRecordResult[] = [];
  const seen = new Set<string>();
  for (const record of Array.isArray(bundle.records) ? bundle.records : []) {
    if (!object(record)) continue;
    const id = capsuleIdOf(record);
    const { verdict, messages } = await verifyRecordSignature(record);
    // A repeated capsule_id is a second record the plain verifier skipped.
    const result =
      !seen.has(id) && Object.hasOwn(plain.capsuleResults, id)
        ? plain.capsuleResults[id]
        : undefined;
    seen.add(id);
    records.push({
      capsuleId: id,
      identityOk: result?.ok === true && result.capsuleId === id,
      signature: verdict,
      keyId: typeof record.key_id === "string" ? record.key_id : null,
      seq: seqs.get(id) ?? null,
      messages,
    });
  }
  const identityFindings = records
    .filter((r) => !r.identityOk)
    .map((r) => `record_identity_invalid:${r.capsuleId}`);
  const identity: ClaimResult =
    records.length && !identityFindings.length
      ? pass()
      : records.length
        ? fail(...identityFindings)
        : fail("no_records");

  const invalidSignatures = records.filter((r) => r.signature === "invalid"),
    unclaimed = records.filter((r) => r.signature === "unclaimed");
  const signatureFindings = [
    ...invalidSignatures.map(
      (r) => `producer_signature_invalid:${r.capsuleId}`,
    ),
    ...unclaimed.map((r) => `producer_signature_unclaimed:${r.capsuleId}`),
  ];
  const signatures: ClaimResult =
    invalidSignatures.length ||
    (unclaimed.length && options.requireSignature === true) ||
    !records.length
      ? fail(...signatureFindings)
      : {
          status: unclaimed.length ? "withheld" : "pass",
          findings: signatureFindings,
        };

  const stated = object(bundle.checkpoint) ? bundle.checkpoint : {};
  const checkpoint = await strictCheckpoint(
    stated,
    object(bundle.completeness_certificate)
      ? bundle.completeness_certificate
      : {},
  );
  const authenticated = checkpoint.signed !== undefined;

  let intervalCoverage = plain.intervalCoverage,
    perRecordMembership = plain.perRecordMembership;
  if (
    object(bundle.completeness) &&
    bundle.completeness.selection === SELECTION_PRODUCER_SELECTED
  ) {
    // The certificate binds the producer's selection, not an interval: the
    // interval proof cannot be read, each record's own proof still can.
    intervalCoverage = {
      status: "withheld",
      findings: [SELECTION_NOT_CHECKABLE],
    };
    perRecordMembership = await selectedMembership(bundle, checkpoint.signed);
  }
  if (!authenticated) {
    intervalCoverage = unanchored(intervalCoverage);
    perRecordMembership = unanchored(perRecordMembership);
  }

  const claims: StrictClaim[] = [
    { name: "records", ...identity },
    { name: "signatures", ...signatures },
    { name: "graph_closure", ...plain.graphClosure },
    { name: "checkpoint", ...checkpoint.claim },
    { name: "interval_coverage", ...intervalCoverage },
    { name: "per_record_membership", ...perRecordMembership },
  ];
  if (Object.hasOwn(bundle, "disclosures")) {
    const failed = plain.disclosures
      .filter((d) => d.status !== DISCLOSURE_MATCH && d.status !== "withheld")
      .map((d) => `${d.status}:${d.capsuleId}:${d.member}`);
    claims.push({
      name: "disclosures",
      ...(failed.length ? fail(...failed) : pass()),
    });
  }

  const witnesses = await verifyWitnessReceipts(
    stated.witnesses,
    checkpoint.signed,
    checkpoint.cose,
    options.witnessDirectory,
  );
  const checkpointKey = checkpoint.signed?.key_id;
  const failed =
    claims.some((claim) => claim.status === "fail") ||
    witnesses.status === "fail";
  return {
    ...plain,
    intervalCoverage,
    perRecordMembership,
    strict: {
      verdict: failed
        ? "INVALID"
        : claims.every((claim) => claim.status === "pass")
          ? "VALID"
          : "INCOMPLETE",
      kindOk: true,
      claims,
      witnesses: {
        status: witnesses.status,
        findings: witnesses.findings,
        receipts: witnesses.receipts,
      },
      records,
      checkpointAuthenticated: authenticated,
      ...(checkpoint.signed === undefined
        ? {}
        : {
            signedCheckpoint: {
              ...checkpoint.signed,
              witnesses: Array.isArray(stated.witnesses)
                ? stated.witnesses
                : [],
            },
          }),
      signerMatchesCheckpoint:
        checkpointKey && records.length
          ? records.every((r) => r.keyId === checkpointKey)
          : null,
    },
  };
}

/** A record's `capsule_id`, or "" when it is not a string. */
const capsuleIdOf = (record: Bundle): string =>
  typeof record.capsule_id === "string" ? record.capsule_id : "";

/** Python's `sorted()` order of strings: by code point, not UTF-16 unit. */
function byCodePoint(a: string, b: string): number {
  const left = Array.from(a, (c) => c.codePointAt(0)!),
    right = Array.from(b, (c) => c.codePointAt(0)!);
  for (let i = 0; i < Math.min(left.length, right.length); i += 1)
    if (left[i] !== right[i]) return left[i]! - right[i]!;
  return left.length - right.length;
}

/** JSON equality that keeps types apart (`1` is not `true` or `1.0`). */
const sameJson = (stated: unknown, signed: string | number): boolean =>
  typeof stated === typeof signed && stated === signed;

/**
 * Verify `checkpoint.cose` and hold the JSON copy, and the completeness
 * certificate's `log_id` when stated, to it. The signed fields
 * and the COSE bytes are returned only when the claim passed.
 */
async function strictCheckpoint(
  stated: Bundle,
  certificate: Bundle,
): Promise<{
  claim: ClaimResult;
  signed?: SignedCheckpointFields;
  cose?: Uint8Array;
}> {
  const encoded = stated.cose;
  if (encoded === undefined || encoded === null)
    return {
      claim: { status: "withheld", findings: ["checkpoint_signature_absent"] },
    };
  const checkpointMetadata = await loadCheckpointMetadata();
  if (!checkpointMetadata)
    return {
      claim: {
        status: "withheld",
        findings: ["checkpoint_verifier_unavailable"],
      },
    };
  let cose: Uint8Array;
  try {
    if (typeof encoded !== "string" || !/^[A-Za-z0-9_-]*$/u.test(encoded))
      throw new TypeError("checkpoint.cose is not unpadded base64url");
    cose = base64UrlDecode(encoded);
  } catch {
    return { claim: fail("checkpoint_signature_malformed") };
  }
  let metadata: Awaited<ReturnType<CheckpointMetadata>>;
  try {
    metadata = await checkpointMetadata(cose);
  } catch {
    metadata = undefined;
  }
  if (metadata === undefined)
    return { claim: fail("checkpoint_signature_invalid") };
  const signed: SignedCheckpointFields = {
    log_id: metadata.logId,
    mmr_size: Number(metadata.size),
    root: metadata.root,
    key_id: metadata.keyId,
    timestamp: metadata.timestamp,
    prev_size: Number(metadata.previousSize),
    prev_root: metadata.previousRoot,
  };
  const findings = [
    ...SIGNED_CHECKPOINT_FIELDS.filter(
      (name) =>
        (Object.hasOwn(stated, name) &&
          !sameJson(stated[name], signed[name])) ||
        // The certificate's log_id is a second stated copy of the signed one
        // (bundle -01 §Completeness): either copy differing is one mismatch.
        (name === "log_id" &&
          Object.hasOwn(certificate, "log_id") &&
          !sameJson(certificate.log_id, signed.log_id)),
    ).map((name) => `checkpoint_field_mismatch:${name}`),
    ...(["log_id", "mmr_size", "root"] as const)
      .filter((name) => !Object.hasOwn(stated, name))
      .map((name) => `checkpoint_field_missing:${name}`),
  ];
  if (findings.length) return { claim: fail(...findings) };
  return { claim: pass(), signed, cose };
}

/**
 * A proof claim with no signed checkpoint behind it: a failure stays a
 * failure; anything else is not shown.
 */
function unanchored(claim: ClaimResult): ClaimResult {
  if (claim.status === "fail") return claim;
  return {
    status: "withheld",
    findings: [...new Set([...claim.findings, "checkpoint_unverified"])],
  };
}

/**
 * Each record's inclusion proof against the signed checkpoint's root and
 * size, for a producer-selected Bundle. With no signed checkpoint nothing is
 * shown (the caller withholds it).
 */
async function selectedMembership(
  bundle: Bundle,
  signed: SignedCheckpointFields | undefined,
): Promise<ClaimResult> {
  if (signed === undefined)
    return { status: "withheld", findings: ["checkpoint_unverified"] };
  const certificate = bundle.completeness_certificate;
  const members = object(certificate) ? certificate.memberships : undefined;
  if (
    !object(certificate) ||
    !object(members) ||
    certificate.range_root !== signed.root
  )
    return fail("completeness_certificate_invalid");
  const root = hex(signed.root);
  const ids = (Array.isArray(bundle.records) ? bundle.records : [])
    .filter(object)
    .map(capsuleIdOf);
  const findings: string[] = [],
    seen = new Set<number>();
  for (const id of ids) {
    const member = Object.hasOwn(members, id) ? members[id] : undefined;
    const coordinates = object(member) ? member.log_coordinates : undefined;
    if (!object(coordinates)) {
      findings.push(`membership_record_unbound:${id}`);
      continue;
    }
    const seq = coordinates.seq,
      index = coordinates.leaf_index;
    if (
      coordinates.log_id !== signed.log_id ||
      !integer(seq) ||
      !integer(index) ||
      seq < 1 ||
      index !== seq - 1 ||
      seen.has(seq)
    ) {
      findings.push(`membership_coordinates_invalid:${id}`);
      continue;
    }
    seen.add(seq);
    const proof = object(member)
      ? parseProof(member.inclusion_proof)
      : undefined;
    if (
      !proof ||
      !isHex64(id) ||
      proof.size !== signed.mmr_size ||
      proof.leaf_index !== index ||
      !(await verifyProof(root, id, proof, index))
    )
      findings.push(`membership_proof_invalid:${id}`);
  }
  for (const id of Object.keys(members).sort(byCodePoint))
    if (!ids.includes(id)) findings.push(`membership_record_unknown:${id}`);
  return findings.length ? fail(...findings) : pass();
}

/** Each record's `seq` as its membership's `log_coordinates` state it. */
function membershipSeqs(bundle: Bundle): Map<string, number> {
  const certificate = bundle.completeness_certificate;
  const members = object(certificate) ? certificate.memberships : undefined;
  const out = new Map<string, number>();
  if (object(members))
    for (const [id, member] of Object.entries(members)) {
      const coordinates = object(member) ? member.log_coordinates : undefined;
      const seq = object(coordinates) ? coordinates.seq : undefined;
      if (integer(seq)) out.set(id, seq);
    }
  return out;
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
// Load cll's COSE checkpoint authenticator through a dynamic import, so that a
// cll without it resolves to undefined instead of failing to load. The pinned
// cll exports it from both its Node and its browser entry.
type CheckpointMetadata = (cose: Uint8Array) => Promise<
  | {
      logId: string;
      size: bigint;
      root: string;
      keyId: string;
      timestamp: string;
      previousSize: bigint;
      previousRoot: string;
    }
  | undefined
>;
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
  // Without cll's COSE checkpoint authenticator, a present checkpoint cannot be
  // independently authenticated here, so it degrades to producer asserted
  // (checkpoint_unverified) rather than invalid; the three completeness claims
  // are still verified from the MMR.
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
  const range = parseRangeProof(certificate.range_proof);
  if (!range || checkpoint.mmr_size !== range.size) return undefined;
  const { fromSeq, toSeq, size, fromIndex, toIndex, witness } = range;
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
/** A certificate's `range_proof` members, or undefined when malformed. */
function parseRangeProof(raw: unknown):
  | {
      fromSeq: number;
      toSeq: number;
      size: number;
      fromIndex: number;
      toIndex: number;
      witness: string[];
    }
  | undefined {
  const range = object(raw) ? raw : undefined,
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
    !witness.every(isHex64)
  )
    return undefined;
  return { fromSeq, toSeq, size, fromIndex, toIndex, witness };
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
   * The strict checks and verdict over the same bytes, computed from
   * `verification` (`verifyBundle`'s `strict`, with no witness directory
   * and unsigned records allowed). Undefined where this runtime has no
   * Ed25519, so no verdict can be reached; that is never a failure. The
   * verdict is what a page states; whether it shows records is
   * `verification`'s alone.
   */
  readonly strict: StrictBundleResult | undefined;
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
 * A structural copy of JSON-shaped input: arrays (by index, re-reading
 * `length` each step) and plain objects (own enumerable string keys, each
 * read once) are copied, primitives are kept. Every reader verifies and reads
 * the copy, so an array's own iterator, which JSON never carries, is not
 * consulted. Keys are
 * defined, not assigned, so a parsed `__proto__` member stays a member. Any
 * other object is kept by reference and left as it is. Iterative, so input
 * nested beyond the stack is copied and then refused by the verifier, never
 * raised as a RangeError (#360).
 */
function ownedCopy<T>(value: T): T {
  const seen = new Map<object, unknown>();
  // One frame per container being copied, depth first: a member's subtree
  // is copied before the next member is read, so every value, getters
  // included, is read in the order the recursive copy read it.
  type Frame =
    | {
        readonly source: readonly unknown[];
        readonly out: unknown[];
        index: number;
      }
    | {
        readonly source: Record<string, unknown>;
        readonly out: Record<string, unknown>;
        readonly keys: readonly string[];
        index: number;
      };
  const frames: Frame[] = [];
  // The copy of `input`, opening a frame for a container not yet copied.
  const copyOf = (input: unknown): unknown => {
    if (input === null || typeof input !== "object" || !plain(input))
      return input;
    const done = seen.get(input);
    if (done !== undefined) return done;
    if (Array.isArray(input)) {
      const out: unknown[] = [];
      seen.set(input, out);
      frames.push({ source: input, out, index: 0 });
      return out;
    }
    const out: Record<string, unknown> = {};
    seen.set(input, out);
    frames.push({
      source: input as Record<string, unknown>,
      out,
      keys: Object.keys(input),
      index: 0,
    });
    return out;
  };
  const root = copyOf(value);
  while (frames.length > 0) {
    const frame = frames[frames.length - 1]!;
    if ("keys" in frame) {
      if (frame.index === frame.keys.length) {
        frames.pop();
        continue;
      }
      const key = frame.keys[frame.index++]!;
      Object.defineProperty(frame.out, key, {
        value: copyOf(frame.source[key]),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    } else {
      if (frame.index >= frame.source.length) {
        frames.pop();
        continue;
      }
      frame.out.push(copyOf(frame.source[frame.index++]));
    }
  }
  return root as T;
}

/**
 * Freeze an object graph the context owns: arrays and plain objects,
 * through data properties (accessors are never invoked). A
 * {@link ReadonlyMapView} freezes itself and its entries are frozen through
 * it. Iterative, like {@link ownedCopy}.
 */
function deepFreeze<T>(value: T): T {
  const seen = new WeakSet<object>();
  const pending: unknown[] = [value];
  while (pending.length > 0) {
    const next = pending.pop();
    if (next === null || typeof next !== "object" || seen.has(next)) continue;
    seen.add(next);
    if (next instanceof ReadonlyMapView) {
      for (const [key, entry] of next as ReadonlyMapView<unknown, unknown>)
        pending.push(key, entry);
      continue;
    }
    if (!plain(next)) continue;
    Object.freeze(next);
    for (const descriptor of Object.values(
      Object.getOwnPropertyDescriptors(next),
    ))
      if ("value" in descriptor) pending.push(descriptor.value);
  }
  return value;
}

/**
 * The plain result as the viewer reads it. The plain checks do not know a
 * producer-selected Bundle (`completeness.selection`, which the Bundle draft
 * does not define), so they read its selection as an interval and fail per-
 * record membership. When the strict checks read the Bundle as a selection
 * (`interval_coverage` carries `selection_not_checkable`), the viewer reads
 * interval coverage and per-record membership as they do, so the page, its
 * render gate and its check lists agree with the strict verdict (#361).
 * Every other claim is the plain one, and an INVALID selection is read
 * plainly.
 */
function readSelection(
  plain: BundleVerificationResult,
  strict: StrictBundleVerificationResult | undefined,
): BundleVerificationResult {
  // Only for a selection the strict checks did not reject: an INVALID one
  // keeps the plain reading, which refuses it as it always has, so this
  // never lets the page show a Bundle it refused before.
  return strict !== undefined &&
    strict.strict.verdict !== "INVALID" &&
    isProducerSelection(strict)
    ? {
        ...plain,
        intervalCoverage: strict.intervalCoverage,
        perRecordMembership: strict.perRecordMembership,
      }
    : plain;
}

/**
 * True when `result` reads its Bundle as a producer selection: the strict
 * checks' interval coverage, or a context's (`readSelection`), is not
 * checkable for it.
 */
export function isProducerSelection(result: BundleVerificationResult): boolean {
  return (
    result.intervalCoverage.status === "withheld" &&
    result.intervalCoverage.findings.includes(SELECTION_NOT_CHECKABLE)
  );
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
  // Every check hashes; with no SHA-256 there is no result (verifyBundle).
  if (digestCapability() === "none") throw new Sha256UnavailableError();
  // Settles ed25519Available() for every reader of this context.
  const ed25519 = await probeEd25519();
  const { plain, strict } = await verifyPlainAndStrict(owned, {
    strict: ed25519,
  });
  return contextFrom(
    owned,
    readSelection(plain, strict),
    strict?.strict,
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
    context.strict,
    countersigners === undefined
      ? undefined
      : deepFreeze(ownedCopy(countersigners)),
    context,
  );
}

function contextFrom(
  bundle: unknown,
  verification: BundleVerificationResult,
  strict: StrictBundleResult | undefined,
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
    strict,
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

// -- the producer ---------------------------------------------------------------
//
// `buildEvidenceBundle` assembles a Bundle from a `ProofSource` and checks the
// result with strict `verifyBundle` before returning it. It holds no key and
// trusts nothing the source returns: the checkpoint is verified from its COSE
// form, and every proof and record is checked by the strict verifier.

/** The producer refused to build the Bundle; the message says why. */
export class BundleBuildError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "BundleBuildError";
  }
}

/**
 * A record as a store holds it: the Capsule's JSON bytes and its Producer
 * Envelope bytes (empty when the record is unsigned).
 */
export interface StoredRecord {
  readonly capsule: Uint8Array;
  readonly producerEnvelope: Uint8Array;
}

/** A membership's `inclusion_proof`, in the Bundle's wire shape. */
export interface BundleInclusionProof {
  readonly v: 1;
  readonly kind: "inclusion";
  readonly size: number;
  readonly leaf_index: number;
  readonly witness: readonly string[];
  readonly peaks_left: readonly string[];
  readonly peaks_right: readonly string[];
}

/** A completeness certificate's `range_proof`, in the Bundle's wire shape. */
export interface BundleRangeProof {
  readonly from_seq: number;
  readonly to_seq: number;
  readonly size: number;
  readonly from_index: number;
  readonly to_index: number;
  readonly witness: readonly string[];
}

/**
 * The read-only proof material {@link buildEvidenceBundle} reads.
 *
 * - `checkpoint()`: the signed CLL COSE checkpoint the Bundle is built against.
 * - `leaves()`: the 32-byte value of every leaf, seq 1 to
 *   `leafCount(mmr_size)`, in order; a record's value is its Capsule ID.
 * - `record(capsuleId)`: the stored record, or `undefined` when the log does
 *   not hold that leaf as a record. Any other failure rejects.
 * - `inclusionProof(seq)`: the inclusion proof for that leaf at the
 *   checkpoint's size.
 * - `rangeProof(firstSeq)`: the range proof over `[firstSeq, tip]`.
 */
export interface ProofSource {
  checkpoint(): Promise<Uint8Array>;
  leaves(): Promise<readonly Uint8Array[]>;
  record(capsuleId: string): Promise<StoredRecord | undefined>;
  inclusionProof(seq: number): Promise<BundleInclusionProof>;
  rangeProof(firstSeq: number): Promise<BundleRangeProof>;
}

/** The CLL backend members {@link proofSourceFromCll} reads. */
export interface CllProofBackend {
  scanEntries(
    afterSeq: bigint,
    limit: number,
  ): Promise<readonly { readonly value: Uint8Array }[]>;
  loadCll(): Promise<{
    readonly nodes: readonly Uint8Array[];
    readonly checkpoint?: Uint8Array;
    readonly checkpointSize?: bigint;
    readonly checkpointIndexedSeq?: bigint;
  }>;
}

/**
 * A record store: `get` resolves to the Capsule's bytes and its Producer
 * Envelope bytes, and rejects with an error whose `code` is `"not_found"` for
 * a record it does not hold.
 */
export interface RecordStore {
  get(capsuleId: string): Promise<{
    readonly capsule: Uint8Array;
    readonly producerEnvelope?: Uint8Array;
  }>;
}

export interface BuildEvidenceBundleOptions {
  /** The Capsule ID the Bundle is built around. */
  readonly root: string;
  /**
   * Required: the first seq of a range proof that ends at the checkpoint tip,
   * carrying every record in `[intervalFrom, tip]` and none below it; or
   * `null` for no range proof, each record proven alone
   * (`completeness.selection: "producer-selected"`, read as INCOMPLETE).
   */
  readonly intervalFrom: number | null;
  /** The citation depth from `root`; 2 when not given. */
  readonly closureDepth?: number;
  /** Further records to carry. */
  readonly include?: readonly string[];
  /** The Bundle-level disclosure overlay, by Capsule ID and member. */
  readonly disclosures?: Readonly<
    Record<string, Readonly<Record<string, unknown>>>
  >;
  readonly suppressedFields?: readonly string[];
  /**
   * Derived from the overlay when not given; a given `all` must reveal every
   * committed, unsuppressed member of each record the overlay discloses.
   */
  readonly payloadsMode?: "all" | "selected";
  /** A raw 32-byte Ed25519 public key: adds `producer-key/v1`. */
  readonly producerKey?: Uint8Array;
  /** Extension blocks of any kind but `producer-key/v1` and `composed/v1`. */
  readonly extensions?: Readonly<Record<string, unknown>>;
  /** The producer's self-report, carried as given. */
  readonly verification?: Readonly<Record<string, unknown>>;
}

export interface BuildUnprovenBundleOptions {
  readonly root: string;
  readonly closureDepth?: number;
  readonly disclosures?: Readonly<
    Record<string, Readonly<Record<string, unknown>>>
  >;
  readonly suppressedFields?: readonly string[];
}

// Extension kinds this package owns; `extensions` cannot set them.
const OWNED_EXTENSIONS = ["producer-key/v1", COMPOSED_KIND] as const;
const PAYLOADS_MODES = ["all", "selected"] as const;

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const eligible = (member: string): boolean =>
  Object.hasOwn(disclosureEligibleFields, member);
const sortedText = (values: Iterable<string>): string =>
  JSON.stringify([...values].sort(byCodePoint));

/**
 * A {@link ProofSource} over a CLL backend (`scanEntries` and `loadCll`) and
 * a record store. The proofs are built from the backend's MMR nodes at the
 * latest checkpoint's size. The backend state is read once, on first use, and
 * the source serves that one consistent snapshot; a checkpoint cut later is
 * seen only by a new source.
 */
export function proofSourceFromCll(
  backend: CllProofBackend,
  records: RecordStore,
): ProofSource {
  let loaded:
    | Promise<{
        state: Awaited<ReturnType<CllProofBackend["loadCll"]>>;
        tree: MmrTree;
      }>
    | undefined;
  const load = () =>
    (loaded ??= backend
      .loadCll()
      .then((state) => ({ state, tree: new MmrTree(state.nodes) })));
  const signed = async () => {
    const { state, tree } = await load();
    if (state.checkpoint === undefined || state.checkpointSize === undefined)
      throw new BundleBuildError(
        "the log has no checkpoint: nothing can be proven until one is cut",
      );
    return { cose: state.checkpoint, size: state.checkpointSize, tree };
  };
  return {
    async checkpoint() {
      return Uint8Array.from((await signed()).cose);
    },
    async leaves() {
      const { state } = await load();
      if (state.checkpoint === undefined) return [];
      const want = state.checkpointIndexedSeq ?? 0n,
        out: Uint8Array[] = [];
      while (BigInt(out.length) < want) {
        const remaining = want - BigInt(out.length);
        const page = await backend.scanEntries(
          BigInt(out.length),
          remaining < 1000n ? Number(remaining) : 1000,
        );
        if (!page.length) break;
        for (const entry of page) out.push(Uint8Array.from(entry.value));
      }
      return out;
    },
    async record(capsuleId) {
      try {
        const stored = await records.get(capsuleId);
        return {
          capsule: stored.capsule,
          producerEnvelope: stored.producerEnvelope ?? new Uint8Array(),
        };
      } catch (error) {
        // The record-store contract's not-found code.
        if (
          error !== null &&
          typeof error === "object" &&
          (error as { code?: unknown }).code === "not_found"
        )
          return undefined;
        throw error;
      }
    },
    async inclusionProof(seq) {
      const { size, tree } = await signed();
      const proof = await inclusionProof(tree, BigInt(seq - 1), size);
      return {
        v: 1,
        kind: "inclusion",
        size: proof.size,
        leaf_index: proof.leaf_index,
        witness: [...proof.witness],
        peaks_left: [...proof.peaks_left],
        peaks_right: [...proof.peaks_right],
      };
    },
    async rangeProof(firstSeq) {
      const { size, tree } = await signed();
      const tip = leafCount(size) ?? 0n;
      const proof = await rangeProof(
        tree,
        BigInt(firstSeq - 1),
        tip - 1n,
        size,
      );
      return {
        from_seq: firstSeq,
        to_seq: Number(tip),
        size: proof.size,
        from_index: proof.from_index,
        to_index: proof.to_index,
        witness: [...proof.witness],
      };
    },
  };
}

function committedMembers(record: Bundle): string[] {
  return Object.entries(disclosureEligibleFields)
    .filter(
      ([, path]) =>
        typeof resolveDisclosurePath(record as ParsedJson, path) === "string",
    )
    .map(([member]) => member)
    .sort(byCodePoint);
}

function copyDisclosures(raw: unknown): Record<string, unknown> {
  if (raw === undefined || raw === null) return {};
  if (!object(raw)) throw new BundleBuildError("disclosures is not an object");
  return Object.fromEntries(
    Object.entries(raw).map(([id, members]) => [
      id,
      object(members) ? { ...members } : members,
    ]),
  );
}

function checkOptions(
  closureDepth: unknown,
  disclosures: Record<string, unknown>,
  suppressedFields: readonly string[],
  payloadsMode: unknown,
  extensions: Record<string, unknown>,
): void {
  if (!integer(closureDepth) || closureDepth < 0)
    throw new BundleBuildError(
      "closureDepth must be a non-negative safe integer",
    );
  if (
    payloadsMode !== undefined &&
    !PAYLOADS_MODES.includes(payloadsMode as "all")
  )
    throw new BundleBuildError(
      `payloadsMode must be one of ${JSON.stringify(PAYLOADS_MODES)}`,
    );
  const ineligible = suppressedFields.filter((member) => !eligible(member));
  if (ineligible.length)
    throw new BundleBuildError(
      `suppressedFields names members that are not disclosure-eligible: ${sortedText(ineligible)}`,
    );
  for (const [id, members] of Object.entries(disclosures)) {
    if (!object(members))
      throw new BundleBuildError(`disclosures[${id}] is not an object`);
    const bad = Object.keys(members).filter((member) => !eligible(member));
    if (bad.length)
      throw new BundleBuildError(
        `disclosures[${id}] names members that are not disclosure-eligible: ${sortedText(bad)}`,
      );
    const both = Object.keys(members).filter((member) =>
      suppressedFields.includes(member),
    );
    if (both.length)
      throw new BundleBuildError(
        `disclosures[${id}] reveals member(s) declared suppressed: ${sortedText(both)}`,
      );
  }
  const owned = OWNED_EXTENSIONS.filter((kind) =>
    Object.hasOwn(extensions, kind),
  );
  if (owned.length)
    throw new BundleBuildError(
      `extensions cannot set kinds this producer owns: ${sortedText(owned)}`,
    );
}

/**
 * Records reached from `root` within `depth` citation edges (root included),
 * and the targets `lookup` does not hold, in first-seen order: the traversal
 * {@link verifyBundle} checks graph closure with.
 */
async function closure(
  root: string,
  depth: number,
  lookup: (capsuleId: string) => Promise<Bundle | undefined>,
): Promise<{ found: Map<string, Bundle>; missing: string[] }> {
  const rootRecord = await lookup(root);
  if (rootRecord === undefined)
    throw new BundleBuildError(`root ${root}: no such record`);
  const found = new Map([[root, rootRecord]]),
    missing: string[] = [];
  let frontier = [root];
  for (let level = 0; level < depth && frontier.length; level += 1) {
    const next: string[] = [];
    for (const source of frontier)
      for (const target of citations(found.get(source)!)) {
        if (found.has(target) || missing.includes(target)) continue;
        const record = await lookup(target);
        if (record === undefined) missing.push(target);
        else {
          found.set(target, record);
          next.push(target);
        }
      }
    frontier = next;
  }
  return { found, missing };
}

function completenessBlock(
  records: readonly Bundle[],
  closureDepth: number,
  missing: readonly string[],
  disclosures: Record<string, unknown>,
  suppressedFields: readonly string[],
  payloadsMode: string | undefined,
): Record<string, unknown> {
  const suppressed = [...new Set(suppressedFields)].sort(byCodePoint);
  const unrevealed: [string, string][] = [];
  for (const record of records) {
    const id = capsuleIdOf(record),
      revealed = disclosures[id];
    for (const member of committedMembers(record))
      if (
        !suppressed.includes(member) &&
        !(object(revealed) && Object.hasOwn(revealed, member))
      )
        unrevealed.push([id, member]);
  }
  const overlay = Object.keys(disclosures).length > 0;
  if (payloadsMode === "all" && overlay) {
    const gaps = unrevealed.filter(([id]) => Object.hasOwn(disclosures, id));
    if (gaps.length)
      throw new BundleBuildError(
        `payloadsMode all, but the disclosures overlay does not reveal: ${gaps
          .map(([id, member]) => `${id}:${member}`)
          .join(", ")}`,
      );
  }
  return {
    closure_depth: closureDepth,
    records_mode: missing.length ? "declared_incomplete" : "complete",
    payloads_mode: payloadsMode ?? (unrevealed.length ? "selected" : "all"),
    suppressed_fields: suppressed,
    missing: [...missing],
  };
}

const noCanonicalDigest = (detail?: string): BundleBuildError =>
  new BundleBuildError(
    `the bundle has no canonical digest: extensions and verification must hold only JSON that canonicalizes (no fractional numbers or integers beyond 2**53 - 1)${detail === undefined ? "" : `; ${detail}`}`,
  );

/**
 * Refuse caller input that has no canonical form before anything reads it,
 * and return a structural copy of each value so the Bundle never aliases a
 * caller object. JCS, the bundle digest's own canonicalization, rejects
 * fractional and unsafe numbers and nesting beyond its depth limit without
 * recursing past it; the copy is its canonical bytes decoded again.
 */
function canonicalInput<T extends Record<string, unknown>>(input: T): T {
  const out: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(input))
    if (value !== undefined) {
      let bytes: Uint8Array;
      try {
        bytes = jcs(value);
      } catch (error) {
        throw noCanonicalDigest(
          `${name}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      out[name] = plainIntegers(decodeStrictJson(bytes));
    }
  return out as T;
}

/**
 * A copy of a source's hash list made by index, not through its iterator, so
 * holes and non-hash members are seen; undefined unless every member is a
 * hash. Called inside the caller's error boundary.
 */
function hashList(list: readonly string[]): string[] | undefined {
  const out: unknown[] = [];
  for (let index = 0; index < list.length; index += 1) out.push(list[index]);
  return out.every(isHex64) ? out : undefined;
}

/**
 * A source's inclusion proof, parsed as the verifier parses it, with only its
 * wire fields copied; parsing and copying share one error boundary.
 */
function inclusionProofWire(seq: number, raw: unknown): BundleInclusionProof {
  let wire: BundleInclusionProof | undefined;
  try {
    const proof = parseProof(raw);
    const witness = proof && hashList(proof.witness),
      left = proof && hashList(proof.peaks_left),
      right = proof && hashList(proof.peaks_right);
    if (proof && witness && left && right)
      wire = {
        v: 1,
        kind: "inclusion",
        size: proof.size,
        leaf_index: proof.leaf_index,
        witness,
        peaks_left: left,
        peaks_right: right,
      };
  } catch {
    wire = undefined; // a getter that throws, say
  }
  if (wire === undefined)
    throw new BundleBuildError(
      `the source's inclusion proof for seq ${seq} is malformed`,
    );
  return wire;
}

/**
 * A source's range proof, parsed as the verifier parses it, with only its
 * wire fields copied; parsing and copying share one error boundary.
 */
function rangeProofWire(raw: unknown): BundleRangeProof {
  let wire: BundleRangeProof | undefined;
  try {
    const range = parseRangeProof(raw);
    const witness = range && hashList(range.witness);
    if (range && witness)
      wire = {
        from_seq: range.fromSeq,
        to_seq: range.toSeq,
        size: range.size,
        from_index: range.fromIndex,
        to_index: range.toIndex,
        witness,
      };
  } catch {
    wire = undefined;
  }
  if (wire === undefined)
    throw new BundleBuildError("the source's range proof is malformed");
  return wire;
}

/**
 * The stored record as a Bundle carries it: the Capsule, with a claimed
 * Producer Envelope re-inlined as its local-only `signature` and `key_id`
 * (both outside the `capsule_id` preimage).
 */
async function decodeRecord(
  capsuleId: string,
  stored: StoredRecord,
): Promise<Bundle> {
  let capsule: unknown;
  try {
    if (!(stored.capsule instanceof Uint8Array))
      throw new TypeError("capsule is not bytes");
    capsule = plainIntegers(decodeStrictJson(stored.capsule));
  } catch (error) {
    throw new BundleBuildError(
      `record ${capsuleId}: the stored capsule is not a JSON object (${String(error)})`,
    );
  }
  if (!object(capsule))
    throw new BundleBuildError(
      `record ${capsuleId}: the stored capsule is not a JSON object`,
    );
  if (capsule.capsule_id !== capsuleId)
    throw new BundleBuildError(
      `record ${capsuleId}: the store returned a different capsule`,
    );
  // Only a verified envelope may claim authorship: inline copies are dropped.
  delete capsule.signature;
  delete capsule.key_id;
  const envelope = stored.producerEnvelope ?? new Uint8Array();
  if (envelope.length) {
    const checked = await verifyProducerEnvelope(capsuleId, envelope);
    if (!checked.ok || checked.publicKey === undefined)
      throw new BundleBuildError(
        `record ${capsuleId}: its producer envelope does not verify`,
      );
    setMember<unknown>(capsule, "signature", toHex(envelope));
    setMember<unknown>(capsule, "key_id", toHex(checked.publicKey));
  }
  return capsule;
}

/**
 * Build an Evidence Bundle around `options.root` from `source`
 * ({@link BuildEvidenceBundleOptions}).
 *
 * Needs `@action-state-group/cll` for its COSE checkpoint verifier. Rejects
 * with {@link BundleBuildError} on every refusal, including any result strict
 * {@link verifyBundle} calls INVALID; a declared-incomplete closure or an
 * unsigned record is stated, not refused.
 */
export async function buildEvidenceBundle(
  source: ProofSource,
  options: BuildEvidenceBundleOptions,
): Promise<Record<string, unknown>> {
  const checkpointMetadata = await loadCheckpointMetadata();
  if (!checkpointMetadata)
    throw new BundleBuildError(
      "building a Bundle needs @action-state-group/cll's checkpoint verifier: install @action-state-group/cll",
    );
  const { root, intervalFrom, producerKey } = options;
  // By index, so a hole (which `every` would skip) is refused too.
  const include: string[] = [];
  if (options.include !== undefined && !Array.isArray(options.include))
    throw new BundleBuildError("include must be a list of Capsule IDs");
  for (let index = 0; index < (options.include?.length ?? 0); index += 1) {
    const id: unknown = options.include![index];
    if (typeof id !== "string")
      throw new BundleBuildError("include must be a list of Capsule IDs");
    include.push(id);
  }
  if (
    producerKey !== undefined &&
    (!(producerKey instanceof Uint8Array) || producerKey.length !== 32)
  )
    throw new BundleBuildError(
      "producerKey must be a raw 32-byte Ed25519 public key",
    );
  for (const name of ["extensions", "verification"] as const)
    if (options[name] !== undefined && !object(options[name]))
      throw new BundleBuildError(`${name} must be a JSON object`);
  const copied = canonicalInput({
    disclosures: options.disclosures,
    extensions: options.extensions,
    verification: options.verification,
  });
  const closureDepth = options.closureDepth ?? 2,
    suppressedFields = options.suppressedFields ?? [],
    disclosures = copyDisclosures(copied.disclosures),
    extensions: Record<string, unknown> = { ...copied.extensions };
  checkOptions(
    closureDepth,
    disclosures,
    suppressedFields,
    options.payloadsMode,
    extensions,
  );
  if (
    intervalFrom === undefined ||
    (intervalFrom !== null && (!integer(intervalFrom) || intervalFrom < 1))
  )
    throw new BundleBuildError(
      "intervalFrom is required: a seq of at least 1, or null for no range proof",
    );

  const cose = await source.checkpoint();
  let signed: Awaited<ReturnType<CheckpointMetadata>>;
  try {
    signed =
      cose instanceof Uint8Array ? await checkpointMetadata(cose) : undefined;
  } catch {
    signed = undefined;
  }
  const tipCount = signed === undefined ? undefined : leafCount(signed.size);
  if (signed === undefined || tipCount === undefined)
    throw new BundleBuildError("the checkpoint does not verify");
  const tip = Number(tipCount);
  const leaves = [...(await source.leaves())];
  if (
    leaves.length !== tip ||
    leaves.some(
      (value) => !(value instanceof Uint8Array) || value.length !== 32,
    )
  )
    throw new BundleBuildError(
      `the source gave ${leaves.length} leaves; the checkpoint covers ${tip} 32-byte leaves`,
    );
  const seqOf = new Map<string, number>();
  leaves.forEach((value, index) => {
    const id = toHex(value);
    if (!seqOf.has(id)) seqOf.set(id, index + 1);
  });

  const lookup = async (capsuleId: string): Promise<Bundle | undefined> => {
    const stored = await source.record(capsuleId);
    if (stored === undefined || stored === null) return undefined;
    if (!seqOf.has(capsuleId))
      throw new BundleBuildError(
        `record ${capsuleId} is not a leaf at or below the checkpoint (not yet covered, or not in this log)`,
      );
    return decodeRecord(capsuleId, stored);
  };

  const { found: carried, missing } = await closure(root, closureDepth, lookup);
  for (const capsuleId of include)
    if (!carried.has(capsuleId)) {
      const record = await lookup(capsuleId);
      if (record === undefined)
        throw new BundleBuildError(`include: no such record: ${capsuleId}`);
      carried.set(capsuleId, record);
    }

  const certificate: Record<string, unknown> = {
    log_id: signed.logId,
    range_root: signed.root,
  };
  if (intervalFrom !== null) {
    if (intervalFrom > tip)
      throw new BundleBuildError(
        `intervalFrom ${intervalFrom} is past the checkpoint tip ${tip}`,
      );
    const below = [...carried.keys()]
      .map((id) => [seqOf.get(id)!, id] as const)
      .filter(([seq]) => seq < intervalFrom)
      .sort(([a, x], [b, y]) => a - b || byCodePoint(x, y));
    if (below.length)
      throw new BundleBuildError(
        `record(s) below intervalFrom ${intervalFrom}: ${below
          .map(([seq, id]) => `${id} (seq ${seq})`)
          .join(", ")}; lower it or build without a range`,
      );
    for (let seq = intervalFrom; seq <= tip; seq += 1) {
      const capsuleId = toHex(leaves[seq - 1]!);
      if (carried.has(capsuleId)) continue;
      const record = await lookup(capsuleId);
      if (record === undefined)
        throw new BundleBuildError(
          `seq ${seq} in the interval is not a record the source holds; a range cannot cover it: start the interval after it or build without a range`,
        );
      carried.set(capsuleId, record);
    }
    certificate.first_seq = intervalFrom;
    certificate.last_seq = tip;
    certificate.body_digests = leaves
      .slice(intervalFrom - 1, tip)
      .map((value) => toHex(value));
    certificate.range_proof = rangeProofWire(
      await source.rangeProof(intervalFrom),
    );
  }

  const ordered = [...carried.keys()].sort(
    (a, b) => seqOf.get(a)! - seqOf.get(b)!,
  );
  const unknown = Object.keys(disclosures).filter((id) => !carried.has(id));
  if (unknown.length)
    throw new BundleBuildError(
      `disclosures given for record(s) the bundle does not carry: ${sortedText(unknown)}`,
    );
  const records = ordered.map((id) => carried.get(id)!);
  const memberships: Record<string, unknown> = {};
  for (const id of ordered) {
    const seq = seqOf.get(id)!;
    setMember(memberships, id, {
      log_coordinates: { log_id: signed.logId, seq, leaf_index: seq - 1 },
      inclusion_proof: inclusionProofWire(
        seq,
        await source.inclusionProof(seq),
      ),
    });
  }
  certificate.memberships = memberships;
  const completeness = completenessBlock(
    records,
    closureDepth,
    missing,
    disclosures,
    suppressedFields,
    options.payloadsMode,
  );
  if (intervalFrom === null)
    completeness.selection = SELECTION_PRODUCER_SELECTED;
  const bundle: Bundle = {
    bundle_version: "2",
    bundle_kind: "evidence-bundle/v2",
    root,
    records,
    completeness,
    completeness_certificate: certificate,
    checkpoint: {
      log_id: signed.logId,
      mmr_size: Number(signed.size),
      root: signed.root,
      prev_size: Number(signed.previousSize),
      prev_root: signed.previousRoot,
      key_id: signed.keyId,
      timestamp: signed.timestamp,
      cose: encodeBase64Url(cose),
    },
  };
  if (Object.keys(disclosures).length) bundle.disclosures = disclosures;
  if (producerKey !== undefined)
    extensions["producer-key/v1"] = { public_key: toHex(producerKey) };
  if (Object.keys(extensions).length) bundle.extensions = extensions;
  if (copied.verification !== undefined)
    bundle.verification = copied.verification;
  return selfChecked(bundle);
}

async function selfChecked(bundle: Bundle): Promise<Bundle> {
  const result = await verifyBundle(bundle, { strict: true });
  if (result.bundleDigest === undefined) throw noCanonicalDigest();
  if (result.strict.verdict === "INVALID") {
    const failed = result.strict.claims
      .filter((claim) => claim.status === "fail")
      .map(
        (claim) =>
          `${claim.name}: ${claim.findings.join(", ") || claim.status}`,
      );
    throw new BundleBuildError(
      `the bundle does not verify: ${failed.join("; ") || "not an evidence bundle"}`,
    );
  }
  return bundle;
}

/**
 * An Evidence Bundle with no log proof: no checkpoint and no certificate, for
 * Capsules that belong to no log. Every given record is carried; the closure
 * from `root` decides `missing`. Strict {@link verifyBundle} reads it as
 * INCOMPLETE. Rejects with {@link BundleBuildError}.
 */
export async function buildUnprovenBundle(
  given: readonly Readonly<Record<string, unknown>>[],
  options: BuildUnprovenBundleOptions,
): Promise<Record<string, unknown>> {
  const { root } = options;
  const copied = canonicalInput({
    records: given,
    disclosures: options.disclosures,
  });
  if (!Array.isArray(copied.records))
    throw new BundleBuildError("records must be a list of Capsules");
  const records = copied.records as readonly Readonly<
    Record<string, unknown>
  >[];
  const closureDepth = options.closureDepth ?? 2,
    suppressedFields = options.suppressedFields ?? [],
    disclosures = copyDisclosures(copied.disclosures);
  checkOptions(closureDepth, disclosures, suppressedFields, undefined, {});
  const ids = records.map((record) =>
    object(record) ? record.capsule_id : undefined,
  );
  if (!ids.every((id): id is string => typeof id === "string"))
    throw new BundleBuildError("every record needs a capsule_id");
  if (new Set(ids).size !== ids.length)
    throw new BundleBuildError("duplicate capsule_id among the records");
  const byId = new Map(ids.map((id, index) => [id, { ...records[index] }]));
  if (!byId.has(root))
    throw new BundleBuildError(`root ${root} is not among the records`);
  const unknown = Object.keys(disclosures).filter((id) => !byId.has(id));
  if (unknown.length)
    throw new BundleBuildError(
      `disclosures given for record(s) the bundle does not carry: ${sortedText(unknown)}`,
    );
  const { missing } = await closure(root, closureDepth, async (id) =>
    byId.get(id),
  );
  const carried = ids.map((id) => byId.get(id)!);
  const bundle: Bundle = {
    bundle_version: "2",
    bundle_kind: "evidence-bundle/v2",
    root,
    records: carried,
    completeness: completenessBlock(
      carried,
      closureDepth,
      missing,
      disclosures,
      suppressedFields,
      undefined,
    ),
  };
  if (Object.keys(disclosures).length) bundle.disclosures = disclosures;
  return selfChecked(bundle);
}
