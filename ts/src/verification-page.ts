import type {
  BundleVerificationResult,
  ClaimResult,
  StrictBundleResult,
  StrictClaim,
  StrictClaimName,
  VerifiedBundleContext,
  ExtensionInterpreterId,
  ExtensionResult,
} from "./bundle.js";
import { isProducerSelection } from "./bundle.js";
import type { CountersignatureStamp } from "./countersignature-stamp.js";
import type { VerificationResult } from "./verify.js";

export type CheckStatus = "pass" | "withheld" | "fail" | "not_checked";

export interface CheckSummary {
  readonly name: string;
  readonly status: CheckStatus;
  /** Exactly five words -- never "proves"/"certificate"/"tamper-proof"/"first". */
  readonly result: string;
}

/** A receipt's grade WORD, read from the receipt header -- never a client-ladder word. */
export type ReceiptGradeWord = "consistency-verified" | "existence-and-time";

/**
 * How the verification page shows a receipt's grade. This runtime does not
 * check witness receipts, so the shown text says the grade is the receipt's
 * claim and never calls it verified. The grade word itself is unchanged.
 */
export const RECEIPT_GRADE_DISPLAY: Readonly<Record<ReceiptGradeWord, string>> =
  Object.freeze({
    "consistency-verified": "consistency claimed (not checked here)",
    "existence-and-time": "existence and time claimed (not checked here)",
  });

export interface ReceiptEntry {
  readonly witness: string;
  readonly grade: ReceiptGradeWord;
  readonly time: string;
}

export interface CompletenessStatement {
  readonly closureDepth?: number;
  readonly recordsMode?: string;
  readonly payloadsMode?: string;
  readonly suppressedFields: readonly string[];
}

/**
 * One supplied record's own standing under the checkpoint, read from the
 * verifier's per-record membership claim and nothing else. `checkpointed`
 * -- bound to the range root by its own inclusion proof, stated only when
 * the claim established coverage (see `CoverageStatement`); `uncheckpointed`
 * -- supplied with no membership entry at all (the verifier's
 * `membership_record_unbound`); `membership_invalid` -- a membership entry
 * was supplied but did not verify (`membership_proof_invalid`,
 * `membership_coordinates_missing`, `membership_coordinates_invalid`,
 * `membership_record_unknown`); `unverified` -- the verifier never reached
 * this record's proof, or stopped on a finding that is not this record's
 * own (no memberships object, a certificate, range-proof or checkpoint
 * failure, a missing or duplicated sequence), so nothing about its standing
 * is established. A record's status is its own: it is never inherited from
 * a neighbour and never summarised away -- and never defaulted to
 * `checkpointed` by the absence of a finding.
 */
export type RecordCoverageStatus =
  | "checkpointed"
  | "uncheckpointed"
  | "membership_invalid"
  | "unverified";

export interface RecordCoverage {
  readonly capsuleId: string;
  readonly status: RecordCoverageStatus;
}

/**
 * Whether the per-record membership claim established each supplied
 * record's standing. `established` -- the claim passed, or failed only
 * because some records are bound to no log position (the accepted
 * relaxation); `not_established` -- the claim failed on at least one
 * finding that is not a clean unbound record, named in `reason`;
 * `withheld` -- the claim was never evaluated (no checkpoint or no
 * certificate), so there is no standing to list at all.
 */
export type CoverageStatement =
  | { readonly status: "established" }
  | { readonly status: "not_established"; readonly reason: string }
  | { readonly status: "withheld"; readonly reason: string };

/**
 * The semantics cell of an uninterpreted extension whose block the bundle
 * digest covers. Exact user-facing wording: covered bytes are not understood
 * bytes, and this line never lets the first read as the second.
 */
export const EXTENSION_NOT_INTERPRETED =
  "Covered by the file's fingerprint; not interpreted by this page's checks";
/**
 * The same cell when the bundle digest could not be computed: nothing about
 * the block's bytes was verified either, so the line must not claim it.
 */
export const EXTENSION_NOT_INTERPRETED_NOT_COVERED =
  "Not covered by the file's fingerprint; not interpreted by this page's checks";
/**
 * The semantics cell of an extension a module this page ran shows, by
 * whether the bundle digest covers the block: a block a module shows is not
 * thereby covered, so the cell always says which.
 */
export const EXTENSION_SHOWN = Object.freeze({
  covered: "Shown by the page's module; covered by the file's fingerprint",
  notCovered:
    "Shown by the page's module; not covered by the file's fingerprint",
} as const);
/**
 * The same for an extension the core itself reads (the presentation header
 * and the countersignature stamp), which no module shows.
 */
export const EXTENSION_READ_BY_PAGE = Object.freeze({
  covered: "Read by this page itself; covered by the file's fingerprint",
  notCovered: "Read by this page itself; not covered by the file's fingerprint",
} as const);
// The interpreters that are part of the core, not of a page module.
const CORE_INTERPRETERS: ReadonlySet<ExtensionInterpreterId> = new Set([
  "presentation-header",
  "countersignature-stamp",
]);

/**
 * One row per `extensions` member, in kind order: its id, whether the bundle
 * digest covers it, and who (if anyone) applied its meaning. `interpreter`
 * is set only for a block this rendering actually interpreted.
 */
export interface ExtensionRow {
  readonly id: string;
  readonly integrity: "covered" | "not covered";
  readonly interpreter?: ExtensionInterpreterId;
  /** One of the shown, read-by-page or not-interpreted lines. */
  readonly semantics: string;
}

/**
 * The verification page's extension rows. `applied`, when given, is the set
 * of interpreters this rendering actually ran: an extension the library can
 * interpret but whose module did not render (a contract-report/v1 block when
 * no contract-report module drew the page, say) is shown as not interpreted, because here
 * its meaning was not applied. Omitted, the verifier's status stands.
 */
export function extensionRows(
  extensions: readonly ExtensionResult[],
  applied?: ReadonlySet<ExtensionInterpreterId>,
): readonly ExtensionRow[] {
  return extensions.map((extension): ExtensionRow => {
    const integrity = extension.integrityCovered ? "covered" : "not covered";
    if (
      extension.status === "interpreted" &&
      (applied === undefined || applied.has(extension.interpreter))
    )
      return {
        id: extension.kind,
        integrity,
        interpreter: extension.interpreter,
        semantics: (CORE_INTERPRETERS.has(extension.interpreter)
          ? EXTENSION_READ_BY_PAGE
          : EXTENSION_SHOWN)[
          extension.integrityCovered ? "covered" : "notCovered"
        ],
      };
    return {
      id: extension.kind,
      integrity,
      semantics: extension.integrityCovered
        ? EXTENSION_NOT_INTERPRETED
        : EXTENSION_NOT_INTERPRETED_NOT_COVERED,
    };
  });
}

export interface VerificationPageModel {
  readonly bundleDigest?: string;
  readonly checkpointRoot?: string;
  readonly checkpointSize?: number;
  readonly receipts: readonly ReceiptEntry[];
  /**
   * True when a checkpoint is supplied but no transparency-service receipt
   * is: the checkpoint is at most producer-signed, so the log witnesses
   * only itself.
   */
  readonly selfWitnessed: boolean;
  /** Every supplied record, in bundle order, with its own coverage status. */
  readonly records: readonly RecordCoverage[];
  /** Records with status `uncheckpointed`: unbound and nothing else wrong. */
  readonly uncheckpointedCount: number;
  readonly coverage: CoverageStatement;
  readonly completeness?: CompletenessStatement;
  readonly checks: readonly CheckSummary[];
  /** One row per supplied extension (empty when the bundle carries none). */
  readonly extensions: readonly ExtensionRow[];
  /** Which checks this page ran, which failed, and which it did not run. */
  readonly checkLists: VerificationCheckLists;
  readonly verifyIndependentlyLine: string;
}

const UNBOUND = "membership_record_unbound:";
// A membership entry that was supplied but rejected. The verifier emits
// coordinates_* and record_unknown BEFORE it binds the record, so each of
// those also gets a `membership_record_unbound` twin; the rejected entry wins
// over the twin. (`membership_seq_duplicate` is keyed by seq, not capsule_id,
// and cannot be attributed to a record from here.)
const INVALID =
  /^membership_(?:proof_invalid|coordinates_missing|coordinates_invalid|record_unknown):(.+)$/u;

function invalidRecordIds(verified: BundleVerificationResult): Set<string> {
  return new Set(
    verified.perRecordMembership.findings.flatMap((finding) => {
      const match = INVALID.exec(finding);
      return match === null ? [] : [match[1]!];
    }),
  );
}

/**
 * The capsule_ids of supplied records the verifier found bound to no log
 * position -- present in `records`, absent from `memberships`. These are the
 * only per-record membership findings that describe a record's coverage
 * rather than a broken proof: a record whose supplied entry was rejected is
 * not unbound, even though the verifier also emits the unbound finding for
 * it, and is left out here.
 */
export function unboundRecordIds(
  verified: BundleVerificationResult,
): readonly string[] {
  const invalid = invalidRecordIds(verified);
  return verified.perRecordMembership.findings.flatMap((finding) => {
    if (!finding.startsWith(UNBOUND)) return [];
    const id = finding.slice(UNBOUND.length);
    return invalid.has(id) ? [] : [id];
  });
}

// Per-record membership may fail solely because some supplied records are
// bound to no log position (the verifier's `membership_record_unbound`): real
// records that sit outside any checkpoint. That is coverage, not a broken
// proof -- every other record's inclusion proof still verified -- so the
// bundle renders, each such record carries its own `uncheckpointed` status,
// and the banner and verification page state how many there are. Any other
// membership finding (an invalid proof, bad coordinates, a missing sequence)
// still fails the bundle as a whole: `unboundRecordIds` leaves out a record
// whose supplied entry was rejected, so the counts below can only agree when
// every finding is a clean unbound record.
function membershipProvenOrUnbound(result: BundleVerificationResult): boolean {
  return (
    result.perRecordMembership.status === "pass" ||
    (result.perRecordMembership.status === "fail" &&
      result.perRecordMembership.findings.length > 0 &&
      result.perRecordMembership.findings.length ===
        unboundRecordIds(result).length)
  );
}

// A producer-selected Bundle, as the context reads it (bundle.ts
// readSelection, only when the strict verdict is not INVALID): no interval
// to check, and each record's own inclusion proof read against the signed
// checkpoint, gated like any Bundle's membership. The strict checks run only
// where WebCrypto has Ed25519 (buildVerifiedBundleContext); a page in a
// browser without it has no strict result, so it refuses the Bundle there
// (test/checkpoint-browser.test.ts).
/**
 * The viewer's verification gate: what "verified" means for a page
 * (spec/verification-display-v0.md section 1).
 */
export function bundleVerified(result: BundleVerificationResult): boolean {
  const selected = isProducerSelection(result);
  return (
    result.graphClosure.status === "pass" &&
    (selected || result.intervalCoverage.status === "pass") &&
    membershipProvenOrUnbound(result) &&
    Object.values(result.capsuleResults).every((capsule) => capsule.ok) &&
    result.disclosures.every(
      (disclosure) =>
        disclosure.status === "disclosure_match" ||
        disclosure.status === "withheld",
    )
  );
}

/**
 * The claim's findings that are not unbound records, one name each with
 * any `:id` / `:seq` suffix removed, in first-seen order. An unbound twin
 * of a rejected entry is left out: that record is already named by the
 * finding that rejected it.
 */
function nonUnboundFindings(verified: BundleVerificationResult): string[] {
  const names: string[] = [];
  for (const finding of verified.perRecordMembership.findings) {
    if (finding.startsWith(UNBOUND)) continue;
    const name = finding.split(":", 1)[0]!;
    if (!names.includes(name)) names.push(name);
  }
  return names;
}

export function coverageStatement(
  verified: BundleVerificationResult,
): CoverageStatement {
  const claim = verified.perRecordMembership;
  if (claim.status === "withheld")
    return { status: "withheld", reason: claim.findings.join(", ") };
  if (claim.status === "pass") return { status: "established" };
  const reasons = nonUnboundFindings(verified);
  return reasons.length === 0
    ? { status: "established" }
    : { status: "not_established", reason: reasons.join(", ") };
}

function recordCoverage(
  bundle: Record<string, unknown>,
  verified: BundleVerificationResult,
  coverage: CoverageStatement,
): RecordCoverage[] {
  const unbound = new Set(unboundRecordIds(verified));
  const invalid = invalidRecordIds(verified);
  return (Array.isArray(bundle.records) ? bundle.records : []).flatMap(
    (record): RecordCoverage[] => {
      const capsuleId = object(record)?.capsule_id;
      if (typeof capsuleId !== "string") return [];
      return [
        {
          capsuleId,
          status: invalid.has(capsuleId)
            ? "membership_invalid"
            : unbound.has(capsuleId)
              ? "uncheckpointed"
              : coverage.status === "established"
                ? "checkpointed"
                : "unverified",
        },
      ];
    },
  );
}

/**
 * The checks the verification page names in its derived lists (presentation
 * contract section 6.1), in the order the lists draw them.
 *
 * - `record-digests`: each record's capsule ID recomputed from its contents
 *   (Class 1 check 2);
 * - `record-rules`: the other Class 1 checks on each record (required
 *   fields, effects, verdict, chain parent, assurance claims);
 * - `closure`: the graph closure from the root to the stated depth;
 * - `range`: the completeness certificate's range over the log;
 * - `membership`: each record's inclusion at its log position;
 * - `checkpoint-signature`: the COSE signature on the log's checkpoint;
 * - `disclosures`: each disclosed value against its committed digest;
 * - `countersignatures`: each countersign/v1 signature over the bundle digest;
 * - `composed`: a composed/v1 block, its member bundles and its digest;
 * - `cited-signers`: the producer signature on the records a page module
 *   cites as signers (a Close and the records that link to it);
 * - `producer-signatures`: the producer signature on every record;
 * - `witness-receipts`: the witness receipts the bundle carries;
 * - `countersignature-types`: a countersignature of a type this runtime does
 *   not check;
 * - `countersignature-receipts`: a receipt carried with a countersignature.
 */
export const VERIFICATION_CHECK_IDS = Object.freeze([
  "record-digests",
  "record-rules",
  "closure",
  "range",
  "membership",
  "checkpoint-signature",
  "disclosures",
  "countersignatures",
  "composed",
  "cited-signers",
  "producer-signatures",
  "witness-receipts",
  "countersignature-types",
  "countersignature-receipts",
] as const);
export type VerificationCheckId = (typeof VERIFICATION_CHECK_IDS)[number];

/**
 * The page's own checks, split by what happened to each here. Every entry is
 * read from this runtime's verification result, its countersignature
 * classification and what its page module checked; none is read from a claim
 * in the bundle. `page`: the check ran here and passed. `failed`: it ran here
 * and did not pass, so it is never listed as checked. `notChecked`: the
 * bundle carries what the check needs, and this runtime does not run it or
 * could not complete it.
 */
export interface VerificationCheckLists {
  readonly page: readonly VerificationCheckId[];
  readonly failed: readonly VerificationCheckId[];
  readonly notChecked: readonly VerificationCheckId[];
  /**
   * True when the checkpoint signature is not checked although the claims
   * that rest on it passed (the verifier recorded `checkpoint_unverified`).
   */
  readonly passedWithoutCheckpoint: boolean;
}

/** What else this runtime checked, beyond the verification result. */
export interface CheckListInputs {
  /** The countersignature classification the page draws. */
  readonly stamps?: readonly CountersignatureStamp[];
  /** True when the rendered page module checked the signers it cites. */
  readonly citedSigners?: boolean;
  /**
   * The strict result this runtime reached (the context's `strict`): with
   * it, the producer signatures and the checkpoint signature were checked
   * here.
   */
  readonly strict?: StrictBundleResult;
}

/** The state a page's banner states (presentation contract section 6.2). */
export type VerifyState =
  | "checking"
  | "verified"
  | "incomplete"
  | "failed"
  | "unable";

/**
 * The banner's line for each state: the core's fixed text, which no module,
 * wording pack or bundle supplies. It names no internal token; the line
 * under it does (`data-banner-detail`). `incomplete` points at the
 * not-checked list only when the page draws one, and `failed` reads one way
 * when the records are still shown and another when the page refuses them.
 */
export const VERIFICATION_BANNER_LINES = Object.freeze({
  checking: "Checking…",
  verified: "✓ Unchanged since it was sealed",
  incomplete:
    'None of the bundle\'s checks failed, but some were not run: see "Not checked on this page" below',
  incompleteNoList: "None of the bundle's checks failed, but some were not run",
  failed: "✗ A check failed: do not rely on this page",
  refused: "✗ This bundle did not verify: do not rely on it",
  unable: "Couldn't check this page here: check it with a full verifier",
} as const);

/** The words a page says when this viewer cannot verify the bundle at all. */
export const UNABLE_TO_VERIFY_LINES = {
  banner: VERIFICATION_BANNER_LINES.unable,
  reason:
    "This viewer cannot compute the SHA-256 digests the checks need, so nothing was checked and no records are shown. This is not a failed check: the file may well be valid.",
  command: "To check this file, run:",
  noCommand:
    "To check this file, open it from a secure (https) page, or check it with a verifier outside this viewer.",
} as const;

/** The refusal line after the banner of a bundle the page refuses (contract I1). */
export const UNVERIFIED_BUNDLE_REFUSAL =
  "This bundle did not verify. Its records, rows and payloads are not shown; the verification page below lists which checks failed.";

const recordsWord = (count: number): string =>
  `${count} ${count === 1 ? "record" : "records"}`;

// A JSON object's members, or none.
const fields = (value: unknown): Record<string, unknown> => object(value) ?? {};

/** The page's verdict: the strict verifier's, in lower case. */
export type BannerVerdict = "valid" | "incomplete" | "invalid";
/** What became of the checkpoint signature on this page. */
export type BannerCheckpoint = "verified" | "unverified" | "invalid" | "absent";

interface BannerWords {
  readonly verdict: BannerVerdict;
  readonly checkpoint: BannerCheckpoint;
  /** The details line under the banner, naming each finding; "" for none. */
  readonly detail: string;
}

// Each claim's name in the banner's words.
const CLAIM_WORDS: Readonly<Record<StrictClaimName, string>> = {
  records: "each record's identity",
  signatures: "the records' producer signatures",
  graph_closure: "the graph closure",
  checkpoint: "the signed checkpoint",
  interval_coverage: "interval coverage",
  per_record_membership: "per-record membership",
  disclosures: "the disclosed values",
};

// A finding's name, without the record or member it is about.
const findingNames = (findings: readonly string[]): string[] => [
  ...new Set(findings.map((finding) => finding.split(":", 1)[0]!)),
];

// What the page did not check for a claim that did not fail, naming the
// verifier's finding so a reader can match it to a full verifier's report.
// A proof claim whose only finding is `checkpoint_unverified` is left to the
// checkpoint sentence.
function notShownWords(claim: StrictClaim, records: number): string {
  const names = findingNames(claim.findings);
  if (claim.name === "checkpoint")
    return names.includes("checkpoint_signature_absent")
      ? "the checkpoint signature, because the checkpoint is not signed (checkpoint_signature_absent)"
      : `the checkpoint signature, which this page cannot check (${names.join(", ")})`;
  if (claim.name === "signatures") {
    const unsigned = claim.findings.length;
    return unsigned === records
      ? "any record's producer signature, because no record is signed (producer_signature_unclaimed)"
      : `the producer signature of ${unsigned} of ${recordsWord(records)}, because ${unsigned === 1 ? "that record is" : "those records are"} not signed (producer_signature_unclaimed)`;
  }
  const rest = names.filter((name) => name !== "checkpoint_unverified");
  if (names.length > 0 && rest.length === 0) return "";
  const words = CLAIM_WORDS[claim.name];
  return rest.length > 0 ? `${words} (${rest.join(", ")})` : words;
}

/**
 * The banner's verdict, checkpoint state and details line, from the strict
 * result alone (the full verifier's three outcomes). The banner's own line
 * is fixed per state (VERIFICATION_BANNER_LINES); this details line names
 * what was not checked or what failed, with the verifier's finding names.
 * When interval coverage or per-record membership carries
 * `checkpoint_unverified`, it says they are relative to a producer-asserted
 * checkpoint (Evidence Bundle, completeness). Without a strict result (no
 * Ed25519 here) no signature was checked, so a bundle whose rows render is
 * at most `incomplete`. A bundle refused by the page's own checks is
 * `invalid` with no details line: the refusal follows the banner.
 */
function bannerWords(
  bundle: unknown,
  verification: BundleVerificationResult,
  strict: StrictBundleResult | undefined,
  rendered: boolean,
  coverage: { uncheckpointed: number; total: number },
): BannerWords {
  const claim = (name: StrictClaimName): StrictClaim | undefined =>
    strict?.claims.find((entry) => entry.name === name);
  const checkpointClaim = claim("checkpoint");
  const cose = fields(fields(bundle).checkpoint).cose;
  // The page's own checks reject a `cose` that is present but unusable
  // (`null` included), whatever the strict claim calls it.
  const rejected = [
    verification.intervalCoverage,
    verification.perRecordMembership,
  ].some((entry) =>
    entry.findings.includes("checkpoint_authentication_invalid"),
  );
  // With no strict result, the page's own checks may still have
  // authenticated a signed checkpoint (CLL needs no WebCrypto): the
  // proofs over it then carry no `checkpoint_unverified`.
  const plainAuthenticated =
    typeof cose === "string" &&
    cose !== "" &&
    verification.intervalCoverage.status === "pass" &&
    [verification.intervalCoverage, verification.perRecordMembership].every(
      (entry) => !entry.findings.includes("checkpoint_unverified"),
    );
  const checkpoint: BannerCheckpoint = rejected
    ? "invalid"
    : checkpointClaim === undefined
      ? cose === undefined || cose === null
        ? "absent"
        : plainAuthenticated
          ? "verified"
          : "unverified"
      : checkpointClaim.status === "pass"
        ? "verified"
        : checkpointClaim.status === "fail"
          ? "invalid"
          : checkpointClaim.findings.includes("checkpoint_signature_absent")
            ? "absent"
            : "unverified";
  if (!rendered)
    return {
      verdict: "invalid",
      checkpoint,
      detail: "",
    };
  const uncheckpointed = `${coverage.uncheckpointed} of ${recordsWord(coverage.total)} are uncheckpointed (bound to no log position), so per-record membership fails.`;
  const sentences: string[] = [];
  let verdict: BannerVerdict;
  if (strict === undefined) {
    // No Ed25519, so no strict verdict; a record bound to no log position
    // has still failed the page's own membership check.
    if (coverage.uncheckpointed > 0) {
      verdict = "invalid";
      sentences.push(uncheckpointed);
    } else {
      verdict = "incomplete";
      const records = fields(bundle).records;
      const carried = [
        ...(checkpoint === "absent" || checkpoint === "verified"
          ? []
          : ["the checkpoint signature"]),
        ...(Array.isArray(records) &&
        records.some((record) => typeof fields(record).signature === "string")
          ? ["the records' producer signatures"]
          : []),
      ];
      sentences.push(
        carried.length > 0
          ? `This page cannot check signatures, so ${carried.join(" and ")} could not be checked.`
          : checkpoint === "verified"
            ? "No record is signed."
            : "Neither the checkpoint nor any record is signed.",
      );
    }
  } else {
    verdict = strict.verdict.toLowerCase() as BannerVerdict;
    if (verdict === "incomplete") {
      const notChecked = strict.claims
        .filter((entry) => entry.status !== "pass" || entry.findings.length > 0)
        .map((entry) => notShownWords(entry, strict.records.length))
        .filter((words) => words !== "");
      // With nothing to name, the banner's own line says it all.
      if (notChecked.length > 0)
        sentences.push(`This page did not check ${notChecked.join("; ")}.`);
    } else if (verdict === "invalid") {
      // The rows render (the bundle passed the page's own checks, which a
      // bundle refused by its kind never does) although the verdict is
      // invalid: say what failed, before any row.
      const failed = strict.claims.filter((entry) => entry.status === "fail");
      const unboundOnly =
        coverage.uncheckpointed > 0 &&
        failed.length === 1 &&
        failed[0]!.name === "per_record_membership" &&
        strict.witnesses?.status !== "fail";
      const named = failed.map((entry) => {
        const invalid = entry.findings.filter((f) =>
          f.startsWith("producer_signature_invalid:"),
        ).length;
        // A count, as the uncheckpointed line gives one: never "the
        // records' signatures" when only some failed.
        if (entry.name === "signatures" && invalid > 0)
          return coverage.total === 1
            ? "the record's producer signature does not verify (producer_signature_invalid)"
            : `${invalid} of ${coverage.total} records' producer signatures do not verify (producer_signature_invalid)`;
        // What went wrong with the checkpoint, not only which object.
        if (entry.name === "checkpoint") {
          const names = findingNames(entry.findings);
          const words = [
            ...(names.includes("checkpoint_field_mismatch")
              ? [
                  "the checkpoint's fields do not match its signature (checkpoint_field_mismatch)",
                ]
              : []),
            ...(names.includes("checkpoint_field_missing")
              ? [
                  "the checkpoint is missing fields its signature covers (checkpoint_field_missing)",
                ]
              : []),
          ];
          if (words.length > 0) return words.join("; ");
        }
        return `${CLAIM_WORDS[entry.name]} (${findingNames(entry.findings).join(", ")})`;
      });
      // Only the receipts that failed, counted; one not checked is not a
      // failure.
      if (strict.witnesses?.status === "fail") {
        const carried = fields(fields(bundle).checkpoint).witnesses;
        const total = Array.isArray(carried) ? carried.length : 0;
        const count = (prefix: string): number =>
          strict.witnesses!.findings.filter((f) => f.startsWith(prefix)).length;
        // The same count form as the records: "1 of 3 … are".
        const receipts = (n: number, plural: string, single: string) =>
          total === 1
            ? `the witness receipt ${single}`
            : `${n} of ${total} witness receipts ${plural}`;
        const malformed = count("witness_receipt_malformed:"),
          invalid = count("witness_receipt_invalid:");
        if (malformed > 0)
          named.push(
            `${receipts(malformed, "are malformed", "is malformed")} (witness_receipt_malformed)`,
          );
        if (invalid > 0)
          named.push(
            `${receipts(invalid, "do not verify", "does not verify")} (witness_receipt_invalid)`,
          );
      }
      sentences.push(
        unboundOnly ? uncheckpointed : `What failed: ${named.join("; ")}.`,
      );
    }
  }
  // The proof claims as this page read them: the strict ones, or the plain
  // ones where no strict verdict was reached.
  const proofs: readonly (readonly [
    StrictClaimName,
    ClaimResult | undefined,
  ])[] =
    strict === undefined
      ? [
          ["interval_coverage", verification.intervalCoverage],
          ["per_record_membership", verification.perRecordMembership],
        ]
      : [
          ["interval_coverage", claim("interval_coverage")],
          ["per_record_membership", claim("per_record_membership")],
        ];
  const unanchored = proofs.filter(
    ([, entry]) =>
      entry !== undefined &&
      entry.status !== "fail" &&
      entry.findings.includes("checkpoint_unverified"),
  );
  // A checkpoint that failed is named above; nothing rests on it.
  if (unanchored.length > 0 && checkpoint !== "invalid") {
    const names = unanchored.map(([name]) => CLAIM_WORDS[name]).join(" and ");
    sentences.push(
      `${names[0]!.toUpperCase()}${names.slice(1)} ${unanchored.length === 1 ? "is" : "are"} checkpoint_unverified: relative to a producer-asserted checkpoint ${checkpoint === "absent" ? "that is not signed" : "this page could not authenticate"}.`,
    );
  }
  return { verdict, checkpoint, detail: sentences.join(" ") };
}

/**
 * The banner a page draws for one verification run (presentation contract
 * section 6.2), once the checks have finished: its state, its fixed line,
 * the strict verdict, what became of the checkpoint signature and the
 * details line naming the findings. It is computed from the verification
 * result alone, so every viewer states AAC's verdict in the same words and
 * none computes a verdict of its own. `checking` and `unable` are drawn
 * before or instead of a result, from VERIFICATION_BANNER_LINES.
 */
export interface VerificationBanner {
  readonly state: Exclude<VerifyState, "checking" | "unable">;
  /** The banner's line: the core's fixed text for the state. */
  readonly line: string;
  readonly verdict: BannerVerdict;
  readonly checkpoint: BannerCheckpoint;
  /** The details line under the banner (`data-banner-detail`); "" for none. */
  readonly detail: string;
  /** Records bound to no log position. */
  readonly uncheckpointed: number;
  /**
   * The refusal line after the banner when the page refuses the records
   * (contract section 8, I1). When it is present the records MUST NOT be
   * shown; when it is absent the checks allow them (section 6.2's "Records
   * shown"), though a presentation refusal can still withhold them.
   */
  readonly refusal?: string;
}

/**
 * The banner for a verified bundle context. `stamps` is the countersignature
 * classification the page draws, the same one it gives
 * `verificationCheckLists`: it can add a not-checked list, and the
 * incomplete line points at that list only when the page draws one. It is
 * required so that a viewer cannot leave it out by mistake.
 */
export function verificationBanner(
  context: VerifiedBundleContext,
  stamps: readonly CountersignatureStamp[],
): VerificationBanner {
  const { bundle, verification, strict } = context;
  const rendered = bundleVerified(verification);
  const records = fields(bundle).records;
  const coverage = {
    uncheckpointed: unboundRecordIds(verification).length,
    total: Array.isArray(records) ? records.length : 0,
  };
  const words = bannerWords(bundle, verification, strict, rendered, coverage);
  const state = !rendered
    ? "failed"
    : words.verdict === "valid"
      ? "verified"
      : words.verdict === "incomplete"
        ? "incomplete"
        : "failed";
  // The page's lists also read `citedSigners`, which depends on the module,
  // but that adds only to the checked list, never to the not-checked one.
  const notCheckedListDrawn =
    verificationCheckLists(bundle, verification, {
      stamps,
      ...(strict === undefined ? {} : { strict }),
    }).notChecked.length > 0;
  return {
    state,
    line: !rendered
      ? VERIFICATION_BANNER_LINES.refused
      : state === "incomplete" && !notCheckedListDrawn
        ? VERIFICATION_BANNER_LINES.incompleteNoList
        : VERIFICATION_BANNER_LINES[state],
    verdict: words.verdict,
    checkpoint: words.checkpoint,
    detail: words.detail,
    uncheckpointed: coverage.uncheckpointed,
    ...(rendered ? {} : { refusal: UNVERIFIED_BUNDLE_REFUSAL }),
  };
}

export const CHECKED_ON_THIS_PAGE = "Checked on this page";
export const FAILED_ON_THIS_PAGE = "Failed on this page";
export const NOT_CHECKED_ON_THIS_PAGE = "Not checked on this page";
/** Drawn after the not-checked list; it names no product or command. */
export const FULL_VERIFIER_LINE =
  "To run these checks, verify the bundle with a full verifier.";
/** Drawn after the lists, whatever they hold. */
export const CHECKS_SCOPE_LINE =
  "None of these checks says who produced the records, or that this file is the most recent copy.";

/**
 * One line per check, worded so it reads true under each heading: it names
 * what was checked, never the outcome. A check this page did not run is
 * never called verified.
 */
export const VERIFICATION_CHECK_WORDS: Readonly<
  Record<VerificationCheckId, string>
> = Object.freeze({
  "record-digests":
    "Each record's contents against the capsule ID it was sealed with.",
  "record-rules":
    "Each record's required fields, effects, verdict, chain parent and assurance claims.",
  closure:
    "That every record the root cites, to the stated depth, is in this file or listed as missing.",
  range:
    "That no record is missing from the stretch of the log this file covers.",
  membership: "That each record bound to a log position sits at that position.",
  "checkpoint-signature":
    "The signature on the log's checkpoint, and the fields it signs.",
  disclosures:
    "Each disclosed value against the digest its record committed to.",
  // A countersignature sits outside the bundle digest, so its outcome never
  // changes the banner's state (presentation contract section 6.2). The line
  // says so, so a failed one under a verified banner is not read as a
  // second verdict.
  countersignatures:
    "Each countersignature's signature, over this bundle's digest, under the key it names. Checking a countersignature is not one of the bundle's own checks, so its result never changes the bundle's verdict.",
  composed:
    "Each bundle this file composes, and the digest over the composition.",
  "cited-signers":
    "The producer signature on the records this page cites as signers, each marked beside it as verified or not. Not the signature on every record.",
  "producer-signatures": "The producer signature on every record.",
  "witness-receipts": "Each witness receipt this file carries.",
  "countersignature-types":
    "A countersignature of a type this page does not check.",
  "countersignature-receipts": "The receipt carried with a countersignature.",
});

/**
 * The name a full verifier's report uses for each check, drawn under its
 * line so a reader can match the two; the line itself stays in plain words.
 */
export const VERIFICATION_CHECK_TECHNICAL_NAMES: Readonly<
  Record<VerificationCheckId, string>
> = Object.freeze({
  "record-digests": "capsule ID matches contents",
  "record-rules":
    "required fields, effect consistency, verdict conflict, chain parent, assurance claims",
  closure: "graph closure",
  range: "interval coverage",
  membership: "per-record membership",
  "checkpoint-signature": "checkpoint signature (checkpoint.cose)",
  disclosures: "disclosure digests",
  countersignatures: "countersignature signatures",
  composed: "composed bundles (composed/v1)",
  "cited-signers": "cited producer signatures",
  "producer-signatures": "producer signatures",
  "witness-receipts": "witness receipts",
  "countersignature-types": "countersignature types",
  "countersignature-receipts": "countersignature receipts",
});

/** Added to the checkpoint line when the claims resting on it passed without it. */
export const CHECKPOINT_NOT_CHECKED_NOTE =
  "This page could not check it, so the range and membership checks rest on a checkpoint the producer asserted.";

/** The words a list item shows for `id` under `list`. */
export function verificationCheckWords(
  id: VerificationCheckId,
  list: keyof Omit<VerificationCheckLists, "passedWithoutCheckpoint">,
  lists: VerificationCheckLists,
): string {
  const words = VERIFICATION_CHECK_WORDS[id];
  return id === "checkpoint-signature" &&
    list === "notChecked" &&
    lists.passedWithoutCheckpoint
    ? `${words} ${CHECKPOINT_NOT_CHECKED_NOTE}`
    : words;
}

// Findings that say the completeness evaluation stopped before it reached
// the checkpoint signature, so neither it nor the memberships ran.
const STOPPED_BEFORE_CHECKPOINT = new Set([
  "bundle_malformed",
  "completeness_certificate_invalid",
  "range_proof_invalid",
]);

/**
 * Derive the page's check lists from its own results. Nothing here reads a
 * bundle claim as a result: the bundle is read only for what it carries
 * (a checkpoint signature, record signatures, witness receipts), which
 * decides whether a check is called for at all.
 */
export function verificationCheckLists(
  bundle: unknown,
  verified: BundleVerificationResult,
  inputs: CheckListInputs = {},
): VerificationCheckLists {
  const top = object(bundle) ?? {};
  const outcome = new Map<
    VerificationCheckId,
    "page" | "failed" | "notChecked"
  >();
  const ran = (id: VerificationCheckId, passed: boolean): void => {
    outcome.set(id, passed ? "page" : "failed");
  };

  // Class 1, per record.
  if (Object.keys(verified.capsuleResults).length > 0) {
    ran(
      "record-digests",
      capsuleGroupStatus(verified.capsuleResults, [2]) === "pass",
    );
    ran(
      "record-rules",
      capsuleGroupStatus(verified.capsuleResults, [1, 3, 4, 5, 6, 7, 8]) ===
        "pass",
    );
  }
  // The graph closure always runs; a declared-incomplete bundle passes it
  // with its missing records listed.
  ran("closure", verified.graphClosure.status !== "fail");

  // Range, membership and the checkpoint signature run only when the bundle
  // carries a completeness certificate and a checkpoint.
  const range = verified.intervalCoverage;
  const signed =
    typeof object(top.checkpoint)?.cose === "string" &&
    object(top.checkpoint)!.cose !== "";
  let passedWithoutCheckpoint = false;
  if (range.status !== "withheld") {
    const stopped = range.findings.some((f) =>
      STOPPED_BEFORE_CHECKPOINT.has(f),
    );
    const checkpointInvalid = range.findings.includes(
      "checkpoint_authentication_invalid",
    );
    ran("range", !stopped || range.status === "pass");
    if (stopped || checkpointInvalid) {
      outcome.set("membership", "notChecked");
    } else {
      // A record bound to no log position fails per-record membership: the
      // rows still render, but the page's verdict calls it a failure.
      ran(
        "membership",
        coverageStatement(verified).status === "established" &&
          unboundRecordIds(verified).length === 0,
      );
    }
    if (checkpointInvalid) outcome.set("checkpoint-signature", "failed");
    else if (signed) {
      const unchecked = [range, verified.perRecordMembership].some((claim) =>
        claim.findings.includes("checkpoint_unverified"),
      );
      if (stopped || unchecked) {
        outcome.set("checkpoint-signature", "notChecked");
        passedWithoutCheckpoint = !stopped && range.status === "pass";
      } else outcome.set("checkpoint-signature", "page");
    }
  } else if (isProducerSelection(verified)) {
    // A producer selection (bundle.ts readSelection): no interval to check;
    // each record's own inclusion proof, read against the signed
    // checkpoint, unless that checkpoint could not be authenticated here.
    const membership = verified.perRecordMembership;
    if (membership.status === "withheld")
      outcome.set("membership", "notChecked");
    else ran("membership", membership.status === "pass");
    if (signed && membership.findings.includes("checkpoint_unverified"))
      outcome.set("checkpoint-signature", "notChecked");
  }

  const disclosed = verified.disclosures.filter((d) => d.status !== "withheld");
  if (disclosed.length > 0)
    ran(
      "disclosures",
      disclosed.every((d) => d.status === "disclosure_match"),
    );

  const stamps = inputs.stamps ?? [];
  const signedStamps = stamps.filter(
    (s) =>
      s.kind === "resolved" ||
      s.kind === "not-independent" ||
      s.kind === "unresolved-signer",
  );
  const invalidStamps = stamps.filter((s) => s.kind === "invalid");
  if (signedStamps.length + invalidStamps.length > 0)
    ran("countersignatures", invalidStamps.length === 0);

  const composed = verified.extensions.flatMap((e) =>
    e.composed === undefined ? [] : [e.composed],
  );
  if (composed.some((c) => c.status === "fail")) ran("composed", false);
  else if (composed.some((c) => c.status === "withheld"))
    outcome.set("composed", "notChecked");
  else if (composed.length > 0) ran("composed", true);

  if (inputs.citedSigners === true) ran("cited-signers", true);

  // Called for by what the bundle carries; this runtime does not run them.
  if (
    Array.isArray(top.records) &&
    top.records.some(
      (record) =>
        typeof object(record)?.signature === "string" &&
        object(record)!.signature !== "",
    )
  )
    outcome.set("producer-signatures", "notChecked");
  if (Array.isArray(top.receipts) && top.receipts.length > 0)
    outcome.set("witness-receipts", "notChecked");
  if (stamps.some((s) => s.kind === "unverified"))
    outcome.set("countersignature-types", "notChecked");
  if (
    signedStamps.some(
      (s) => "statement" in s && s.statement.receipt === "unverified",
    )
  )
    outcome.set("countersignature-receipts", "notChecked");

  // The strict checks ran here: the lists say how the producer signatures,
  // the checkpoint, the proof claims and the witness receipts went, not only
  // that the bundle carries them.
  const strict = inputs.strict;
  if (strict?.kindOk === true) {
    const claim = (name: StrictClaimName) =>
      strict.claims.find((entry) => entry.name === name);
    const signatures = claim("signatures");
    if (signatures?.status === "pass") ran("producer-signatures", true);
    else if (
      signatures?.findings.some((f) =>
        f.startsWith("producer_signature_invalid:"),
      )
    )
      ran("producer-signatures", false);
    const checkpoint = claim("checkpoint");
    if (checkpoint?.status === "pass") ran("checkpoint-signature", true);
    else if (checkpoint?.status === "fail") ran("checkpoint-signature", false);
    // A proof claim the strict verdict failed is never listed as checked:
    // records bound to no log position fail per-record membership.
    if (claim("interval_coverage")?.status === "fail") ran("range", false);
    if (claim("per_record_membership")?.status === "fail")
      ran("membership", false);
    // The receipts in `checkpoint.witnesses`, as the strict verdict read
    // them: checked only when every one verified.
    const witnesses = strict.witnesses;
    if (witnesses?.status === "fail") ran("witness-receipts", false);
    else if (
      witnesses?.status === "pass" &&
      witnesses.receipts.every((r) => r.status === "pass")
    )
      ran("witness-receipts", true);
    else if (
      witnesses !== null &&
      witnesses !== undefined &&
      !witnesses.findings.includes("witness_receipt_absent")
    )
      outcome.set("witness-receipts", "notChecked");
  }

  const pick = (which: "page" | "failed" | "notChecked") =>
    VERIFICATION_CHECK_IDS.filter((id) => outcome.get(id) === which);
  const failed = pick("failed");
  return {
    page: pick("page"),
    failed,
    notChecked: pick("notChecked"),
    // The note says the range and membership checks passed on a checkpoint
    // the producer asserted: true only when the page's own checks
    // (bundleVerified) pass, no check on this page failed and the
    // checkpoint line is in the not-checked list.
    passedWithoutCheckpoint:
      passedWithoutCheckpoint &&
      outcome.get("checkpoint-signature") === "notChecked" &&
      failed.length === 0 &&
      bundleVerified(verified),
  };
}

export const VERIFY_INDEPENDENTLY_LINE =
  "verify independently at verify.agentactioncapsule.org or with a full verifier";

const FIVE_WORD_RESULT: Readonly<Record<CheckStatus, string>> = Object.freeze({
  pass: "passed with no errors found",
  withheld: "still withheld pending producer disclosure",
  fail: "failed at least one check",
  not_checked: "not checked no evidence supplied",
});

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function capsuleGroupStatus(
  capsuleResults: Readonly<Record<string, VerificationResult>>,
  checks: readonly number[],
): CheckStatus {
  const results = Object.values(capsuleResults);
  if (results.length === 0) return "not_checked";
  const failed = results.some((result) =>
    result.findings.some(
      (finding) =>
        finding.severity === "error" &&
        finding.check !== undefined &&
        checks.includes(finding.check),
    ),
  );
  return failed ? "fail" : "pass";
}

function receiptGradeWord(value: unknown): ReceiptGradeWord | undefined {
  return value === "mmr-verified"
    ? "consistency-verified"
    : value === "countersigned-observed"
      ? "existence-and-time"
      : undefined;
}

function receipts(raw: unknown): ReceiptEntry[] {
  if (!Array.isArray(raw)) return [];
  return raw.flatMap((entry): ReceiptEntry[] => {
    const record = object(entry);
    if (record === undefined) return [];
    const witness = record.witness,
      time = record.time,
      grade = receiptGradeWord(record.grade);
    return typeof witness === "string" &&
      typeof time === "string" &&
      grade !== undefined
      ? [{ witness, grade, time }]
      : [];
  });
}

function completenessStatement(
  raw: unknown,
): CompletenessStatement | undefined {
  const record = object(raw);
  if (record === undefined) return undefined;
  return {
    ...(typeof record.closure_depth === "number"
      ? { closureDepth: record.closure_depth }
      : {}),
    ...(typeof record.records_mode === "string"
      ? { recordsMode: record.records_mode }
      : {}),
    ...(typeof record.payloads_mode === "string"
      ? { payloadsMode: record.payloads_mode }
      : {}),
    suppressedFields: Array.isArray(record.suppressed_fields)
      ? record.suppressed_fields.filter(
          (field): field is string => typeof field === "string",
        )
      : [],
  };
}

function summarize(name: string, status: CheckStatus): CheckSummary {
  return { name, status, result: FIVE_WORD_RESULT[status] };
}

/**
 * Build the viewer-owned verification page model from VERIFIED data only:
 * the already-computed BundleVerificationResult (never bundle-supplied
 * markup). Ten named checks: six aggregate the base-profile Capsule checks
 * (numbered 1-8 by verifyClass1) into six groups; four are Bundle-level
 * claims already computed independently by verifyBundle.
 */
export function buildVerificationPageModel(
  bundle: unknown,
  verified: BundleVerificationResult,
  appliedInterpreters?: ReadonlySet<ExtensionInterpreterId>,
  checkInputs: CheckListInputs = {},
): VerificationPageModel {
  const top = object(bundle) ?? {};
  const checkpoint = object(top.checkpoint);
  const checks: CheckSummary[] = [
    summarize(
      "Required fields",
      capsuleGroupStatus(verified.capsuleResults, [1]),
    ),
    summarize(
      "Capsule ID matches contents",
      capsuleGroupStatus(verified.capsuleResults, [2]),
    ),
    summarize(
      "Effect consistency",
      capsuleGroupStatus(verified.capsuleResults, [3, 5]),
    ),
    summarize(
      "Verdict conflict",
      capsuleGroupStatus(verified.capsuleResults, [4]),
    ),
    summarize("Chain parent", capsuleGroupStatus(verified.capsuleResults, [6])),
    summarize(
      "Assurance claims",
      capsuleGroupStatus(verified.capsuleResults, [7, 8]),
    ),
    summarize(
      "Bundle digest",
      verified.bundleDigest === undefined ? "fail" : "pass",
    ),
    summarize("Graph closure", verified.graphClosure.status),
    summarize("Interval coverage", verified.intervalCoverage.status),
    summarize("Per-record membership", verified.perRecordMembership.status),
  ];
  const coverage = coverageStatement(verified);
  return {
    ...(verified.bundleDigest === undefined
      ? {}
      : { bundleDigest: verified.bundleDigest }),
    ...(typeof checkpoint?.root === "string"
      ? { checkpointRoot: checkpoint.root }
      : {}),
    ...(typeof checkpoint?.mmr_size === "number"
      ? { checkpointSize: checkpoint.mmr_size }
      : {}),
    receipts: receipts(top.receipts),
    selfWitnessed:
      checkpoint !== undefined && receipts(top.receipts).length === 0,
    records: recordCoverage(top, verified, coverage),
    uncheckpointedCount: unboundRecordIds(verified).length,
    coverage,
    ...(completenessStatement(top.completeness) === undefined
      ? {}
      : { completeness: completenessStatement(top.completeness)! }),
    checks,
    extensions: extensionRows(verified.extensions, appliedInterpreters),
    checkLists: verificationCheckLists(bundle, verified, checkInputs),
    verifyIndependentlyLine: VERIFY_INDEPENDENTLY_LINE,
  };
}
