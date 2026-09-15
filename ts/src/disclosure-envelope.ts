import { asJsonObject, isHex64, jsonDigest, type ParsedJson } from "./json.js";
import { resolveDisclosurePath } from "./disclosure-path.js";
import { disclosureEligibleFields } from "./registries.js";
import { verifyClass1, type VerificationResult } from "./verify.js";

export const DISCLOSURE_MATCH = "disclosure_match";
export const DISCLOSURE_MISMATCH = "disclosure_mismatch";
export const DISCLOSURE_INELIGIBLE_FIELD = "disclosure_ineligible_field";
export const DISCLOSURE_NO_COMMITTED_DIGEST = "disclosure_no_committed_digest";

export interface DisclosureFinding {
  readonly member: string;
  readonly code: string;
}

/** Build a Disclosure Envelope after enforcing DE-1 through DE-3. */
export async function buildDisclosureEnvelope(
  capsule: Record<string, ParsedJson>,
  disclosures: Record<string, ParsedJson>,
): Promise<{
  capsule: Record<string, ParsedJson>;
  disclosures: Record<string, ParsedJson>;
}> {
  for (const [member, value] of Object.entries(disclosures)) {
    const path =
      disclosureEligibleFields[member as keyof typeof disclosureEligibleFields];
    if (path === undefined) {
      throw new Error(`${DISCLOSURE_INELIGIBLE_FIELD}: ${member}`);
    }
    const committed = resolveDisclosurePath(capsule, path);
    if (!isHex64(committed)) {
      throw new Error(`${DISCLOSURE_NO_COMMITTED_DIGEST}: ${member}`);
    }
    let computed: string;
    try {
      computed = await jsonDigest(value);
    } catch {
      throw new Error(`${DISCLOSURE_MISMATCH}: ${member}`);
    }
    if (computed !== committed) {
      throw new Error(`${DISCLOSURE_MISMATCH}: ${member}`);
    }
  }
  return { capsule, disclosures: { ...disclosures } };
}

export interface DisclosureEnvelopeResult {
  readonly ok: boolean;
  readonly capsuleResult: VerificationResult;
  readonly disclosuresChecked: number;
  readonly disclosuresMatched: number;
  readonly disclosureFindings: readonly DisclosureFinding[];
}

/** Verify an AAC Disclosure Envelope through DE-3 without conflating Class 1. */
export async function verifyDisclosureEnvelope(
  envelope: ParsedJson,
): Promise<DisclosureEnvelopeResult> {
  const wrapper = asJsonObject(envelope);
  const capsule = wrapper?.capsule ?? envelope;
  const capsuleResult = await verifyClass1(capsule);
  const disclosures = asJsonObject(wrapper?.disclosures);
  const findings: DisclosureFinding[] = [];
  const capsuleObject = asJsonObject(capsule);

  if (disclosures !== undefined) {
    for (const [member, value] of Object.entries(disclosures).sort(
      ([left], [right]) => (left < right ? -1 : left > right ? 1 : 0),
    )) {
      const path =
        disclosureEligibleFields[
          member as keyof typeof disclosureEligibleFields
        ];
      if (path === undefined) {
        findings.push({ member, code: DISCLOSURE_INELIGIBLE_FIELD });
        continue;
      }
      const committed =
        capsuleObject === undefined
          ? undefined
          : resolveDisclosurePath(capsuleObject, path);
      if (typeof committed !== "string" || !/^[0-9a-f]{64}$/u.test(committed)) {
        findings.push({ member, code: DISCLOSURE_NO_COMMITTED_DIGEST });
        continue;
      }
      let matches = false;
      try {
        const computed = await jsonDigest(value);
        matches = computed === committed;
      } catch {
        matches = false;
      }
      findings.push({
        member,
        code: matches ? DISCLOSURE_MATCH : DISCLOSURE_MISMATCH,
      });
    }
  }

  const matched = findings.filter(
    (finding) => finding.code === DISCLOSURE_MATCH,
  ).length;
  return {
    ok:
      capsuleResult.ok &&
      findings.every((finding) => finding.code === DISCLOSURE_MATCH),
    capsuleResult,
    disclosuresChecked: findings.length,
    disclosuresMatched: matched,
    disclosureFindings: findings,
  };
}
