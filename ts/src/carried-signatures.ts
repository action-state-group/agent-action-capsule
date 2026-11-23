// SPDX-License-Identifier: BSD-3-Clause
import { verifyEd25519Strict } from "./ed25519-strict.js";
import { jcs, setMember } from "./json.js";

/**
 * The carried signature profiles of `composed/v1`
 * (draft-mih-zhang-agent-disclosure-bundle-03, "Carried Signature Profiles"),
 * a port of `go/bundle/carried_signatures.go`: three opt-in profiles in which
 * a verifier checks the signature of a refusal or an artifact response a
 * member carries. Pass {@link verifyCarriedRefusal} and
 * {@link verifyCarriedResponse} as `ComposedOptions.refusalSignature` and
 * `responseSignature`; without them every carried signature stays
 * signature-unverified.
 *
 * Each check resolves to `verified`, `invalid` or `signature_unverified`.
 * The state covers the signature alone: no check of a signed value enters it,
 * and it does not compare the key with the member's responder. Ed25519 is
 * strict ({@link verifyEd25519Strict}): a small-order key or R never verifies.
 */
export const THREE_MEMBER_REFUSAL = "three-member-refusal/v1";
export const WHOLE_REFUSAL = "whole-refusal/v1";
export const DIGEST_BOUND_ARTIFACT_RESPONSE =
  "digest-bound-artifact-response/v1";

/**
 * The `type` the verifier supplies to a digest-bound artifact response's
 * signing input; it is never read from the carried object.
 */
export const ARTIFACT_RESPONSE_TYPE = "evidence-artifact-response/v1";

export type CarriedSignatureState =
  | "verified"
  | "invalid"
  | "signature_unverified";

type Obj = Readonly<Record<string, unknown>>;

const KEY = /^[0-9a-f]{64}$/u;
const SIG = /^[0-9a-f]{128}$/u;

const has = (value: Obj, name: string): boolean =>
  Object.prototype.hasOwnProperty.call(value, name);

const bytes = (hex: string): Uint8Array =>
  Uint8Array.from(hex.match(/../gu) ?? [], (byte) => parseInt(byte, 16));

/**
 * The profile a carried refusal is read in: one that carries `sig` and no
 * `signature` is in {@link THREE_MEMBER_REFUSAL}, unless it also carries
 * `policy_digest` (an evidence-interop/2 refusal may sign it), in which case
 * it is in none of these profiles (`undefined`); every other refusal is in
 * {@link WHOLE_REFUSAL}. Presence decides; a `null` member is present.
 */
export function carriedRefusalProfile(refusal: Obj): string | undefined {
  if (has(refusal, "sig") && !has(refusal, "signature"))
    return has(refusal, "policy_digest") ? undefined : THREE_MEMBER_REFUSAL;
  return WHOLE_REFUSAL;
}

/**
 * {@link DIGEST_BOUND_ARTIFACT_RESPONSE} for a carried response that does
 * not carry `responder`; `undefined` for one that does, which is in none of
 * these profiles.
 */
export function carriedResponseProfile(response: Obj): string | undefined {
  return has(response, "responder")
    ? undefined
    : DIGEST_BOUND_ARTIFACT_RESPONSE;
}

function strings(
  value: Obj,
  names: readonly string[],
): Record<string, string> | undefined {
  const out: Record<string, string> = {};
  for (const name of names) {
    const member = value[name];
    if (!has(value, name) || typeof member !== "string") return undefined;
    out[name] = member;
  }
  return out;
}

async function verifies(
  key: unknown,
  sig: unknown,
  message: Uint8Array,
): Promise<CarriedSignatureState> {
  if (
    typeof key !== "string" ||
    typeof sig !== "string" ||
    !KEY.test(key) ||
    !SIG.test(sig)
  )
    return "invalid";
  return (await verifyEd25519Strict(bytes(key), bytes(sig), message))
    ? "verified"
    : "invalid";
}

/**
 * The UTF-8 JCS of the refusal's `issued_at`, `reason` and
 * `request_digest`, or `undefined` when one is absent or not a string.
 */
export function threeMemberRefusalSigningInput(
  refusal: Obj,
): Uint8Array | undefined {
  const signed = strings(refusal, ["issued_at", "reason", "request_digest"]);
  if (signed === undefined) return undefined;
  try {
    return jcs(signed);
  } catch {
    // A string JCS cannot serialize, such as an unpaired surrogate.
    return undefined;
  }
}

/**
 * The refusal's `sig` under its `key_id` in {@link THREE_MEMBER_REFUSAL}. A
 * refusal in this profile carries `sig`, so it is never signature-unverified.
 */
export async function verifyThreeMemberRefusal(
  refusal: Obj,
): Promise<CarriedSignatureState> {
  const input = threeMemberRefusalSigningInput(refusal);
  if (input === undefined) return "invalid";
  return verifies(refusal.key_id, refusal.sig, input);
}

/**
 * The refusal's `signature` under its `key_id` over the JCS of the refusal
 * without `signature`, in {@link WHOLE_REFUSAL}.
 */
export async function verifyWholeRefusal(
  refusal: Obj,
): Promise<CarriedSignatureState> {
  if (!has(refusal, "key_id") && !has(refusal, "signature"))
    return "signature_unverified";
  // setMember: plain assignment would turn a member named `__proto__` into
  // the object's prototype and drop it from the signing input.
  const unsigned: Record<string, unknown> = {};
  for (const [name, member] of Object.entries(refusal))
    if (name !== "signature") setMember(unsigned, name, member);
  let input: Uint8Array;
  try {
    input = jcs(unsigned);
  } catch {
    return "invalid";
  }
  return verifies(refusal.key_id, refusal.signature, input);
}

/** A carried refusal's signature in the profile it is read in. */
export async function verifyCarriedRefusal(
  refusal: Obj,
): Promise<CarriedSignatureState> {
  const profile = carriedRefusalProfile(refusal);
  if (profile === undefined) return "signature_unverified";
  return profile === THREE_MEMBER_REFUSAL
    ? verifyThreeMemberRefusal(refusal)
    : verifyWholeRefusal(refusal);
}

/**
 * The signing input of {@link DIGEST_BOUND_ARTIFACT_RESPONSE}: the UTF-8 JCS
 * of the five members and `type` {@link ARTIFACT_RESPONSE_TYPE}.
 */
export function artifactResponseSigningInput(
  requestDigest: string,
  anchor: string,
  artifactKind: string,
  artifactDigest: string,
  issuedAt: string,
): Uint8Array {
  return jcs({
    type: ARTIFACT_RESPONSE_TYPE,
    request_digest: requestDigest,
    anchor,
    artifact_kind: artifactKind,
    artifact_digest: artifactDigest,
    issued_at: issuedAt,
  });
}

/**
 * A carried response's `sig` under its `key_id` in
 * {@link DIGEST_BOUND_ARTIFACT_RESPONSE}. A response that carries
 * `responder` is in none of these profiles and is signature-unverified, as is
 * one that carries neither `key_id` nor `sig`.
 */
export async function verifyDigestBoundArtifactResponse(
  response: Obj,
): Promise<CarriedSignatureState> {
  if (carriedResponseProfile(response) === undefined)
    return "signature_unverified";
  if (!has(response, "key_id") && !has(response, "sig"))
    return "signature_unverified";
  const signed = strings(response, [
    "request_digest",
    "anchor",
    "artifact_kind",
    "artifact_digest",
    "issued_at",
  ]);
  if (signed === undefined) return "invalid";
  let input: Uint8Array;
  try {
    input = artifactResponseSigningInput(
      signed.request_digest!,
      signed.anchor!,
      signed.artifact_kind!,
      signed.artifact_digest!,
      signed.issued_at!,
    );
  } catch {
    // A string JCS cannot serialize, such as an unpaired surrogate.
    return "invalid";
  }
  return verifies(response.key_id, response.sig, input);
}

/** The response hook: every carried response this module can check. */
export const verifyCarriedResponse = verifyDigestBoundArtifactResponse;
