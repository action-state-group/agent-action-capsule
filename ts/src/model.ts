import type { ParsedJson } from "./json.js";
import { computeCapsuleId, decodeCapsuleJson, verifyClass1 } from "./verify.js";

export interface LogCoordinates {
  readonly log_id: ParsedJson;
  readonly leaf_index: ParsedJson;
  readonly inclusion_proof: ParsedJson;
}

export interface ReferenceEntry {
  readonly type: string;
  readonly digest_alg: string;
  readonly digest: string;
  readonly citation_purpose?: string;
  readonly log_coordinates?: LogCoordinates;
}

export interface Chain {
  readonly parent_capsule_id: string;
  readonly relation: string;
}

/**
 * The spec_version a producer emits: the newest published value (draft -05,
 * "Identity and parties").
 */
export const CURRENT_SPEC_VERSION = "draft-mih-scitt-agent-action-capsule-05";

/**
 * Every published spec_version value. A verifier accepts all of them;
 * spec_version selects no digest or verification algorithm, so verifyClass1
 * never branches on it.
 */
export const PUBLISHED_SPEC_VERSIONS: readonly string[] = Object.freeze([
  "draft-mih-scitt-agent-action-capsule-00",
  "draft-mih-scitt-agent-action-capsule-01",
  "draft-mih-scitt-agent-action-capsule-02",
  "draft-mih-scitt-agent-action-capsule-03",
  "draft-mih-scitt-agent-action-capsule-04",
  CURRENT_SPEC_VERSION,
]);

/** Format-4 record model. Extension members remain permitted and committed. */
export interface CapsuleBody {
  readonly spec_version: string;
  readonly format_version: "4";
  readonly canonicalization_id: "jcs";
  readonly action_id: string;
  readonly action_type: "fyi" | "decide";
  readonly operator: string;
  readonly developer: string;
  readonly timestamp: string;
  readonly chain?: Chain;
  readonly references?: readonly ReferenceEntry[];
}

export type Capsule = CapsuleBody & { readonly capsule_id: string };

/** Seal a format-4 body. Only capsule_id and local Producer Envelope fields are excluded. */
export async function sealCapsule(body: CapsuleBody): Promise<Capsule> {
  if (body.format_version !== "4" || body.canonicalization_id !== "jcs")
    throw new TypeError(
      "format_version '4' requires canonicalization_id='jcs'",
    );
  const record = body as unknown as Record<string, ParsedJson | undefined>;
  for (const member of [
    "spec_version",
    "action_id",
    "action_type",
    "operator",
    "developer",
    "timestamp",
  ]) {
    if (typeof record[member] !== "string" || record[member] === "")
      throw new TypeError(`${member} must be a non-empty string`);
  }
  const value = { ...body } as unknown as Record<string, ParsedJson>;
  delete value.capsule_id;
  const capsule_id = await computeCapsuleId(value);
  return Object.freeze({ ...body, capsule_id }) as Capsule;
}

/** Strictly parse and validate a Capsule before returning the typed record. */
export async function parseCapsule(
  input: Uint8Array | string,
): Promise<Capsule> {
  const value = decodeCapsuleJson(input);
  const result = await verifyClass1(value);
  if (!result.ok)
    throw new TypeError(
      `non-conforming Capsule: ${result.findings.map((item) => item.code).join(", ")}`,
    );
  return Object.freeze(value) as unknown as Capsule;
}
