/**
 * The `parent-log-witness/v1` extension (Evidence Bundle draft -03, "The
 * parent-log-witness/v1 Extension").
 *
 * A producer can have its checkpoint witnessed without sending it to a
 * witness: the checkpoint (the Bundle's, or an earlier one of the same log
 * with a consistency proof) is a salted leaf of a Merkle tree whose root is
 * one entry of a parent log signed by the same key, and the parent log's
 * checkpoint carries the Receipts. {@link verifyParentLogWitness} checks every
 * link of that chain, then the Receipts over the parent checkpoint with
 * {@link verifyWitnessReceipts}, and computes the extent itself. Nothing the
 * block states about its extent is read.
 *
 * Strict `verifyBundle` calls it when the Bundle carries the block; see
 * `vectors/bundle/parent-log-witness/` and the Python reference
 * `python/agent_action_capsule/parent_witness.py`.
 */
import { leafCount, verifyConsistency } from "@action-state-group/cll";
import {
  consistencyProof,
  decodeCose,
  hex,
  integer,
  object,
  parseProof,
  signedCheckpointFields,
  uint,
  verifyProof,
} from "./cll-checkpoint.js";
import { isHex64, jcs, sha256Hex } from "./json.js";
import {
  verifyWitnessReceipts,
  type SignedCheckpointFields,
  type WitnessReceiptResult,
} from "./witness.js";

/** The extension kind. */
export const PARENT_LOG_WITNESS_KIND = "parent-log-witness/v1";
/** The most hashes a `path` may hold. */
export const PARENT_WITNESS_MAX_PATH = 32;

/**
 * The leaf counts of the covered checkpoint (`entries`) and of the Bundle's
 * checkpoint (`of`): entries up to `entries` were witnessed when the parent
 * checkpoint was. The extent is whole when the two are equal.
 */
export interface ParentWitnessExtent {
  readonly entries: number;
  readonly of: number;
}
/**
 * The block's result. `extent` is set only when `status` is `pass`.
 * `receipts` are the Receipts over the parent checkpoint, once every link
 * held; they are never Receipts over the Bundle's checkpoint.
 */
export interface ParentWitnessResult {
  readonly status: "pass" | "withheld" | "fail";
  readonly findings: readonly string[];
  readonly extent: ParentWitnessExtent | null;
  readonly receipts: readonly WitnessReceiptResult[];
}

const failed = (finding: string): ParentWitnessResult => ({
  status: "fail",
  findings: [finding],
  extent: null,
  receipts: [],
});

/** SHA-256 of the concatenated parts, as octets. */
async function digest(...parts: readonly Uint8Array[]): Promise<Uint8Array> {
  const joined = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  return hex(await sha256Hex(joined));
}

/** The tree leaf naming a checkpoint: SHA-256(0x00 || JCS(...)). */
async function treeLeaf(
  logId: string,
  size: number,
  checkpointCose: Uint8Array,
  salt: string,
): Promise<Uint8Array> {
  return digest(
    Uint8Array.of(0),
    jcs({
      checkpoint_sha256: await sha256Hex(checkpointCose),
      log_id: logId,
      salt,
      size,
    }),
  );
}

/** The root from a leaf, its position and its path (leaf first). */
async function treeRoot(
  leaf: Uint8Array,
  index: number,
  path: readonly Uint8Array[],
): Promise<Uint8Array> {
  let h = leaf;
  // index may exceed 2^31, so its bits are read arithmetically.
  for (const [level, sibling] of path.entries())
    h =
      Math.floor(index / 2 ** level) % 2 === 0
        ? await digest(Uint8Array.of(1), h, sibling)
        : await digest(Uint8Array.of(1), sibling, h);
  return h;
}

/**
 * Verify `stated.checkpoint.cose`: "malformed" when it is not unpadded
 * canonical base64url, "invalid" when the octets do not verify, else the
 * signed fields and the octets.
 */
async function signedCheckpoint(
  stated: unknown,
): Promise<
  "malformed" | "invalid" | { signed: SignedCheckpointFields; cose: Uint8Array }
> {
  const checkpoint = object(stated) ? stated.checkpoint : undefined;
  const cose = decodeCose(object(checkpoint) ? checkpoint.cose : undefined);
  if (cose === undefined) return "malformed";
  const signed = await signedCheckpointFields(cose);
  return signed === undefined ? "invalid" : { signed, cose };
}

/**
 * Check a `parent-log-witness/v1` block against the Bundle's SIGNED
 * checkpoint (`signed`, its fields as `checkpoint.cose` states them, and
 * `cose`, its octets; undefined when it did not verify), and the Receipts
 * over the parent checkpoint under `directory` (undefined trusts no
 * witness). The links are checked in the draft's order and the first that
 * fails is the result. Never throws on its input.
 */
export async function verifyParentLogWitness(
  block: unknown,
  signed: SignedCheckpointFields | undefined,
  cose: Uint8Array | undefined,
  directory?: unknown,
): Promise<ParentWitnessResult> {
  if (signed === undefined || cose === undefined)
    return {
      status: "withheld",
      findings: ["checkpoint_unverified"],
      extent: null,
      receipts: [],
    };
  if (!object(block)) return failed("parent_witness_malformed");

  let covered = signed,
    coveredCose = cose;
  if (Object.hasOwn(block, "earlier")) {
    const earlier = block.earlier;
    const prior = await signedCheckpoint(earlier);
    if (prior === "malformed")
      return failed("parent_witness_earlier_checkpoint_malformed");
    if (prior === "invalid")
      return failed("parent_witness_earlier_checkpoint_signature_invalid");
    if (
      prior.signed.key_id !== signed.key_id ||
      prior.signed.log_id !== signed.log_id ||
      prior.signed.mmr_size >= signed.mmr_size
    )
      return failed("parent_witness_earlier_checkpoint_not_this_log");
    // signedCheckpoint verified, so `earlier` is an object.
    const proof = consistencyProof(
      (earlier as Record<string, unknown>).consistency_proof,
    );
    if (
      proof === undefined ||
      proof.oldSize !== BigInt(prior.signed.mmr_size) ||
      proof.newSize !== BigInt(signed.mmr_size) ||
      !(await verifyConsistency(
        hex(prior.signed.root),
        hex(signed.root),
        proof,
      ))
    )
      return failed("parent_witness_earlier_checkpoint_not_a_prefix");
    covered = prior.signed;
    coveredCose = prior.cose;
  }

  const logId = block.log_id,
    size = block.size;
  if (
    typeof logId !== "string" ||
    logId !== covered.log_id ||
    !uint(size) ||
    size !== covered.mmr_size
  )
    return failed("parent_witness_leaf_does_not_name_this_checkpoint");
  const path = block.path;
  if (
    !Array.isArray(path) ||
    path.length > PARENT_WITNESS_MAX_PATH ||
    !path.every(isHex64)
  )
    return failed("parent_witness_path_malformed");
  const salt = block.salt,
    index = block.index;
  if (
    typeof salt !== "string" ||
    salt === "" ||
    !uint(index) ||
    index >= 2 ** path.length
  )
    return failed("parent_witness_leaf_malformed");
  let leaf: Uint8Array;
  try {
    leaf = await treeLeaf(logId, size, coveredCose, salt);
  } catch {
    // A salt JCS cannot render (an unpaired surrogate) is no salt.
    return failed("parent_witness_leaf_malformed");
  }
  const root = await treeRoot(leaf, index, path.map(hex));

  const parent = block.parent;
  const parentCheckpoint = await signedCheckpoint(parent);
  if (parentCheckpoint === "malformed")
    return failed("parent_witness_parent_checkpoint_malformed");
  if (parentCheckpoint === "invalid")
    return failed("parent_witness_parent_checkpoint_signature_invalid");
  const parentSigned = parentCheckpoint.signed;
  if (parentSigned.key_id !== signed.key_id)
    return failed("parent_witness_parent_signer_differs");
  // signedCheckpoint verified, so `parent` is an object.
  const stated = parent as Record<string, unknown>;
  if (
    typeof stated.log_id !== "string" ||
    stated.log_id !== parentSigned.log_id
  )
    return failed("parent_witness_parent_log_id_mismatch");
  const entryIndex = stated.entry_index;
  const inclusion = parseProof(stated.inclusion_proof);
  if (
    !uint(entryIndex) ||
    inclusion === undefined ||
    inclusion.size !== parentSigned.mmr_size ||
    inclusion.leaf_index !== entryIndex ||
    !(await verifyProof(
      hex(parentSigned.root),
      Array.from(root, (byte) => byte.toString(16).padStart(2, "0")).join(""),
      inclusion,
      entryIndex,
    ))
  )
    return failed("parent_witness_entry_not_included");

  const { status, findings, receipts } = await verifyWitnessReceipts(
    stated.witnesses,
    parentSigned,
    parentCheckpoint.cose,
    directory,
  );
  const entries = leafCount(BigInt(covered.mmr_size)),
    of = leafCount(BigInt(signed.mmr_size));
  return {
    status,
    findings,
    extent:
      status === "pass" && entries !== undefined && of !== undefined
        ? { entries: Number(entries), of: Number(of) }
        : null,
    receipts,
  };
}
