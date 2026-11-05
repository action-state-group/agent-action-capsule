/**
 * Checkpoint consistency against a head the reader retained (verification
 * ladder rung 6).
 *
 * The head a reader kept from an earlier look at a log is the reader's own
 * state, so the producer cannot know it and it is no Bundle member: it is an
 * input to the verifier. {@link verifyRetainedHead} takes that retained head,
 * the log's current head (the Bundle's signed checkpoint, once authenticated)
 * and a consistency proof, and says whether the current head extends the
 * retained one. It never fetches anything and never guesses: with no retained
 * head, or no proof for a retained head that differs from the current one, the
 * status is `not_present`, never `pass`.
 *
 * Browser-safe (the same primitives as {@link verifyParentLogWitness}). See
 * `vectors/checkpoint-consistency/`.
 */
import { verifyConsistency } from "@action-state-group/cll";
import { consistencyProof, hex, integer, object } from "./cll-checkpoint.js";
import { isHex64 } from "./json.js";

/** A log head: the MMR size (the checkpoint's `mmr_size`) and its root, 64 lowercase hex. */
export interface LogHead {
  readonly size: number;
  readonly root: string;
}

/**
 * `pass`: the current head extends the retained one. `fail`: the inputs
 * contradict it or are malformed. `not_present`: nothing was supplied to
 * check, so nothing is stated.
 */
export interface RetainedHeadResult {
  readonly status: "pass" | "fail" | "not_present";
  /** Null when `pass`; otherwise the one reason. */
  readonly finding:
    | null
    | "retained_head_absent"
    | "consistency_proof_absent"
    | "retained_head_malformed"
    | "current_head_malformed"
    | "consistency_proof_malformed"
    | "consistency_proof_sizes_differ"
    | "retained_head_ahead_of_current"
    | "retained_head_root_differs"
    | "retained_head_not_a_prefix";
}

const result = (
  status: RetainedHeadResult["status"],
  finding: RetainedHeadResult["finding"],
): RetainedHeadResult => ({ status, finding });

function head(value: unknown): LogHead | undefined {
  return object(value) &&
    integer(value.size) &&
    value.size > 0 &&
    isHex64(value.root)
    ? { size: value.size, root: value.root }
    : undefined;
}

/**
 * Check that `current` extends `retained`.
 *
 * `retained` is the reader's kept head (undefined or null: none was supplied).
 * `current` is the log's head, taken from a checkpoint the caller has already
 * authenticated; this function checks no signature. `proof` is the consistency
 * proof from `retained.size` to `current.size`, in the wire shape of
 * `parent-log-witness/v1`'s `earlier.consistency_proof` (`kind`, `v`,
 * `old_size`, `new_size`, `old_peaks`, `witness`, `new_peaks`). When both
 * heads are the same size no proof is needed: they are consistent exactly when
 * the roots are equal. Never throws on its input.
 */
export async function verifyRetainedHead(
  retained: unknown,
  current: unknown,
  proof?: unknown,
): Promise<RetainedHeadResult> {
  if (retained === undefined || retained === null)
    return result("not_present", "retained_head_absent");
  const old = head(retained);
  if (old === undefined) return result("fail", "retained_head_malformed");
  const now = head(current);
  if (now === undefined) return result("fail", "current_head_malformed");
  if (old.size > now.size)
    return result("fail", "retained_head_ahead_of_current");
  if (old.size === now.size)
    return old.root === now.root
      ? result("pass", null)
      : result("fail", "retained_head_root_differs");
  if (proof === undefined || proof === null)
    return result("not_present", "consistency_proof_absent");
  const parsed = consistencyProof(proof);
  if (parsed === undefined)
    return result("fail", "consistency_proof_malformed");
  if (
    parsed.oldSize !== BigInt(old.size) ||
    parsed.newSize !== BigInt(now.size)
  )
    return result("fail", "consistency_proof_sizes_differ");
  try {
    return (await verifyConsistency(hex(old.root), hex(now.root), parsed))
      ? result("pass", null)
      : result("fail", "retained_head_not_a_prefix");
  } catch {
    return result("fail", "consistency_proof_malformed");
  }
}
