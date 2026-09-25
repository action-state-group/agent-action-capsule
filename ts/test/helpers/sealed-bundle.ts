import { MmrTree, inclusionProof, rangeProof } from "@action-state-group/cll";
// Imported directly (not via src/index.js) so this helper also loads under
// the jsdom test environment, where the emitter's node:fs shell read cannot.
import { jsonDigest } from "../../src/json.js";
import { computeCapsuleId } from "../../src/verify.js";

/**
 * Seal a hand-written evidence bundle into one the bundle verifier accepts.
 *
 * Fixtures are easiest to read with alias identities ("root", "act") and no
 * digests, but the evidence-graph model only accepts a disclosed payload whose
 * JCS SHA-256 equals the digest its record committed to, and the view only
 * renders rows from a bundle that verifies. This helper keeps the readable
 * source and derives the honest form at test time:
 *
 * - every record gets the format-4 fields Class 1 requires (existing fields
 *   win), a committed digest for each member disclosed for it, and a real
 *   capsule_id;
 * - every string value anywhere in the bundle (references, chain, payload
 *   contents, completeness.missing, root) that equals an alias is rewritten
 *   to the sealed capsule_id, in dependency order; disclosures are re-keyed;
 * - the records are appended, in their given order (or by existing
 *   membership seq), to a fresh MMR, and a completeness certificate plus
 *   checkpoint are built over it.
 *
 * Countersignatures are never carried over: they sign the old bundle digest.
 */

type Obj = Record<string, unknown>;

export interface SealedBundle {
  readonly bundle: Obj;
  /** alias (the capsule_id written in the source) -> sealed capsule_id */
  readonly ids: Readonly<Record<string, string>>;
}

const DISCLOSURE_MEMBERS = ["agent_input", "agent_output"] as const;

const BODY_DEFAULTS: Obj = {
  spec_version: "draft-mih-scitt-agent-action-capsule-04",
  format_version: "4",
  canonicalization_id: "jcs",
  action_type: "fyi",
  operator: "sealed-fixture",
  developer: "sealed-fixture@v1",
  timestamp: "2026-09-14T00:00:00Z",
  assurance: {
    effect_mode: "not_applicable",
    attestation_mode: "self_attested",
    ledger_mode: "standalone",
  },
};

const isObj = (value: unknown): value is Obj =>
  value !== null && typeof value === "object" && !Array.isArray(value);

function rewrite(value: unknown, ids: ReadonlyMap<string, string>): unknown {
  if (typeof value === "string") return ids.get(value) ?? value;
  if (Array.isArray(value)) return value.map((item) => rewrite(item, ids));
  if (isObj(value))
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, rewrite(item, ids)]),
    );
  return value;
}

function mentions(value: unknown, out: Set<string>): void {
  if (typeof value === "string") out.add(value);
  else if (Array.isArray(value)) value.forEach((item) => mentions(item, out));
  else if (isObj(value))
    for (const item of Object.values(value)) mentions(item, out);
}

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

export async function sealEvidenceBundle(source: Obj): Promise<SealedBundle> {
  const sourceRecords = (source.records as Obj[]).filter(isObj);
  const sourceDisclosures = isObj(source.disclosures) ? source.disclosures : {};
  const certificate = isObj(source.completeness_certificate)
    ? source.completeness_certificate
    : {};
  const memberships = isObj(certificate.memberships)
    ? certificate.memberships
    : {};
  const seqOf = (alias: string): number | undefined => {
    const member = memberships[alias];
    const coordinates = isObj(member) ? member.log_coordinates : undefined;
    return isObj(coordinates) && typeof coordinates.seq === "number"
      ? coordinates.seq
      : undefined;
  };
  const aliases = sourceRecords.map((record) => record.capsule_id as string);
  const ordered = aliases.every((alias) => seqOf(alias) !== undefined)
    ? [...aliases].sort((left, right) => seqOf(left)! - seqOf(right)!)
    : aliases;
  const byAlias = new Map(
    sourceRecords.map((record) => [record.capsule_id as string, record]),
  );

  const ids = new Map<string, string>();
  const sealed = new Map<string, Obj>();
  const disclosures: Obj = {};
  const pending = new Set(aliases);
  while (pending.size > 0) {
    let progressed = false;
    for (const alias of pending) {
      const record = byAlias.get(alias)!;
      const entry = isObj(sourceDisclosures[alias])
        ? sourceDisclosures[alias]
        : undefined;
      const dependencies = new Set<string>();
      mentions(record, dependencies);
      mentions(entry, dependencies);
      dependencies.delete(alias);
      if (
        [...dependencies].some(
          (dependency) => byAlias.has(dependency) && !ids.has(dependency),
        )
      )
        continue;
      const body: Obj = {
        ...BODY_DEFAULTS,
        action_id: alias,
        ...(rewrite(record, ids) as Obj),
      };
      delete body.capsule_id;
      const payloads =
        entry === undefined ? undefined : (rewrite(entry, ids) as Obj);
      if (payloads !== undefined) {
        const attestation = isObj(body.model_attestation)
          ? { ...body.model_attestation }
          : {};
        const compute = isObj(attestation.compute_attestation)
          ? { ...attestation.compute_attestation }
          : {};
        for (const member of DISCLOSURE_MEMBERS)
          if (Object.hasOwn(payloads, member))
            compute[`${member}_digest`] = await jsonDigest(payloads[member]);
        attestation.compute_attestation = compute;
        body.model_attestation = attestation;
      }
      const id = await computeCapsuleId(body as never);
      ids.set(alias, id);
      sealed.set(alias, { ...body, capsule_id: id });
      if (payloads !== undefined) disclosures[id] = payloads;
      pending.delete(alias);
      progressed = true;
    }
    if (!progressed)
      throw new Error(
        `cyclic capsule references among: ${[...pending].join(", ")}`,
      );
  }

  const records = ordered.map((alias) => sealed.get(alias)!);
  const tree = new MmrTree();
  for (const record of records)
    await tree.appendHexIdentity(record.capsule_id as string);
  const size = tree.size;
  const proofs = await Promise.all(
    records.map((_, index) => inclusionProof(tree, BigInt(index), size)),
  );
  const range = await rangeProof(tree, 0n, BigInt(records.length - 1), size);
  const logId =
    typeof certificate.log_id === "string"
      ? certificate.log_id
      : "sealed-fixture-log";
  const members: Obj = {};
  records.forEach((record, index) => {
    const proof = proofs[index]!;
    members[record.capsule_id as string] = {
      log_coordinates: { log_id: logId, seq: index + 1, leaf_index: index },
      inclusion_proof: {
        ...proof,
        witness: [...proof.witness],
        peaks_left: [...proof.peaks_left],
        peaks_right: [...proof.peaks_right],
      },
    };
  });
  const root = hex(await tree.root());

  const {
    records: _records,
    disclosures: _disclosures,
    completeness_certificate: _certificate,
    checkpoint: _checkpoint,
    countersignatures: _countersignatures,
    ...rest
  } = source;
  return {
    ids: Object.fromEntries(ids),
    bundle: {
      bundle_version: "2",
      bundle_kind: "evidence-bundle/v2",
      completeness: {
        closure_depth: 2,
        records_mode: "complete",
        payloads_mode: "all",
        suppressed_fields: [],
        missing: [],
      },
      ...(rewrite(rest, ids) as Obj),
      records,
      disclosures,
      completeness_certificate: {
        log_id: logId,
        range_root: root,
        first_seq: 1,
        last_seq: records.length,
        body_digests: records.map((record) => record.capsule_id),
        range_proof: {
          from_seq: 1,
          to_seq: records.length,
          size: Number(size),
          from_index: range.from_index,
          to_index: range.to_index,
          witness: [...range.witness],
        },
        memberships: members,
      },
      checkpoint: { root, mmr_size: Number(size) },
    },
  };
}
