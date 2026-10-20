// The Evidence Bundle producer: buildEvidenceBundle over a ProofSource and
// buildUnprovenBundle, as python/tests/test_bundle_producer.py checks them.
//
// Every produced Bundle is read back with strict verifyBundle: a
// range-proven Bundle of signed records is VALID, a producer-selected one
// INCOMPLETE, and a one-byte change INVALID. Each refusal is checked by name.
import {
  checkpointMetadata,
  createCheckpointIdentity,
  MemoryStore,
  MmrTree,
  signCheckpoint,
} from "@action-state-group/cll";
import { beforeAll, describe, expect, it } from "vitest";
import {
  BundleBuildError,
  buildEvidenceBundle,
  buildUnprovenBundle,
  proofSourceFromCll,
  verifyBundle,
  type ProofSource,
  type RecordStore,
  type StoredRecord,
} from "../src/bundle.js";
import { jcs, jsonDigest } from "../src/json.js";
import {
  createEd25519Identity,
  signCapsuleId,
} from "../src/producer-envelope.js";
import { computeCapsuleId } from "../src/verify.js";

type Obj = Record<string, unknown>;

const PRODUCER = createEd25519Identity(new Uint8Array(32).fill(0x0b));
const LOG_KEY = createCheckpointIdentity(new Uint8Array(32).fill(0x2c));
const LOG_ID = "log:producer-tests";
const TIMESTAMP = "2026-10-19T00:00:00Z";
const ABSENT = "ab".repeat(32);

const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(Buffer.from(value, "hex"));

async function capsule(
  actionId: string,
  options: { parent?: string; cites?: string[]; agentInput?: unknown } = {},
): Promise<Obj> {
  const record: Obj = {
    spec_version: "draft-mih-scitt-agent-action-capsule-04",
    format_version: "4",
    canonicalization_id: "jcs",
    action_id: actionId,
    action_type: "fyi",
    operator: "ACME-CO",
    developer: "agent@v1",
    timestamp: TIMESTAMP,
    assurance: {
      effect_mode: "not_applicable",
      attestation_mode: "self_attested",
      ledger_mode: "standalone",
    },
    disposition: {
      verdict_class: "not_applicable",
      decision: "report",
      approver: "policy",
      human_disposed: false,
    },
  };
  if (options.parent)
    record.chain = { parent_capsule_id: options.parent, relation: "follows" };
  if (options.cites?.length)
    record.references = options.cites.map((digest) => ({
      type: "agent-action-capsule",
      digest_alg: "SHA-256",
      digest,
    }));
  if (options.agentInput !== undefined)
    record.model_attestation = {
      compute_attestation: {
        agent_input_digest: await jsonDigest(options.agentInput),
      },
    };
  record.capsule_id = await computeCapsuleId(record as never);
  return record;
}

const envelope = (capsuleId: string): Uint8Array =>
  signCapsuleId(capsuleId, PRODUCER);

class NotFound extends Error {
  public readonly code = "not_found";
}

/**
 * A record store in the artifact-store shape: `get` resolves to capsule and
 * envelope bytes, and rejects with an error whose `code` is "not_found".
 */
class Records implements RecordStore {
  public readonly held = new Map<string, StoredRecord>();
  public put(record: Obj, signed = true): void {
    const id = record.capsule_id as string;
    this.held.set(id, {
      capsule: jcs(record),
      producerEnvelope: signed ? envelope(id) : new Uint8Array(),
    });
  }
  public async get(capsuleId: string): Promise<StoredRecord> {
    const stored = this.held.get(capsuleId);
    if (stored === undefined) throw new NotFound(capsuleId);
    return stored;
  }
}

/**
 * A CLL memory backend holding `leaves` (hex values), checkpointed after the
 * first `checkpointAfter` leaves (all by default).
 */
async function makeLog(
  leaves: readonly string[],
  records: RecordStore,
  checkpointAfter = leaves.length,
): Promise<ProofSource> {
  const backend = new MemoryStore();
  const tree = new MmrTree();
  for (const [index, value] of leaves.entries()) {
    await backend.append({ value: fromHex(value), appendedAt: new Date(0) });
    if (index < checkpointAfter) await tree.appendHexIdentity(value);
  }
  const peaks = tree.peakHashes();
  const signed = await signCheckpoint({
    logId: LOG_ID,
    mmrSize: tree.size,
    peaks,
    previousSize: 0n,
    previousPeaks: [],
    timestamp: TIMESTAMP,
    identity: LOG_KEY,
  });
  await backend.commitCll(0n, undefined, {
    size: tree.size,
    nodes: tree.nodes(),
    indexedSeq: BigInt(checkpointAfter),
    checkpoint: signed.cose,
    checkpointSize: tree.size,
    checkpointIndexedSeq: BigInt(checkpointAfter),
    checkpointPeaks: peaks,
    witnesses: [],
  });
  return proofSourceFromCll(backend, records);
}

async function verdict(bundle: unknown): Promise<string> {
  return (await verifyBundle(bundle, { strict: true })).strict.verdict;
}
async function claims(bundle: unknown): Promise<Record<string, string>> {
  const result = await verifyBundle(bundle, { strict: true });
  return Object.fromEntries(
    result.strict.claims.map((claim) => [claim.name, claim.status]),
  );
}
const ids = (bundle: Obj): string[] =>
  (bundle.records as Obj[]).map((record) => record.capsule_id as string);
const refused = (promise: Promise<unknown>, message: string | RegExp) =>
  expect(promise).rejects.toThrow(
    expect.objectContaining({
      name: "BundleBuildError",
      message: expect.stringMatching(message),
    }),
  );

/** Three signed records, each citing the one before; every leaf a record. */
let source: ProofSource, caps: Obj[], records: Records;
const cid = (index: number): string => caps[index]!.capsule_id as string;
beforeAll(async () => {
  records = new Records();
  const a = await capsule("a", { agentInput: { step: 0 } });
  const b = await capsule("b", { parent: a.capsule_id as string });
  const c = await capsule("c", { parent: b.capsule_id as string });
  caps = [a, b, c];
  for (const record of caps) records.put(record);
  source = await makeLog(
    caps.map((record) => record.capsule_id as string),
    records,
  );
});

describe("success", () => {
  it("a whole-log range is VALID", async () => {
    const bundle = await buildEvidenceBundle(source, {
      root: cid(2),
      intervalFrom: 1,
    });
    expect(ids(bundle)).toEqual([cid(0), cid(1), cid(2)]);
    const cert = bundle.completeness_certificate as Obj;
    expect([cert.first_seq, cert.last_seq]).toEqual([1, 3]);
    expect(cert.body_digests).toEqual([cid(0), cid(1), cid(2)]);
    expect(bundle.completeness).not.toHaveProperty("selection");
    for (const record of bundle.records as Obj[])
      expect(record.key_id).toBe(toHex(PRODUCER.publicKey));
    expect(await verdict(bundle)).toBe("VALID");
  });

  it("a suffix range is VALID", async () => {
    const bundle = await buildEvidenceBundle(source, {
      root: cid(2),
      intervalFrom: 2,
      closureDepth: 1,
    });
    expect(ids(bundle)).toEqual([cid(1), cid(2)]);
    expect(await verdict(bundle)).toBe("VALID");
  });

  it("no range is producer-selected and INCOMPLETE", async () => {
    const bundle = await buildEvidenceBundle(source, {
      root: cid(1),
      intervalFrom: null,
      closureDepth: 0,
    });
    expect(ids(bundle)).toEqual([cid(1)]);
    expect((bundle.completeness as Obj).selection).toBe("producer-selected");
    expect(bundle.completeness_certificate).not.toHaveProperty("range_proof");
    expect((await claims(bundle)).per_record_membership).toBe("pass");
    expect(await verdict(bundle)).toBe("INCOMPLETE");
  });

  it("checkpoint fields come from the signed statement", async () => {
    const bundle = await buildEvidenceBundle(source, {
      root: cid(0),
      intervalFrom: 1,
    });
    const cp = bundle.checkpoint as Obj;
    const decoded = (await checkpointMetadata(
      Uint8Array.from(Buffer.from(cp.cose as string, "base64url")),
    ))!;
    expect(cp).toMatchObject({
      log_id: decoded.logId,
      mmr_size: Number(decoded.size),
      root: decoded.root,
      prev_size: Number(decoded.previousSize),
      prev_root: decoded.previousRoot,
      key_id: decoded.keyId,
      timestamp: decoded.timestamp,
    });
  });

  it("include carries further records", async () => {
    const bundle = await buildEvidenceBundle(source, {
      root: cid(2),
      intervalFrom: null,
      closureDepth: 0,
      include: [cid(0)],
    });
    expect(ids(bundle)).toEqual([cid(0), cid(2)]);
  });

  it("an unsigned record is carried unsigned and INCOMPLETE", async () => {
    const store = new Records();
    const a = await capsule("unsigned");
    store.put(a, false);
    const bundle = await buildEvidenceBundle(
      await makeLog([a.capsule_id as string], store),
      { root: a.capsule_id as string, intervalFrom: 1 },
    );
    const record = (bundle.records as Obj[])[0]!;
    expect(record).not.toHaveProperty("signature");
    expect(record).not.toHaveProperty("key_id");
    expect((await claims(bundle)).signatures).toBe("withheld");
    expect(await verdict(bundle)).toBe("INCOMPLETE");
  });

  it("a missing citation is declared and INCOMPLETE", async () => {
    const store = new Records();
    const a = await capsule("cites-absent", { cites: [ABSENT] });
    store.put(a);
    const bundle = await buildEvidenceBundle(
      await makeLog([a.capsule_id as string], store),
      { root: a.capsule_id as string, intervalFrom: 1 },
    );
    expect((bundle.completeness as Obj).missing).toEqual([ABSENT]);
    expect((bundle.completeness as Obj).records_mode).toBe(
      "declared_incomplete",
    );
    expect(await verdict(bundle)).toBe("INCOMPLETE");
  });

  it("disclosures and payloadsMode", async () => {
    const root = cid(0);
    const revealed = await buildEvidenceBundle(source, {
      root,
      intervalFrom: null,
      closureDepth: 0,
      disclosures: { [root]: { agent_input: { step: 0 } } },
    });
    expect((revealed.completeness as Obj).payloads_mode).toBe("all");
    expect((await claims(revealed)).disclosures).toBe("pass");
    const plain = await buildEvidenceBundle(source, {
      root,
      intervalFrom: null,
      closureDepth: 0,
    });
    expect((plain.completeness as Obj).payloads_mode).toBe("selected");
    // Material carried elsewhere is the caller's claim.
    const declared = await buildEvidenceBundle(source, {
      root,
      intervalFrom: null,
      closureDepth: 0,
      payloadsMode: "all",
    });
    expect((declared.completeness as Obj).payloads_mode).toBe("all");
    await refused(
      buildEvidenceBundle(source, {
        root: cid(2),
        intervalFrom: 1,
        payloadsMode: "all",
        disclosures: { [cid(1)]: {}, [root]: {} },
      }),
      /does not reveal/,
    );
  });

  it("extensions, verification and producerKey", async () => {
    const key = Uint8Array.from({ length: 32 }, (_, index) => index);
    const bundle = await buildEvidenceBundle(source, {
      root: cid(0),
      intervalFrom: 1,
      producerKey: key,
      extensions: { "example/notes": { n: 1 } },
      verification: { producer: "tests", checks: [] },
    });
    expect(bundle.extensions).toEqual({
      "example/notes": { n: 1 },
      "producer-key/v1": { public_key: toHex(key) },
    });
    expect(bundle.verification).toEqual({ producer: "tests", checks: [] });
    expect(await verdict(bundle)).toBe("VALID");
    for (const owned of ["producer-key/v1", "composed/v1"])
      await refused(
        buildEvidenceBundle(source, {
          root: cid(0),
          intervalFrom: 1,
          extensions: { [owned]: {} },
        }),
        /owns/,
      );
    await refused(
      buildEvidenceBundle(source, {
        root: cid(0),
        intervalFrom: 1,
        producerKey: new Uint8Array(5),
      }),
      /32-byte/,
    );
  });
});

describe("tamper", () => {
  const flip = (text: string): string =>
    (text[0] !== "0" ? "0" : "1") + text.slice(1);
  it.each([
    "record",
    "body_digest",
    "inclusion_proof",
    "range_witness",
    "cose",
    "checkpoint_root",
  ])("a one-byte change in %s is INVALID", async (where) => {
    const bundle = await buildEvidenceBundle(source, {
      root: cid(2),
      intervalFrom: 2,
      closureDepth: 1,
    });
    const bad = structuredClone(bundle);
    const cert = bad.completeness_certificate as Obj;
    const checkpoint = bad.checkpoint as Obj;
    if (where === "record") {
      const record = (bad.records as Obj[])[0]!;
      record.action_id = flip(record.action_id as string);
    } else if (where === "body_digest") {
      const digests = cert.body_digests as string[];
      digests[0] = flip(digests[0]!);
    } else if (where === "inclusion_proof") {
      const proof = (
        (cert.memberships as Obj)[cid(1)] as { inclusion_proof: Obj }
      ).inclusion_proof;
      const key = ["witness", "peaks_left", "peaks_right"].find(
        (name) => (proof[name] as string[]).length,
      )!;
      const hashes = proof[key] as string[];
      hashes[0] = flip(hashes[0]!);
    } else if (where === "range_witness") {
      const witness = (cert.range_proof as Obj).witness as string[];
      witness[0] = flip(witness[0]!);
    } else if (where === "cose") {
      const raw = Buffer.from(checkpoint.cose as string, "base64url");
      raw[raw.length - 1]! ^= 1;
      checkpoint.cose = raw.toString("base64url");
    } else checkpoint.root = flip(checkpoint.root as string);
    expect(await verdict(bad)).toBe("INVALID");
  });
});

describe("refusals", () => {
  it("intervalFrom is required", async () => {
    await refused(
      buildEvidenceBundle(source, { root: cid(0) } as never),
      /intervalFrom/,
    );
    for (const bad of [0, -1, true, "1", 1.5])
      await refused(
        buildEvidenceBundle(source, {
          root: cid(0),
          intervalFrom: bad as never,
        }),
        /intervalFrom/,
      );
    await refused(
      buildEvidenceBundle(source, { root: cid(0), intervalFrom: 9 }),
      /past the checkpoint tip/,
    );
  });

  it("a record below intervalFrom is refused by name", async () => {
    await refused(
      buildEvidenceBundle(source, {
        root: cid(2),
        intervalFrom: 2,
        closureDepth: 2,
      }),
      `below intervalFrom 2: ${cid(0)} \\(seq 1\\)`,
    );
    await refused(
      buildEvidenceBundle(source, {
        root: cid(2),
        intervalFrom: 3,
        closureDepth: 0,
        include: [cid(0)],
      }),
      /below intervalFrom/,
    );
  });

  it("a range over a non-record leaf is refused", async () => {
    const store = new Records();
    const a = await capsule("a"),
      b = await capsule("b");
    store.put(a);
    store.put(b);
    const stamp = "cd".repeat(32); // a leaf the store does not hold as a record
    const log = await makeLog(
      [a.capsule_id as string, stamp, b.capsule_id as string],
      store,
    );
    await refused(
      buildEvidenceBundle(log, {
        root: b.capsule_id as string,
        intervalFrom: 1,
      }),
      /seq 2 in the interval is not a record/,
    );
    expect(
      await verdict(
        await buildEvidenceBundle(log, {
          root: b.capsule_id as string,
          intervalFrom: 3,
        }),
      ),
    ).toBe("VALID");
  });

  it("an uncovered record is refused", async () => {
    const store = new Records();
    const a = await capsule("a"),
      late = await capsule("late");
    store.put(a);
    store.put(late);
    const log = await makeLog(
      [a.capsule_id as string, late.capsule_id as string],
      store,
      1,
    );
    await refused(
      buildEvidenceBundle(log, {
        root: late.capsule_id as string,
        intervalFrom: null,
      }),
      /is not a leaf at or below the checkpoint \(not yet covered, or not in this log\)/,
    );
  });

  it("an unknown root and include are refused", async () => {
    await refused(
      buildEvidenceBundle(source, { root: ABSENT, intervalFrom: null }),
      /no such record/,
    );
    await refused(
      buildEvidenceBundle(source, {
        root: cid(0),
        intervalFrom: null,
        include: [ABSENT],
      }),
      /include: no such record/,
    );
  });

  it.each([
    ["absent", [], undefined, /does not carry/],
    ["root", ["tool_args"], undefined, /not disclosure-eligible/],
    ["root-input", ["agent_input"], undefined, /declared suppressed/],
    [undefined, ["tool_args"], undefined, /suppressedFields names/],
    [undefined, [], "none", /payloadsMode must be/],
  ] as const)(
    "bad options are refused (%s, %j, %s)",
    async (which, suppressed, payloads, message) => {
      const root = cid(0);
      let disclosures: Record<string, Record<string, unknown>> | undefined;
      let suppressedFields: readonly string[] = suppressed;
      if (which === "absent") disclosures = { [ABSENT]: { agent_input: {} } };
      else if (which === "root") {
        disclosures = {
          [root]: Object.fromEntries(suppressed.map((m) => [m, {}])),
        };
        suppressedFields = [];
      } else if (which === "root-input")
        disclosures = { [root]: { agent_input: { step: 0 } } };
      await refused(
        buildEvidenceBundle(source, {
          root,
          intervalFrom: null,
          closureDepth: 0,
          ...(disclosures === undefined ? {} : { disclosures }),
          suppressedFields,
          payloadsMode: payloads as never,
        }),
        message,
      );
    },
  );

  it("a mismatched disclosure is refused by the self-check", async () => {
    const root = cid(0);
    await refused(
      buildEvidenceBundle(source, {
        root,
        intervalFrom: null,
        closureDepth: 0,
        disclosures: { [root]: { agent_input: { step: 9 } } },
      }),
      /does not verify/,
    );
  });

  it("a negative closureDepth is refused", async () => {
    await refused(
      buildEvidenceBundle(source, {
        root: cid(0),
        intervalFrom: null,
        closureDepth: -1,
      }),
      /closureDepth/,
    );
  });

  it("a source that lies is refused", async () => {
    const other = await capsule("other");
    const wrongInclusion = async (seq: number) => {
      const proof = await source.inclusionProof(seq);
      return { ...proof, leaf_index: (proof.leaf_index + 1) % 3 };
    };
    const cases: [Partial<ProofSource>, RegExp][] = [
      [{ checkpoint: async () => new Uint8Array() }, /does not verify/],
      [
        { leaves: async () => (await source.leaves()).slice(0, -1) },
        /the source gave 2 leaves/,
      ],
      [
        {
          leaves: async () => [
            new Uint8Array(5),
            ...(await source.leaves()).slice(1),
          ],
        },
        /32-byte/,
      ],
      [
        {
          record: async () => ({
            capsule: jcs(other),
            producerEnvelope: new Uint8Array(),
          }),
        },
        /different capsule/,
      ],
      [
        {
          record: async (id: string) => ({
            capsule: records.held.get(id)!.capsule,
            producerEnvelope: envelope(ABSENT),
          }),
        },
        /envelope does not verify/,
      ],
      [
        {
          record: async () => ({
            capsule: new TextEncoder().encode("not json"),
            producerEnvelope: new Uint8Array(),
          }),
        },
        /not a JSON object/,
      ],
      [{ inclusionProof: wrongInclusion }, /does not verify/],
    ];
    for (const [override, message] of cases)
      await refused(
        buildEvidenceBundle(
          { ...source, ...override },
          { root: cid(2), intervalFrom: null },
        ),
        message,
      );
  });

  it("a store error other than not_found propagates", async () => {
    const disk = new Error("disk");
    const broken = await makeLog([cid(0)], {
      get: async () => {
        throw disk;
      },
    });
    await expect(
      buildEvidenceBundle(broken, { root: cid(0), intervalFrom: null }),
    ).rejects.toBe(disk);
  });

  it("a log without a checkpoint is refused", async () => {
    const log = proofSourceFromCll(new MemoryStore(), new Records());
    expect(await log.leaves()).toEqual([]);
    await refused(
      buildEvidenceBundle(log, { root: ABSENT, intervalFrom: null }),
      /no checkpoint/,
    );
  });

  it("BundleBuildError is an Error", () => {
    expect(new BundleBuildError("x")).toBeInstanceOf(Error);
  });
});

describe("round-1 review", () => {
  /** A source every read of which fails: the refusal came first. */
  const untouchable: ProofSource = {
    checkpoint: () => Promise.reject(new Error("source read")),
    leaves: () => Promise.reject(new Error("source read")),
    record: () => Promise.reject(new Error("source read")),
    inclusionProof: () => Promise.reject(new Error("source read")),
    rangeProof: () => Promise.reject(new Error("source read")),
  };
  const deep = (levels: number): Obj => {
    let value: Obj = {};
    for (let level = 0; level < levels; level += 1) value = { n: value };
    return value;
  };

  it("a bundle with no canonical digest is refused", async () => {
    await refused(
      buildEvidenceBundle(source, {
        root: cid(0),
        intervalFrom: 1,
        extensions: { "example/notes": { n: 1.5 } },
      }),
      /no canonical digest/,
    );
    await refused(
      buildEvidenceBundle(source, {
        root: cid(0),
        intervalFrom: 1,
        verification: { count: 2 ** 60 },
      }),
      /no canonical digest/,
    );
  });

  it.each([
    ["a valid inline signature", "valid"],
    ["a malformed inline signature", "malformed"],
    ["only one of the two fields", "one"],
  ] as const)(
    "an empty envelope with %s is carried unsigned",
    async (_, kind) => {
      const a = await capsule(`inline-${kind}`);
      const id = a.capsule_id as string;
      const inline: Obj = { ...a };
      if (kind === "valid") {
        inline.signature = toHex(envelope(id));
        inline.key_id = toHex(PRODUCER.publicKey);
      } else if (kind === "malformed") {
        inline.signature = "zz";
        inline.key_id = toHex(PRODUCER.publicKey);
      } else inline.key_id = toHex(PRODUCER.publicKey);
      const store = new Records();
      store.held.set(id, {
        capsule: jcs(inline),
        producerEnvelope: new Uint8Array(),
      });
      const bundle = await buildEvidenceBundle(await makeLog([id], store), {
        root: id,
        intervalFrom: 1,
      });
      const record = (bundle.records as Obj[])[0]!;
      expect(record).not.toHaveProperty("signature");
      expect(record).not.toHaveProperty("key_id");
      expect((await claims(bundle)).signatures).toBe("withheld");
      expect(await verdict(bundle)).toBe("INCOMPLETE");
    },
  );

  it("the closure walk stops when nothing new is reached", async () => {
    const bundle = await buildEvidenceBundle(source, {
      root: cid(1),
      intervalFrom: null,
      closureDepth: Number.MAX_SAFE_INTEGER,
    });
    expect(ids(bundle)).toEqual([cid(0), cid(1)]);
    const lone = await buildUnprovenBundle([caps[1]!], {
      root: cid(1),
      closureDepth: Number.MAX_SAFE_INTEGER,
    });
    expect((lone.completeness as Obj).missing).toEqual([cid(0)]);
    for (const depth of [Number.MAX_SAFE_INTEGER + 1, 1.5, Infinity])
      await refused(
        buildEvidenceBundle(untouchable, {
          root: cid(0),
          intervalFrom: null,
          closureDepth: depth,
        }),
        /closureDepth must be a non-negative safe integer/,
      );
  });

  it("a derived payloadsMode is all when nothing committed is unrevealed", async () => {
    // caps[1] commits to no payload: vacuously all, with no overlay.
    const vacuous = await buildEvidenceBundle(source, {
      root: cid(1),
      intervalFrom: null,
      closureDepth: 0,
    });
    expect((vacuous.completeness as Obj).payloads_mode).toBe("all");
    const suppressed = await buildEvidenceBundle(source, {
      root: cid(0),
      intervalFrom: null,
      closureDepth: 0,
      suppressedFields: ["agent_input"],
    });
    expect((suppressed.completeness as Obj).payloads_mode).toBe("all");
    expect(
      (
        (await buildUnprovenBundle([caps[1]!], { root: cid(1) }))
          .completeness as Obj
      ).payloads_mode,
    ).toBe("all");
  });

  it("source proofs carry only their wire fields", async () => {
    const padded: ProofSource = {
      ...source,
      inclusionProof: async (seq) => ({
        ...(await source.inclusionProof(seq)),
        extra: 1,
        hook: () => 0,
      }),
      rangeProof: async (first) => ({
        ...(await source.rangeProof(first)),
        extra: 1,
      }),
    };
    const bundle = await buildEvidenceBundle(padded, {
      root: cid(2),
      intervalFrom: 2,
      closureDepth: 1,
    });
    const cert = bundle.completeness_certificate as Obj;
    expect(Object.keys(cert.range_proof as Obj).sort()).toEqual([
      "from_index",
      "from_seq",
      "size",
      "to_index",
      "to_seq",
      "witness",
    ]);
    for (const member of Object.values(cert.memberships as Obj))
      expect(
        Object.keys(
          (member as { inclusion_proof: Obj }).inclusion_proof,
        ).sort(),
      ).toEqual([
        "kind",
        "leaf_index",
        "peaks_left",
        "peaks_right",
        "size",
        "v",
        "witness",
      ]);
    expect(await verdict(bundle)).toBe("VALID");
  });

  it("a malformed source proof is refused", async () => {
    const throwing = Object.defineProperty({}, "v", {
      enumerable: true,
      get() {
        throw new Error("getter");
      },
    });
    const cases: [Partial<ProofSource>, RegExp][] = [
      [
        { inclusionProof: async () => "proof" as never },
        /the source's inclusion proof for seq 3 is malformed/,
      ],
      [
        { inclusionProof: async () => throwing as never },
        /inclusion proof for seq 3 is malformed/,
      ],
      [{ rangeProof: async () => null as never }, /range proof is malformed/],
      [
        {
          rangeProof: async (first) => ({
            ...(await source.rangeProof(first)),
            witness: [1] as never,
          }),
        },
        /range proof is malformed/,
      ],
    ];
    for (const [override, message] of cases)
      await refused(
        buildEvidenceBundle(
          { ...source, ...override },
          { root: cid(2), intervalFrom: 3, closureDepth: 0 },
        ),
        message,
      );
  });

  it("a source that lies under a range is refused", async () => {
    const corrupt = (hashes: string[]): void => {
      hashes[0] = (hashes[0]![0] !== "0" ? "0" : "1") + hashes[0]!.slice(1);
    };
    const cases: [Partial<ProofSource>, number, RegExp][] = [
      [
        {
          rangeProof: async (first) => {
            const proof = await source.rangeProof(first);
            const witness = [...proof.witness];
            corrupt(witness);
            return { ...proof, witness };
          },
        },
        2,
        /does not verify: .*range_proof_invalid/,
      ],
      [
        {
          leaves: async () => {
            const [a, b, ...rest] = await source.leaves();
            return [b!, a!, ...rest];
          },
        },
        1,
        /does not verify/,
      ],
      [
        {
          inclusionProof: async (seq) => {
            const proof = await source.inclusionProof(seq);
            const copy = {
              ...proof,
              witness: [...proof.witness],
              peaks_left: [...proof.peaks_left],
              peaks_right: [...proof.peaks_right],
            };
            const key = (
              ["witness", "peaks_left", "peaks_right"] as const
            ).find((name) => copy[name].length)!;
            corrupt(copy[key]);
            return copy;
          },
        },
        1,
        /does not verify: .*membership_proof_invalid/,
      ],
    ];
    for (const [override, intervalFrom, message] of cases)
      await refused(
        buildEvidenceBundle(
          { ...source, ...override },
          { root: cid(2), intervalFrom, closureDepth: 3 - intervalFrom },
        ),
        message,
      );
  });

  it("a record edited under its capsule_id is refused by name", async () => {
    const edited = { ...caps[1]!, action_id: "edited" };
    for (const intervalFrom of [1, null])
      await refused(
        buildEvidenceBundle(
          {
            ...source,
            record: async (id) =>
              id === cid(1)
                ? { capsule: jcs(edited), producerEnvelope: envelope(id) }
                : source.record(id),
          },
          { root: cid(2), intervalFrom },
        ),
        `record_identity_invalid:${cid(1)}`,
      );
  });

  it("a hostile source hash list is copied or refused, never thrown raw", async () => {
    // An iterator that throws is never used: the copy is made by index.
    const noIterator = (list: readonly string[]): string[] => {
      const copy = [...list];
      Object.defineProperty(copy, Symbol.iterator, {
        get() {
          throw new Error("iterator");
        },
      });
      return copy;
    };
    // An element that reads once, then throws: it passes the parser and
    // fails in the copy, inside the same error boundary.
    const secondReadThrows = (list: readonly string[]): string[] => {
      const copy = [...list];
      let reads = 0;
      Object.defineProperty(copy, 0, {
        enumerable: true,
        get() {
          reads += 1;
          if (reads > 1) throw new Error("second read");
          return list[0];
        },
      });
      return copy;
    };
    const holed = (list: readonly string[]): string[] => {
      const copy = [...list];
      delete copy[0];
      return copy;
    };
    const options = { root: cid(2), intervalFrom: 2, closureDepth: 1 };
    const withInclusion = (
      change: (list: readonly string[]) => string[],
    ): ProofSource => ({
      ...source,
      inclusionProof: async (seq) => {
        const proof = await source.inclusionProof(seq);
        const key = (["witness", "peaks_left", "peaks_right"] as const).find(
          (name) => proof[name].length,
        )!;
        return { ...proof, [key]: change(proof[key]) };
      },
    });
    const withRange = (
      change: (list: readonly string[]) => string[],
    ): ProofSource => ({
      ...source,
      rangeProof: async (first) => {
        const proof = await source.rangeProof(first);
        return { ...proof, witness: change(proof.witness) };
      },
    });
    for (const make of [withInclusion, withRange])
      expect(
        await verdict(await buildEvidenceBundle(make(noIterator), options)),
      ).toBe("VALID");
    for (const change of [secondReadThrows, holed]) {
      await refused(
        buildEvidenceBundle(withInclusion(change), options),
        /the source's inclusion proof for seq \d+ is malformed/,
      );
      await refused(
        buildEvidenceBundle(withRange(change), options),
        /the source's range proof is malformed/,
      );
    }
  });

  it("an include list with a hole is refused before the source is read", async () => {
    for (const include of [new Array(1), [cid(0), , cid(1)]])
      await refused(
        buildEvidenceBundle(untouchable, {
          root: cid(0),
          intervalFrom: null,
          include: include as string[],
        }),
        /include must be a list of Capsule IDs/,
      );
  });

  it("caller input is validated before the source is read", async () => {
    const base = { root: cid(0), intervalFrom: null };
    const cases: [Obj, RegExp][] = [
      [{ producerKey: "00".repeat(32) }, /producerKey must be/],
      [{ producerKey: new Uint8Array(31) }, /producerKey must be/],
      [{ include: cid(0) }, /include must be a list of Capsule IDs/],
      [{ include: [1] }, /include must be a list of Capsule IDs/],
      [{ extensions: [] }, /extensions must be a JSON object/],
      [{ extensions: "x" }, /extensions must be a JSON object/],
      [{ verification: [] }, /verification must be a JSON object/],
      [{ verification: 1 }, /verification must be a JSON object/],
      [
        { extensions: { "example/deep": deep(5000) } },
        /no canonical digest.*extensions: JSON nesting exceeds/,
      ],
      [
        { verification: deep(5000) },
        /no canonical digest.*verification: JSON nesting exceeds/,
      ],
    ];
    for (const [options, message] of cases)
      await refused(
        buildEvidenceBundle(untouchable, { ...base, ...options } as never),
        message,
      );
    await refused(
      buildUnprovenBundle(caps, {
        root: cid(0),
        disclosures: { [cid(0)]: { agent_input: deep(5000) } },
      }),
      /no canonical digest.*disclosures: JSON nesting exceeds/,
    );
    await refused(
      buildUnprovenBundle([{ ...caps[0]!, deep: deep(5000) }], {
        root: cid(0),
      }),
      /no canonical digest.*records: JSON nesting exceeds/,
    );
  });
});

describe("round-3 review", () => {
  it("a range over a Capsule ID repeated at two leaves is refused", async () => {
    // MemoryStore appends a repeated value idempotently, so this log is a
    // bare backend over an MMR that holds the repeat.
    const values = [cid(0), cid(1), cid(0)];
    const tree = new MmrTree();
    for (const value of values) await tree.appendHexIdentity(value);
    const signed = await signCheckpoint({
      logId: LOG_ID,
      mmrSize: tree.size,
      peaks: tree.peakHashes(),
      previousSize: 0n,
      previousPeaks: [],
      timestamp: TIMESTAMP,
      identity: LOG_KEY,
    });
    const repeated = proofSourceFromCll(
      {
        scanEntries: async (after, limit) =>
          values
            .slice(Number(after), Number(after) + limit)
            .map((value) => ({ value: fromHex(value) })),
        loadCll: async () => ({
          nodes: tree.nodes(),
          checkpoint: signed.cose,
          checkpointSize: tree.size,
          checkpointIndexedSeq: BigInt(values.length),
        }),
      },
      records,
    );
    await refused(
      buildEvidenceBundle(repeated, { root: cid(1), intervalFrom: 1 }),
      /does not verify/,
    );
  });

  it("a checkpoint with one signature byte flipped is refused", async () => {
    const cose = Uint8Array.from(await source.checkpoint());
    cose[cose.length - 1]! ^= 1;
    await refused(
      buildEvidenceBundle(
        { ...source, checkpoint: async () => cose },
        { root: cid(0), intervalFrom: 1 },
      ),
      /the checkpoint does not verify/,
    );
  });

  it("the bundle never aliases caller objects", async () => {
    const root = cid(0);
    const extensions = { "example/notes": { n: 1, list: [1] } };
    const verification = { producer: "tests", checks: [{ ok: true }] };
    const disclosures = { [root]: { agent_input: { step: 0 } } };
    const bundle = await buildEvidenceBundle(source, {
      root,
      intervalFrom: 1,
      extensions,
      verification,
      disclosures,
    });
    const before = structuredClone(bundle);
    extensions["example/notes"].n = 2;
    extensions["example/notes"].list.push(2);
    verification.checks[0]!.ok = false;
    disclosures[root]!.agent_input.step = 9;
    expect(bundle).toEqual(before);
    expect(await verdict(bundle)).toBe("VALID");

    const given = caps.map((record) => structuredClone(record));
    const unproven = await buildUnprovenBundle(given, { root: cid(2) });
    const snapshot = structuredClone(unproven);
    for (const record of given) record.action_id = "mutated";
    expect(unproven).toEqual(snapshot);
  });
});

describe("the unproven form", () => {
  it("carries no log proof", async () => {
    const bundle = await buildUnprovenBundle(caps, { root: cid(2) });
    expect(bundle).not.toHaveProperty("checkpoint");
    expect(bundle).not.toHaveProperty("completeness_certificate");
    expect((bundle.completeness as Obj).records_mode).toBe("complete");
    expect(await verdict(bundle)).toBe("INCOMPLETE");
    const partial = await buildUnprovenBundle(caps.slice(1), { root: cid(2) });
    expect((partial.completeness as Obj).missing).toEqual([cid(0)]);
  });

  it("refusals", async () => {
    await refused(
      buildUnprovenBundle(caps, { root: ABSENT }),
      /not among the records/,
    );
    await refused(
      buildUnprovenBundle([...caps, caps[0]!], { root: cid(0) }),
      /duplicate/,
    );
    await refused(buildUnprovenBundle([{}], { root: "x" }), /capsule_id/);
    await refused(
      buildUnprovenBundle(caps, {
        root: cid(0),
        disclosures: { [ABSENT]: {} },
      }),
      /does not carry/,
    );
  });
});

describe("leafContent (Evidence Bundle -02)", () => {
  const padding = async (label: string): Promise<Obj> => {
    const body = {
      record_type: "padding",
      epistemic_type: "producer_claim",
      store_nonce: await jsonDigest(label),
    };
    return { capsule_id: await jsonDigest(body), ...body };
  };
  /** A source with the optional `leafContent` capability over another. */
  const withContent = (
    base: ProofSource,
    contents: Map<number, unknown>,
  ): ProofSource => ({
    checkpoint: () => base.checkpoint(),
    leaves: () => base.leaves(),
    record: (id) => base.record(id),
    inclusionProof: (seq) => base.inclusionProof(seq),
    rangeProof: (seq) => base.rangeProof(seq),
    leafContent: async (seq) => structuredClone(contents.get(seq)),
  });
  /** Records at seq 1 and 3, padding at 2 and at the tip, 4. */
  const padded = async () => {
    const store = new Records();
    const a = await capsule("a"),
      b = await capsule("b");
    store.put(a);
    store.put(b);
    const pads = new Map<number, Obj>([
      [2, await padding("2")],
      [4, await padding("4")],
    ]);
    const log = await makeLog(
      [
        a.capsule_id as string,
        pads.get(2)!.capsule_id as string,
        b.capsule_id as string,
        pads.get(4)!.capsule_id as string,
      ],
      store,
    );
    return { log, a, b, pads };
  };

  it("a source with leafContent carries padding when asked", async () => {
    const { log, a, b, pads } = await padded();
    const stored = new Map(
      [...pads].map(([seq, pad]) => [
        seq,
        { ...pad, signature: "00", key_id: "11" }, // envelope dropped
      ]),
    );
    const bundle = await buildEvidenceBundle(withContent(log, stored), {
      root: b.capsule_id as string,
      intervalFrom: 1,
      carryNonRecordLeaves: true,
    });
    expect((bundle.completeness_certificate as Obj).non_record_leaves).toEqual([
      { seq: 2, content: pads.get(2) },
      { seq: 4, content: pads.get(4) },
    ]);
    expect(ids(bundle)).toEqual([a.capsule_id, b.capsule_id]);
    expect(await verdict(bundle)).toBe("VALID");
  });

  it("carrying over a range without padding adds no member", async () => {
    const bundle = await buildEvidenceBundle(withContent(source, new Map()), {
      root: cid(2),
      intervalFrom: 1,
      carryNonRecordLeaves: true,
    });
    expect(bundle.completeness_certificate).not.toHaveProperty(
      "non_record_leaves",
    );
  });

  it("carrying is off by default", async () => {
    const { log, b, pads } = await padded();
    await refused(
      buildEvidenceBundle(withContent(log, pads), {
        root: b.capsule_id as string,
        intervalFrom: 1,
      }),
      /seq 2 in the interval is not a record/,
    );
  });

  it("an old source is unchanged", async () => {
    const { log, b, pads } = await padded();
    expect(log.leafContent).toBeUndefined();
    await refused(
      buildEvidenceBundle(log, {
        root: b.capsule_id as string,
        intervalFrom: 1,
        carryNonRecordLeaves: true,
      }),
      /seq 2 in the interval is not a record/,
    );
    const old = await buildEvidenceBundle(log, {
      root: b.capsule_id as string,
      intervalFrom: null,
      closureDepth: 0,
    });
    const carried = await buildEvidenceBundle(withContent(log, pads), {
      root: b.capsule_id as string,
      intervalFrom: null,
      closureDepth: 0,
      carryNonRecordLeaves: true,
    });
    expect(carried).toEqual(old);
    expect(carried.completeness_certificate).not.toHaveProperty(
      "non_record_leaves",
    );
  });

  it("no padding in the interval means no member", async () => {
    const { log, b, pads } = await padded();
    await refused(
      buildEvidenceBundle(log, {
        root: b.capsule_id as string,
        intervalFrom: 3,
      }),
      /seq 4/,
    );
    const bundle = await buildEvidenceBundle(withContent(log, pads), {
      root: b.capsule_id as string,
      intervalFrom: 3,
      carryNonRecordLeaves: true,
    });
    expect((bundle.completeness_certificate as Obj).non_record_leaves).toEqual([
      { seq: 4, content: pads.get(4) },
    ]);
  });

  it.each([
    [{ record_type: "checkpoint_stamp" }, /not a padding record/],
    ["padding", /not a padding record/],
    ["wrong-nonce", /does not hash to the leaf/],
    ["no-id", /does not hash to the leaf/],
    [{ record_type: "padding", weight: 0.5 }, /no canonical digest/],
  ])(
    "leafContent %j that is not that padding is refused",
    async (content, message) => {
      const { log, b, pads } = await padded();
      let given: unknown = content;
      if (content === "wrong-nonce")
        given = { ...pads.get(2), store_nonce: "00".repeat(32) };
      else if (content === "no-id") {
        const { capsule_id: _, ...rest } = pads.get(2)!;
        given = rest;
      }
      await refused(
        buildEvidenceBundle(
          withContent(log, new Map<number, unknown>([...pads, [2, given]])),
          {
            root: b.capsule_id as string,
            intervalFrom: 1,
            carryNonRecordLeaves: true,
          },
        ),
        message,
      );
    },
  );

  it("a malformed padding shape is refused by the self-check", async () => {
    const body = {
      record_type: "padding",
      epistemic_type: "producer_claim",
      store_nonce: "AB".repeat(32),
    };
    const bad = { capsule_id: await jsonDigest(body), ...body };
    const store = new Records();
    const a = await capsule("a");
    store.put(a);
    const log = await makeLog([a.capsule_id as string, bad.capsule_id], store);
    await refused(
      buildEvidenceBundle(withContent(log, new Map([[2, bad]])), {
        root: a.capsule_id as string,
        intervalFrom: 1,
        carryNonRecordLeaves: true,
      }),
      /non_record_leaf_malformed:2/,
    );
  });
});
