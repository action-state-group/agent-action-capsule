#!/usr/bin/env node
// The stdin/stdout adapter for the CI interlock.
//
// `seal` and `verify` read a Capsule. `bundle-produce <kind>` reads a
// producer fixture (vectors/cross-language/bundle-producer-log.json or
// bundle-producer-padded-log.json) and writes the JCS bytes of the Bundle
// `kind` names in its `builds`.
// `bundle-verify` reads a Bundle's JSON text and prints its strict verdict.
import { readFileSync } from "node:fs";
import {
  buildEvidenceBundle,
  decodeCapsuleJson,
  decodeFragment,
  jcs,
  proofSourceFromCll,
  sealCapsule,
  verifyBundle,
  verifyClass1,
} from "./index.js";
import type { CapsuleBody } from "./model.js";

const usage =
  "usage: cross-language seal|verify|bundle-produce <kind>|bundle-verify";

interface Fixture {
  readonly root: string;
  readonly builds: Record<
    string,
    {
      readonly interval_from: number | null;
      readonly closure_depth: number;
      readonly carry_non_record_leaves?: boolean;
    }
  >;
  /** Each padding leaf's content by seq, as a store holds it. */
  readonly leaf_contents?: Record<string, unknown>;
  readonly log: {
    readonly entries: readonly string[];
    readonly state: {
      readonly nodes: readonly string[];
      readonly checkpoint: {
        readonly cose: string;
        readonly size: number;
        readonly indexed_seq: number;
      };
    };
  };
  readonly records: Record<
    string,
    { readonly capsule: string; readonly producer_envelope: string }
  >;
}

const fromHex = (text: string): Uint8Array =>
  Uint8Array.from(Buffer.from(text, "hex"));

async function bundleProduce(kind: string): Promise<number> {
  const fixture = JSON.parse(readFileSync(0, "utf8")) as Fixture;
  const build = Object.hasOwn(fixture.builds, kind)
    ? fixture.builds[kind]
    : undefined;
  if (build === undefined) {
    console.error(`unknown bundle kind ${JSON.stringify(kind)}`);
    return 2;
  }
  const entries = fixture.log.entries.map((value) => ({
    value: fromHex(value),
  }));
  const { state } = fixture.log;
  const backend = {
    async scanEntries(afterSeq: bigint, limit: number) {
      return entries.slice(Number(afterSeq), Number(afterSeq) + limit);
    },
    async loadCll() {
      return {
        nodes: state.nodes.map(fromHex),
        checkpoint: fromHex(state.checkpoint.cose),
        checkpointSize: BigInt(state.checkpoint.size),
        checkpointIndexedSeq: BigInt(state.checkpoint.indexed_seq),
      };
    },
  };
  const records = {
    async get(capsuleId: string) {
      const record = Object.hasOwn(fixture.records, capsuleId)
        ? fixture.records[capsuleId]
        : undefined;
      if (record === undefined)
        throw Object.assign(new Error(capsuleId), { code: "not_found" });
      return {
        capsule: fromHex(record.capsule),
        producerEnvelope: fromHex(record.producer_envelope),
      };
    },
  };
  const source = proofSourceFromCll(backend, records);
  const contents = fixture.leaf_contents;
  if (contents !== undefined)
    source.leafContent = async (seq: number) =>
      Object.hasOwn(contents, String(seq)) ? contents[String(seq)] : undefined;
  const bundle = await buildEvidenceBundle(source, {
    root: fixture.root,
    intervalFrom: build.interval_from,
    closureDepth: build.closure_depth,
    carryNonRecordLeaves: build.carry_non_record_leaves === true,
  });
  process.stdout.write(jcs(bundle));
  return 0;
}

async function bundleVerify(): Promise<number> {
  // The Bundle's own strict reader: its URL-fragment decoder over these bytes.
  const text = readFileSync(0).toString("utf8").trim();
  let bundle: unknown;
  try {
    bundle = decodeFragment(Buffer.from(text, "utf8").toString("base64url"));
  } catch (error) {
    console.error(String(error));
    return 1;
  }
  const result = await verifyBundle(bundle, { strict: true });
  process.stdout.write(`${result.strict.verdict}\n`);
  return 0;
}

const [command, ...rest] = process.argv.slice(2);
if (command === "bundle-produce" && rest.length === 1) {
  process.exitCode = await bundleProduce(rest[0]!);
} else if (command === "bundle-verify" && rest.length === 0) {
  process.exitCode = await bundleVerify();
} else if ((command === "seal" || command === "verify") && rest.length === 0) {
  const value = decodeCapsuleJson(readFileSync(0));
  if (command === "seal") {
    process.stdout.write(
      `${JSON.stringify(await sealCapsule(value as unknown as CapsuleBody))}\n`,
    );
  } else {
    const result = await verifyClass1(value);
    if (!result.ok) {
      console.error(result.findings.map((finding) => finding.code).join(", "));
      process.exit(1);
    }
    process.stdout.write(`${result.capsuleId ?? ""}\n`);
  }
} else {
  console.error(usage);
  process.exit(2);
}
