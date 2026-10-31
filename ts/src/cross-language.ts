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
  "usage: cross-language seal|verify|bundle-produce <kind>|bundle-verify|composed-verify";

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

// `composed-verify` reads {container, controller_bindings, binding_revocations}
// and prints the container's composed/v1 block as one JCS line: its status and,
// per join, the declared and derived state, result and corroboration. The
// Python, Go and Rust adapters print the same line.
async function composedVerify(): Promise<number> {
  const input = JSON.parse(readFileSync(0, "utf8")) as {
    container: unknown;
    controller_bindings?: Record<string, unknown>[];
    binding_revocations?: Record<string, unknown>[];
  };
  // The Bundle's own strict reader, as bundle-verify uses.
  const container = decodeFragment(
    Buffer.from(JSON.stringify(input.container), "utf8").toString("base64url"),
  );
  const result = await verifyBundle(container, {
    controllerBindings: input.controller_bindings ?? [],
    bindingRevocations: input.binding_revocations ?? [],
  });
  const composed = result.extensions.find(
    (e) => e.composed !== undefined,
  )?.composed;
  if (composed === undefined || !("joins" in composed)) {
    console.error("no composed/v1 block");
    return 1;
  }
  const joins = composed.joins.map((join, i) => {
    const corroboration = composed.corroboration[i]!;
    return {
      members: [...join.members],
      declared: join.declared,
      derived: join.derived ?? null,
      result: join.result,
      corroboration: corroboration.result,
      reason: "reason" in corroboration ? corroboration.reason : null,
    };
  });
  process.stdout.write(
    `${new TextDecoder().decode(jcs({ status: composed.status, joins }))}\n`,
  );
  return 0;
}

const [command, ...rest] = process.argv.slice(2);
if (command === "bundle-produce" && rest.length === 1) {
  process.exitCode = await bundleProduce(rest[0]!);
} else if (command === "bundle-verify" && rest.length === 0) {
  process.exitCode = await bundleVerify();
} else if (command === "composed-verify" && rest.length === 0) {
  process.exitCode = await composedVerify();
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
