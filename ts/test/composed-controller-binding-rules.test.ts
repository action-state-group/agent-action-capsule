// The composed/v1 controller_binding join: -02's own rules layered on the one
// binding verifier, as go/bundle/composed_binding_test.go reads them. Records
// are re-signed with the vectors' test seeds (vectors/bundle/composed-controller-binding/).
import { createHash, createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { composedDigest, jcs, verifyBundle } from "../src/index.js";

type Obj = Record<string, unknown>;
interface Case {
  id: string;
  container: Obj;
  controller_bindings: Obj[];
}
const FILE = JSON.parse(
  readFileSync(
    resolve(
      process.cwd(),
      "..",
      "vectors",
      "bundle",
      "composed-controller-binding",
      "vectors.json",
    ),
    "utf8",
  ),
) as {
  keys: Record<string, { seed_hex: string; public_key_hex: string }>;
  cases: Case[];
};

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const linked = (): Case =>
  FILE.cases.find((c) => c.id === "controller-binding-linked")!;
const blockOf = (container: Obj): Obj =>
  (container.extensions as Obj)["composed/v1"] as Obj;

/** Sign `data` with the vectors' test seed for `name`. */
function seedSign(name: string, data: Uint8Array): string {
  const key = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.from(FILE.keys[name]!.seed_hex, "hex"),
    ]),
    format: "der",
    type: "pkcs8",
  });
  return sign(null, data, key).toString("hex");
}

const withoutSigs = (record: Obj): Obj => {
  const rest = { ...record };
  delete rest.sigs;
  return rest;
};

async function seal(container: Obj): Promise<Obj> {
  const block = blockOf(container);
  block.composed_digest = await composedDigest(block);
  return container;
}

/**
 * Re-sign `record` with the named keys in sigs order and point a copy of the
 * case's container at its new binding digest.
 */
async function resign(record: Obj, ...signers: string[]): Promise<Obj> {
  const input = jcs(withoutSigs(record));
  const sigs = record.sigs as Obj[];
  signers.forEach((name, i) => {
    sigs[i]!.sig = seedSign(name, input);
  });
  const container = clone(linked().container);
  ((blockOf(container).joins as Obj[])[0] as Obj).identifier_digest =
    createHash("sha256").update(input).digest("hex");
  return seal(container);
}

async function derive(
  container: Obj,
  controllerBindings: Obj[],
  bindingRevocations: Obj[] = [],
) {
  const result = await verifyBundle(container, {
    controllerBindings,
    bindingRevocations,
  });
  const block = result.extensions[0]!.composed!;
  if (block.malformed) throw new Error("malformed block");
  return block;
}

describe("composed controller_binding join: -02's own rules", () => {
  // A binding the verifier received but cannot read under the join's keys is
  // unjoined, never corroborating, whichever way it fails.
  it("failures never corroborate", async () => {
    const mutations: Record<string, (r: Obj) => void> = {
      "second signature from the first key": (r) => {
        const sigs = r.sigs as Obj[];
        sigs[1]!.sig = sigs[0]!.sig;
      },
      "one signature": (r) => {
        r.sigs = (r.sigs as Obj[]).slice(0, 1);
      },
      "third signature": (r) => {
        const sigs = r.sigs as Obj[];
        r.sigs = [...sigs, sigs[0]];
      },
      "sigs out of key order": (r) => {
        const sigs = r.sigs as Obj[];
        r.sigs = [sigs[1], sigs[0]];
      },
    };
    for (const [name, mutate] of Object.entries(mutations)) {
      const record = clone(linked().controller_bindings[0]!);
      mutate(record);
      const block = await derive(linked().container, [record]);
      expect(block.joins[0]!.derived, name).toBe("unjoined");
      expect(block.joins[0]!.result, name).toBe("join_state_mismatch");
      expect(block.corroboration[0]!.result, name).toBe("not_applicable");
    }
  });

  // -02: a binding with an empty nonce is malformed. Signed by both keys, it
  // is still unjoined (derivable, never linked); with a nonce it is linked.
  it("an empty nonce is malformed", async () => {
    const empty = clone(linked().controller_bindings[0]!);
    empty.nonce = "";
    const bad = await derive(
      await resign(empty, "responder-a", "responder-b"),
      [empty],
    );
    expect(bad.joins[0]!.derived).toBe("unjoined");
    const ok = clone(linked().controller_bindings[0]!);
    ok.nonce = "ceremony-2";
    const good = await derive(await resign(ok, "responder-a", "responder-b"), [
      ok,
    ]);
    expect(good.joins[0]!.derived).toBe("agree");
  });

  // -02 defines no key type but ed25519: a record naming another is well
  // formed, without CB v0's bip340 nonce rule, and not implemented.
  it("an undefined key type is not derivable, whatever its nonce", async () => {
    const record = clone(linked().controller_bindings[0]!);
    record.key_types = ["ed25519", "bip340"];
    const block = await derive(
      await resign(record, "responder-a", "responder-b"),
      [record],
    );
    expect(block.joins[0]!.result).toBe("not_derivable");
  });

  // A revocation statement that does not apply (another binding, a key that is
  // not bound, a bad signature, a time after both records) leaves the link.
  it("a revocation statement must apply", async () => {
    const c = linked();
    const digest = ((blockOf(c.container).joins as Obj[])[0] as Obj)
      .identifier_digest as string;
    const revoke = (name: string, binding: string, at: string): Obj => {
      const statement: Obj = {
        revocation_version: "controller-binding-revocation/0",
        binding,
        key_id: FILE.keys[name]!.public_key_hex,
        revoked_at: at,
      };
      statement.sig = seedSign(name, jcs(statement));
      return statement;
    };
    const badSignature = revoke("responder-b", digest, "2026-10-02T00:00:00Z");
    badSignature.sig = "0".repeat(128);
    const statements: Record<string, Obj> = {
      "another binding": revoke(
        "responder-b",
        "0".repeat(64),
        "2026-10-02T00:00:00Z",
      ),
      "unbound key": revoke("runtime observer", digest, "2026-10-02T00:00:00Z"),
      "bad signature": badSignature,
      "after both": revoke("responder-b", digest, "2026-10-03T00:00:00Z"),
    };
    for (const [name, statement] of Object.entries(statements)) {
      const block = await derive(c.container, c.controller_bindings, [
        statement,
      ]);
      expect(block.joins[0]!.derived, name).toBe("agree");
      expect(block.corroboration[0]!.result, name).toBe("redundant");
    }
    // Dated between the two root records' times, it reaches the later one.
    for (const [signer, at, derived] of [
      ["responder-a", "2026-10-02T12:10:30Z", "unjoined"],
      ["responder-b", "2026-10-02T12:11:00Z", "unjoined"],
      ["responder-b", "2026-10-02T12:11:01Z", "agree"],
      ["runtime observer", "2026-10-02T00:00:00Z", "agree"],
    ] as const) {
      const block = await derive(c.container, c.controller_bindings, [
        revoke(signer, digest, at),
      ]);
      expect(block.joins[0]!.derived, `${signer} ${at}`).toBe(derived);
    }
  });

  // A controller_binding join without identifier_digest or pointer names no
  // binding record, so it is not derivable, whatever the verifier received.
  it("a join without digest or pointer is not derivable", async () => {
    for (const member of ["identifier_digest", "pointer"]) {
      const container = clone(linked().container);
      const join = (blockOf(container).joins as Obj[])[0] as Obj;
      delete join[member];
      join.state = "unjoined";
      const block = await derive(
        await seal(container),
        linked().controller_bindings,
      );
      expect(block.joins[0]!.result, member).toBe("not_derivable");
    }
  });

  // Both root records under one bound key are not the record's two keys.
  it("needs both keys", async () => {
    const container = clone(linked().container);
    const members = blockOf(container).members as Obj[];
    const root = (m: Obj): Obj =>
      ((m.bundle as Obj).records as Obj[])[0] as Obj;
    root(members[1]!).key_id = root(members[0]!).key_id;
    const block = await derive(container, linked().controller_bindings);
    expect(block.joins[0]!.derived).toBe("unjoined");
  });

  // A sig that cannot be serialized (a float where a sig-hex belongs) is
  // malformed under ed25519 keys and merely not implemented under a key type
  // -02 does not define; the digest leaves sigs out, so the record still
  // matches its join.
  it("an unserializable sig is malformed or unimplemented by key type", async () => {
    const record = clone(linked().controller_bindings[0]!);
    (record.sigs as Obj[])[0]!.sig = 1.5;
    const sealed = async (r: Obj): Promise<Obj> => {
      const container = clone(linked().container);
      ((blockOf(container).joins as Obj[])[0] as Obj).identifier_digest =
        createHash("sha256")
          .update(jcs(withoutSigs(r)))
          .digest("hex");
      return seal(container);
    };
    expect(
      (await derive(await sealed(record), [record])).joins[0]!.derived,
    ).toBe("unjoined");
    record.key_types = ["ed25519", "x-example-type"];
    expect(
      (await derive(await sealed(record), [record])).joins[0]!.result,
    ).toBe("not_derivable");
  });
});
