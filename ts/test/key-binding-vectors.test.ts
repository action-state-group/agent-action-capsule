// verifyKeyBinding over the shared vectors/controller-binding-v0 files (the
// same ones Go reads): the key asked about is the first half's producer.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { parseProfileTime } from "../src/controller-binding.js";
import { verifyKeyBinding } from "../src/key-binding.js";
import { decodeStrictJson } from "../src/json.js";

interface Case {
  id: string;
  pins: { evaluation_time: string };
  inputs: {
    halves: { octets_text: string }[];
    binding: { octets_text: string };
    revocations?: { octets_text: string }[];
    revocation_list?: { declaration: unknown; octets_text: string };
  };
  expected: {
    binding: { properties: Record<string, string> };
  };
}
const corpus = JSON.parse(
  readFileSync(
    resolve(
      process.cwd(),
      "..",
      "vectors",
      "controller-binding-v0",
      "vectors.json",
    ),
    "utf8",
  ),
) as { cases: Case[] };

const half = (c: Case, i: number) =>
  decodeStrictJson(c.inputs.halves[i]!.octets_text) as {
    producer: string;
    issued_at: string;
  };
const get = (id: string) => corpus.cases.find((c) => c.id === id)!;

describe("verifyKeyBinding", () => {
  it("is NOT_CHECKED with no cited binding", async () => {
    const c = get("valid-same-controller");
    const r = await verifyKeyBinding(
      half(c, 0).producer,
      parseProfileTime(half(c, 0).issued_at)!,
      [],
    );
    expect(r.status).toBe("NOT_CHECKED");
  });
  it("is NOT_CHECKED when the binding names neither half's key", async () => {
    const c = get("no-half-key-bound");
    const r = await verifyKeyBinding(
      half(c, 0).producer,
      parseProfileTime(half(c, 0).issued_at)!,
      [c.inputs.binding.octets_text],
    );
    expect(r.status).toBe("NOT_CHECKED");
  });
  for (const c of corpus.cases) {
    const key = half(c, 0).producer;
    it(`${c.id}: status follows the vector's expected binding`, async () => {
      const list = c.inputs.revocation_list;
      const r = await verifyKeyBinding(
        key,
        parseProfileTime(half(c, 0).issued_at)!,
        [c.inputs.binding.octets_text],
        {
          revocations: (c.inputs.revocations ?? []).map((x) => x.octets_text),
          ...(list === undefined
            ? {}
            : {
                revocationList: {
                  declaration: JSON.stringify(list.declaration),
                  list: list.octets_text,
                  evaluatedAt: parseProfileTime(c.pins.evaluation_time)!,
                },
              }),
        },
      );
      const want = c.expected.binding;
      const named = r.bindings.length > 0;
      if (!named) {
        expect(r.status).toBe("NOT_CHECKED");
        return;
      }
      // The binding names the first half's key, so it is the pair's binding
      // or one of its keys is: the key-level answer is CB §6.2 for the
      // binding at the first half's time, and a revocation FAIL stops it.
      const rev = want.properties.controller_binding_revocation;
      if (rev === "FAIL") expect(r.status).toBe("FAIL");
      // Asked at one time (the first half's), not the pair's two, so a list
      // that does not cover the second half can count here; only the cases
      // the vector expects PASS must read as checked, and none without a list.
      if (list === undefined) expect(r.revocationChecked).toBe(false);
      else if (rev === "PASS") expect(r.revocationChecked).toBe(true);
    });
  }
  it("a revoked binding reads FAIL and a counting declaration sets revocationChecked", async () => {
    const at = (id: string) => parseProfileTime(half(get(id), 0).issued_at)!;
    for (const id of [
      "complete-list-revoked",
      "complete-list-malformed-revoked",
    ]) {
      const c = get(id);
      const list = c.inputs.revocation_list!;
      const r = await verifyKeyBinding(
        half(c, 0).producer,
        at(id),
        [c.inputs.binding.octets_text],
        {
          revocationList: {
            declaration: JSON.stringify(list.declaration),
            list: list.octets_text,
            evaluatedAt: parseProfileTime(c.pins.evaluation_time)!,
          },
        },
      );
      expect(r.status).toBe("FAIL");
    }
    const c = get("complete-list");
    const list = c.inputs.revocation_list!;
    const r = await verifyKeyBinding(
      half(c, 0).producer,
      at("complete-list"),
      [c.inputs.binding.octets_text],
      {
        revocationList: {
          declaration: JSON.stringify(list.declaration),
          list: list.octets_text,
          evaluatedAt: parseProfileTime(c.pins.evaluation_time)!,
        },
      },
    );
    expect(r.status).toBe("PASS");
    expect(r.revocationChecked).toBe(true);
  });
});
