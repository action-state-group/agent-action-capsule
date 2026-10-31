// Every case of vectors/controller-binding-v0 is run from its inputs alone and
// compared with the case's whole expected binding block and its
// issuer_independence, as go/controllerbinding/vectors_test.go does. The
// halves' own signatures and satisfied_becomes belong to the interop profile
// verifier, not to this verifier.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  bindingApplies,
  bindingAppliesTo,
  bindingBindsPair,
  pairIndependence,
  parseProfileTime,
  STATUS_FAIL,
  STATUS_NOT_CHECKED,
  STATUS_PASS,
  verifyBinding,
  type BindingOptions,
  type CredentialVerifier,
  type Instant,
} from "../src/controller-binding.js";
import { verifyEd25519Strict } from "../src/ed25519-strict.js";
import { decodeStrictJson, jcs } from "../src/json.js";

type Obj = Record<string, unknown>;
interface Case {
  id: string;
  pins: {
    evaluation_time: string;
    trust_policy: { credential_issuers: string[] };
    verification_policy: { credential_methods_implemented: string[] };
  };
  inputs: {
    halves: { octets_text: string }[];
    binding: { octets_text: string };
    revocations?: { octets_text: string }[];
    credential?: { octets_text: string };
    revocation_list?: { declaration: Obj; octets_text: string };
  };
  expected: {
    binding: {
      claim: string;
      binding_digest: string;
      properties: Record<string, string>;
      binds_pair: boolean;
      applies: boolean;
      proves: string[];
      revocation_list?: {
        profile: string;
        asserted_by: string;
        list_digest: string;
        as_of: string;
        counts: boolean;
      };
    };
    issuer_independence: {
      status: string;
      shown_as: string;
      reason: string | null;
    };
    fails: string[];
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
) as { credential_method: string; cases: Case[] };

const hexBytes = (text: string): Uint8Array =>
  Uint8Array.from(text.match(/../gu) ?? [], (b) => parseInt(b, 16));

/**
 * The credential format the vectors fix for themselves (CB §10), checked under
 * the case's pinned credential issuers. It is test code: the package ships no
 * credential verifier.
 */
const vectorCredential =
  (issuers: string[]): CredentialVerifier =>
  async (octets, credential, keys) => {
    let value: unknown;
    try {
      value = decodeStrictJson(octets);
    } catch {
      return STATUS_FAIL;
    }
    const o = value as Obj;
    if (
      typeof o !== "object" ||
      o === null ||
      Object.keys(o).length !== 5 ||
      o.issuer !== credential.issuer ||
      !issuers.includes(credential.issuer)
    )
      return STATUS_FAIL;
    for (const name of ["issued_at", "organization", "sig"])
      if (typeof o[name] !== "string") return STATUS_FAIL;
    const named = o.keys as unknown[];
    if (!Array.isArray(named) || named[0] !== keys[0] || named[1] !== keys[1])
      return STATUS_FAIL;
    const { sig, ...rest } = o;
    return (await verifyEd25519Strict(
      hexBytes(credential.issuer),
      hexBytes(sig as string),
      jcs(rest),
    ))
      ? STATUS_PASS
      : STATUS_FAIL;
  };

function inputs(c: Case): {
  keys: [string, string];
  times: Instant[];
} {
  const keys: string[] = [];
  const times: Instant[] = [];
  for (const h of c.inputs.halves) {
    const parsed = JSON.parse(h.octets_text) as Obj;
    keys.push(parsed.producer as string);
    times.push(parseProfileTime(parsed.issued_at)!);
  }
  return { keys: keys as [string, string], times };
}

describe("controller-binding-v0 vectors", () => {
  it("has 42 cases", () => expect(corpus.cases).toHaveLength(42));
  for (const c of corpus.cases)
    it(c.id, async () => {
      const { keys, times } = inputs(c);
      const options: BindingOptions = {
        revocations: (c.inputs.revocations ?? []).map((r) => r.octets_text),
        ...(c.inputs.credential === undefined
          ? {}
          : { credential: c.inputs.credential.octets_text }),
        ...(c.inputs.revocation_list === undefined
          ? {}
          : {
              revocationList: {
                declaration: JSON.stringify(
                  c.inputs.revocation_list.declaration,
                ),
                list: c.inputs.revocation_list.octets_text,
                evaluatedAt: parseProfileTime(c.pins.evaluation_time)!,
              },
            }),
        credentialVerifiers: Object.fromEntries(
          c.pins.verification_policy.credential_methods_implemented.map((m) => {
            expect(m).toBe(corpus.credential_method);
            return [
              m,
              vectorCredential(c.pins.trust_policy.credential_issuers),
            ];
          }),
        ),
      };
      const report = await verifyBinding(
        c.inputs.binding.octets_text,
        times,
        options,
      );
      const want = c.expected.binding;
      expect(report.claim).toBe(want.claim);
      expect(report.bindingDigest).toBe(want.binding_digest);
      expect(report.properties).toEqual(want.properties);
      expect(bindingBindsPair(report, keys[0], keys[1])).toBe(want.binds_pair);
      expect(bindingAppliesTo(report, keys[0], keys[1])).toBe(want.applies);
      expect(report.proves).toEqual(want.proves);
      if (report.revocationList !== undefined) {
        const got = report.revocationList;
        // A reason exactly when it does not count; a diagnostic, not a vector value.
        expect(got.counts).toBe(got.reason === undefined);
        expect({
          profile: got.profile,
          asserted_by: got.assertedBy,
          list_digest: got.listDigest,
          as_of: got.asOf,
          counts: got.counts,
        }).toEqual(want.revocation_list);
      } else expect(want.revocation_list).toBeUndefined();
      const independence = pairIndependence(keys[0], keys[1], report);
      expect({
        status: independence.status,
        shown_as: independence.shownAs,
        reason: independence.reason,
      }).toEqual({
        status: c.expected.issuer_independence.status,
        shown_as: c.expected.issuer_independence.shown_as,
        reason: c.expected.issuer_independence.reason,
      });
      const failed = Object.entries(report.properties)
        .filter(([, s]) => s === STATUS_FAIL)
        .map(([p]) => p);
      expect(failed.sort()).toEqual([...c.expected.fails].sort());
    });

  // With no credential verifier passed, a delivered credential is
  // NOT_CHECKED, never PASS: the package trusts no issuer of its own.
  it("a credential with no verifier is NOT_CHECKED", async () => {
    for (const c of corpus.cases) {
      if (c.inputs.credential === undefined) continue;
      const report = await verifyBinding(
        c.inputs.binding.octets_text,
        inputs(c).times,
        {
          credential: c.inputs.credential.octets_text,
        },
      );
      expect(report.properties.controller_binding_credential, c.id).toBe(
        STATUS_NOT_CHECKED,
      );
      expect(bindingApplies(report), c.id).toBe(c.expected.binding.applies);
    }
  });
});
