import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  computeCapsuleId,
  decodeStrictJson,
  verifyClass1,
  verifyStore,
  type ParsedJson,
} from "../src/index.js";

const root = resolve(import.meta.dirname, "..", "..", "vectors", "capsule");
const manifest = JSON.parse(
  readFileSync(resolve(root, "vectors.json"), "utf8"),
) as { cases: Array<{ name: string; kind: string }> };
describe("complete upstream AAC corpus", () => {
  for (const item of manifest.cases)
    it(item.name, async () => {
      const input = decodeStrictJson(
        readFileSync(resolve(root, item.name, "input.json")),
      );
      const expected = JSON.parse(
        readFileSync(resolve(root, item.name, "expected.json"), "utf8"),
      ) as {
        ok?: boolean;
        capsule_id_recomputed?: string;
        exception?: string | null;
        derived?: Record<string, string>;
        findings?: Array<{ code: string }>;
        results?: Array<{
          ok: boolean;
          capsule_id_recomputed?: string;
          findings: Array<{ code: string }>;
        }>;
      };
      if (item.kind === "canonical") {
        if (expected.exception !== null)
          await expect(
            computeCapsuleId(input as Record<string, ParsedJson>),
          ).rejects.toThrow();
        else
          expect(
            await computeCapsuleId(input as Record<string, ParsedJson>),
          ).toBe(expected.capsule_id_recomputed);
        return;
      }
      if (item.kind === "store") {
        const ledger = (input as { ledger: ParsedJson[] }).ledger;
        const actual = await verifyStore(ledger);
        expect(actual.map((result) => result.ok)).toEqual(
          expected.results!.map((result) => result.ok),
        );
        expect(actual.map((result) => result.capsuleId)).toEqual(
          expected.results!.map((result) => result.capsule_id_recomputed),
        );
        expect(
          actual.map((result) =>
            result.findings.map((finding) => finding.code),
          ),
        ).toEqual(
          expected.results!.map((result) =>
            result.findings.map((finding) => finding.code),
          ),
        );
        return;
      }
      const actual = await verifyClass1(input);
      expect(actual.ok).toBe(expected.ok);
      expect(actual.capsuleId ?? null).toBe(
        expected.capsule_id_recomputed ?? null,
      );
      expect(actual.assurance).toEqual(expected.derived);
      expect(actual.findings.map((finding) => finding.code)).toEqual(
        (expected.findings ?? []).map((finding) => finding.code),
      );
    });
});

// The provenance-mode corpus is Python and Go: this verifier does not
// implement check 9 or derive provenance_mode. Its check-1 cases still apply,
// so they run here on ok, capsule_id and findings.
describe("provenance_mode check-1 type cases", () => {
  const pmRoot = resolve(root, "..", "..", "provenance-mode-vectors");
  const pmManifest = JSON.parse(
    readFileSync(resolve(pmRoot, "vectors.json"), "utf8"),
  ) as { cases: Array<{ name: string }> };
  const typed = pmManifest.cases.filter((item) =>
    item.name.startsWith("neg-field-not-string-"),
  );
  it("has cases", () => expect(typed.length).toBeGreaterThan(0));
  for (const item of typed)
    it(item.name, async () => {
      const input = decodeStrictJson(
        readFileSync(resolve(pmRoot, item.name, "input.json")),
      );
      const expected = JSON.parse(
        readFileSync(resolve(pmRoot, item.name, "expected.json"), "utf8"),
      ) as {
        ok: boolean;
        capsule_id_recomputed: string;
        findings: Array<{ code: string }>;
      };
      const actual = await verifyClass1(input);
      expect(actual.ok).toBe(expected.ok);
      expect(actual.capsuleId).toBe(expected.capsule_id_recomputed);
      expect(actual.findings.map((finding) => finding.code)).toEqual(
        expected.findings.map((finding) => finding.code),
      );
    });
});

// provenance_mode is an object when present (AAC -05 "Provenance mode and
// backfilled records"); any other JSON type fails check 1 with the same
// block_not_object finding, in the same position, as the Python and Go
// verifiers. This verifier still does not run check 9 on the block's members.
describe("provenance_mode block shape", () => {
  const sealed = async (
    edit: (capsule: Record<string, ParsedJson>) => void,
  ): Promise<Record<string, ParsedJson>> => {
    const capsule = decodeStrictJson(
      readFileSync(resolve(root, "pos-executed-confirmed", "input.json")),
    ) as Record<string, ParsedJson>;
    edit(capsule);
    delete capsule.capsule_id;
    capsule.capsule_id = await computeCapsuleId(capsule);
    return capsule;
  };

  for (const [label, raw] of [
    ["a string", '"backfilled"'],
    ["an array", '["backfilled"]'],
    ["null", "null"],
    ["a number", "1"],
  ] as const)
    it(`refuses ${label} with block_not_object (check 1)`, async () => {
      const capsule = await sealed((c) => {
        c.provenance_mode = decodeStrictJson(raw);
      });
      const result = await verifyClass1(capsule);
      expect(result.ok).toBe(false);
      expect(result.capsuleId).toBe(capsule.capsule_id);
      expect(
        result.findings.map(({ code, check, severity }) => ({
          code,
          check,
          severity,
        })),
      ).toEqual([{ code: "block_not_object", check: 1, severity: "error" }]);
    });

  it("reports it after the other blocks and before constraints", async () => {
    const capsule = await sealed((c) => {
      c.cross_party = "x";
      c.provenance_mode = "backfilled";
      c.constraints = decodeStrictJson("{}");
    });
    expect(
      (await verifyClass1(capsule)).findings.map(({ code, detail }) => [
        code,
        detail,
      ]),
    ).toEqual([
      ["block_not_object", "cross_party MUST be a JSON object when present"],
      [
        "block_not_object",
        "provenance_mode MUST be a JSON object when present",
      ],
      [
        "constraints_not_array",
        "constraints MUST be an array when present (§8.1)",
      ],
    ]);
  });

  it("accepts a well-formed backfilled block", async () => {
    const capsule = await sealed((c) => {
      c.provenance_mode = decodeStrictJson(
        JSON.stringify({
          mode: "backfilled",
          source_ref: {
            type: "x-external-ledger-entry",
            digest_alg: "SHA-256",
            digest: "5".repeat(64),
          },
          source_asserted_at: "2026-08-26T05:34:57.860343",
          import_batch: "fixture-import-1",
          imported_at: "2026-09-14T00:00:00Z",
        }),
      );
    });
    const result = await verifyClass1(capsule);
    expect(result.ok).toBe(true);
    expect(result.findings).toEqual([]);
  });
});

describe("reference parity edge cases", () => {
  const fixture = (): Record<string, ParsedJson> =>
    decodeStrictJson(
      readFileSync(resolve(root, "pos-executed-confirmed", "input.json")),
    ) as Record<string, ParsedJson>;

  it("checks effect_attestation presence independently of its type", async () => {
    const capsule = fixture();
    const effect = capsule.effect as Record<string, ParsedJson>;
    effect.effect_attestation = decodeStrictJson("1");
    expect(
      (await verifyClass1(capsule)).findings.some(
        (finding) => finding.code === "effect_attestation_missing",
      ),
    ).toBe(false);

    effect.status = "planned";
    expect(
      (await verifyClass1(capsule)).findings.some(
        (finding) => finding.code === "effect_attestation_present",
      ),
    ).toBe(true);
  });

  it("treats a null effect_attestation as absent like the references", async () => {
    const capsule = fixture();
    const effect = capsule.effect as Record<string, ParsedJson>;
    effect.effect_attestation = null;
    expect(
      (await verifyClass1(capsule)).findings.some(
        (finding) => finding.code === "effect_attestation_missing",
      ),
    ).toBe(true);

    effect.status = "planned";
    expect(
      (await verifyClass1(capsule)).findings.some(
        (finding) => finding.code === "effect_attestation_present",
      ),
    ).toBe(false);
  });

  it("does not attempt ID computation when the identity profile is invalid", async () => {
    for (const name of [
      "neg-float-in-digest-field",
      "neg-unsafe-integer-in-digest-field",
    ]) {
      const capsule = decodeStrictJson(
        readFileSync(resolve(root, name, "input.json")),
      ) as Record<string, ParsedJson>;
      capsule.format_version = "4";
      capsule.canonicalization_id = decodeStrictJson("4");
      const codes = (await verifyClass1(capsule)).findings.map(
        (finding) => finding.code,
      );
      expect(codes).toContain("canonicalization_id_not_string");
      expect(codes).not.toContain("capsule_id_uncomputable");
    }
  });

  it.each([
    ["1", "jcs", "unsupported_format_version"],
    ["2", undefined, "unsupported_format_version"],
    ["2", null, "unsupported_format_version"],
    ["3", "jcs", "unsupported_format_version"],
    ["4", undefined, "canonicalization_id_missing"],
    ["4", null, "canonicalization_id_not_string"],
    ["4", "", "canonicalization_profile_mismatch"],
    ["4", "jcs-n", "canonicalization_profile_mismatch"],
  ] as const)(
    "does not derive an ID finding for format %s and canonicalization %s",
    async (formatVersion, canonicalizationId, expectedCode) => {
      const capsule = fixture();
      capsule.format_version = formatVersion;
      if (canonicalizationId === undefined) delete capsule.canonicalization_id;
      else capsule.canonicalization_id = canonicalizationId;

      const result = await verifyClass1(capsule);
      const codes = result.findings.map((finding) => finding.code);
      expect(codes).toContain(expectedCode);
      expect(codes).not.toContain("capsule_id_uncomputable");
      expect(result.capsuleId).toBeUndefined();
    },
  );

  it("reports assurance overclaims when optional evidence is absent", async () => {
    const capsule = fixture();
    delete capsule.chain;
    delete capsule.cross_party;
    capsule.assurance = {
      attestation_mode: "anchored",
      ledger_mode: "anchored",
      cross_party_rung: "full_bilateral",
    };
    expect(
      (await verifyClass1(capsule)).findings.filter(
        (finding) => finding.code === "assurance_overclaim",
      ),
    ).toHaveLength(3);
  });

  it("matches reference disposition presence and type findings", async () => {
    const capsule = fixture();
    const disposition = capsule.disposition as Record<string, ParsedJson>;
    disposition.decision = decodeStrictJson("5");
    disposition.human_disposed = "not-a-boolean";
    const codes = (await verifyClass1(capsule)).findings.map(
      (finding) => finding.code,
    );
    expect(codes).not.toContain("missing_required_field");
    expect(codes).toContain("field_not_bool");

    delete disposition.human_disposed;
    const missingCodes = (await verifyClass1(capsule)).findings.map(
      (finding) => finding.code,
    );
    expect(missingCodes).toContain("field_not_bool");
    expect(missingCodes).not.toContain("missing_required_field");
  });
});
