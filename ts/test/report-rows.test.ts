import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { buildReportRows } from "../src/report-rows.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

function fixture(name: string): Record<string, unknown> {
  return JSON.parse(
    readFileSync(resolve(process.cwd(), "test", "testdata", name), "utf8"),
  ) as Record<string, unknown>;
}

describe("buildReportRows", () => {
  it("is undefined for a bundle whose root is not report/v1", async () => {
    await expect(
      buildReportRows(fixture("week-bundle.json")),
    ).resolves.toBeUndefined();
  });

  it("reads rows, statuses, reasons, and resolves citations", async () => {
    const { bundle, ids } = await sealEvidenceBundle(
      fixture("report-rows-bundle.json"),
    );
    const rows = await buildReportRows(bundle);
    expect(rows).toBeDefined();
    expect(rows!.title).toBe("EU AI Act obligations — tau2 airline CLL");
    expect(rows!.rows).toHaveLength(3);

    const established = rows!.rows.find((row) => row.rowId === "art-50")!;
    expect(established.status).toBe("established");
    expect(established.reason).toBeUndefined();
    expect(established.citations).toHaveLength(1);
    expect(established.citations[0]!.capsuleId).toBe(ids["act-established"]);
    expect(established.citations[0]!.disclosure).toBe("disclosed");
    expect(established.citations[0]!.disclosedPayload).toEqual({
      example: "disclosed evidence for art-50",
    });

    const notChecked = rows!.rows.find((row) => row.rowId === "art-14")!;
    expect(notChecked.status).toBe("not_checked");
    expect(notChecked.reason).toBe(
      "pack runtime did not evaluate this clause in the demo window",
    );
    expect(notChecked.citations).toHaveLength(1);
    expect(notChecked.citations[0]!.disclosure).toBe("withheld");
    expect(notChecked.citations[0]!.disclosedPayload).toBeUndefined();

    const notPresent = rows!.rows.find((row) => row.rowId === "art-26-6")!;
    expect(notPresent.status).toBe("not_present");
    expect(notPresent.citations).toHaveLength(0);
  });

  it("marks a citation whose disclosed value does not hash to its committed digest as a mismatch, never a payload", async () => {
    const { bundle, ids } = await sealEvidenceBundle(
      fixture("report-rows-bundle.json"),
    );
    const disclosures = bundle.disclosures as Record<string, unknown>;
    const forged = {
      ...bundle,
      disclosures: {
        ...disclosures,
        [ids["act-established"]!]: { agent_input: { example: "forged" } },
      },
    };
    const rows = await buildReportRows(forged);
    const established = rows!.rows.find((row) => row.rowId === "art-50")!;
    expect(established.citations[0]).toEqual(
      expect.objectContaining({
        capsuleId: ids["act-established"],
        disclosure: "disclosure_mismatch",
      }),
    );
    expect(established.citations[0]!.disclosedPayload).toBeUndefined();
    expect(JSON.stringify(rows)).not.toContain("forged");
  });

  it("drops a row missing required fields rather than fabricating one", async () => {
    const { bundle } = await sealEvidenceBundle({
      root: "root",
      records: [{ capsule_id: "root" }],
      disclosures: {
        root: {
          agent_input: {
            spec_version: "report/v1",
            rows: [
              { row_id: "ok", label: "ok row", status: "established" },
              { row_id: "missing-status", label: "no status" },
              { label: "no row_id", status: "established" },
            ],
          },
        },
      },
    });
    const rows = await buildReportRows(bundle);
    expect(rows!.rows).toHaveLength(1);
    expect(rows!.rows[0]!.rowId).toBe("ok");
  });
});
