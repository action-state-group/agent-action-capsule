import { expect, it } from "vitest";
import { pageModel } from "./helpers/page-model.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

// A verified bundle whose root is none of report/v1, a Result v0 root or an
// evaluation-summary/v1 aggregate (a deal root, for example) still has its
// verification stated. capsule-viewer resolves it to the no-aggregate floor
// and draws the page without the aggregate panel.
it("states the verification of a verified bundle with no evaluation summary", async () => {
  const { bundle } = await sealEvidenceBundle({
    root: "deal",
    records: [{ capsule_id: "deal" }],
    disclosures: {
      deal: {
        agent_input: { spec_version: "x-example-deal/v0", step: "open" },
      },
    },
  });
  const { banner, page } = await pageModel(bundle);
  expect(banner.state).toBe("incomplete");
  expect(banner.refusal).toBeUndefined();
  expect(page.checks.length).toBeGreaterThan(0);
});
