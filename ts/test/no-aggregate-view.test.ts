import { expect, it } from "vitest";
import { pageModel } from "./helpers/page-model.js";
import { builtinPage } from "./helpers/builtin-resolution.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

// A verified bundle whose root is none of report/v1, a Result v0 root or an
// evaluation-summary/v1 aggregate (a deal root, for example) resolves to the
// no-aggregate floor instead of no page, and its verification is stated.
// capsule-viewer draws the page without the aggregate panel.
it("resolves a verified bundle with no evaluation summary to the no-aggregate page", async () => {
  const { bundle } = await sealEvidenceBundle({
    root: "deal",
    records: [{ capsule_id: "deal" }],
    disclosures: {
      deal: {
        agent_input: { spec_version: "x-example-deal/v0", step: "open" },
      },
    },
  });
  const { context, banner, page } = await pageModel(bundle);
  expect(banner.state).toBe("incomplete");
  expect(await builtinPage(context)).toBe("aac.builtin.no-aggregate/v0");
  expect(page.checks.length).toBeGreaterThan(0);
});
