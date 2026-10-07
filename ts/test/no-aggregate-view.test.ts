// @vitest-environment jsdom

import { expect, it } from "vitest";
import { renderEvidenceGraph } from "../src/browser.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

// A verified bundle whose root is none of report/v1, a Result v0 root or an
// evaluation-summary/v1 aggregate (a deal root, for example) renders without
// the aggregate panel instead of throwing and rendering nothing.
it("renders a verified bundle with no evaluation summary, without the aggregate panel", async () => {
  const { bundle } = await sealEvidenceBundle({
    root: "deal",
    records: [{ capsule_id: "deal" }],
    disclosures: {
      deal: {
        agent_input: { spec_version: "x-example-deal/v0", step: "open" },
      },
    },
  });
  const root = document.createElement("main");
  await renderEvidenceGraph(bundle, root);
  expect(root.querySelector('[data-verify="verified"]')).not.toBeNull();
  expect(root.querySelector('[data-notice="no-aggregate"]')).not.toBeNull();
  expect(root.querySelector('[data-page="verification"]')).not.toBeNull();
});
