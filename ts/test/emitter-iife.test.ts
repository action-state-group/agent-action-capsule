import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { beforeAll, describe, expect, it } from "vitest";

const tsRoot = new URL("../", import.meta.url);

describe("browser IIFE emitter", () => {
  beforeAll(() => {
    execFileSync("npm", ["run", "emitter:iife"], {
      cwd: tsRoot,
      stdio: "inherit",
    });
  });

  it("builds a non-trivial global renderEvidenceGraph artifact", async () => {
    const packageJson = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    ) as { scripts: Record<string, string> };
    expect(packageJson.scripts["emitter:iife"]).toBeDefined();

    const iife = await readFile(
      new URL("../dist/evidence-graph.iife.js", import.meta.url),
      "utf8",
    );
    expect(iife).toContain("renderEvidenceGraph");
    expect(iife.length).toBeGreaterThan(1000);
  });
});
