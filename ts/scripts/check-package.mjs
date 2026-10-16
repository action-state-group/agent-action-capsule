import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const temporary = mkdtempSync(join(tmpdir(), "aac-package-"));
const run = (command, args, cwd = temporary) =>
  execFileSync(command, args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });

try {
  const [packed] = JSON.parse(
    run(
      "npm",
      ["pack", "--ignore-scripts", "--json", "--pack-destination", temporary],
      root,
    ),
  );
  assert(packed.files.some(({ path }) => path === "LICENSE"));
  writeFileSync(
    join(temporary, "package.json"),
    JSON.stringify({ private: true, type: "module" }),
  );
  run("npm", [
    "install",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    join(temporary, packed.filename),
  ]);
  for (const name of [
    "@action-state-group/cll",
    "better-sqlite3",
    "fs-ext",
    "mysql2",
  ])
    assert(
      !existsSync(join(temporary, "node_modules", name)),
      `${name} was installed by the core package`,
    );

  writeFileSync(
    join(temporary, "core.mjs"),
    `
    import assert from "node:assert/strict";
    import * as core from "@action-state-group/agent-action-capsule/core";
    const capsule = await core.sealCapsule({
      spec_version: "draft-mih-scitt-agent-action-capsule-05",
      format_version: "4", canonicalization_id: "jcs",
      action_id: "package-check", action_type: "fyi",
      operator: "operator", developer: "developer",
      timestamp: "2026-10-05T00:00:00Z", references: [],
    });
    assert((await core.verifyClass1(capsule)).ok);
    assert.equal(typeof core.jsonDigest, "function");
    assert.equal(typeof core.verifyProducerEnvelope, "function");
    assert.equal("verifyBundle" in core, false);
    assert.equal("createEd25519Identity" in core, !process.execArgv.includes("--conditions=browser"));
    const settlement = await import("@action-state-group/agent-action-capsule/settlement");
    assert.equal((await settlement.verifySettlements([null])).conforming, false);
    const witness = await import("@action-state-group/agent-action-capsule/witness");
    assert.equal((await witness.verifyCoseReceipt(new Uint8Array(), new Uint8Array(), new Uint8Array())).ok, false);
    for (const name of ["verifyReceipt", "verifyRekorReceipt", "verifyScrapiReceipt", "witnessRowFor", "witnessRowKeys"])
      assert.equal(typeof witness[name], "function");
  `,
  );
  run(process.execPath, [join(temporary, "core.mjs")]);
  run(process.execPath, ["--conditions=browser", join(temporary, "core.mjs")]);
  console.log(
    "Packed core, settlement and witness: Node/browser imports, async verification and installation without CLL/storage PASS",
  );

  const metadata = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  run("npm", [
    "install",
    "--no-audit",
    "--no-fund",
    process.env.CLL_PACKAGE ??
      `@action-state-group/cll@${metadata.devDependencies["@action-state-group/cll"]}`,
  ]);
  writeFileSync(
    join(temporary, "bundle.mjs"),
    `
    import assert from "node:assert/strict";
    import { readFileSync } from "node:fs";
    import { bundleDigest, verifyBundle } from "@action-state-group/agent-action-capsule/bundle";
    import * as legacy from "@action-state-group/agent-action-capsule";
    const fixture = JSON.parse(readFileSync(${JSON.stringify(join(root, "..", "vectors", "bundle", "report-single-record.json"))}, "utf8"));
    for (const testCase of fixture.cases) {
      const result = await verifyBundle(testCase.bundle);
      assert.equal(result.graphClosure.status, testCase.expected.graph_closure);
      assert.equal(result.intervalCoverage.status, testCase.expected.interval_coverage);
      assert.equal(result.perRecordMembership.status, testCase.expected.per_record_membership);
      assert.equal(result.bundleDigest, await bundleDigest(testCase.bundle));
    }
    assert.equal(legacy.verifyBundle, verifyBundle);
    const strictVectors = JSON.parse(readFileSync(${JSON.stringify(join(root, "..", "vectors", "bundle", "strict", "vectors.json"))}, "utf8"));
    for (const testCase of strictVectors.cases.slice(0, 3)) {
      const result = await verifyBundle(testCase.bundle, { strict: true });
      assert.equal(result.strict.verdict, testCase.expect.verdict);
    }
  `,
  );
  run(process.execPath, [join(temporary, "bundle.mjs")]);
  console.log(
    "Packed Bundle (plain and strict) and existing root with explicitly installed CLL PASS",
  );
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
