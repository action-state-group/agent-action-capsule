#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { decodeCapsuleJson, sealCapsule, verifyClass1 } from "./index.js";
import type { CapsuleBody } from "./model.js";

const command = process.argv[2];
if (command !== "seal" && command !== "verify") {
  console.error("usage: cross-language seal|verify");
  process.exit(2);
}
const value = decodeCapsuleJson(readFileSync(0));
if (command === "seal") {
  process.stdout.write(
    `${JSON.stringify(sealCapsule(value as unknown as CapsuleBody))}\n`,
  );
} else {
  const result = verifyClass1(value);
  if (!result.ok) {
    console.error(result.findings.map((finding) => finding.code).join(", "));
    process.exit(1);
  }
  process.stdout.write(`${result.capsuleId ?? ""}\n`);
}
