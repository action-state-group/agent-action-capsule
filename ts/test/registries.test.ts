import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import { registries } from "../src/index.js";

const registryMd = readFileSync(
  join(
    dirname(fileURLToPath(import.meta.url)),
    "..",
    "..",
    "spec",
    "REGISTRY.md",
  ),
  "utf8",
);

/**
 * Seeded values of one "## N. `name`" section, read the way the Go and Python
 * references read it: from table rows, ordered-list items, and "Initial
 * contents" lines only, never from prose backticks.
 */
function seededValues(name: string): Set<string> {
  const lines = registryMd.split("\n");
  const start = lines.findIndex((line) =>
    new RegExp(`^## \\d+\\. \`${name.replace(".", "\\.")}\``).test(line),
  );
  if (start < 0) throw new Error(`registry section ${name} not found`);
  const values = new Set<string>();
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.startsWith("## ")) break;
    const stripped = line.trim();
    const row = /^\|\s*`([^`]+)`\s*\|/.exec(stripped);
    if (row) values.add(row[1]!);
    const item = /^\d+\.\s+`([^`]+)`\s*$/.exec(stripped);
    if (item) values.add(item[1]!);
    if (stripped.includes("Initial contents")) {
      for (let j = i; j < lines.length && lines[j]!.trim() !== ""; j++) {
        const text =
          j === i
            ? lines[j]!.slice(lines[j]!.indexOf("Initial contents"))
            : lines[j]!;
        for (const match of text.matchAll(/`([^`]+)`/g)) values.add(match[1]!);
      }
    }
  }
  return values;
}

it.each(Object.keys(registries))(
  "registry %s mirrors spec/REGISTRY.md",
  (name) => {
    expect(registries[name as keyof typeof registries]).toEqual(
      seededValues(name),
    );
  },
);
