// Nostr-host profile vectors (vectors/profiles/) — TypeScript parity with the Python reference
// generator python/scripts/generate_profile_vectors.py. Re-derives every labelled digest with
// jsonDigest and applies the same five rule codes as the Python and Go checkers, asserting the
// committed `expect.violations` exactly. Two sets are covered: nostr-host.* (current) and buzz.*
// (released in 0.6.0, superseded, kept as released bytes).
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { jsonDigest } from "../src/json.js";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type JsonObject = { [key: string]: Json };

interface ProfileVector {
  expect: { valid: boolean; violations: string[] };
  digest_labels: Array<{ path: string; prefix?: string; label: string }>;
  record: JsonObject;
}

const root = resolve(import.meta.dirname, "..", "..", "vectors", "profiles");
const manifest = JSON.parse(
  readFileSync(resolve(root, "manifest.json"), "utf8"),
) as { cases: Array<{ file: string; valid: boolean; violations: string[] }> };

const HEX64 = /^[0-9a-f]{64}$/;
const TEXT_KEY = /(^|_)(text|message|content|body)(_|$)/;
const SCORE_KEY = /(^|_)(score|rating|rank)(_|$)/;

function isObject(value: Json | undefined): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function at(record: JsonObject, path: string): Json | undefined {
  let value: Json | undefined = record;
  for (const part of path.split(".")) {
    if (Array.isArray(value)) value = value[Number(part)];
    else if (isObject(value)) value = value[part];
    else return undefined;
  }
  return value;
}

function keys(value: Json | undefined, out: string[]): string[] {
  if (Array.isArray(value)) for (const item of value) keys(item, out);
  else if (isObject(value))
    for (const [key, child] of Object.entries(value)) {
      out.push(key);
      keys(child, out);
    }
  return out;
}

/** Mirrors check_record in python/scripts/generate_profile_vectors.py. */
function checkProfileRecord(record: JsonObject): string[] {
  const found = new Set<string>();
  const subject = record.subject;
  let eventId: string | undefined;
  let semantic: string | undefined;
  if (
    isObject(subject) &&
    Object.keys(subject).length === 2 &&
    typeof subject.event_id === "string" &&
    typeof subject.semantic_digest === "string" &&
    HEX64.test(subject.event_id) &&
    HEX64.test(subject.semantic_digest)
  ) {
    eventId = subject.event_id;
    semantic = subject.semantic_digest;
  } else found.add("subject_shape");
  const commitments = Array.isArray(record.payload_commitments)
    ? record.payload_commitments
    : [];
  if (eventId !== undefined) {
    if (semantic === eventId) found.add("event_id_as_digest");
    for (const c of commitments)
      if (isObject(c) && c.digest === eventId) found.add("event_id_as_digest");
  }
  for (const c of commitments) {
    const role = isObject(c) ? c.role : undefined;
    if (typeof role !== "string" || role === "" || role === "semantic_digest")
      found.add("body_digest_named");
  }
  for (const key of keys(record, [])) {
    if (TEXT_KEY.test(key)) found.add("message_text_present");
    if (SCORE_KEY.test(key)) found.add("score_present");
  }
  return [...found].sort();
}

describe("Nostr-host profile vectors (Python-generated) — TypeScript parity", () => {
  it("lists all twenty fixtures (nostr-host.* current, buzz.* released in 0.6.0)", () => {
    expect(manifest.cases).toHaveLength(20);
    const sets: Record<string, number> = {};
    for (const c of manifest.cases) {
      const set = c.file.split(".")[0];
      sets[set] = (sets[set] ?? 0) + 1;
    }
    expect(sets).toEqual({ "nostr-host": 10, buzz: 10 });
  });
  for (const item of manifest.cases)
    it(item.file, async () => {
      const vector = JSON.parse(
        readFileSync(resolve(root, item.file), "utf8"),
      ) as ProfileVector;
      expect(vector.digest_labels.length).toBeGreaterThan(0);
      for (const entry of vector.digest_labels)
        expect(at(vector.record, entry.path), entry.path).toBe(
          (entry.prefix ?? "") + (await jsonDigest({ label: entry.label })),
        );
      expect(vector.expect.valid).toBe(item.valid);
      expect(vector.expect.violations).toEqual(item.violations);
      expect(checkProfileRecord(vector.record)).toEqual(
        vector.expect.violations,
      );
    });
});
