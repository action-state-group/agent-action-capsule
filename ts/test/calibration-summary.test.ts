import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";
import {
  readCalibrationSummary,
  readHumanRating,
} from "../src/calibration-summary.js";

type Obj = Record<string, unknown>;

const repo = resolve(process.cwd(), "..");
const json = (...path: string[]): Obj =>
  JSON.parse(readFileSync(resolve(repo, ...path), "utf8")) as Obj;

// format: date-time is an annotation under 2020-12, as in the Python checker
// (schemas/check_judge_record_examples.py attaches no format checker).
const ajv = new Ajv2020({ strict: false, validateFormats: false });
const summarySchema = ajv.compile(
  json("schemas", "judge", "calibration-summary-v1.json"),
);
const ratingSchema = ajv.compile(
  json("schemas", "judge", "human-rating-v1.json"),
);

const vectors = (family: string): [string, Obj][] =>
  readdirSync(resolve(repo, "vectors", "judge", family))
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => [name, json("vectors", "judge", family, name)]);

const records = json("ts", "test", "testdata", "calibration-records.json") as {
  summary: Obj;
  ratings: Obj[];
};
const weekSummary = (
  (
    json("ts", "test", "testdata", "week-bundle-calibration.json")
      .disclosures as Obj
  ).calibration as Obj
).agent_input as Obj;

describe("calibration fixtures validate against the judge schemas", () => {
  it.each([
    ["calibration-records.json summary", records.summary],
    ["week-bundle-calibration.json calibration", weekSummary],
  ])("%s is a valid calibration-summary/v1 record", (_name, record) => {
    expect(summarySchema(record), JSON.stringify(summarySchema.errors)).toBe(
      true,
    );
    expect(readCalibrationSummary(record)).toBeDefined();
  });

  it.each(records.ratings.map((rating, i) => [i + 1, rating] as const))(
    "calibration-records.json rating %d is a valid human-rating/v1 record",
    (_i, rating) => {
      expect(ratingSchema(rating), JSON.stringify(ratingSchema.errors)).toBe(
        true,
      );
      expect(readHumanRating(rating)).toBeDefined();
    },
  );
});

describe("the readers accept exactly what the schemas accept", () => {
  it.each(vectors("calibration-summary"))(
    "calibration-summary vector %s",
    (name, record) => {
      expect(name.startsWith("pos-")).toBe(summarySchema(record));
      expect(readCalibrationSummary(record) !== undefined).toBe(
        summarySchema(record),
      );
    },
  );

  it.each(vectors("human-rating"))("human-rating vector %s", (name, record) => {
    expect(name.startsWith("pos-")).toBe(ratingSchema(record));
    expect(readHumanRating(record) !== undefined).toBe(ratingSchema(record));
  });

  it("refuses k > n, the cross-field rule the schema cannot express (section 8)", () => {
    for (const member of ["agreement", "drift"]) {
      const record = structuredClone(records.summary);
      (record.clauses as Obj[])[0]![member] = { k: 4, n: 3 };
      expect(summarySchema(record)).toBe(true);
      expect(readCalibrationSummary(record)).toBeUndefined();
    }
  });
});
