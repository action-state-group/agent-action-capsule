import { readFileSync } from "node:fs";
import { resolve } from "node:path";

/**
 * A monthly-scale compliance bundle, derived at test time from the committed
 * `test/testdata/compliance-bundle.json` (two sessions: one with five
 * judged or recomputed clauses, one with four). It repeats those two
 * sessions, alternately, for `sessions` sessions spread over the 30 days of
 * September 2026, renaming each copy's records, case and claims and
 * recomputing the aggregate, so the result has the shape a month of the
 * same report would have. Deterministic: the same `sessions` gives the same
 * bundle, byte for byte. Unsealed: pass it to sealEvidenceBundle.
 *
 * Not committed, for the same reason as derived-fixtures.ts: it is a few
 * hundred kilobytes of repetition of a committed source.
 */

type Obj = Record<string, unknown>;

const isObj = (value: unknown): value is Obj =>
  value !== null && typeof value === "object" && !Array.isArray(value);

function rewrite(value: unknown, swap: (s: string) => string): unknown {
  if (typeof value === "string") return swap(value);
  if (Array.isArray(value)) return value.map((item) => rewrite(item, swap));
  if (isObj(value))
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, rewrite(v, swap)]),
    );
  return value;
}

export function monthlyComplianceFixture(sessions: number): Obj {
  if (!Number.isInteger(sessions) || sessions < 2 || sessions % 2 !== 0)
    throw new RangeError("sessions must be an even integer of at least 2");
  const source = JSON.parse(
    readFileSync(
      resolve(process.cwd(), "test", "testdata", "compliance-bundle.json"),
      "utf8",
    ),
  ) as Obj;
  const disclosures = source.disclosures as Obj;
  const result = (disclosures.result as Obj).agent_input as Obj;
  const claims = result.claims as Obj[];
  const aggregate = result.aggregate as Obj;
  const buckets = aggregate.buckets as Record<string, string[]>;
  const bucketOf = new Map<string, string>();
  for (const [bucket, ids] of Object.entries(buckets))
    for (const id of ids) bucketOf.set(id, bucket);

  // The two template sessions: their record aliases and case ids.
  const templates = [
    { prefix: "s1.", caseId: "tau2:airline:task-0:trial-0" },
    { prefix: "s2.", caseId: "tau2:airline:task-1:trial-0" },
  ];

  const records: Obj[] = [{ capsule_id: "result" }];
  const outDisclosures: Obj = {};
  const outClaims: Obj[] = [];
  const outBuckets: Record<string, string[]> = Object.fromEntries(
    Object.keys(buckets).map((b) => [b, [] as string[]]),
  );
  for (let k = 0; k < sessions; k++) {
    const template = templates[k % 2]!;
    const caseId = `tau2:airline:task-${k}:trial-0`;
    const day = `day:2026-09-${String(1 + (k % 30)).padStart(2, "0")}`;
    const swap = (s: string): string => {
      let out = s;
      if (out.startsWith(template.prefix))
        out = `m${k}.${out.slice(template.prefix.length)}`;
      out = out.replaceAll(template.caseId, caseId);
      if (out === "day:2026-09-23") out = day;
      return out;
    };
    for (const alias of Object.keys(disclosures).sort()) {
      if (!alias.startsWith(template.prefix)) continue;
      const renamed = swap(alias);
      records.push({ capsule_id: renamed });
      outDisclosures[renamed] = rewrite(disclosures[alias], swap);
    }
    for (const claim of claims) {
      const id = claim.id as string;
      if (!id.startsWith(`${template.caseId}::`)) continue;
      const renamed = rewrite(claim, swap) as Obj;
      outClaims.push(renamed);
      const bucket = bucketOf.get(id);
      if (bucket !== undefined) outBuckets[bucket]!.push(renamed.id as string);
    }
  }
  const coverage = aggregate.coverage as Obj;
  const pairs = sessions / 2;
  return {
    root: "result",
    records,
    disclosures: {
      result: {
        agent_input: {
          ...result,
          generated_at: "2026-09-30T23:59:59Z",
          claims: outClaims,
          aggregate: {
            ...aggregate,
            coverage: {
              ...coverage,
              evaluated_population:
                (coverage.evaluated_population as number) * pairs,
              excluded_not_applicable:
                (coverage.excluded_not_applicable as number) * pairs,
            },
            buckets: outBuckets,
          },
        },
      },
      ...outDisclosures,
    },
    extensions: source.extensions,
  };
}
