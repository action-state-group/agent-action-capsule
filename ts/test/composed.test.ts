// @vitest-environment jsdom
//
// composed/v1: the verify core's port of go/bundle/composed.go, and the
// composition section that shows its result.
//
// Parity: testdata/composed-parity/ holds, per case, the output of
// `capsulectl verify --bundle` (capsule-cli, which verifies composed/v1 with
// this repository's Go reference) for the same bundle. Cases `vector-*` are
// the published vectors (vectors/bundle/composed); the others are built from
// them by testdata/composed-parity/generate.py, which also says how the
// capsulectl outputs were produced.
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  BUILTIN_MANIFEST_COMPOSED,
  BUILTIN_MANIFESTS,
  BUILTIN_PRESENTATIONS,
  BUILTIN_SECTIONS,
  EXTENSION_NOT_INTERPRETED,
  PresentationAmbiguityError,
  PresentationRegistry,
  buildVerifiedBundleContext,
  composedDigest,
  composedDigestPreimage,
  createPresentationRegistry,
  createSectionRegistry,
  renderEvidenceGraph,
  verifyBundle,
  verifyComposed,
  type ComposedResult,
  type PresentationManifest,
  type PresentationModule,
} from "../src/browser.js";
import { sealEvidenceBundle } from "./helpers/sealed-bundle.js";

type Obj = Record<string, unknown>;

const read = (...path: string[]): unknown =>
  JSON.parse(readFileSync(resolve(process.cwd(), ...path), "utf8"));
const VECTORS = read("..", "vectors", "bundle", "composed", "vectors.json") as {
  cases: { id: string; container: Obj; expect: Obj }[];
};
const PARITY_DIR = resolve(
  process.cwd(),
  "test",
  "testdata",
  "composed-parity",
);

/** Every parity case: its bundle and capsulectl's output for it. */
function parityCases(): { name: string; bundle: Obj; cli: Obj }[] {
  return readdirSync(PARITY_DIR)
    .filter((f) => f.endsWith(".capsulectl.json"))
    .sort()
    .map((f) => {
      const name = f.slice(0, -".capsulectl.json".length);
      const bundle = name.startsWith("vector-")
        ? VECTORS.cases.find((c) => `vector-${c.id}` === name)!.container
        : (read(
            "test",
            "testdata",
            "composed-parity",
            `${name}.bundle.json`,
          ) as Obj);
      return {
        name,
        bundle,
        cli: read("test", "testdata", "composed-parity", f) as Obj,
      };
    });
}

const cliComposed = (cli: Obj): Obj => {
  const output = cli.output as { extensions: Obj[] };
  return output.extensions.find((e) => e.kind === "composed/v1")!
    .composed as Obj;
};

/** The TS result, in capsulectl's JSON shape (internal/cli/composed.go). */
function asCli(result: ComposedResult): Obj {
  if (result.malformed)
    return { status: result.status, findings: result.findings };
  return {
    status: result.status,
    findings: result.findings,
    composed_digest: result.composedDigest,
    members: result.members.map((m) => ({
      id: m.id,
      observer: m.observer,
      outcome: m.outcome,
      body: m.body,
      digest: m.digest,
      findings: m.findings,
      ...(m.bundle === undefined
        ? {}
        : {
            bundle: {
              graph_closure: m.bundle.graphClosure,
              interval_coverage: m.bundle.intervalCoverage,
              per_record_membership: m.bundle.perRecordMembership,
            },
          }),
      ...(m.refusalSignature === undefined
        ? {}
        : { refusal_signature: m.refusalSignature }),
    })),
    composition_closure: result.compositionClosure,
    joins: result.joins.map((j) => ({
      members: j.members,
      basis: j.basis,
      declared: j.declared,
      derived: j.derived ?? null,
      result: j.result,
      ...(j.differences.length === 0 ? {} : { differences: j.differences }),
    })),
    corroboration: result.corroboration,
  };
}

/** capsulectl's composed output, reduced to the fields asCli reports. */
function fromCli(composed: Obj): Obj {
  const digest = composed.composed_digest as Obj;
  return {
    status: composed.status,
    findings: composed.findings,
    composed_digest: digest,
    members: (composed.members as Obj[]).map((m) => {
      const bundle = m.bundle as Obj | undefined;
      const claim = (c: unknown) => c as Obj;
      return {
        id: m.id,
        observer: m.observer,
        outcome: m.outcome,
        body: m.body,
        digest: m.digest,
        findings: m.findings,
        ...(bundle === undefined
          ? {}
          : {
              bundle: {
                graph_closure: claim(bundle.graph_closure),
                interval_coverage: claim(bundle.interval_coverage),
                per_record_membership: claim(bundle.per_record_membership),
              },
            }),
        ...(m.refusal_signature === undefined
          ? {}
          : { refusal_signature: (m.refusal_signature as Obj).status }),
      };
    }),
    composition_closure: composed.composition_closure,
    joins: composed.joins,
    corroboration: composed.corroboration,
  };
}

async function tsComposed(bundle: Obj): Promise<ComposedResult> {
  const entry = (await verifyBundle(bundle)).extensions.find(
    (e) => e.kind === "composed/v1",
  );
  return entry!.composed!;
}

describe("composed/v1 verification (port of go/bundle/composed.go)", () => {
  it.each(VECTORS.cases.map((c) => [c.id, c] as const))(
    "%s: the published vector's expected results",
    async (_id, c) => {
      const block = (c.container.extensions as Obj)["composed/v1"];
      const expectation = c.expect as {
        composed_digest: string;
        canonical_preimage: string;
        members: Record<string, Obj>;
        composition_closure: Obj;
        joins: Obj[];
        corroboration: Obj[];
      };
      expect(new TextDecoder().decode(composedDigestPreimage(block))).toBe(
        expectation.canonical_preimage,
      );
      expect(await composedDigest(block)).toBe(expectation.composed_digest);
      const result = await tsComposed(c.container);
      if (result.malformed) throw new Error("malformed");
      for (const m of result.members) {
        const want = expectation.members[m.id]!;
        expect([m.outcome, m.body, m.digest]).toEqual([
          want.outcome,
          want.body,
          want.digest,
        ]);
        const claims = want.claims as Record<string, string> | null;
        expect(
          m.bundle === undefined
            ? null
            : {
                graph_closure: m.bundle.graphClosure.status,
                interval_coverage: m.bundle.intervalCoverage.status,
                per_record_membership: m.bundle.perRecordMembership.status,
              },
        ).toEqual(claims);
      }
      expect(result.compositionClosure.status).toBe(
        expectation.composition_closure.status,
      );
      expect(result.compositionClosure.missing).toEqual(
        expectation.composition_closure.missing,
      );
      expect(
        result.joins.map((j) => ({
          members: j.members,
          declared: j.declared,
          derived: j.derived ?? null,
          result: j.result,
        })),
      ).toEqual(expectation.joins);
      expect(result.corroboration).toEqual(
        expectation.corroboration.map((c) =>
          c.result === "redundant" ? { ...c, reasons: [c.reason] } : c,
        ),
      );
    },
  );

  it.each(parityCases().map((c) => [c.name, c] as const))(
    "%s: every composed result equals capsulectl verify --bundle",
    async (_name, c) => {
      expect(asCli(await tsComposed(c.bundle))).toEqual(
        fromCli(cliComposed(c.cli)),
      );
    },
  );

  it("the parity cases cover every join state, both results of a derivation and every agreement result", () => {
    const joins = parityCases().flatMap(
      (c) => cliComposed(c.cli).joins as Obj[],
    );
    expect(new Set(joins.map((j) => j.derived))).toEqual(
      new Set(["agree", "mismatch", "unjoined", "one_sided", null]),
    );
    expect(new Set(joins.map((j) => j.result))).toEqual(
      new Set(["derived_matches", "join_state_mismatch", "not_derivable"]),
    );
    const agreement = parityCases().flatMap(
      (c) => cliComposed(c.cli).corroboration as Obj[],
    );
    expect(new Set(agreement.map((a) => a.result))).toEqual(
      new Set(["corroborating", "redundant", "not_applicable"]),
    );
  });

  it("a malformed block reports nothing but the malformation, and is not interpreted", async () => {
    const bundle = {
      ...VECTORS.cases[0]!.container,
      extensions: { "composed/v1": { composed_digest: "00" } },
    };
    const verified = await verifyBundle(bundle);
    expect(verified.extensions).toEqual([
      {
        kind: "composed/v1",
        status: "uninterpreted",
        integrityCovered: true,
        composed: {
          status: "fail",
          malformed: true,
          findings: ["composed_block_malformed:composed_digest"],
        },
      },
    ]);
    expect(
      await verifyComposed({ composed_digest: "00" }, () => {
        throw new Error("no member is verified");
      }),
    ).toEqual(verified.extensions[0]!.composed);
  });
});

// The section renders only on a bundle that verified (contract I1). The
// published containers carry no checkpoint, so the viewer refuses them;
// sealing one adds a checkpoint and leaves the composed/v1 block untouched.
async function sealed(container: Obj): Promise<Obj> {
  const out = (await sealEvidenceBundle(container)).bundle;
  expect((out.extensions as Obj)["composed/v1"]).toEqual(
    (container.extensions as Obj)["composed/v1"],
  );
  return out;
}

async function render(bundle: unknown): Promise<HTMLElement> {
  const root = document.createElement("main");
  await renderEvidenceGraph(bundle, root);
  return root;
}

const extensionCells = (root: HTMLElement): string[][] =>
  Array.from(root.querySelectorAll("table[data-extensions] tbody tr"), (tr) =>
    Array.from(tr.querySelectorAll("td"), (td) => td.textContent ?? ""),
  );

describe("the composition section", () => {
  it.each(parityCases().map((c) => [c.name, c] as const))(
    "%s: the page's join and agreement classifications equal capsulectl's",
    async (_name, c) => {
      const root = await render(await sealed(c.bundle));
      const section = root.querySelector<HTMLElement>(
        '[data-section="composition"]',
      )!;
      expect(section).not.toBeNull();
      const composed = cliComposed(c.cli);
      expect(
        section.querySelector<HTMLElement>("[data-composition-status]")!.dataset
          .compositionStatus,
      ).toBe(composed.status);
      expect(
        Array.from(
          section.querySelectorAll<HTMLElement>("tr[data-join-members]"),
          (tr) => [
            tr.dataset.joinMembers,
            tr.dataset.joinDeclared,
            tr.dataset.joinDerived,
            tr.dataset.joinResult,
          ],
        ),
      ).toEqual(
        (composed.joins as Obj[]).map((j) => [
          (j.members as string[]).join(","),
          j.declared,
          j.derived ?? "not_derivable",
          j.result,
        ]),
      );
      expect(
        Array.from(
          section.querySelectorAll<HTMLElement>("tr[data-agreement-members]"),
          (tr) => [tr.dataset.agreementMembers, tr.dataset.corroboration],
        ),
      ).toEqual(
        (composed.corroboration as Obj[]).map((a) => [
          (a.members as string[]).join(","),
          a.result,
        ]),
      );
      expect(
        Array.from(
          section.querySelectorAll<HTMLElement>("tr[data-member-id]"),
          (tr) => [tr.dataset.memberId, tr.dataset.body, tr.dataset.digest],
        ),
      ).toEqual(
        (composed.members as Obj[]).map((m) => [m.id, m.body, m.digest]),
      );
      const digest = section.querySelector<HTMLElement>(
        "[data-composed-digest]",
      )!;
      expect([digest.dataset.composedDigest, digest.dataset.matches]).toEqual([
        (composed.composed_digest as Obj).declared,
        String((composed.composed_digest as Obj).matches),
      ]);
      // The verification page now says the block was interpreted, by this module.
      expect(extensionCells(root)).toEqual([
        [
          "composed/v1",
          "covered",
          `interpreted by ${BUILTIN_MANIFEST_COMPOSED.id}`,
        ],
      ]);
    },
  );

  it("a same-custody agreeing pair renders redundant, not corroborating, with its reason", async () => {
    const container = VECTORS.cases.find(
      (c) => c.id === "same-custody-redundant",
    )!.container;
    const root = await render(await sealed(container));
    const row = root.querySelector<HTMLElement>("tr[data-agreement-members]")!;
    expect(row.dataset.corroboration).toBe("redundant");
    expect(row.dataset.reasons).toBe("same_custody_domain");
    expect(row.textContent).toContain(
      "redundant, not corroborating (same_custody_domain)",
    );
    expect(row.textContent).not.toContain("corroborating, on declared custody");
    // Both observers are shown with the one custody domain they declare.
    expect(
      Array.from(
        root.querySelectorAll("tr[data-observer-id] td:last-child"),
        (td) => td.textContent,
      ),
    ).toEqual(["operator.example", "operator.example"]);
  });

  it("a separate-custody agreeing pair is corroborating only on declared custody", async () => {
    const container = VECTORS.cases.find((c) => c.id === "agree")!.container;
    const root = await render(await sealed(container));
    const row = root.querySelector<HTMLElement>("tr[data-agreement-members]")!;
    expect(row.dataset.corroboration).toBe("corroborating");
    expect(row.textContent).toContain("corroborating, on declared custody");
    expect(root.textContent).toContain(
      "distinct labels do not establish that two observers are independent",
    );
  });

  it("a mismatch shows each member's value at the differing pointer and names no winner", async () => {
    const c = parityCases().find((p) => p.name === "mismatch")!;
    const root = await render(await sealed(c.bundle));
    const details = root.querySelector<HTMLElement>("[data-join-differences]")!;
    expect(details.tagName).toBe("DETAILS");
    const values = Array.from(
      details.querySelectorAll("dd"),
      (dd) => dd.textContent,
    );
    expect(values).toEqual([
      'responder-a: "0edfc9959ac786349dfd2e07e41bb73fa91d31113c64655836da2ee4e75da408"',
      'responder-b: "4d0c2ac3b851f692b652985e349e55268be73d0b8ecf815df8654d8a97df4cc7"',
    ]);
  });

  it("an unverified container shows no section, and the block reads not interpreted", async () => {
    const container = VECTORS.cases.find((c) => c.id === "agree")!.container;
    const root = await render(container);
    expect(
      root.querySelector('[data-refusal="unverified-bundle"]'),
    ).not.toBeNull();
    expect(root.querySelector('[data-section="composition"]')).toBeNull();
    expect(extensionCells(root)).toEqual([
      ["composed/v1", "covered", EXTENSION_NOT_INTERPRETED],
    ]);
  });

  it("a bundle without composed/v1 does not select the section", async () => {
    const plain = read("test", "testdata", "week-bundle.json") as Obj;
    const context = await buildVerifiedBundleContext(plain);
    expect(await createSectionRegistry().resolve(context, "*", "html")).toEqual(
      { kind: "no-presentation" },
    );
    const root = await render(plain);
    expect(root.querySelector('[data-section="composition"]')).toBeNull();
  });

  it("the section is drawn after the page module and before the verification page", async () => {
    const container = VECTORS.cases.find((c) => c.id === "agree")!.container;
    const root = await render(await sealed(container));
    const order = Array.from(
      root.querySelectorAll<HTMLElement>(
        '[data-notice="no-aggregate"], [data-section="composition"], [data-page="verification"]',
      ),
      (el) => el.dataset.notice ?? el.dataset.section ?? el.dataset.page,
    );
    expect(order).toEqual(["no-aggregate", "composition", "verification"]);
  });
});

const stub = (manifest: PresentationManifest): PresentationModule => ({
  manifest,
  canRender: () => true,
  buildModel: () => null,
  render: () => undefined,
});

describe("precedence (contract sections 4.3 to 4.5)", () => {
  it("as a page module the composition manifest is ambiguous with the five specific built-ins, so registration refuses it", () => {
    const specific = BUILTIN_MANIFESTS.filter((m) => !m.fallback);
    expect(specific).toHaveLength(5);
    for (const other of specific) {
      const pair = new PresentationRegistry();
      pair.register(stub(other));
      expect(() => pair.register(stub(BUILTIN_MANIFEST_COMPOSED))).toThrow(
        PresentationAmbiguityError,
      );
    }
    expect(() =>
      createPresentationRegistry().register(BUILTIN_SECTIONS[0]!),
    ).toThrow(PresentationAmbiguityError);
  });

  it("as a page module it would also refuse a composition-aware page module (contract appendix B)", () => {
    const compositionAware: PresentationManifest = {
      spec_version: "aac.presentation-manifest/v0",
      id: "org.example.composition-aware/v0",
      trust_class: "trusted-executable",
      requires: {
        bundle_kind: "evidence-bundle/v2",
        profiles: ["spec_version:org.example.exchange/v0"],
        extensions: { required: ["composed/v1"] },
      },
      audiences: ["*"],
      formats: ["html", "fragment", "embedded"],
      fallback: false,
      priority: 1,
      executable: {
        carrier: "module-slot",
        script_sha256:
          "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
      },
    };
    const pages = new PresentationRegistry();
    pages.register(stub(compositionAware));
    expect(() => pages.register(stub(BUILTIN_MANIFEST_COMPOSED))).toThrow(
      PresentationAmbiguityError,
    );
    // In the section registry the two never meet: the page module renders
    // the page and the composition section is drawn beneath it.
    const sections = createSectionRegistry();
    expect(sections.list().map((m) => m.manifest.id)).toEqual([
      BUILTIN_MANIFEST_COMPOSED.id,
    ]);
  });

  it("the page registry is unchanged: the six built-ins, nothing else", () => {
    expect(createPresentationRegistry().list()).toEqual(BUILTIN_PRESENTATIONS);
    expect(BUILTIN_MANIFESTS.map((m) => m.id)).not.toContain(
      BUILTIN_MANIFEST_COMPOSED.id,
    );
  });

  it("a second section matching composed/v1 is refused at registration", () => {
    const sections = createSectionRegistry();
    expect(() =>
      sections.register(
        stub({ ...BUILTIN_MANIFEST_COMPOSED, id: "org.example.other/v0" }),
      ),
    ).toThrow(PresentationAmbiguityError);
  });
});
