import type { VerifiedBundleContext } from "./bundle.js";
import { BUILTIN_MANIFEST_COMPOSED } from "./builtin-manifests.js";
import {
  COMPOSED_KIND,
  type ComposedClaim,
  type ComposedResult,
  type CorroborationResult,
  type JoinDifference,
} from "./composed.js";
import type {
  PresentationHost,
  PresentationModule,
  PresentationServices,
} from "./presentation-registry.js";

/**
 * The composition section: a generic view of the `composed/v1` block's
 * verification, as the verify core computed it (`composed.ts`). It reports
 * what draft-mih-zhang-agent-disclosure-bundle-01 "Verifying composed/v1"
 * says a verifier reports, separately: the composed digest, each member,
 * composition closure, each join's declared and derived state, and per
 * derived agreement whether it is redundant or corroborating on declared
 * custody. It shows no product wording and names no party's business role;
 * an observer's `role` is shown as the block declares it, uninterpreted.
 *
 * It never verifies: every value it shows is read from the context's one
 * verification result.
 */

type Verified = Extract<ComposedResult, { malformed: false }>;

export interface ComposedSectionModel {
  readonly result: Verified;
}

/** The well-formed composed/v1 result the core verified, if there is one. */
function composedResult(context: VerifiedBundleContext): Verified | undefined {
  const entry = context.verification.extensions.find(
    (extension) => extension.kind === COMPOSED_KIND,
  );
  const composed = entry?.composed;
  return composed !== undefined && !composed.malformed ? composed : undefined;
}

function element(tag: string, text?: string): HTMLElement {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  return node;
}

function row(cells: readonly string[], header = false): HTMLElement {
  const tr = element("tr");
  for (const cell of cells) tr.append(element(header ? "th" : "td", cell));
  return tr;
}

function table(
  name: string,
  columns: readonly string[],
  rows: readonly HTMLElement[],
): HTMLElement {
  const node = element("table");
  node.setAttribute(`data-${name}`, "");
  const head = element("thead");
  head.append(row(columns, true));
  const body = element("tbody");
  body.append(...rows);
  node.append(head, body);
  return node;
}

const NOT_APPLICABLE = "—";
const findingsText = (findings: readonly string[]): string =>
  findings.length === 0 ? "none" : findings.join(", ");
const claimText = (claim: ComposedClaim | undefined): string =>
  claim === undefined
    ? NOT_APPLICABLE
    : claim.findings.length === 0
      ? claim.status
      : `${claim.status} (${claim.findings.join(", ")})`;
const pairText = (members: readonly [string, string]): string =>
  `${members[0]} – ${members[1]}`;

// The values two members hold at one compare pointer, as text. No winner is
// named (draft "Joins": "names no winner").
function renderDifference(difference: JoinDifference, host: HTMLElement): void {
  const list = element("dl");
  list.dataset.pointer = difference.pointer;
  list.append(element("dt", difference.pointer));
  for (const value of difference.values)
    list.append(
      element(
        "dd",
        value.resolved
          ? `${value.member}: ${JSON.stringify(value.value)}`
          : `${value.member}: does not resolve`,
      ),
    );
  host.append(list);
}

// go/bundle/composed.go:102-114 and draft "Observers and Redundancy": a
// redundant pair is presented as "redundant, not corroborating" with its
// reason; a corroborating one is qualified as resting on declared custody.
function corroborationText(c: CorroborationResult): string {
  switch (c.result) {
    case "redundant":
      return `${c.report} (${c.reasons.join(", ")})`;
    case "corroborating":
      return "corroborating, on declared custody";
    case "not_applicable":
      return "not applicable: the join did not derive agree";
  }
}

function renderComposed(
  model: ComposedSectionModel,
  host: PresentationHost,
  services: PresentationServices,
): void {
  const result = model.result;
  const section = element("section");
  section.dataset.section = "composition";
  section.dataset.module = BUILTIN_MANIFEST_COMPOSED.id;
  section.append(element("h2", "Composition"));

  const status = element("p", `composed/v1 check: ${result.status}`);
  status.dataset.compositionStatus = result.status;
  section.append(status);
  if (result.findings.length > 0)
    section.append(element("p", `findings: ${result.findings.join(", ")}`));
  // capsule-cli internal/cli/composed.go:69, the same statement of scope.
  section.append(
    element(
      "p",
      "Composition closure covers the declared members only; it is not completeness of participation.",
    ),
  );

  section.append(element("h3", "Composed digest"));
  const digest = element("dl");
  digest.dataset.composedDigest = result.composedDigest.declared;
  digest.dataset.matches = String(result.composedDigest.matches);
  digest.append(
    element("dt", "declared"),
    element("dd", result.composedDigest.declared),
    element("dt", "recomputed"),
    element("dd", result.composedDigest.recomputed || "uncomputable"),
    element("dt", "matches"),
    element("dd", result.composedDigest.matches ? "yes" : "no"),
  );
  section.append(digest);

  section.append(element("h3", "Members"));
  section.append(
    table(
      "composition-members",
      [
        "member",
        "observer",
        "outcome",
        "body",
        "digest",
        "graph closure",
        "interval coverage",
        "per-record membership",
        "refusal signature",
        "findings",
      ],
      result.members.map((m) => {
        const tr = row([
          m.id,
          m.observer,
          m.outcome,
          m.body,
          m.digest,
          claimText(m.bundle?.graphClosure),
          claimText(m.bundle?.intervalCoverage),
          claimText(m.bundle?.perRecordMembership),
          m.refusalSignature ?? NOT_APPLICABLE,
          findingsText(m.findings),
        ]);
        tr.dataset.memberId = m.id;
        tr.dataset.body = m.body;
        tr.dataset.digest = m.digest;
        return tr;
      }),
    ),
  );

  section.append(element("h3", "Observers"));
  section.append(
    table(
      "composition-observers",
      ["observer", "role", "custody domain"],
      result.observers.map((o) => {
        const tr = row([o.id, o.role, o.custodyDomain]);
        tr.dataset.observerId = o.id;
        return tr;
      }),
    ),
  );
  // Draft "Observers and Redundancy": custody labels can only downgrade.
  section.append(
    element(
      "p",
      "Custody domains are labels declared by whoever composed this block. Identical labels make an agreeing pair redundant; distinct labels do not establish that two observers are independent.",
    ),
  );

  section.append(element("h3", "Composition closure"));
  const closure = element(
    "p",
    `${result.compositionClosure.status}; missing: ${
      result.compositionClosure.missing.length === 0
        ? "none"
        : result.compositionClosure.missing.join(", ")
    }; findings: ${findingsText(result.compositionClosure.findings)}`,
  );
  closure.dataset.closureStatus = result.compositionClosure.status;
  section.append(closure);

  section.append(element("h3", "Joins"));
  if (result.joins.length === 0) section.append(element("p", "No joins."));
  else {
    section.append(
      table(
        "composition-joins",
        ["members", "basis", "declared", "derived", "result"],
        result.joins.map((j) => {
          const tr = row([
            pairText(j.members),
            j.basis,
            j.declared,
            j.derived ?? "not derivable",
            j.result,
          ]);
          tr.dataset.joinMembers = j.members.join(",");
          tr.dataset.joinDeclared = j.declared;
          tr.dataset.joinDerived = j.derived ?? "not_derivable";
          tr.dataset.joinResult = j.result;
          return tr;
        }),
      ),
    );
    for (const j of result.joins) {
      if (j.differences.length === 0) continue;
      const details = services.details(
        `Differing values: ${pairText(j.members)}`,
      );
      details.dataset.joinDifferences = j.members.join(",");
      for (const difference of j.differences)
        renderDifference(difference, details);
      section.append(details);
    }

    // Per pair, never combined into a count or a score.
    section.append(element("h3", "Agreement"));
    section.append(
      table(
        "composition-agreement",
        ["members", "result"],
        result.corroboration.map((c) => {
          const tr = row([pairText(c.members), corroborationText(c)]);
          tr.dataset.agreementMembers = c.members.join(",");
          tr.dataset.corroboration = c.result;
          if (c.result === "redundant")
            tr.dataset.reasons = c.reasons.join(",");
          return tr;
        }),
      ),
    );
  }
  host.L1.append(section);
}

/** The built-in composition section module (`aac.builtin.composed/v0`). */
export const composedSectionModule: PresentationModule<ComposedSectionModel> = {
  manifest: BUILTIN_MANIFEST_COMPOSED,
  canRender: (context) => composedResult(context) !== undefined,
  buildModel: (context) => {
    const result = composedResult(context);
    if (result === undefined)
      throw new Error(
        `${BUILTIN_MANIFEST_COMPOSED.id}: buildModel called although canRender was false`,
      );
    return { result };
  },
  render: renderComposed,
};
