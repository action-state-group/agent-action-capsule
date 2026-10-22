# The contract-report/v1 Extension — v1

**Status.** Informational, kept in this repository. It changes no Internet-Draft. It defines one
Evidence Bundle extension kind, `contract-report/v1`, registered in `REGISTRY.md` §14. The block
is a producer's opt-in to a **contract-report view** of a verified Evidence Result: any Evidence
Contract's Result, shown grouped by row and by status. Its companion schema is
`schemas/contract-report-v1.json`. Where the schema and this document disagree, this document
governs.

## Dependency boundary

**Owns:** the block (§1), how a contract-report module reads the Result (§2), the wording keys the
kind defines (§3), and the manifest a contract-report module registers with (§4).

**Uses unchanged:**

| Tag | Document | What this document takes from it |
|---|---|---|
| ER | `spec/evidence-result-v0.md` | the claim, its verdict, sufficiency, tier, grade and carrier status (§1, §2, §4, §6); the aggregate (§3, §7); the typed-claim rendering rules (§4.1); `x-` members (§8a) |
| PC | `spec/presentation-contract-v0.md` | the descriptor and resolution (§4), the chrome rule (§6), wording packs and `wording_sha256` (§7.3, §7.4), the built-in manifests (appendix A) |

**Does not define:** a renderer. The core runtime ships no contract-report module; the module is a
presentation runtime's own (§4). Nor does it define any pack, its rows, its words, or how a builder
chooses a pack for a page.

## 1. The block

```json
"extensions": { "contract-report/v1": {} }
```

The block is a closed empty object. It carries no words, data, grouping, flags or provenance:
everything a contract-report module shows comes from the sealed Result, and every word from the
module's wording pack (§3).

A block that is not an object, or that has any member, is **declined**: the kind is not engaged
(PC §4.2), and the verification page still lists the block as present. Present and well formed
means engaged. Like every extension, the block is covered by the bundle digest.

## 2. How a contract-report module reads the Result

A **contract-report module** is a presentation module that draws the contract-report view. These
rules bind it:

- **Summary first.** It shows the Result's sealed `aggregate` as it is: coverage, then the three
  buckets (ER §3). Coverage counts evaluations, beside the number of distinct requirements the
  claims cite ("24 evaluations of 4 requirements"), and the buckets list claims; the module labels
  each with its unit and never calls `unknown_count` unresolved requirements (ER §3). It never
  recomputes the aggregate. A bucket that names a claim the Result lacks, or a claim with a
  different verdict, makes the Result invalid (ER §4); the Result checks report that, and the
  module does not repair it. Showing the sealed aggregate does not mean every judgment in it
  verified: a claim whose own checks fail is shown as failed, apart from the producer's counts.
- **Rows.** A row is one (`contract_ref`, `requirement_ref`) pair. Its tally counts that row's
  claims by `verdict` (`met`, `not_met`, `not_evaluable`), each a separate count, always shown with
  its denominator ("2 of 5 claims"). A re-judged requirement has several claims, and each counts as
  a claim, never as a requirement. There is no percentage and no single score.
- **Several contracts.** A Result that cites more than one contract shows its rows grouped by
  `contract_ref` first, in order of first appearance.
- **Groups.** A row's group is the part of its `requirement_ref` before the first `.`. It is read
  from the claims; the producer never supplies it. Groups and rows keep the order of their first
  claim. A `requirement_ref` with no `.` is in a final group with no title. There is one level of
  grouping: a group is a heading, a row is level 1 and its claims are level 2. How groups and rows
  are laid out (lines or cards) is the module's chrome.
- **Assurance stays on the claim.** Each claim shows its `tier`, its `grade` and its carrier
  `status` (for example `WITHHELD` or `NOT_COMMITTED`). `analysis` and `story` text is never shown
  as evidence.
- **Typed claims** follow ER §4.1's rendering rules: a `reconcile` claim's `A_ONLY` and `B_ONLY`
  never read as `CONFLICTING`, and a claim of an unrecognized `type` is shown as unrecognized, never
  dropped.
- **`x-` members** (ER §8a) are never read.
- **Other sealed records.** A module MAY also show other sealed records of the bundle (for example
  per-case reports) under the same rules: every number traces to sealed records, withheld stays
  explicit, and producer text is labelled as the producer's.
- **Applicability** (whether a requirement applies yet) is not shown: Result v0 has no member for
  it, and this kind adds none.
- **Verdicts.** The kind shows the verdict values ER defines, and no others.

## 3. Words

Words come only from the module's wording pack and the core's fixed text (PC §6, §7.4), never from
the bundle. Which pack a page uses is an input to the builder or host, like the theme and the
locale: a builder may, for example, choose the pack for the Result's contract, or take it as a
command-line option. Delivering the pack to the module is the presentation runtime's.

A module MAY layer its own default pack beneath the host's pack, entry by entry. Each layer is
bound by its own `wording_sha256`, and the page records each layer's `wording_sha256`. A builder
MAY refuse to write a page whose pack is refused (PC §7.4) instead of falling back.

**Keys this kind defines.** Each is a full `WordingKey` once assembled. An enum value is
lowercased:

| Key | Meaning |
|---|---|
| `report.title`, `report.summary` | The report's heading and its one-line summary. |
| `group.<segment>.title` | A group's heading. |
| `row.<requirement_ref>.label`, `.detail`, `.not_evaluable` | A row's name, its explanation, and the note shown when its claims are not evaluable. |
| `verdict.<value>` | `met`, `not_met`, `not_evaluable`. |
| `sufficiency.<value>` | `satisfied`, `gap`, `insufficient`, `unknown`. |
| `tier.<value>` | `recomputed`, `judged`. |
| `grade.<value>` | `self-attested`, `witnessed`, `countersigned`. |
| `status.<value>` | The lowercased EvidenceStatus, for example `withheld`. |

`row.*` and `group.*` keys apply only when every claim cites the same `contract_ref`: a pack is
written for one contract, and two contracts can use one `requirement_ref` for different
requirements (ER §1). In a Result that cites several contracts, rows and groups show their raw
identifiers.

**Missing words.** Each layer is checked on its own (PC §7.4), and a refused layer contributes no
words. When every layer is refused, the core's own fallback labels are shown, and a word with none
is shown as its raw token or identifier. Otherwise, after layering, a word whose entry is missing
or whose assembled key is not a valid `WordingKey` is shown as its raw token or identifier. A
missing `report.title` shows no title. Nothing is guessed. Other keys a pack carries are the
module's own.

`schemas/examples/presentation-manifest-v0/example-wording-pack-contract-report.json` is an example
pack for this kind; `schemas/check_contract_report_examples.py` checks it.

## 4. Resolution

**In the core runtime.** The built-in manifest `aac.builtin.result-contract-report/v0` (PC appendix
A) requires `result_version:evidence-result-v0` and `contract-report/v1` and forbids
`spec_version:report/v1`. It draws the generic Result page: the core runtime has no
contract-report module. The built-in Result page and the two earlier display cards forbid
`contract-report/v1`, so a Result root that opts in resolves to this manifest, whether or not it
also carries an earlier kind (PC §4.2's deprecation table). The verification page lists the
engaged block as not interpreted, because the core applies no report view.

**A runtime with a contract-report module** registers that module **in place of**
`aac.builtin.result-contract-report/v0`, never beside it: the two match the same descriptors, so
registering both is an ambiguity error (PC §4.5). The module's manifest has the same match:

| Member | Value |
|---|---|
| `requires.bundle_kind` | `evidence-bundle/v2` |
| `requires.profiles` | `["result_version:evidence-result-v0"]` |
| `requires.extensions.required` | `["contract-report/v1"]` |
| `forbids.profiles` | `["spec_version:report/v1"]` |
| `audiences` | `["*"]` |
| `formats` | `["html", "fragment", "embedded"]` |
| `fallback`, `priority` | `false`, `1` |

It carries no `executable.wording_sha256`: the pack is a builder input, recorded as provenance (PC
§7.3). Its `canRender` is true whenever the generic Result page's would be, whatever the pack or
the number of contracts, so every Result root that opts in reaches it. A runtime MAY list the block
as interpreted by the module that resolved on it. `vectors/presentation-resolution/registration.json`
pins both registrations (`contract-report-module-beside-builtin`,
`contract-report-module-in-place-of-builtin`).

## 5. Earlier kinds

Two earlier, unregistered display kinds are deprecated aliases of this one, listed in PC §4.2's
deprecation table with the releases that deprecate and remove them. Nothing converts an earlier
block into this one: until their removal they are read by their own readers, unchanged, and
their built-in manifests differ only in forbidding `contract-report/v1`. A producer migrates by
writing `{"contract-report/v1": {}}` in place of its earlier block and moving its words into its
wording pack.
