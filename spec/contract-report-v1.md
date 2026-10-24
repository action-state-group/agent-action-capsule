# The contract-report/v1 Extension — v1

**Status.** Informational, kept in this repository. It changes no Internet-Draft. It defines one
Evidence Bundle extension kind, `contract-report/v1`, registered in `REGISTRY.md` §14. The block
is a producer's opt-in to a **contract-report view** of a verified Evidence Result: any Evidence
Contract's Result, shown grouped by row and by status. Its companion schema is
`schemas/contract-report-v1.json`. Where the schema and this document disagree, this document
governs.

## Dependency boundary

**Owns:** the block (§1) and the earlier kinds it replaces (§5).

**Uses unchanged:**

| Tag | Document | What this document takes from it |
|---|---|---|
| ER | `spec/evidence-result-v0.md` | the Evidence Result the block opts into a view of |
| PC | `spec/presentation-contract-v0.md` | which extension kinds are engaged (§4.2) |
| REG | `spec/REGISTRY.md` | the kind's row and the deprecation table of the earlier kinds (§14) |

**Does not define:** a renderer. The core runtime ships no contract-report module. Nor does it
define any pack, its rows, its words, or how a builder chooses a pack for a page.

## 1. The block

```json
"extensions": { "contract-report/v1": {} }
```

The block is a closed empty object. It carries no words, data, grouping, flags or provenance:
everything a contract-report module shows comes from the sealed Result, and every word from the
module's wording pack (the former §3, below).

A block that is not an object, or that has any member, is **declined**: the kind is not engaged
(PC §4.2), and the verification page still lists the block as present. Present and well formed
means engaged. Like every extension, the block is covered by the bundle digest.

Sections 2 to 4 (how a contract-report module reads the Result, its words and keys, its
resolution, manifest and registration) and the example pack moved to the
`action-state-group/capsule-viewer` repository as `spec/contract-report-module-v1.md`.

## 5. Earlier kinds

Two earlier, unregistered display kinds are deprecated aliases of this one, listed in REG §14's
deprecation table with the releases that deprecate and remove them. Nothing converts an earlier
block into this one: until their removal they are read by their own readers, unchanged, and
their built-in manifests differ only in forbidding `contract-report/v1`. A producer migrates by
writing `{"contract-report/v1": {}}` in place of its earlier block and moving its words into its
wording pack.
