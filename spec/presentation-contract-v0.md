# Presentation Contract — v0 (moved)

**Status.** Informative pointer. This document is not normative. The presentation contract that
was here is split in two:

- What decides which page a bundle gets and how the page is assembled (the module interface and
  its ABI, the manifest, the descriptor, resolution, trust classes, the chrome rule, presentation
  words and wording packs, the presentation invariants, depth levels and the built-in manifests)
  is now `spec/presentation-contract-v0.md` in the `action-state-group/capsule-viewer`
  repository.
- What a page states about verification (what "verified" means for a page, the verification
  page's check lists, the verification banner, the refusal's text, evidentiary words, the
  `sha256-jcs-nonce256` construction and the evidence-identifier invariant) is
  `spec/verification-display-v0.md` in this repository. It keeps this document's section
  numbers.
- The deprecation table of section 4.2 is in `spec/REGISTRY.md` section 14.

The last revision with the whole text is `60a5b11`. Public names are unchanged:
`aac.presentation-api/v0`, `aac.presentation-manifest/v0`, `aac.wording-pack/v0`, the
`aac.builtin.*` manifest ids, the `data-*` attributes and the `vectors/` case ids.

## Where each section went

"Viewer contract" is capsule-viewer's `spec/presentation-contract-v0.md`, at the same section
number unless the row says otherwise. "Verification display" is `spec/verification-display-v0.md`.

| Section here | Now in |
|---|---|
| Status, Dependency boundary | Viewer contract |
| 1. Terms: "Verified" | Verification display §1 |
| 1. Terms: every other term | Viewer contract §1 |
| 2. The pipeline | Viewer contract |
| 3. The module interface, 3.1, 3.2 | Viewer contract |
| 4. The manifest, 4.1 | Viewer contract |
| 4.2 The descriptor | Viewer contract; its deprecation table is in `spec/REGISTRY.md` §14 |
| 4.3 Resolution, 4.4 Priority, 4.5 The static ambiguity test | Viewer contract |
| 5. Trust classes, 5.1, 5.2 | Viewer contract |
| 6. The chrome rule | Viewer contract |
| 6.1 The verification page's check lists | Verification display §6.1; the paragraph "Modules MUST NOT restate verification" is in the viewer contract §6.1 |
| 6.2 The verification banner | Verification display §6.2 (the states, the table, each state's line and the details line); the rules on a presentation refusal and on a module that changes the banner are in the viewer contract §6.2 |
| 7. The text-binding rule | Viewer contract (the section's lead) |
| 7.1 Evidentiary words | Verification display §7.1 |
| 7.2 `sha256-jcs-nonce256` | Verification display §7.2 |
| 7.3 Presentation words, 7.4 Wording packs and `wording_sha256` | Viewer contract |
| 8. Invariants: I1 | The refusal's text: verification display §8, I1. The collapse and the render-failure rules: viewer contract §8, I1 |
| 8. Invariants: I3 | Verification display §8, I3 |
| 8. Invariants: I2, I4 to I8 | Viewer contract |
| 9. Depth levels and the shell, 9.1, 9.2 | Viewer contract |
| 10. Conformance | Both: a viewer's words equal `vectors/viewer-core-text/` (verification display §10); manifests, registries, runtimes, modules and the rest of a viewer (viewer contract §10) |
| Appendices A, B and C | Viewer contract |

The companion schema `schemas/presentation-manifest-v0.json`, its examples and checker, the
shared resolution vectors `vectors/presentation-resolution/`, and the TypeScript and Go
registries (`ts/src/presentation-registry.ts`, `go/presentation`) moved with the viewer contract.
