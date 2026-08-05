# Implementation Status

This page records implementations and integrations known to the maintainers;
entries are facts with links, not endorsements. Corrections and additions by
PR.

Entries are grouped by strength of evidence, strongest first, following the
precedent of [RFC 7942, "Implementation Status"][rfc7942] — a section IETF
readers will recognize. An open pull request is not adoption; it is listed as
open. Every entry below was verified by opening its link at the time this
page was written.

[rfc7942]: https://www.rfc-editor.org/rfc/rfc7942

---

## 1. Merged upstream

**[ietf-wg-scitt/examples PR #3](https://github.com/ietf-wg-scitt/examples/pull/3)**
— "Add scitt-cose RFC9162_SHA256 cross-implementation test vectors (v1)".
Merged 2026-06-26 (merge commit `727ee03d`) into the IETF SCITT working
group's shared examples repository. Vendors the `scitt-cose` `RFC9162_SHA256`
test-vector suite byte-identical from `scitt-cose` tag
[`v0.1.1`](https://github.com/action-state-group/scitt-cose/releases/tag/v0.1.1)
(commit `41811d1e`).

**[projnanda/nandatown PR #197](https://github.com/projnanda/nandatown/pull/197)**
— "Trust/Payments layer: verifiable capsule receipts (capsule-emit-nanda) —
rebuild addressing #177". Merged 2026-07-15 (by Skyrider3, a Project NANDA
maintainer, not this project) from `StevenMih:hackathon/capsule-trust` into
`projnanda/nandatown:main` — 20 files changed, +2049/-0 lines. Adds an
installable `capsule-emit-nanda` package under `examples/capsule-emit/`
(`CapsuleEmitTrust` and `StripeCapsuledPayments` plugins, sealing NANDA Town
agent receipts and payments into an Agent Action Capsule ledger, verifiable
by any third party via `agent-action-capsule verify --store`), plus a
`receipt_reputation_capsule` scenario, and wires capsule validation into
NANDA's own `packages/nest-core/nest_core/validators.py` and `scenarios.py`.
Companion **[PR #200](https://github.com/projnanda/nandatown/pull/200)** —
"Trust layer: verifiable capsule receipts with CCF write-receipt anchoring" —
merged the same day (2026-07-15), adding CCF / Azure Confidential Ledger
write-receipt anchoring (offline-verified) on top of the same plugin.
Both supersede earlier, unmerged attempts at the same trust-layer work
by this project — [PR #177](https://github.com/projnanda/nandatown/pull/177),
[#54](https://github.com/projnanda/nandatown/pull/54), and
[#32](https://github.com/projnanda/nandatown/pull/32) (all closed) — PR #197's
title states it is the rebuild addressing #177's reviewer objections, and its
own commit history references reworking #32.

---

## 2. Registry entries by other owners

No third-party-owned registry entry citing this specification could be
independently verified with a working link at the time of writing. (Two
candidates — MachineMandate, VTO — were reviewed and dropped; see the
verification note in this page's originating PR.)

---

## 3. Proposed / in review

**[ietf-wg-scitt/examples PR #4](https://github.com/ietf-wg-scitt/examples/pull/4)**
— "Add two-TS Transparent Statement: Microsoft CCF dev + ASG RFC 9162
SHA-256". Opened 2026-07-20, **open, not merged**.

**[microsoft/scitt-ccf-ledger PR #424](https://github.com/microsoft/scitt-ccf-ledger/pull/424)**
— "Experimental RFC9162_SHA256 receipt support for IETF 126". Opened
2026-07-18, **open, not merged**, authored by achamayou (Amaury Chamayou,
Microsoft, a repository maintainer) — this is a Microsoft maintainer's
experimental PR, not a submission from this project, and its being open is
not a Microsoft adoption claim. It pins the IETF SCITT `valid-es256` and
`fail-tampered-path` example vectors at commit `727ee03d`. That commit is
the exact merge commit of [examples PR #3](#1-merged-upstream) above
(verified by comparing the pinned SHA to the PR's `mergeCommit` field and the
file list of that commit) — so the pinned vectors are, byte-for-byte, the
ones this project contributed in PR #3. The PR's own description states it
verifies the valid example and correctly rejects the tampered inclusion path
using those vectors.

---

## 4. Independent implementations and reviews

**[draft-rampalli-scitt-capsule-provenance-binding-00](https://datatracker.ietf.org/doc/draft-rampalli-scitt-capsule-provenance-binding/)**
— "Binding Per-Action Authorization and Memory Provenance into Agent Action
Capsules", Karthik Rampalli (Glyphzero, Inc.), 5 July 2026, active
Internet-Draft, sole author. Builds on this specification's extension points,
citing `I-D.mih-scitt-agent-action-capsule` sections 5.3 (effect record /
anchoring), 5.4 / 5.4.1 (disposition structure), 8.2, and 13 (extension
namespacing) throughout. Independent of this project — Glyphzero is not
a contributor to this specification.

This is a small, early-stage list. Most drafts and integrations touching this
specification currently involve project contributors directly and are not
listed here as independent; they are visible in the specification's own
Contributors section and in git history.

---

## Corrections

If any entry above is inaccurate, out of date, or missing attribution, open
a PR or an issue against this repository.
