# Conformance vector index

Informative. This index points at the conformance vector corpora and never
redefines a vector: a corpus is authoritative for the specification it names,
and the specification is the source of truth. Listing a set here makes it
normative for nothing and claims no adoption.

Each row gives the set's path, its owning specification, the SDK verbs it
exercises, and its case count. The verb column is an informative reading, not a
registered vocabulary: `record` (seal a record or Capsule), `request` /
`respond` (ask for evidence and answer), `verify` (check what was received),
`evaluate` (decide a claim or contract), `pack` (build a bundle), `report`
(render a result or page), `doctor` (self-diagnosis).

Sets in this repository are pinned to the commit that contains this file.
`scripts/check_vector_index.py` recomputes every case count below from the
files and fails when a count differs or when a vector directory has no row; CI
runs it. A case is one entry of the set's own case list, or, where a set has
none, one case file or case directory. [`vectors/README.md`](vectors/README.md)
describes how the sets are generated and checksummed.

## Run the vectors

One command per language runs every set below that the language has tests for,
offline, and prints `PASS`, `FAIL`, `PARTIAL` or `SKIP` per set with the set's
case count (the count in the table below).
`PASS` means every test mapped to the set passed; the count is the set's size in
the files, not the number of cases the tests executed. A set a language has no tests for is
listed as `SKIP`, never left out; `PARTIAL` means some of its tests were skipped
(a missing optional tool), and the reason is printed.

| Language | Command (from the repository root) |
|---|---|
| Python | `python3 scripts/run_vectors.py python` |
| TypeScript | `python3 scripts/run_vectors.py ts` |
| Go | `python3 scripts/run_vectors.py go` |
| Rust | `python3 scripts/run_vectors.py rust` |

The runner is stdlib-only Python 3 that calls each language's own test runner on
the tests mapped to each set in [`scripts/vector_sets.json`](scripts/vector_sets.json).
It exits non-zero when any set fails.

**Setup, once per language (this is the only step that needs a network).**
The runner itself never touches the network.

| Language | Setup |
|---|---|
| Python | `python3 -m venv python/.venv && python/.venv/bin/pip install -e "python[dev,bundle]" jsonschema` |
| TypeScript | `cd ts && npm ci` |
| Go | `cd go && GOWORK=off go mod vendor` (the runner then uses `-mod=vendor` and `GOPROXY=off`) |
| Rust | `cd rust && mkdir -p .cargo && cargo vendor --locked vendor > .cargo/config.toml` (the runner passes `--offline --locked`) |

The vendored trees and `python/.venv` are local build output; do not commit
them. [`scripts/build_offline_bundle.sh`](scripts/build_offline_bundle.sh) packs
all of the above, with a Python wheelhouse and an npm cache, into one tarball
with a `setup-offline.sh` that needs no network;
[`scripts/verify_offline_bundle.sh`](scripts/verify_offline_bundle.sh) unpacks
it and runs everything with the network denied. A bundle is built for one OS,
CPU and Python minor version (its compiled Python wheels are platform-specific),
so build one per target platform; `setup-offline.sh` stops on any other machine.
Each language also needs its toolchain installed.

**Break one byte.** Add `--break-one-byte` to any command above:

```bash
python3 scripts/run_vectors.py go --break-one-byte
```

It changes the last character of `action_id` in
`vectors/capsule/pos-v4-jcs-chain-committed/input.json`, runs the
`vectors/capsule/` set, and the case `pos-v4-jcs-chain-committed` fails with a
`capsule_id_mismatch` (the recomputed `capsule_id` no longer equals the carried
one). The file is restored afterwards and the command exits 0 only when the set
failed and the restore is byte for byte. To do it by hand, edit one character
of any positive vector's `input.json`, run the language's command, then
`git checkout -- vectors`.

## Capsule, envelopes and bundles

| Set | Owning specification | Verbs | Cases |
|---|---|---|---|
| `vectors/capsule/` | `draft-mih-scitt-agent-action-capsule-05` (format 4, Class-1) | record, verify | 119 |
| `provenance-mode-vectors/` | `draft-mih-scitt-agent-action-capsule-05` (provenance mode) | record, verify | 27 |
| `vectors/producer-envelope/` | `draft-mih-scitt-agent-action-capsule-04#producer-envelope` | record, verify | 47 |
| `vectors/disclosure-envelope/` | `draft-mih-agent-disclosure-envelope-00` | record, verify | 9 |
| `vectors/cross-language/` | Class-1 and Evidence Bundle inputs shared by every implementation | record, pack, verify | 72 |
| `vectors/bundle/vectors.json` | `draft-mih-zhang-agent-disclosure-bundle-00` | pack, verify | 14 |
| `vectors/bundle/composed/` | `draft-mih-zhang-agent-disclosure-bundle-01` (`composed/v1`) | pack, verify | 6 |
| `vectors/bundle/producer-key/` | `draft-mih-zhang-agent-disclosure-bundle-01` (`producer-key/v1`) | pack, verify | 8 |
| `vectors/bundle/report-single-record.json` | `draft-mih-zhang-agent-disclosure-bundle-00` (report of one record) | report | 3 |
| `vectors/bundle/strict/` | Evidence Bundle strict verification | verify | 82 |
| `vectors/bundle/fragment/` | `draft-mih-zhang-agent-disclosure-bundle` (Fragment Codec) | pack, report | 7 |
| `vectors/minimum-necessary/` | `spec/REGISTRY.md` §10, §14, §16 (provisional entries) | pack, verify | 15 |
| `vectors/judgment/` | `x-judgment-v1` extension (provisional) | record, verify | 5 |
| `vectors/evidence-layer/padding/` | `draft-mih-agent-evidence-layer-00` (What a Checkpoint Reveals) | record, verify | 17 |
| `vectors/registry-conformance/` | `spec/REGISTRY.md` | verify | 26 |

Counts that are not a set's own case list: `vectors/cross-language/` is the 54
Ed25519 and 14 COSE cases of `cll-ed25519-vectors.json` plus one case for each
of its four other input files; `vectors/bundle/strict/` is its 73 `cases` plus
its 9 `record_signatures`.

## Request, respond and the interop profile

| Set | Owning specification | Verbs | Cases |
|---|---|---|---|
| `vectors/evidence-request/` | `draft-mih-agent-evidence-request-00`, `-01` and `-02` | request, respond, verify | 212 |
| `vectors/settlement/` | `draft-mih-agent-settlement-records-00` | record, verify | 24 |
| `vectors/interop/` | composition and run-under suites | verify | 11 |
| `vectors/interop-profile-v0/` | `spec/interop-profile-v0.md` (`evidence-interop/0`) | respond, verify | 55 |
| `vectors/interop-profile-v0-requirement-facts/` | `spec/interop-profile-v0.md` §8.3 | evaluate | 2 |
| `vectors/interop-profile-v1/` | `spec/interop-profile-v1.md` (`evidence-interop/1`) | respond, verify | 58 |
| `vectors/interop-profile-v1-requirement-facts/` | `spec/interop-profile-v1.md` §8.3 | evaluate | 2 |
| `vectors/cll-material/` | `spec/interop-profile-v0.md` §6.2.1 | respond, verify | 184 |
| `vectors/coverage-declaration-v0/` | `spec/interop-profile-v0.md` §6.7 | evaluate, verify | 13 |
| `vectors/controller-binding-v0/` | `spec/controller-binding-v0.md` | verify | 42 |
| `vectors/personal-history-basic-v0/` | `spec/personal-agent-history-profile-v0.md` §6.4 (Basic) | respond, verify | 14 |
| `vectors/personal-history-outcome-v0/` | `spec/personal-agent-history-outcome-v0.md` (Outcome) | respond, evaluate | 25 |
| `vectors/standard-history-v0/` | `spec/standard-history-v0.md` (`standard_history/1`) | evaluate, report | 28 |
| `vectors/inference-service-history-v0/` | `spec/inference-service-history-profile-v0.md` | respond, verify | 27 |
| `vectors/inference-service-history-v0-interop-v1/` | `spec/inference-service-history-profile-v0.md` over `evidence-interop/1` | respond, verify | 28 |
| `vectors/history-frame-v0/` | `spec/history-frame-v0.md` (the instances' counting tables and wording packs) | evaluate | 9 |

## Evaluate, judge and report

| Set | Owning specification | Verbs | Cases |
|---|---|---|---|
| `vectors/evidence-result/` | `spec/evidence-result-v0.md` (including `plan_ref` and `dataset_ref`) | evaluate, report | 78 |
| `vectors/evidence-dataset/` | `spec/evidence-plan-ir-v0.md` §5.1, §6.2 (dataset plans and datasets) | evaluate | 32 |
| `vectors/deal-reconcile-v0/` | `spec/deal-reconcile-contract-v0.md` (`ec:deal-reconcile@1`) | evaluate | 14 |
| `vectors/judge/` | `spec/judge-record-family-v1.md` | record, evaluate | 18 |
| `vectors/profiles/` | host-principal and Evidence Contract profiles (illustrative) | record, evaluate | 10 |
| `vectors/viewer-core-text/` | `spec/verification-display-v0.md` §6.1, §6.2 | report | 21 |
| `vectors/adapters/x402/` | `spec/adapters/x402-v0.md` | verify | 2 |
| `vectors/adapters/ucp/` | `spec/adapters/ucp-v0.md` §3 | verify | 2 |

## Verbs with no corpus

| Verb | Vectors |
|---|---|
| `doctor` | none |

Every other verb above has at least one set. `pack` and `report` are covered
only by the bundle sets and the viewer text, not by a corpus of their own.

<!-- sibling-sets -->
## Implementation vector sets (informative)

Sets held in other repositories of the action-state-group organization. Each
is pinned by full commit SHA with its count taken at that commit. A set here
is normative for its own repository's specification, never because this index
lists it, and these rows are not checked by CI.

| Set | Owning specification | Verbs | Pinned commit | Cases |
|---|---|---|---|---|
| capsule-engine `conformance-vectors/guard/v0/` | guard gates (capsule-engine) | evaluate | `1679214500543b4620ab3cc6b24fa956b6080c1a` | 942 (44 case files; `KNOWN-DIFFERENCES.json` not counted) |
| capsule-viewer `vectors/presentation-resolution/` `table.json` | `spec/presentation-contract-v0.md` Appendix A.3 | report | `f6880200f8376306bb30514fe89ff75dab627967` | 3072 |
| capsule-viewer `vectors/presentation-resolution/` `registration.json` | `spec/presentation-contract-v0.md` §3.2, §4.3, §4.5 | report | `f6880200f8376306bb30514fe89ff75dab627967` | 63 |
| capsule-viewer `vectors/presentation-resolution/` `descriptors.json` | `spec/presentation-contract-v0.md` §4.2 | report | `f6880200f8376306bb30514fe89ff75dab627967` | 565 |
| evidencebook `testdata/derivation/` | `spec/interop-profile-v0.md` (derivations) | respond | `f509823c7ed34e8dc52dc2dedee7fdae9ec06d74` | 12 |

The `contract-report/v1` page vectors of capsule-viewer are not yet merged and
have no row. Downstream indexes, such as evidencebook's `VECTORS.md`, point
here instead of repeating this table.
