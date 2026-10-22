# Agent Action Capsule TypeScript reference

This package is the record-format reference conforming to the Python authority
in this repository. It implements strict JSON/JCS, format-4 Capsule IDs, the
typed record model, Class-1 and `references[]` verification, registries,
Producer Envelopes, and Disclosure Envelopes through DE-3. It intentionally
does not contain Capsule producer verbs, CLL storage, policy, adapters, or
permalink transport.

For record-only consumers, use the supported `@action-state-group/agent-action-capsule/core`
entry. It exports the existing JSON/identity, typed Capsule model, Class-1/store,
registry, Disclosure Envelope and Producer Envelope APIs without loading Bundle,
CLL or presentation modules. Its `browser` condition excludes Node signing/key
creation while retaining WebCrypto envelope verification.

```ts
import { verifyClass1 } from "@action-state-group/agent-action-capsule/core";
const result = await verifyClass1(capsule);
```

CLL is an optional peer, so a clean production installation does not install
CLL or its storage drivers. To use `@action-state-group/agent-action-capsule/bundle`
or the existing broad root entry, explicitly install the pinned compatible CLL:

```bash
npm install @action-state-group/agent-action-capsule @action-state-group/cll@0.2.1
```

`verifyBundle(bundle, { strict: true })` adds the strict checks of
[`vectors/bundle/strict/README.md`](../vectors/bundle/strict/README.md) and a
verdict (`result.strict.verdict`: `VALID`, `INCOMPLETE` or `INVALID`). Pass
`requireSignature` to fail unsigned records and `witnessDirectory` (a parsed
`witnesses.json`) to check the witness receipts in `checkpoint.witnesses`; none
is trusted without it. The signed checkpoint is verified only in Node, where
CLL's COSE checkpoint verifier exists; elsewhere the `checkpoint` claim is
`withheld` and the verdict is never `VALID`.

`renderEvidenceGraph` states that verdict in its banner, one of the states of
the presentation contract's section 6.2. `data-verify` names the state:
`checking` until the checks finish, then `verified` (only for a `valid`
verdict), `incomplete`, `failed` or `unable` (no SHA-256 at all). Each state
has one fixed line (`VERIFICATION_BANNER_LINES`, pinned for every viewer in
[`vectors/viewer-core-text/`](../vectors/viewer-core-text/README.md)), and no
module, wording pack or bundle supplies it: a module that changes the banner
is discarded for the refusal. `data-verdict` is `valid`, `incomplete` or
`invalid`, and `data-checkpoint` is `verified`, `unverified`, `invalid` or
`absent`. A details line under the banner (`data-banner-detail`) names what
the page did not check or what failed, with the verifier's finding names, and
labels interval coverage and per-record membership `checkpoint_unverified`
when they rest on a checkpoint the page did not authenticate. A runtime with
no Ed25519 reaches no strict verdict; missing Ed25519 is never itself a
failure, so a bundle that passes the page's own checks, with every record
bound to a log position, reads `incomplete`. The browser build cannot
authenticate a checkpoint, so it says at most `incomplete`. Match a page's
state on these attributes, not on its words.

`buildEvidenceBundle(source, { root, intervalFrom })` builds a Bundle from a
`ProofSource`: the log's signed COSE checkpoint, its leaves, records by Capsule
ID, and inclusion and range proofs in the Bundle's own wire shape. It holds no
key, and it checks the result with `verifyBundle(bundle, { strict: true })`
before returning it, rejecting with `BundleBuildError` anything that verifier
calls INVALID. `proofSourceFromCll(backend, records)` makes a `ProofSource`
from a CLL backend (`scanEntries`, `loadCll`) and a record store whose
`get(capsuleId)` resolves to `capsule` and `producerEnvelope` bytes and rejects
with `code: "not_found"` for a record it does not hold.

- `intervalFrom: N` carries every record from seq N to the checkpoint tip, and
  none below N, with a range proof: the Bundle can read VALID. `N = 1` is the
  whole log.
- `intervalFrom: null` carries only the chosen records, each with its own
  inclusion proof, and states `completeness.selection: "producer-selected"`:
  nothing is claimed about the records between them, so it reads INCOMPLETE.

`intervalFrom` has no default, so a caller never hands over the whole log by
omission. A range over a leaf that is not a record, a carried record below N
and a record past the checkpoint are refused by name. A missing citation or an
unsigned record is stated, not refused, and reads INCOMPLETE.
`buildUnprovenBundle(records, { root })` is the form with no log proof, for
Capsules that belong to no log. `buildEvidenceBundle` needs CLL and Node, where
the checkpoint verifier runs; `buildUnprovenBundle` reads no checkpoint, so it
runs wherever strict `verifyBundle` does, the browser included.

`@action-state-group/agent-action-capsule/settlement` exports
`verifySettlements`, which derives the states of
`draft-mih-agent-settlement-records-00` from both parties' leg records. It
needs no CLL.

`@action-state-group/agent-action-capsule/witness` exports the witness receipt
checks strict mode uses, for callers outside a Bundle: `verifyCoseReceipt`
(a COSE Receipt over leaf bytes under one DER public key), `verifyReceipt`,
`verifyRekorReceipt`, `verifyScrapiReceipt`, and the directory helpers
`witnessRowFor` and `witnessRowKeys`. It needs no CLL.

The existing root exports remain available with CLL installed. The separate
Bundle entry reuses AAC's existing verifier and CLL proof operations; it does
not introduce another implementation. Development installs include CLL so the
full Bundle and browser conformance suites continue to run.

The Node entry requires Node.js 20 or newer. Bundlers using the `browser`
condition resolve a WebCrypto-only verification entry; it excludes the
Node-only Producer Envelope signing and key-creation APIs while retaining
`verifyProducerEnvelope`.

Digest-dependent APIs are async: await `sha256Hex`, `jsonDigest`,
`computeCapsuleId`, `verifyClass1`, `verifyStore`,
`verifyDisclosureEnvelope`, `sealCapsule`, and `parseCapsule`.
`verifyProducerEnvelope` is also async on both entry points.

```bash
npm ci
npm run check
```

The tests consume the same-commit corpora under `../vectors/`.

## Release

Releases follow the repository's [RELEASING.md](../RELEASING.md): run
**Release · Prepare** for `ts`, and merging its pull request creates the
`ts/v<version>` tag and dispatches
[Release · Publish TypeScript](https://github.com/action-state-group/agent-action-capsule/actions/workflows/publish-ts.yml)
on it. The workflow checks the tag against `ts/package.json`, the lockfile and
that the commit is on `main`, runs `npm ci` and the complete package
check/build, and performs `npm publish --dry-run` before uploading from the
`npm` environment. Reruns skip a version npm already has, and registry errors
other than E404 stop publication. Prerelease versions publish under the `next`
dist-tag, and a stable version older than npm's current `latest` under
`backport`, so `latest` never moves backward.

Before a real release, the npm package owner must configure a
[trusted publisher](https://docs.npmjs.com/trusted-publishers/) for
`@action-state-group/agent-action-capsule`: GitHub owner `action-state-group`,
repository `agent-action-capsule`, workflow filename `publish-ts.yml`, and
permission for direct `npm publish`, with environment name `npm` (the job runs
in that environment). The package/scope
must be provisioned by its owner; this workflow does not bootstrap ownership.
The workflow uses Node 22 (>=22.14) and installs npm 11.19.1; trusted
publishing requires npm >=11.5.1. No long-lived npm token is used, and
trusted publishing supplies provenance automatically. The package is public.

The TS workflow publishes only for a `ts/v*` tag: when Release · Tag dispatches
it on the tag, or when a GitHub Release for a `ts/v*` tag is published, so
publishing such a release by hand uploads to npm. Dispatched on a branch, it
does nothing. `ts/v` tags never start the Python/PyPI publish job, and vector
releases stay separate.

For a local upload-free preview, run from `ts/`:

```bash
npm ci
npm run check
npm publish --dry-run --access public
```

If npm already contains the version but GitHub rejects tag recovery with the
workflow token, a maintainer with the required workflow permission must create
`ts/v<version>` at npm's recorded `gitHead`, then rerun the workflow. Do not
retag another commit or publish a replacement for the same npm version.
