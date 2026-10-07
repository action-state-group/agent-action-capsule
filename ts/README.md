# Agent Action Capsule TypeScript reference

This package is the record-format reference conforming to the Python authority
in this repository. It implements strict JSON/JCS, format-4 Capsule IDs, the
typed record model, Class-1 and `references[]` verification, registries,
Producer Envelopes, and Disclosure Envelopes through DE-3. It intentionally
does not contain producer verbs, CLL storage, policy, adapters, or permalink
transport.

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
npm install @action-state-group/agent-action-capsule github:action-state-group/cll-ts#0ac72b3
```

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

## Bundle verification verdict

`verifyBundle` reports each Evidence Bundle claim on its own: graph closure,
the checkpoint signature (`checkpointSignature`), interval coverage,
per-record membership, and the records' producer signatures
(`producerSignatures`, with each record's state in `recordSignatures`).
`bundleVerdict(result)` combines them into one of three verdicts, using the
same rules as `capsulectl verify --bundle`:

- `invalid`: a claim failed, a record failed its identity check, or a
  disclosed member is neither a match nor withheld.
- `incomplete`: nothing failed, but some claim was not shown. A claim counts
  as not shown when it is not `pass` or carries a finding, such as
  `checkpoint_signature_absent`, `checkpoint_unverified`,
  `producer_signature_unclaimed` or `declared_incomplete`.
  `bundleVerdictDetail(result)` lists those claims.
- `valid`: every claim passes with no findings.

A missing witness receipt does not lower the verdict, because this library
checks no receipts.

The browser build can't authenticate a COSE checkpoint, because CLL's browser
substrate has no checkpoint authenticator. So in that build the checkpoint
claim is `withheld` with `checkpoint_unverified`, and interval coverage and
per-record membership carry the same finding. Under the Evidence Bundle draft,
those claims hold only relative to a producer-asserted checkpoint. The
browser build reports them that way, so it is at most `incomplete`, even for
a bundle that the Node build or the CLI calls `valid`.

Producer signatures are verified with WebCrypto Ed25519. Where a runtime
lacks it, a signed record is reported as `producer_signature_unverified`
rather than passed.

The rendered page puts the verdict in its banner as `data-verdict` (`valid`,
`incomplete` or `invalid`). It sets `data-checkpoint` to `verified`,
`unverified`, `invalid` or `absent`. The banner says "passed" only for
`valid`. The older `data-verify` attribute still records only whether the
page rendered the bundle's rows; it is not the verdict.

## Release

The manual [Publish TypeScript npm package](https://github.com/action-state-group/agent-action-capsule/actions/workflows/publish-ts.yml)
workflow follows capsule-emit-ts's main-only trusted-publishing convention.

1. Update the version in `ts/package.json` and both root version fields in
   `ts/package-lock.json`, merge to `main`, and wait for CI to pass.
2. Run `publish-ts.yml` on `main`, supplying that exact version. The workflow
   checks the name/version/lockfile, runs `npm ci` and the complete package
   check/build, and performs `npm publish --dry-run` before uploading.
3. Verify the npm package and `ts/v<version>` GitHub tag/release. Reruns skip
   existing npm versions and check the tag against npm's `gitHead`, which must
   be in the selected main commit's history. Registry errors other than E404
   stop publication. A mismatched existing tag fails instead of moving it.

Before a real release, the npm package owner must configure a
[trusted publisher](https://docs.npmjs.com/trusted-publishers/) for
`@action-state-group/agent-action-capsule`: GitHub owner `action-state-group`,
repository `agent-action-capsule`, workflow filename `publish-ts.yml`, no
environment name, and permission for direct `npm publish`. The package/scope
must be provisioned by its owner; this workflow does not bootstrap ownership.
The workflow uses Node 22 (>=22.14) and installs npm 11.19.1; trusted
publishing requires npm >=11.5.1. No long-lived npm token is used, and
trusted publishing supplies provenance automatically. The package is public.

The TS workflow has no push/tag/release trigger. Its `ts/v` releases are
excluded from the Python/PyPI publish job; ordinary Python release behavior
and vector release behavior remain separate. Running the TS workflow is an
actual release operation, not a dry-run-only dispatch.

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
