<!-- SPDX-License-Identifier: BSD-3-Clause -->
# Releasing

The Python package (PyPI), the TypeScript package (npm) and the Rust crate
(crates.io) release the same way. A release is a merged version bump: you choose the bump, review it as a
pull request, and merging it tags and publishes. The packages are listed in
[`.github/releases.json`](.github/releases.json), which
[`.github/release.py`](.github/release.py) reads.

| Package | Manifest | Tag | Publisher | Environment |
|---|---|---|---|---|
| `python` | `python/pyproject.toml` | `python/v<version>` | `publish-python.yml` | `pypi` (tag rule `python/v*`) |
| `ts` | `ts/package.json` and `ts/package-lock.json` | `ts/v<version>` | `publish-ts.yml` | `npm` (tag rule `ts/v*`) |
| `crates/agent-action-capsule` | `rust/agent-action-capsule/Cargo.toml` and `rust/Cargo.lock` | `crates/agent-action-capsule-v<version>` | `publish-rust.yml` | `crates-io` (tag rule `crates/*-v*`) |

The prefix is only on the Git tag. The registry version stays plain (`0.8.0`).
Python releases up to 0.7.0 were tagged bare `v<version>` (`v0.0.3` to
`v0.7.0`); those tags stay, but a new bare `v*` tag no longer publishes.

## Cutting a release

1. **Prepare.** Run [Release · Prepare](https://github.com/action-state-group/agent-action-capsule/actions/workflows/prepare-release.yml)
   on `main`, choosing the package and `patch`, `minor` or `major`. It raises
   the version from the current one, commits the bump with a sign-off, and
   pushes `release/<package>-v<version>`.
2. **Review.** Open the pull request from the link in the run summary. Open it
   yourself: a pull request opened by the workflow would not start CI. Add the
   CHANGELOG entry for the release on the same branch if it is not in yet.
3. **Merge.** [Release · Tag](https://github.com/action-state-group/agent-action-capsule/actions/workflows/tag-release.yml) runs on the
   merge. For each package whose version changed it creates the tag and GitHub
   Release on the merge commit and dispatches the package's publisher on that
   tag.
4. **Publish.** The publisher checks that the tag is the package's prefix plus
   its manifest version and that the commit is on `main`, then uploads through
   OIDC trusted publishing from its environment. Confirm the run and the new
   version on the registry.

Bumping a version by hand in any pull request releases it the same way when it
merges.

If a publish fails after the tag exists:

- **A transient or configuration failure** (registry outage, trusted publisher
  or environment settings): fix it and re-run the failed publisher run.
  `publish-ts.yml` skips a version npm already has from the same commit, so a
  re-run after a successful upload is harmless.
- **A defect in the code or the workflow:** a re-run uses the tagged commit
  again, so a fix merged to `main` does not reach it. Release the fix as a new
  version.
- **Release · Tag failed before dispatching** (no publisher run exists): re-run
  the Release · Tag run. It accepts a tag and GitHub Release it already created on
  the same commit and dispatches the publisher again.

## Safeguards

- **Guard.** `release.py check` refuses a tag from another package, a version
  that differs from the manifest, and a commit that is not on `main`.
- **Environments.** `pypi`, `npm` and `crates-io` accept deployments only from their tag
  pattern, so a job started from a branch or another tag cannot upload.
- **Tags.** The `release tags` ruleset lets only admins move or delete tags.
  Creating `go/v*` tags is also admin-only, because a Go release is the pushed
  tag itself, with no workflow in between.

## Other artifacts

- **Go:** an admin pushes `go/v<version>`. A bad release can only be withdrawn
  with a `retract` directive in a later version.
- **Conformance vectors:** run `vectors-release.yml`, which creates
  `vectors/v<version>`.

## Registry configuration

Each registry's trusted publisher names owner `action-state-group`, repository
`agent-action-capsule`, the publisher workflow file and its environment:

| Registry | Package | Workflow | Environment |
|---|---|---|---|
| PyPI | `agent-action-capsule` | `publish-python.yml` | `pypi` |
| npm | `@action-state-group/agent-action-capsule` | `publish-ts.yml` | `npm` |
| crates.io | `agent-action-capsule` | `publish-rust.yml` | `crates-io` |

A project owner configures it on the registry (PyPI: **Project → Settings →
Publishing**; npm: the package's **Settings → Trusted Publisher**, with
permission for direct `npm publish`; crates.io: the crate's **Settings →
Trusted Publishing**). crates.io offers Trusted Publishing only for a crate
that exists, so a crate's first version is published by hand by one of its
crates.io owners (`cargo publish -p <crate>` from `rust/` at the tagged
commit); every later version goes through the flow above. Renaming a publisher workflow breaks
publishing until the registry is updated first. No registry token is stored in
this repository: trusted publishing exchanges the workflow's OIDC identity for
a short-lived upload credential, and npm adds provenance automatically.
