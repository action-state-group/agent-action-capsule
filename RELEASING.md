<!-- SPDX-License-Identifier: BSD-3-Clause -->
# Releasing

The Python package (PyPI) and the TypeScript package (npm) release the same
way. A release is a merged version bump: you choose the bump, review it as a
pull request, and merging it tags and publishes. The packages are listed in
[`.github/releases.json`](.github/releases.json), which
[`.github/release.py`](.github/release.py) reads.

| Package | Manifest | Tag | Publisher | Environment |
|---|---|---|---|---|
| `python` | `python/pyproject.toml` | `python/v<version>` | `publish-python.yml` | `pypi` (tag rule `python/v*`) |
| `ts` | `ts/package.json` and `ts/package-lock.json` | `ts/v<version>` | `publish-ts.yml` | `npm` (tag rule `ts/v*`) |

The prefix is only on the Git tag. The registry version stays plain (`0.8.0`).

## Cutting a release

1. **Prepare.** Run [Prepare release](https://github.com/action-state-group/agent-action-capsule/actions/workflows/prepare-release.yml)
   on `main`, choosing the package and `patch`, `minor` or `major`. It raises
   the version from the current one, commits the bump with a sign-off, and
   pushes `release/<package>-v<version>`.
2. **Review.** Open the pull request from the link in the run summary. Open it
   yourself: a pull request opened by the workflow would not start CI. Add the
   CHANGELOG entry for the release on the same branch if it is not in yet.
3. **Merge.** [Tag release](https://github.com/action-state-group/agent-action-capsule/actions/workflows/tag-release.yml) runs on the
   merge. For each package whose version changed it creates the tag and GitHub
   Release on the merge commit and dispatches the package's publisher on that
   tag.
4. **Publish.** The publisher checks that the tag is the package's prefix plus
   its manifest version and that the commit is on `main`, then uploads through
   OIDC trusted publishing from its environment. Confirm the run and the new
   version on the registry.

Bumping a version by hand in any pull request releases it the same way when it
merges.

If a publish fails after the tag exists, fix the cause and re-run the
publisher's failed run. `publish-ts.yml` skips a version npm already has, so a
re-run after a successful upload is harmless.

## Safeguards

- **Guard.** `release.py check` refuses a tag from another package, a version
  that differs from the manifest, and a commit that is not on `main`.
- **Environments.** `pypi` and `npm` accept deployments only from their tag
  pattern, so a job started from a branch or another tag cannot upload.
- **Tags.** The `release tags` ruleset lets only admins move or delete tags.
  Creating `go/v*` tags is also admin-only, because a Go release is the pushed
  tag itself, with no workflow in between.

## Other artifacts

- **Go:** an admin pushes `go/v<version>`. A bad release can only be withdrawn
  with a `retract` directive in a later version.
- **Conformance vectors:** run `vectors-release.yml`, which creates
  `vectors/v<version>`.

Registry configuration (trusted publishers and project owners) is described in
[`python/RELEASING.md`](python/RELEASING.md) for PyPI and in the
[TypeScript README](ts/README.md#release) for npm.
