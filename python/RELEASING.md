<!-- SPDX-License-Identifier: BSD-3-Clause -->
# Releasing `agent-action-capsule` to PyPI

The release steps are in the repository's [RELEASING.md](../RELEASING.md).
This page covers the PyPI side.

Publishing is automated by `.github/workflows/publish-python.yml` via PyPI's **OIDC
Trusted Publishing** — no API token is stored in this repo. The workflow:

1. On any push to a `release` event, `workflow_dispatch`, or a pushed tag it
   builds the sdist + wheel from `python/` and runs `twine check` (the `build`
   job). This always runs and never uploads — it is the dry run.
2. Only for a `python/v` tag does the `publish` job run: when
   `tag-release.yml` dispatches the workflow on the tag it created, or when a
   GitHub Release for such a tag is published. Before uploading it runs
   `.github/release.py check python`, which fails the job unless the tag is
   exactly `python/v` + the `version` in `python/pyproject.toml` and the tagged
   commit is an ancestor of `origin/main`. It then requests a short-lived OIDC
   token via `id-token: write` and uploads through
   `pypa/gh-action-pypi-publish`.

## Tag namespace

The Python package owns `python/v<version>` tags (`python/v0.8.0`, or
`python/v0.8.0rc1` for a pre-release). The prefix is only on the Git tag: the
PyPI version stays `0.8.0`. Other artifacts in this repository use their own
prefixes (`go/v*`, `ts/v*`, `vectors/v*`, `legacy-verify/*`), and a GitHub
Release for one of those tags never publishes to PyPI.

Python releases up to 0.7.0 were tagged bare `v<version>` (`v0.0.3` to
`v0.7.0`). Those tags stay as they are, but a new bare `v*` tag no longer
publishes.

## One-time PyPI configuration (a PyPI project Owner, not this workflow)

Before the first real publish, configure a Trusted Publisher on PyPI:

1. Log in to <https://pypi.org> as the `agent-action-capsule` project owner.
   - If the project does not exist on PyPI yet, use
     <https://pypi.org/manage/project/create-trusted-publisher/> to
     pre-register a publisher for a project name that doesn't exist yet
     ("pending publisher"); the first successful publish then claims it.
   - If the project already exists, go to
     **Project → Settings → Publishing** and add a new publisher there.
2. Fill in:
   | Field | Value |
   |---|---|
   | PyPI project name | `agent-action-capsule` |
   | Owner | `action-state-group` |
   | Repository name | `agent-action-capsule` |
   | Workflow filename | `publish-python.yml` |
   | Environment name | `pypi` |
3. In the GitHub repo, create an Actions **environment** named `pypi`
   (Settings → Environments) so `environment: pypi` in the workflow resolves.
   Under **Deployment branches and tags**, choose *Selected branches and
   tags* and add the tag rule `python/v*`, so the environment itself refuses a
   publish job from any other ref. Optionally add required reviewers on that
   environment for an extra gate before any publish job runs.

No secret or token needs to be added anywhere — Trusted Publishing exchanges
the workflow's OIDC identity for a one-time upload credential at publish time.

## Cutting a release

Follow [RELEASING.md](../RELEASING.md): run **Prepare release** for `python`,
merge the pull request it links, and confirm the dispatched
`publish-python.yml` run and the new version at
<https://pypi.org/project/agent-action-capsule/>.
