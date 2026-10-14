<!-- SPDX-License-Identifier: BSD-3-Clause -->
# Releasing `agent-action-capsule` to PyPI

Publishing is automated by `.github/workflows/publish-python.yml` via PyPI's **OIDC
Trusted Publishing** — no API token is stored in this repo. The workflow:

1. On any push to a `release` event, `workflow_dispatch`, or a pushed tag it
   builds the sdist + wheel from `python/` and runs `twine check` (the `build`
   job). This always runs and never uploads — it is the dry run.
2. Only when the trigger is a **published GitHub Release** whose tag starts
   with `v`, the `publish` job runs. Before uploading it runs
   `.github/check_python_release.py`, which fails the job unless the tag is
   exactly `v` + the `version` in `python/pyproject.toml` and the tagged
   commit is an ancestor of `origin/main`. It then requests a short-lived OIDC
   token via `id-token: write` and uploads through
   `pypa/gh-action-pypi-publish`.

## Tag namespace

The Python package owns bare `v<version>` tags (`v0.7.0`, or `v0.8.0rc1` for a
pre-release). Other artifacts in this repository use their own prefixes
(`go/v*`, `ts/v*`, `legacy-verify/*`), and a GitHub Release for one of those
tags never publishes to PyPI.

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
   tags* and add the tag rule `v*`, so the environment itself refuses a
   publish job from any other ref. Optionally add required reviewers on that
   environment for an extra gate before any publish job runs.

No secret or token needs to be added anywhere — Trusted Publishing exchanges
the workflow's OIDC identity for a one-time upload credential at publish time.

## Cutting a release

1. Bump `version` in `python/pyproject.toml` and merge it to `main`.
2. Tag that `main` commit `v<version>` and publish a GitHub Release for the
   tag. The `publish` job runs only for the `release: published` trigger, so a
   plain tag push or a manually run `workflow_dispatch` build the package but
   do not upload it. A tag that differs from the pyproject version, or a
   commit not on `main`, fails the guard before anything uploads.
3. Confirm the run's `publish` job succeeded and the new version is live at
   <https://pypi.org/project/agent-action-capsule/>.
