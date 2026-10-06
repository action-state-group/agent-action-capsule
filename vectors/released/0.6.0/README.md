# Released v0.6.0 vectors, frozen

These are the exact bytes of fixtures that shipped in tag `v0.6.0` /
`go/v0.6.0` (commit `13a1f45`) and were later renamed or regenerated on main
by the EXAMPLE-ORG placeholder rename (#158, `6e7deff`). Released vectors are
never rewritten, so the shipped bytes are kept here, each under its original
repository-relative path.

They are not current fixtures. No schema checker, generator or vector runner
reads them, and they may fail the current schemas. The current fixtures live
at their usual paths (`vectors/evidence-result/`, `vectors/judge/`,
`schemas/examples/evidence-plan-ir-v0/`), with `pos-oo-*` renamed to
`pos-example-org-*`.

`SHA256SUMS` lists every file. `schemas/check_released_vectors.py` checks that
each file matches it, that no unlisted file is present, and that `SHA256SUMS`
itself matches a digest pinned in the script. CI runs it in the `schemas`
workflow. To check by hand:

```bash
cd vectors/released/0.6.0 && sha256sum --check SHA256SUMS
```

| Original path (in `v0.6.0`) | What happened on main |
|---|---|
| `vectors/evidence-result/pos-oo-claims-result.json` | renamed to `pos-example-org-claims-result.json` and regenerated |
| `vectors/evidence-result/neg-*.json` (5 files) | regenerated in place |
| `vectors/judge/*/pos-oo-*.json` (8 files) | renamed to `pos-example-org-*.json` and regenerated |
| `vectors/judge/*/neg-*.json` (8 files) | regenerated in place |
| `schemas/examples/evidence-plan-ir-v0/*.json` (9 files) | regenerated in place |

Files that main still carries byte-identical to `v0.6.0` are not copied here.
