# vendored-registry

Cases for `check-vendored` (Python `python -m agent_action_capsule.registries
check-vendored`, Go `registries.CheckVendored`): does a vendored registry
value-set file still equal the named section of `spec/REGISTRY.md` at a pinned
agent-action-capsule ref?

- `cases.json`: each case gives the vendored file, the registry copy it is
  checked against (`registry`), the ref that copy is at (`registry_ref`), the pin
  passed as `--ref` (`ref`, or null for the file's own `source.registry_ref`),
  and the `expected` outcome: `ok`, the resolved `registry` and `section`, the
  `ref` checked, the `added` and `missing` values, and the `problems` codes.
- `REGISTRY.fixture.md`: §6, §10, §17 and §18 of spec/REGISTRY.md, frozen. §10
  holds two tables and a Provisional subsection.
- `registries.fixture.json`: the same fixture in the registries.json form.

A pass proves the copy equals the registry at the pinned ref, not that the pin
is current. Regenerate with
`python3 python/scripts/generate_vendored_registry_vectors.py`; the generator
fails if the reference disagrees with a hand-written expectation.
