# Registry conformance vectors

These cases check one property: every registry-governed value a Capsule carries
is registered on the axis that carries it. The registered sets are the ones in
`spec/REGISTRY.md`.

This is a check a **producer** runs on its own output, in its own CI. It is not
verification. A verifier MUST NOT reject a record solely because it carries an
unregistered value (`spec/REGISTRY.md`, "The never-reject invariant"). So a
wrong token passes sealing and passes verification, and only a conformance
check like this one reports it. Each `expected.json` records both results for
the same bytes: `conformant` (this check) and `verify_ok` (`verify()`). For
every negative except two, `verify_ok` is `true`.

## Fields and axes

| Capsule field | Registry (`spec/REGISTRY.md`) |
|---|---|
| `disposition.verdict_class` | §1 `verdict_class` |
| `disposition.decision` | §2 `disposition.decision` |
| `effect.type` | §3 `effect.type` |
| `effect.irreversibility_class` | §4 `irreversibility_class` |
| `effect.effect_attestation` | §5 `effect_attestation` |
| `chain.relation` | §6 `chain.relation` |
| `references[].citation_purpose` | §11 `citation_purpose` |
| `domain` | §8 `domain` |
| `provenance` | §9 `provenance` |
| `provenance_mode.mode` | §12 `provenance_mode` |

§13 to §18 (Evidence Bundle, Evidence Request and Evidence Layer
vocabularies) are not carried in these Capsule fields. They are still read as
"another axis" for the cross-axis case.

## Classification

Each present value gets one status:

- `registered`: in the registered set for the field's own axis.
- `legacy_alias`: a `chain.relation` token that §6 lists as a read-only legacy
  alias. `emit_instead` names the registered value producers emit.
- `cross_axis`: not registered on this axis, but registered on another one.
  `registered_on` names those axes.
- `private`: an `x-` prefixed `domain` value (§8). Not a failure.
- `unregistered`: none of the above, including a value that is not a string.

A record is `conformant` when every status is `registered` or `private`. An
absent field produces no finding.

A field is matched by its **path**, not by its string. `supersedes` is
registered both as a `chain.relation` value (§6) and as an Evidence Layer link
type (§18), and neither registration defines the other. A check that searched a
record for the string `supersedes` could pass on the wrong axis.

## Cases

Each `neg-<axis>-unregistered` case has a positive twin that differs only in
the one value under test: `pos-<axis>-registered`. Two are exceptions, and
their twin is `pos-all-fields-registered`. For `verdict_class`, every other
registered value conflicts with that Capsule's confirmed effect (Internet-Draft
§5.4.2). For `provenance_mode`, the other value, `backfilled`, requires four
more members. The cross-axis and
legacy-alias negatives are also single-value changes from
`pos-all-fields-registered`:

- `neg-disposition-decision-cross-axis-verdict-class`: `hitl_dispatched`,
  registered on `verdict_class` only, carried as a decision.
- `neg-chain-relation-cross-axis-link-type` and
  `neg-citation-purpose-cross-axis-link-type`: `cites`, a §18 link type.
- `neg-chain-relation-legacy-resolves` and `neg-chain-relation-legacy-sequence`:
  §6 legacy aliases.

Two negatives also fail `verify()`, for reasons that have nothing to do with
registries: `provenance_mode.mode` is a closed enum (§12), and a list in
`verdict_class` fails the type check.

## Files

- `vectors.json`: the case list.
- `<case>/input.json`: a sealed Capsule. Its `capsule_id` recomputes.
- `<case>/expected.json`: `conformant`, `findings` (one per present value:
  `path`, `axis`, `value`, `status`, plus `registered_on` or `emit_instead`)
  and `verify_ok`.
- `SHA256SUMS`: every file in this directory.

The reference implementation is
`python/agent_action_capsule/registry_conformance.py`; run it as
`python -m agent_action_capsule.registry_conformance FILE...` (exit 1 on any
non-conformant value). `python/scripts/generate_registry_conformance_vectors.py`
regenerates the cases.
