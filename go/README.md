# Agent Action Capsule Go reference

These packages conform to the Python record-format authority in this
repository. They implement format-4 JCS and Capsule IDs, Class-1 and
`references[]` verification, the seven registries and disclosure eligibility
table, Producer Envelopes, and Disclosure Envelopes through DE-3.

The Go code does not own producer verbs, CLL, adapters, policy, or permalink
transport. It consumes the same-commit corpora under `../vectors/`; the
cross-language CI also verifies Python-, Go-, and TypeScript-sealed Capsules in
all three implementations.

`references[]` uses CPB typed digest references. For the registered
`agent-action-capsule`/`SHA-256` context, the digest is a Capsule ID and must
not duplicate `chain.parent_capsule_id`. Missing external targets are
informational and do not become chain failures. `log_coordinates` records a
location claim; Class 1 validates its shape but does not prove inclusion.

Run locally:

```sh
GOWORK=off gofmt -w .
GOWORK=off go mod tidy
GOWORK=off go vet ./...
GOWORK=off go test ./...
GOWORK=off go test -race ./...
GOWORK=off go run ./cmd/vector_runner/
```

## Evidence Bundles

`bundle.VerifyBundle` checks a Bundle's claims and `bundle.VerifyStrict` gives
the strict verdict (`VALID`, `INCOMPLETE` or `INVALID`).
`bundle.VerifyBundleForPage` reads a Bundle as the TypeScript page context
does (`bundle.VerifyBundle`, with a producer selection the strict checks do not
reject read through `bundle.VerifyStrict`, and one they call INVALID refused),
and `bundle.Verified` is the page's
verification gate on that result (`spec/verification-display-v0.md` section 1,
TypeScript `bundleVerified`). The presentation resolver that was `presentation/`
is now `github.com/action-state-group/capsule-viewer/go/presentation`.

`bundle.BuildEvidenceBundle(ctx, source, opts)` builds a Bundle from a
`ProofSource`: the log's signed COSE checkpoint, its leaves, records by
Capsule ID, and inclusion and range proofs in the Bundle's wire shape. It
holds no key, and it checks the result with `VerifyStrict` before returning
it, refusing anything that verifier calls INVALID.
`bundle.ProofSourceFromCLL(backend, records)` makes a `ProofSource` from a CLL
backend (`ScanEntries`, `LoadCLL`) and a `RecordSource`.

- `IntervalFrom: N` carries every record from seq N to the checkpoint tip, and
  none below N, with a range proof: the Bundle can read VALID. `N = 1` is the
  whole log.
- `NoRange: true` carries only the chosen records, each with its own
  inclusion proof, and states `completeness.selection: "producer-selected"`:
  nothing is claimed about the records between them, so it reads INCOMPLETE.

One of the two is required, so a caller never hands over the whole log by
omission. `ClosureDepth` is a `*int` whose nil is the draft's 2. A range over
a leaf that is not a record, a carried record below N and a record past the
checkpoint are refused by name. A missing citation or an unsigned record is
stated, not refused, and reads INCOMPLETE. `bundle.BuildUnprovenBundle` is
the form with no log proof, for Capsules that belong to no log.

## Standard history

`standardhistory.Check(card, policy, asOf, deals)` reports the six card
properties of the `standard_history/1` derivation (spec
`standard-history-v0.md` section 6) for a card's JSON octets, from whatever
the caller holds beside it: a property that needs a missing input is
`NOT_CHECKED`. `standardhistory.Derive` builds the card from the deal
entries. Both are at parity with the Python reference
`agent_action_capsule.standard_history`, and both run
`../vectors/standard-history-v0/`.

## Controller binding v0

`controllerbinding.Verify(record, times, opts)` checks one binding record
(spec `controller-binding-v0.md`, CB) as received, at the times asked about:
its form, both signatures over the one signing input, its window, the
revocation statements in `opts.Revocations`, and a revocation list a using
profile declared complete in `opts.RevocationList` (CB section 5.1). The
declaration goes in as the JSON object received; one that is not in its form
does not count, and the list's entries are still read. Take it only through
the using profile's own channel, never from the party presenting the evidence:
it is unsigned. It reports the CB section 6.1 properties, the claim type, the
two keys, what the binding proves and, with a list, `Report.RevocationList`: the
declaration's profile, asserting party and `as_of` as delivered, the list's
digest, whether the declaration counts and, when it does not, a `reason`.
`Report.AppliesTo(a, b)` says whether it applies to a pair (CB section 6.2),
and `controllerbinding.PairIndependence` gives the pair's
`issuer_independence` (CB section 7 item 4): `FAIL`, redundant, when a
binding applies, never `PASS`. The package ships no credential verifier,
trust anchors or accepted issuers. A `same_organization_credentialed`
credential is `NOT_CHECKED` unless the caller passes a verifier for its
method in `opts.CredentialVerifiers`, which holds the caller's own trust
policy. It runs `../vectors/controller-binding-v0/`.

`cross_language binding` is the same check on stdin and stdout. Stdin is one
JSON object: `binding` (the record's text as received), `at` (the times, in
the form `YYYY-MM-DDTHH:MM:SSZ`), and optionally `revocations` (statements'
text), `credential` (its text), `key` (a key the binding must name, such as
a node's evidence key) and `revocation_list`. That is an object with
`declaration` (the CB section 5.1 declaration, a JSON object), `list` (the
list's text as received) and optionally `evaluated_at` (the evaluation time;
the current time when absent). A declaration that is a JSON object but not in
its form is reported with `counts` false and a `reason`; only one that is not a
JSON object, or stdin that is not well formed (such as a duplicate member), is
exit 2. Stdout is the report as JSON with `applies`.

| Exit | Meaning |
|---|---|
| 0 | The binding applies: form, signatures and window `PASS` at every time, revocation not `FAIL`, and it names `key` when one is given |
| 1 | It does not apply: a property is `FAIL`, or it does not name `key` |
| 3 | It does not apply because its method is not implemented (signatures `NOT_CHECKED`) |
| 2 | Bad input, or a report that could not be written |

Exit 0 is not a trust verdict. It says that whoever held each key signed the
record. It does not say who controls either key. A binding that applies to a
pair makes the pair redundant, not corroborating.
Revocation is `FAIL` when a received statement revokes the binding, `PASS`
when a declared revocation list counts (CB section 5.1), and otherwise
`NOT_CHECKED` (CB-1). A `PASS` is the asserting party's statement that the list
was complete as of `as_of`, not the verifier's finding. Neither `PASS` nor a
declared list changes the exit code, and the credential never decides it.

## Evidence Result v0

`evidenceresult.Check(doc, records)` is the gate for an Evidence Result v0
document (`doc` as `evidenceresult.Decode` reads it), at parity with the
Python reference
`../schemas/check_evidence_result_examples.py`. It validates the document
against the embedded `evidence-result-v0.json`, a byte copy of
`../schemas/evidence-result-v0.json`, then runs the cross-element rules the
schema cannot express (spec `evidence-result-v0.md` sections 3, 4, 4.1 to 4.3
and 7.1). It returns the claims, each marked in force or later. `records` are
the record headers the close claims cite (`DecodeRecords`). A close claim
whose Close is not among them is refused, since its state is recomputed from
the records' links, never trusted. A calibration claim's cited records are read as given: pass the unwrapped judge records (`calibration-summary/v1`, `human-rating/v1`), not records wrapped in `agent_input`. Formats are annotations, as in the Python
reference: `generated_at` is held to RFC 3339 by the applicability rule when a
claim is dated. Schema patterns are read as ECMA-262, JSON Schema's dialect:
`\s` is Unicode whitespace and `$` matches only at the end of the text.

## Dataset plans and datasets

`evidenceplan.Run(plan, records)` runs a dataset plan (spec
`evidence-plan-ir-v0.md` section 5.1) over a book's committed record headers
and returns its rows in log order. `evidenceplan.Build` wraps them in the
dataset document of section 6.2, whose JSON digest is a Result's
`dataset_ref`. `evidenceplan.CheckDataset(plan, dataset, records)` refuses a
dataset that is not what the plan selects, with an `*evidenceplan.Error` whose
`Reason` is the one the Python reference (`../schemas/evidence_dataset.py`)
gives. Both run `../vectors/evidence-dataset/`. Values come from
`evidenceplan.Decode`; the schema is an embedded byte copy of
`../schemas/evidence-plan-ir-v0.json`.
