# A sealed Result v0 as the bundle root

The report takes one input: a bundle whose root record is a sealed Evidence
Result v0. Not a bundle plus a Result file. This note says what that root
looks like, what the viewer reads from it, what it reads from the records it
cites, and the two rules the root adds. Module: `src/result-root.ts`; view:
`src/evidence-graph-view.ts`; fixture: `test/testdata/result-root-bundle.json`.

## The record

The bundle draft requires `root` to be the `capsule_id` of an unmodified
Capsule in `records`. A Result therefore reaches the root only sealed as a
capsule: one format-4 record whose disclosed member is the Result document
itself, committed by digest in `model_attestation.compute_attestation`
exactly as any other disclosed payload. The Result document is the one
`spec/evidence-result-v0.md` defines and `schemas/evidence-result-v0.json`
validates -- unchanged, unwrapped. It is recognised by its own discriminator,
`result_version: "evidence-result-v0"`; the schema closes the document
(`additionalProperties: false`), so no `spec_version` key is added to it and
no new family name is introduced here.

The member: the viewer consults `agent_output` first, then `agent_input`,
and takes the first disclosed value that names itself a Result. The fixture
carries it in `agent_input`, the member every other root family on main
uses. Which member a producer should use is an open question for the spec.

## Two carriers of the root

The disclosed member carries the Result in one of two forms, and the viewer
accepts both. **Payload form:** the member is the document itself,
recognised by `result_version` -- what a capsule sealed with the document
as its payload discloses (`AssembleBundle` on a mysql/sqlite profile;
`test/testdata/result-root-bundle.json`). **Book form:** the root is an
evidence-book record and the member is its record header (evidencebook
discloses headers under `agent_input`): `record_type: "evidence_result"`,
`links` of type `cites` naming the daily reports it rests on, and the Result
document verbatim under `statement` (`evidencebook.Book.Bundle` on a jsonl
profile, which is what `capsulectl result build` followed by
`bundle --disclose` produces; `test/testdata/result-root-book-bundle.json`).
A header of any other `record_type` is not a Result root. In book form the
`statement` is validated by the same structural mirror, and a finding is
rooted at `agent_input.statement` so the error names the statement. The
model records which form it read (`form: "payload" | "book"`); headlines,
buckets and claim rows are identical for the same Result in either form.
The header's `links` are the book's closure walk, not the bundle draft's
`references[]`; a book-form root need not carry `references[]` for the
viewer, whose claim-level resolution reads `records` by digest regardless.

The root capsule's `references[]` cite, `acted_on`, the records the claims
rest on, so the bundle's closure walk (`graphClosure`, `closure_depth`)
covers them. That walk is the verifier's, and unchanged; the claim-level
resolution below is a separate, second check.

## Citations

A claim's `evidence[]` is a list of `{digest_alg: "SHA-256", digest}`. A
`capsule_id` is a SHA-256 digest, so each entry names a record in this
bundle directly: the digest is looked up in `records` by `capsule_id`.
Daily reports, cases, and close records are all cited this way; the viewer
does not care which family a cited record belongs to. A cited record's own
`acted_on` references are followed in turn (a daily report to its acts), so
aggregate -> daily -> case -> act is a walk over citations.

`proofs[]` (`inclusion_proof` / `receipt`, by digest) are carried and shown
by digest. Nothing in the bundle draft says which bytes they digest, so the
viewer does not resolve them and says so on the row.

## What is read from where

From the root Result, and only from there: the coverage line
(`evaluated_population`, `excluded_not_applicable`, `unknown_count`), the
three buckets, and for every claim its `sufficiency`, `verdict`, `tier`,
`grade`, `type`, presentation carrier and status, and its cited digests.

From the cited records, and only from there: every drill-down -- the
record's provenance (capsule id, action time and seal time as written,
seal status, log coordinates), each committed member as disclosed or as
`withheld · <digest>`, and the records it cites in turn.

## The two rules the root adds

**Unsupported, never met, never dropped.** A claim whose cited ids do not
all resolve in `records` -- or that cites nothing -- is `unsupported`. Its
row stays, with its tier, grade and sufficiency; its verdict cell reads
`unsupported` (`data-verdict="unsupported"`, class `claim-unsupported`), and
the drill-down names the digests that did not resolve. The Result's stated
verdict is kept in the model and never drawn for such a claim. The bucket
the Result put the claim in still lists it, marked.

**Not a Result v0 is an error.** A root whose disclosed member is not a
Result v0, or names itself one and fails validation, raises
`EvidenceGraphError` from `buildResultRoot`. Validation is a structural
mirror of the schema, not a JSON Schema validation: the document's top
level is closed to the schema's five members (`result_version`,
`generated_at`, `claims`, `aggregate`, `view`); required members, closed
vocabularies and the sufficiency/verdict binding are checked on the objects
it mirrors (claims, carriers, digest and proof refs, `aggregate`, coverage,
buckets); plus the two cross-element rules spec section 4 assigns to a
verifier: unique claim ids, and bucket entries naming claims with that
verdict. Below the top level the mirror is open-world on additional keys;
`view` is not checked (nothing reads it; the page's chrome is the
bundle-level `presentation/v1`); `generated_at` is checked as a string, not
as a date-time. No JSON Schema validator is wired into `ts/`;
`test/result-root.test.ts` reads the schema file and keeps the mirror in
step. Unknown members on a claim are tolerated: a claim `type` this module
does not know renders as `unrecognized (<type>)` with its axes intact,
never dropped, so a later schema's claim types render rather than fail.

A `disclosure` carrier's own `evidence[]` is drawn in the claim's
drill-down under "Carrier evidence", one row per digest in the same shape as
any other citation (a supplied record opens on click; one not in this bundle
says so). It is shown, not judged: the verdict rests on the claim's
`evidence[]` alone.

## Render order

Verify first, as today. An unverified bundle draws the banner, the refusal
and the verification page, and no Result page. On a verified bundle the
Result page draws its heading, then the coverage line, then the three
buckets, then one row per claim; within the Result section no number
precedes coverage, and no percentage or single figure appears above the
rows. A cited record outside the checkpoint renders `uncheckpointed` in its
own provenance panel under the Result, its claim still supported
(`test/result-root-view.test.ts` seals `day-2` out of the log and asserts
this). Root families dispatch in order: `report/v1`, then a Result v0,
then the `evaluation-summary/v1` graph. The verification page is unchanged
and last.

One placement is inherited from main and left as is, flagged for the
maintainer: the verification banner's "N of M records uncheckpointed" is
bundle-level, drawn before every section, and so sits above the Result
section's coverage line whenever any record is uncheckpointed. It is the
one figure that precedes coverage on the rendered document; the Result
section itself carries none.

## Unchanged

Verify-before-render; the disclosure rules (a supplied value that does not
hash to its committed digest is never shown; withheld renders with the
digest); `uncheckpointed` status per record; times printed as given, zone
marked when not stated; the verification banner and page; the Go emitter,
which embeds bytes and knows no root family (`go/emitter` parity is pinned
on the committed sealed fixture from both sides).
