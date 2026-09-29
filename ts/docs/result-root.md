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

## Recomputed, never asserted (2026-09-28)

The maintainer's adversarial review found that the headline values --
coverage, the bucket counts, and above all a close claim's state -- were
producer assertions nothing recomputed: a contested close relabelled
`AGREED` validated, and a producer's "not met: none" could hide a failure.
Four rules now stand, each pinned in `test/result-root.test.ts` and
`test/result-root-view.test.ts`:

**The buckets partition the claims exactly.** Every claim appears in
exactly one bucket, and the buckets carry exactly as many entries as there
are claims. A claim in no bucket (`aggregate.buckets: claim-2 (not_met)
appears in no bucket`), one in two, or an entry count that is not the
claim count is a finding from `validateEvidenceResult`, so the Result is
refused with that error and never rendered. This is what stops "not met:
none" over a `not_met` claim from reaching the page.

**Counts are recomputed from the claims.** `evaluated_population` and
`unknown_count` are recomputed (the claim count; the claims whose
sufficiency is `UNKNOWN`), as is each bucket's headline count (from the
claims' verdicts, never from the bucket lists' lengths). `recomputeCounts`
is a pure function of the document; `ResultRoot.coverage` and
`ResultRoot.bucketCounts` carry the recomputed values, `statedCoverage` the
producer's, and `countMismatches` every stated number the claims do not
bear out. The page draws the recomputed value; where the producer
disagreed a `count mismatch` marker (`data-count-mismatch=<field>`) sits
beside it, with the stated figure on the marker's `data-stated` attribute
and nowhere in the text a reader takes as the number. The one figure
carried as stated is `excluded_not_applicable`
(`data-excluded-basis="stated"`): requirements excluded as not applicable
are outside the evaluated population by construction and are never
claims, so the document holds nothing to recount them from. The bucket
headings read `met: 1` / `not met: none`, from the recomputed counts; a
bucket-count disagreement is unreachable through `buildResultRoot` (the
partition gate refuses it first) and is pinned on `recomputeCounts`
directly, so no loosening of the gate could ever draw the stated number.

**One headline document per root.** The root carries exactly one Result
v0, in one member. A root carrying one in both `agent_output` and
`agent_input`, or any other record in the bundle whose disclosed member
carries a Result v0 in either form, is an error from `buildResultRoot`
naming every carrier (`bundle carries 2 Result v0 documents: root <id> and
<id>; a bundle has exactly one headline document`). `isResultRoot` still
answers true for such a bundle -- the root does carry one -- so the
dispatch reaches the precise error rather than falling through to another
root family.

**A close claim's state is read from links, not from the claim.** A claim
of `type: "close"` with a readable `close` body (`close_state` in
`UNILATERAL | AGREED | CONTESTED`, `close_ref` a digest) is recognized and
modelled as `ResultClaim.close`. When the cited Close (`close_ref`) is a
record in this bundle, its state is recomputed from the `acknowledges` /
`rebuts` links other records make to it -- read from each record's
disclosed `agent_input` when that is an evidence-book record header
carrying `links[{type, target}]`; a withheld or mismatched member
contributes nothing. Any `rebuts` link makes it `CONTESTED`; otherwise any
`acknowledges` link makes it `AGREED`; neither leaves it `UNILATERAL`
(`deriveCloseState`; spec section 4.1). The page draws the recomputed
state (`data-close-state`, `data-close-derivation="recomputed"`); when it
differs from the Result's own a `state mismatch` marker sits beside it,
the asserted value on the marker's `data-asserted` attribute only -- a
Close relabelled `AGREED` over a `rebuts` link draws `CONTESTED`, never
`AGREED`. When the cited Close is not a record in this bundle the asserted
state is drawn under a `producer-asserted` marker, never bare. `AGREED`
carries no mark of its own: its label and the acknowledging peer's record
are the whole affordance. `peer_close_ref` is checked to be the record
carrying the link that makes the state (`peerRefMismatch`). The verdict
axis is the Close's own and is untouched by the state.
`test/testdata/result-root-close-bundle.json` carries an AGREED close over
an `acknowledges` link; the tests flip the link to `rebuts`, to `cites`,
and remove the Close from the bundle.

## A close-state mismatch fails the claim (2026-09-28, second pass)

The maintainer's second pass: "a close-state mismatch should fail the
claim, per #140's own normative text. Today it adds a marker and still
counts the claim under its stated verdict." It no longer does. When the
cited Close is in the bundle and the state its links read is not the state
the Result asserts, the claim is **failed** (`ResultClaim.failed`, with
`failure` saying why: `close_state mismatch: asserted AGREED, the cited
Close's links read CONTESTED`). A failed claim's `sufficiency` and
`verdict` are the producer's words and are never drawn as the claim's: on
the row and in the drill-down both cells read `failed`
(`data-verdict="failed"`, `data-sufficiency="failed"`, class
`claim-failed`), with the stated values on `data-stated-verdict` /
`data-stated-sufficiency` only, and the drill-down carries a `failed: …;
sufficiency and verdict withheld` note (`data-claim-failed`). The row and
the `state mismatch` marker stay.

The recomputed counts follow. `recomputeCounts(document, failed)` counts
a failed claim under `bucketCounts.failed` and under no verdict; it stays
in `evaluated_population` (the producer did evaluate it) and contributes
nothing to `unknown_count`. The page draws a fourth heading after the
producer's three, `failed: none` / `failed: 1` (`data-bucket-of="failed"`,
always drawn, with its own list when non-empty) -- the verifier's state,
not a verdict bucket. The producer's own listing of the claim stays under
whatever bucket it wrote, marked `· failed`, and its `buckets.met` of two
over one standing `met` claim reads as `met: 1 count mismatch` with the
stated two on the marker. A relabelled-AGREED close therefore never
contributes to `met`; `test/result-root.test.ts` and
`test/result-root-view.test.ts` pin the row, the drill-down, the headings
and the counts. Only a state mismatch fails a claim: a `peer_close_ref`
that is not the linking record is marked (`peerRefMismatch`), and a Close
absent from the bundle is `producer-asserted` -- neither is a failure,
since neither contradicts the state.

**On "not met: none".** A producer's empty `not_met` bucket over a
`not_met` claim is refused by the partition gate before anything renders
(`(i)` in both test files: no Result page, no rows). The `not met: 1`
display that recomputation would draw for such a document is therefore
covered by the unit test on `recomputeCounts` only
(`recomputeCounts: a producer 'not met: none' …`), not by a render test:
no render path reaches it, by design.

**Follow-ups, deliberately not in this PR** (each its own change):
grade-as-asserted (a claim's `grade` is still the producer's word;
`countersigned` is not checked against any countersignature in the
bundle); nested-field checks below the top level of a claim (the mirror is
open-world there); drill-down beyond `acted_on` (a cited record's other
citation purposes are not followed); `generated_at` as a date-time (checked
as a string); the CONTESTED-is-never-met rule from #140's second pass (a
recomputed CONTESTED with `verdict: met` is not itself a failure here yet);
M3: engine adapter from judged claims (EM-side). The counterparty rule is
mirrored as of the third pass -- see the next section.

## The counterparty is the named peer's book under a different key (2026-09-29, third pass)

Maintainer's third pass: _"neither book_id nor signer alone is enough,
since a producer can mint a second book or a second key equally easily."_
An `acknowledges` / `rebuts` link now makes a state only when the linking
record satisfies **all three** of:

1. its disclosed header's `book_id` is present and differs from the cited
   Close's `book_id`;
2. that `book_id` equals the claim's named `peer` (`close.peer`);
3. its signer differs from the Close's signer.

The signer is the record's **local Producer Envelope `key_id`** -- the
envelope field a composite capsule carries beside `signature`, excluded
from the capsule id (`draft-mih-scitt-agent-action-capsule-04`, "capsule_id";
`verify.ts` strips it before hashing). It is the only per-record signer the
bundle model exposes, and the same 64-hex form the countersignature stamp
keys on. #140's schema checker sees only record headers, so it enforces (1)
and (2); (3) lives here and in the CLI, where the signer is visible.

`counterpartyLinks(close, peer, inbound)` (`ts/src/result-root.ts`) splits
the inbound links into `links` (the counterparty ones the state is read
from) and `ignored` (each with a `reason`). A Close whose header names no
`book_id`, or whose record carries no `key_id`, takes no link at all: nothing
can be shown to be its counterparty, so it is UNILATERAL at best. A claim
that names no `peer` takes none either. `ResultClose` carries the Close's
own `bookId` / `keyId`, and every `CloseLink` its linker's.

So a **self-acknowledged** Close (the acknowledger from the Close's own
book), a **third-book** acknowledger (a different book that is not the
named peer), a **same-key** acknowledger (the peer's book, the Close's own
key), or an acknowledger **with no `key_id`** each reads UNILATERAL: the
state-mismatch marker is drawn, the ignored link is listed under "Links
ignored (not from the counterparty)" with its reason, and the claim
**fails** exactly as the relabelled-CONTESTED case does -- never a verified
AGREED. A `rebuts` from a non-counterparty makes no CONTESTED either. Until
the contract pins the peer's key, AGREED means "acknowledged by the named
peer's book under a different key", not "by an independent party".

Two more rules from #140's checker are mirrored in the same pass, each a
claim failure (`ResultClaim.failedOn` names the first rule that fired;
the row's `data-failed` and the drill-down note's `data-claim-failed`
carry it):

- **`evidence`** -- `close_ref` and, when present, `peer_close_ref` MUST be
  among the claim's own `evidence[]` digests. A claim reports only on a
  Close, and cites only a state-making record, that it puts in evidence.
  Judged first.
- **`close_state`** -- the asserted state differs from what the
  counterparty links read (as before; the failure text now names each
  ignored link and why).
- **`peer_close_ref`** -- the state is AGREED or CONTESTED by the
  counterparty links, but `peer_close_ref` is not the record carrying that
  link. Previously a marker only; now a failure, as in #140's checker.

The honest close bundle (`test/testdata/result-root-close-bundle.json`)
gives the airline's Close and the peer's Close distinct `key_id`s so that
it still reads AGREED under all three parts.

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
