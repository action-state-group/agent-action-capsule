# Two bounded completeness examples

Proposed informative companion to interop-profile-v0.md Section 6.7. This note
adds no material kind, algorithm, registry entry or normative requirement. In
v0, `coverage_declaration_commitment` remains `NOT_CHECKED`.

## Suggested clarification

Completeness relative to the holder's declared live set and completeness
relative to an authenticated anchor are different results. Checking inclusion
of returned records and agreement with the declared count does not bind that
count, the interval endpoints or the complete stream set to the anchor. A
positive completeness result needs a supported method that checks those
bindings as well as the returned population. The verifier retains each
property's result and the exact scope; an unavailable check is not a failed
check and is not a successful check. Even a positive bounded result says
nothing about actions never recorded in the selected streams.

## Example A: omission with a self-consistent smaller count

The relying party has selected checkpoint K for stream S before receiving the
response. K commits to the three record occurrences R1, R2 and R3 at positions
0, 1 and 2. The requested selection is `all_records`, with `from = null`.
The holder answers with R1 and R2, supplies their valid inclusion evidence at
K, and declares S with `start = 0`, `count = 2`, and `checkpoint = K`.
Every answer uses `anchor.digest = K`, and `interval.to = K`.

Under v0's coverage checks, declaration form, anchor equality and population
count can all be `PASS`. The count agrees with the two supplied occurrences.
The declaration's commitment property is still `NOT_CHECKED`. This is not
verified completeness relative to K. Under Section 6.7.3, a requirement that
would otherwise be SATISFIED but depends on this completeness is UNKNOWN with
verdict `not_evaluable`. A verifier unable to interpret the requirement's
condition is already UNKNOWN under P-48.

If the holder instead declares `count = 3` but supplies only R1 and R2,
`coverage_declaration_population` fails. That simpler mismatch does not test
the commitment gap: the stronger negative example reduces the declared count
as well as the returned population while preserving K.

A later method that checks K's committed population must detect the omitted
occurrence or inconsistent opening. Merely recomputing a digest over R1 and R2
and comparing it with a new holder-selected checkpoint would change the task.

## Example B: full bounded opening under an explicitly defined later method

Use the same S, K and `all_records` selection. A proposed experiment supplies
R1, R2 and R3 and enough authenticated material to check all of the following:

- K is the checkpoint selected by the relying party, authenticated under its
  fixed key and log policy; its stream scope is exactly S, not an unchecked
  subset of a multi-stream commitment.
- The method fixes record encoding, leaf hashing, tree construction, positions
  and authenticated size. The opening covers exactly positions 0 through N-1,
  with N = 3, no omissions and no extra or duplicate occurrences. Equal content
  at distinct committed positions is not silently collapsed into one event.
- Reconstructing the commitment from those occurrences gives K's committed
  value. The live-set checkpoint, start and count agree with that opening.
- The ordinary applicable envelope and coverage checks are also performed;
  the positive result retains its method, interval, stream set and assumptions.

This is a possible initial full-disclosure experiment, not an implementation
provided by v0. It needs a separately specified material and verification
contract. Until that method is supported, v0 continues to report the commitment
property as `NOT_CHECKED`; adding this example does not turn it into `PASS`.
If a later implemented method satisfies the conditions, completeness can be
established for this bounded committed population. That only removes the
completeness gate: it does not by itself satisfy another contract condition.

Completeness here excludes a claim that K is the latest checkpoint, that no
other log branch exists, that every actual action was captured, or that any
reported business action executed. Each stronger claim needs its own basis.
An invalid opening, absent proof material, an unsupported method and a resource
limit remain distinct outcomes under the applicable verification vocabulary.
