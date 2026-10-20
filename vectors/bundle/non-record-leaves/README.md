# Evidence Bundle vectors: non-record leaves in a range

These vectors pin strict `verify_bundle` on Bundles whose range covers leaves
that are not records: padding records, carried in full in
`completeness_certificate.non_record_leaves`
(`draft-mih-zhang-agent-disclosure-bundle-02`, "Non-Record Leaves"). Everything
not described here is read exactly as in `../strict/README.md`: the case
format, the claims and their order, the verdict, and how to consume a case.

The log in every case has 64 leaves: 5 records, 27 padding records, 3
records, 29 padding records. That is the layout of a real log whose store pads
before every checkpoint with a bucket of 32, so the checkpoint tip (seq 64) is
a padding leaf. The records are signed by the producer key and the checkpoint
by the log key of `../strict/`. Each padding nonce is a fixed value derived
from a label, so the run is reproducible.

## The member

`non_record_leaves` is an array. Each element is `{"seq": <seq>, "content":
<object>}`. Members of an element other than these two are ignored.

The only non-record leaf type the -02 draft defines is padding. Padding
`content` has exactly four members:

```json
{"capsule_id": "<64 lowercase hex>", "record_type": "padding",
 "epistemic_type": "producer_claim", "store_nonce": "<64 lowercase hex>"}
```

`capsule_id` is the lowercase-hex SHA-256 of the JCS (RFC 8785) of the other
three members, and it is the leaf value: it must equal `body_digests[seq -
first_seq]`. A local-only producer envelope (`signature`, `key_id`) is not part
of the content. This is the serialization of `../../evidence-layer/padding/`.

## The rules

The member is part of per-record membership. Every seq of `[first_seq,
last_seq]` is accounted for by exactly one of: a record's membership entry; a
`non_record_leaves` element; or neither, which is
`membership_record_missing:<seq>`.

The elements are read in order. For each one:

1. Not an object: `non_record_leaf_element_invalid:<index>` (0-based index in
   the array).
2. `seq` is not a safe integer (a JSON integer, not a boolean, within
   ±(2^53 − 1), as in `../strict/`; `18.0` is not one), is outside
   `[first_seq, last_seq]`, is a seq that any `memberships` entry states in its
   `log_coordinates` (whatever else is wrong with that entry), or is the seq of
   an earlier element: `non_record_leaf_seq_invalid:<index>`. The element
   accounts for no seq.
3. Otherwise the element accounts for its `seq`, whatever follows. Then:
   - `content` is not an object, or its `record_type` is not a string
     (including an element that carries a digest in place of `content`):
     `non_record_leaf_malformed:<seq>`;
   - `record_type` is not `padding`: `non_record_leaf_type_unsupported:<seq>`;
   - the padding content does not have exactly the four members above,
     `epistemic_type` is not `producer_claim`, or `store_nonce` or `capsule_id`
     is not 64 lowercase hex characters: `non_record_leaf_malformed:<seq>`;
   - the recomputed `capsule_id` differs from the carried one or from
     `body_digests[seq - first_seq]`: `non_record_leaf_mismatch:<seq>`.

`non_record_leaves` that is not an array is `non_record_leaves_malformed`, and
then accounts for no seq.

The findings come in this order: the membership entries' findings as in
`../strict/`, then the `non_record_leaves` findings, then
`membership_record_missing:<seq>` in seq order, then
`membership_record_unbound:<id>`.

Every finding fails per-record membership except
`non_record_leaf_type_unsupported`. When that is the only kind of finding, the
claim is `withheld`, so the verdict is never `VALID`; when there is any other
finding, the claim fails and lists both kinds. Without a signed checkpoint, a
claim that did not fail is `withheld` with `checkpoint_unverified` appended, as
in `../strict/`.

A leaf of an undefined type is not checked beyond its `record_type`: its
content is not hashed against its body digest. So a party that changes a Bundle
can put such an element where a record or a padding leaf was, turning a
failure into `withheld` (`incomplete-unknown-type-in-place-of-record`). It can
never make the claim pass: the verdict is at best INCOMPLETE.

A producer-selected Bundle has no range, so a `non_record_leaves` member on
one, even an empty array, makes its certificate invalid:
`completeness_certificate_invalid`.

Interval coverage is unchanged: the range proof already binds every
`body_digests` entry, padding leaves included.

## Cases

| id | What it shows | verdict |
|---|---|---|
| `pos-padded-whole-log` | the whole log, [1, 64] | VALID |
| `pos-padded-suffix` | the suffix [6, 64], starting on a padding leaf | VALID |
| `neg-padding-nonce-edited` | seq 6's nonce edited, its `capsule_id` left | INVALID |
| `neg-padding-capsule-id-edited` | seq 23 recomputes to its body digest but carries another `capsule_id` | INVALID |
| `neg-padding-other-leaf` | seq 7 is a self-consistent padding record of another log | INVALID |
| `neg-padding-swapped` | the contents of seq 6 and 7 swapped | INVALID |
| `neg-padding-digest-only` | seq 8 carried as a digest, no content | INVALID |
| `neg-padding-extra-member` | seq 9 also carries `links: []` | INVALID |
| `neg-padding-envelope-left` | seq 10 still carries `signature` and `key_id` | INVALID |
| `neg-padding-epistemic-type` | seq 11 has `epistemic_type` `observed_event` | INVALID |
| `neg-padding-nonce-uppercase` | seq 12's nonce in uppercase | INVALID |
| `neg-padding-content-not-object` | seq 13's content is a string | INVALID |
| `neg-padding-seq-out-of-range` | seq 14's element says 65 | INVALID |
| `neg-padding-seq-repeated` | seq 15's element says 16, as does the next | INVALID |
| `neg-padding-seq-on-record` | seq 17's element says 3, a record's seq | INVALID |
| `neg-padding-seq-not-integer` | seq 18's element says `"18"` | INVALID |
| `neg-padding-omitted` | the tip's element left out | INVALID |
| `neg-non-record-leaves-not-array` | the member is an object | INVALID |
| `neg-non-record-leaf-element-not-object` | seq 19's element is the number 19 | INVALID |
| `incomplete-unknown-leaf-type` | seq 20 of an unknown `record_type`, everything else passes | INCOMPLETE |
| `neg-unknown-type-and-mismatch` | the unknown type and seq 21's nonce edited | INVALID |
| `neg-unknown-type-and-missing` | the unknown type and seq 22's element left out | INVALID |
| `incomplete-unknown-leaf-type-unsigned-checkpoint` | the unknown type with no `checkpoint.cose` | INCOMPLETE |
| `neg-non-record-leaves-on-producer-selected` | an empty member on a producer-selected Bundle | INVALID |
| `neg-padding-seq-on-invalid-membership` | seq 33's membership has a wrong `leaf_index`; a padding element also claims 33 | INVALID |
| `incomplete-unknown-type-in-place-of-record` | the record at seq 33 removed, an undefined type at seq 33 | INCOMPLETE |

## Regenerating

From the repository root, with `agent-action-capsule[bundle,envelope]`
installed:

```sh
python3 python/scripts/generate_bundle_02_vectors.py
```

It rewrites every file here except this README, byte for byte, and the files
of `../certificate-mode/`. Each expected result is written by hand in the
generator; the generator runs no verifier.
