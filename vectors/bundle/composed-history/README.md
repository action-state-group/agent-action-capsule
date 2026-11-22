# Evidence Bundle `composed/v1` History member vectors

These vectors cover History members in the `composed/v1` extension
("History Members" in `draft-mih-zhang-agent-disclosure-bundle-03`). A
History is one party's derivation over its own evidence stream, as of one
coverage anchor, here a `standard_history/1` card. Each History is still
asked for and answered by its own Evidence Request: one request, one subject,
one artifact.

A History member is an `artifact` member with `form` `history`. Its body,
`history`, is the responder's signed response as received, here an
`evidence-interop/0` envelope over the card. Its `digest` is the SHA-256 of
the JCS of that object. `anchor_checkpoint` carries the History's anchor, a
CLL COSE checkpoint whose SHA-256 is the envelope's signed `anchor.digest`.
Its signed `timestamp` is the anchor time.

A `same_key` join ties a History to the member that carries its party's half
of a deal; it carries no `pointer`. It derives `agree` when the half's root
record carries a Producer Envelope that verifies under its `key_id` over the
recomputed Capsule ID, that `key_id` is the History's `responder`, and the
anchor time is not earlier than the record's `timestamp`. It derives
`unjoined` when the keys differ (`history_key_differs`) or the anchor
predates the deal (`history_anchor_predates_deal`). It is not derivable for
an unsigned or badly signed half, or one whose carried `capsule_id` is not
its recomputed Capsule ID (`half_signature_unverified`), a member
listed in `missing`, a body that did not verify as carried, a History
signature not verified, or no anchor time. A `same_key` agreement is always
`redundant, not corroborating`. Two History members are related only when
each agrees with its party's half and the two halves agree on
`pre_agreed_identifier`; each related pair is reported with those halves and
that join's `pointer` (`related_histories`), never because the Histories are
carried together.

The composed digest is computed as in `../composed/`, with each member's
`form` added to the digest input when the member carries it. Blocks without
History members keep their digests.

## Cases (`vectors.json`)

The two parties' halves (`half-a`, `half-b`) carry the deal id at the
exchange pointer of `../composed/` and join `pre_agreed_identifier` on it.
Half A is at minute 10, half B at minute 11. History A is anchored at minute
20 and History B at minute 21.

| id | what changes | expected |
|---|---|---|
| `history-staple` | nothing | `pass`; three joins `agree`; the two `same_key` pairs redundant; the deal pair corroborating; `related_histories` relates History A and B through the halves at the deal-id pointer |
| `history-key-differs` | History A signed by another key | `same_key` `unjoined` (`history_key_differs`); declared `agree` fails; not related |
| `history-anchored-before-deal` | History A anchored at minute 5 | `unjoined` (`history_anchor_predates_deal`); fails; not related |
| `history-anchored-at-deal-time` | History A anchored at minute 10 | `agree`: only an earlier anchor is unjoined |
| `history-anchor-not-carried` | no `anchor_checkpoint` | `same_key` `not_derivable` (`history_anchor_time_unknown`); `withheld` |
| `history-anchor-checkpoint-other` | History B's checkpoint on History A | `history_anchor_checkpoint_mismatch`; fails |
| `history-signature-invalid` | `issued_at` changed after signing | `history_signature_invalid`; fails; join `not_derivable` |
| `history-signature-unverified` | no deployment signature profile | each History `signature_unverified`; joins `not_derivable`; `withheld` |
| `history-request-digest-other` | History A's member names History B's request | `member_request_digest_mismatch`; fails; `same_key` `not_derivable` |
| `history-member-missing` | History A declared missing | same composed digest as `history-staple`; closure `withheld`; join `not_derivable` |
| `history-deal-unjoined` | half B carries another deal id | deal join `unjoined`; each `same_key` `agree`; the Histories are not related |
| `history-beside-refusal` | party B refused its half | History B's `same_key` derives `unjoined`; deal join `one_sided` |
| `malformed-history-in-deal-join` | a `pre_agreed_identifier` join names History A | malformed: `join_names_history_member` |
| `malformed-same-key-two-histories` | `same_key` between the two Histories | malformed: `same_key_members` |
| `malformed-same-key-with-compare` | `same_key` with `compare` | malformed: `same_key_shape` |
| `malformed-history-with-bundle` | History A also carries `bundle` | malformed: `body_outcome_conflict` |
| `history-half-unsigned` | half A carries party A's `key_id` but no `signature` | `same_key` `not_derivable` (`half_signature_unverified`); `withheld`; not related |
| `history-half-key-copied` | half A signed by another key, party A's key copied into `key_id` | `not_derivable` (`half_signature_unverified`), never `agree` |
| `history-listed-missing-carries-body` | History A listed in `missing` with its answer still carried | closure fails; `same_key` `not_derivable` |
| `history-body-changed` | an unsigned member added to History A's answer after its digest | digest does not reproduce (closure fails); `same_key` `not_derivable` |
| `history-halves-linked-other-basis` | different deals; halves also agree on `shared_artifact_digest` at `/spec_version` | each `same_key` `agree`; not related (only `pre_agreed_identifier` relates) |
| `history-related-through-a-shared-field` | different deals; halves agree on `pre_agreed_identifier` at `/spec_version` | related, reported with pointer `/spec_version`: the relation is only as strong as the pointer |
| `history-anchor-time-malformed` | History A's anchor signed with a non-RFC 3339 `timestamp` | `history_anchor_checkpoint_invalid`; fails |
| `history-anchor-time-offset` | History A's anchor signed with an RFC 3339 time with a numeric offset | `history_anchor_checkpoint_invalid`: only a UTC instant with `Z` is read |
| `history-anchor-signature-invalid` | History A's anchor matches the signed digest but its signature does not verify | `history_anchor_checkpoint_invalid`; fails |
| `history-half-empty-history` | party B's half is an empty-history Bundle | History B's `same_key` `unjoined`; deal join `one_sided` |
| `history-half-capsule-id-relabelled` | half A's carried `capsule_id` (and the Bundle's `root`) is not its recomputed Capsule ID | `same_key` `not_derivable` (`half_signature_unverified`): the signed record is not the one named |
| `history-half-response-other-request` | half A carries a `response` naming party B's request | `member_response_request_digest_mismatch`; fails; `same_key` `not_derivable` |
| `malformed-same-key-with-pointer` | `same_key` with `pointer` | malformed: `same_key_shape` |
| `malformed-form-on-refusal` | a refusal member with `form` `history` | malformed: `form` |

Each case names the options it is verified with. `history_signature`
`evidence-interop/0` is Ed25519 by `responder` over the JCS of the signed
envelope members present (`spec/interop-profile-v0.md` §6.2). A case without
it is verified with no deployment signature profile. The History's own
properties (the card against `artifact_digest`, the derivation's rules) are
its profile's, and these vectors do not check them.

## Regenerating

```bash
python3 python/scripts/generate_bundle_composed_history_vectors.py
```

The run is deterministic. All keys are test-only seeds derived from fixed
labels and listed in `vectors.json`; none is a production key. The generator
imports its building blocks from `generate_bundle_composed_vectors.py` and
needs the same dependencies.
