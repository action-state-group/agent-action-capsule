# Profile vectors — `nostr-pubkey` host-principal profile + first Buzz Evidence Contract profiles

**Status: subject shape ruled (2026-09-23); illustrative vectors, generated, two-language parity.**
Registry placement of the profile entries is still **unruled** (see `capsule-registry`'s
`drafts/a18-host-principal-and-buzz-profiles.md`, which quotes the ruling). These fixtures pin the
record *shape* the profiles name; they are not yet a conformance suite for any published schema.

## The ruling these vectors apply

> UNIFORM `semantic_digest`: the EvidenceRecord subject is `{event_id, semantic_digest}` for
> EVERY profile — NO per-profile digest names ([the three per-profile subject digest names used
> in earlier drafts] withdrawn). "What kind" is carried by the profile id + epistemic types,
> never the field name. Extra digested facts go as NAMED digests in the record BODY/epistemic
> payload, never by renaming the subject digest. Rationale: uniform neutral verify surface (one
> field for every profile/connector; no special-casing).

So every record here carries exactly `subject: {event_id, semantic_digest}`:

- `event_id` — the Buzz transport event id (a specific Nostr transmission; not recomputable from
  bytes).
- `semantic_digest` — the content identity of that event's payload (recomputable).

"What kind" of subject a record is about comes from `contract_ref` (the profile id) and
`epistemic_type`, never from a field name. Any further digested fact is a NAMED body digest in
`payload_commitments` (`{digest_alg, digest, role}`, `role` naming the fact) — never a second
`subject` field, and never `role: "semantic_digest"`.

## How they are generated

`python/scripts/generate_profile_vectors.py` (Python reference) writes every file in this
directory, including `manifest.json`:

```
cd python && python -m scripts.generate_profile_vectors
```

Every 64-hex value is `json_digest({"label": <label>})` over a labelled placeholder (this
repository's lowercase-hex SHA-256 of JCS), and each fixture lists its `digest_labels`
(`{path, label, prefix?}`) so any implementation can re-derive every value. Each fixture also
carries `expect: {valid, violations}` — the rule codes a checker must report.

Three suites assert the **same committed files**:

| Language | Test | Asserts |
|---|---|---|
| Python | `python/tests/test_profile_vectors.py` | committed files == generator output (byte-identical); every labelled digest re-derives; rule codes == `expect`; each negative passes once its documented rule is disabled (it fails for that reason only); no withdrawn per-profile digest name appears anywhere here |
| Go | `go/canonical/profile_vectors_test.go` | every labelled digest re-derives via `canonical.JSONDigest`; the same rule codes == `expect` |
| TypeScript | `ts/test/profile-vectors.test.ts` | every labelled digest re-derives via `jsonDigest`; the same rule codes == `expect` |

## Rules

| Code | A record violates it when |
|---|---|
| `subject_shape` | `subject` is not exactly `{event_id, semantic_digest}` with both values 64-hex |
| `event_id_as_digest` | the transport event id is reused as a digest — `subject.semantic_digest == subject.event_id`, or a body digest equals `subject.event_id` |
| `body_digest_named` | a `payload_commitments` entry has no `role`, an empty one, or reuses `semantic_digest` as its role |
| `message_text_present` | any field name marks free text (`text` / `message` / `content` / `body` as a `_`-delimited word) — records carry digests only |
| `score_present` | any field name marks a score (`score` / `rating` / `rank` as a `_`-delimited word) — no scores, no per-user history |

## Layout

```
manifest.json
buzz.agent-job/v1/
  positive-01.json
  negative-event-id-as-digest.json
buzz.moderation/v1/
  positive-semantic-judgment.json      # worked content-vs-decision vector (below)
  positive-human-report-review.json
  positive-obligation-reference.json
  negative-event-id-as-digest.json
  negative-message-text-present.json
  negative-score-field-present.json
buzz.release/v1/
  positive-01.json
  negative-event-id-as-digest.json
```

## `buzz.moderation/v1`: the worked content-vs-decision vector

A moderation record binds *what was moderated* and *what was decided about it*. In
`positive-semantic-judgment.json`:

- `subject.{event_id, semantic_digest}` identify the **moderation action event** — the same
  uniform subject every profile uses;
- `payload_commitments[0]` (`role: "moderated-content"`) is the digest of the moderated content —
  never the content itself;
- `payload_commitments[1]` (`role: "moderation-decision"`) is the digest of the decision
  (disposition + evaluator/calibration provenance).

Content and decision are two NAMED body digests, never subject fields. The three positives
(`semantic_judgment`, `human_report` review, `obligation_reference`) share that one subject;
a `buzz.moderation/v1` requirement needs the three together, not any single record. The
obligation reference cites DSA Art. 17 and Art. 24(5) — a citation, never a compliance
conclusion.

`buzz.release/v1`'s positive carries the release's approval record the same way: one NAMED body
digest (`role: "approval-record"`) beside the uniform subject.

## Negatives

Each negative is a minimal mutation of its profile's positive and fails exactly one rule:

| File(s) | Mutation | Rule |
|---|---|---|
| `*/negative-event-id-as-digest.json` (all three profiles) | `subject.semantic_digest` set equal to `subject.event_id` | `event_id_as_digest` |
| `buzz.moderation/v1/negative-message-text-present.json` | `judgment.moderated_text` added, carrying free text | `message_text_present` |
| `buzz.moderation/v1/negative-score-field-present.json` | `judgment.principal_trust_score` added, a numeric score | `score_present` |

## Still unruled (not decided by these vectors)

- `principal_ref_relay_hint` — the `nostr-pubkey` profile's optional relay-hint companion field
  is proposed, not ruled; the vectors carry it as an informational field only. Key control is
  never authority: a `principal_ref` says who signed, nothing about what the signer may do.
- `minimum_assurance` / `retention_check` values in the profile entries' evidence requirements are
  placeholders.
- Registry placement of the four entries.
