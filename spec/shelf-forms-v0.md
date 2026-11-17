# Shelf Log Forms: Book Fact, Stamp Proof and Record Push, v0

**Status.** Informational, pre-Internet-Draft, kept in this repository. It changes no
Internet-Draft and no other document here. It writes down, as a specification another
implementation can follow, the forms the evidencebook library already uses
(<https://github.com/action-state-group/evidencebook>, commit
`0cd482b577b5c052d70962b7733f9edeeda9248d`, cited as EBL), and nothing that library does not
do. Each rule names the EBL file it comes from; "design §n" is section n of EBL
`docs/design/461-shelf-facts.md`. Where EBL is silent, this document does not
decide: it lists the question under [Open points](#9-open-points) (SF-1, SF-2, ...). A
difference between this text and EBL at that commit is a defect of one of them, to be resolved
openly, never a second behavior.

This document defines four things:

- the **entry documents** of a shelf log after its format switch: the book fact, the journal
  fact, the stamp entry and the format-switch marker (§3);
- the **commitments and openings** a fact carries, and which audience may be handed which
  opening (§4);
- the **stamp proof**: one book fact, the book checkpoint it carries, its inclusion in the shelf
  log and the shelf checkpoint, with its JSON encoding and the order of the verifier's checks
  (§5);
- the **record push**: an abstract message carrying a record, a stamp proof or both, and the
  answers a receiver gives to each part (§6).

## Dependency boundary

**Owns:** the four entry document kinds and their members (§3), the commitment and opening form
and the audience table (§4), the stamp proof and its checks (§5), and the record push message and
its answers (§6).

**Uses unchanged:**

| Tag | Document | What this document takes from it |
|---|---|---|
| JCS | RFC 8785 | the canonical JSON form of every entry document, committed value and opening |
| AAC | `spec/draft-mih-scitt-agent-action-capsule-06.md` | the JSON value conventions for digest-bearing material: no floating-point values, and integers inside the IEEE-754 safe range (the paragraph that fixes `canonicalization_id: "jcs"`) |
| CLL | the Checkpointed Local Log (`draft-mih-scitt-checkpointed-local-log`), as EBL embeds it (`github.com/action-state-group/checkpointed-local-log/go` v0.4.0, EBL `go.mod`) | the log, its entries (32-byte ids), its signed COSE checkpoint statement (log id, MMR size, root, key id, time), and its MMR inclusion and consistency proofs and their verification |
| SHA | FIPS 180-4 | SHA-256 |
| B64 | RFC 4648 §4 | standard base64 with padding, for byte strings inside the stamp proof's JSON (§5.2) |

**Does not define:** the record format of any profile (EBL knows none; a profile reads its own
records, §6.1), any profile's status value (§4.2), the cadence and the tree roots a shelf log
held before its format switch, how a shelf stores what it holds, when a stamp is taken, the
handover a holder gives a reader of its whole shelf, how a count or card is computed from facts,
any transport, and the binding of the record push to a protocol (SF-1, `bindings/record-push-v0.md`).

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

- **Holder:** the party whose shelf it is. One checkpoint key signs the checkpoints of the
  holder's logs.
- **Book** and **book log:** a log of the holder's records about one matter, a CLL log with its
  own log id. A **host log** is a CLL log the holder keeps whose entries are not records.
- **Shelf log:** the one CLL log of the holder that commits, entry by entry, to the state of every
  book. A **shelf checkpoint** is a CLL checkpoint of the shelf log; a **book checkpoint** is a
  CLL checkpoint of a book log.
- **Entry document:** a JSON object whose canonical bytes the shelf log commits to (§3.1).
- **Fact:** an entry document stating one book's state at a stamp (§3.2, §3.3).
- **Stamp:** one batch of entries appended to the shelf log, ending with a stamp entry (§3.4).
- **Journal:** the holder's own book of private bookkeeping, one per shelf (design §3).
- **Size:** a CLL MMR size (the number of nodes), never a count of entries, unless a rule says
  "entries".
- **Hex:** lowercase hexadecimal. A **digest** is 64 hex characters, a SHA-256 value.
- **Matter:** what a record belongs to, as the receiver's profile names it (EBL `ReceivedRecord`
  `DealID`); this document gives it no other meaning.
- **Counted prefix:** for one sender and book log, the run of records the receiver holds from
  position `1` up with no gap and no fork (§6.2). A record in it is **counted**.
- **Coverage:** here, a received record being covered by an accepted stamp proof (§6.3). It is
  unrelated to the `coverage` of an Evidence Request, and to the **coverage start** of a shelf
  log (§3.6).

## 2. Overview

After its format switch, a holder's shelf log carries one fact for each book whose state changed
since that book's last fact, at each stamp. A fact shows the book's log id, size and checkpoint
digest, and hides two values behind salted commitments: what the holder holds from the other side
(the link value) and the profile's status of the book (the status value). An opening shows one
hidden value to an audience allowed to see it (§4).

A stamp proof lets a holder show one party that its shelf log carries a given fact under a signed
shelf checkpoint, without handing over the rest of the shelf (§5). A record push carries a
counterparty's signed record, a stamp proof, or both, to a receiver who stores what it may keep
and answers each part (§6).

## 3. Entry documents

### 3.1 Encoding and entry id

Every entry of the shelf log after the format-switch marker is the SHA-256 of one entry
document's canonical JSON [JCS]; the document's canonical bytes are kept beside the entry (EBL
`shelf_facts.go` `EntryID`; design §2.1). Entries before the marker are not entry documents and
are out of scope.

An entry document MUST be a JSON object with exactly the members its kind lists below, and no
other. Its numbers are integers in the AAC safe range; floating-point values are refused (EBL
`canonical.go`, AAC). A reader MUST refuse document bytes that are not exactly the canonical JSON
of the document they decode to: a duplicate member, an unknown member, a missing member or a
second spelling of a value changes the bytes (EBL `shelf_handover.go` `canonicalDocument`). A
reader MUST also refuse bytes that are not valid UTF-8 or that escape an unpaired UTF-16
surrogate (EBL `shelf_facts.go` `validJSONText`).

Every document carries `"v": 1` and a `kind`. The kinds are `book_fact`, `journal_fact`, `stamp`
and `format_switch` (EBL `shelf_facts.go` constants).

### 3.2 The book fact

```
{"v": 1, "kind": "book_fact", "profile": "<profile>", "book_id": "<digest>",
 "log_id": "<log id>", "size": <n>, "checkpoint_sha256": "<digest>",
 "prev_fact_size": <m>, "link_commitment": "<digest>", "status_commitment": "<digest>"}
```

(EBL `shelf_facts.go` `BookFact`, `newBookFact`; design §2.2.)

| Member | Value |
|---|---|
| `v` | `1` |
| `kind` | `"book_fact"` |
| `profile` | the profile whose status value the status commitment holds, a non-empty UTF-8 string. `"none"` names a book no profile describes, whose status value is `{}`. This document defines no other value. |
| `book_id` | a digest. For a book of records: the record id of the book's first record. For a host log: the CLL entry id of its first entry. A log with no entry has no `book_id` and no fact (design §2.2). |
| `log_id` | the book's CLL log id, a non-empty UTF-8 string |
| `size` | the book's MMR size at the checkpoint this fact carries |
| `checkpoint_sha256` | the SHA-256 of that checkpoint's COSE statement bytes, a digest |
| `prev_fact_size` | `size` of this book's previous fact; `0` for its first. `size` MUST NOT be below it. |
| `link_commitment` | the commitment to the link value (§4.1, §4.2) |
| `status_commitment` | the commitment to the status value (§4.1, §4.2) |

### 3.3 The journal fact

The journal's fact has the book fact's members, with these values (EBL `shelf_facts.go`
`newJournalFact`; design §2.2):

| Member | Value |
|---|---|
| `kind` | `"journal_fact"` |
| `profile` | `"none"` |
| `book_id` | the SHA-256 of the journal's log id (its UTF-8 bytes) |
| `log_id` | the journal's log id |
| `size`, `prev_fact_size` | `0` in the clear |
| `checkpoint_sha256` | `""` in the clear |
| `link_commitment` | the commitment to `{"last_received": null, "checked_over": []}` |
| `status_commitment` | the commitment to `{"size": <n>, "checkpoint_sha256": "<digest>", "prev_fact_size": <m>}`, the journal's true values, with `size` not below `prev_fact_size` |

A journal fact shows a reader of the whole shelf that the journal changed at a stamp, and never
its size (design §2.2).

### 3.4 The stamp entry

```
{"v": 1, "kind": "stamp", "stamp": <n>, "facts": <count>}
```

`stamp` is the stamp's number and `facts` the number of facts the stamp appended before this
entry. Stamps are numbered after the ticks of the format before the switch: the switch's own
stamp is `last_tick + 1` (§3.5), each later stamp is the previous one's number plus one, and a
stamp finished after a crash keeps the number its stored batch has (EBL `shelf_stamp.go`
`Migrate`, `stampLocked`) (EBL `shelf_facts.go` `StampEntry`; `shelf_stamp.go` `buildStampLocked`). Every stamp ends
with one stamp entry, so the shelf log grows, and a new shelf checkpoint is cut, at every stamp,
including a stamp with no fact (design §2.5).

### 3.5 The format-switch marker

```
{"v": 1, "kind": "format_switch", "format": "book_facts/1", "last_tick": <n>,
 "logs": [{"log_id": "<log id>", "size": <n>}, ...]}
```

(EBL `shelf_facts.go` `FormatSwitch`, `newFormatSwitch`; design §4 step 3.) A shelf log carries
one marker, its first entry document. `last_tick` is the number of the last tick of the format
before it. `logs` lists every log the shelf's cadence lists at the switch, empty logs included, each once, sorted
by log id in the byte order of its UTF-8, each with its MMR size at the switch (`0` for a log
with no entry; EBL `shelf_stamp.go`, where the size listed is the log's MMR size). A `log_id`
MUST be non-empty and MUST NOT be listed twice.

### 3.6 Order of entries

A stamp appends, in this order: one fact for each book whose state changed, in `book_id` order
(EBL breaks a tie by `log_id`: `shelf_stamp.go` `buildStampLocked`), the journal's fact among
them by its `book_id`; then one stamp entry (design §2.5). The switch appends the marker, then a
first fact (`prev_fact_size` `0`, profile `"none"` for a host log) for every listed log with an
entry, in the same order, then a stamp entry; that stamp's shelf checkpoint is the **coverage
start** (design §4 steps 3 and 4).

When a book gets a fact is the holder's write rule (design §2.4), not a property of the forms:
a verifier of one fact or one stamp proof cannot judge it.

## 4. Commitments and openings

### 4.1 Commitment and opening

A commitment is

```
hex(SHA-256(salt || JCS(value)))
```

where `salt` is 32 bytes drawn fresh for each commitment of each fact, and `value` is a JSON value
(EBL `shelf_facts.go` `commit`; design §2.2). Within one fact the link salt is drawn before the
status salt (EBL `commitBoth`).

An **opening** shows one committed value:

```
{"salt": "<64 hex>", "value": <the committed JSON value>}
```

A verifier of an opening against a commitment MUST check, in this order, that `salt` is 32 bytes
written as 64 lowercase hex characters; that `value` is valid JSON text with no unpaired
surrogate escape, nested no deeper than 128 levels (AAC's canonical JSON limit, `canonical`
`MaxNestingDepth`, where `[]` is one level); and that `hex(SHA-256(salt || JCS(value)))` equals the commitment (EBL
`shelf_facts.go` `FactOpening.Verify`). An opening that fails any of these is refused.

Because each commitment has its own fresh salt, two facts with the same value carry different
commitments: values are compared, never commitments (design §2.4).

### 4.2 The committed values

- **Link value** (EBL `LinkValue`, `linkValue`):

  ```
  {"last_received": {"log_id": "<log id>", "size": <n>, "record_digest": "<digest>"} | null,
   "checked_over": ["<digest>", ...]}
  ```

  `last_received` names the last record the holder holds from the other side of the book, by
  its log id, the size of that log at it (at least `1`) and its digest, or is `null`.
  `checked_over` lists the digests of the records the holder's recomputed checks ran over,
  sorted, each once. A host log's link value, and the journal's, is
  `{"last_received": null, "checked_over": []}`.
- **Status value** (EBL `statusValue`): a JSON object, the profile's; `{}` for profile `"none"`.
  `null`, an array or any other non-object is refused. EBL commits to it and does not interpret
  it.
- **Journal status value:** as §3.3.

### 4.3 Audiences

A holder hands a party only the openings that party's audience may have (EBL `shelf_facts.go`
`OpeningsFor`; `shelf_stamp.go` `Openings`, which hands a book's facts with their openings by
audience, and `Cadence.StampProof`, which puts a status opening in a stamp proof (§5.1); design
§2.2):

| Audience | Book fact: link opening | Book fact: status opening | Journal fact: both openings |
|---|---|---|---|
| `counterparty` (the other side of the book) | yes | yes | no |
| `adjudicator` (the adjudicator the book's agreement names) | yes | no | no |
| `asker` (an asker the holder lets see that book) | yes | no | no |
| `chosen_reader` (a reader the holder chooses, such as a reader handed the whole shelf) | no | yes | no |
| `auditor` (an auditor the holder appoints; EBL's current rule, design §2.2, not ruled: SF-9) | no | no | yes |
| `owner` (the holder itself) | yes | yes | yes |

The fact documents themselves are not hidden: every audience may be handed the facts, each with
only the openings this table allows.

## 5. The stamp proof

### 5.1 Members

A stamp proof shows that a holder's shelf log carries one book fact under a signed shelf
checkpoint (EBL `shelf_stamp_proof.go` `StampProof`):

| Member | Content |
|---|---|
| `fact` | the book fact's canonical JSON bytes (§3.2) |
| `status_opening` | OPTIONAL. The fact's status opening (§4.1), present only when the audience the proof is made for may have it (§4.3) |
| `book_checkpoint` | the COSE statement bytes of the book checkpoint the fact carries |
| `inclusion` | the fact entry's CLL inclusion evidence in the shelf log under `shelf_checkpoint` (§5.2) |
| `shelf_checkpoint` | the COSE statement bytes of the shelf checkpoint |

A stamp proof never carries a link opening, and a journal fact is proved to nobody (EBL
`Cadence.StampProof`). The holder's builder takes the book's latest fact at or before a finished
stamp; the verifier does not depend on which stamp (§5.3).

### 5.2 JSON encoding

(EBL `testdata/shelf/receive/README.md`, "Stamp proofs"; the Go, Rust and Python encodings in
EBL agree.)

| Member | Encoding |
|---|---|
| `fact` | the fact's bytes in standard base64 with padding [B64] |
| `status_opening` | `{"salt": "<hex>", "value": <JSON value>}`; the member is absent when not given |
| `book_checkpoint`, `shelf_checkpoint` | the statement bytes in standard base64 with padding [B64] |
| `inclusion` | `{"kind": "cll-mmr-inclusion", "seq": <the fact entry's position, from 1>, "proof": {"v": 1, "kind": "inclusion", "size": <shelf MMR size>, "leaf_index": <seq - 1>, "witness": ["<digest>", ...], "peaks_left": ["<digest>", ...], "peaks_right": ["<digest>", ...]}}` |

EBL's readers ignore a member they do not know and read an absent or `null` member as its zero
value (empty bytes, an empty list, `0`, no opening), and then run §5.3 on what they read. Whether
the proof then fails depends on the member: an unknown member, or a `null` `status_opening`,
leaves a proof that otherwise passes still passing (EBL Python `StampProof.from_value`; SF-4).

### 5.3 Verification

A verifier MUST run these checks in this order, and MUST refuse the proof at the first that fails
(EBL `shelf_stamp_proof.go` `VerifyStampProof`):

1. `book_checkpoint` parses as a CLL checkpoint statement, its signature verifies, and its MMR
   size is the size of a complete MMR.
2. `shelf_checkpoint` passes the same checks.
3. Both checkpoints name the same signing key id. That key is the proof's key.
4. `fact` is valid UTF-8 JSON text with no unpaired surrogate escape, and is exactly the canonical
   JSON of a document with the book fact's members (§3.1).
5. The fact's `v` is `1` and its `kind` is `book_fact`.
6. The fact's `log_id` is the book checkpoint's log id, and its `size` is the book checkpoint's
   MMR size.
7. The SHA-256 of the `book_checkpoint` bytes is the fact's `checkpoint_sha256`.
8. If `status_opening` is present, it verifies against the fact's `status_commitment` (§4.1).
9. `inclusion.kind` is `cll-mmr-inclusion`, and `inclusion.seq` is at least `1` and at most the
   number of entries the shelf checkpoint covers.
10. Every digest in `inclusion.proof` (`witness`, `peaks_left`, `peaks_right`) and the shelf
    checkpoint's root are 64 lowercase hex characters.
11. The CLL MMR inclusion of the entry `SHA-256(fact)` at leaf index `inclusion.seq - 1` verifies
    against the shelf checkpoint's root and MMR size [CLL]; in particular `proof.v` is `1`,
    `proof.kind` is `inclusion`, `proof.size` is the shelf checkpoint's MMR size and
    `proof.leaf_index` is `inclusion.seq - 1` (CLL Go `mmr.VerifyInclusion`, v0.4.0).

A proof that passes shows the fact, the book checkpoint, the shelf checkpoint and the proof's key.
It shows nothing about the records the receiver holds, and a proof that passes is not yet
coverage of any record: comparing the book checkpoint with the records is the receiver's step
(§6.3). EBL does not check that the shelf checkpoint's log is the holder's
shelf log beyond the shared key (SF-5).

## 6. The record push

### 6.1 The message

A record push carries:

- `record`: OPTIONAL. One record's bytes, signed by its sender, in the format of a profile the
  receiver knows;
- `stamp_proof`: OPTIONAL. One stamp proof (§5).

At least one of the two MUST be present; a push with neither is refused as `invalid` (EBL
`shelf_receive.go` `Receive`). Having no part to answer, a binding carries it as its protocol's
invalid-params error (`bindings/record-push-v0.md` §2.3 rule 3). A receiver handles the record
part first and then the proof part, each on its own: the answer to one part does not depend on
the other, so a record sent again with a proof it lacked the first time still delivers the proof
(design §3).

This document does not define a record format. A receiver reads a record through its profile,
which checks the record's signature and gives, for the record (EBL `ReceiveProfile.Read`,
`ReceivedRecord`): its digest (its entry in its sender's book log, a digest); the sender's key;
the book log id and the position in it (from `1` to `2^63 - 1`); the digest of the record at the position before
it (empty exactly at position `1`); the matter the record belongs to; and whether it is an
unsolicited offer, a record that belongs to no book the receiver holds.

### 6.2 The record part

A receiver handles the record in this order (EBL `shelf_receive.go` `receiveRecord`,
`receiveRecordTx`):

1. A record over the receiver's size bound is refused `over_limit` (EBL default 1 MiB).
2. A record the profile cannot read, or whose signature fails, is refused `invalid`; so is one
   whose fields break §6.1 (no sender, log or matter; position `0` or past `2^63 - 1`; a
   predecessor named at position `1`, or none after it).
3. A record the receiver held once and deleted under its retention is answered `deleted`: it is
   not stored again.
4. A record already held is answered `duplicate`, with whether it is counted, and is not stored
   again. Other bytes under a held record's digest are refused `invalid`.
5. A sender the push rule does not admit is refused `refused`, and nothing is stored. The push
   rule is EBL's current rule (design §3, EBL `ReceiveProfile.Admit`), not ruled (SF-6): an
   offer may come from any key; any other record only from a key a book on the shelf names as its
   counterparty or adjudicator, a key whose offer the holder answered, or a key to which an offer
   in the holder's journal was sent. Holding someone's offer grants nothing.
6. An offer over the offer byte bound is refused `over_limit`. For an offer, the receiver then
   plans the room it needs under the offer bounds (per sender and in total, in count and bytes):
   the oldest offers are to be dropped first, except one the holder has answered, which is to
   leave the bounds instead (EBL defaults: 16 offers and 4 MiB per sender, 1024 offers and 64 MiB
   in total). Nothing is dropped yet. If the holder's books keep changing while the
   plan is made, the offer is refused `busy`, and sending it again later may succeed (EBL
   `planOfferRoom`, `ErrBusy`).
7. In one write, before anything is dropped: a record past the per-book count bound (EBL default
   100000 records held from one sender and log) is refused `over_limit`, and the planned drops
   are not made. Otherwise the planned drops are made, and
8. the record is stored, in the same write. If it contradicts a record held, or a position a
   deleted record held, it forks (§6.4). (EBL `receiveRecordTx`.)

**The counted prefix.** For each sender and book log, the receiver counts records from position
`1` up: a record counts while it is the only record held at its position and no position at or
before it holds a conflict. A held record claims its own digest at its position and its
predecessor's digest at the position before; a position with two different claimed digests is a
fork, and the counted prefix ends before the lowest such position for good (EBL
`receivedPrefix`; design §3), with one exception: a fork in a log of offers alone (§6.4) that
is past the offer evidence bounds is not recorded, so it ends the counted prefix only while both
its records are held. When a gap is filled, the stored records after it join the counted
prefix up to the next gap or fork.

### 6.3 The proof part

A receiver handles the stamp proof in this order (EBL `shelf_stamp_proof.go` `receiveProof`):

1. A proof that fails §5.3 is refused `invalid`.
2. The receiver relates the proof's key and the fact's log id to a sender whose records it holds,
   and asks whether that sender may push a proof now (EBL `ReceiveProfile.ProofSender`). A sender
   that may not is refused `refused`.
3. A proof whose book checkpoint has another root than a book checkpoint already held from that
   sender for the same log at the same size is refused `invalid`, and the two checkpoints are kept
   as evidence (§6.4).
4. If the sender's counted prefix in that log (§6.2) reaches the book checkpoint's number of
   entries, a proof whose root the counted records up to it do not recompute is refused
   `invalid`, and the checkpoint is kept as evidence with the digests it was recomputed over.
5. A proof whose book checkpoint, at that size, is already held under the same shelf checkpoint
   (by the SHA-256 of its bytes) is answered `duplicate`.
6. Otherwise the proof is `accepted` and kept, beside any proof of the same book checkpoint under
   another shelf checkpoint.

An accepted proof grants coverage to the records it covers only once the counted records reach
its size and recompute its root; one past the records held is kept, and checked when they arrive
(design §3).

### 6.4 Forks and contradictions

A receiver keeps, as evidence, the first conflict it finds at each position or size (EBL
`shelf_receive.go` evidence kinds; design §3):

| Kind | What is kept |
|---|---|
| `fork` | two records the sender signed at one position, or a record naming a predecessor other than the one held: the record held first and the other one |
| `checkpoint` | two book checkpoints the sender signed for one log at one size with different roots: the one held and the other |
| `checkpoint_records` | a book checkpoint whose root the records held do not recompute, and the digests it was recomputed over |

A fork is kept even when a record involved is later deleted; another record arriving at a
deleted record's position forks there. The one exception is what unsolicited offers leave
behind, since an offer belongs to no matter: the position of each dropped offer, and a `fork`
found when an offer arrives in a **log of offers alone** (one where the sender's log holds no
record that is not an offer, and no position a deleted such record held). These are bounded per
sender and in total (EBL defaults 16 and 1024 rows, `ReceiveBounds.MaxOfferEvidencePerSender`,
`MaxOfferEvidence`); past the bound nothing is kept, and such a position may later be forgotten
(EBL `receiveRecordTx`, `noteConflict`, `vacate`). A `fork` in any other log, and every
`checkpoint` and `checkpoint_records` conflict, is kept whatever the bounds.

### 6.5 The answers

Each part present in a push gets one answer (EBL `RecordOutcome`, `ProofOutcome`; the member
names are those of EBL's vectors, `testdata/shelf/receive/script.json`, `expect`). A record's
answer also carries `digest`, the record's digest, once the profile has read the record and its
fields pass §6.1 (§6.2 step 2): every answer from step 3 on carries it, a refusal at step 1 or 2
does not (EBL `receiveRecord`).

| Part | Answer | Members | Meaning |
|---|---|---|---|
| record | duplicate | `duplicate: true`, `counted` | already held; acknowledged and not stored again |
| record | deleted | `deleted: true` | held once and deleted under the receiver's retention; acknowledged and not stored again |
| record | stored | `stored: true`, `counted: true` | stored, and within the sender's counted prefix |
| record | stored, not counted | `stored: true`, `counted: false`, `ask_for_book: true` | stored past a gap or at a fork; the receiver asks the sender for its book |
| record | refused | `refused: <class>` | nothing of it stored; class `invalid`, `refused`, `over_limit` or `busy` |
| proof | accepted | `accepted: true` | kept (§6.3 step 6) |
| proof | duplicate | `duplicate: true` | already held; acknowledged and not stored again |
| proof | refused | `refused: <class>` | class `invalid` or `refused`; for a contradiction (§6.3 steps 3 and 4) its evidence is kept |

A held record that is not counted is answered with `ask_for_book: true` too, duplicate or not
(EBL `receiveRecord`). A record that forks is answered as stored and not counted: "stored" does
not mean accepted as the sender's one record at that position, and the record answer carries no
member that says it forked (SF-3). EBL returns a part's refusal class also as
the call's error, joined over the parts.

**What the receiver learns.** Beside the answers, EBL returns to the receiver's own profile the
matters each push changed: those with records that entered (`grew`) or left (`shrank`) a counted
prefix, those with new evidence of a fork or contradicting checkpoint (`forked`), and those whose
records gained coverage (`covered`), each list sorted (EBL `ReceiveChanges`). These are the
receiver's, for recomputing its own state; this document does not put them in an answer.

### 6.6 Bounds and retention

The receiver's bounds are its own settings (EBL `ReceiveBounds`, `DefaultReceiveBounds`). How
long received records are kept is the holder's setting, by default the life of the shelf (design
§3). Nothing of a matter is deleted before the matter is settled: every row of it agreed,
uncontested, or ruled with its remedy done; a matter that is open or contested keeps everything.
Whether a matter is settled is the receiver's profile's to compute, and a profile MUST NOT report
a matter settled that does not meet that condition (EBL `Forget` takes the profile's answer). A
deleted record leaves a tombstone holding its digest, its sender, when it was received and when
it was deleted, and nothing else of it; a record so deleted is reported deleted, not missing,
when pushed again (§6.5) and wherever it is cited. An offer dropped to make room was never part
of a matter and leaves no tombstone.

## 7. Bindings

This document defines the record push as an abstract message and its answers. EBL defines no
transport for it: its design leaves the MCP and A2A entries for the push and the stamp proof to
follow this document (design §1 and §5). Their binding is a separate document,
[`bindings/record-push-v0.md`](bindings/record-push-v0.md), which carries §6 over MCP and A2A
and changes nothing here (SF-1).

## 8. Security and privacy considerations

- **What a fact shows.** A fact shows a book's log id, size and checkpoint digest, and when they
  changed. A reader of the whole shelf learns how many books the holder has and how often each
  changes. A journal fact shows when the journal changed, never its size (§3.3).
- **What a commitment hides.** Each commitment has its own fresh 32-byte salt (§4.1), so a reader
  without the opening cannot test a guessed value, and cannot tell two facts with the same value
  apart from two with different values.
- **Openings by audience.** A holder that hands an opening outside §4.3 discloses what this
  document keeps from that party. A stamp proof never carries a link opening (§5.1).
- **Proof key.** A stamp proof binds the fact, the book checkpoint and the shelf checkpoint by one
  signing key (§5.3 step 3). Which key a receiver accepts for which sender is the receiver's
  profile's (§6.3 step 2).
- **Unsolicited pushes.** A receiver bounds what it stores (§6.2 steps 1, 6 and 7), and what
  unsolicited offers leave behind (§6.4). A duplicate
  or deleted record is answered before the push rule runs, so a party that has a record's bytes
  can learn from the answer whether the receiver holds or held it (§6.2 steps 3 and 4, SF-6).
- **Forks.** Evidence is kept once per position or size (§6.4): repeating a fork at a position
  already noted adds none.

## 9. Open points

| # | Point |
|---|---|
| SF-1 | The binding of the record push and the stamp proof to MCP and to A2A: method or skill names, how a record's bytes are carried, and how the answers of §6.5 are carried. EBL has no binding; its design places these entries after this document. Drafted in [`bindings/record-push-v0.md`](bindings/record-push-v0.md), which leaves SF-2 to SF-9 open. |
| SF-2 | Naming the missing positions in a stored-not-counted answer. EBL answers `ask_for_book` (the whole book), with no positions; the counted prefix's size (EBL `Shelf.CountedPrefix`) would let a receiver name the first missing position, but no answer carries it. |
| SF-3 | Telling the sender that its record forked. EBL's record answer has no fork member; the fork appears only in the receiver's own changes (`forked`) and evidence (§6.4). |
| SF-4 | Strictness of the stamp proof's JSON (§5.2): EBL ignores unknown members and reads absent or `null` members as their zero values before §5.3, so some such proofs still pass. Whether a wire form refuses unknown or `null` members outright is not decided. |
| SF-5 | Binding the shelf checkpoint to the holder's shelf log: §5.3 checks only that one key signed both checkpoints, not which log the shelf checkpoint is of. A receiver's profile relates the key and book log to a sender (§6.3 step 2); EBL states no rule naming the shelf log id. |
| SF-6 | The push rule (§6.2 step 5) is EBL's current rule, not ruled: who may push records to a holder changes what a party can do, so it is a product rule, and a binding (SF-1) MUST NOT fix it before it is ruled. With it, its order: EBL answers `duplicate` or `deleted` before it applies the push rule (§6.2 steps 3 to 5), so a party holding a record's bytes can probe whether the receiver holds or held it (§8). Applying the push rule first is recommended and not decided. |
| SF-7 | The handover a holder gives a reader of its whole shelf (every entry up to an anchor, facts with status openings, book checkpoints, consistency proofs and receipts; design §2.7) is out of scope here; its wire form is not specified. Whatever form it takes, a handover that cites a deleted record reports it as deleted, not missing (§6.6). |
| SF-8 | Conformance vectors in this repository. EBL's vectors (`testdata/shelf/facts/vectors.json`, `testdata/shelf/receive/`) are the reference today, and are the vectors this repository adopts for these forms; this document adds none yet. |
| SF-9 | Who may hold the journal's openings (§4.3 `auditor`), and how the holder appoints them: EBL's current rule (design §2.2), not ruled. |
