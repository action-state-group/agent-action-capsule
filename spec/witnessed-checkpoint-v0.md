# The Witnessed Checkpoint Follow-up: Receipts and Shelf Consistency, v0

**Status.** Informational, pre-Internet-Draft, kept in this repository. It changes no
Internet-Draft and no other document here. It defines the message that carries a holder's
witnessed shelf checkpoint to the other side of a book: a stamp proof of
[`shelf-forms-v0.md`](shelf-forms-v0.md) (cited as SF), the witness receipts the holder holds for
that stamp proof's shelf checkpoint, and a consistency proof from a shelf checkpoint the
receiver kept. It also defines the ask for one, and the carriage of both over MCP and A2A.

Unlike SF, this document does not write down something the evidencebook library
(<https://github.com/action-state-group/evidencebook>, cited as EBL) already does. EBL's deal
profile design names the gap: before a side treats a deal as settled or relies on the other
side's card, it asks for "a shelf checkpoint with a receipt from a named witness, the consistency
proof from the checkpoint it kept, and the stamp proof for the book's newest fact", and neither
EBL nor SF has a form for receipts or a shelf consistency proof in a push (EBL
`docs/design/461-deal-profile.md` at commit `17ca8a0b1cb3e78bfffebd0fced0c55e7302cee7`, §7.2
and Q8, cited as DP). DP's §8.1 needs the same receipts for a second use: a counterparty record takes its time from its author's stamp
only once that stamp's receipts reach the other side.
Every encoding here is one that EBL or this repository already uses; this document adds the
message around them and the order of the checks.

## Dependency boundary

**Owns:** the ask and the follow-up (§3, §4), the receiver's checks and its answer (§5), and the
MCP tool `witnessed_checkpoint` and the A2A extension that carry them (§6).

**Uses unchanged:**

| Tag | Document | What this document takes from it |
|---|---|---|
| SF | `spec/shelf-forms-v0.md` | the shelf log, its shelf checkpoints and book facts (§1 to §3); the audiences (§4.3); the stamp proof, its JSON encoding and its checks (§5); the receiver's handling of a pushed stamp proof and its proof answer (§6.3, §6.5); evidence kept (§6.4) |
| RP | `spec/bindings/record-push-v0.md` | the carriage rules for both protocols (§2.3), the MCP tool conventions (§3) and the A2A message and reply shapes (§4), which §6 reuses |
| WIT | `vectors/bundle/strict/README.md`, "The rules", `witnesses` | the CLL `WitnessRecord` a receipt is (`ts_url`, `entry_hash`, `receipt_b64`, `leaf_index`, `tree_size`, optional `is_stub`), the witness directory, and how one receipt is checked against a checkpoint's COSE statement, with its status `pass`, `withheld` or `fail`, its directory `key_id` and its `registration_time` (AAC `go/witness` `VerifyReceipts`; EBL `cadence.go` `verifyWitnessReceipt` calls it) |
| CLL | the Checkpointed Local Log, as SF cites it (`github.com/action-state-group/checkpointed-local-log/go` v0.4.0) | the shelf checkpoint statement (log id, MMR size, root, key id), the consistency proof object and its verification (`mmr.VerifyConsistency`) |
| B64U | RFC 4648 §5 | base64url without padding, for the stamp proof's octets |

**Does not define:** which witnesses count for a book (the profile's: EBL's deal profile names
each witness in the agreement by its directory key id, DP Q1), the time a record gets from a
receipt (the profile's, DP §4.3 and §8.1), when a party may rely on the other side's card, the
witness directory a receiver uses, how a holder reaches the other side of a book, any transport
authentication, the push rule (SF-6), and conformance vectors (§8).

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

SF's terms apply: holder, book, shelf log, shelf checkpoint, book checkpoint, book fact, stamp,
size (a CLL MMR size), hex and digest. In addition:

- **Holder:** the party whose shelf log the follow-up is about.
- **Receiver:** the other side of one of the holder's books, which receives the follow-up. In a
  deal each side is the holder of its own book and the receiver of the other's.
- **Asker:** a party that asks a holder for a follow-up (§3).
- **Checkpoint digest:** the SHA-256 of a shelf checkpoint's COSE statement bytes, as a digest.
  It names a shelf checkpoint, as SF's `checkpoint_sha256` names a book checkpoint.
- **Held shelf checkpoint:** a shelf checkpoint the receiver holds from a sender: the shelf
  checkpoint of a stamp proof it accepted or holds as a duplicate (SF §6.3 steps 5 and 6),
  whether pushed alone or in a follow-up.

## 2. Overview

A stamp proof shows that a holder's shelf log carried a book fact under a signed shelf checkpoint
(SF §5). It does not show that anyone outside the holder saw that checkpoint, nor that the
holder's later checkpoints extend it. A **witness receipt** shows the first: a witness took the
shelf checkpoint and returned a receipt the receiver checks offline (WIT), with the time the
witness registered it. A **consistency proof** shows the second: the shelf log at a later
checkpoint extends the one at a checkpoint the receiver kept (CLL).

The **follow-up** carries the three together for one book and one shelf checkpoint. The holder
sends it to the other side of the book: unasked, when receipts arrive for a shelf checkpoint it
already proved to that side (§4.3), or after an **ask** (§3). The receiver checks each part and
answers (§5).

## 3. The ask

An ask is one JSON object with these members and no other:

| Member | Presence | Value |
|---|---|---|
| `book_id` | REQUIRED | the `book_id` of one of the holder's books (SF §3.2), a digest |
| `at` | OPTIONAL | the checkpoint digest of the shelf checkpoint the follow-up is to be about |
| `kept` | OPTIONAL | the checkpoint digest of the newest held shelf checkpoint of the asker's from this holder |

The asker uses `at` to ask again for the receipts of a stamp proof it holds, and `kept` so that
the follow-up proves consistency from the checkpoint it relies on.

Nothing in an ask is authenticated, and nothing in the carriage names the asker (RP §2.3
rule 2). So the holder never answers an ask with a follow-up. It answers every ask the same way
(§6.1), whether or not it holds the book, whoever asks, and whether or not it will act, and it
sends any follow-up only to the other side of the book, by the means it already uses to push to
that side (§4.3). An ask therefore discloses nothing to the asker, and a party that is not the
other side of the book gains nothing by asking.

On an ask for a book it holds, a holder SHOULD send that book's other side a follow-up, built by
§4.2, within a rate bound of its own. It MAY ignore an ask for a book it does not hold, an ask
whose `at` names no shelf checkpoint eligible for that book (§4.2), and asks beyond its bound.

## 4. The follow-up

### 4.1 The object

A follow-up is one JSON object with these members and no other:

| Member | Presence | Value |
|---|---|---|
| `stamp_proof` | REQUIRED | the octets of one stamp proof's JSON text (SF §5.2), in base64url without padding [B64U], non-empty |
| `receipts` | REQUIRED | an array, possibly empty, of witness receipts for the stamp proof's shelf checkpoint, each a CLL `WitnessRecord` JSON object as WIT reads it |
| `consistency` | OPTIONAL | a consistency proof from a held shelf checkpoint of the receiver's to the stamp proof's shelf checkpoint (below) |

`consistency` is a JSON object with these members and no other:

```
{"kind": "cll-mmr-consistency", "from": "<checkpoint digest>",
 "proof": {"v": 1, "kind": "consistency", "old_size": <MMR size>, "new_size": <MMR size>,
           "old_peaks": ["<digest>", ...], "witness": [["<digest>", ...], ...],
           "new_peaks": ["<digest>", ...]}}
```

`from` names the earlier shelf checkpoint by its checkpoint digest. `proof` is the CLL
consistency proof object (CLL `mmr.ConsistencyProof`), with every hash in lowercase hex: the
encoding EBL produces (`substrate_cll.go` `ProveConsistency`, whose `ConsistencyEvidence` carries
the same `kind` and `proof`) and that `draft-mih-zhang-agent-disclosure-bundle-03` uses for
`earlier.consistency_proof` in its `parent-log-witness/v1` extension. Its integers are JSON
integers in the AAC safe range (SF §3.1).

The stamp proof travels as opaque octets, read by SF §5.2 as it stands, as in a record push (RP
§2.1), so SF-4 stays with SF. The receipts and the consistency proof are JSON values, not octets:
WIT reads each receipt as a JSON object, and a receipt's own bytes are already inside it, in
`receipt_b64`.

### 4.2 What the holder puts in it

A follow-up is about one of the holder's books and one **target** shelf checkpoint, cut by one of
the holder's finished stamps at or after the stamp that wrote the book's first fact.

1. **`stamp_proof`:** the stamp proof of the book's latest fact at or before the target's stamp,
   under the target (SF §5.1: the builder takes the book's latest fact at or before a finished
   stamp), made for the `counterparty` audience (SF §4.3), so carrying the fact's status opening
   and never a link opening (SF §5.1).
2. **`receipts`:** every receipt for the target that passed the holder's own check (WIT), one
   per witness and key, sorted by `ts_url` in the byte order of its UTF-8 and then by the
   directory `key_id` it passed under (EBL keeps only receipts that pass, `shelf_record_time.go`,
   and orders them so, `shelf_handover_tie.go` `receiptsLocked`). An empty array says the holder
   holds no such receipt for the target.
3. **`consistency`:** absent when the ask's `kept` names the target itself. Otherwise present
   from the **base**, a shelf checkpoint of the holder's whose size is below the target's: the
   one `kept` names, when it names one of the holder's shelf checkpoints and its size is below
   the target's; otherwise the newest shelf checkpoint below the target's size that the holder
   proved to the receiver before. Absent when there is no base.

The **eligible** shelf checkpoints for a book are those cut by the holder's finished stamps at or
after the stamp that wrote the book's first fact. After an ask, the target is the shelf checkpoint
named by `at` when the ask has it and it is eligible; otherwise the newest eligible one for which
the holder holds a receipt; otherwise, when it holds no receipt for any, the newest eligible one.
An ask whose `at` names a shelf checkpoint that is not eligible for the book gets no follow-up
(§3).

### 4.3 When the holder sends it

A holder SHOULD send the other side of a book a follow-up whenever it holds a receipt, for the
shelf checkpoint of a stamp proof it sent that side, that no follow-up it sent that side carried:
the first receipt for that checkpoint, and each one that arrives later, since the witness the
receiver counts may be a later one. It MAY wait to gather several receipts into one follow-up.
This is how receipts travel with stamp proofs (DP §8.1). It SHOULD also send one after an ask
(§3). It sends a follow-up only to the party on the other side of the book, as the holder's
profile names that party, by the same means it pushes records to that party (SF §6; how it reaches the party is outside this document). A follow-up
carries a status opening for the `counterparty` audience (§4.2 step 1), so sending one to anyone
else discloses what SF §4.3 keeps from them.

## 5. The receiver

### 5.1 The checks

A receiver handles a follow-up in this order. The outcomes of steps 1, 3 and 4 go into the answer
(§5.2).

1. **The stamp proof.** The receiver decodes `stamp_proof` and handles it as the proof part of a
   record push, by SF §6.3 steps 1 to 6, with the same outcomes (`accepted`, `duplicate`, or
   `refused` with class `invalid` or `refused`), the same evidence kept (SF §6.4) and the same
   coverage (SF §6.3). If the proof is refused, the receiver stops: it checks neither
   `consistency` nor `receipts`, and keeps nothing of them. The **target** is the stamp proof's
   shelf checkpoint.
2. **The target against held checkpoints.** If the receiver holds another shelf checkpoint signed
   by the same key, of the same log id and the same size as the target, with a different root,
   it keeps the two as evidence of kind `shelf_checkpoint` (§5.3): one key signed two shelf
   checkpoints of one log at one size with different roots. This step runs whether or not the
   follow-up has `consistency`, and gives no outcome of its own in the answer.
3. **The consistency proof**, when `consistency` is present.
   1. If `from` is not the checkpoint digest of a held shelf checkpoint from this sender (one
      signed by the stamp proof's key, SF §5.3 step 3), the outcome is `unknown_from`.
   2. Otherwise, if that held checkpoint names another log id or another key id than the target,
      or its size is not below the target's, the outcome is `invalid` (two of one size with
      different roots are also kept by step 2).
   3. Otherwise the outcome is `accepted` when `kind` is `cll-mmr-consistency`; `proof` is an
      object with exactly the members `v` (the integer `1`), `kind` (the string `consistency`),
      `old_size` and `new_size` (integers in the AAC safe range), `old_peaks` and `new_peaks`
      (arrays of strings) and `witness` (an array of arrays of strings), and no other;
      `proof.old_size` is the held checkpoint's size; `proof.new_size` is the target's size;
      every hash in `proof` is 64 lowercase hex characters; and the CLL consistency proof verifies from the held
      checkpoint's root to the target's root (CLL Go `mmr.VerifyConsistency`, v0.4.0); and
      `invalid` otherwise. A proof that fails to verify is not evidence against the sender: the
      receiver keeps nothing of it. An `accepted` outcome links `from` to the target (§5.4).
4. **The receipts.** For each entry of `receipts`, in order, the receiver applies WIT's check of
   one receipt to the target's COSE statement under its own witness directory, and takes its
   status: `pass`, `withheld` or `fail`. An entry WIT finds malformed is `fail`. A receiver that
   does not check an entry, because it cannot run a receipt check or because the entry is past a
   bound of its own, reports it `withheld` (WIT). The receiver keeps each receipt that passes
   beside the target, with the `key_id` and the `registration_time` WIT gives it, which is `null`
   when the receipt passed with no usable registration time (WIT); it MAY keep a `withheld` one,
   to check again later.

Steps 2 to 4 are independent once the stamp proof passes step 1: a consistency outcome other
than `accepted` changes neither the proof's outcome nor what the receipts give, and a receipt
that fails changes neither of the others. Sending the same follow-up again is safe: the stamp
proof is answered `duplicate` (SF §6.3 step 5), and the other steps give the same outcomes.

### 5.2 The answer

The answer to a follow-up is one JSON object with exactly these three members:

| Member | Type | Value |
|---|---|---|
| `stamp_proof` | object | the proof answer of RP §2.2: `accepted`, `duplicate` and `refused`, from step 1 |
| `consistency` | string | `""` when the follow-up had no `consistency` or the stamp proof was refused; otherwise the outcome of step 3: `accepted`, `invalid` or `unknown_from` |
| `receipts` | array of strings | one status per entry of `receipts`, in order, from step 4: `pass`, `withheld` or `fail`; empty when the stamp proof was refused |

On `unknown_from`, the receiver can ask (§3) with its own `kept`. Like a record push's answer,
this answer is an acknowledgment: it is not signed, and it is not evidence of what the receiver
holds (RP §2.2).

### 5.3 Evidence

This document adds one kind to SF §6.4's table of what a receiver keeps:

| Kind | What is kept |
|---|---|
| `shelf_checkpoint` | two shelf checkpoints one key signed for one log at one size with different roots: the one held and the other |

As for SF's `checkpoint` kind, it is kept whatever the receiver's bounds, once per key, log id and
size: two holders may use the same log id.

### 5.4 What a follow-up shows

A follow-up whose stamp proof passes step 1 and with a receipt that passes in step 4 shows the
receiver that the holder's shelf log carried the book's fact under a shelf checkpoint that a
witness registered, and, when that receipt's `registration_time` is not `null`, when the witness
registered it. A receipt that passes with a `null` time shows registration and gives no time.

The target **extends** a shelf checkpoint the receiver relies on only when step 3 accepted a
consistency proof from that checkpoint to the target, or from a checkpoint that, through a chain
of consistency proofs the receiver accepted, extends the one it relies on. A held checkpoint is
not, by being held, one the target extends: a stamp proof whose shelf checkpoint failed
consistency is still held (step 1). A receiver that relies on an earlier checkpoint names it in
its ask's `kept`.

Whether a witness is one the book's agreement names, and what that does to a row's status or a
card, is the receiver's profile's (DP §4.3, §7.2, §8.1). Beside the answer, a receiver's profile
learns which matters gained a receipt with a registration time that is not `null`, as it learns
which gained coverage (SF §6.5, "What the receiver learns"); this document puts that in
no answer.

## 6. Carriage

The ask, the follow-up and their answers travel over MCP and A2A as the record push does (RP),
in one **message object** and one **answer object**:

| Message object | Answer object |
|---|---|
| `{"ask": <the ask, §3>}` | `{"ask": {}}` |
| `{"follow_up": <the follow-up, §4.1>}` | `{"follow_up": <the answer, §5.2>}` |

A message object has exactly one of the two members. The answer to an ask is always the empty
object, so that it says nothing (§3). One endpoint serves both: a party in a book receives asks
about its own book and follow-ups about the other side's.

RP §2.3 rules 2 to 7 apply as written, reading "push" as a message object and "answer" as an
answer object, with these differences:

- Rule 1: the stamp proof is opaque octets, and the receipts and the consistency proof are JSON
  values handed to §5.1 as received (§4.1).
- Rule 3: a message object with neither member, with both, or with a member that is not an ask or
  a follow-up of §3 or §4.1 (an unknown or missing member, or a value of the wrong type) is not a
  message: it gets the invalid-params error, never an answer object.
- Rule 6: the message bound SHOULD let a follow-up carrying a stamp proof and the receipts of the
  witnesses the receiver's directory lists reach the receiver.
- Rule 7 names the `witnessed_checkpoint` tool and the extension entry below.

### 6.1 MCP

A party that serves the ask and the follow-up over MCP MUST list one tool, as RP §3.1 lists
`record_push`, under exactly the name `witnessed_checkpoint`, with fixed `title` and
`description` text, and these schemas. Its `inputSchema`:

```json
{
 "type": "object",
 "properties": {
  "ask": {
   "type": "object",
   "properties": {
    "book_id": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "at": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "kept": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
   },
   "required": ["book_id"],
   "additionalProperties": false
  },
  "follow_up": {
   "type": "object",
   "properties": {
    "stamp_proof": {"type": "string", "pattern": "^[A-Za-z0-9_-]+$"},
    "receipts": {"type": "array", "items": {"type": "object"}},
    "consistency": {
     "type": "object",
     "properties": {
      "kind": {"const": "cll-mmr-consistency"},
      "from": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
      "proof": {"type": "object"}
     },
     "required": ["kind", "from", "proof"],
     "additionalProperties": false
    }
   },
   "required": ["stamp_proof", "receipts"],
   "additionalProperties": false
  }
 },
 "minProperties": 1,
 "maxProperties": 1,
 "additionalProperties": false
}
```

The schema leaves a receipt's members to WIT, which finds a malformed receipt `fail` rather than
refusing the message (§5.1 step 4), and leaves `proof`'s members to §5.1 step 3.3, which makes a
malformed proof `invalid`.

Its `outputSchema`:

```json
{
 "type": "object",
 "properties": {
  "ask": {"type": "object", "additionalProperties": false},
  "follow_up": {
   "type": "object",
   "properties": {
    "stamp_proof": {
     "type": "object",
     "properties": {
      "accepted": {"type": "boolean"},
      "duplicate": {"type": "boolean"},
      "refused": {"enum": ["", "invalid", "refused"]}
     },
     "required": ["accepted", "duplicate", "refused"],
     "additionalProperties": false
    },
    "consistency": {"enum": ["", "accepted", "invalid", "unknown_from"]},
    "receipts": {"type": "array", "items": {"enum": ["pass", "withheld", "fail"]}}
   },
   "required": ["stamp_proof", "consistency", "receipts"],
   "additionalProperties": false
  }
 },
 "minProperties": 1,
 "maxProperties": 1,
 "additionalProperties": false
}
```

The call, the result and its errors follow RP §3.2 and §3.3, with `name` `witnessed_checkpoint`
and `arguments` the message object: the answer object is the result's `structuredContent`, with
`isError` `false` whatever it says, and a call whose `arguments` do not satisfy the input schema,
or whose `stamp_proof` does not strictly decode to at least one octet, gets the JSON-RPC error
`-32602` and no answer object. No property carries an `x-mcp-header` annotation (RP §3.1).

### 6.2 A2A

A party that serves them over A2A MUST list one `AgentExtension`, as RP §4.1 does, with `uri`
exactly `https://datatracker.ietf.org/doc/draft-mih-agent-witnessed-checkpoint/`, fixed
`description` text, `required` `false` and no `params`. As in RP §4.1, the URI names the
datatracker page of the Internet-Draft meant to carry this document; it is an identifier and does
not resolve until that draft is posted. The message and the reply follow RP §4.2
and §4.3 with that URI: one `data` part holding the message object, and a completed `Task` with
one Artifact, carrying that URI, whose one `data` part holds the answer object. A message whose
`data` value does not satisfy the input schema of §6.1 carries no message object and gets the
errors of RP §4.2.

### 6.3 Example (informative)

An ask over MCP from a buyer that kept the seller's shelf checkpoint `9f1c…`:

```
{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
 "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
  "io.modelcontextprotocol/clientCapabilities": {}},
 "name": "witnessed_checkpoint",
 "arguments": {"ask": {"book_id": "<the seller's book_id>", "kept": "<9f1c…, 64 hex>"}}}}
```

is answered `{"ask": {}}` in `structuredContent`. The seller then calls the buyer's
`witnessed_checkpoint` tool with

```
{"follow_up": {"stamp_proof": "<the stamp proof's JSON octets, base64url>",
  "receipts": [{"ts_url": "https://witness.example", "entry_hash": "<64 hex>",
    "receipt_b64": "<the COSE receipt, standard base64>", "leaf_index": 41, "tree_size": 42}],
  "consistency": {"kind": "cll-mmr-consistency", "from": "<9f1c…, 64 hex>",
    "proof": {"v": 1, "kind": "consistency", "old_size": 25, "new_size": 41,
      "old_peaks": ["<64 hex>", "<64 hex>", "<64 hex>"], "witness": [["<64 hex>"], ["<64 hex>", "<64 hex>"],
        ["<64 hex>", "<64 hex>", "<64 hex>"]],
      "new_peaks": ["<64 hex>", "<64 hex>", "<64 hex>"]}}}}
```

and a buyer that already held the stamp proof, holds a directory row for that witness and keeps
`9f1c…` answers

```
{"follow_up": {"consistency": "accepted", "receipts": ["pass"],
  "stamp_proof": {"accepted": false, "duplicate": true, "refused": ""}}}
```

The sizes and the shape of `witness` are consistent (14 leaves to 22); the hashes are
placeholders, not a proof that verifies.

## 7. Security and privacy considerations

- **The ask is unauthenticated.** Anyone can ask. The holder's answer is the same for every ask
  (§3, §6), so an ask learns nothing, not even whether the book exists; the follow-up goes only
  to the other side of the book (§4.3). A holder bounds how often an ask makes it send.
- **What a follow-up discloses.** To the other side of the book, beside what a stamp proof
  already shows (SF §5.3, §8): which witnesses the holder uses and when they registered its shelf
  checkpoint, and, through the consistency proof's peaks, nothing a shelf checkpoint's size does
  not already show. A follow-up carries a status opening (§4.2 step 1), so a holder MUST NOT send
  one to anyone but the other side of the book.
- **A forked shelf log.** A holder that shows the other side two shelf checkpoints of one size
  with different roots leaves evidence of it when the later of the two arrives in a follow-up
  (§5.1 step 2, §5.3). A stamp proof pushed alone is checked by SF §6.3, which compares book
  checkpoints only, so a conflicting shelf checkpoint that arrives later in a plain push leaves
  none. A consistency proof that fails to verify is
  refused and leaves none, since anyone could send one (§5.1 step 3.3).
- **Receipts are checked, not trusted.** A receipt counts only under the receiver's own witness
  directory (WIT); one from a witness the receiver has no row for is `withheld`, never `pass`.
  The answer's per-receipt statuses (§5.2) tell the holder which of its witnesses the receiver's
  directory lists.
- **The answer is unsigned** (RP §6): an intermediary can alter it, and it is evidence of
  nothing.

## 8. Conformance

This document adds no vectors yet (open point WC-1). An implementation claims conformance to it
only once vectors exist.

## 9. Open points

| # | Point |
|---|---|
| WC-1 | Conformance vectors: a follow-up with each outcome of §5.1 (each refusal of the stamp proof; a target of the size of a held checkpoint with a different root, with and without `consistency`, keeping `shelf_checkpoint` evidence; `unknown_from`; a held checkpoint of another log or key, or of a size not below the target's; a proof of the wrong sizes, of a malformed hash, and one that does not verify; receipts that pass, are withheld, fail and are malformed), and the carriage edge cases of §6 (neither member, both members, an unknown member). They are to land in this repository's `vectors/` with the first implementation, which can cross-check them, as SF-8 does for SF. |
| WC-2 | Binding the shelf checkpoint to the holder's shelf log (SF-5). §5.1 step 3 binds each later shelf checkpoint to the log of one the receiver already holds, but the first one a receiver holds is still bound to the holder only by its key (SF §5.3 step 3). |
