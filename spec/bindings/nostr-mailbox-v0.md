# Nostr Mailbox Carriage — v0 (EXPERIMENTAL)

**Status.** EXPERIMENTAL. Informational carriage binding, kept in this repository. It is not an
Internet-Draft, it is not part of any Internet-Draft revision, and it changes no posted draft. It
is not part of the Minimum Evidence Interoperability Profile `evidence-interop/0`
([`interop-profile-v0.md`](../interop-profile-v0.md), cited here as IP) and defines no binding
token. A responder MUST NOT list a token for this binding in a manifest's `bindings` [IP §11.4.2].
That rule already follows from IP, which allows no token beyond those its listed profiles define.
Its adapter declaration is [`../adapters/nostr-mailbox-v0.md`](../adapters/nostr-mailbox-v0.md).
Its vectors are in `vectors/adapters/nostr-mailbox/` (§9).

**Answer in one paragraph.** A responder with no inbound reachability (no listener that a requester
can open a connection to) has no endpoint for the bindings ER defines, the peer-to-peer stream and
HTTP [ER §10], or for the A2A and MCP carriages [IP §11.4]: in each, the request is delivered to an
endpoint the responder serves. Here both parties connect outward to a Nostr relay instead. The
requester publishes a request event addressed to the responder's mailbox key. The responder reads
the events addressed to that key, and publishes a reply event naming the request event. Each event's
content is the request or reply octets, unchanged. The envelope or refusal inside is signed by the
responder's evidence key, end to end. The relay only moves bytes. A relay can drop, delay, replay or
read what it carries. It cannot make a reply that verifies, and it cannot make the requester discard
one. When no reply arrives by the request's `deadline`, the requester records an absence [ER §4.4].

ER is `draft-mih-agent-evidence-request-00` (`spec/draft-mih-agent-evidence-request-00.md`).
Section numbers are those of its rendered `.txt`.

## 1. When this binding applies

This binding is for a responder with no inbound reachability. For such a responder it is the only
inbound route this repository describes. A responder that can be reached inbound SHOULD be asked
over the native stream, HTTP, A2A or MCP [ER §10; IP §11.4], which need no third party in the path.

A deployment MAY run its own relay. Doing so is optional infrastructure. This binding names no
relay, assumes no particular operator, and works with any relay that implements NIP-01.

## 2. What was read

| Source | Version | Sections used |
|---|---|---|
| NIP-01, Basic protocol flow description | `nostr-protocol/nips` commit `0b54c4d1c70b046fbb2e3c599c09b641e00f5dcd`, `01.md`, SHA-256 `d5c5ce2b5639eee440b5d342dbe81af42008838cb260ec04acaffaffd29dcaf7` | Events and signatures; Tags; Kinds; Communication between clients and relays |
| NIP-19, bech32-encoded entities | same commit, `19.md`, SHA-256 `5b53c98637ae0cb8e6d99e1570e32da2c5842154ba898393439f334f1fd90aad` | the introduction; Shareable identifiers with extra metadata (`nprofile`); Examples |
| NIP-21, `nostr:` URI scheme | same commit, `21.md`, SHA-256 `e9a15c24e7bf61883fdf9af3b77c84a99761903f7237dc9124d0bde5744daf91` | the scheme |
| NIP-40, Expiration Timestamp | same commit, `40.md`, SHA-256 `1e88a08583391084fc95b842932119555cb270988612261fbb78017e84a0dc78` | the `expiration` tag; Client Behavior; Relay Behavior; Warning |
| NIP-44, Encrypted Payloads (Versioned) | same commit, `44.md`, SHA-256 `b5f89374e4e1dbdee7881e8573b4313b6a89430a9c8d518471599ae0660cf0e2` | Versions; Limitations (§8 and N-3 only) |
| NIP-59, Gift Wrap | same commit, `59.md`, SHA-256 `b46b078ff5b219fd4ab33a53b479b49d4cbd604b88be46d6b978d53d8f8b43a0` | the introduction and Overview (§8 and N-3); the rumor and seal of its example, as published values (§9) |
| NIP-65, Relay List Metadata | same commit, `65.md`, SHA-256 `ca9cceac7b113bd98d543026c793f87d56478c624f93c799fa4d536e0e7de04a` | the read and write relay lists; publishing to the read relays of each tagged user (§4.3) |
| NIP-90, Data Vending Machine | same commit, `90.md`, SHA-256 `a82714bac7563cecf7cdb17e83dc60ebea25d06159e826b3bde9c361c28414bb` | Kinds (only to avoid its range, §4) |
| NIP-94, File Metadata | same commit, `94.md`, SHA-256 `1a035c0aa9c36213821c0f5616ccb030f23115421f501dfccfb42aac68c6a7ee` | the `m` tag (§4) |
| BIP-340, Schnorr Signatures for secp256k1 | `bitcoin/bips` commit `5aadddb511a5dcfe4599531bd8ae5e5b96d0f793`; `bip-0340/test-vectors.csv`, SHA-256 `34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d` | Sign, Verify; test vectors 0, 1, 5, 6, 12, 13 and 14 (§9) |

All NIPs are informative references. The repositories were read only. Nothing was posted to them.
URLs: <https://github.com/nostr-protocol/nips/blob/0b54c4d1c70b046fbb2e3c599c09b641e00f5dcd/01.md>,
and the same path with `19.md`, `21.md`, `40.md`, `44.md`, `59.md`, `65.md`, `90.md` and `94.md`;
<https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0340.mediawiki>.

## 3. Two keys, two jobs

| Key | Algorithm | Held by | What it does here |
|---|---|---|---|
| **Mailbox key** | secp256k1, BIP-340 (NIP-01) | the responder | Addresses the mailbox: request events are addressed to it, and reply events are signed by it. |
| **Responder key** | Ed25519 [IP §6.2] | the responder | Signs the envelope or refusal. The only key that makes a reply evidence. |

The requester also holds a Nostr key, its **carriage key**, to sign its request event. That key
says nothing about who the requester is under the evidence protocol.

**The mailbox key is a route, not an identity.** ER says the route field is "a hint for the
transport binding and nothing more", and that "a responder reached through a route is authenticated
by its signature on the response, never by the route" [ER §3.6]. Here the mailbox key is that kind
of hint. A verifier never accepts a reply because the mailbox key signed its event. It accepts what
the responder key signed, under the trust policy [IP §7.2 `responder_trust`]. The mailbox key
decides only which events are in the reply position (§4.2), and the responder's signed answer to a
request counts wherever it arrives from.

**Learning the mailbox key needs trust.** The mailbox key fills the reply position (§4.2): what its
holder publishes in reply to a request is verified as the responder's reply, and a reply that fails
verification is a response received and failed, which ER says requesters SHOULD treat as adverse
[ER §4.1]. That is the same position an HTTP endpoint holds over a POST. So a requester MUST take
the mailbox key from a source it trusts to speak for the responder's route, such as the
responder's commitment (§4.3). A mailbox key from any other source can put the failed replies of
whoever holds it in front of the verifier. How the key is published is outside this revision
(N-5).

## 4. Events

Both events are NIP-01 events. Their `id` is SHA-256 over the UTF-8 JSON serialization that
NIP-01 fixes, and their `sig` is a BIP-340 signature over the `id` by the event's `pubkey`. This
binding uses two kinds:

| Kind | Event |
|---|---|
| `4700` | request event |
| `4701` | reply event |

Both are in NIP-01's **regular** range, where events "are all expected to be stored by relays".
That storage is what makes a relay a mailbox: the request waits until the responder connects, and
the reply waits until the requester does. NIP-01 calls its ranges "just conventions", so a relay
may still not store them (§6). Both kinds avoid the range `5000-7000` that NIP-90 reserves. They
are placeholders, not registered anywhere (N-1).

In both kinds, `content` is the carried octets in base64url without padding (RFC 4648 §5), as in
IP §11.4.5. The `m` tag names their media type, one of the two values of IP §11.4.1 rule 7.
NIP-94 uses an `m` tag for "the data type of the file" in MIME type form. Here the tag has the same
use, defined for these two kinds: NIP-01 says kinds specify how clients should interpret "the
meaning of each event and the other fields of each event".

### 4.1 Request event

Published by the requester, signed by its carriage key.

| Field | Value |
|---|---|
| `kind` | `4700` |
| `content` | the request octets, base64url without padding |
| tag `p` | exactly one: `["p", <mailbox key, 64 lowercase hex>, <relay URL, optional>]` (NIP-01) |
| tag `m` | exactly one: `["m", <media type of the request>]` |
| tag `expiration` | when the request carries `deadline`: `["expiration", <the deadline, as a unix timestamp in seconds, as a decimal string>]` (NIP-40) |
| `created_at` | the requester's clock; carriage only (§7) |

**Addressing by key.** The `p` tag is the address. NIP-01 expects relays to index single-letter
tags, so a responder finds its mail with a subscription filter on the `p` tag and the kind:
`{"kinds": [4700], "#p": [<mailbox key>]}`. The request map itself names no responder. ER defines
no such field, and a deployment that wants one adds it as an extension [ER §3.7].

**Deadline.** The `expiration` tag repeats the request's `deadline` so a relay may drop the request
once nobody needs it. NIP-40 is optional for relays. It says relays "MAY persist them
indefinitely", and warns against treating expiring messages as a security feature. So the tag is a
storage hint, and the `deadline` member in the request octets decides the window (§5.3). NIP-40
says clients "SHOULD NOT send expiration events to relays that do not support this NIP"; a
requester follows that, and so it may send a request with a `deadline` and no `expiration` tag. A
request without `deadline` carries no `expiration` tag.

### 4.2 Reply event

Published by the responder, signed by the mailbox key.

| Field | Value |
|---|---|
| `kind` | `4701` |
| `content` | the reply octets (an envelope [IP §6.2] or a refusal [IP §6.3]), base64url without padding |
| tag `e` | exactly one: `["e", <the request event's id>, <relay URL, optional>]` (NIP-01) |
| tag `p` | exactly one: `["p", <the request event's pubkey>]` |
| tag `m` | exactly one: the request's media type [IP §11.4.1 rule 3] |
| `created_at` | the responder's clock; carriage only (§7) |

**Reply-to.** The `e` tag is the reply-to. The requester subscribes with
`{"kinds": [4701], "#e": [<request event id>], "authors": [<mailbox key>]}`. Because the event `id`
covers the tags, a reply event names exactly one request event, and nobody without the mailbox key
can move it to another.

**Which events are replies.** The requester applies these checks, in order, to each event
delivered on that subscription.

Format checks. If one fails, the event is not a reply and is named by the check:

1. `kind`: the kind is `4701`.
2. `reply_to`: exactly one `e` tag, naming the request event's `id`.
3. `media_type`: exactly one `m` tag, equal to the request's media type.
4. `content`: `content` decodes as base64url without padding.

Attribution checks. They decide whether the event is in the reply position:

5. `id`: the `id` equals the NIP-01 hash of the event.
6. `signature`: `sig` verifies under `pubkey` by BIP-340 over `id`.
7. `author`: `pubkey` is the mailbox key the request event addressed.

An event that passes all seven is a reply. Its octets are classified and verified by IP (§5.2),
and a failure is a response received and failed, as on any carriage.

**Reply by content.** An event that passes checks 1 to 4 and fails one of checks 5 to 7 is not in
the reply position, but its content may still be the responder's answer. ER says a responder "is
authenticated by its signature on the response, never by the route" [ER §3.6], and that a refusal
which arrived is never recorded as an absence [ER §4.5]. So the requester verifies the decoded
content against this request on its own [IP §7]. It is a reply, named for the first attribution
check that failed, when:

- it is an envelope whose `envelope_signature`, `responder_trust` and `request_binding` are `PASS`;
  or
- it is a refusal whose `refusal_signature`, `responder_trust` and `request_binding` are `PASS`.

Otherwise the event is not a reply, and is named by that check. Its content is discarded: it is
not a response received and failed.

An event that is not a reply is a transport condition [IP §9.2]: the request stays pending, then
becomes an absence [IP §11.4.1 rule 6]. It is never a refusal. Events with the same `id` are one
event, however many times a relay delivers them. The `p` tag of a reply event is for the
requester's own filtering, and is not checked.

This keeps two things true at once. A relay or third party cannot turn a pending request into a
response received and failed: content outside the reply position counts only when the responder
signed it under a trusted key for this very request, and then it is the responder's own act. And
the responder's signed answer is never thrown away because of the carriage it came through, for
example a mailbox key that was rotated, or an event re-published by another key.

### 4.3 Relays

**The relay choice is the responder's.** The responder declares the relays it reads, in a relay
list carried in its commitment. The list follows the model of NIP-65. In NIP-65 a user publishes a
relay list whose relays are marked as where it **reads** mentions or where it **writes**, and when
publishing an event, clients SHOULD "send the event to all **read** relays of each tagged user".
Here the tagged user is the mailbox key, and the responder's declared relay list is the set of
relays it reads.

- The requester MUST publish the request event to at least one relay on the responder's declared
  relay list, and SHOULD publish it to every one.
- The responder MUST publish each reply event to the relay it read the request event from, and
  MAY also publish it to its other declared relays. The requester's carriage key may be fresh for
  this request (§8), with no relay list of its own, so the reply goes where the request was found.
- The requester subscribes for replies on the relays it published the request to.

**Open item.** The member of the commitment that carries the relay list is named where the
commitment profile is specified, not here. This binding writes its rules against "the responder's
declared relay list (carried in its commitment)" and defines no field name. Until the member is
named, a requester has no conforming way to read the list (N-4).

A relay URL in an example (`wss://relay.example`) is an example of an entry in that list. It is
not a relay this binding names.

## 5. The exchange over a mailbox

Nothing about the exchange changes. The request map, envelope, refusal and absence record are
those of IP §6. This section says only how they meet the carriage.

### 5.1 Octets and digests

The carriage moves the request and reply octets as opaque bytes. The octets are those obtained by
decoding `content` [IP §11.4.1 rule 1]. The request digest is SHA-256 over the decoded request
octets as received, never over the event, its `content` text, or a re-serialization [ER §4.2;
IP §11.4.1 rules 1 and 2]. The same request octets sent over this carriage and over any other give
the same request digest.

### 5.2 Classifying a reply

A reply's octets are classified and verified as IP says for every carriage: by the octets alone,
as an envelope or a refusal [IP §1, §7], with each distinct reply verified on its own and every
envelope held for one request compared through `caller_invariance` [IP §11.4.1 rules 6 and 8]. A
responder that declines MUST either put a signed refusal in a reply event or publish no reply
[IP §11.4.1 rule 5]. A responder that determines it cannot answer by the deadline SHOULD send a
`deadline_unmet` refusal before the deadline [ER §3.4]. A relay's `OK` with `false`, a `CLOSED`
message or a `NOTICE` is a transport condition, never a refusal [ER §10; IP §9.2].

### 5.3 Deadline and absence

The requester's waiting window opens when it publishes the request event, and closes at the
request's `deadline`. When the request has no `deadline`, it closes at the requester's local
timeout [ER §4.4; IP §6.4]. Before it closes the request is pending [ER §4.3]. If no reply (§4.2)
has arrived when it closes, the requester writes an absence record [IP §6.4] with:

- `window.closed` equal to the request's `deadline`, when the request has one;
- `route` the NIP-21 `nostr:` URI of a NIP-19 `nprofile` whose key is the mailbox key and whose
  relay entries are the relays the request event was published to. NIP-19 says its bech32 forms are
  "not meant to be used anywhere in the core protocol" and are for display and sharing. The absence
  record is not a Nostr protocol message, and `route` is a text hint kept for people and records
  [ER §3.6], so that is the use NIP-19 intends.

The requester judges arrival by its own clock when the event reaches it, never by `created_at`,
which the publisher sets. A dropped request, a dropped reply, a relay that delayed either past the
deadline, a responder that was offline, and a responder that chose not to answer all produce the
same absence [ER §4.4]. The record SHOULD NOT say which.

A reply event that reaches the requester after it has written the absence record is still a reply,
and the requester keeps it [IP §11.4.1 rule 8]. It is checked as §4.2 says and verified on its own,
as every reply is (§5.2). It never rewrites the absence:

- The absence record stays as written, byte for byte. The requester MUST NOT edit or delete it, and
  MUST NOT replace it with a record that says a reply arrived in time.
- The late reply is its own, later fact. It already cites the request: an envelope or a refusal
  signs the `request_digest` of the request it answers [IP §6.2, §6.3], which is the
  `request_digest` of the absence record [IP §6.4], and its reply event names the request event in
  its `e` tag (§4.2). The requester keeps the reply beside the absence record. Neither refers to
  the other. What joins them is the request digest both carry.
- This is the append-only rule of lifecycle links [IP §11.2]: a signed record is never edited, and
  a later record names the earlier one by digest. The later record is the reply, and the record
  it names is the request. No lifecycle statement is issued. `supersedes` would replace the
  absence for current use and `amends` would change it [IP §11.2.1], and a late reply corrects
  nothing: the window closed with no reply, and that stays true. A requester MUST NOT issue a
  lifecycle statement against an absence record because a reply arrived late.

A verifier given both shows both: the absence for the window, and the reply with its own results.
Vector `mailbox-late-reply-after-absence` (§9).

## 6. What a relay can and cannot do

The relay is an untrusted store-and-forward hop. The envelope or refusal is signed by the
responder key, end to end, and the relay holds no key that matters.

| A relay can | What the requester sees | Detected? |
|---|---|---|
| drop or not store the request or the reply | no reply; absence at the deadline | no: indistinguishable from silence [ER §4.4] |
| delay either past the deadline | absence; a late reply, if it arrives later, kept beside it (§5.3) | no, beyond the envelope's signed `issued_at` |
| deliver a request event twice | the responder answers each request event `id` once, and SHOULD NOT answer a redelivery; if it does, two replies with one request digest | both verified; `caller_invariance` compares them [IP §7.2] (vector `mailbox-request-redelivered`) |
| deliver a reply event twice | one event (§4.2) | yes, by `id` |
| deliver an old reply event for a new request | an `e` tag naming another request event | not a reply: check 2 (vector `mailbox-reply-to-other-request`) |
| alter an event's content or tags | an `id` mismatch | not a reply unless the content proves itself (vector `mailbox-event-tampered`) |
| attach a signature that is not the event's | a signature that does not verify | the same rule (vector `mailbox-event-bad-signature`, whose content does prove itself) |
| publish its own reply event, carrying the responder's old envelope | an event not by the mailbox key, whose content binds another request | not a reply (vector `mailbox-other-key-replays-old-envelope`) |
| re-publish the responder's genuine answer under its own key | an event not by the mailbox key, whose content proves itself | a reply by content (vector `mailbox-relayed-by-other-key`) |
| read everything | the request, both carriage keys, the timing | not prevented in v0 (§8) |

| A relay cannot | Why |
|---|---|
| make a reply that verifies | it holds neither the mailbox key nor the responder key |
| bind a genuine envelope to another request | the envelope signs `request_digest` [IP §6.2] |
| make an absence look like a refusal | a refusal is signed by the responder key [ER §4.2] |

The holder of the mailbox key is the responder, or whoever holds that key in its place. It can do
more than a relay: it can put any octets in front of the verifier. It still cannot forge the
responder key's signature. An envelope signed by a key outside the trust policy is
`responder_trust` `FAIL` (vector `mailbox-envelope-untrusted-key`). A genuine envelope attached to
another request is `request_binding` `FAIL` (vector `mailbox-envelope-replayed`). Both are IP §8.1
row 2. That second check depends on the two requests having different digests, so a requester
SHOULD set `nonce` [ER §3.5]: two requests with the same octets have the same digest, and an old
answer to one binds to the other.

## 7. What the carriage adds

The event `id`, `pubkey`, `created_at`, `kind`, `tags` and `sig`, the requester's carriage key, the
mailbox key and the relay are carriage. None is part of the request [ER §3; IP §11.4.1 rule 4],
and none may influence the artifact [ER §5]. The artifact octets are the same over this carriage as
over any other, for the same responder, subject, resolved anchor and derivation [IP §6.2].

## 8. Privacy considerations

In v0, events are not encrypted. A relay, and anyone who can subscribe to it, sees:

- the request octets: subject, coverage, deadline, nonce and route;
- that a carriage key asked the mailbox key, when, and whether and when it was answered;
- the reply octets, including the artifact.

IP forbids a discovery object to reveal a counterparty or a time of activity [IP §11.4.3]. ER §12
discusses what an exchange discloses. A mailbox on a relay that others can read publishes the
request, the parties' carriage keys and the timing to every reader. So in v0:

- the requester SHOULD use a fresh carriage key for each request, so its requests are not linked
  to each other by key;
- a deployment MUST NOT use this binding for an exchange whose subject, timing or parties it would
  not publish, until encryption is specified (N-3).

NIP-44 defines a versioned encryption format (version `0x02`: "secp256k1 ECDH, HKDF, padding,
ChaCha20, HMAC-SHA256, base64"), and notes that nostr's relay-based architecture makes metadata
hiding difficult. NIP-59, Gift Wrap, builds on NIP-44 to "obscure most metadata" of an event. They
are the obvious next step, and they are not specified in v0 (N-3). Encryption would not change what
is signed: the envelope and refusal stay end to end, inside it.

## 9. Vectors and drift check

The vectors are in `vectors/adapters/nostr-mailbox/`.
`python/scripts/generate_nostr_mailbox_vectors.py` generates them deterministically, and
`python/tests/test_nostr_mailbox_vectors.py` checks them offline. The evidence side reuses the IP
corpus: its responder key, log, artifact and envelope builders, and its contract pin. Each case
carries the request octets, the request event, the events the relay delivered, and, where the
window closed, the absence record and any events delivered after it, each with the time it reached
the requester. The test recomputes every event `id`, verifies every BIP-340
signature with its own code, applies the checks of §4.2, and passes each reply to the reference
verifier of IP. It also checks its NIP-01 `id` and BIP-340 against the rumor and seal published in
NIP-59, its BIP-340 against BIP-340 test vectors 0, 1, 5, 6, 12, 13 and 14, and its bech32 against
the NIP-19 `nprofile` example.

| Case | What it shows | Sections |
|---|---|---|
| `mailbox-exchange` | a request event and a reply event carrying an envelope: a reply, every required envelope property `PASS`, IP §8.1 row 7 | §4, §5.1, §5.2 |
| `mailbox-refusal-deadline-unmet` | a JSON request answered with a signed `deadline_unmet` refusal before the deadline | §5.2 |
| `mailbox-request-redelivered` | what the requester receives when the responder answered one request event twice, with one reply event delivered again: two replies, `caller_invariance` `PASS` | §4.2, §6 |
| `mailbox-envelope-untrusted-key` | the mailbox key carries an envelope by a key the trust policy does not accept: `responder_trust` `FAIL`, row 2 | §3, §6 |
| `mailbox-envelope-replayed` | the mailbox key answers request 2 with request 1's genuine envelope: `request_binding` `FAIL`, row 2 | §6 |
| `mailbox-relayed-by-other-key` | another key carries the responder's genuine envelope for this request: a reply by content | §4.2 |
| `mailbox-other-key-replays-old-envelope` | another key carries the responder's envelope for another request: not a reply; absence | §4.2, §6 |
| `mailbox-event-bad-signature` | the reply event's signature does not verify, and its content is the responder's envelope for this request: a reply by content | §4.2 |
| `mailbox-event-tampered` | the reply event's content changed after signing, to an envelope under an untrusted key: not a reply; absence | §4.2 |
| `mailbox-reply-to-other-request` | a genuine reply event delivered for another request: not a reply; absence | §4.2 check 2 |
| `mailbox-no-reply` | no event before the deadline: an absence whose window closes at the deadline and whose route is the mailbox | §5.3 |
| `mailbox-late-reply-after-absence` | no event before the deadline, then reply event 1, delayed by the relay, after the absence is recorded: the absence record is unchanged, and the late event is a reply that verifies as in `mailbox-exchange` and cites the request's digest and event id | §5.3, §6 |
| `mailbox-no-deadline-no-reply` | a request with no deadline and no `expiration` tag: the window closes at the local timeout | §4.1, §5.3 |

The test also shows each check of §4.2 that has a vector failing when the check is removed. Checks
1, 3 and 4 have no vector in this revision, and the order of the checks is not exercised.

The workflow `.github/workflows/nostr-mailbox.yml` regenerates the vectors, fails when the
committed files differ, and runs the test. No relay is contacted, in the vectors or in CI.

## 10. Open points

- **N-1. Event kinds.** `4700` and `4701` are placeholders. They are absent from the kind list at
  the pinned NIPs commit and outside NIP-90's range. They are not registered or proposed anywhere.
  They stay placeholders in this experimental text. A NIP or registered kinds are proposed only
  once a second, independent implementation exists.
- **N-2. A reply after the absence.** Resolved in §5.3: the absence record stays as written, and
  the late reply is its own later fact, citing the request.
- **N-3. Encryption.** NIP-44 and NIP-59 (§8) are not specified in v0. Until they are, §8 limits
  where this binding may be used.
- **N-4. The relay list member.** The responder's declared relay list is carried in its
  commitment (§4.3). The member's name and shape are fixed where the commitment profile is
  specified. This binding defines no field name. Two things the commitment profile has to settle:
  ER already lets a retention commitment carry "a `route` at which the responder expects to be
  reachable" [ER §9], which could hold the `nprofile` of §5.3; and IP says a discovery object MUST
  NOT contain a route [IP §11.4.3], so the relay list cannot simply go in the manifest.
- **N-5. Learning the mailbox key.** How the responder publishes its mailbox key is outside v0.
  The requester has to trust the source (§3), and the natural one is the commitment that carries
  the relay list (N-4).
- **N-6. Promotion.** A binding token for this carriage, and its place in IP §11.4, are a proposal
  to make once the vectors and drift check pass, not a decision this document makes.

## References

- ER: `draft-mih-agent-evidence-request-00`, `spec/draft-mih-agent-evidence-request-00.md`.
- IP: Minimum Evidence Interoperability Profile v0, `spec/interop-profile-v0.md`.
- NIP-01, NIP-19, NIP-21, NIP-40, NIP-44, NIP-59, NIP-65, NIP-90, NIP-94 (informative): §2.
- BIP-340 (informative): §2.
- RFC 4648, The Base16, Base32, and Base64 Data Encodings: §4 (base64url).
