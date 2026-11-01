# Evidence Commitment Carriers — v0 (EXPERIMENTAL)

**Status.** EXPERIMENTAL. Informational carrier binding, kept in this repository. It is not an
Internet-Draft, it is not part of any Internet-Draft revision, and it changes no posted draft. It
is not part of the Minimum Evidence Interoperability Profile `evidence-interop/0`
([`interop-profile-v0.md`](../interop-profile-v0.md), cited here as IP) and defines no binding
token. It builds on the experimental Nostr mailbox carriage
([`nostr-mailbox-v0.md`](nostr-mailbox-v0.md), cited here as NMB). Its vectors are in
`vectors/adapters/evidence-commitment-carriers/` (§10).

**Answer in one paragraph.** A responder that answers evidence requests can say so to strangers
by publishing one signed **evidence commitment**: how to ask it, what it answers, its signed
disclosure-policy digest, how long an asker should wait, its latest checkpoint and one stapled
history card per evidence stream. It carries no counts. This document puts the same commitment
octets on three carriers: an attestation entry in a directory record (an ARD file, a NANDA Index
or AI Catalog record), an extension entry in an A2A Agent Card, and an addressable Nostr event.
The carriers differ only in how a stranger finds them. A verifier ignores everything a carrier
says except where the octets are. It verifies the commitment's own signature, its staples and its
`issued_at`, relies on it for a responder only when that responder's signed answers are under the
commitment's key, and labels each stream witnessed or unwitnessed from the receipts it can check
itself. Finding a commitment confers no trust.

ER is `draft-mih-agent-evidence-request-00` (`spec/draft-mih-agent-evidence-request-00.md`).
Section numbers are those of its rendered `.txt`.

## 1. What this is, and what it is not

The commitment is a separate, opt-in disclosure. It carries a checkpoint, history cards and an
`issued_at`, each of which IP forbids in a discovery object [IP §11.4.3]. So:

- A commitment MUST NOT be placed inside a discovery object: the manifest, the evidence-request
  A2A extension entry [IP §11.4.4] or the MCP tool definitions [IP §11.4.5]. Each carrier below
  gives it a place of its own.
- A responder publishes a commitment only when its operator turns publishing on. The default is
  off: with publishing off, a responder publishes no commitment and no carrier entry.
- Advertising changes neither who may ask nor what is answered. A responder that publishes no
  commitment still answers under IP.

This document names no registry, no relay, no directory operator and no NIP. It defines no new
cryptography: the commitment is signed with Ed25519 [IP §6.2], and the Nostr event as NIP-01 fixes.

## 2. What was read

| Source | Version | Sections used |
|---|---|---|
| Agentic Resource Discovery (ARD) | v0.91, <https://agenticresourcediscovery.org/spec/>, read 2026-11-01, page SHA-256 `aae28848be8a33ccefc208a4356aed4cf5c487e94b5f2772f8ece0ac73259fcb` | §4.5 (the `trustManifest` term, open schema; "ARD reads only identity"), §4.5.2 (the attestation `digest` "covers the referenced attestation document itself"), §5.3 (filter on `trustManifest.attestations.type`), §5.1 (`/.well-known/ard.json`) |
| NANDA Index v2 record types | `projnanda/nanda-index-v2` commit `6d08daac6b2642159781435c79bb6f70faa79702`, `server/src/types/api/index-record.ts`, SHA-256 `338756790ef3a9dafcc51a0abaee90bcc36239481c429a53433857eb245a5460` | `Attestation` (`type`, `uri`, `mediaType`, `digest?`, `size?`, `description?`), `TrustManifest.attestations`, `IndexRecord.tags`, `trust_manifest_verified` (always `false`) |
| A2A Protocol | v1.0.1, as pinned by IP §2 (`docs/specification.md` SHA-256 `627ccfe6ffb1be2c56811c3dcc18780deb419f41cdc98248095c939b2d9dc9cb`, `specification/a2a.proto` SHA-256 `e195bf96ab630c69797851970203e1b2b6b19528f2e9803b7d904b91a5104016`) | §4.4.3 `AgentCapabilities`, §4.4.4 `AgentExtension` (`uri`, `description`, `required`, `params`), §4.6.1 extension declaration |
| NIP-01 | `nostr-protocol/nips` commit `0b54c4d1c70b046fbb2e3c599c09b641e00f5dcd`, as NMB §2 pins it | events and signatures; Kinds (the addressable range `30000 <= n < 40000`, "addressable by their `kind`, `pubkey` and `d` tag value"); single-letter tags indexed by relays |
| NIP-19, NIP-21 | same commit, as NMB §2 pins them | `naddr` (TLV `0` the `d` value, `1` relay, `2` author, `3` kind, 32-bit big-endian); the `nostr:` URI |
| NIP-24 | same commit, `24.md`, SHA-256 `1caddcaf0b6c5a626b41054910ab77e9a9ac7267e566b6ba92f9dedb599d3026` | the `t` tag ("a hashtag. The value MUST be a lowercase string") and the `r` tag ("a web URL the event is referring to") |
| NIP-65 | same commit, as NMB §2 pins it | read relays |
| NIP-94 | same commit, as NMB §2 pins it | the `x` tag ("the SHA-256 hexencoded string of the file") |
| NIPs README | same commit, `README.md`, SHA-256 `4f79971a6dbdb5be713ea523fd94d2fabe7a94c0c31230410938e247003b7269` | the kind list (only to avoid a listed kind, §5.3) |
| BIP-340 | as NMB §2 pins it | Verify |

All are informative references. The sources were read only. Nothing was posted to them.

## 3. The commitment

The commitment's profiles are `evidence-commitment/0` and `evidence-commitment/1`. The profile
fixes the full member list and refuses any member beyond it; it is specified outside this
document. This document reads only the members below, and a verifier of this document applies no
other member rule.

| Member | Read for |
|---|---|
| `profile` | the profile; also the type of the directory entry (§5.1) |
| `node_id` | 64 lowercase hex: the responder's node identifier; the Nostr event's `d` (§5.3) |
| `key_id` | 64 lowercase hex: the responder's Ed25519 public key, raw. The commitment's key (§6, V2 and V5) |
| `spki` | base64: the same key as DER SubjectPublicKeyInfo |
| `issued_at` | `YYYY-MM-DDTHH:MM:SSZ`: when the responder signed it (§6, V4) |
| `checkpoint.bytes`, `checkpoint.sha256` | the latest checkpoint, base64, and its SHA-256 in 64 lowercase hex (V3) |
| `history_cards[]` (`/1`) | one stapled card per stream: `stream`, `checkpoint_key` (base64url DER SPKI, optional), `bytes` (base64), `sha256` (V3, §7) |
| `history_card` (`/0`) | one stapled card; read as a list of one |
| `ask.nostr` (`/1`, optional) | the Nostr route (below) |
| `sig` | `{"alg": "Ed25519", "canon": "jcs", "value": <base64url>}` |

**Signing.** The signed octets are the commitment without `sig`, in JCS (RFC 8785). The signature
is Ed25519 (RFC 8032) over them, verified under the key in `spki`.

**The Nostr route, `ask.nostr`.** A responder that is asked through the Nostr mailbox (NMB) or
announces on Nostr (§5.3) carries `ask.nostr`, an object with exactly two members, both required
when it is present:

| Member | Value |
|---|---|
| `ask.nostr.mailbox_key` | the mailbox key [NMB §3]: secp256k1, BIP-340 x-only, 64 lowercase hex |
| `ask.nostr.relays` | a non-empty list of distinct `wss://` URLs: the relays the responder reads (NIP-65 read relays) [NMB §4.3], and the relays it announces to (§5.3) |

The two members travel together: a mailbox key without relays cannot be reached, and relays
without a key address nobody. A commitment profile that carries this route uses these names and
this shape. They settle NMB's open points N-4 and N-5. `ask.nostr` is not a binding token, since
NMB defines none (its Status and N-6), so it is not listed in `ask.bindings`.

**Which route to use.** A requester takes `ask.nostr` only from a commitment that passes V0 to V4
(§6) and whose `key_id` is a responder key its trust policy accepts for the responder it means to
ask [IP §7.2, `responder_trust`]. That commitment is the trusted source NMB §3 requires. V5 cannot
come first, because no answer exists before the first ask. A commitment whose `key_id` the policy
does not accept for that responder is a route to whoever holds that `key_id`: answers through it
are bound to that key alone (V5), and a failure among them is never adverse to another
responder [NMB §3].

## 4. Digests

A **commitment digest** is SHA-256 over the commitment octets exactly as served, never over a
re-serialization. A directory entry and an A2A entry write it `sha256:` followed by 64 lowercase
hex. The Nostr `x` tag writes the 64 lowercase hex alone, as NIP-94 does.

The commitment embeds the latest checkpoint, so its octets change at every checkpoint. A digest in
a carrier names one version and goes stale. A digest that does not match the octets is a carrier
fact, never a reason to reject octets that verify (V1).

## 5. Carriers

### 5.1 Directory record: the attestation entry

An ARD entry (in `/.well-known/ard.json`) or a NANDA Index or AI Catalog record carries one entry
in `trustManifest.attestations[]` (`trust_manifest.attestations[]` in an index record):

| Member | Value |
|---|---|
| `type` | the commitment's `profile`, `evidence-commitment/1` or `evidence-commitment/0` |
| `uri` | where the commitment octets are served: an `https:` URI, or the `nostr:` `naddr` of the responder's announce event (§5.3) |
| `mediaType` | `application/json` |
| `digest` | the commitment digest, `sha256:<hex>` (§4) |
| `description` | fixed text, for example "Answers evidence requests about its own records; verify the commitment, not this entry" |

The entry carries no `size`: a size in a carrier is a count. A record that carries the entry
SHOULD also list `evidence-request` in its `tags`, so that a directory search can filter on it.
ARD leaves the trust manifest's schema open and reads only `identity` [ARD §4.5], and the index
stores manifests unverified (`trust_manifest_verified` `false`). Both match V1: the entry is a
pointer, and the commitment is what is verified.

### 5.2 A2A Agent Card: the commitment extension entry

An Agent Card carries the commitment pointer in its own `AgentExtension` in
`capabilities.extensions` [A2A §4.4.3, §4.4.4, §4.6.1]:

| Field | Value |
|---|---|
| `uri` | exactly `https://github.com/action-state-group/agent-action-capsule/blob/main/spec/bindings/evidence-commitment-carriers-v0.md` |
| `description` | fixed text, for example "Points to this agent's signed evidence commitment; verify the commitment, not this entry" |
| `required` | `false` |
| `params` | exactly `{"commitment_uri": <https: URI>, "commitment_digest": "sha256:<hex>"}` |

The URI is compared as a string and is not dereferenced. `required` is `false` because a client
that ignores the entry still works [A2A §4.4.4]. The entry is kept apart from the evidence-request
entry of IP §11.4.4: that entry's `params` is the manifest and nothing else, and a card whose
evidence-request entry carries a commitment member breaks IP §11.4.3 (V0, `discovery_object`). A
card's JWS, when present, authenticates the card. Its signer is not compared with `key_id` (V5).

A2A has no directory. A stranger reaches the card through a known domain or through a directory
record that lists the card.

### 5.3 Nostr: the announce event

The responder publishes one NIP-01 event, signed by its mailbox key (`ask.nostr.mailbox_key`),
to every relay in `ask.nostr.relays`:

| Field | Value |
|---|---|
| `kind` | `34700` |
| tag `d` | exactly one: `["d", <node_id>]` |
| tag `t` | exactly one: `["t", "evidence-commitment"]` (NIP-24) |
| tag `x` | exactly one: `["x", <commitment digest, 64 lowercase hex>]` (NIP-94) |
| tag `r` | optional, at most one: `["r", <https: URI where the commitment octets are served>]` (NIP-24) |
| `content` | the commitment octets in base64url without padding, as the mailbox kinds carry octets [NMB §4]; or the empty string (Size, below) |

`34700` is in NIP-01's addressable range, so a relay keeps the latest event per mailbox key and
`d`, and a republished commitment replaces the last. It is absent from the kind list at the pinned
commit, and it is a placeholder, not registered anywhere (C-1). It is separate from the mailbox
kinds `4700` and `4701` [NMB §4].

**Find.** A stranger subscribes with `{"kinds": [34700], "#t": ["evidence-commitment"]}` on relays
it knows of; with `{"kinds": [34700], "#d": [<node_id>]}` for a node it already knows of.

**Address.** The event's address, for a directory entry's `uri` (§5.1), is the NIP-21 `nostr:` URI
of a NIP-19 `naddr` whose `d` value is `node_id`, whose author is the mailbox key, whose kind is
`34700` and which carries at least one relay from `ask.nostr.relays`. Without a relay hint a reader
does not know where to ask.

**Size.** Relays cap event size, and the checkpoint and cards count toward it. A commitment is
signed over every member, so an event never carries an edited commitment: one with its card
octets removed fails its signature (V2). A responder whose commitment does not fit puts the empty
string in `content`, keeps the `x` tag, and adds an `r` tag when it can serve the octets
elsewhere. A reader then fetches the octets from `r`. Without `r` the responder is not findable on
this carrier (C-2).

**Attribution.** After the commitment verifies (§6), an event whose `pubkey` is the commitment's
`ask.nostr.mailbox_key` and whose `d` is the commitment's `node_id` is **announced** by the
responder. Any other event carrying the same octets is **relayed**. Either way the octets are the
same, and they are what is verified. The author is never compared with `key_id` (V5).

## 6. Verify (every carrier)

A verifier applies these steps to every commitment it obtains, from any carrier. The first step
that fails names the result.

- **V0, carrier form.** The entry has the form its carrier section gives (§5.1, §5.2 or §5.3), and
  for A2A the evidence-request entry carries no commitment member. A failure names the carrier
  check (`directory_entry`, `a2a_entry`, `discovery_object`, `nostr_event`). For a Nostr event the
  form includes its NIP-01 `id` and BIP-340 signature. The entry is then not read.
- **V1, octets.** Take the octets: from `content` when it is not empty, otherwise from the `uri`,
  `commitment_uri` or `r` tag. A carrier digest that does not match the octets is reported as
  `digest_mismatch` and changes nothing else: for a URI it means the pointer is stale. The octets
  are verified on their own, below.
- **V2, signature.** The octets parse as a JSON object with a `profile` of §3; `key_id` is the raw
  key of `spki`; and `sig` verifies over the JCS of the rest under `spki`. Failures:
  `commitment_form`, `key_id_spki`, `commitment_signature`. A commitment that fails here is
  refused, whichever carrier brought it.
- **V3, staples.** `checkpoint.sha256` and every card's `sha256` are the SHA-256 of their decoded
  `bytes`. Failure: `staple_digest`. This document reads the top-level `checkpoint` for nothing
  else: V6 and §7 work per stream, from each card's last checkpoint.
- **V4, newest wins.** A commitment whose `issued_at` is later than the verifier's time plus the
  clock skew it configures is **future_dated** and takes no part in this step, so a commitment
  signed with a wrong clock cannot supersede every later one. Among the other commitments that
  pass V2 and V3 with the same `key_id` and `node_id`, the one with the latest `issued_at` is
  **current**; the others are **superseded**. Two with the same `issued_at` and different octets
  are **conflicting**: the responder's key signed both, and neither is current until the verifier
  reads, from any carrier, one with a later `issued_at`. Arrival order and carrier never decide.
- **V5, key binding.** `key_id` is proven only by the Ed25519 signature on the responder's
  evidence answers, an envelope [IP §6.2] or a refusal [IP §6.3], on whatever channel they arrive.
  A verifier relies on a commitment for a responder only when that responder's answers verify under
  `key_id`. A commitment under another key does not describe that responder (`key_mismatch`). The
  mailbox key, the Nostr event author and an A2A card's JWS signer are never compared with
  `key_id`: they are routes or carriage, not the responder's identity [NMB §3; ER §3.6].
- **V6, still extended.** This step is per stream. The **held checkpoint** of a stream is the
  asker's first-use pin for (`key_id`, `stream`) (§7), or, with no pin, the card's last
  checkpoint. Offline, a card whose last checkpoint is earlier than the held checkpoint (a smaller
  log size), or whose checkpoint at the held checkpoint's log size is a different one, is
  **behind_pin**: the log was cut back or forked, and the stream is not relied on. Before relying on
  a stream, the verifier asks the responder a `checkpoints` request for it with
  `coverage.expected_pin` set to the held checkpoint's digest [ER §3.2]. The answer relies only if
  it carries a checkpoint at or past the card's last checkpoint and a consistency proof from the
  held checkpoint to it, verified offline. An answer that stops at or before the held checkpoint,
  or does not prove consistency, is treated as ER treats an unverifiable artifact.
- **V7, no trust from discovery.** Passing V0 to V5 means the commitment is the responder's own
  signed statement, and nothing more. Admission policy reads the cards (§7).

To learn a newer commitment, the verifier reads the carriers again. This revision defines no
request for the commitment itself (C-3).

## 7. Witness label and first use

**Witnessed.** A stream's receipt counts when the card's checkpoint it covers is signed by the
stream's `checkpoint_key`, the receipt names that checkpoint's digest, and the receipt's signature
verifies offline under a witness key in the verifier's own configuration. A stream with at least
one counted receipt is labelled `witnessed`, with the witness key and the timestamp of the earliest
checkpoint it covers.

**Unwitnessed.** The verifier derives the label; the responder never sets it, so it cannot lie
about it. A stream whose card carries no receipt is labelled `unwitnessed`: its log age and timing
are the responder's own word. A stream whose receipts are all under keys the verifier does not
configure, or do not verify, is labelled `unknown_witness`: a responder can mint receipts of its
own. A stream without a `checkpoint_key` has no receipt counted. A stream whose card carries
receipts of which none counts is labelled `unknown_witness`. The label is not a failure: an
unwitnessed commitment still passes V0 to V5, and admission policy decides. A policy MAY refuse
unwitnessed responders.

**A label is the log's, not the responder's.** Nothing in a card binds its log to `key_id`: the
log key need not be the responder's key, and another commitment can staple the same public card.
So a label, and the age it gives, describe the log signed by `checkpoint_key`. The verifier
reports each label with that `checkpoint_key`. Whether that log key is right for the responder is
the relying party's policy, as it is for any checkpoint [IP §6.2.1; P-31], and an admission policy
that relies on a stream's witnesses or age accepts the log key for that responder first.

**Trust on first use.** For every (`key_id`, `stream`) pair, the asker keeps the first checkpoint
it saw: its digest, and when the asker saw it. Every later answer for that stream must prove
consistency from that pin (V6). A stream missing from a later current commitment is shown as
`dropped` since the time the asker first saw it missing, and a stream not seen before as `new`
since the time it first appeared. A responder that restarts a log under a new stream name is never
shown as continuing the old one. Pins are per `key_id`: a commitment under a new key starts with
no pins and inherits nothing.

The vectors fix a card format for testing only, the one of
[`inference-service-history-profile-v0.md`](../inference-service-history-profile-v0.md) §9: a card
`{anchor, derivation, evidence_stream, history, subject}` whose `history` entries are
`{checkpoint, receipts}`. This document does not register a card format.

## 8. What a carrier can and cannot do

| A carrier, or whoever controls it, can | What the verifier sees | Result |
|---|---|---|
| serve stale octets | an older `issued_at` | superseded by a newer commitment from any carrier (V4); V6 catches a log that stopped |
| sign a short card, cut back below a pin | a card's last checkpoint earlier than the held one | `behind_pin` (V6) |
| staple another responder's public cards | cards whose `checkpoint_key` is that responder's log key | the labels carry that log key; the relying party's policy decides whether it is this responder's (§7) |
| point at another responder's commitment | a commitment under that responder's key | `key_mismatch` for the responder it is asked about (V5) |
| alter the octets | a signature that fails | refused, `commitment_signature` (V2) |
| keep a digest that does not match | `digest_mismatch` | the octets are verified on their own (V1) |
| re-post a commitment under another Nostr key | an author that is not the mailbox key | relayed, the same verified octets (§5.3) |
| take over a domain and replace card and commitment | a commitment under a new `key_id` | a different responder; no pin carries over (§7) |
| hide or drop the entry | nothing | other carriers still work |

| A carrier cannot | Why |
|---|---|
| make a commitment that verifies | it does not hold the responder key |
| mark a stream witnessed | the label comes from receipts under keys the verifier configures (§7) |
| make a newer commitment lose to an older one | V4 compares signed `issued_at`, not carrier or arrival; a future-dated one takes no part |

## 9. Privacy considerations

Publishing a commitment discloses, to everyone, what IP keeps out of discovery: that the
responder keeps evidence streams, their latest checkpoint, its history cards with their witnesses
and timing, and its routes. That is why publishing is opt-in and off by default (§1). The card is
safe to serve under the digests-only tier [ER §8.1], but it is history, and a responder that would
not publish its history MUST NOT publish a commitment. Over Nostr the announce event, its relays
and the mailbox key are public [NMB §8].

## 10. Vectors

The vectors are in `vectors/adapters/evidence-commitment-carriers/`.
`python/scripts/generate_evidence_commitment_carriers_vectors.py` generates them
deterministically, and `python/tests/test_evidence_commitment_carriers_vectors.py` checks them
offline with its own code: Ed25519 for commitments, checkpoints and receipts, NIP-01 `id` and
BIP-340 for events (NMB's checks), and bech32 for `naddr`. Answers for V5 are envelopes of the IP
corpus, verified by IP's reference verifier. Each case carries the carrier entries, the octets each
URI serves, the verifier's witness configuration and, where it applies, the answer and the pins,
with the expected result of every step.

| Case | What it shows | Sections |
|---|---|---|
| `three-carriers-one-commitment` | the same commitment through a directory entry, an A2A entry and a Nostr event: one digest, verified once, current, key bound, stream `witnessed`, the event announced | §5, §6, §7 |
| `directory-entry-naddr` | a directory entry whose `uri` is the announce event's `naddr`: resolved to the event, same octets | §5.1, §5.3 |
| `nostr-over-size-r-tag` | an event with empty `content`, its `x` digest and an `r` URI: octets fetched from `r` | §5.3 |
| `nostr-relayed-by-other-key` | the genuine commitment in an event by another key: verified, relayed | §5.3 |
| `forged-carrier-entry` | a Nostr event whose content is the commitment with a member changed: refused, `commitment_signature` | §6 V2, §8 |
| `forged-key-id` | a commitment signed under one key whose `key_id` names the responder: refused, `key_id_spki` | §6 V2 |
| `stale-digest` | a directory entry whose digest names an older version: `digest_mismatch`, the octets verify | §4, §6 V1 |
| `staple-digest-mismatch` | a commitment, signed as it is, whose card digest is not its card bytes' SHA-256: refused, `staple_digest` | §6 V3 |
| `answer-key-mismatch` | a valid commitment under another key, and an answer signed by the responder: `key_mismatch` | §6 V5 |
| `older-beside-newer` | two valid commitments under one key from two carriers: the later `issued_at` is current, the other superseded | §6 V4 |
| `same-issued-at-conflict` | two valid commitments with one `issued_at` and different octets: conflicting, none current | §6 V4 |
| `unwitnessed-labelled` | two streams, one with no receipt and one with a receipt under an unconfigured witness: verified, labelled `unwitnessed` and `unknown_witness` | §7 |
| `first-use-dropped-and-new` | pins from an earlier commitment, and a current one that drops a stream and starts another: `dropped` and `new` | §7 |
| `short-card-behind-pin` | a newer commitment whose card's last checkpoint is earlier than the asker's pin: `behind_pin` | §6 V6, §7 |
| `future-dated-issued-at` | a valid commitment dated past the verifier's time and clock skew, beside the current one: `future_dated` | §6 V4 |
| `a2a-commitment-in-discovery-object` | the commitment pointer in the evidence-request entry's `params`: `discovery_object`, not read | §5.2, §6 V0 |
| `nostr-event-bad-signature` | an announce event whose signature does not verify: `nostr_event`, not read | §6 V0 |

The workflow `.github/workflows/evidence-commitment-carriers.yml` regenerates the vectors, fails
when the committed files differ, and runs the test. No relay, directory or host is contacted. V6
needs a live responder for its request; its offline part, `behind_pin`, has a vector.

## 11. Open points

- **C-1. Event kind.** `34700` is a placeholder in the addressable range, unregistered, as NMB
  N-1 treats the mailbox kinds. A NIP or a registered kind is proposed only once a second,
  independent implementation exists.
- **C-2. Over the size cap with nowhere to host.** Such a responder is not findable on Nostr. Its
  commitment can still reach a stranger through a directory record with an `https:` URI.
- **C-3. Asking for the commitment.** The verifier rereads carriers for a newer commitment. A
  request for the responder's current commitment over the mailbox or A2A is not defined: V6 needs
  only the checkpoint pin, and re-reading the carriers serves the size fallback except for C-2.
- **C-4. The extension URI.** The A2A entry's URI names this document. If the text moves into an
  Internet-Draft, the URI moves with it, as IP's extension URI names its draft [IP §11.4.4].
- **C-5. A directory type URI.** The directory entry's `type` is the profile string. A URL type is
  not proposed; no registry is.

## References

- ER: `draft-mih-agent-evidence-request-00`, `spec/draft-mih-agent-evidence-request-00.md`.
- IP: Minimum Evidence Interoperability Profile v0, `spec/interop-profile-v0.md`.
- NMB: Nostr Mailbox Carriage v0, `spec/bindings/nostr-mailbox-v0.md`.
- ARD v0.91, NANDA Index v2, A2A v1.0.1, NIP-01, NIP-19, NIP-21, NIP-24, NIP-65, NIP-94, BIP-340
  (informative): §2.
- RFC 8032 (Ed25519), RFC 8785 (JCS), RFC 4648 §5 (base64url).
