# Adapter declaration: Nostr mailbox carriage — v0 (EXPERIMENTAL)

**Status.** EXPERIMENTAL. Informational adapter declaration, kept in this repository. It is not
part of any Internet-Draft revision and changes no posted draft or profile. It declares the one
foreign object the experimental Nostr mailbox carriage handles, the NIP-01 event, using the five
declarations the other adapter declarations in this directory make. The carriage itself is
specified in [`../bindings/nostr-mailbox-v0.md`](../bindings/nostr-mailbox-v0.md), cited here as
NMB. The Minimum Evidence Interoperability Profile `evidence-interop/1`
([`interop-profile-v1.md`](../interop-profile-v1.md)), whose exchange NMB carries, is cited as IP. No binding token exists for
this carriage, and none appears in a conformant manifest (NMB Status; IP §11.4.2).

**Answer in one paragraph.** A Nostr event is signed, so it has a native check: recompute its `id`
and verify its BIP-340 signature under its `pubkey` (NIP-01). That check establishes which Nostr key
published the event, and nothing about the evidence it carries. The event is carriage. Its key is
the responder's mailbox key, which is a route, not the responder's identity (NMB §3). So the event's
native check decides only whether the event is attributed to the mailbox, one of the two ways into
the reply position (NMB §4.2). An event that fails it is still in the reply position, and carries a
reply, when its content is the responder's signed answer to the request. The check never enters IP's property catalogue or §8 mapping. The evidence inside, the envelope or refusal, is
verified by IP unchanged, under the responder's Ed25519 key.

## 1. What was read

The sources and pinned digests are NMB §2. This declaration uses NIP-01 (event format, `id`
serialization, signature) and BIP-340 (Verify) from that table.

## 2. The five declarations: the NIP-01 event

**(a) Object and format.** A NIP-01 event of kind `4700` (request event) or `4701` (reply event),
as a JSON object with members `id`, `pubkey`, `created_at`, `kind`, `tags`, `content` and `sig`
(NMB §4). The event is not digested or carried as evidence. What matters is the octets its
`content` decodes to (NMB §5.1).

**(b) Issuer.** The holder of the key in `pubkey`: for a reply event, the mailbox key the request
addressed (NMB §4.2 check 7); for a request event, the requester's carriage key. Neither is
resolved by the relying party's trust policy, and neither is mapped to a party. A trust policy
under IP holds Ed25519 responder keys [IP §7.2]. The mailbox key is not one of them, and an event
signed by it never makes a reply trusted.

**(c) Native verification method.** NMB §4.2 checks 5 and 6:

1. Serialize `[0, pubkey, created_at, kind, tags, content]` as NIP-01 fixes, and compare SHA-256 of
   its UTF-8 octets with `id`.
2. Verify `sig` under `pubkey` over the 32 octets of `id`, by BIP-340 Verify.

The rest of NMB §4.2 (kind, author, reply-to, media type, content encoding) is carriage logic,
not part of the native check.

**(d) Supported predicate.** *The holder of the key `K` published an event naming request event
`R`, with content `C`.* Nothing more. When `K` is the mailbox key, the event is in the reply
position (NMB §4.2). It does not establish that the responder produced `C`, that
`C` is evidence, or that `K` belongs to the responder. Those come from IP's verification of `C`
[IP §6.2, §6.3, §7].

**(e) Per-event result.** Not an IP property, and not reported under IP §7.1 or mapped by IP §8.1:

| Result | Meaning | Consequence |
|---|---|---|
| `reply` | every check of NMB §4.2 holds | the decoded content goes to IP §7 as a reply |
| `reply_by_content:<check>` | the format checks hold, the named attribution check (`id`, `signature`, `author`) failed first, and the content proves itself (NMB §4.2, reply by content) | the decoded content goes to IP §7 as a reply |
| `not_a_reply:<check>` | the named check of NMB §4.2 failed first (`kind`, `reply_to`, `media_type`, `content`), or an attribution check failed and the content did not prove itself, or an attribution check failed beyond the requester's limit on replies by content (`limit`, NMB §4.2) | a transport condition [IP §9.2]; the request stays pending, then becomes an absence |
| `duplicate` | an event whose `id` was already taken as a reply | ignored; it is the same event |

## 3. Why the native check is not a property

IP reports properties of evidence: envelopes, refusals and their bindings [IP §7.2]. A Nostr event
is the carriage's container, as an A2A `Artifact` or an MCP tool result is in IP §11.4. IP keeps
both apart from the canonical Artifact, and says an A2A `Artifact`'s own fields "are never signed or
verified" [IP §11.4]. A Nostr event is signed, unlike those two. Its signature is still a carriage
signature: it protects the relay hop and decides which events are attributed to the mailbox
(NMB §4.2, checks 5 to 7). Reporting it as an evidence property would let a mailbox key appear to
vouch for a reply, which NMB §3 rules out.

## 4. Conformance vectors

In `vectors/adapters/nostr-mailbox/`, listed in NMB §9. Each event's native check is recomputed by
`python/tests/test_nostr_mailbox_vectors.py` with its own BIP-340 code, which is itself checked
against BIP-340 test vectors 0, 1, 5, 6, 12, 13 and 14 and against the events published in NIP-59.
Vectors `mailbox-event-tampered` and `mailbox-event-bad-signature` are the two native-check
failures: the first carries content that proves nothing, and the second content that proves itself.
All vectors are constructed. No relay was contacted to make them.

## 5. Open points

The binding's open points are NMB §10. One is specific to this declaration:

- **A-1.** NIP-01 fixes which characters of `content` are escaped and requires every other
  character verbatim. The vectors use printable ASCII only, with no character NIP-01 escapes in
  `content`, so the escaping rules are not exercised. Base64url content (NMB §4) has no such
  character. Tags (relay URLs, media types) are printable ASCII here too; a serializer that escapes
  `/` would compute a different `id` for them.
