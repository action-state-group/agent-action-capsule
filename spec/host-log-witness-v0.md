# The Host Log Witness: One Witnessed Checkpoint for Many Holders, v0

**Status.** Informational, pre-Internet-Draft, kept in this repository. It changes no
Internet-Draft. [`witnessed-checkpoint-v0.md`](witnessed-checkpoint-v0.md) (cited as WC) carries
its host chain (§6). It defines how a host that runs the shelves of many holders has one
checkpoint of its own witnessed per interval and gives each holder a chain, the **host chain**,
from that holder's shelf checkpoint to the witnessed host checkpoint. It also defines how a
receiver checks a host chain.

The evidencebook library (<https://github.com/action-state-group/evidencebook>, cited as EBL)
implements it (evidencebook#1085). The design is `parent-log-witness/v1` of
`draft-mih-zhang-agent-disclosure-bundle-04` (cited as PLW, §"The parent-log-witness/v1
Extension") one level up, with three differences:

- The parent log is the host's, signed by the host's key, not the holder's.
- Each holder has a fixed position in each tick's tree.
- The tree's parameters are committed in the parent log's entry.

The kind string `host-log-witness/v1` names the object's version, as `parent-log-witness/v1`
does, while this document is `-v0`, a pre-Internet-Draft. A host chain is not a Bundle extension. It travels beside a holder's stamp proof, as WC's
receipts do, and never inside a Bundle.

## Dependency boundary

**Owns:** the host, its members, the host log and its ticks (§2), the host chain object (§3),
and its checks and result (§4).

**Uses unchanged:**

| Tag | Document | What this document takes from it |
|---|---|---|
| PLW | `spec/draft-mih-zhang-agent-disclosure-bundle-04.md`, the `parent-log-witness/v1` extension | the leaf, interior node and root fold of the tree; the shape of `parent`, with its `inclusion_proof` and `witnesses`; the CLL consistency proof object of `earlier.consistency_proof` |
| SF | `spec/shelf-forms-v0.md` | holder, shelf log, shelf checkpoint, stamp proof (§5) |
| WC | `spec/witnessed-checkpoint-v0.md` | the follow-up that carries a host chain, and the receiver's handling of it (§4, §5) |
| WIT | `vectors/bundle/strict/README.md`, "The rules", `witnesses` | how one receipt is checked against a checkpoint's COSE statement, with status `pass`, `withheld` or `fail` and its `registration_time` |
| CLL | the Checkpointed Local Log, as SF cites it | checkpoint statements, MMR inclusion and consistency proofs and their verification |

**Does not define:** which witness a host uses, or which witnesses a receiver trusts. It does
not define how a holder joins or leaves a host, or how a host decides when a tick is due. It
defines no conformance vectors (§8).

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

SF's terms apply. In addition:

- **Host:** a party that keeps a CLL log of its own, the **host log**, signed by the **host key**,
  and has that log's checkpoints witnessed on behalf of the holders that joined it.
- **Member:** a holder that joined a host. A member is identified by its **member id**, the pair
  of its checkpoint key id and its shelf log's log id. Two holders may share a log id (WC §5.3);
  they are still two members.
- **Head:** the newest shelf checkpoint a member handed to its host before a tick.
- **Tick:** one entry of the host log: the commitment to one tree over the members' heads.
- **Host checkpoint:** a CLL checkpoint of the host log.

## 2. The host

### 2.1 Joining is opt-in

A holder stamps its own shelf log, with its own witness, unless it joins a host. Joining MUST be
the holder's own choice. A host or profile MUST NOT make it the default. §7 says what a member
gives up: a holder that does not trust its host's operator stays unjoined.

### 2.2 A tick

At each tick, the host:

1. Draws a fresh **tick salt**: 32 octets from a cryptographically secure source.
2. Computes each member's **slot**: the integer whose 8 octets, read big-endian, are the first 8
   octets of SHA-256(tick salt ‖ key id ‖ 0x00 ‖ log id), taken modulo 2^32. Here key id and log
   id are the UTF-8 octets of the member's checkpoint key id and log id. If two members have the
   same slot, the host draws a new tick salt and computes every slot again, until no two members
   share a slot. A host MUST NOT leave a member out of a tick because of a collision.
3. Places at each member's slot the leaf of its head, as PLW forms a leaf: SHA-256 of 0x00 ‖
   JCS({`checkpoint_sha256`, `log_id`, `salt`, `size`}). `checkpoint_sha256` is the SHA-256 of
   the head's COSE octets, `size` is its MMR size, and `salt` is a fresh random string of at least
   256 bits for each leaf.
4. Computes the root of a binary tree of depth 32 by PLW's interior node. Every subtree that
   holds no member's leaf takes, as its root, a value only the host can derive from a secret seed
   of the tick and the subtree's level and index, for example HMAC-SHA-256(seed, uint8(level) ‖
   uint32be(index)). Such a value SHOULD be indistinguishable from a hash to anyone without the
   seed. The host computes only the nodes above the members' leaves, about 32 hashes per member
   per tick, and never the empty positions one by one. A seeded value is never a leaf: it stands
   only for a subtree where no member's slot is.

   The depth is 32, not the 16 of EBL's cadence tree, so that slot collisions are rare at any
   number of members (§2.2 step 2 redraws the salt on one): with N members, a draw has no
   collision with probability about exp(-N²/2^33), above one half at the maximum of 2^16 members.
   At depth 16 the same holds only for a few hundred members.
5. Appends one entry to the host log, whose 32-octet value is the **tick value**: SHA-256 of
   0x04 ‖ uint8(32) ‖ tick salt ‖ root. The 0x04 octet separates it from PLW's leaf (0x00) and
   node (0x01). uint8(32) is the tree depth.

A member with no new head since the last tick has a leaf of its last head, so every tick holds a
leaf for every member. A host MUST refuse a new member when the tick salt draw would
not end: it states a maximum number of members, at most 2^16.

A host MUST take a member's new head only when the member also gives a CLL consistency proof
from the last head the host took for it to the new one, and the proof verifies. The new head
MUST be signed by the key the member joined with and name its log id. This is the host's own
check. §7 says why it is not an independent one.

### 2.3 The host checkpoint and its witness

The host has host checkpoints witnessed as CLL checkpoints, with the witness and the cadence of
its choice. A host checkpoint covers every tick before it, so a holder's head in a tick whose
checkpoint was never witnessed is covered by the next witnessed one. Each on-demand stamp opens
a new tick.

The host's operator chooses the host's witness, and MAY choose any. A host MUST name its witness
to a holder before the holder joins, and joining is the holder's acceptance of that witness; a
holder that wants another witness joins another host or stays unjoined (§2.1). A host whose
members include holders that do not run the host MUST use a witness run separately from the
host's operator. The time a host chain gives (§4.3) means something only when the witness is run
separately from the host: a witness run by the host's operator attests nothing the host could
not make up.

## 3. The host chain

A host chain is one JSON object with these members and no other:

~~~
{
  "kind": "host-log-witness/v1",
  "log_id": "<log id of the leaf's checkpoint>",
  "size": <MMR size of the leaf's checkpoint>,
  "salt": "<the leaf's salt>",
  "index": <the member's slot>,
  "path": ["<64 lowercase hex>", ...],
  "tick_salt": "<64 lowercase hex>",
  "head": {
    "checkpoint": { "cose": "<unpadded base64url>" },
    "consistency_proof": { "v": 1, "kind": "consistency", ... }
  },
  "parent": {
    "log_id": "<log id of the host log>",
    "checkpoint": { "cose": "<unpadded base64url>" },
    "entry_index": <zero-based leaf index of the tick's entry>,
    "inclusion_proof": { ... },
    "witnesses": [ ... ]
  }
}
~~~

The **covered checkpoint** is the shelf checkpoint the chain is for: in a follow-up, the stamp
proof's shelf checkpoint (§6). The **leaf checkpoint** is the checkpoint in `head.checkpoint.cose`
when `head` is present, and the covered checkpoint otherwise. `head` is present only when the
member's head at that tick is a later shelf checkpoint than the covered one. Its
`consistency_proof` then goes from the covered checkpoint to the head, in PLW's encoding of
`earlier.consistency_proof`. `path` holds exactly 32 hashes, leaf level first. `parent` is PLW's,
except that its checkpoint is a host checkpoint and its entry is the tick value. Every integer is
a JSON integer in the AAC safe range (SF §3.1).

## 4. Checking a host chain

### 4.1 The checks

A receiver checks a host chain only after the covered checkpoint's signature verified. It applies
these checks in order, stops at the first that fails, and the chain's outcome is then `invalid`
with that finding:

1. `host_chain_malformed`: the chain is not an object of the members of §3, or `kind` is not
   `host-log-witness/v1`.
2. When `head` is present:
   1. `host_chain_head_signature_invalid`: `head.checkpoint.cose` is not unpadded base64url of a
      CLL COSE checkpoint that verifies under its own key.
   2. `host_chain_head_not_this_log`: its key id or log id differs from the covered
      checkpoint's, or its MMR size is not above the covered checkpoint's.
   3. `host_chain_head_not_an_extension`: `consistency_proof` is not of PLW's shape, its sizes
      are not those of the covered checkpoint and the head, or it does not prove that the head
      extends the covered checkpoint.
3. `host_chain_leaf_does_not_name_this_checkpoint`: `log_id` or `size` is not the leaf
   checkpoint's.
4. `host_chain_path_malformed`: `path` is not an array of exactly 32 strings of 64 lowercase hex
   characters, or `tick_salt` is not 64 lowercase hex characters.
5. `host_chain_slot_mismatch`: `salt` is empty, or `index` is not the slot that §2.2 step 2
   computes from `tick_salt` and the leaf checkpoint's key id and log id.
6. `host_chain_parent_checkpoint_invalid`: `parent` is not an object, or its `checkpoint.cose`
   is not unpadded base64url of a CLL COSE checkpoint that verifies under its own key. The host
   key need not be the covered checkpoint's key: the hashes bind the chain, not the host's
   signature.
7. `host_chain_parent_log_id_mismatch`: `parent.log_id` is not the host checkpoint's log id.
8. `host_chain_entry_not_included`: computing the root from the leaf (PLW), `index` and `path`,
   then the tick value (§2.2 step 5) from `tick_salt` and that root: `entry_index` is not a
   non-negative integer, or `inclusion_proof` is malformed, does not state the host checkpoint's
   MMR size and `entry_index`, or does not prove the tick value's leaf at `entry_index` under the
   host checkpoint's root.

When every check passes, the chain's outcome is `valid`. Each entry of `parent.witnesses` is then
checked as WIT checks a receipt, against the host checkpoint's COSE statement, giving `pass`,
`withheld` or `fail`. When the chain is `invalid`, no receipt is checked: when `parent.witnesses`
is an array, each of its entries is reported `withheld`; otherwise no receipt is reported.

### 4.2 What the checks show

The tick value commits to the tick salt and the root, so a chain must use the salt the host
committed to. With one slot per member id, a tick holds one leaf for a member. So two chains for
one member from the same tick name the same leaf checkpoint, or one of them fails.

When `head` is absent, the leaf commits to the covered checkpoint's COSE octets. When `head` is
present, the leaf commits to the head's octets, and the consistency proof shows that the covered
checkpoint's log is a prefix of the head's. It does not commit to the covered checkpoint's own
signature or time: the holder could have signed it later, over the same prefix.

### 4.3 The result a receiver reports

A receiver that reports on a host chain:

- MUST report it as a stamp through a host log, and MUST NOT report a receipt over the host
  checkpoint as a receipt over the covered checkpoint.
- When `head` is absent and a receipt passes with a registration time T, reports that the covered
  checkpoint existed at T.
- When `head` is present and a receipt passes with a registration time T, reports only that the
  covered checkpoint's log entries, up to its size, existed at T. That covers the facts the
  entries commit to. It does not report the covered checkpoint itself as existing at T.
- MUST NOT report that a witness checked the holder's shelf log for forks, or that the stamp
  gives fork detection. §7 says why.

## 5. The holder

A member keeps, for each shelf checkpoint it may need to prove, the host chain to the first
witnessed host checkpoint that covers it, with that checkpoint's receipts. It gives a host chain
only to a party it would give the receipts to (WC §4.3).

## 6. Carriage in a follow-up

A member carries its host chain in a WC follow-up's `host_chain` member, instead of `receipts`.
WC §4.1, §4.2, §5.1 step 4, §5.2, §5.4 and §6.1 define that member, the receiver's handling and
the answer's `host_chain` outcome. This document only defines the chain and its checks.

## 7. Security and privacy considerations

- **What a member gives up: independent fork detection.** A holder that stamps its own shelf
  log has the witness check that each new shelf checkpoint extends the last one the witness
  accepted. A member's witness sees only the host's checkpoints. So no witness checks a member's
  shelf log for forks, even when the witness is independent of the host. The host's check (§2.2)
  is run by the host, which in practice runs the member's software and often its keys, so it is
  not independent. The slot rule (§4.2) stops two heads of one member in one tick. It does not
  stop a host from putting one head in a tick and a forked head in a later tick, including a tick
  that an on-demand stamp opened. Each counterparty's chain then verifies alone. A holder that
  does not trust its host stays unjoined (§2.1).
- **The time depends on the witness being separate from the host.** A receipt shows when the
  witness registered the host checkpoint. That bounds the covered checkpoint only if the witness
  is run separately from the host (§2.3). A receiver's witness directory decides which witnesses
  count.
- **What the witness learns.** One host checkpoint per tick, never how many members the host has
  or which member changed. The host log grows by one entry per tick, whatever its members do. On
  the host's scheduled ticks, the witness learns nothing of when a member's deals happen. An
  on-demand stamp opens a tick off the schedule (§2.3): its checkpoint's arrival, or the extra
  entry a later checkpoint covers, shows the witness that some member of the host stamped on
  demand at about that time, as a holder's own on-demand stamp shows its own witness today. It
  does not show which member.
- **What a receiver learns.** From a member's chain, the host log's id, the host checkpoint and
  its size (and so how many ticks the host has made), and 32 sibling hashes. The siblings are
  members' leaves or seeded values (§2.2 step 4), which look the same, so they do not show how
  many members the host has.
- **The host key binds nothing.** Any key may sign a host checkpoint. The chain holds because
  the tick value, the root, the leaf and the head are bound by SHA-256, as PLW's security
  considerations say for a parent log.

## 8. Conformance

This document adds no vectors yet. An implementation claims conformance to it only once vectors
exist. They are to land in `vectors/` with EBL's implementation, which can cross-check them. They
should cover each finding of §4.1, a chain whose `tick_salt` puts the member at another slot
under the same tick value, two members with one log id and different keys, a head-present chain
against a newly signed earlier checkpoint, and the follow-up's carriage cases of §6 (neither
form, both forms, an invalid chain with receipts that would pass).
