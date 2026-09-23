# AAC and TRACE: references, addressing, and what retention can say

**Date:** 2026-09-13
**Context:** AAIF `fg-state-and-context`, 2 to 11 September 2026, Steven Mih (Agent Action Capsule) and Imran Siddique (TRACE). Posted in channel on 4 September; Steven asked for both halves in this repo on 5 September.
**Pinned:** `agent-action-capsule` at `26ffa1d`, draft-mih-scitt-agent-action-capsule-04, Cross-record references. `agentrust-io/trace-spec` at `6737005`, `spec/trace-v0.2.md` section 3.1.2.
**Status:** Non-normative. Changes neither specification.

## TRACE's references block today

A TRACE `references` entry is `{rel, id, resolver, retention?, digest?}`. `id` is a name in the resolver's system, `resolver` is the party obliged to keep it working, and `digest` is optional. Entries are assurance-neutral: a reference MUST NOT affect `runtime.platform` and a verifier MUST NOT treat a resolved reference as attested evidence.

## The same block against AAC's addressing

The required and optional halves swap.

- `digest` becomes the identity. Typed and required, the self-derived key AAC already uses.
- `log_coordinates {log_id, leaf_index, inclusion_proof}` is an optional unit. Per -04 it is an upgrade and never a second identity.
- `id` and `resolver` drop to optional. They stop being the address and become a route.
- TRACE's rule 4 inverts. Today a producer who cannot name a resolver omits the entry. Under AAC addressing it is a producer who cannot compute a digest.

## What TRACE's retention field stops being able to say

Today `retention` is the only field in the block speaking to findability, which is why it reads as an availability guarantee it could never give. Once the digest carries that weight:

1. It stops hiding that resolvable and unchanged are two different promises. TRACE's digest is optional, so an entry can promise a name stays resolvable while saying nothing about whether the bytes at the far end are the ones that were there at issue time. The npm `keyv` unpublish was the address disappearing. This is the address surviving while the content moves under it, and TRACE's current shape cannot tell a verifier it happened.
2. It stops being enforceable later in principle. Once addressing is self-derived there is no privileged party left to enforce against. Superseded, see below.

**What it costs.** `resolver` is required in TRACE today, so every reference names someone obliged. Optional means some entries name nobody. TRACE buys accountability at the price of addressing, AAC buys addressing at the price of accountability, and neither is strictly better.

`retention` occurs once in -04: "This profile states no availability or retention obligation for a cited artifact."

## Where it landed

Steven's answer on 5 September changed the conclusion of point 2.

The digest as identity was deliberate in AAC and predates CPB: a mutable reference is not evidence, and a citation that can drift is worse than none. That reasoning is now stated in -04's Cross-record references section (#94), which also says AAC states no availability obligation and that one belongs to whichever profile carries the locator.

So retention does not retire. Kept beside the digest as an optional route obligation rather than as identity, it says what party X undertakes to serve: the bytes with digest D until T. A request for D supplies evidence for assessing that promise. Whether a response establishes a breach depends on the promise's terms and the verified response. That replaces point 2.

A verified signed no_such_record response establishes that its signer reported absence. Attributing it to X requires checking the expected responder key and matching the response to the request. A requester-side timeout records that no answer arrived; it does not establish that X received the request or breached the promise.

## For a third format

Any two record formats that compose have to decide where the join is. Join by name and the addressing party can move it. Join by digest and neither can. Resolver, retention and log coordinates are routes to a digest, never the identity of one.
