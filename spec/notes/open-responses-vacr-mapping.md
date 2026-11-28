# Open Responses to VACR: a mapping, with per-turn Capsules as receipts

**Status.** Non-normative note. It changes no draft, profile, registry or wire member of this
repository. Where it proposes a parameter or field name, the name is a placeholder until a
specification registers it. It may later become the basis of an informational Internet-Draft.

This note answers four questions for a recorder that observes Open Responses traffic and writes
the conversation as a Verifiable Agent Conversation Record (VACR) in a vCon:

1. Where each Open Responses item lands as a VACR entry (§2).
2. How a VACR entry, or a vCon attachment, cites an Agent Action Capsule by identifier and digest (§3).
3. What the Capsule for turn N must bind about earlier turns, through `previous_response_id` (§4).
4. What one implementation does today, as measured (§5).

## 1. Sources

| Short name | Document | Retrieved as |
|---|---|---|
| OR | Open Responses specification, version 2026-04-24: `src/specifications/2026-04-24.mdx` and `public/openapi/2026-04-24/openapi.json` in openresponses/openresponses | commit `dce9ddb91921427c2ba06901c7dfaf0cc7056799` |
| AIX | draft-birkholz-vcon-ai-agent-extension-00, "An AI Agent Extension for Virtualized Conversations (vCon)" | `.txt`, sha256 `ba305ed67a0199afd86fd0e58d3bc8c39ef7099f1888f8daabda78ee14f2068b` |
| VACR | draft-birkholz-verifiable-agent-conversations-01, "Verifiable Agent Conversation Records"; AIX §1.2 replaces it | `.txt`, sha256 `033dff9866ed4403a060bd0cdc92aa59067b6fb4720f0d662a82d35cb3e2617e` |
| AS | draft-howe-vcon-agent-session-00, "vCon Agent Session" (expired 21 November 2026; cited as work in progress) | `.txt`, sha256 `b88e60f74fc6737ceb4ffd230c2bfa49b5c5250b64b058bcd009b4b75a61c507` |
| CORE | draft-ietf-vcon-vcon-core-05 | datatracker revision 05 |
| AAC | draft-mih-scitt-agent-action-capsule-06, this repository | `spec/` |
| P298 | Design answer on Mesh-LLM/capsules-plugin#298: where an evidence receipt goes in Open Responses traffic, and what a turn Capsule binds | issue thread |
| L455 | Measurements for evidence-network/loop#455 in evidence-network/loop-data | commits `b9144639cb416ca23563c2b93c31a83ce6488e76` and `ae32d3ecb3beae992a8d7afaf3048bc8fc9c4268` |

A VACR can be written in two ways, and this note gives the target for both:

- **AIX form.** Entries are native vCon objects. A message is a `"text"` Dialog Object, and the
  other entry kinds are Event Objects of type `"tool-call"`, `"tool-result"`, `"reasoning"` or
  `"system-event"` (AIX §4.5, §4.6).
- **AS form.** The whole trace is one Analysis Object with `type: "agent_trace"`, whose `body` is a
  JSON VACR with `message-entry`, `tool-call-entry`, `tool-result-entry`, `reasoning-entry` and
  `event-entry` maps (AS §6.1; VACR §3.8). The user and assistant turns are also ordinary vCon
  `dialog[]` entries (AS §5).

AIX Appendix C maps each VACR data item to its AIX form, so the two columns of the table in §2
are kept consistent through that appendix.

## 2. Item mapping

OR defines five output item types (the `ItemField` union: `message`, `function_call`,
`function_call_output`, `reasoning`, `compaction`). It defines nine input item shapes (the
`ItemParam` union): the same types, with `message` split by role into `user`, `system`,
`developer` and `assistant`, plus `item_reference`. It also allows provider-prefixed extension
items (OR "Items are extensible"). The table covers every one of these. A response's own status
is covered as a row, because it carries the `incomplete` state.

| Open Responses item | AIX target | VACR entry (AS form) | Field mapping and notes |
|---|---|---|---|
| `message`, role `user` | `"text"` Dialog Object; `parties` names the user's Party Object | `message-entry`, `type: "user"` | `id` → `entry_id`. Each `input_text` part → Dialog body. Each `input_image` or `input_file` part → its own Attachment Object, either inline or as `url` + `content_hash` (CORE §2.4); the text Dialog keeps the order. |
| `message`, role `assistant` | `"text"` Dialog Object; `parties` names the agent's Party Object (`type: "bot"`, carrying `agent_meta`) | `message-entry`, `type: "assistant"` | `id` → `entry_id`. `output_text` → body. `refusal` → body, with the part type kept in a placeholder parameter `content_part_type`, because AIX has no refusal field. The response's `model` → `model_id`. The response's `usage` → `token_usage` (`input_tokens` → `input`, `output_tokens` → `output`, `cached_tokens` → `cached`, `reasoning_tokens` → `reasoning`, `total_tokens` → `total`), placed on the response's last assistant message only, because OR reports usage per response, not per item. `phase` (`commentary` or `final_answer`) has no AIX field and goes in a placeholder dialog parameter `phase`. |
| `message`, role `system` | `"text"` Dialog Object; `parties` names a Party Object for the deploying application (`type: "organization"`, or `"bot"` when an agent wrote it) | `message-entry`: **no exact target.** VACR's `type` is only `"user"` or `"assistant"` (VACR §3.8.1). Write `type: "user"` with a member `role: "system"`, which the map's `* tstr => any` permits. | Same as for a user message. The request's top-level `instructions` field is mapped the same way, as a system Dialog placed before the turn's input. |
| `message`, role `developer` | As for `system`, with role `developer` | As for `system`, with `role: "developer"` | As for `system`. |
| `function_call` | `"tool-call"` Event Object | `tool-call-entry` | `name` → `tool_name`. `arguments` → `input`, **kept as the JSON string OR transmits and not parsed**, so a digest over it reproduces. `call_id` → `call_id`. `id` → `entry_id`. `parent_id` → the `entry_id` of the turn's input message, when the recorder links the tree. |
| `function_call_output` | `"tool-result"` Event Object | `tool-result-entry` | `output` (a string or an array of input content parts) → `output`, as transmitted. `call_id` → `call_id`. `id` → `entry_id`, when present (it is optional on input). **`status` is not mapped onto AIX `status`:** OR's `status` is the item lifecycle (`in_progress`, `completed`, `incomplete`), while AIX's is the tool outcome (`"success"`, `"error"`). OR carries no tool-outcome field, so `status` and `is_error` are left out rather than guessed. In OR the client runs externally hosted tools and returns the output as input (OR "Externally-hosted tools"). The AIX `party` stays the agent's Party Object (AIX §4.6), and the recorder notes that the output arrived as client input. |
| `reasoning` | `"reasoning"` Event Object | `reasoning-entry` | `content` → `content`. `encrypted_content` → `encrypted`, as an opaque string (OR §Reasoning). If only `encrypted_content` is present, `content` is `""` (AIX §4.6.3). `summary` has **no AIX field**: `subject` is a topic label, not a summary. It goes in a placeholder `$$reasoning-event-ext` parameter `summary`. `id` → `entry_id`. |
| `compaction` | `"system-event"` Event Object, `event_type: "compaction"` | `event-entry`, the same `event_type` | AIX has no compaction type. `encrypted_content` is opaque by definition and is provider-protected state, not conversation content. Record its SHA-256 in `data`, as placeholder member `encrypted_content_sha256` (lowercase hex over the UTF-8 octets of the string). Carry the content itself only where the record's disclosure policy allows it. `created_by`, when present, → `data.created_by`. `id` → `entry_id`. The `/responses/compact` call that produced the item has no response id (OR "WebSocket Compaction"); see §4.5. |
| `item_reference` (input only) | **No new entry.** | **No new entry.** | It points to an item already in context by `id`. If the recorder already holds that item, it adds nothing and may set the `parent_id` of the turn's next entry to the referenced `entry_id`. If it does not hold the item, it cannot write content it never saw. It records a `"system-event"` with `event_type: "item-reference-unresolved"` and `data.item_id`. |
| Extension item `<slug>:<name>` | `"tool-call"` and `"tool-result"` Event Objects when the implementer documents call and result semantics. Otherwise `"system-event"` with `event_type` set to the prefixed type. | The matching entry, or `event-entry` | OR says extension items are not portable (OR "Extending Items"). The prefixed type string is kept verbatim. With no documented schema, the body goes in `data` as transmitted. |
| Response `status` (`completed`, `incomplete`, `failed`), with `incomplete_details.reason` | One `"system-event"` per response, `event_type` `"response-completed"`, `"response-incomplete"` or `"response-failed"` (placeholder values; AIX does not enumerate them) | `event-entry`, the same `event_type` | `data` carries `response_id`, `previous_response_id` (when the request had one), `status`, `incomplete_details.reason` or `error.code`, and `store`. This is the per-turn anchor that cites the turn Capsule (§3). An item whose own `status` is `incomplete` is mapped by its type as usual, with its partial content. OR requires it to be the response's last item (OR "Items are state machines"). **Do not use vCon's `"incomplete"` Dialog type:** CORE §4.5.1.3 defines it as a conversation that failed to set up, with no content, which is a different meaning. |

**Streaming events.** OR streaming events (the 24 `*StreamingEvent` schemas in the 2026-04-24
OpenAPI document, such as `response.output_text.delta` and `response.output_item.added`, plus the
two WebSocket frame schemas) are a transport for the item states above. They have no entry of their own. A recorder writes
each item once, from its terminal state (`response.output_item.done` or the final response
object). The lifecycle events `response.created`, `response.queued` and `response.in_progress`
add nothing that the terminal `"system-event"` lacks. `response.completed`, `response.incomplete`
and `response.failed` are that terminal event. A standalone `error` event that ends a turn
(including `previous_response_not_found`) is a `"system-event"` with `event_type:
"response-failed"` and `data.error.code`. WebSocket `response.create` frames are requests; their
content maps through their input items. `sequence_number` is transport order, not entry
identity, and is not recorded.

**Sessions.** One vCon Session Object (AIX §4.4) holds one conversation: a run of responses linked
by `previous_response_id`. A response sent without `previous_response_id` begins a new Session,
because OR treats that request as a new chain whatever the client intends. When the recorder
knows the new chain continues an earlier one, as with resending full context after a reconnect or
continuing after compaction (OR "WebSocket Reconnects"), it links the two Sessions with a
`Session_Reference` (CORE §4.2.8). It does not merge them, because the reference chain did break.

## 3. Citing a Capsule from a VACR entry or a vCon attachment

**The identifier is the digest.** A Capsule's `capsule_id` is SHA-256 over the JCS form of the
Capsule with `capsule_id` removed (AAC §Identity and parties). AAC §Cross-record references makes the digest
the identity of any cited record: "for a cited AAC Capsule, checking a `references` entry against
that Capsule's own `capsule_id` computation is exactly this comparison". A citation therefore
carries one value, used twice:

```json
{ "capsule_id": "<64 lowercase hex>", "digest_alg": "sha-256", "digest": "<the same 64 lowercase hex>" }
```

The shape follows AAC's CPB typed digest reference (`{type, digest_alg, digest}`) without `type`.
CPB-05 leaves artifact types to the profile that owns them, and AAC -06 declares none for its own
Capsule, so there is no registered token to use (open question Q2). A verifier recomputes
`capsule_id` from the Capsule's bytes and compares. It never trusts the carried value (AAC
§Identity and parties: "Verifiers MUST recompute; carried values MUST NOT be trusted").

**Where the citation goes.**

| Carrier | Placement | Notes |
|---|---|---|
| AIX Event Object | On the turn's terminal `"system-event"` (§2), as a placeholder parameter `capsule_ref` holding the object above | AIX event types end in an extension socket (AIX §4.1). `"system-event"` has `$$system-event-ext`. Where a producer seals one Capsule per tool call instead of per turn, the reference goes on that `"tool-call"` Event through `$$tool-call-event-ext`. |
| VACR entry (AS form) | The same object as member `capsule-ref` of the matching `event-entry` or `tool-call-entry` | VACR entry maps allow extra members (`* tstr => any`). AIX Appendix C converts kebab-case to snake_case, so `capsule-ref` and `capsule_ref` name one thing. |
| vCon Attachment Object | `purpose: "agent_action_capsule"` (placeholder; CORE §4.6.1 leaves `purpose` unrestricted, and AS §7.1 starts a purpose registry). `session` or `dialog` gives the turn. The content is either inline (`body` is the Capsule JSON, `encoding: "json"`, `mediatype: "application/agent-action-capsule+json"`) or external (`url` + `content_hash`) | **Two digests, two jobs.** CORE `content_hash` is SHA-512 over the octets served at `url` (CORE §2.4.2), and proves the fetched bytes were not swapped. `capsule_id` is SHA-256 over the canonical Capsule, and proves which Capsule those bytes are. A verifier checks `content_hash` over the fetched octets, then parses them, recomputes `capsule_id`, and compares it with the `capsule_ref` on the Event. Neither digest substitutes for the other. A Producer Envelope (AAC §Producer Envelope wire profile) may ride as a further Attachment; it signs `capsule_id`, so it verifies without the Capsule JSON. |

AS §8 defines `scitt_receipt` and `agent_trace_cose_sign1` attachment purposes for a signed VACR.
Those cover the VACR record itself, not a Capsule, so they are not reused here.

**How the recorder learns which Capsule covers a turn.** P298 §1 puts the receipt outside the
Responses output (no extension item, no event, no header, nothing in `metadata`). The client
fetches it by response `id`, and the lookup answers found, pending or none. A recorder that
holds the response id fetches the receipt and writes its `capsule_id` into `capsule_ref`. Without
a receipt, a recorder that kept the exact request bytes can match its own SHA-256 of them against
the Capsule's input digest (§5, M6). That gives a candidate match, not proof, because two turns
with identical request bytes give the same digest.

## 4. The lineage rule: what a turn-N Capsule binds about earlier turns

The rule below matches P298 §2 and §3, and states it so that two implementers produce the same
values. The field names are placeholders; P298 left them, and the place they live in a Capsule,
to spec text with vectors (open question Q1).

### 4.1 The fields

The Capsule that the **ingress** sealed for a turn (the node that received the `/v1/responses`
request and emitted the response object) carries:

| Field (placeholder) | Value | Present when |
|---|---|---|
| `response_id_digest` | SHA-256 over the UTF-8 octets of the response object's `id` string **exactly as emitted**: no prefix stripped, no case change, no trimming. Lowercase hex, 64 characters. | The turn emitted a response object with an `id`, whatever its status: `completed`, `incomplete` or `failed`. |
| `previous_response_id_digest` | SHA-256 over the UTF-8 octets of the request's `previous_response_id` string **exactly as received**, in the same encoding. | The request carried a non-null `previous_response_id` **and** the host resolved it, so the turn ran. When the request had none, or had `null`, the field is **absent**: not `null`, not the empty string. |

The Capsule MUST NOT carry a digest over the whole earlier chain. Content is bound separately: the
Capsule's input digest commits to the request the model ran. Where the host rebuilds context from
stored state (`previous.input + previous.output + input`, OR "previous_response_id"), that digest
covers earlier turns only as far as the model received them, after any truncation or compaction
(P298 §2, "Content"). A chain digest would claim history the model may not have seen.

The two fields MUST NOT go in the Capsule's `chain` block or its `references` array. `chain` is
the producer's own same-stream predecessor (AAC §Cross-record references, "Boundary rule").
`references` cites an artifact by the digest of its bytes, and a response id's digest is not the
digest of any artifact's bytes.

A serving peer that receives only an expanded request never sees response ids. Its Capsule
carries neither field, rather than a guessed one (P298 §2, "Serving peer").

### 4.2 Worked example

The three-turn chain in L455 `reports/loop-455-open-responses/raw/chain-A-raw.json` (commit
`b9144639`):

| Turn | `id` | `previous_response_id` | `response_id_digest` | `previous_response_id_digest` |
|---|---|---|---|---|
| 1 | `resp_c9c42d5e153b4496bd57a4f13bcae414` | `null` | `2bf1b158d8e5a7598307d1950d01ffbb55b780bfafd88dac8f186c166fa0d5ba` | absent |
| 2 | `resp_d776009114f843d486b4239311053543` | `resp_c9c42d5e153b4496bd57a4f13bcae414` | `58a0389f3f04a2ae130dcccece4a4b880a21accf345a814fc06dbc49c205a692` | `2bf1b158d8e5a7598307d1950d01ffbb55b780bfafd88dac8f186c166fa0d5ba` |
| 3 | `resp_c46bc49d1b974944b5996d5e0ba949de` | `resp_d776009114f843d486b4239311053543` | `3c13e8b4fdc438617d7c32b49179b5a9b96c7d0ac3e6db339f24aa7fc4acf6f4` | `58a0389f3f04a2ae130dcccece4a4b880a21accf345a814fc06dbc49c205a692` |

Each digest is `sha256(id.encode("utf-8")).hexdigest()`. Two independent tools give the same
values. The measured Capsules do not carry these fields (§5, M4); the values show what the rule
yields.

### 4.3 What a verifier may conclude

Suppose both Capsules' signatures verify, under the same signing node, and turn N's
`previous_response_id_digest` equals turn N−1's `response_id_digest`. Then:

- **Shown:** turn N's record names the id that turn N−1's record emitted. Because turn N is a
  success record, the host resolved that id. OR requires the server to load the referenced
  response's input and output (OR "previous_response_id"). OR names `previous_response_not_found`
  as the failure only on the WebSocket transport, but the measured host returns it on HTTP as well
  (§5, M8).
- **Not shown:** which content of turn N−1 reached the model. The input digest bounds that.
- **Not shown:** that no other record carries the same id. A digest that more than one record
  carries is treated as **no link**. The rule depends on the host emitting unique, unguessable
  response ids on every path. P298 §2 ("Unique ids") records a stream path that emitted
  second-resolution ids at the first measured head; it was not re-measured.

On the vCon side, the terminal `"system-event"` of each response carries `response_id` and
`previous_response_id` in clear (§2). Anyone holding the vCon can compute both digests and join
each turn to its Capsule without an index.

### 4.4 Disclosure

The digest is not a secret: anyone holding an id can compute it. Two records with the same
`previous_response_id_digest` let their holder group one caller's turns into a conversation.
P298 §2 ("Sharing") therefore keeps the two fields in the ingress node's own records. They are
left out of exchange reports, of anything sent to a counterparty, and of the receipt. That is
the current default. A share rule would be its own decision.

### 4.5 When the chain breaks

| Case | What is sealed | Lineage fields |
|---|---|---|
| The continuation is refused (`previous_response_not_found`: restart, eviction, expiry, a different ingress, or a referenced response that was never stored) | No inference runs, so there is no turn Capsule. A failure record, where one is sealed, holds no body digest. | No `previous_response_id_digest`. A failed attempt is never evidence of a continuation. |
| The client resends full context after a refusal or reconnect (OR "WebSocket Reconnects") | A normal turn Capsule | `response_id_digest` only. The break is visible in the record. |
| `/responses/compact`, then a new response on the compacted window | The compact call's own record, if the host seals one; then a normal turn Capsule | The compact call emits no response id, so there is no `response_id_digest` for it. The next turn has no `previous_response_id`, so no `previous_response_id_digest`. Lineage across compaction is not bound by this rule (open question Q3). |
| The response ends `incomplete` | A turn Capsule for the response that was emitted | `response_id_digest` is present. OR does not say whether an incomplete response can be continued. Where the host does not store it, no later record will carry the matching `previous_response_id_digest`. |

## 5. What is measured today

One implementation was measured: the Open Responses support in Mesh-LLM/mesh-llm#3105, an open
draft pull request, at two heads. The first run used `4a3c8e27222554472b8b0534117f668e045ab149`,
with data in L455 commit `b9144639cb416ca23563c2b93c31a83ce6488e76`, directory
`reports/loop-455-open-responses/`. The rerun used `6b3c5fdcb7392f32d123499ef02a54cfd626d19f`,
with data in L455 commit `ae32d3ecb3beae992a8d7afaf3048bc8fc9c4268`, directory
`reports/loop-455-open-responses/rerun-6b3c5fdc/`. Capsules were sealed by a capsules plugin
observing the host's exchange events. In the table, `R/` is the first directory and `R6/` the
second.

| # | Claim | Evidence |
|---|---|---|
| M1 | One Capsule is sealed per `/v1/responses` call on each of the four paths: plain HTTP, SSE stream, WebSocket `response.create`, and `/v1/responses/compact`. The compact call also produces one, although under OR it is not a turn with a response id. | `R/raw/paths-A.json` and `R/README.md` §2; `R6/raw/capsule-delta-per-path.txt` (host-served Capsule count 31 → 32 → 33 → 34 → 35, one call per path) |
| M2 | The plugin sees the traffic only through host exchange events carrying request and response digests (the plugin reports body access as not granted). Nothing in the Responses output changes. | `R/README.md` §2; `R/raw/lifecycle-events-A.jsonl`, `R/raw/lifecycle-events-B.jsonl` |
| M3 | A three-turn `previous_response_id` chain on one ingress returns 200 three times. Turns 2 and 3 cite the previous turn's id. | `R/raw/chain-A-raw.json` (ids in §4.2); `R6/raw/chain-A-raw.json` |
| M4 | No measured Capsule carries `previous_response_id` or any `resp_` id, so lineage is not bound. | First run: the substring count is 0 in each of `R/raw/ledger-A-after-chain.json`, `R/raw/ledger-B-after-chain.json`, `R/raw/ledger-A-after-cross.json` and `R/raw/ledger-B-after-cross.json`. Rerun: `inf_with_prev_or_resp: []` in `R6/raw/snap-A-final.json`, `R6/raw/snap-B-final.json` and `R6/raw/snap-C-final.json`, over 50, 27 and 33 host-served Capsules, scanned by `R6/scripts/snap.py` over the stored Capsule bytes. The rerun scan covers host-served Capsules only. |
| M5 | `chain.parent_capsule_id` with `relation: "follows"` is the node ledger's own predecessor, not conversation lineage. | `R/README.md` §2; `R/raw/ledger-A-after-chain.json` (the last three host-served records chain consecutively, as ledger neighbours) |
| M6 | Each measured Capsule's input digest is SHA-256 of the request body the host forwarded. On the ingress that is the client's request body, which contains `previous_response_id` when one is sent. The cited id is therefore hashed in, but cannot be recovered from the Capsule. | `R/README.md` §2; `R/raw/ledger-A-after-chain.json` (`agent_input_digest` equals `host_binding.digest`, whose `construction` names request-body SHA-256) |
| M7 | Every host-served Capsule's `capsule_id` recomputes, so a §3 citation would verify against these records. | 39 of 39 host-served records in `R/raw/ledger-A-after-chain.json` match `compute_capsule_id` from this repository's Python reference (`python/agent_action_capsule/canonical.py`) at `f87ed2cff7e9244d52b84859fcaed752673b481a` |
| M8 | A continuation sent to a different ingress returns 404 `previous_response_not_found` in both directions, and nothing is sealed for the refused turn. The implementation treats this 404 as by design: stored state belongs to its ingress. | `R/raw/chain-cross-raw.json`; `R/README.md` §2 ("Rejected turns … seal no capsule") and §3; `R6/raw/cross-ingress.txt` |
| M9 | A response that ends `incomplete` (`max_output_tokens`) is returned with an id but cannot be continued (404 `previous_response_not_found`); a completed one can. At the rerun head the incomplete response carries `store: false`. | `R/raw/incomplete-continuation-live.txt`; `R6/raw/incomplete-continuation-live.txt` |
| M10 | Two turns of one conversation, sent through one ingress to two different serving providers, both succeed, and turn 2 recalls turn 1. The conversation lives at the ingress, which is why §4.1 puts the lineage fields on the ingress record. | `R6/raw/two-providers-B.txt`, `R6/README.md` §5 |
| M11 | The official compliance runner passes 17/17 through both ingress nodes at both heads. Standalone serving passes 17/17 at the first head and 1/17 at the rerun head. | `R/raw/official-mesh-A.json`, `R/raw/official-mesh-B.json`, `R/raw/official-standalone.json`; `R6/raw/official-mesh-A.json`, `R6/raw/official-mesh-B.json`, `R6/raw/official-standalone.json` |

**Not measured.** No implementation produced a vCon, an AIX Event Object or an AS `agent_trace`
from this traffic, so the §2 table and the §3 placements are untested. The measured chains used
only `message` items: no `function_call`, `function_call_output`, `reasoning`, `compaction` or
`item_reference` item went through the lineage or receipt path. The P298 receipt lookup is not
built. The §4 fields exist in no Capsule. Nothing after head
`6b3c5fdcb7392f32d123499ef02a54cfd626d19f` was measured; the pull request is an open draft.

## 6. Open questions

- **Q1. Field names and placement.** The two lineage fields need registered names and an agreed
  place in a Capsule, so that a verifier finds them without knowing the producer. P298 put them in
  a producer-namespaced extension block. Spec text and vectors come first: a match, no match, an
  absent field, and one id carried by two records.
- **Q2. An artifact-type token for an AAC Capsule.** It is needed if a `capsule_ref` is to be a full
  CPB typed reference (`type` included), and to make the Attachment `purpose` a registered value.
- **Q3. Lineage across compaction.** OR makes compaction restart the chain. Binding the compacted
  window to the chain it came from, for example by the digest of the `compaction` item's
  `encrypted_content` on both sides, is not proposed here.
- **Q4. `system` and `developer` messages in VACR.** VACR `message-entry` has no role for them. The
  AIX form needs a Party for the deploying application. Both are raised for the VACR and AIX
  authors, not settled here.
- **Q5. Tool outcome.** OR's `function_call_output` has no success or error field, so the AIX
  `status` and `is_error` stay empty for every Open Responses tool result.
