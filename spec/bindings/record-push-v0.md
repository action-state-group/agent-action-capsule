# Record Push over MCP and A2A, v0

**Status.** Informational, pre-Internet-Draft, kept in this repository. It changes no
Internet-Draft and no other document here. It is the binding that open point SF-1 of
[`../shelf-forms-v0.md`](../shelf-forms-v0.md) (cited as SF) asks for: it carries SF's record
push (SF §6.1) and its answers (SF §6.5) over MCP and over A2A. It adds no part, no outcome and
no answer to SF, and it decides none of SF's other open points.

The evidencebook library (<https://github.com/action-state-group/evidencebook>, cited as EBL)
has no MCP or A2A entry for its `Receive` call yet: its design leaves the wire form to this
document (EBL `docs/design/461-shelf-facts.md` §1 and §5; `shelf_stamp_proof.go`, the
`StampProof` comment). This binding reuses the conventions of the evidence request carriage that
EBL already serves, `interop_mcp.go` and `interop_a2a.go`, specified in
[`../interop-profile-v1.md`](../interop-profile-v1.md) §11.4 (cited as IP): the same protocol
revisions, the same JSON-RPC handling, opaque bytes never re-serialized, carriage fields never
read as an identity, errors never presented as answers, and discovery the same for every caller.

## Dependency boundary

**Owns:** the push object and the answer object (§2), the MCP tool `record_push` (§3), and the
A2A extension that carries the push (§4).

**Uses unchanged:**

| Tag | Document | What this document takes from it |
|---|---|---|
| SF | `spec/shelf-forms-v0.md` | the record push, its parts, the order a receiver handles them in, and the answers (§6); the stamp proof's JSON encoding (§5.2) and checks (§5.3) |
| IP | `spec/interop-profile-v1.md` | the pinned A2A (v1.0.1) and MCP (2026-07-28) revisions and the sections read (Dependency boundary table); the carriage conventions of §11.4.3 to §11.4.5 that this document names where it uses them |
| B64U | RFC 4648 §5 | base64url without padding, for the opaque octets in the push object |
| JCS | RFC 8785 | the canonical form of the push and answer objects in the examples |

**Does not define:** the record format of any profile (SF §6.1), the push rule (SF-6), naming the
missing positions of a gap (SF-2), a fork member in the answer (SF-3), the stamp proof's
strictness (SF-4), any transport authentication rule, the handover (SF-7), and conformance
vectors (§7).

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

The **sender** pushes; the **receiver** holds a shelf and answers (SF §6). A **transport
condition** is anything other than an answer in the answer position: the sender learns nothing
about what the receiver did with the push, which may have been handled in whole, in part or not
at all (§2.3 rule 4).

## 2. The push and the answer

### 2.1 The push object

A push is one JSON object with these members and no other:

| Member | Presence | Value |
|---|---|---|
| `record` | OPTIONAL | the record's octets (SF §6.1) in base64url without padding [B64U], non-empty |
| `stamp_proof` | OPTIONAL | the octets of one stamp proof's JSON text (SF §5.2) in base64url without padding [B64U], non-empty |

At least one of the two MUST be present (SF §6.1). The receiver decodes each member and hands the
decoded octets to SF §6.2 and §6.3 exactly as received. It never parses and re-serializes the
record, and it reads the stamp proof from the decoded octets by SF §5.2.

Both parts travel as opaque octets, so this binding fixes no form for a record or a proof beyond
SF. A record's format is its profile's (SF §6.1), and the receiver's profile reads its sender, log,
position and digest from the record, never from the carriage. The stamp proof's JSON is read by
SF §5.2 as it stands, so the open question of how strictly unknown or `null` members are refused
(SF-4) stays with SF and does not move into this binding's schemas.

A push whose members both decode but whose `stamp_proof` octets are not a stamp proof is still a
push: SF §6.3 step 1 answers its proof part `refused: "invalid"`. The same holds for a record the
profile cannot read (SF §6.2 step 2).

### 2.2 The answer object

The answer is one JSON object with a member for each part the push carried and no other:

| Member | Present when | Value |
|---|---|---|
| `record` | the push had `record` | the record answer |
| `stamp_proof` | the push had `stamp_proof` | the proof answer |

The record answer has exactly these seven members, all always present (EBL
`testdata/shelf/receive/script.json`, `expect.record`; EBL `RecordOutcome`):

| Member | Type | Value |
|---|---|---|
| `digest` | string | the record's digest (SF §6.5); `""` when the record was refused at SF §6.2 step 1 or 2 |
| `stored` | boolean | stored by this push |
| `duplicate` | boolean | already held; not stored again |
| `deleted` | boolean | held once and deleted under the receiver's retention; not stored again |
| `counted` | boolean | within the sender's counted prefix |
| `ask_for_book` | boolean | held and not counted: the receiver asks the sender for its book |
| `refused` | string | `""` when the record was not refused, or the refusal class: `invalid`, `refused`, `over_limit` or `busy` |

The proof answer has exactly these three members, all always present (EBL `expect.proof`; EBL
`ProofOutcome`):

| Member | Type | Value |
|---|---|---|
| `accepted` | boolean | kept (SF §6.3 step 6) |
| `duplicate` | boolean | already held; not stored again |
| `refused` | string | `""` when the proof was not refused, or the refusal class: `invalid` or `refused` |

The values are those of SF §6.5 and nothing else: every answer a receiver writes is one row of
the SF §6.5 table, with every member that row does not name `false` or `""`, except `digest` as
stated above and `ask_for_book`, which is `true` on every held record that is not counted,
duplicate or not (SF §6.5). A refused part has every boolean `false`. The answer carries none of the
receiver's own changes (SF §6.5, "What the receiver learns").

The answer is an acknowledgment. It is not signed, it is not evidence of what the receiver holds,
and `stored` does not mean the record was accepted as the sender's one record at its position
(SF §6.5). An answer is not proof, to anyone, that the receiver holds a record.

### 2.3 Rules for both carriages

1. **Opaque octets.** The carriage moves the record and the stamp proof as the octets the push
   object's text decodes to. It never parses and re-serializes them (IP §11.4.1 rule 1).
2. **Nothing in the carriage is an identity.** The sender of a record is the key that signs it
   (SF §6.1); the key of a stamp proof is the key that signs both its checkpoints (SF §5.3
   step 3). The receiver MUST NOT read a sender from anything the carriage adds: the MCP `_meta`
   (client information included), the JSON-RPC `id`, the A2A `messageId`, `contextId`,
   `taskId`, `referenceTaskIds`, `tenant`, `configuration`, `metadata` and service parameters,
   and any client identification either protocol carries. This binding passes no transport
   identity to the receiver. Who may push is the push rule, which is not ruled (SF-6); this
   binding neither sets it nor lets a carriage stand in for it.
3. **An error is never an answer.** Anything that is not a push under §3 or §4 gets a JSON-RPC
   or A2A error, never an answer object. A receiver MUST NOT put an answer object in an error,
   and MUST NOT present an error as a refusal. A push with neither part has no part to answer,
   so the `invalid` of SF §6.1 is carried as the invalid-params error of §3.2 and §4.2.
4. **No answer on a receiver fault.** When the receiver cannot complete a push for a reason of its
   own (its store or its profile fails), it sends a JSON-RPC internal error (`-32603`) and no
   answer, even when one part was already handled. The sender concludes nothing about either
   part until it pushes again. Sending the push again is safe: a record already stored is
   answered `duplicate`, a proof already kept `duplicate` (SF §6.2 step 4, §6.3 step 5).
5. **The sender classifies by the answer alone.** An answer object in the answer position, of the
   form of §2.2 with one member per part pushed, is the answer, whatever `isError` or a task state
   says. Anything else is a transport condition. A sender MAY push again after a transport
   condition, and after `refused: "busy"` (SF §6.2 step 6).
6. **Message bound.** A receiver bounds a message's size before parsing it, and answers a larger
   one with the JSON-RPC error `-32600`, a transport condition. The bound SHOULD let a record
   that is at the receiver's own record bound (SF §6.2 step 1), together with a stamp proof,
   reach the receiver, so that a sender over that record bound is answered `over_limit` rather
   than meeting a transport condition. EBL's evidence request carriage uses twice the largest
   payload plus 64 KiB (`interop_mcp.go`, `interop_a2a.go`, `maxMessage`); twice the record bound
   plus 64 KiB is the same rule here.
7. **Same discovery for every caller.** The `record_push` tool definition (§3.1) and the A2A
   extension entry (§4.1) are fixed text and schemas, the same for every caller, authenticated or
   not, and carry nothing about what the receiver holds: no count, no size, no key, no matter, no
   time of activity (IP §11.4.3). A receiver that listed the tool, or the extension, to some
   callers only would tell each caller whether it is among the receiver's counterparties.

## 3. MCP binding

The MCP revision is 2026-07-28 as pinned in IP, and every message follows IP §11.4.5's handling of
JSON-RPC, `_meta`, `resultType` and protocol version (EBL `interop_mcp.go` `Handle`).

### 3.1 The tool

A receiver that takes pushes over MCP MUST list one tool, under exactly this name:

| Field | Value |
|---|---|
| `name` | `record_push` |
| `title` | fixed text, for example `Record push` |
| `description` | fixed text within §2.3 rule 7 |
| `inputSchema` | below |
| `outputSchema` | below |

The `inputSchema` is:

```json
{
 "type": "object",
 "properties": {
  "record": {"type": "string", "pattern": "^[A-Za-z0-9_-]+$"},
  "stamp_proof": {"type": "string", "pattern": "^[A-Za-z0-9_-]+$"}
 },
 "minProperties": 1,
 "additionalProperties": false
}
```

The `outputSchema` is:

```json
{
 "type": "object",
 "properties": {
  "record": {
   "type": "object",
   "properties": {
    "digest": {"type": "string"},
    "stored": {"type": "boolean"},
    "duplicate": {"type": "boolean"},
    "deleted": {"type": "boolean"},
    "counted": {"type": "boolean"},
    "ask_for_book": {"type": "boolean"},
    "refused": {"enum": ["", "invalid", "refused", "over_limit", "busy"]}
   },
   "required": ["digest", "stored", "duplicate", "deleted", "counted", "ask_for_book", "refused"],
   "additionalProperties": false
  },
  "stamp_proof": {
   "type": "object",
   "properties": {
    "accepted": {"type": "boolean"},
    "duplicate": {"type": "boolean"},
    "refused": {"enum": ["", "invalid", "refused"]}
   },
   "required": ["accepted", "duplicate", "refused"],
   "additionalProperties": false
  }
 },
 "minProperties": 1,
 "additionalProperties": false
}
```

No property of either schema carries an `x-mcp-header` annotation: that would copy a record or a
proof into an HTTP header that intermediaries see (IP §11.4.5). As MCP lets a client that
aggregates servers prefix tool names, the server lists the name above and the prefix is the
client's affair (IP §11.4.5).

### 3.2 The call

The push is one `tools/call` with `name` `record_push` whose `arguments` are the push object
(§2.1). The receiver decodes each present member from base64url (strictly: no padding, no other
alphabet) and handles the push by SF §6.

A call whose `arguments` do not satisfy the input schema (no member, an extra member, a member
that is not base64url), or with a member that does not strictly decode to at least one octet,
carries no push. The receiver MUST NOT answer it with an answer object. It SHOULD answer with a
JSON-RPC error with code `-32602` (invalid params), as IP §11.4.5 does for `evidence_request`.

### 3.3 The result

The answer is a tool result with `resultType` `complete`, `isError` `false` and
`structuredContent` the answer object (§2.2), whatever the answer says: a refused part is an
answer, not an error. The `content` array MAY be empty; a receiver MAY also put the answer
object's JSON in a text block, and a sender reads only `structuredContent` (IP §11.4.5).

A receiver MUST NOT return an `input_required` result or a task handle for `record_push`: a push
is answered in one result. The sender treats either as a transport condition (§2.3 rule 5).

### 3.4 Example (informative)

A push of one record and one stamp proof, with the octets elided:

```
{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {
 "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
  "io.modelcontextprotocol/clientCapabilities": {}},
 "name": "record_push",
 "arguments": {"record": "<the record octets, base64url>",
  "stamp_proof": "<the stamp proof's JSON octets, base64url>"}}}
```

A receiver that already held the record within the counted prefix and keeps the new proof
answers (the `_meta` with its server information elided):

```
{"jsonrpc": "2.0", "id": 7, "result": {"resultType": "complete", "content": [],
 "isError": false, "structuredContent": {
  "record": {"ask_for_book": false, "counted": true, "deleted": false,
   "digest": "71db53839ee90023a82b5d166eceb29c262872e43df0bfe46a21cb8311c67ccb",
   "duplicate": true, "refused": "", "stored": false},
  "stamp_proof": {"accepted": true, "duplicate": false, "refused": ""}}}}
```

These are the outcomes of EBL's vector step at `2026-10-20T00:08:00Z`
(`testdata/shelf/receive/script.json`).

## 4. A2A binding

The A2A revision is 1.0 in its JSON-RPC binding, as pinned in IP, and every message follows IP
§11.4.4's handling of `A2A-Version`, `A2A-Extensions` and the methods this carriage does not
serve (EBL `interop_a2a.go` `Handle`).

### 4.1 The declaration

A receiver that takes pushes over A2A MUST list one `AgentExtension` in its Agent Card's
`capabilities.extensions`:

| Field | Value |
|---|---|
| `uri` | exactly `https://datatracker.ietf.org/doc/draft-mih-agent-record-push/` |
| `description` | fixed text within §2.3 rule 7 |
| `required` | `false` |
| `params` | absent |

As in IP §11.4.4, the URI names the datatracker page of the Internet-Draft meant to carry this
binding, the extension entry is what advertises the push, and no `AgentSkill` is needed. The URI
is an identifier: it does not resolve until that draft is posted, and this document defines the
binding. `required` is `false` because a push is opted into per message. A receiver MUST NOT
advertise this binding under any other URI. The Agent Card SHOULD list `application/json` in
`defaultInputModes` and `defaultOutputModes`.

### 4.2 The message

The sender sends one `SendMessage` with `A2A-Version` `1.0` and the extension URI in the
`A2A-Extensions` service parameter. Its `Message` MUST have:

- `role` `ROLE_USER`;
- `extensions` containing the extension URI;
- `parts` holding exactly one `Part`, whose content is `data`, holding the push object (§2.1),
  and whose `mediaType` is `application/json`;
- no `taskId`, so that each push starts its own task.

If the sender sets `acceptedOutputModes`, it MUST include `application/json`.

This differs on purpose from the evidence request carriage, which puts its request octets in one
`raw` part (IP §11.4.4). A push has two optional parts, so a single opaque octet string cannot
hold it without a wrapper. The `data` part holds the same push object as the MCP arguments
(§3.2), and the octets inside it still travel as opaque base64url strings (§2.3 rule 1), so both
carriages hand the receiver the same octets.

A `Message` of any other shape carries no push: the push object anywhere other than one `data`
part, in `metadata`, as `text` or as `raw`, or a `data` value that is not a push object under the
input schema of §3.1 or that has a member that does not strictly decode to at least one octet
(as in §3.2). The receiver MUST NOT answer it with an answer object. It answers with a
JSON-RPC error `-32602` (invalid params), or an A2A error, such as `ContentTypeNotSupportedError`
for another `mediaType`, which is a transport condition to the sender. A receiver MAY answer
`SendStreamingMessage` with `UnsupportedOperationError`, as EBL's evidence request carriage does.

### 4.3 The reply

The receiver MUST return a `Task`, not a direct `Message`, in `TASK_STATE_COMPLETED`, holding one
`Artifact` whose `extensions` contain the extension URI, with exactly one `Part` whose content is
`data`, holding the answer object (§2.2), and whose `mediaType` is `application/json`. A refused
part is an answer: the task still completes.

The sender looks for that Artifact by the extension URI, whatever the task state, as IP §11.4.4
does: an Artifact of that form is the answer (§2.3 rule 5). No such Artifact, a task with no
Artifact, an A2A error or a direct `Message` is a transport condition.

The receiver keeps no task: `GetTask` and `CancelTask` find nothing, and `ListTasks` lists none.
The identifiers it mints (`id`, `contextId`, `artifactId`) MUST be unpredictable and MUST NOT
encode a count or a time (IP §11.4.3). The task's `status.message`, the Artifact's `name`,
`description` and `metadata`, and the task's `history` are never part of the answer.

### 4.4 Example (informative)

The same push as §3.4:

```
POST /rpc HTTP/1.1
Content-Type: application/json
A2A-Version: 1.0
A2A-Extensions: https://datatracker.ietf.org/doc/draft-mih-agent-record-push/

{"jsonrpc": "2.0", "id": 7, "method": "SendMessage", "params": {"message": {
  "messageId": "m-7", "role": "ROLE_USER",
  "extensions": ["https://datatracker.ietf.org/doc/draft-mih-agent-record-push/"],
  "parts": [{"mediaType": "application/json", "data": {
    "record": "<the record octets, base64url>",
    "stamp_proof": "<the stamp proof's JSON octets, base64url>"}}]}}}
```

The completed task carries one Artifact
`{"artifactId": "…", "extensions": ["https://datatracker.ietf.org/doc/draft-mih-agent-record-push/"], "parts": [{"mediaType": "application/json", "data": <the answer object of §3.4>}]}`.

## 5. Both carriages, one push

A push sent over MCP and the same push sent over A2A carry the same octets and are answered by
the same SF §6 steps: the second is answered `duplicate` for each part the first stored or kept.
Neither carriage adds a part, an outcome or an answer member, and neither carriage's fields
change an answer.

## 6. Security and privacy considerations

- **Who learns that a push was made.** Over MCP's Streamable HTTP, the tool name travels in a
  request header (IP §11.4.5), so intermediaries can see that a `record_push` call was made. Only
  transport confidentiality hides that. No property carries `x-mcp-header` (§3.1), so the record
  and the proof never go into a header.
- **Probing.** A duplicate or deleted record is answered before the push rule runs (SF §6.2 steps
  3 to 5), so a party that has a record's bytes can learn from the answer whether the receiver
  holds or held it. This binding carries the answer SF gives and does not change that order
  (SF-6, SF §8).
- **Discovery.** The tool and the extension entry are the same for every caller and say only that
  pushes are taken (§2.3 rule 7).
- **The answer is unsigned.** An intermediary can alter an answer. A sender that needs evidence
  of what the receiver holds asks for it by other means; an answer is never that evidence (§2.2).
- **Bounds.** The message bound (§2.3 rule 6) runs before parsing; SF's bounds (SF §6.2 steps 1,
  6 and 7) run on the decoded parts.

## 7. Conformance

This document adds no vectors. The answer objects of §2.2 are those of EBL's receive vectors
(`testdata/shelf/receive/script.json`), which SF-8 adopts for SF §6. The MCP and A2A message
shapes of §3 and §4 have no vectors yet: they are open point RP-1, and an implementation's entry
claims conformance to this binding only once carriage vectors exist.

## 8. Open points

| # | Point |
|---|---|
| RP-1 | Carriage vectors for §3 and §4: a push and its answer over each carriage, and the edge cases (a member that fails strict decoding and a `raw` or `text` part, each answered with an error and no answer; an answer Artifact on a task not completed, which is still the answer; a completed task with no such Artifact, a transport condition). They are to land with the first implementation's MCP and A2A entry for `Receive`, in this repository's `vectors/`. |
