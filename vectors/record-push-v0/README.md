# Record push carriage vectors (RP-1)

Carriage vectors for `spec/bindings/record-push-v0.md` §3 (MCP) and §4 (A2A), the open
point RP-1 of that binding. They are derived from the binding text only: every expected
result is written by hand in `python/scripts/generate_record_push_vectors.py` from the
section it cites, and the generator runs no receiver or sender. Every case is
`spec-derived`.

**What they pin:** the shape of the `record_push` tool call and of the A2A `Message`; strict
base64url members (no padding, no other alphabet, at least one octet); that a call or message
that carries no push is answered with an error and never with an answer object (§2.3 rule 3);
how a sender classifies a reply by the answer position alone (§2.3 rule 5), including an answer
Artifact on a task that is not completed, and a completed task with no such Artifact; and the
fixed tool definition and extension entry (§2.3 rule 7).

**What they do not pin:** a record or a stamp proof (both are opaque octets here, of no profile),
the push rule (SF-6, so no case depends on who the sender is), how strictly a proof's JSON is read
(SF-4), or the values of an answer. The answer objects are those of EBL's receive vectors (§7);
the cases here use the §3.4 example only to put a well-formed value in the answer position.

**Not yet checked by an implementation.** No implementation serves `record_push` yet (EBL has
no `Receive` entry for MCP or A2A), so the only checker is the reference reader in
`python/tests/test_record_push_vectors.py`, written from the binding text. An implementation's
entry claims conformance to the binding only once it passes these cases.

## File

`carriage.json` holds the cases. Each has an `id`, a `kind`, a `carriage` (`mcp` or `a2a`),
the `section` it follows, a `description`, an `input` or `received` and an `expect`.

- `push`: `input` is the `tools/call` params (`name`, `arguments`) over MCP, or the `Message`
  over A2A. `expect.result` is `push` with `record_hex` and `stamp_proof_hex` (the octets the
  members decode to, `null` when absent), or `error` with `answer` `false` and `code` `-32602`
  (over A2A an A2A error is also allowed; either way it is a transport condition to the sender).
- `classify`: `pushed` names the parts pushed; `received.response` is the JSON-RPC response the
  sender got. `expect.classification` is `answer` (with the `answer`) or `transport_condition`.
- `declaration`: `input` is a tool definition or an extension entry; `expect.conforms`.

`python/scripts/generate_record_push_vectors.py` regenerates `carriage.json`, `manifest.json`
and `SHA256SUMS`; this file is hand-written.

| Case | Kind | Carriage | Result |
|---|---|---|---|
| `pos-mcp-both-parts` | push | MCP | a push |
| `pos-mcp-record-only` | push | MCP | a push |
| `pos-mcp-proof-only` | push | MCP | a push |
| `pos-mcp-url-safe-alphabet` | push | MCP | a push |
| `pos-a2a-both-parts` | push | A2A | a push |
| `pos-a2a-record-only` | push | A2A | a push |
| `pos-a2a-proof-only` | push | A2A | a push |
| `neg-mcp-empty-arguments` | push | MCP | error, no answer |
| `neg-a2a-empty-arguments` | push | A2A | error, no answer |
| `neg-mcp-extra-member` | push | MCP | error, no answer |
| `neg-a2a-extra-member` | push | A2A | error, no answer |
| `neg-mcp-padded` | push | MCP | error, no answer |
| `neg-a2a-padded` | push | A2A | error, no answer |
| `neg-mcp-standard-alphabet` | push | MCP | error, no answer |
| `neg-a2a-standard-alphabet` | push | A2A | error, no answer |
| `neg-mcp-empty-member` | push | MCP | error, no answer |
| `neg-a2a-empty-member` | push | A2A | error, no answer |
| `neg-mcp-impossible-length` | push | MCP | error, no answer |
| `neg-a2a-impossible-length` | push | A2A | error, no answer |
| `neg-mcp-whitespace` | push | MCP | error, no answer |
| `neg-a2a-whitespace` | push | A2A | error, no answer |
| `neg-mcp-not-a-string` | push | MCP | error, no answer |
| `neg-a2a-not-a-string` | push | A2A | error, no answer |
| `neg-mcp-null-member` | push | MCP | error, no answer |
| `neg-a2a-null-member` | push | A2A | error, no answer |
| `neg-mcp-one-bad-member` | push | MCP | error, no answer |
| `neg-a2a-one-bad-member` | push | A2A | error, no answer |
| `neg-a2a-raw-part` | push | A2A | error, no answer |
| `neg-a2a-text-part` | push | A2A | error, no answer |
| `neg-a2a-metadata-only` | push | A2A | error, no answer |
| `neg-a2a-two-parts` | push | A2A | error, no answer |
| `neg-a2a-no-parts` | push | A2A | error, no answer |
| `neg-a2a-other-media-type` | push | A2A | error, no answer |
| `neg-a2a-task-id-present` | push | A2A | error, no answer |
| `neg-a2a-role-agent` | push | A2A | error, no answer |
| `neg-a2a-extension-not-listed` | push | A2A | error, no answer |
| `pos-classify-mcp-answer-both` | classify | MCP | answer |
| `pos-classify-mcp-answer-record-only` | classify | MCP | answer |
| `pos-classify-mcp-answer-proof-only` | classify | MCP | answer |
| `pos-classify-mcp-refused-is-an-answer` | classify | MCP | answer |
| `pos-classify-mcp-busy-is-an-answer` | classify | MCP | answer |
| `pos-classify-mcp-is-error-true-still-an-answer` | classify | MCP | answer |
| `pos-classify-mcp-text-block-ignored` | classify | MCP | answer |
| `neg-classify-mcp-jsonrpc-error` | classify | MCP | transport condition |
| `neg-classify-mcp-internal-error` | classify | MCP | transport condition |
| `neg-classify-mcp-message-too-large` | classify | MCP | transport condition |
| `neg-classify-mcp-input-required` | classify | MCP | transport condition |
| `neg-classify-mcp-no-structured-content` | classify | MCP | transport condition |
| `neg-classify-mcp-missing-part-member` | classify | MCP | transport condition |
| `neg-classify-mcp-extra-part-member` | classify | MCP | transport condition |
| `neg-classify-mcp-extra-answer-member` | classify | MCP | transport condition |
| `neg-classify-mcp-missing-answer-member` | classify | MCP | transport condition |
| `neg-classify-mcp-wrong-member-type` | classify | MCP | transport condition |
| `neg-classify-mcp-unregistered-refusal` | classify | MCP | transport condition |
| `pos-classify-a2a-completed-answer` | classify | A2A | answer |
| `pos-classify-a2a-record-only` | classify | A2A | answer |
| `pos-classify-a2a-refused-is-an-answer` | classify | A2A | answer |
| `pos-classify-a2a-artifact-on-failed-task` | classify | A2A | answer |
| `pos-classify-a2a-artifact-on-rejected-task` | classify | A2A | answer |
| `pos-classify-a2a-artifact-on-working-task` | classify | A2A | answer |
| `pos-classify-a2a-artifact-on-canceled-task` | classify | A2A | answer |
| `neg-classify-a2a-completed-no-artifact` | classify | A2A | transport condition |
| `neg-classify-a2a-failed-no-artifact` | classify | A2A | transport condition |
| `neg-classify-a2a-artifact-without-extension` | classify | A2A | transport condition |
| `neg-classify-a2a-artifact-other-extension` | classify | A2A | transport condition |
| `neg-classify-a2a-two-parts` | classify | A2A | transport condition |
| `neg-classify-a2a-text-part` | classify | A2A | transport condition |
| `neg-classify-a2a-other-media-type` | classify | A2A | transport condition |
| `neg-classify-a2a-direct-message` | classify | A2A | transport condition |
| `neg-classify-a2a-error` | classify | A2A | transport condition |
| `neg-classify-a2a-extra-part-member` | classify | A2A | transport condition |
| `pos-declared-mcp-tool` | declaration | MCP | conforms |
| `neg-declared-mcp-other-name` | declaration | MCP | does not conform |
| `neg-declared-mcp-header-annotation` | declaration | MCP | does not conform |
| `neg-declared-mcp-open-input` | declaration | MCP | does not conform |
| `neg-declared-mcp-no-min-properties` | declaration | MCP | does not conform |
| `neg-declared-mcp-no-output-schema` | declaration | MCP | does not conform |
| `pos-declared-a2a-extension` | declaration | A2A | conforms |
| `neg-declared-a2a-other-uri` | declaration | A2A | does not conform |
| `neg-declared-a2a-required` | declaration | A2A | does not conform |
| `neg-declared-a2a-params` | declaration | A2A | does not conform |
