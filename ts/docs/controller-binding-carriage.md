# Carrying a key's Controller Binding to a page (ladder rung 8)

This is a convention on an existing mechanism, not a new bundle member. The
Controller Binding v0 spec (`spec/controller-binding-v0.md`) and the bundle
drafts are unchanged.

**Carriage.** A binding record reaches a page as an ordinary record. The record
whose `key_id` the binding binds cites it through a `references[]` entry with
`digest_alg` `SHA-256` and a `digest` that is the SHA-256 of the binding
record's octets as transmitted, not the CB §4 binding digest. No `type` value is
registered for binding records and this convention fixes none: the page matches
on the digest. The caller checks that match before handing the octets to
`verifyKeyBinding`, which does not. A bundle that holds the cited binding's
octets lets the page check it; one that does not leaves rung 8 `NOT_CHECKED`.

**Check.** `verifyKeyBinding(keyId, at, records, options)` takes the binding
octets the page resolved from those citations, the record's `key_id`, and the
record's own time `at`. It runs `verifyBinding` on each and keeps those whose
`keys` include `keyId`:

| Result        | When                                                                                                                                                                                 |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `NOT_CHECKED` | no handed binding names the key (none cited, or all name other keys)                                                                                                                 |
| `PASS`        | at least one names the key and applies at `at` (CB §6.2: form, signatures and window `PASS`, revocation not `FAIL`)                                                                  |
| `FAIL`        | some name the key and none applies: outside its validity window, revoked, signed by one key, or an unverifiable signature method. A record that does not name the key is not counted |

**What `PASS` says.** Both key holders signed the claim (CB §7). It names no
controller, person or organization, and a page must not. A revocation statement
the page was given makes the binding `FAIL` (CB §6.2). A revocation the page was
not given cannot be seen: no revocation source is registered (CB-1), so
`revocationChecked` is true only when an applying binding's
`controller_binding_revocation` is `PASS` under a declaration that counts
(CB §5.1). A binding revoked by a statement the page was not given still reads
`PASS`, with `revocationChecked` false, and the page says so.

**Vectors.** `ts/test/key-binding-vectors.test.ts` and the Go verifier read the
same files under `vectors/controller-binding-v0/`, not copies.
