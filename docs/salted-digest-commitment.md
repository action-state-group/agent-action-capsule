# Salted JSON-DIGEST Commitment

**Status:** Informational note, not part of `draft-mih-scitt-agent-action-capsule` or any other
Internet-Draft in this repository. It names a construction so that a profile which uses it can
point at one description and one set of vectors. It registers nothing, changes no draft text and
places no requirement on producers or verifiers.
**Identifier:** `sha256-jcs-nonce256`.
**Vectors:** `vectors/salted-digest-commitment/`.

---

## The construction

A producer that wants to commit to a text now and reveal it later, to a party of its choosing,
picks a nonce `N` of 256 bits written as 64 lowercase hexadecimal characters, and computes

    commitment = JSON-DIGEST({"nonce": N, "text": T})

where `T` is the text as a JSON string and JSON-DIGEST is the base profile's rule, as the
Disclosure Envelope (`draft-mih-agent-disclosure-envelope-00`) restates it under "JSON-DIGEST":
the lowercase-hex SHA-256 of `UTF8(JCS(value))`, with JCS as defined in RFC 8785 and no member
filtering. The commitment is therefore an ordinary 64-character JSON-DIGEST, and the record that
carries it can name the construction with the identifier `sha256-jcs-nonce256`.

For example, with `N` = `abab…ab` (the two characters `ab` repeated 32 times) and `T` =
`412.00 USD`, the preimage is the RFC 8785 string

    {"nonce":"abababababababababababababababababababababababababababababababab","text":"412.00 USD"}

and the commitment is `47c96a7dc56f9f7e78c114f1d2fdd22ce4b0a5c190a93e65fcd6bea7e6628edf`
(vector `pos-ascii`).

## Opening and checking

The commitment is opened by disclosing the object `{"nonce": N, "text": T}`. The party that
receives it checks the opening with the same computation as Disclosure Envelope check DE-3
("Digest Recomputation and Comparison"): compute JSON-DIGEST of the disclosed object and compare
it with the commitment. Equal means the disclosed text is the text that was committed; different
means it is not, and the text is then not confirmed.

Only DE-3's computation is reused. DE-1 (eligibility) and DE-2 (committed-digest presence) look
up a Capsule field in the Disclosure Envelope's eligibility table, and a commitment of this kind
is a member that a profile defines inside its own payload, not one of those fields. A profile
that uses the construction says where its commitments sit and where an opening is delivered.

## What the construction gives, and what it does not

- **Hiding.** Without the opening, the commitment shows nothing about `T` beyond what a guess can
  confirm, and a 256-bit nonce chosen unpredictably makes guessing `T` impractical, even for a
  short or predictable text such as an amount.
- **Binding.** A different nonce or text gives a different commitment (vectors
  `neg-nonce-other`, `neg-text-edited`). JCS compares strings exactly: it does not case-fold
  (`neg-nonce-uppercase`), trim (`neg-trailing-space`) or Unicode-normalize, so a checker that
  normalizes either side is not performing the check.
- **Equality by design.** The same nonce and text always give the same commitment (vector
  `equality-same-nonce-same-text`). A producer that commits the same text in two records under one
  nonce lets anyone see that the two are equal without seeing the text; under separate nonces the
  two commitments are unlinkable.
- **No authentication of its own.** An opening is not signed. What makes a matching opening
  meaningful is that the commitment sits in a record whose integrity is already established, for
  example a Capsule whose `capsule_id` covers the payload that carries it.

## Not the Selective Disclosure profile

This construction is not the Selective Disclosure profile
(`draft-mih-scitt-agent-action-capsule-sel-disc-00`). That profile conceals members drawn from a
closed set of SD-eligible Capsule fields, each under its own 128-bit salt in a
`[salt, name, value]` disclosure, with base64url digests in `_sd` arrays signalled by `_sd_alg`.
A salted JSON-DIGEST commitment covers a text that a profile carries in its own payload, so it
needs neither the eligible set nor the `_sd` structure, and its bytes differ: the two encodings
of the same text give different digests and cannot be substituted for one another.
