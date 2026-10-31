# Adapter declarations

**Status.** Informational, pre-Internet-Draft. This file describes the declarations in this
directory. It changes no posted draft, no profile and no registry, and it adds no status, no
property and no wire member.

An adapter declaration says what a verifier can and cannot check about a foreign object: one that
another protocol produced and an Artifact carries or cites. The rules each declaration applies
are those of the Minimum Evidence Interoperability Profile
([`interop-profile-v0.md`](../interop-profile-v0.md), cited here as IP), above all §5.1 (a foreign
signed object, carried as transmitted) and §7 (property statuses and the `native_check` report).

The declarations here are [`x402-v0.md`](x402-v0.md), [`ucp-v0.md`](ucp-v0.md) and
[`acp-v0.md`](acp-v0.md). A declaration may also live outside this repository, beside the code
that implements it. The Lightning declaration is `adapters/lightning-v0.md` in
Mesh-LLM/capsules-plugin.

## 1. The five items

Every declaration states the same five items, each labelled (a) to (e). A declaration may state
them once for the file or once per object it covers, and in any order; x402-v0, for example,
gives (e) in its §7 before (d) in its §8.

| Item | What it states |
|---|---|
| (a) The native object | Each object the adapter reads, its format, and the exact octets it is held as: the octets IP §5.1 names, as the originating protocol delivered them and never parsed and re-serialized, canonicalized only where the object's own type definition says so (as x402-v0 does for its EIP-712 receipt) |
| (b) The issuer | Who issues each object, and how the relying party's trust policy resolves that issuer (a key set, an address, a policy entry). Where an object has no cryptographic issuer, the declaration says so and names what attribution there is, such as a TLS connection |
| (c) The verification method | The method each object defines for itself, run over the held octets. Where an object defines none, the declaration says so: holding it by digest proves possession of its octets and nothing more. A declaration may add checks the adapter runs against an independent source or by joining objects, such as x402-v0's recorded chain lookup or lightning-v0's join on `payment_hash`; each such check names its source in `method` |
| (d) The predicates supported | The exact predicates the adapter can report on and, where the declaration gives one, how each maps to an Evidence Result (IP §8; see §3 below for `NOT_CHECKED`). A predicate the declaration does not list is not supported |
| (e) The per-property results | For each check, the result for each IP §7.1 status and the `method` text reported with it, as a `native_check` report (IP §7.2) |

Each declaration also opens with a status line and says which sources it read, at which version
or commit. A declaration may state its scope, what it supports and what it reports otherwise, as
x402-v0 §3 does. Where a declaration has vectors, it says where they are.

## 2. Naming a declaration

A declaration is named by a pair, `{id, digest}`:

- `id` is the declaration's name and revision, written as its file name without `.md`, for
  example `x402-v0` or `lightning-v0`.
- `digest` is the SHA-256 of the declaration file's bytes as committed at the revision relied on,
  in lowercase hexadecimal: the git blob, not a working copy that a checkout may have converted
  (for example to CRLF line endings).

The id alone names no particular text: a declaration is edited in place, and two repositories can
each hold a declaration with the same id. The pair names one text. Any edit to a declaration
changes its digest, so a relying party that pinned the pair keeps relying on the text it
reviewed until it pins the new one.

## 3. An undeclared adapter is not checked

A verifier, or a relying party's policy, accepts a set of declarations, each named by its pair. For
a foreign object, the verifier uses the accepted declaration that covers it. When more than one
accepted declaration covers the object, as during a move from one digest to another, the policy
names the one that applies; if it names none, no declaration applies. When no declaration
applies, the verifier reports each property it was asked to check about that object as
`NOT_CHECKED` (IP §7.1). That covers two cases:

- **No declaration covers the object**, for example a rail no adapter is declared for. The method
  is unsupported.
- **A declaration covers the object, but its pair is not accepted**: the policy pins no
  declaration with that id, or pins one with another digest. The policy excludes it.

Neither case is ever `PASS`, and neither is `FAIL` for that reason alone: an object the verifier
did not check has not failed.

IP §8.1 has no row for a `native_check` that is neither `PASS` nor `FAIL`, so a `NOT_CHECKED`
must not fall through to row 7 and be evaluated as if the object had been checked. Until a profile
revision adds a row, the declarations map it as IP §8.1 row 4 (x402-v0 §8.1, ucp-v0 and acp-v0
likewise): when the requirement is or rests on that object, `UNKNOWN`, sufficiency `UNKNOWN`,
verdict `not_evaluable`, never `met` or `not_met`.

## 4. Worked examples

The digests below are of the files at the commits named, and change with any later edit. Compute
a digest from the committed bytes, for example
`git show dbde399111f13ae880e388c7117fd5991c61456a:spec/adapters/x402-v0.md | shasum -a 256`.

| Declaration | `id` | Where | Commit | `digest` |
|---|---|---|---|---|
| x402 payments | `x402-v0` | this directory, [`x402-v0.md`](x402-v0.md) | `dbde399111f13ae880e388c7117fd5991c61456a` | `8b2d56701682cdeee33131dfa85eac4660e50de02b0a2b1038eb46e635b520fb` |
| Lightning payments | `lightning-v0` | Mesh-LLM/capsules-plugin, `adapters/lightning-v0.md` | `f046e96e846beb91be5ed4ae32aa88f2dd934411` | `2df8f2c92d1679ac277693ef3a30550f7445afe06d83f45d17dfc61deeda71e4` |

**x402.** A relying party that pins `{x402-v0, 8b2d5670…}` checks an x402 payment by that text.
The text reads the payment payload, the settlement response and the receipt (a), names the payer,
the facilitator and the payee as their issuers (b), and checks the payer's EIP-712 signature and
the settlement on chain (c). It reports the checks in its §7 table (e) for the predicates in its §8
(d). An object outside its scope, such as an x402 version 1 payment, is `NOT_CHECKED` under the
text itself (x402-v0 §3).

**Lightning.** The Lightning declaration has the same five items over a Lightning payment. A
relying party that pins `{lightning-v0, 2df8f2c9…}` checks the payment by that text. One that pins
only `x402-v0` reports every property of a Lightning payment `NOT_CHECKED` (§3): no accepted
declaration covers it.

A verifier that holds a later edit of `x402-v0`, under a policy that pins
`{x402-v0, 8b2d5670…}`, is in the second case of §3: until the policy pins the edit's digest,
the edited text checks nothing.
