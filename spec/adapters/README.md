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

Every declaration states the same five items, in this order:

| Item | What it states |
|---|---|
| (a) The native object | Each object the adapter reads, its format, and the exact octets it is held as: the as-transmitted octets of IP §5.1, never a re-encoding |
| (b) The issuer | Who issues each object, and how the relying party's trust policy resolves that issuer (a key set, an address, a policy entry). Where an object has no cryptographic issuer, the declaration says so and names what attribution there is, such as a TLS connection |
| (c) The native verification method | The method each object defines for itself, run over the held octets. Where an object defines none, the declaration says so: the object is held by digest, which proves possession of its octets and nothing more |
| (d) The predicates supported | The exact predicates the adapter can report on, and how each maps to an Evidence Result (IP §8). A predicate the declaration does not list is not supported |
| (e) The per-property results | For each check, the result for each IP §7.1 status and the `method` text reported with it, as a `native_check` report (IP §7.2) |

Each declaration also opens with a status line, says which sources it read and at which version or
commit, and states its scope: what it supports and what it reports otherwise, which is usually
`NOT_CHECKED`. Where a declaration has vectors, it says where they are.

## 2. Naming a declaration

A declaration is named by a pair, `{id, digest}`:

- `id` is the declaration's name and revision, written as its file name without `.md`, for
  example `x402-v0` or `lightning-v0`.
- `digest` is the SHA-256 of the declaration file's exact bytes at the revision relied on, in
  lowercase hexadecimal.

The id alone names no particular text: a declaration is edited in place, and two repositories can
each hold a declaration with the same id. The pair names one text. Any edit to a declaration
changes its digest, so a relying party that pinned the pair keeps relying on the text it
reviewed until it pins the new one.

## 3. An undeclared adapter is not checked

A verifier, or a relying party's policy, accepts a set of declarations, each named by its pair. For
a foreign object, the verifier uses the accepted declaration that covers it. When there is none,
the verifier reports each property it was asked to check about that object as `NOT_CHECKED`
(IP §7.1). That covers two cases:

- **No declaration covers the object**, for example a rail no adapter is declared for. The method
  is unsupported.
- **A declaration covers the object, but its pair is not accepted**: the policy pins no
  declaration with that id, or pins one with another digest. The policy excludes it.

Neither case is ever `PASS`, and neither is `FAIL` for that reason alone: an object the verifier
did not check has not failed. IP §8 maps `NOT_CHECKED` as it maps any other.

## 4. Worked examples

The digests below are of the files at the commits named, and change with any later edit. Compute
the digest from the exact bytes, for example `shasum -a 256 x402-v0.md`.

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

Pinning `x402-v0` with another digest, such as a later edit's, is the second case of §3: until the
policy pins the new digest, the edited text checks nothing.
