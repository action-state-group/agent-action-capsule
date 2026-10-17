# Adapter declaration: Agentic Commerce Protocol (ACP) — v0

**Status.** Informational adapter declaration, kept in this repository. It is not part of any
Internet-Draft revision and changes no posted draft or profile. For each object ACP produces that
an Artifact may carry or cite, it makes five declarations (§2). These say what a verifier can and
cannot check about the object under the Minimum Evidence Interoperability Profile
([`interop-profile-v0.md`](../interop-profile-v0.md), cited here as IP) and
`draft-mih-agent-settlement-records-00` (SR).

**Answer in one paragraph.** ACP 2026-04-17 defines no signature by the issuer over any of the
objects declared here: not the checkout session, not the order, and not the delegated payment
token. A response reaches its caller over TLS, and nothing in the response octets authenticates
it to anyone else. ACP's request `Signature` header is produced by the caller, over the caller's
own request. Its canonical form is unspecified, and its algorithm is advertised out of band (§3.1).
The order webhook carries an HMAC under a secret the two parties to it share (§3.3). So this
adapter supports possession of exact octets and nothing more (IP §5.1; SR §8 rule 3). Its
`native_check` is `NOT_PRESENT` for the checkout session, order and token, and `NOT_CHECKED` for
the webhook HMAC. No conformance vector in this repository pretends otherwise. §4 names what ACP
would have to add for a native check to exist.

## 1. What was read

All of it is from <https://github.com/agentic-commerce-protocol/agentic-commerce-protocol>, read
at commit `7fdd78df677a94dce04c770644b0fbbb1401272b` (default branch, 2026-07-17). The released
API version is `2026-04-17`, and its release commit is `9abf303f48088d170503a54502d612b8b1997897`.
Two later commits changed files under `spec/2026-04-17/`:

- `6b828681206f1f98a3faba978610ced66770d2ae` (2026-04-30), an order schema alignment;
- `17adf494cf8b4bcb41967a0386188b8103316d2f` (2026-06-15), an examples fix.

The digests below are of the bytes at the commit read, not the release commit. No change between
the two touches a signature, HMAC or signing header.

| Cited as | File at the commit read | SHA-256 |
|---|---|---|
| OAS-CHK | `spec/2026-04-17/openapi/openapi.agentic_checkout.yaml` | `2a0aa239b4aed50732461d9b7e443ad98d5c2d3431277899433ead07cbd4fc55` |
| OAS-DP | `spec/2026-04-17/openapi/openapi.delegate_payment.yaml` | `ffc98ff3b7a69dd2be5feffe3d91eaf0a687aab31b3fb55b4db63a4e06b4815a` |
| OAS-WH | `spec/2026-04-17/openapi/openapi.agentic_checkout_webhook.yaml` | `10f84a9a20658d1990bd514017c8ad8494d8c65bd30568f476da1883b747c1c9` |
| JS-CHK | `spec/2026-04-17/json-schema/schema.agentic_checkout.json` | `d0e4290617d66bf05d002b8ace388732be2b3eb9a92a1003db7a2daa1e0436f2` |
| JS-DP | `spec/2026-04-17/json-schema/schema.delegate_payment.json` | `307739ae400e7368eaa25c6024d30751348a4af8a516d071565fcd8aa328cf4d` |
| RPC-CHK | `spec/2026-04-17/openrpc/openrpc.agentic_checkout.json` | `99692a36eb01dac949bf51837ac64ed4e14f83015de94a3060a83d01ab16ed67` |
| RFC-CHK | `rfcs/rfc.agentic_checkout.md` (header: Draft, version 2026-01-16) | `6dd81e0f3e0767a3ca9a3c8b1770c475228707c9711d0c39abcfdb6ea4c00da2` |
| RFC-DP | `rfcs/rfc.delegate_payment.md` (header: Draft, version 2025-09-29) | `d9086ccbd0e8ec66bbd0acab0b9f667c602da3e93a882a8003aaa4282d97e8c5` |
| RFC-DA | `rfcs/rfc.delegate_authentication.md` (header: Draft, version 2026-01-28) | `da26179bf065d6a73dc69cd1cedacdf5862cc2ee3e1873dc9c4772e347a5556b` |
| RFC-DISC | `rfcs/rfc.discovery.md` (header: Proposal, unreleased) | `1a8ffd29b60d8267a40ee87dc1df27cd2c131bab0195adeb066b31c110d8414d` |
| MCP | `docs/mcp-binding.md` | `d0923f212aa5136c17d8118a558e7147898d7446ee19e89edb8ba7829a6d9df1` |

Operations are cited by their OpenAPI `operationId`, and MCP tools by their OpenRPC method name.

## 2. The five declarations

For each object, this document declares:

- **(a)** the native object and its format;
- **(b)** the issuer, and how the relying party's trust policy resolves it;
- **(c)** the native verification method;
- **(d)** the exact predicate the adapter can support;
- **(e)** the per-property result, with the method that produced it, in the IP §7.1 vocabulary.

**Octets of an unsigned object.** IP §5.1 states the as-transmitted rule for a foreign *signed*
object. None of the objects below is signed. This declaration still digests them the same way, as
its own choice: SHA-256 over the octets as delivered, never parsed and re-serialized. Every byte
counts, and no normalization is applied. A trailing newline, for example, is part of the octets
and of the digest.

**The carried digest.** ACP itself carries no digest, so the carried digest is never an ACP
property. It comes from one of two places:

- a settlement-records wrapper: the digest that the wrapping record states for the wrapped octets
  (SR §8);
- with no wrapper (a standalone adapt), a relying-party pin, `acp.carried_digest`.

The digest row's `method` says which of the two it is.

### 2.1 Checkout session

**(a) Object and format.** A `CheckoutSession` object, or a `CheckoutSessionWithOrder` object once
the session completes (JS-CHK `$defs`). It is a JSON response body returned by:

- `createCheckoutSession` (`POST /checkout_sessions`, 201);
- `updateCheckoutSession` (`POST /checkout_sessions/{checkout_session_id}`);
- `getCheckoutSession` (`GET /checkout_sessions/{checkout_session_id}`);
- `completeCheckoutSession` (`POST /checkout_sessions/{checkout_session_id}/complete`);
- `cancelCheckoutSession` (`POST /checkout_sessions/{checkout_session_id}/cancel`).

Over MCP, the same object is the JSON-RPC `result` of `create_checkout_session`,
`get_checkout_session`, `update_checkout_session`, `complete_checkout_session` or
`cancel_checkout_session` (RPC-CHK; MCP "Response Mapping").

The octets are the response body as received: the HTTP message content after any content coding
is removed, or, over MCP, the octets of the `result` member's value as it appears in the JSON-RPC
response. ACP fixes no byte sequence for the object itself. Two retrievals of the same session
are different octets and different digests.

**(b) Issuer.** The merchant (the server of the checkout API). ACP gives the object no issuer
identifier or key. The only attribution is the caller's TLS connection to the merchant's endpoint
(RFC-CHK §7 "Security Considerations"). That provenance is the caller's own observation, and a
third party cannot re-check it from the octets. When an MCP server proxies a merchant's REST API
(MCP "Proxy Trust Boundary"), the TLS connection reaches only the proxy. A relying party's trust
policy has nothing in the object to resolve.

**(c) Native verification method.** None. OAS-CHK defines these response headers for the
operations:

- `Idempotency-Key` and `Idempotent-Replayed` on POST responses;
- `Request-Id` on the 201 of `createCheckoutSession`;
- `Retry-After` on the 409 responses;
- none on `getCheckoutSession`.

None is a signature. The `Signature` and `Timestamp` request headers are the caller's signature
over its own request (§3.1), not the merchant's over the session.

**(d) Supported predicate.** Possession only: *the presenting party holds octets whose SHA-256 is
`D`, and states they are the body ACP returned from operation `O` at time `T`*. The digest binds
the octets. The operation, the time and the merchant are the presenter's statement. Carrying the
object does not establish that the merchant produced it. Nor does it establish that its `status`,
`line_items`, `totals` or `order` were the merchant's state (IP §5.1). A sealer that carries it
holds those octets, and that is all its own envelope says (SR §8 rule 3).

**(e) Per-property result.**

| Property | Status | Method |
|---|---|---|
| digest of carried octets | `PASS` or `FAIL` | `SHA-256 over the octets as delivered`, compared with the carried digest from the wrapper or from the `acp.carried_digest` pin, naming which |
| `native_check` | `NOT_PRESENT` | `none: ACP 2026-04-17 defines no issuer signature over CheckoutSession` |

### 2.2 Order

**(a) Object and format.** An `Order` object. It is produced in two places, and its schema
depends on which:

1. the `order` member of the `CheckoutSessionWithOrder` that `completeCheckoutSession` returns
   (RFC-CHK §4.4 "Complete Session").
   - It validates against JS-CHK `$defs/Order`, which requires `id`, `checkout_session_id` and
     `permalink_url`.
   - Its octets are those of §2.1 (a). The order is a member inside them, not separately
     delivered octets.
   - Such a response therefore gives two `native_check` results, one for the session and one for
     the order. Each names its object in `detail`. It gives one digest, over the single octet
     string.
2. the `data` member of an order event that the merchant POSTs to the agent platform's receiver
   by `postOrderEvents` (`POST /agentic_checkout/webhooks/order_events`, OAS-WH).
   - It validates against OAS-WH's `EventDataOrder`. That is the checkout `Order` with `type`,
     `checkout_session_id`, `permalink_url` and `status` also required.
   - Its octets are the request body as received, the `raw_body` of OAS-WH's signing rule.

**(b) Issuer.** The merchant. In path 1 the attribution is as for §2.1 (b). In path 2 the request
carries a `Merchant-Signature` header (§3.3). Its key is a secret shared by the merchant and the
receiving platform. Either holder can compute a valid value, so it identifies no single issuer to
a third party. ACP defines no way to publish that key or resolve it under a relying party's
trust policy.

**(c) Native verification method.** None that attributes the object to the merchant alone. The
webhook HMAC is a check between the two secret holders (§3.3).

**(d) Supported predicate.** Possession only, as §2.1 (d), with `O` = `completeCheckoutSession`
or `postOrderEvents`. For path 2, the receiving platform may also *state* that it verified the
`Merchant-Signature` at receipt. That statement is the receiver's own, and no one else can re-check
it.

**(e) Per-property result.**

| Property | Status | Method |
|---|---|---|
| digest of carried octets | `PASS` or `FAIL` | as §2.1 (e) |
| `native_check` (path 1) | `NOT_PRESENT` | `none: ACP 2026-04-17 defines no issuer signature over Order` |
| `native_check` (path 2, `Merchant-Signature` present) | `NOT_CHECKED` | `not run: HMAC-SHA256 under a shared secret (OAS-WH Merchant-Signature)`, with the reason in `detail` (§3.3) |
| `native_check` (path 2, `Merchant-Signature` absent) | `NOT_PRESENT` | `none: no Merchant-Signature header was received with the order event body` |

### 2.3 Delegated payment token

**(a) Object and format.** A `DelegatePaymentResponse` object (JS-DP; members `id`, `created`,
`metadata`). It is the JSON body of the 201 response to `delegatePayment`
(`POST /agentic_commerce/delegate_payment`, OAS-DP; RFC-DP §2.4 "Token Creation & Response").

- `id` is an opaque vault token identifier (`vt_…`).
- The token's constraints are the `Allowance` in the *request*: `reason`, `max_amount`,
  `currency`, `checkout_session_id`, `merchant_id` and `expires_at` (RFC-DP §3.5). The response
  does not restate them.
- The token is later presented as `payment_data` to `completeCheckoutSession`.
- The octets are the response body as received.

**(b) Issuer.** The server of the delegate payment API. OAS-DP describes the operation as
tokenizing a credential "for controlled usage by the merchant's PSP per the **Allowance**
constraints". ACP gives the response no issuer identifier or key. Attribution is the caller's TLS
connection to that server (RFC-DP §6 "Security Considerations").

**(c) Native verification method.** None. RFC-DP §2.5 "Usage & Expiry" requires that the token be
usable only within the Allowance and become invalid at `expires_at`. It does not name who checks
this. ACP defines nothing a third party can check that binds `id` to an Allowance, signed or
otherwise. It also defines no operation a third party can call to query the token's state.

**(d) Supported predicate.** Possession only: *the presenting party holds octets whose SHA-256 is
`D`, and states they are the body `delegatePayment` returned at time `T`*. These octets do not
show that the token existed, was bound to a given Allowance, or was valid at any time. Suppose a
token identifier also appears in a carried `completeCheckoutSession` request. That shows only
that the two carried objects name the same string.

**(e) Per-property result.**

| Property | Status | Method |
|---|---|---|
| digest of carried octets | `PASS` or `FAIL` | as §2.1 (e) |
| `native_check` | `NOT_PRESENT` | `none: ACP 2026-04-17 defines no issuer signature over DelegatePaymentResponse` |

## 3. The signatures ACP does define, and why none is a native check here

### 3.1 The request `Signature` header

The `Signature` and `Timestamp` headers appear on the request for every checkout operation in
OAS-CHK and for `delegatePayment` in OAS-DP. Over MCP they are `meta.signature` and
`meta.timestamp` (MCP "Header Mapping"). The caller signs, so this is a signature over the
caller's request, never over a merchant or issuer object. Nor does it support a third-party check
of the request itself at this version:

- **It is optional.** OAS-CHK and OAS-DP mark it `required: false`, and RFC-CHK §3.1 and RFC-DP
  §2.3 list it as RECOMMENDED. Only RFC-DP §2.2 "Preparation & Signing" says the client MUST sign.
  RFC-DA lists it as REQUIRED for its own operations, and its §8 says it MUST be verified.
- **Its signing input is not specified.** RFC-DP §2.2 says "a canonical JSON scheme" and RFC-CHK
  §2.1 says "canonical JSON". Neither names a scheme, so a verifier cannot rebuild the signed
  octets reliably.
- **The algorithm and key are not discoverable.** The algorithm is "advertised out-of-band"
  (RFC-DP §2.1; RFC-CHK §2.1). No key identifier is carried, and no key discovery is defined.
  RFC-DISC §11 "Future Extensions" lists "Public key advertisement (JWK format) for signature
  verification, enabling agents to verify the authenticity of responses. Deferred pending
  formalization of ACP's request signing specification."
- **The released files disagree on what the value is.** OAS-CHK describes it as "HMAC signature
  for webhook verification". OAS-DP describes it as a "Detached JSON signature for request
  verification". RFC-DP §2.2 describes a detached signature computed with the client's private
  key.

A future adapter for a *caller-issued* object (the signed `completeCheckoutSession` request)
could declare a native check once ACP fixes these. This revision does not.

### 3.2 Transport authentication

`Authorization: Bearer` authenticates the caller to the server. TLS (RFC-CHK §7; RFC-DP §6)
authenticates the server's endpoint to the caller for the duration of one connection. Neither
leaves anything in the delivered octets that a later verifier can check.

### 3.3 The webhook `Merchant-Signature`

OAS-WH defines the header as `t=<unix_seconds>,v1=<64_hex>`, where `v1` is HMAC-SHA256 over
`timestamp + "." + raw_body` under a shared secret. A verifier that is neither party lacks the
secret and cannot run the check. A secret holder that runs it and gets `PASS` learns only that
one of the two holders produced the value. This adapter does not run the check, because its
result cannot attribute the order to the merchant alone. It reports `NOT_CHECKED`, the IP §7.1
status for a check the verifier did not run. The reason goes in `detail`. When an order event
body arrives without the header, the input the check needs is absent, and the status is
`NOT_PRESENT`.

## 4. What ACP would need for a native check

Each item names the addition, not a design for it. This document proposes none of them upstream.

1. **An issuer signature over the response body**, for the checkout operations and
   `delegatePayment`. Its signing input must be the delivered octets, or octets ACP fixes. Then
   the digest taken over the octets as delivered and the signed bytes coincide, as IP §5.1
   requires for a foreign signed object.
2. **Issuer key publication and resolution.** A key identifier in the signature, and a published
   key set per merchant and per token issuer, so that (b) resolves under a relying party's trust
   policy. RFC-DISC §11 already lists JWK advertisement "to verify the authenticity of responses"
   as deferred.
3. **An asymmetric signature on order events**, in addition to or in place of the shared-secret
   HMAC, so that an `Order` delivered by `postOrderEvents` is attributable to the merchant alone.
4. **A signed token statement.** A statement by the token issuer binding the token `id` to the
   Allowance members it is limited to (`max_amount`, `currency`, `checkout_session_id`,
   `merchant_id`, `expires_at`). A verifier could then check what the token was limited to.
5. **A fixed request-signing profile**: a canonical form, an algorithm identifier and a key
   identifier. It also needs OAS-CHK's `Signature` description reconciled with OAS-DP and RFC-DP
   §2.2. This item is for the caller-issued request (§3.1), not the issuer objects above.

## 5. Settlement records and the Wrapped Object Types registry

SR §8 "Wrapping Existing Signed Objects" is written for objects signed under their own protocol.
Its registry (SR "Wrapped Object Types") already holds entries that are not signatures, such as
`iso20022.message` and `delivery.proof`. Each entry names an issuer and exact octets, and the
§2 declarations above supply both. ACP objects could therefore be registered. This revision
requests no `acp.*` registration: see open point A-3.

## 6. Conformance vectors

None in this revision. A positive and native-check-fails pair needs a native check, and §2 shows
that ACP 2026-04-17 has none for these objects. A later revision adds vectors under
`vectors/adapters/acp/` only for what it can actually check: the digest property of §2, using
example bodies that validate against JS-CHK and JS-DP. Any native-check vector waits until ACP
adds one of the items in §4.

**Upstream examples and schema, at the commit read.** An adapter validates against ACP's schema,
not against ACP's examples. Some of those examples fail the schema, and one schema cannot be
satisfied. The check behind each fact below:

- tool: Python `jsonschema` 4.10.3, Draft 2020-12;
- schemas: OAS-CHK and OAS-WH `components/schemas`, with OAS-WH's `$ref` to OAS-CHK resolved
  across the two files;
- examples: `examples/2026-04-17/`.

The facts:

- `webhook_order_create_event` and `webhook_order_update_event` in
  `examples.agentic_checkout.json` fail OAS-WH `WebhookEvent`. Each `data` carries `refunds`,
  which the schema does not allow, and lacks the required `id`.
- Every checkout response `result` in `examples.mcp.agentic_checkout.json` fails OAS-CHK:
  - `create_checkout_session_response` carries a `links[].type` of `terms_of_service`, which is
    not in the enum;
  - the `get`, `update`, `complete` and `cancel` responses lack the required
    `fulfillment_options`.
- In OAS-CHK, `CheckoutSessionWithOrder` cannot be satisfied when its schema is applied strictly.
  It is `allOf` of `CheckoutSessionBase` and an object adding `order`, and OAS-CHK's
  `CheckoutSessionBase` sets `additionalProperties: false` without listing `order`, so it rejects
  `order`. No completed session validates against OAS-CHK as written. JS-CHK does not have this
  defect: its `$defs/CheckoutSessionBase` lists `order` among its properties, so a completed session
  validates against JS-CHK as a whole object. A validator for path 1 of §2.2 that uses OAS-CHK has
  to treat this case specially, and this declaration does not choose how (open point A-4).

These facts are recorded here only, not reported upstream.

## 7. Open points

- **A-1 (closed).** IP §8.1 rows 5 and 6 cover a `native_check` `FAIL`, and no row covers
  `NOT_PRESENT` or `NOT_CHECKED`. Until a profile revision adds rows, a `native_check`
  `NOT_PRESENT` or `NOT_CHECKED` is mapped as profile §8.1 rows 3-4 pending a profile row:
  - `NOT_PRESENT` gives `INSUFFICIENT` / `INSUFFICIENT` / `not_evaluable` when the requirement is,
    or rests on, that check;
  - `NOT_CHECKED` gives `UNKNOWN` / `UNKNOWN` / `not_evaluable`;
  - neither gives `met` or `not_met` (RES §1).

  Every ACP object declared here has no native signature. So its `NOT_PRESENT` never counts
  against a requirement that does not rest on that check.
- **A-2.** An MCP `result` (§2.1 (a)) has as-transmitted octets that depend on how the JSON-RPC
  response is serialized, and ACP does not fix that. So two parties may not compute the same
  digest for the same session.
- **A-3.** Whether to register `acp.checkout-session`, `acp.order-event` and
  `acp.delegate-payment-response` in SR "Wrapped Object Types" (Specification Required), using the
  issuers and octets of §2. A settlement leg that needs to cite an ACP object meanwhile carries
  its digest as an opaque reference.
- **A-4.** How to validate a `CheckoutSessionWithOrder` against OAS-CHK, which, applied
  strictly, cannot accept one (§6). JS-CHK accepts it as a whole object. One option validates `order` against `$defs/Order` and the
  rest against `CheckoutSessionBase`. The other evaluates `additionalProperties` across the
  `allOf`.
