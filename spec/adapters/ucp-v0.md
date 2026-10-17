# Universal Commerce Protocol (UCP) adapter declaration — v0

**Status.** Informational, pre-Internet-Draft, kept in this repository. It changes no posted
draft and registers nothing. It declares, for UCP's merchant-side checkout and order objects,
the five items every adapter for a foreign object declares: (a) the native object and format,
(b) the issuer identity and how it is resolved under the relying party's trust policy, (c) the
native verification method, (d) the exact predicate the adapter can support, and (e) the
per-property result with the method that produced it. This revision is stage 1: declarations
only. It ships no vectors.

The rules this declaration applies are those of the Minimum Evidence Interoperability Profile
(`spec/interop-profile-v0.md`, cited as [IP]) and of
`draft-mih-agent-settlement-records-00` (cited as [SR]): a foreign signed object is carried as
exact octets and never re-signed ([SR] §Wrapping Existing Signed Objects); carrying it by digest
proves possession of those octets and nothing more; and a verifier runs the object's native
check before it reports any property of the object's signature or meaning ([IP] §5.1, P-11).

## 1. What was read

| Item | Value |
|---|---|
| Specification | Universal Commerce Protocol, <https://github.com/Universal-Commerce-Protocol/ucp> |
| Version | `v2026-08-25` (git tag) |
| Commit | `cd78fb38e819de77d9b527d110476eccb876f1bd` |
| Also read, for fixtures and test keys | `Universal-Commerce-Protocol/conformance` at `016ecbc22240affdec4429a60d539bedd04ab51b`; `Universal-Commerce-Protocol/samples` at `b7d7a5496d61650e0780f4d1f87684e10f811562` |
| Read on | 2026-10-17 |

Section names below are the headings of the UCP specification at that commit. File paths are
relative to that repository:

- Message Signatures: `docs/specification/signatures.md`
- AP2 Mandates Extension: `docs/specification/payment/extensions/ap2-mandates.md`
- Specification overview, including Identity & Authentication: `docs/specification/overview/index.md`
- Checkout Capability: `docs/specification/shopping/checkout/index.md`
- Checkout Capability - REST Binding: `docs/specification/shopping/checkout/rest.md`
- Order Capability: `docs/specification/shopping/order/index.md`
- Identity Linking Capability: `docs/specification/common/identity-linking/index.md`
- Schemas: `source/schemas/shopping/checkout.json`, `source/schemas/shopping/order.json`,
  `source/schemas/common/payment_ap2_mandate.json`
- Operations: `source/services/shopping/rest.openapi.json`, `source/services/shopping/mcp.openrpc.json`

## 2. The native-object answer

UCP defines one object that the merchant signs as an object: the **checkout object carrying
`ap2.merchant_authorization`**. It exists only when the optional AP2 Mandates Extension
(`dev.ucp.common.payment.ap2_mandate`) is in the capability intersection of both parties. In that
case the business MUST include `ap2.merchant_authorization` in all checkout responses (AP2
Mandates Extension, §Activation and Session Locking). This includes the `complete_checkout`
response, whose `order` member carries the order's `id` and `permalink_url` (Checkout
Capability, §Complete Checkout). The signature is a JWS with detached content over the RFC 8785
(JCS) form of the checkout without `ap2` (AP2 Mandates Extension, §Business Authorization,
§Canonicalization). UCP gives the reason for JCS here: unlike its message signatures, this
signature is for "durable artifacts" (Message Signatures, §REST Binding), which are "verified days
or months later" and may be re-serialized in transit (AP2 Mandates Extension, §Canonicalization).

The **order object** (`order.json`) is not signed as an object. When the business pushes it to
the platform in an Order Event Webhook, the HTTP request MUST be signed with RFC 9421 HTTP
Message Signatures, with the body bound through `Content-Digest` (Order Capability, §Webhook
Signature Verification). That signature belongs to one HTTP message, not to the order. It can be
checked again only by a holder that kept the covered request components along with the body.

Without the AP2 Mandates Extension, the checkout object has no object-level signature. RFC 9421
response signatures are RECOMMENDED for `complete_checkout` and OPTIONAL for the other checkout
operations (Checkout Capability - REST Binding, §Response Signing). They are message-level, as
for the webhook.

**Verifiable credentials.** The spec text uses the term in one place: the AP2 Mandates Extension,
§Overview, "the secure exchange of user intents and authorizations using **Verifiable Digital
Credentials**." Those credentials are the checkout and payment mandates. They are SD-JWT with key
binding (`+kb`), and the platform or the user's wallet issues them, not the merchant (§Mandate
Structure; §Step 2, Options 1 and 2). The merchant's `merchant_authorization` is a plain detached
JWS. It is not a verifiable credential. No merchant-issued verifiable credential appears in the
specification. The README's sentence ("verifiable credentials") refers to these mandates.

So the stop rule applies to the order object and to the checkout without AP2. Those get a
possession-only (d) (§5). It does not apply to the AP2-signed checkout, which gets a native check
(§3).

## 3. Object 1: checkout with `ap2.merchant_authorization`

### (a) Native object and format

The UCP Checkout object (`https://ucp.dev/schemas/shopping/checkout.json`, extended by
`payment_ap2_mandate.json#/$defs/dev.ucp.shopping.checkout`). It is a JSON object with required
members `ucp`, `id`, `line_items`, `status`, `currency`, `totals` and `links`, plus `ap2`. The
string `ap2.merchant_authorization` has the form `<base64url-header>..<base64url-signature>`
(schema pattern `^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+$`). Its protected header carries `alg` and
`kid` (AP2 Mandates Extension, §Business Authorization, JWS Header Claims).

The business returns it from the operations `create_checkout`, `get_checkout`, `update_checkout`,
`complete_checkout` and `cancel_checkout`. The names are the same in the REST binding
(`rest.openapi.json` operationIds) and the MCP binding (`mcp.openrpc.json` methods). Over A2A it
is the `a2a.ucp.checkout` data part (Checkout Capability - A2A Binding,
`docs/specification/shopping/checkout/a2a.md`). Each response signs one state of the session. A
later response for the same `id` signs a later state.

**Octets for wrapping.** The checkout reaches the platform inside a different container on each
transport: an HTTP body, an MCP tool result, an A2A data part. The signature covers no transport
bytes. It covers the JCS form of the object. So, following [SR]'s precedent for the x402 EIP-712
objects, the octets this adapter digests are the **RFC 8785 form of the complete checkout object
as received, `ap2` included**. This selects `jcs` rather than `as-transmitted` in the terms of
`draft-mih-sokolov-scitt-payload-binding` §4.1. The type definition says so, as [SR] rule 1
requires. Including `ap2` keeps the signature inside the digested octets. The native check
removes `ap2` again before it rebuilds the signing input. A proposed Settlement Wrapped Object
Types entry is in §6.

### (b) Issuer identity and its resolution

The issuer is the **business** (the merchant). Neither the JWS header nor the signed payload
names the business: the header carries only `alg` and `kid`. The signer is identified by context.
The verifier takes the business's UCP profile, served at `https://<business-origin>/.well-known/ucp`
(Specification overview, §Identity & Authentication, §Key Discovery), and looks up `kid` in that
profile's top-level `keys[]` (JWK Set). Integrity of the key list comes from TLS to that origin
(§Identity Resolution Algorithm, step 3). The profile has no self-signature.

Under the relying party's trust policy, then, the adapter needs two inputs that the object does
not carry:

1. the **business origin** whose profile was used. The carrier records it beside the wrapped
   object, as a claim of the party that wrapped it. The wrapped object does not attest it.
2. the **key set** used for the check: a retained copy of the profile's `keys[]`, or a live fetch.
   Under §Key Rotation (Message Signatures) a business removes old or compromised keys from
   `keys[]`, and "a key still listed in `keys[]` continues to verify". The JWS header carries no
   signing time. A live fetch therefore says only whether the key is listed now. A retained copy
   says whether it was listed when that copy was taken.

The relying party's policy decides whether that origin is the merchant it means. UCP leaves this
to the parties: a business "**SHOULD** maintain a registry of pre-approved platforms"
(§Fetching). It defines no merchant registry for platforms or third parties.

### (c) Native verification method

The method is the one in AP2 Mandates Extension, §Step 1 (`verify_merchant_authorization`), and
§Business Verification:

1. Split `ap2.merchant_authorization` at `..` into `encoded_header` and `encoded_signature`. The
   form must match the schema pattern.
2. Decode the header. `alg` must be one that AP2 accepts. AP2 v0.2 requires ECDSA (`ES256`,
   `ES384`, `ES512`), and UCP notes the open question AP2 #268 (§Cryptographic Requirements,
   note). `kid` must be present.
3. Remove the `ap2` member from the received checkout. Keep every other member, `ucp` included:
   "removing any member covered by `merchant_authorization` changes the JCS payload"
   (§Canonicalization). Compute the RFC 8785 form.
4. Form the signing input `encoded_header || "." || base64url(JCS bytes)` (RFC 7515 Appendix F,
   detached content).
5. Find the JWK in the resolved `keys[]` whose `kid` equals the header's `kid`. Skip keys with
   `use:"enc"`, and keys whose `key_ops` lacks `"verify"` (Specification overview, §Identity
   Resolution Algorithm, step 4).
6. Verify the signature under that key and `alg`. A JWS ECDSA signature is the fixed-width
   `r||s` form (RFC 7518 §3.4).

The method uses only the object and a key set. Given a retained key set it runs offline.

### (d) The exact predicate

When the native check passes, the adapter supports exactly this:

> The holder possesses a UCP checkout object, and every member of it except `ap2` was signed,
> in that exact JSON content, by the key with identifier `kid` in the business key set the
> verifier used. That key set was the one served at `<business-origin>/.well-known/ucp`,
> fetched live or as of the time it was retained.

When `status` is `completed` and `order` is present, the signed content includes the order's
`id` and `permalink_url`. The predicate then covers the business's signed statement of those
identifiers for that checkout. It covers nothing else about the order.

The adapter does **not** support, from this object alone:

- that the business origin is the merchant the relying party has in mind. That is the trust
  policy's decision (b);
- that the key was listed at the time of signing. The JWS carries no signing time, and keys
  leave `keys[]` on rotation and on compromise;
- that the buyer or the user authorized the purchase. That is the `ap2.checkout_mandate`, which
  the platform or the user issues and which already has its own wrapped type (`ap2.checkout-mandate`, [SR]);
- that payment settled, or that the order was fulfilled, shipped or not cancelled later. Later
  order state reaches the platform only as webhooks (§5);
- that this is the last state of the session. Each response signs one state.

### (e) Per-property results

Each row is one named check, with a status in the [IP] §7.1 vocabulary. In v0 each check except
the last is reported as a `native_check` property report ([IP] §7.2), with the check's name in
`detail`, together with the object's wrapped type, as the other adapters do:
`{"property": "native_check", "status": …, "method": …, "detail": {"check": "<name>", "object": "ucp.checkout"}}`. Property
names of their own for these checks are left to the next profile revision. The object's native
check passes when each of those reports is `PASS`. The last row, `ucp.business_trust`, is reported
separately, as `responder_trust` is reported beside the envelope signature in [IP] §7.2.

| Property | `PASS` when | Other statuses | `method` |
|---|---|---|---|
| `ucp.checkout.schema` | the object validates against `payment_ap2_mandate.json#/$defs/dev.ucp.shopping.checkout` at the pinned UCP version | `FAIL` on a schema violation | `ucp-schema validate --response --op <operation>, UCP v2026-08-25` (for example `--op complete`) |
| `ucp.merchant_authorization.present` | `ap2.merchant_authorization` is present | `NOT_PRESENT` when absent. UCP names this case `merchant_authorization_missing` | `UCP AP2 Mandates §Business Authorization` |
| `ucp.merchant_authorization.form` | the value matches the detached-JWS pattern, and the header decodes to JSON with `alg` and `kid` | `FAIL` otherwise | `RFC 7515 Appendix F detached JWS` |
| `ucp.merchant_authorization.alg` | `alg` is accepted by AP2 and supported by the verifier | `NOT_CHECKED` when AP2 accepts it and the verifier does not support it; `FAIL` when AP2 does not accept it | `AP2 v0.2 algorithm rule` |
| `ucp.merchant_authorization.key` | `kid` resolves to a usable key in the key set used | `NOT_CHECKED` when no key set was retained and the verifier is offline; `FAIL` when the key set used does not list `kid` | `UCP profile keys[] lookup by kid, live` or `retained keys[] (<key-set source>)`, with ` as of <time>` when the retention time is known |
| `ucp.merchant_authorization.signature` | the signature verifies over the §3(c) signing input | `FAIL` when it does not. UCP names this case `merchant_authorization_invalid` | `<alg> over JWS signing input of JCS(checkout − ap2)` |
| `ucp.business_trust` | the relying party's trust policy accepts the business origin | `FAIL` when the policy rejects the origin; `INCONCLUSIVE` when the policy does not list it or cannot decide; `NOT_CHECKED` when no policy was supplied | relying-party policy identifier |

A check that does not pass is reported with its own status. A `FAIL` of
`ucp.merchant_authorization.signature` maps to a result by [IP] §8.1. It is decisive only for a
requirement that *is* this check (row 5). For a requirement the check only supports, such as
"the order was placed", it is `INSUFFICIENT` (row 6).

[IP] §8.1 has no row for a `native_check` that is neither `PASS` nor `FAIL`. Such a status is
**mapped as profile §8.1 rows 3-4 pending a profile row**, when the requirement is, or rests on,
that check:

- `NOT_PRESENT`: `INSUFFICIENT` / `INSUFFICIENT` / `not_evaluable`, as row 3;
- `NOT_CHECKED` or `INCONCLUSIVE`: `UNKNOWN` / `UNKNOWN` / `not_evaluable`, as row 4.

Neither gives `met` or `not_met`.

## 4. Object 2: Order Event Webhook (RFC 9421 message signature)

### (a) Native object and format

The Order object (`https://ucp.dev/schemas/shopping/order.json`), a full current-state snapshot
delivered as the JSON body of the `order_event_webhook` request, which the business POSTs to the
platform's `webhook_url` (Order Capability, §Order Event Webhook, §Webhook URL Configuration). The
signature is RFC 9421 HTTP Message Signatures (`Signature-Input`, `Signature`) with an RFC 9530
`Content-Digest` over the raw body bytes (Message Signatures, §REST Binding, §REST Request
Signing). The order is not signed as an object. The `get_order` operation returns the same entity.
UCP does not require a signature on its response (Message Signatures, §When Signatures Apply).

### (b) Issuer identity and its resolution

The issuer is the business. The webhook carries `UCP-Agent: profile="<business profile URL>"`,
and the platform resolves `keyid` in that profile's `keys[]` (Order Capability, §Verification
(Platform)). The profile URL is a covered component of the signature when the signature lists
`ucp-agent`. Specification overview, §Identity Resolution Algorithm, step 5 requires it to be
listed whenever the header is present. The example in Order Capability, §Webhook Signature
Verification omits it. A verifier applying step 5 rejects a signature shaped like that example.
Key-set retention and rotation are as in §3(b).

UCP also requires an authorization step: the platform confirms that the signer's profile matches
the business the order was created with (§Verification (Platform), Authorization). A third party
can repeat that step only if it holds the checkout that created the order.

### (c) Native verification method

Message Signatures, §REST Request Verification (`verify_rest_request`), applied to the webhook
request: parse `Signature-Input`; resolve the key; enforce the covered components (`@method`,
`@authority`, `@path`, `content-digest`, `content-type`, and `ucp-agent` when present); check
`Content-Digest` against the SHA-256 of the raw body; rebuild the RFC 9421 signature base; verify.
The inputs are the body **and** the method, authority, path and the covered header values of the
request as received.

### (d) The exact predicate

When the holder kept the whole request (method, target, covered headers, raw body) and the check
passes:

> The holder possesses an HTTP request whose body is this order snapshot, and that request was
> signed, with the covered components listed in its `Signature-Input`, by the key `keyid` in the
> key set used for the business profile named in its `UCP-Agent`.

When the holder kept only the body, as a `wrapped` entry in [SR] does (it holds one octet string),
the native check cannot run: `native_check` is `NOT_PRESENT`. The predicate is then possession
only, per FR-20 and §5.

In neither case does the adapter support any of the following: that the order state is current;
that the events arrived in the order the business sent them; that an earlier snapshot was
superseded; or that the business is the one that took the order. That last claim needs the
authorization step in (b).

### (e) Per-property results

| Property | `PASS` when | Other statuses | `method` |
|---|---|---|---|
| `ucp.order.schema` | the body validates against `order.json` at the pinned version | `FAIL` on a violation | `JSON Schema 2020-12, UCP v2026-08-25` |
| `ucp.webhook.components` | the method, target and every covered header are held | `NOT_PRESENT` when only the body is held | `RFC 9421 §2 component set` |
| `ucp.webhook.coverage` | the covered set includes every component UCP requires | `FAIL` otherwise. UCP calls this `coverage_insufficient` | `UCP Identity Resolution Algorithm step 5` |
| `ucp.webhook.content_digest` | `Content-Digest` equals `sha-256` of the raw body | `FAIL`, UCP `digest_mismatch` | `RFC 9530 sha-256 over raw body` |
| `ucp.webhook.key` | `keyid` resolves in the key set used | as for `ucp.merchant_authorization.key` | as for §3(e) |
| `ucp.webhook.signature` | the signature verifies over the rebuilt signature base | `FAIL`, UCP `signature_invalid` | `RFC 9421 <alg> over signature base` |
| `ucp.business_trust` | as §3(e) | as §3(e) | as §3(e) |

## 5. Objects without a native check: possession only

These objects carry no signature of their own that a holder can check again:

- a checkout object when the AP2 Mandates Extension was not negotiated;
- an order object held without its signed webhook request;
- the response to any operation whose RFC 9421 response signature is absent, or whose covered
  components were not kept.

For these, (c) is: no native check exists. (d) is limited, per FR-20, to:

> The holder possesses these exact octets (SHA-256 digest equal to the wrapped `digest`), and the
> party that wrapped them says it received them from the named business origin over the named
> UCP transport.

Transport-level provenance (TLS to the business origin, an RFC 9421 signature checked when the
message arrived) is the wrapping party's claim about how it received the bytes. The wrapped octets
do not evidence it. The adapter reports `native_check` as `NOT_PRESENT`, with `method` set to
`none: UCP defines no object signature for this object`. It reports nothing about the object's
signature or meaning ([IP] §5.1, P-11). Possession is shown by [SR]'s `wrapped_digest_mismatch`
check and the digest itself. That `NOT_PRESENT` is mapped as in §3(e). It never counts against a
requirement that does not rest on the object's signature.

### What UCP would need to add for a native check of the order

1. **An object-level business signature on the order.** For example, the
   `merchant_authorization` construction (detached JWS over the JCS form without the signature
   member) extended to `order.json` and to each webhook snapshot. This is what makes the
   checkout object checkable.
2. **A signing time inside the signed content.** For example, `iat` in the JWS protected header.
   Without one, no verifier can tell whether a key was listed when it signed.
3. **The business's identity inside the signed content.** For example, the business profile URL
   as a protected header member. Today the signer is identified only by the profile the verifier
   chose to fetch.
4. **Key history.** A rule for publishing retired keys with their validity periods, rather than
   removing them from `keys[]`, so that past signatures can be checked after a rotation.
5. **Published test material.** A test key pair and signed example objects for
   `merchant_authorization`. At the commits read, the conformance suite's AP2 test uses a
   placeholder mandate string. It checks no merchant signature. The spec's JWK examples are public
   keys only.

Items 2 to 4 also apply to the AP2-signed checkout of §3.

## 6. Proposed wrapped object types (not registered here)

The Settlement Wrapped Object Types registry ([SR] §IANA, Wrapped Object Types) uses
Specification Required. These rows are proposals for that registry's process. This document does
not register them.

`ucp.checkout`:
: Issuer: business (merchant). Octets: the RFC 8785 form of the complete checkout object as
  received, `ap2` included. Native check: §3(c), only when `ap2.merchant_authorization` is
  present. Reference: UCP v2026-08-25, AP2 Mandates Extension.

`ucp.order`:
: Issuer: business (merchant). Octets: the raw body octets of the `order_event_webhook` request,
  or of the `get_order` response, as received. Native check: none at the object level (§5).
  Reference: UCP v2026-08-25, Order Capability.

## 7. Vectors

`vectors/adapters/ucp/` holds two cases for §3, written by
`python/scripts/generate_ucp_adapter_vectors.py`. Each case's checkout validates against UCP's
published schema at the commit read. The README records the schema path and the validator.

- `positive`: a `complete_checkout` response (`status` `completed`, with `order`) carrying
  `ap2.merchant_authorization`. Every check in §3(e) is `PASS`.
- `native-check-fails`: the same checkout with one signed member changed after signing (the
  `total` amount). The schema still validates. `ucp.merchant_authorization.signature` is `FAIL`.

UCP publishes no test key (§5 item 5). The signing key is therefore the ES256 example key of
RFC 7515, Appendix A.3, a published example key. Its source is named in the vectors' README.
There are no vectors for §4 or §5. Those objects have no native check that a vector could
exercise.
