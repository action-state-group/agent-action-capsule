---
title: "Two-Party Settlement Records for Agent Payments"
abbrev: "Agent Settlement Records"
docname: draft-mih-agent-settlement-records-00
date: 2026-10-01
category: std
submissiontype: IETF
ipr: trust200902
area: Security
keyword:
  - agent
  - payment
  - settlement
  - SCITT
  - transparency
  - evidence
stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 - ins: S. Mih
   name: Steven Mih
   organization: Action State Group, Inc.
   email: spec@actionstate.ai

normative:
  RFC2119:
  RFC8174:
  RFC3339:
  RFC4648:
  RFC8126:
  RFC8785:
  RFC9052:
  I-D.mih-scitt-agent-action-capsule:
    title: "An Agent Action Capsule Profile for SCITT"
    seriesinfo:
      Internet-Draft: draft-mih-scitt-agent-action-capsule-05
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
    date: 2026-09

informative:
  RFC9338:
  RFC9562:
  RFC9942:
  RFC9943:
  I-D.mih-agent-bilateral-attestation:
    title: "Bilateral Attestation of Cross-Organization Agent Actions"
    seriesinfo:
      Internet-Draft: draft-mih-agent-bilateral-attestation-02
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
    date: 2026-09-13
  I-D.mih-sokolov-scitt-payload-binding:
    title: "Canonicalization Declaration for SCITT Signed Statements"
    seriesinfo:
      Internet-Draft: draft-mih-sokolov-scitt-payload-binding-05
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
      - ins: A. Sokolov
        name: Anton Sokolov
        organization: Tyche Institute
    date: 2026-09-11
  I-D.mih-zhang-agent-disclosure-bundle:
    title: "AAC Evidence Bundle"
    seriesinfo:
      Internet-Draft: draft-mih-zhang-agent-disclosure-bundle-00
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
      - ins: Y. Zhang
        name: Yiqun Zhang
        organization: Independent
    date: 2026-09
  I-D.mih-scitt-agent-action-capsule-sel-disc:
  I-D.mih-agent-evidence-request:
    title: "An Interaction Model for Requesting Verifiable Evidence"
    seriesinfo:
      Internet-Draft: draft-mih-agent-evidence-request-00
    author:
      - ins: S. Mih
        name: Steven Mih
        organization: Action State Group, Inc.
    date: 2026-09-26
  I-D.ryan-httpauth-payment:
  I-D.dogru-cedulon-core:
  X402:
    title: "x402 Protocol Specification, Version 2"
    author:
      - organization: x402 Foundation
    target: https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md
    date: 2026
  X402-OFFER-RECEIPT:
    title: "x402 Extension: Signed Offer and Receipt (version 0.6)"
    author:
      - organization: x402 Foundation
    target: https://github.com/x402-foundation/x402/blob/main/specs/extensions/extension-offer-and-receipt.md
    date: 2026-02
  AP2:
    title: "Agent Payments Protocol (AP2) Specification, v0.2"
    author:
      - organization: FIDO Alliance
    target: https://ap2-protocol.org/ap2/specification/
    date: 2026-04
  ACP:
    title: "Agentic Commerce Protocol"
    author:
      - organization: Agentic Commerce Protocol contributors
    target: https://github.com/agentic-commerce-protocol/agentic-commerce-protocol
    date: 2026
  UCP:
    title: "Universal Commerce Protocol"
    author:
      - organization: Universal Commerce Protocol contributors
    target: https://github.com/Universal-Commerce-Protocol/ucp
    date: 2026-01
  BOLT11:
    title: "BOLT #11: Invoice Protocol for Lightning Payments"
    author:
      - organization: Lightning Network specification contributors
    target: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
  BOLT12:
    title: "BOLT #12: Flexible Protocol for Lightning Payments (including payer proofs)"
    author:
      - organization: Lightning Network specification contributors
    target: https://github.com/lightning/bolts/blob/master/12-offer-encoding.md
    date: 2026-07
  ISO20022:
    title: "ISO 20022 Financial Services - Universal Financial Industry Message Scheme (message definitions pacs.002, pacs.004, pacs.008, camt.054)"
    author:
      - organization: International Organization for Standardization
    target: https://www.iso20022.org/
  OPEN-PAYMENTS:
    title: "Open Payments API"
    author:
      - organization: Interledger Foundation
    target: https://openpayments.dev/
  CAIP-2:
    title: "CAIP-2: Blockchain ID Specification"
    author:
      - organization: Chain Agnostic Standards Alliance
    target: https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-2.md
  CAIP-19:
    title: "CAIP-19: Asset Type and Asset ID Specification"
    author:
      - organization: Chain Agnostic Standards Alliance
    target: https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-19.md
  ISO4217:
    title: "Codes for the representation of currencies"
    author:
      - organization: International Organization for Standardization
    seriesinfo:
      ISO: "4217:2015"
  AEP:
    title: "A-Comm Evidence Protocol (AEP) Specification v1.0.3-rc.2 (Draft)"
    author:
      - organization: A-Comm Technologies, Inc.
    target: https://github.com/A-Comm-Tech/a-comm-evidence-protocol
    date: 2026-07

--- abstract

A payment between two agents is observed by two systems: the payer's wallet
or bank and the payee's. Existing payment protocols record one of those
observations, signed by one party, and most record nothing about what was
delivered in exchange. This document defines two-party settlement records,
carried as Agent Action Capsules, in which payer and payee each seal, under
their own key, only what their own system observed. A settlement is a set of up to
four leg records (terms, payer-observed, payee-observed, and delivered) that
cite each other by digest and join on a typed payment reference. The state
of a settlement (one-sided, agreed, or mismatched) is derived by the
verifier from which legs are present and whether they agree; no record
asserts it. Signed objects from existing payment protocols are carried by
digest and never re-signed. Amounts are exact integers with a decimal
scale. The document defines a registry of payment reference types covering
x402, Lightning, AP2, ACP, UCP, the Payment HTTP authentication scheme,
ISO 20022, and Open Payments, and maps its states to ISO 20022 status codes.

--- note_Note_to_Readers

This document is an individual submission. It is a companion to the Agent
Action Capsule profile {{I-D.mih-scitt-agent-action-capsule}} and to the
bilateral attestation exchange {{I-D.mih-agent-bilateral-attestation}}.
Conformance vectors are maintained in the `vectors/settlement/` directory of
this document's source repository.

--- middle

# Introduction {#introduction}

When an agent pays another agent for an inference, a data set, or a
physical good, at least two systems see the payment. The payer's wallet
sees a transfer leave. The payee's wallet, processor, or bank sees a
transfer arrive. Each system can produce a record. The payment protocols in
use today choose one of them:

* The x402 settlement response {{X402}} is returned to the payer and is not
  signed; its trust comes from the chain it names. The x402 signed offer and
  receipt extension {{X402-OFFER-RECEIPT}} adds a receipt signed by the payee
  only.
* AP2 {{AP2}} binds user and agent mandates, and returns a Payment Receipt
  signed by the payment processor and a Checkout Receipt signed by the
  merchant. Each receipt is one party's statement.
* The Payment HTTP authentication scheme {{I-D.ryan-httpauth-payment}}
  returns a `Payment-Receipt` header that is not signed.
* BOLT 12 payer proofs {{BOLT12}} combine a payee-signed invoice with a
  payer signature. They are two-sided for the payment, and specific to
  Lightning.
* ISO 20022 status reports {{ISO20022}} are produced by each agent in the
  chain about its own side, under bank keys.

None of these records what the delivered content was, and none lets a third
party check, offline, that the two sides' observations of one payment
agree. When they disagree, or when one side says nothing, the evidence is
one party's log against the other's.

This document defines settlement records in which:

1. The payer and the payee are independent sealers. Each seals, under its
   own key, only what its own wallet or system observed. Neither attests to
   the other's side ({{sealers}}).
2. A settlement is up to four leg records: terms, payer-observed,
   payee-observed, and delivered. Each leg cites the terms leg by digest,
   and a leg may cite the counterparty's leg it holds ({{legs}}).
3. Legs join on a typed payment reference drawn from an open registry
   ({{payment-ref}}).
4. Signed objects from existing protocols are carried by digest, and
   optionally as their exact bytes. They are never re-signed or re-encoded
   ({{wrap}}).
5. Amounts are exact: an integer value and a decimal scale, never a
   floating-point number ({{amounts}}).
6. The delivered leg binds a digest of the delivered content to the terms
   ({{delivered-leg}}).
7. The state of a settlement is derived from the legs present, never
   asserted by a leg ({{states}}). One side's leg alone is a stated claim,
   not an agreement.

Each leg is an Agent Action Capsule {{I-D.mih-scitt-agent-action-capsule}}
with one additional member. These records therefore inherit the Capsule's
content identity, its Producer Envelope signature, its cross-record
references, and its registration path to a SCITT Transparency Service
{{RFC9943}}.

## What This Document Does Not Do {#nongoals}

This document does not move money, define a payment protocol, replace any
protocol it binds to, or decide between the parties. It defines no trust policy for
deciding which key may seal for a payer or payee; that is the verifier's
policy, as in {{I-D.mih-scitt-agent-action-capsule}}. It does not rank,
rate, or otherwise grade the parties to a settlement. It records what each
side observed, and it defines how a verifier derives whether the
observations agree.

# Conventions and Definitions {#conventions}

{::boilerplate bcp14-tagged}

Payer:
: The party whose funds leave its control in the payment.

Payee:
: The party to whom the funds are directed.

Sealer:
: The party that produces a leg record and signs it with a Producer
  Envelope. In this document a sealer is always the payer or the payee.

Leg:
: One of the four records of a settlement: terms, payer-observed,
  payee-observed, or delivered.

Leg record:
: An Agent Action Capsule carrying a `settlement` member ({{leg-record}}).

Observation:
: What a sealer's own wallet, account, processor, or delivery system
  reported to that sealer. An observation is about the sealer's own side
  only.

Payment reference:
: A typed identifier that both sides' systems report for the same payment,
  such as a transaction hash or an end-to-end identifier ({{payment-ref}}).

Wrapped object:
: A signed or otherwise authoritative object defined by another protocol
  (for example an x402 signed offer or an AP2 Payment Receipt), carried in a
  leg by digest ({{wrap}}).

Stated claim:
: A leg that no leg from the other side corroborates. It records what one
  side says it observed. It is not an agreement.

Verifier:
: Any party that checks a set of leg records and derives the settlement
  state ({{states}}).

Digests in this document are SHA-256, written as 64 lowercase hexadecimal
characters. A "JSON digest" is the Capsule profile's JSON digest: SHA-256
over the RFC 8785 {{RFC8785}} canonical form ({{I-D.mih-scitt-agent-action-capsule}},
Conventions and Definitions).

# Two Independent Sealers {#sealers}

The payer and the payee each produce their own leg records and sign them
with their own key. The rules in this section are what make a settlement
two-sided rather than one party's account of both sides.

1. **Own side only.** A sealer MUST record in a leg only what its own system
   observed. The payer-observed leg records what the payer's wallet or
   account reported about the outgoing payment. The payee-observed leg
   records what the payee's wallet, processor, or account reported about
   the incoming payment. A sealer MUST NOT record the counterparty's
   observation as its own, even when it holds the counterparty's evidence.
   It MAY cite the counterparty's leg ({{citations}}) or wrap a
   counterparty-issued object ({{wrap}}); both are carried as what they
   are, never as the citing sealer's observation.

2. **Own key.** Each leg is signed by a Producer Envelope, a COSE_Sign1
   {{RFC9052}} object over the leg's Capsule ID
   ({{I-D.mih-scitt-agent-action-capsule}}, Producer Envelope wire profile),
   whose `kid` is the sealer's key. The payer-observed leg MUST be sealed
   under a key the verifier's policy accepts for the payer, and the
   payee-observed leg under a key it accepts for the payee.

3. **Distinct keys.** Within one settlement, a payer-observed leg and a
   payee-observed leg sealed under the same key are not two sides. A
   verifier MUST report `sealer_conflation` for such a pair and MUST NOT
   derive `agreed` from it ({{states}}). This check needs no key policy: it
   compares the two envelopes' `kid` values.

4. **Role consistency.** A leg's `sealer_role` MUST match the leg: `payer`
   for a payer-observed leg and `payee` for a payee-observed leg. The terms
   leg and the delivered leg may be sealed by either party
   ({{terms-leg}}, {{delivered-leg}}).

What a signature proves is unchanged from the base profile: the holder of
the key signed the Capsule ID. Whether that key belongs to the payer or the
payee is the verifier's policy (certificates, DIDs, DNS-published keys, or
the signer-authorization methods of the protocol being bound). A verifier
MUST return each leg's authenticated key so that its caller can apply that
policy.

# The Leg Record {#leg-record}

## Carriage in a Capsule {#carriage}

A leg record is an Agent Action Capsule of format 4
{{I-D.mih-scitt-agent-action-capsule}} with a top-level `settlement` member.
Everything the base profile requires of a Capsule applies: the
`capsule_id` is the SHA-256 of the RFC 8785 form of the Capsule without
`capsule_id`, floating-point numbers are forbidden in digest-bearing
material, and the `settlement` member participates in the digest. A leg
record's identity is its `capsule_id`.

A leg record SHOULD use `action_type: "fyi"` and an `assurance` block whose
`effect_mode` is `not_applicable`: the leg records an observation, and the
payment itself is not an effect the sealer's gate committed. A deployment
in which the sealer's own gate dispatched the payment MAY instead record it
as the effect of a separate Capsule with `effect.type: "send_payment"` and
cite that Capsule from the payer-observed leg; this document does not
require it.

A verifier unaware of this document processes a leg record as an ordinary
Capsule. Every check of the base profile still applies to it.

## The settlement Member {#settlement-member}

The `settlement` member is a JSON object:

| Member | Type | Required in | Meaning |
|---|---|---|---|
| `version` | string | all legs | MUST be `"0"` for this document. |
| `leg` | string | all legs | `terms`, `payer_observed`, `payee_observed`, or `delivered`. A closed set; any other value is a structural failure. |
| `sealer_role` | string | all legs | `payer` or `payee` ({{sealers}}). |
| `terms_ref` | string | all legs except terms | The `capsule_id` of the terms leg this leg answers. |
| `amount` | object | terms, payer_observed | The amount ({{amounts}}). In the terms leg, the price. In the payer-observed leg, the amount the payer's system reports it sent toward the payee, excluding any routing fee ({{fees}}). |
| `routing_fee` | object | OPTIONAL, payer_observed | The fee the payer's system reports it paid to intermediaries on top of `amount` ({{fees}}). |
| `received` | object | payee_observed | The amount the payee's system reports credited to the payee, after any receive fee ({{fees}}). |
| `receive_fee` | object | OPTIONAL, payee_observed | The fee the payee's system reports deducted on the receiving side between the amount sent and `received` ({{fees}}). |
| `payment_ref` | object | payer_observed, payee_observed | The payment reference ({{payment-ref}}). OPTIONAL in the terms leg when the reference is fixed before payment (for example a Lightning payment hash). |
| `status` | string | payer_observed, payee_observed | `pending`, `settled`, `failed`, or `reversed`, as the sealer's own system reported it ({{status}}). |
| `observed_at` | string | payer_observed, payee_observed, delivered | {{RFC3339}} UTC time at which the sealer's system reported the observation. |
| `deliverable` | object | OPTIONAL, terms | What is to be delivered ({{terms-leg}}). |
| `valid_until` | string | OPTIONAL, terms | {{RFC3339}} UTC time after which the terms no longer apply. |
| `delivery` | object | delivered | What was delivered ({{delivered-leg}}). |
| `wrapped` | array | OPTIONAL, all legs | Wrapped objects ({{wrap}}). |

A member not listed for a leg MUST NOT be present in that leg. A verifier
reports a missing required member or a present forbidden member as
`settlement_malformed`.

No member of `settlement` states the settlement's state. The state is
derived ({{states}}); a member that asserted it would let one sealer state
a fact that only the combination of both sides' records can establish.

## Citations Between Legs {#citations}

Legs cite each other in two ways.

**The terms reference.** Every leg other than the terms leg carries
`terms_ref`, the `capsule_id` of the terms leg it answers. A leg answers
exactly one terms leg. `terms_ref` is a bare digest, in the
same way the base profile's `cross_party.initiator_ref` is: it names the
terms leg's `capsule_id`, and a verifier compares it with the recomputed
`capsule_id` of the terms leg it holds.

**Counterparty legs.** A sealer that holds a leg sealed by the other party
MAY cite it from its own leg with a `references` entry
({{I-D.mih-scitt-agent-action-capsule}}, Cross-record references) of type
`agent-action-capsule`, `digest_alg` `SHA-256`, the cited leg's
`capsule_id` as `digest`, and `citation_purpose: "counterparty_half"`. As
the base profile defines that purpose, the citation records custody of the
counterparty's leg, not an observation of it.

A sealer's own legs form its own stream, and a sealer MAY link them with
`chain` (for example, a payee's delivered leg following its payee-observed
leg with relation `follows`). The join of a settlement never depends on
`chain`; it depends on `terms_ref` and `payment_ref` only.

The usual order of a settlement is shown below. Only the terms leg must
exist before the others; any subset of the other legs can be present.

~~~
   payee (or payer)              payer                 payee
  +----------------+     +------------------+    +------------------+
  |  terms leg     |<----| payer_observed   |    | payee_observed   |
  |  amount, wraps |     | payment_ref,     |    | payment_ref,     |
  |  offer/mandate |<-+  | amount,          |<...| received,        |
  |                |  |  | routing_fee,     |    | receive_fee,     |
  |                |  |  | status           |    | status           |
  +----------------+  |  +------------------+    +------------------+
          ^           |                                   |
          |           +-----------------------------------+
          |                terms_ref (every leg)
  +-----------------------------+
  |  delivered leg (either side)|
  |  content_digest, direction  |
  +-----------------------------+

   <---- terms_ref        <.... references[] counterparty_half
~~~

# The Legs {#legs}

## Terms {#terms-leg}

The terms leg fixes what the payment is for and how much it is. It is
sealed by the party that set the terms. That is usually the payee, whose
offer or invoice states the price; in a mandate-based flow it is usually
the payer, whose mandate states what it authorized. The other party
accepts the terms by citing them: its observed leg carries the same
`terms_ref`. A terms leg that no counterparty leg cites is one party's
statement of the terms, not an agreement on them.

The terms leg carries:

* `amount`: the agreed amount ({{amounts}}).
* `wrapped` (OPTIONAL): the protocol object that stated the terms. Examples
  are the x402 signed offer {{X402-OFFER-RECEIPT}}, the AP2 Checkout or
  Payment Mandate {{AP2}}, and a BOLT 12 invoice {{BOLT12}}.
* `deliverable` (OPTIONAL): an object with at least one of these members:
  * `content_digest`: the digest of the content to be delivered, when it
    is known in advance (for example a data set with a published digest).
  * `description_digest`: the JSON digest of a description of what is to
    be delivered, when the content is not known in advance (for example an
    inference whose output does not yet exist).
* `payment_ref` (OPTIONAL): the payment reference, when it is fixed before
  payment.
* `valid_until` (OPTIONAL).

When the terms come from a protocol object, the terms leg's `amount` MUST
equal the amount that object states ({{amounts}}). The x402 offer's
`amount` is already an integer string in the asset's atomic units, so it
becomes `value` directly, with `assetScale` set to the asset's number of
decimals.

## Payer-Observed {#payer-leg}

The payer-observed leg records what the payer's own system reported about
the payment it made: the payment reference, the amount it sent toward the
payee (`amount`), the routing fee it paid on top of that (`routing_fee`),
and the status the payer's system reported. It is sealed by the payer.

It SHOULD wrap the object the payer's system returned, where one exists:
the x402 `PaymentPayload` the payer sent and the settlement response it
received {{X402}}, the BOLT 12 payer proof {{BOLT12}}, or the ISO 20022
status report the payer's bank returned {{ISO20022}}. A payer that received
a payee-issued receipt (for example an AP2 Payment Receipt or an x402 signed
receipt) MAY wrap it here; it is then carried as the issuer's object, not as
the payer's observation ({{wrap}}).

## Payee-Observed {#payee-leg}

The payee-observed leg records what the payee's own system reported about
the payment it received: the payment reference, the amount credited to it
(`received`), the fee deducted on the receiving side (`receive_fee`), and
the status the payee's system reported. It is sealed by the payee.

It SHOULD wrap the object the payee's system produced or received: the x402
settlement response from its facilitator, the x402 signed receipt it issued
{{X402-OFFER-RECEIPT}}, the AP2 Payment Receipt or Checkout Receipt {{AP2}},
the `Payment-Receipt` it returned {{I-D.ryan-httpauth-payment}}, or the
ISO 20022 credit notification its bank sent. Where a signed payee receipt
already exists, the payee-observed leg wraps it; it does not restate and
re-sign the same claim.

A payee that holds the payer-observed leg MAY cite it ({{citations}}).

## Delivered {#delivered-leg}

The delivered leg records what was delivered under the terms. Either party
may seal one, and both may: the payee records what it sent, and the payer
records what it received. Each records only its own side.

The `delivery` member is an object:

| Member | Type | Req | Meaning |
|---|---|---|---|
| `direction` | string | REQUIRED | `sent` (sealed by the payee) or `received` (sealed by the payer). Any other combination of `direction` and `sealer_role` is `settlement_malformed`. |
| `content_digest` | string | REQUIRED for digital content | The digest of the delivered content: SHA-256 over the exact octets sent or received, or the JSON digest when the content is a JSON value. |
| `carrier` | string | OPTIONAL | For physical goods: the carrier ({{aep}}). |
| `tracking_digest` | string | OPTIONAL | For physical goods: the digest of the carrier's tracking number. The tracking number itself is not carried ({{privacy}}). |
| `status` | string | OPTIONAL | For physical goods: `pending`, `in_transit`, `delivered`, `failed`, or `returned`. |
| `shipped_at` | string | OPTIONAL | For physical goods: {{RFC3339}} UTC. |
| `delivered_at` | string | OPTIONAL | For physical goods: {{RFC3339}} UTC. |
| `address_digest` | string | OPTIONAL | For physical goods: a salted digest of the canonical delivery address ({{privacy}}). |

**Binding to the terms.** The delivered leg is bound to the terms in two
ways. Its `terms_ref` names the terms leg, so the content digest is a
statement about delivery under those terms and no other. And when the
terms leg carries `deliverable.content_digest`, a verifier compares the
delivered `content_digest` with it ({{delivery-state}}). When the terms
carry only `description_digest`, the verifier can establish that both
sides name the same delivered content, but not that the content matches
the description; that judgment is outside this document.

For an inference, `content_digest` is the digest of the completion as
returned at the serving boundary, the same value a Capsule with
`effect.type: "inference_completion"` records as its `response_digest`
({{I-D.mih-scitt-agent-action-capsule}}, Effect Record). A delivered leg
MAY cite that Capsule with `citation_purpose: "acted_on"`.

# Amounts {#amounts}

An amount is a JSON object with exactly three members, the same triple Open
Payments uses {{OPEN-PAYMENTS}}:

| Member | Type | Meaning |
|---|---|---|
| `value` | string | A non-negative integer in decimal digits: `0`, or a digit 1-9 followed by digits. No sign, no leading zeros, no decimal point, no exponent, no whitespace. |
| `assetCode` | string | The asset. For a fiat currency, the ISO 4217 alphabetic code {{ISO4217}}. For an asset on a network with a CAIP-2 identifier, the CAIP-19 asset type {{CAIP-19}}. For Lightning, `BTC`. |
| `assetScale` | integer | The number of decimal places: an integer from 0 to 255. |

For example, USDC on Base has the CAIP-19 asset type
`eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`.

The amount is `value` divided by ten to the power `assetScale`. For example,
`{"value": "1500000", "assetCode": "eip155:8453/erc20:0x8335...2913",
"assetScale": 6}` is 1.5 units of that token, and `{"value": "21000",
"assetCode": "BTC", "assetScale": 11}` is 21000 millisatoshi.

Decimal amounts are exact: 1.50 USDC is `value` `"1500000"` with
`assetScale` 6, 0.000001 is `value` `"1"` with `assetScale` 6, and
1234.56 is `value` `"123456"` with `assetScale` 2; any decimal fraction is
representable by choosing `assetScale`.

The rules for amounts:

1. `value` MUST be a JSON string matching the grammar above. A JSON number
   in `value` is not conforming, whether or not it has a fractional part. A
   floating-point number anywhere in a Capsule already fails the base
   profile's digest rules; a string with a decimal point or exponent fails
   this document as `amount_not_exact`.
2. `assetScale` MUST be a JSON integer from 0 to 255.
3. Two amounts are equal if and only if their `assetCode` strings are
   identical and their values are equal at a common scale: with
   S = max(s1, s2), v1 * 10^(S - s1) = v2 * 10^(S - s2), computed in exact
   integer arithmetic. Implementations MUST NOT convert either amount to a
   binary floating-point number at any point.
4. Amounts with different `assetCode` values are never equal, even if a
   conversion rate exists. A settlement in which the two sides report
   different assets is a mismatch ({{states}}).

The x402 `amount` and the AEP `amount_atomic` {{AEP}} are integer strings in
atomic units; they become `value` unchanged, with `assetScale` set to the
asset's decimals. Lightning amounts in millisatoshi use `assetScale` 11.

## Fees {#fees}

The two sides of one payment do not, in general, report the same number.
A Lightning payee's wallet, for example, can report 995 millisatoshi
received with a receive-side fee of 5 for a payment of 1000 millisatoshi
the payer sent with no routing fee. Both observations are honest. This
document therefore records each side's gross, fee, and net separately, and
never compares the payer's and the payee's amounts directly.

The members, each an amount in the form above:

* Payer-observed: `amount` is what the payer's system reports it sent
  toward the payee. `routing_fee` is what it paid to intermediaries on
  top. The payer's total debit is `amount` + `routing_fee`.
* Payee-observed: `received` is what the payee's system reports credited.
  `receive_fee` is what was deducted on the receiving side, including any
  charges deducted by intermediaries from the amount in transit, as the
  payee's system reports them. The gross amount that arrived for the payee
  is `received` + `receive_fee`; equivalently, net = gross - fee.

The rules for fees:

1. A fee is non-negative: its `value` follows the grammar of rule 1 above.
2. A fee MUST carry the same `assetCode` as the amount it accompanies
   (`routing_fee` with `amount`, `receive_fee` with `received`). It MAY
   use a different `assetScale`; sums are computed in exact integer
   arithmetic at the largest scale involved, as in rule 3 above. A fee in
   a different asset cannot be combined with its amount; a verifier reports
   `fee_asset_differs` and the pair is `unjoined` ({{payment-state}}).
3. A fee member that is present with value `0` states that the sealer's
   system reported no fee. A fee member that is absent states nothing.
4. An absent `receive_fee` is read as zero only when the payment reference
   type declares that receive fees are not applicable to it
   ({{payment-ref-types}}). For every other type, a payee-observed leg
   without `receive_fee` cannot be joined: the verifier reports
   `fee_unstated` and the pair is `unjoined`, never `agreed`. A payee that
   observed no fee records `receive_fee` with value `0`.
5. `routing_fee` does not enter the join ({{payment-state}}); the payee
   cannot observe it. A payer SHOULD record it so that the payer's total
   debit is reconstructable.

# Payment References {#payment-ref}

## Shape and Join Rule {#payment-ref-shape}

A payment reference is a JSON object with a `type` member, a `value`
member, and the qualifier members its type defines:

~~~ json
{"type": "x402.transaction",
 "value": "0x5a1f...c3d2",
 "network": "eip155:8453"}
~~~

* `type` (string, REQUIRED): a registered payment reference type
  ({{iana-payment-ref}}).
* `value` (string, REQUIRED): the identifier, copied from the field the
  type names, in the normal form the type defines.
* Qualifiers (strings): as the type defines. A qualifier names the space
  in which `value` is unique (for example the CAIP-2 network of a
  transaction hash).

Two payment references are the same reference if and only if their `type`
is the same registered type and every member is identical as a string after
the type's normal form is applied. A verifier MUST NOT join legs on a
payment reference whose type it does not recognize: equal-looking strings
of an unknown type are not known to name the same payment, because the
verifier does not know the type's normal form or uniqueness scope. Such a
pair is `unjoined` ({{states}}). Under the base profile's never-reject
invariant, the legs themselves remain valid Capsules.

Types whose names begin with `x-` are private and MUST NOT be registered.

## Initial Types {#payment-ref-types}

`x402.transaction`:
: `value` is the settlement response `transaction` member. Qualifier `network`: the CAIP-2 network identifier {{CAIP-2}}, from the settlement response `network` member. Normal form: for `eip155` networks, lowercase hexadecimal with `0x` prefix; otherwise as received. Source: {{X402}}.

`ln.payment_hash`:
: `value` is the BOLT 11 payment hash (tagged field `p`). Normal form: 64 lowercase hex. Source: {{BOLT11}}.

`bolt12.invoice_payment_hash`:
: `value` is the BOLT 12 invoice `invoice_payment_hash`. Normal form: 64 lowercase hex. Source: {{BOLT12}}.

`ap2.transaction_id`:
: `value` is the AP2 Payment Mandate `transaction_id`. Normal form: as received. Source: {{AP2}}.

`ap2.payment_id`:
: `value` is the AP2 Payment Receipt `payment_id`. Normal form: as received. Source: {{AP2}}.

`ap2.network_confirmation_id`:
: `value` is the AP2 Payment Receipt `network_confirmation_id`. Normal form: as received. Source: {{AP2}}.

`acp.order_id`:
: `value` is the ACP order `order.id`. Normal form: as received. Source: {{ACP}}.

`ucp.order_id`:
: `value` is the UCP order `order.id`. Normal form: as received. Source: {{UCP}}.

`mpp.reference`:
: `value` is the `reference` member of the decoded `Payment-Receipt`. Qualifier `method`: the receipt's `method` member. Normal form: as received. Source: {{I-D.ryan-httpauth-payment}}.

`iso20022.uetr`:
: `value` is the ISO 20022 `UETR` (Unique End-to-end Transaction Reference). Normal form: lowercase UUID string {{RFC9562}}. Source: {{ISO20022}}.

`iso20022.end_to_end_id`:
: `value` is the ISO 20022 `EndToEndId`. Qualifier `debtor_agent`: the BIC of the debtor agent. Normal form: as received. Source: {{ISO20022}}.

`open_payments.incoming_payment`:
: `value` is the Open Payments incoming payment `id` (a URL). Normal form: as received. Source: {{OPEN-PAYMENTS}}.

Receive fees: `x402.transaction` declares receive fees not applicable,
because the x402 `exact` scheme transfers exactly `amount` to `payTo` and
any facilitator charge is outside that transfer. Every other initial type
declares that a receive fee may apply ({{fees}}, rule 4).

Notes on the initial types:

* x402 settlement responses always carry `transaction` and `network`. The
  x402 signed receipt omits `transaction` by default for privacy
  {{X402-OFFER-RECEIPT}}; a payee-observed leg takes the reference from the
  settlement response its facilitator returned, not from the receipt.
* For batched settlement, where many payments settle in one on-chain
  transaction, the transaction hash is not unique to one payment. Such a
  rail needs its own type naming the per-payment identifier it assigns.
* `EndToEndId` is assigned by the initiating party and is not globally
  unique; the `debtor_agent` qualifier narrows it. Where a `UETR` exists,
  `iso20022.uetr` SHOULD be used instead.
* AP2 `payment_id` and `network_confirmation_id` appear in the Payment
  Receipt, which is produced after the payment; `transaction_id` appears in
  the Payment Mandate, before it. A payer's leg and a payee's leg join only
  on a type both sides' systems report.

# Wrapping Existing Signed Objects {#wrap}

Many payment protocols already produce signed objects: the x402 signed offer
and receipt, AP2 mandates and receipts, the BOLT 12 invoice and payer proof.
These records carry such an object as it is. It never re-signs it and
never re-encodes it.

A `wrapped` entry is a JSON object:

| Member | Type | Req | Meaning |
|---|---|---|---|
| `type` | string | REQUIRED | A registered wrapped object type ({{iana-wrapped}}). |
| `digest_alg` | string | REQUIRED | `SHA-256`. |
| `digest` | string | REQUIRED | SHA-256 over the object's octets as defined for its type, 64 lowercase hex. |
| `content` | string | OPTIONAL | The same octets, base64url-encoded without padding ({{RFC4648}}, Section 5). |

The rules:

1. **Exact octets.** `digest` is computed over the octets the type defines,
   which are the octets as the protocol delivered them (for example the
   ASCII octets of a JWS compact serialization). A sealer MUST NOT parse
   and re-serialize the object before digesting it, and MUST NOT apply RFC
   8785 to it unless the type says so. This is the rule that
   {{I-D.mih-sokolov-scitt-payload-binding}}, Section 4.4, names
   `as-transmitted`: no canonicalization, SHA-256 over the exact octet
   sequence the carrying format already fixes, written as 64 lowercase hex
   characters. A wrapped type's octet definition ({{iana-wrapped}}) plays
   the role of that section's byte-boundary selector, and SHOULD name the
   production in the type's own specification that fixes those octets.
2. **Content check.** When `content` is present, a verifier MUST decode it
   and check that its SHA-256 equals `digest`. A mismatch is
   `wrapped_digest_mismatch`.
3. **Never re-sign.** A sealer MUST NOT re-sign a wrapped object, sign a
   copy of it with its own key, or restate its claims as members of its own
   leg in place of wrapping it. The sealer's Producer Envelope covers the
   leg, and therefore the digest of the wrapped object; it says that the
   sealer holds an object with that digest, not that the sealer issued it.
   A wrapped object whose signature verifies under the sealer's own leg key,
   where the wrapped type's issuer is a different party, is
   `wrapped_resigned`.
4. **Verification of the wrapped object is the wrapped protocol's.** A
   verifier MAY verify the wrapped object under its own protocol's rules
   (for example an AP2 receipt under the processor's key). This document
   does not change those rules, and a wrapped object's validity does not
   change what the leg itself proves.

The octets for each initial type are defined in {{iana-wrapped}}. For the
x402 objects in EIP-712 format, the protocol defines no byte string for the
object as a whole, so the octets are the RFC 8785 form of the JSON envelope
object (`format`, `payload`, `signature`); the EIP-712 signature covers the
typed-data hash, not JSON octets, so this canonical form does not affect the
signature. In the terms of {{I-D.mih-sokolov-scitt-payload-binding}}, that
type selects `jcs` (Section 4.1) rather than `as-transmitted`, because the
container defines no byte sequence to select.

{::comment}
EDITOR'S NOTE (for Steven, not for publication): the COSE successor to the
payload-binding draft (the deterministic preimage-encodings document, renamed
draft-mih-sokolov-cose-det-encodings-00 on 2026-09-26) is not yet on the
datatracker under that name or any earlier one. Its citation here is pending
its submission; add it as an informative reference once it is posted.
{:/comment}

# Derived Settlement States {#states}

## Inputs {#state-inputs}

A verifier derives states from a set of leg records. A party that presents
its own legs, the counterparty legs it holds, and the octets of the objects
they wrap can carry them together in an Evidence Bundle
{{I-D.mih-zhang-agent-disclosure-bundle}}, whose citation closure lets the
verifier check that every leg a presented leg cites is present. For each leg it first
checks:

1. the Capsule checks of the base profile;
2. each Producer Envelope, and the authenticated key;
3. the `settlement` member's structure ({{settlement-member}}) and amounts
   ({{amounts}});
4. the wrapped entries ({{wrap}});
5. the sealer rules ({{sealers}}), against the verifier's key policy.

A leg that fails a check is reported with the failure and does not
contribute to the derived state. The distinct-key rule ({{sealers}}) is a
check on a pair of legs, not on one: `sealer_conflation` prevents `agreed`
but does not by itself exclude either leg, because without a key policy the
verifier cannot tell which of the two legs is the genuine one. The legs
that remain are grouped by `terms_ref`. Every check is performed on the records' own bytes; no
state is read from any record.

## Payment State {#payment-state}

For one terms leg, let P be the payer-observed legs that cite it and Q the
payee-observed legs that cite it. A sealer SHOULD produce at most one
observed leg per terms leg; when it produces a later one (for example when
`pending` becomes `settled`), the later leg SHOULD chain to the earlier
with relation `supersedes`, and the verifier uses the head of that chain.

| State | Condition |
|---|---|
| `terms_only` | No observed leg cites the terms leg. |
| `payer_stated` | Only a payer-observed leg is present. A stated claim. |
| `payee_stated` | Only a payee-observed leg is present. A stated claim. |
| `agreed` | Both are present and joinable, sealed under distinct keys, their payment references are the same reference ({{payment-ref-shape}}), the amount rule below holds, and their `status` values are equal. The verifier reports the agreed status. |
| `mismatch` | Both are present and joinable, and the amount rule fails, the `status` values differ, or the payment references differ. The verifier reports which of `amount`, `status`, and `payment_ref` differ. |
| `unjoined` | Both are present, but they cannot be joined: a payment reference type is not recognized, the two legs carry payment references of different types, `receive_fee` is absent where the type does not declare receive fees not applicable (`fee_unstated`), or a fee is in a different asset from its amount (`fee_asset_differs`). |

**The amount rule.** The two observed legs are consistent on amount if and
only if

~~~
   payer.amount = payee.received + payee.receive_fee
~~~

where all three carry the same `assetCode` and the sum and comparison are
computed exactly at the largest `assetScale` of the three
({{amounts}}, {{fees}}). If `payer.amount` has a different `assetCode`
from `payee.received`, the amount rule fails and the state is `mismatch`.
A verifier MUST NOT compare `payer.amount` with `payee.received` directly:
a receive-side fee makes them differ in an honest payment, and treating
that difference as a mismatch would misreport it. A verifier MUST NOT relax
the amount rule by a tolerance; a difference of one unit at the common
scale is a mismatch.

A verifier MUST NOT report `agreed` for a pair that fails the distinct-key
rule ({{sealers}}); it reports `sealer_conflation` instead.

A one-sided state is a stated claim. It says what one sealer reports its
own system observed. It is not evidence of agreement, and a verifier MUST
NOT present it as `agreed`. The absence of the other leg is not evidence
that the other side disagrees: the other leg may not exist yet, may exist
and not have been shared, or may never be produced. A verifier that needs
to distinguish these can ask the counterparty for its leg using an
evidence request {{I-D.mih-agent-evidence-request}}, whose outcomes
distinguish an answer, a signed refusal, and a recorded absence.

`agreed` is about the payment only. A verifier also reports, separately,
whether the payer's `amount` equals the terms leg's `amount`
(`terms_amount: equal` or `differs`). Two sides can agree on what moved and
both differ from the terms. This document defines no fee bounds in the
terms leg; whether a fee was acceptable is a question about the terms, not
about whether the two sides agree, and a future revision that adds bounds
reports them in the same separate way.

## Delivery State {#delivery-state}

For one terms leg, let D be the delivered legs that cite it.

| State | Condition |
|---|---|
| `none` | No delivered leg. |
| `stated` | One side's delivered leg only, and its `content_digest` does not differ from the terms' `deliverable.content_digest` when that is present. |
| `matched` | A `sent` leg and a `received` leg carry the same `content_digest`, and it does not differ from the terms' `deliverable.content_digest` when that is present. |
| `mismatch` | A `sent` and a `received` leg carry different `content_digest` values, or any delivered `content_digest` differs from the terms' `deliverable.content_digest`. |

The two states are independent. A payment can be `agreed` while delivery is
`none`, and delivery can be `matched` while the payment is `payee_stated`.

## Failures {#failures}

The failure codes a verifier reports for these records are:

| Code | Meaning |
|---|---|
| `settlement_malformed` | The `settlement` member is missing a required member, carries a forbidden one, or has a value outside its closed set. |
| `amount_not_exact` | An amount `value` is not a string of the required grammar, or `assetScale` is not an integer from 0 to 255. |
| `terms_ref_unresolved` | A leg's `terms_ref` does not match the `capsule_id` of any terms leg in the set. |
| `leg_role_mismatch` | A leg's `sealer_role` does not match its leg ({{sealers}}). |
| `sealer_not_authorized_for_role` | The leg's authenticated key is not accepted by the verifier's policy for the leg's role. |
| `sealer_conflation` | A payer-observed and a payee-observed leg for one terms leg are sealed under the same key. |
| `wrapped_digest_mismatch` | A wrapped entry's `content` does not hash to its `digest`. |
| `wrapped_resigned` | A wrapped object carries a signature by the leg's own sealer where its type's issuer is a different party. |
| `payment_ref_type_unknown` | A payment reference type is not recognized. Informational: the leg is not rejected, and the pair is `unjoined`. |
| `fee_unstated` | A payee-observed leg has no `receive_fee` and its payment reference type does not declare receive fees not applicable. Informational: the leg is not rejected, and the pair is `unjoined`. |
| `fee_asset_differs` | A fee's `assetCode` differs from the amount it accompanies. Informational: the leg is not rejected, and the pair is `unjoined`. |

# Status Values and ISO 20022 {#status}

An observed leg's `status` is one of four values. Each is what the
sealer's own system reported about the sealer's own side.

| `status` | Meaning |
|---|---|
| `pending` | The sealer's system reports the payment as accepted or in process, not final. |
| `settled` | The sealer's system reports the payment as final on the sealer's side: debited for the payer, credited or received for the payee. |
| `failed` | The sealer's system reports the payment as rejected or not completed. |
| `reversed` | The sealer's system reports a payment that had settled as returned or reversed. |

These values map to ISO 20022 {{ISO20022}} as follows, so that reviewers
familiar with bank status reports can read a leg directly. The payer's side
corresponds to the status the debtor agent reports; the payee's side to the
status the creditor agent reports or the entry status in the account
notification.

| `status` | Payer-observed (pacs.002 `TxSts`) | Payee-observed (pacs.002 `TxSts`) | Payee-observed (camt.054 entry status) |
|---|---|---|---|
| `pending` | `ACTC`, `ACCP`, `ACSP`, or `PDNG` | `ACSP` or `PDNG` | `PDNG` |
| `settled` | `ACSC` | `ACCC` | `BOOK` |
| `failed` | `RJCT` | `RJCT` | (no entry) |
| `reversed` | a pacs.004 return of the payment | a pacs.004 return of the payment | `BOOK` with reversal indicator `true` |

The mapping is one-way: a sealer whose system reports an ISO 20022 code
records the corresponding `status` and SHOULD wrap the status report itself.
A code not listed (for example `ACWC`, accepted with change) does not map
to `settled`; a sealer records `pending` and wraps the report, and the
change appears as an amount difference if the amounts differ.

Fees correspond to ISO 20022 charges as follows. The correspondence is
informative; a sealer records what its own system reported and wraps the
message.

| Member | ISO 20022 |
|---|---|
| payer `amount` | pacs.008 `InstdAmt`, or `IntrBkSttlmAmt` when no instructed amount is given |
| payer `routing_fee` | charges the debtor bears and is billed for separately (charge bearer `ChrgBr` `DEBT`) |
| payee `received` | camt.054 entry `Amt` of the credit |
| payee `receive_fee` | charges deducted from the amount in transit or by the creditor agent: pacs.008 `ChrgsInf` amounts deducted under `ChrgBr` `SHAR` or `CRED`, as reported to the creditor in camt.054 `Chrgs` |

With these, the amount rule ({{payment-state}}) reads: the instructed
amount equals the booked credit plus the charges deducted on the way.

For other rails, the sealer derives `status` from the object its system
returned:

| Rail object | `settled` | `failed` |
|---|---|---|
| x402 settlement response {{X402}} | `success` is `true` | `success` is `false` |
| AP2 Payment Receipt {{AP2}} | `status` is `Success` | `status` is `Error` |
| `Payment-Receipt` {{I-D.ryan-httpauth-payment}} | receipt present (`status` is `success`) | no receipt |
| Lightning payment | preimage obtained (payer) or invoice settled (payee) | payment failed |

# Crosswalk to AEP Fulfillment Fields {#aep}

The A-Comm Evidence Protocol {{AEP}} records a commerce transaction as a
single-sealer hash chain whose fulfillment artifact (AEP Section 3.7)
records shipping and delivery. A delivered leg maps to it as follows, so
that an AEP fulfillment artifact can be produced from a delivered leg and
compared with one.

| AEP Section 3.7 field | This document | Note |
|---|---|---|
| `fulfillment_id` | Capsule `action_id` | |
| `platform_order_id` | `payment_ref` of type `acp.order_id` or `ucp.order_id` on the observed legs | |
| `carrier` | `delivery.carrier` | |
| `tracking_number` | `delivery.tracking_digest` | Digest only; the number is not carried ({{privacy}}). |
| `tracking_url` | not carried | A locator, not evidence. |
| `status` | `delivery.status` | Same five values. |
| `shipped_at` | `delivery.shipped_at` | |
| `delivered_at` | `delivery.delivered_at` | |
| `delivery_address_hash` | `delivery.address_digest` | Same salted-hash approach. |
| `delivery_address_match` | not carried | A derived value; derived by the verifier, never asserted. |
| `signature_captured` | not carried | Personal data; a proof-of-delivery document may be wrapped by digest. |
| `proof_of_delivery_url` | `wrapped` entry of type `delivery.proof` | The document by digest, not its URL. |
| `captured_at` | Capsule `timestamp` | |
| `idempotency_key` | Capsule `action_id` | |

The authorization fields of AEP Section 3.6 that concern settlement map as
follows. AEP records no fee fields; `routing_fee`, `received`, and
`receive_fee` have no AEP counterpart, and an AEP export carries the
payer's `amount` only.

| AEP Section 3.6 field | This document |
|---|---|
| `settlement_rail` | implied by the `payment_ref` type |
| `stablecoin.chain` | `payment_ref.network` (`x402.transaction`) |
| `stablecoin.transaction_hash` | `payment_ref.value` (`x402.transaction`) |
| `stablecoin.asset` | `amount.assetCode` (as a CAIP-19 asset type) |
| `stablecoin.amount_atomic` | payer `amount.value`, with `assetScale` set to the asset's decimals |
| `x402_payment_response` | `wrapped` entry of type `x402.settle-response` |

AEP seals its chain under one server key and names independent signatures
as one way to raise a bundle above its "Asserted" signal class. A pair of
payer-observed and payee-observed legs, each sealed by its own party, is
evidence of that kind for the payment.

# Registration with a Transparency Service {#registration}

Each leg is a Capsule and can be made transparent the way the base profile
defines: a registrar submits a Signed Statement whose payload is the leg's
Capsule ID to a SCITT Transparency Service {{RFC9943}} and obtains a Receipt
{{RFC9942}}. A Receipt proves that the leg was registered in that
Transparency Service's log; it does not prove that the leg's content is
true, and it does not make a one-sided leg two-sided.

Each sealer SHOULD register its own legs. A sealer MAY register with more
than one Transparency Service. Registration gives a third party a way to
check that a leg existed at the time of its Receipt; a sealer that later
produces a conflicting leg for the same terms cannot also make the earlier
one disappear from a log it was registered in. Which Registration Policy a
Transparency Service applies is that service's concern.

# Relationship to Existing Work {#related}

**Bilateral attestation.** {{I-D.mih-agent-bilateral-attestation}} defines a
request/action exchange between two organizations, in which each signs its
own half and acknowledges the other's. This document applies the same
discipline to a payment: each side signs only its own half, the halves cite
each other by digest, and a missing half is a defined state rather than an
error. The settlement legs are not the bilateral exchange's objects; a
deployment can use both, with an action attestation citing a terms leg.

**x402.** This document binds to the x402 settlement response's `transaction`
and `network` {{X402}}, and wraps the signed offer and receipt
{{X402-OFFER-RECEIPT}}. It adds a record of what the payer's side observed,
which x402 does not define, and a delivered-content digest bound to the
terms.

**AP2.** AP2 mandates and receipts {{AP2}} are wrapped by digest. A Payment
Receipt is the processor's statement; in these records it is carried in the
payee's leg as the processor's object, and the payee's own observation is
the leg itself.

**BOLT 12 payer proofs.** A payer proof {{BOLT12}} is a two-sided proof of a
Lightning payment. It is wrapped, not replaced; this document adds the
delivery leg and a form that is the same across rails.

**Payment HTTP authentication.** The `Payment-Receipt`
{{I-D.ryan-httpauth-payment}} is not signed. Wrapped in a payee-observed
leg, it becomes part of a signed record that can be registered.

**Cedulon.** {{I-D.dogru-cedulon-core}} defines an issuer-signed Trade
Manifest before payment and an issuer-signed Spend Receipt after it, with an
optional second signature by the payee over a delivered-content hash
(`deliveredHash`). Both documents use COSE and bind delivery by digest.
This document differs in having two sealers of equal standing, each
recording its own observation, and in deriving the settlement state from
both.

**COSE countersignatures.** Nothing in this document is a COSE
countersignature {{RFC9338}}. Each leg is a separate Capsule from a
separate sealer.

# Security Considerations {#security}

**One party sealing both sides.** The main attack on a two-sided record is
one party producing both halves. A payer-observed and payee-observed pair
under one key is detected without any policy ({{sealers}}). A pair under
two keys that one party controls is not detectable from the records; the
verifier's key policy is what binds each key to a party, and the evidence
is no stronger than that binding.

**Stated claims.** A one-sided leg is easy to produce and says only what one
party claims. Verifiers MUST present one-sided states as stated claims
({{payment-state}}).

**Pre-written legs.** A sealer can write several candidate legs for one
terms leg and disclose the one it prefers. Registration with a Transparency
Service ({{registration}}) makes each registered leg discoverable later,
and the at-most-one-observed-leg rule ({{payment-state}}) makes a second
unchained leg for the same terms visible as such. A payer-observed leg
cites a terms leg whose `capsule_id` the payer did not choose, and the
payment reference is produced by the rail, so the values a payer digests
are not all under its control. See also the considerations on predictable
values in {{I-D.mih-agent-bilateral-attestation}}.

**Wrapped objects.** A wrapped object is carried by digest. A leg that
wraps an object proves the sealer held octets with that digest; it does not
prove the object is valid. A verifier that relies on a wrapped object's
content verifies that object under its own protocol.

**Re-signing.** A sealer that re-signs an upstream object makes it look as
though the sealer issued it, and replaces the upstream signer's evidence
with its own. The never-re-sign rule ({{wrap}}) prevents this; the
`wrapped_resigned` check detects the simplest case.

**Amounts.** Floating-point amounts produce different values on different
platforms and make digests unstable. Amounts are exact integers with a
scale ({{amounts}}); comparing assets by identical `assetCode` prevents a
rate from being applied silently.

**Fees.** A naive comparison of the payer's and the payee's amounts would
report every payment with a receive-side fee as a mismatch, and a verifier
that learned to ignore such mismatches would then also ignore real ones.
The amount rule ({{payment-state}}) is exact, so a difference it does not
explain is always reported. Because the rule trusts the payee's report of
`receive_fee`, a payee can explain a shortfall by overstating its fee; the
two sides then agree on the arithmetic, and whether that fee was
acceptable is a question for the terms. A payee that omits `receive_fee`
on a rail where fees apply gets `unjoined`, never `agreed`, so silence
cannot pass for a zero fee.

**Payment references.** A payment reference names a payment; it is not
evidence the payment happened. The status in an observed leg is the
sealer's report of its own system's report. A verifier that needs the
rail's own confirmation obtains it from the rail.

**Canonicalization.** All digests over JSON in this document use the base
profile's declared RFC 8785 construction, the `jcs` algorithm of
{{I-D.mih-sokolov-scitt-payload-binding}}. Wrapped objects use the octets
their type defines, under that document's `as-transmitted` rule
({{wrap}}). No digest is computed over an object re-encoded by
inference from its shape.

# Privacy Considerations {#privacy}

Payment records are personal data in most jurisdictions when a party is a
natural person, and commercially sensitive otherwise.

**Identifiers are personal data.** Payment references (transaction hashes,
end-to-end identifiers, order identifiers) and wallet addresses can
identify a person or link payments together. A leg carries only the
payment reference needed to join the two sides. Deployments SHOULD treat a
leg as personal data and disclose it only to the counterparty and to
parties entitled to review the settlement.

**No raw account numbers.** A leg MUST NOT carry a raw bank account number,
card number, IBAN, or similar account identifier. Where an account must be
matched, a leg carries a salted digest of it. Delivery addresses and
tracking numbers are carried only as salted digests (`address_digest`,
`tracking_digest`); the salt is kept by the sealer and disclosed only to
parties entitled to check the match. Unsalted digests of low-entropy values
such as addresses can be reversed by guessing.

**Correlation.** A payment reference that appears in registered legs links
those legs to the public record of the rail (for example an on-chain
transaction). Registering legs in a Transparency Service in clear text
makes the payment discoverable to anyone who can read the log. Deployments
SHOULD register only the leg's Capsule ID, as the base profile does, and
SHOULD use the selective-disclosure profile
{{I-D.mih-scitt-agent-action-capsule-sel-disc}} to commit to the payment
reference and amount rather than disclose them where the use case allows.
The x402 signed receipt omits the transaction reference by default for the
same reason {{X402-OFFER-RECEIPT}}.

**Fees.** Fee amounts can reveal the route, the intermediaries, or the
commercial terms between a payee and its provider. They are subject to the
same disclosure considerations as amounts.

**Delivered content.** The delivered leg carries a digest of the content,
never the content. A digest of low-entropy content (a short answer, a
yes/no result) can be guessed; a sealer delivering such content SHOULD
digest a structure that includes an unpredictable component, such as the
full response object.

# IANA Considerations {#iana}

This document asks IANA to create two registries in a new "Agent Settlement
Records" registry group. Until IANA establishes them, the source repository
of this document keeps them as the interim registry of record.

## Payment Reference Types {#iana-payment-ref}

Registry name: Settlement Payment Reference Types.

Registration policy: Specification Required ({{RFC8126}}, Section 4.6).

Each entry has: the type name; the upstream field `value` is copied from;
the qualifier members and their meaning; the normal form; whether a
receive fee may apply or is not applicable ({{fees}}); and a reference
to a publicly available specification of the upstream field.

Designated-expert guidance: the expert checks that the upstream field is
publicly specified, that the normal form makes equality well defined, that
the qualifiers make `value` unique for one payment, and that the type does
not duplicate an existing one. Names beginning with `x-` are not
registered.

Initial contents: the types in {{payment-ref-types}}, each referencing this
document and the source listed there.

## Wrapped Object Types {#iana-wrapped}

Registry name: Settlement Wrapped Object Types.

Registration policy: Specification Required ({{RFC8126}}, Section 4.6).

Each entry has: the type name; the issuer of the object under its own
specification; the exact octets the digest is computed over; and a
reference.

Initial contents:

`x402.offer`:
: Issuer: payee. Octets: JWS format: the ASCII octets of the JWS compact serialization. EIP-712 format: RFC 8785 form of the envelope object (`format`, `payload`, `signature`). Reference: {{X402-OFFER-RECEIPT}}.

`x402.receipt`:
: Issuer: payee. Octets: As for `x402.offer`. Reference: {{X402-OFFER-RECEIPT}}.

`x402.payment-payload`:
: Issuer: payer. Octets: The base64-decoded value of the `PAYMENT-SIGNATURE` header as sent. Reference: {{X402}}.

`x402.settle-response`:
: Issuer: facilitator. Octets: for the payer, the base64-decoded value of the `PAYMENT-RESPONSE` header as received; for the payee, the settlement response body as its facilitator returned it. Reference: {{X402}}.

`ap2.checkout-mandate`:
: Issuer: user or agent. Octets: The SD-JWT serialization as presented. Reference: {{AP2}}.

`ap2.payment-mandate`:
: Issuer: user or agent. Octets: The SD-JWT serialization as presented. Reference: {{AP2}}.

`ap2.checkout-receipt`:
: Issuer: merchant. Octets: The JWT compact serialization as received. Reference: {{AP2}}.

`ap2.payment-receipt`:
: Issuer: payment processor. Octets: The JWT compact serialization as received. Reference: {{AP2}}.

`bolt12.invoice`:
: Issuer: payee. Octets: The invoice TLV stream octets. Reference: {{BOLT12}}.

`bolt12.payer-proof`:
: Issuer: payer. Octets: The payer proof TLV stream octets. Reference: {{BOLT12}}.

`mpp.payment-receipt`:
: Issuer: payee. Octets: The base64url-decoded value of the `Payment-Receipt` header. Reference: {{I-D.ryan-httpauth-payment}}.

`iso20022.message`:
: Issuer: the agent that sent it. Octets: The XML message octets as received. Reference: {{ISO20022}}.

`delivery.proof`:
: Issuer: carrier or payee. Octets: The proof-of-delivery document octets. Reference: this document.

## No Other Actions

This document reserves the Capsule payload member name `settlement` for the
use defined here. The base profile has no IANA registry of payload member
names, so no IANA action is requested for it. The `leg`, `sealer_role`,
`status`, and `delivery.direction` values are closed sets defined by this
document and are not registries; a future revision that needs a new value
updates this document.

--- back

# Conformance Vectors {#vectors}
{:numbered="false"}

The source repository of this document carries conformance vectors in
`vectors/settlement/`. They are generated by a deterministic script from
fixed Ed25519 seeds and RFC 8785 canonical forms, and each case states its
expected states and failure codes. The cases are: a two-sided x402
settlement with matching legs and matched delivery; two Lightning payments
of 1000 millisatoshi each where the payee recorded 995 received and a
receive fee of 5, which agree; a receive fee that does not explain the
difference, and an absent receive fee, on Lightning; one-sided payer and
payee settlements; mismatches in asset and in delivered content; amounts
equal at different scales; a two-sided BOLT 12 settlement wrapping a payer
proof; an AP2 Payment Receipt wrapped by digest; and negative cases for a
re-signed wrapped object, a wrapped object whose content does not match its
digest, a floating-point amount, a decimal-fraction amount string, an
unknown payment reference type, and a payee-observed leg sealed with the
payer's key.

# Example {#example}
{:numbered="false"}

A payer-observed leg for an x402 payment of 1.5 USDC on Base (the Capsule's
other members abbreviated):

~~~ json
{
  "action_id": "settle-0001-payer",
  "action_type": "fyi",
  "canonicalization_id": "jcs",
  "format_version": "4",
  "settlement": {
    "version": "0",
    "leg": "payer_observed",
    "sealer_role": "payer",
    "terms_ref": "<capsule_id of the terms leg>",
    "payment_ref": {
      "type": "x402.transaction",
      "value": "0x5a1f...c3d2",
      "network": "eip155:8453"
    },
    "amount": {
      "value": "1500000",
      "assetCode": "eip155:8453/erc20:0x8335...2913",
      "assetScale": 6
    },
    "routing_fee": {
      "value": "0",
      "assetCode": "eip155:8453/erc20:0x8335...2913",
      "assetScale": 6
    },
    "status": "settled",
    "observed_at": "2026-10-01T12:00:05Z",
    "wrapped": [
      {"type": "x402.payment-payload",
       "digest_alg": "SHA-256",
       "digest": "<SHA-256 of the PAYMENT-SIGNATURE octets>"}
    ]
  }
}
~~~

# Acknowledgments
{:numbered="false"}

This document was shaped by the public discussion of offer digests, delivery
hashes, and offline-verifiable receipts in the x402 community, by the AP2
receipt model, by the BOLT 12 payer proof work, and by the AEP and Cedulon
drafts.
