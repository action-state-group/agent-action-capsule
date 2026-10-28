# Exchange Records onto Bilateral Attestation: a Mapping — v0

**Status.** Informational, pre-Internet-Draft, kept in this repository. It changes no
Internet-Draft, defines no record format, registers nothing and names nothing new. It maps the
records two existing producers seal for a two-party exchange onto the objects of
`draft-mih-agent-bilateral-attestation-03` (cited here as BA). Each record is either defined by
`draft-mih-agent-settlement-records-00` (SR), in which case this document follows SR and does not
restate or change it, or it is **plugin-local**. For every record the nearest BA object is named,
with what the record lacks to be one.

## Dependency boundary

**Uses unchanged:**

| Tag | Document | What this document takes from it |
|---|---|---|
| BA | `spec/draft-mih-agent-bilateral-attestation-03.md` | the four exchange objects, the constraint-record obligations, the asymmetry dispositions, the reduced-assurance indicator, the delivery intermediary, registration |
| SR | `spec/draft-mih-agent-settlement-records-00.md` | the four legs, the `settlement` member, the derived states, and its statement that "The settlement legs are not the bilateral exchange's objects; a deployment can use both, with an action attestation citing a terms leg" (SR cites BA -02; BA's definitions and exchange sections differ between -02 and -03 only editorially: "anchored" became "registered", and capitalization) |
| AAC | `spec/draft-mih-scitt-agent-action-capsule-05.md` | `verdict_class`, `references[]` |
| REG | `spec/REGISTRY.md` | `citation_purpose` (§11) |
| DR | `spec/deal-reconcile-contract-v0.md` | the half, its field commitments, the reconcile |

**Does not define:** any record, member, name or registry entry; what either producer should
change; any judgment over an exchange.

## 1. Sources

Each row is read from source at the commit named.

| Tag | What | Pinned at |
|---|---|---|
| SRC-A | A compute-exchange plugin: the settlement legs it seals for a paid exchange (one terms leg per invoice) | release tag `v0.1.4`, commit `b4e24453f572b2d9fe8f2cefbd0f35a5eb54b0ad` |
| SRC-B | A marketplace plugin: its deal record profile (a closed set of twenty record types, per its schema's enum), its typed action records, its settlement notes, its reconcile of two closes, its countersign rung | commit `1819bb569b50ee34359046d3cf246fe4923ac45b` |
| SRC-C | The core the marketplace plugin builds on: the `countersign/v1` entry, the cadence publisher, the settlement-leg builders | commit `8a856b7513166d80c001529b9f0b3db22950d2f2` |

## 2. The BA objects mapped onto

| Label | BA object | Members BA requires of it |
|---|---|---|
| BA-REQ | Request attestation | the requested action and its material terms; the requester's verifiable organizational identity; the named performing party; a content digest; a nonce; a timestamp; a validity window |
| BA-ACT | Action attestation | the request attestation's digest; a result for every constraint in the pinned set (pass, fail, not-evaluated with a reason), each identified by reference; the constraint-set digest (MUST); an input-commitment digest over the inputs the constraints consulted (SHOULD); the disposition, as an AAC `verdict_class`; the performer's identity |
| BA-ACK | Acknowledgment | receipt of the counterparty's attestation; "Receipt does not assert agreement with the attestation's contents" |
| BA-ASYM | Asymmetry dispositions | `delivery_unconfirmed`, `counterparty_timeout`, `countersign_refused`; binding by correlation identifier and shared action digest; the orphan state |
| BA-RAI | Reduced-assurance indicator | a marker that an exchange completed with fewer than the full set of attestations; "Degradation MUST be recorded, never silent" |
| BA-DI | Delivery intermediary | stores and forwards attestations as opaque blobs and issues signed delivery receipts, which it registers |
| BA-REG | Registration | each attestation and acknowledgment registered with a Transparency Service (SHOULD) |

BA uses "countersign" for the performing party issuing its own signed half citing the request.
SRC-C's `countersign/v1` is a different thing (§5.1). The two are kept apart below.

## 3. The rule for the shared record

The shared exchange record (a description of what both producers can emit, not a name) is held
to these rules:

1. **Required core:** the agreed terms, each side's observation of the payment, and what was
   delivered. Both producers use SR's legs for these, so the core is SR's four legs: terms,
   payer-observed, payee-observed, delivered. §5.6 states which legs each producer seals today.
2. **Everything before agreement is optional:** the intent that started the exchange, and the
   negotiation trail (offers, counters, acceptance).
3. **The agreed terms verify without the trail.** No required check on the core reads an
   optional record.
4. **A record only one side emits never forces a second format.** An optional record rides on
   the core by digest reference or stays plugin-local. It adds no member the other producer must
   understand.

## 4. The mapping

Fit is one of: **SR** (defined by SR, so not a BA object, per SR's statement quoted above), or
**plugin-local** (neither BA nor SR defines it). No record either producer seals today is a BA
object. The "Nearest BA object" column names what each record comes closest to, and "Lacks"
names what keeps it from being one.

### 4.1 SRC-A: the compute-exchange plugin's settlement legs

| # | Record (sealer) | What it carries at SRC-A | Fit | Nearest BA object | Lacks | Shared record |
|---|---|---|---|---|---|---|
| A1 | terms leg (payer) | `amount` (invoice amount, `BTC`, `assetScale` 11), `payment_ref` (`ln.payment_hash`) | SR: terms | none. In SR's model a BA-ACT may cite it. | — | required: agreed terms |
| A2 | payer-observed (payer) | `terms_ref`, `amount`, `payment_ref`, `status` `settled`, `observed_at`, `routing_fee` when the host reports it | SR: payer_observed | none | BA has no object for either party's observation of the payment. | required: payer's observation |
| A3 | payee-observed (payee) | `terms_ref`, `received`, `receive_fee`, `payment_ref`, `status` `settled`, `observed_at`; sealed only when the host reports both the credited amount and the fee; no `references[]`, so no `counterparty_half` citation of the payer's leg | SR: payee_observed | none | As A2. | required: payee's observation |
| A4 | delivered, direction `received` (payer) | `terms_ref`, `observed_at`, `delivery.content_digest` (the exchange's response digest) | SR: delivered | BA-ACK by the requester | It is an observation of delivered content. A BA-ACK acknowledges an attestation and has no content-digest member. | required: delivered |
| A5 | delivered, direction `sent` | not sealed at SRC-A: the provider's exchange events are not joined to its payment events | — | BA-ACT (`executed`) | — | required: delivered (the other direction serves) |
| A6 | intent | none emitted | — | — | — | optional; omitted |
| A7 | negotiation trail | none emitted (fixed price, terms only) | — | — | — | optional; omitted |

### 4.2 SRC-B: the marketplace plugin's records

Every value of SRC-B's `record_type` enum and every typed record of its §9 appears once.

| # | Record | What it is | Fit | Nearest BA object | Lacks | Shared record |
|---|---|---|---|---|---|---|
| B1 | `baseline` (open) | First contact: the request, pre-agreement terms, `recourse`, `channel`, and counterparty identifiers as per-deal keyed fingerprints | plugin-local | BA-REQ | Not addressed or signed to the counterparty. It names the counterparty by keyed fingerprints, not by a verifiable organizational identity. It has no validity window, and its terms are first-contact terms, not agreed ones. | its intent: optional (B3) |
| B2 | shared `deal_id`, two-party open (open) | Both parties' steps carry one opaque `deal_id`, and a composition joins their copies on it, or derives `unjoined` | plugin-local | BA-ASYM correlation identifier | No shared action digest and no asymmetry disposition. `unjoined` is the nearest thing SRC-B has to BA's orphan. | — |
| B3 | `intent`, the baseline's `intent`, `task-authority/v0` (intent) | The user's request and limits, by commitment. The task authority is re-sealed when the user confirms new limits. | plugin-local | none (§5.3) | — | optional |
| B4 | `check`, typed `proposed-action/v0` (check) | The exact act about to be taken, before a point of no return | plugin-local | BA-ACT, the evaluated input | `proposed_action_digest` covers the proposed action only. The evaluator also reads the ruleset, task authority, history and platform approvals (the check request), so this is a subset of BA's input commitment. The evaluator is the acting party's own agent checking against its user's authority; the counterparty sends no request. | — |
| B5 | `verdict`, typed `action-evaluation/v0` (check) | Disposition `DO`, `ASK` or `DENY`, with findings | plugin-local | BA-ACT, constraint record and disposition | `ruleset_digest` pins the constraint set (meets BA's MUST). `findings` lists differences only, never a passing rule, and `rules_checks` gives one verdict per ruleset, so BA's result for every constraint (MUST) is not met. It has no request-attestation digest and no verifiable organizational identity. It carries no `verdict_class`; a proposed reading (not stated by any source) is `DENY` as `denied` or `blocked`, `ASK` as `hitl_dispatched` or `needs_decision`, and `DO` as no terminal class until the following action. | — |
| B6 | `approval`, typed `action-approval/v0` with `user_approval`, `card_answer`, `policy_change`, `platform_approval`, or `one_shot_override` (reserved, refused) (check) | The authority for the next step | plugin-local | none | Authority between a user and its own agent. BA mentions this layer only informatively: a request attestation "may reference the delegation receipt authorizing the requesting agent". | — |
| B7 | typed `check-request/v0`, `check-response/v0` (check) | The shapes an evaluator takes and returns, sealed or not | plugin-local | none | — | — |
| B8 | countersign: a `countersign/v1` entry on a deal's Evidence Bundle (SRC-B rung, SRC-C entry) | A signature over one bundle's digest, with `statement.checks`, `recomputed_at`, `scope` | plugin-local | BA-ACK | §5.1 | — |
| B9 | `close` (close) | The deal's end, its outcome, `actor` and `reason` | plugin-local | none | — | — |
| B10 | DR half: a final close's `amount` and `currency` commitments (close) | Only a final close with status `received` commits non-empty terms: the delivered price and currency, or the agreed ones where the close names none. Every other close commits the empty text. DR reconciles the two parties' halves. | plugin-local | none | Two independent self-records reconciled by a verifier, like SR's derived state. Neither half is a BA object, and neither is an SR terms leg. | — |
| B11 | cadence: one cadence-log entry per tick, the `x-cadence-witness/v0` bundle extension (SRC-C) | A fixed-depth tree over each deal's checkpoint plus a filler leaf, published to a witness on the clock alone | plugin-local | BA-REG | §5.2 | — |
| B12 | `sale` (sale) | The root of a seller's sale to one of several buyers | plugin-local | none | BA has one requester and one performer per exchange. Each buyer's thread is a deal of its own, mapped by the other rows. | — |
| B13 | `thread`, `thread_opened` (sale) | Registration and opening of one buyer's thread on the sale's log | plugin-local | none | — | — |
| B14 | `sale_cut`, `sale_close` (sale) | The cut a sale bundle is made at; the end of the sale | plugin-local | none | — | — |
| B15 | `check` with `action: offer`, its `supersedes` chain, the offer `action` (negotiation) | A seller's exact proposal; each later offer supersedes the latest earlier one | plugin-local | BA-REQ | §5.4 | optional: trail |
| B16 | counterparty acceptance observation, typed `action-approval/v0` (negotiation) | That the counterparty accepted the latest offer, its words by commitment | plugin-local | BA-ACT by the counterparty | Observed and sealed by one side; the counterparty signs nothing (§5.4). | optional: trail |
| B17 | `message` (negotiation) | One message in the thread, its text by commitment | plugin-local | none | — | optional: trail |
| B18 | `action`, typed `action-record/v0`, including an approved disclosure (`disclosed`) | A point-of-no-return act taken, with its authority basis | plugin-local | BA-ACT, unilateral, at reduced assurance | No request-attestation digest (the counterparty sent none). No BA-RAI marker, which BA requires on a unilateral record. Constraint completeness as B5. No verifiable organizational identity. | — |
| B19 | `outcome`, typed `action-outcome/v0` | What was observed afterwards | plugin-local | none | It overlaps SR's delivered leg in meaning but is not one. | — |
| B20 | `evidence` carrying a `settlement` member: payment received (seller) | SR payee-observed leg, `payment_ref` `x402.transaction`, answering the buyer's terms leg by `terms_ref` | SR: payee_observed | none | As A2. | required: payee's observation |
| B21 | `evidence` carrying a `settlement` member: delivered (seller) | SR delivered leg, direction `sent`, a content digest or the carrier fields | SR: delivered | BA-ACT effect | An SR leg is an observation and carries no constraint results or disposition. | required: delivered |
| B22 | `evidence`, other uses | A claim's evidence, a merchant's signed email, a held object by digest (`wrapped`, in SR's shape) | plugin-local | none | — | — |
| B23 | `claim` | A counterparty's assertion, recorded as a claim, by commitment | plugin-local | none | — | — |
| B24 | `agent_move` | The agent's search, options, recommendation, choice or failure | plugin-local | none | — | — |
| B25 | `detail_change` | The counterparty changed an identifier, a term or the rail | plugin-local | none | — | — |
| B26 | `disclosure` (authority `none`, or any untyped disclosure) | What the agent told someone about the user, by class and commitment. An approved disclosure in a typed deal is B18. | plugin-local | none | — | — |
| B27 | `counterparty_profile` | The payee fingerprinted under a profile key; never shared | plugin-local | none | — | — |
| B28 | sealed report, standalone report; typed `action-report/v0` (reserved) | A copy's readable text, sealed; not a step | plugin-local | none | — | — |
| B29 | terms Result on the deal's results book | The DR Result a party computes and seals | plugin-local | none | — | — |

SRC-B as pinned seals no terms leg and no payer-observed leg. The seller side consumes the
buyer's terms leg (`--terms`, a capsule file) and never restates it. SRC-C's settlement package
exports builders for the payee-observed leg (x402) and the delivered leg (direction `sent`) only.

## 5. Findings

### 5.1 Countersign: not without loss

A `countersign/v1` entry is a signature by some party over the digest of one Evidence Bundle
file. The digest leaves out only the `countersignatures` member. The entry carries a statement
of named check results. SRC-C's `countersign request` submits only a withheld bundle (it refuses
one that carries disclosures), so the signer is given records without their payloads. Its
nearest BA object is BA-ACK. As a BA-ACK it loses:

- **`statement.checks`**: the signer's named check results. A BA-ACK records receipt only;
  BA: "Receipt does not assert agreement with the attestation's contents". It has no member for
  a check result.
- **`statement.scope`** (`ledger_id`, `period`, `closure_depth`) and **`recomputed_at`**.
- **Granularity.** One countersignature covers a whole bundle of many records; one BA-ACK covers
  one attestation. A mapping between them keeps one binding and loses the other.
- **The signer.** A BA-ACK is the counterparty's. A countersigner is any party the verifier's
  chosen directory resolves. BA's other signers (the delivery intermediary's receipts, a
  Transparency Service's Receipts) attest delivery and inclusion, not checks over records.
- **What the verifier reports about the signer.** SRC-B's rung reports `countersigned`,
  `self_countersigned`, `unresolved_signer`, `unverified` and `not_countersigned`; SRC-C's verify
  step reports its own results. BA has no counterpart.

The word also collides: BA's `countersign_refused` is a performing party refusing to issue its
half. That is not the absence of a `countersign/v1` entry, which SRC-B reports as
`not_countersigned`. **Classification: plugin-local.** Where the signer is the counterparty, it
can also issue a BA-ACK, but the BA-ACK does not replace the entry.

### 5.2 Cadence: not without loss

Cadence is not a statement about an exchange, so it maps to no BA object. It is how one party
publishes its own logs to a witness. Its nearest BA object is BA-REG. Forcing it into BA-REG
loses the property cadence exists for. Cadence publishes one entry per tick on the clock alone,
over a fixed-depth tree with a filler leaf and salted leaves at random positions, so a witness
learns neither how many exchanges there are nor when each happened. BA-REG registers each
attestation itself, which reveals that volume and timing. BA's Privacy Considerations name this
correlation risk and leave its mitigations TBD. **Classification: plugin-local.** It is
compatible with BA, because it registers checkpoints that cover the records, and it is a
candidate input to BA's open mitigation.

### 5.3 Intent: no slot in BA; an optional reference is enough

BA has no member for intent. Its nearest text is informative: a request attestation "may
reference the delegation receipt authorizing the requesting agent". SRC-B's intent is the user's
request and limits, sealed by one side for its own agent, and SRC-A emits none.

§3 rule 4 is met without any new member. A producer that emits intent cites it from its own
records with an AAC `references[]` entry, by digest. That entry sits outside SR's `settlement`
member, so it leaves that member's closed list alone. A producer with no intent omits the entry,
and nothing else changes. Which registered `citation_purpose` that entry carries is open (O1).
A BA slot is needed only when BA fixes its wire encodings, and then only as an optional
reference on BA-REQ.

### 5.4 Negotiation trail: plugin-local as sealed today

Read as BA, a trail would be a sequence of exchanges: each offer a BA-REQ from one party, and
each acceptance or counter the other party's BA-ACT. As SRC-B seals it, the trail is one party's
record of both sides' moves. The offers are the seller's own checks, which name the buyer only
by keyed fingerprints and carry no validity window. The acceptance is an observation of the
buyer's words, and the buyer signs nothing. BA also has no state for a request that its own
requester superseded. Its asymmetry dispositions cover requests that were not delivered, that
lapsed after delivery, or that the performer refused to answer, so an unanswered superseded
offer has no BA reading. **Classification: plugin-local, optional.** A trail would become a
sequence of BA exchanges only if both parties signed their own moves.

### 5.5 The agreed terms verify without the trail, in SR's form only

The SR terms leg is self-contained: an amount, and optionally a deliverable, payment reference
and validity, in one Capsule. That the terms were agreed is shown by the other side's leg citing
them (`terms_ref`), not by any trail. SR: "A terms leg that no counterparty leg cites is one
party's statement of the terms, not an agreement on them." In that form, §3 rule 3 holds.

SRC-B's own record of agreement does not hold rule 3. A seller's commit is defined against the
trail: it cites the acceptance it rests on, and it is refused unless its terms equal the accepted
offer's. A DR half commits terms only on a `received` close. So SRC-B's plugin-local records
cannot carry the agreed terms of the shared record. Only an SR terms leg, cited by the other
side's leg, can.

SRC-A meets rule 3, with one gap. When its host does not report the credited amount and fee, no
payee leg is sealed, and its terms leg stays one party's statement.

### 5.6 Required core: not yet sealed by both producers

| Core part | SRC-A | SRC-B, user sells | SRC-B, user buys |
|---|---|---|---|
| agreed terms (SR terms) | sealed (by the payer) | the buyer's, consumed and cited | not sealed |
| payer's observation | sealed | the buyer's; not sealed | not sealed |
| payee's observation | sealed (`ln.payment_hash`) when the host reports credited amount and fee | sealed (`x402.transaction`) | the seller's |
| delivered | sealed, `received` | sealed, `sent` | not sealed (`outcome` only) |

Where SRC-B's user is the payee, it seals SR's legs for its side. Where its user buys, it seals
none of SR's legs. A buyer's side of the core would need three legs: terms, payer-observed and
delivered `received`. Both producers already use SR's legs unchanged, so the core needs no
second format, only those legs.

## 6. Open points

- **O1.** The `citation_purpose` for an optional intent reference (§5.3). The nearest registered
  value is `ran_under` ("executed under the runtime environment and authority the cited record
  states"), but a leg's Capsule records an observation, not an executed action. Not decided
  here.
- **O2.** Whether SRC-B's evaluation records (B5) should meet BA's completeness rule, and carry a
  BA-RAI marker (B18), if they are to be carried as a BA-ACT. Not decided here.
