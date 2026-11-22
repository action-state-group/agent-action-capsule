# Exchange Records onto Bilateral Attestation: a Mapping — v0

**Status.** Informational, pre-Internet-Draft, kept in this repository. It changes no
Internet-Draft, defines no record format, registers nothing and names nothing new. It maps the
records two existing producers seal for a two-party exchange onto the objects of
`draft-mih-agent-bilateral-attestation-03` (cited here as BA). One producer seals two versions of
its deal record profile, and both are mapped. Each record falls into one of three kinds. It is
defined by `draft-mih-agent-settlement-records-01` (SR), and this document follows SR without
restating or changing it. Or it is an acceptance record of this repository's interop profile
(IP). Or it is **plugin-local**. For every record the nearest BA object is named, with what the
record lacks to be one.

## Dependency boundary

**Uses unchanged:**

| Tag | Document | What this document takes from it |
|---|---|---|
| BA | `spec/draft-mih-agent-bilateral-attestation-03.md` | the four exchange objects, the constraint-record obligations, the asymmetry dispositions, the reduced-assurance indicator, the delivery intermediary, registration |
| SR | `spec/draft-mih-agent-settlement-records-01.md` | the four legs, the `settlement` member, the derived states, and its statement that "The settlement legs are not the bilateral exchange's objects; a deployment can use both, with an action attestation citing a terms leg". SR -01 leaves the `settlement` member's wire as -00 had it (`version` `"0"`, its Changes from -00), so a leg a producer seals under -00 reads the same under -01. SR cites BA -02. The BA text SR's statement relies on, the four exchange objects, is editorially unchanged in -03. This document also relies on text that is new in -03: the definition of "countersign" and the delivery intermediary, which replaces -02's relay and registers with a Transparency Service. -03 also drops -02's section on retention and the decay of the bilateral property. |
| IP | `spec/interop-profile-v0.md` | the acceptance record, its acceptance receipt and its statement that neither an acknowledgment nor a BA action attestation is an acceptance (§11.1, §11.1.6) |
| AAC | `spec/draft-mih-scitt-agent-action-capsule-06.md` | `verdict_class`, `references[]` |
| EB | `spec/draft-mih-zhang-agent-disclosure-bundle-03.md` | the `parent-log-witness/v1` extension kind, its checks and findings, and its Security and Privacy Considerations ("The parent-log-witness/v1 Extension"). It is on this repository's `main`, added at commit `3c808e2` and read at `5a2bc703d10d1cfffc315f45ba32f49d294ead84`, with its verifier `go/bundle/parent_witness.go` |
| REG | `spec/REGISTRY.md` | `citation_purpose` (§11) |
| DR | `spec/deal-reconcile-contract-v0.md` | the half, its field commitments, the reconcile |

**Does not define:** any record, member, name or registry entry; what either producer should
change; any judgment over an exchange.

## 1. Sources

Each row is read from source at the commit named.

| Tag | What | Pinned at |
|---|---|---|
| SRC-A | A compute-exchange plugin: the settlement legs it seals for a paid exchange (one terms leg per invoice), the session agreement its legs cite, and the payment lifecycle records it seals | release tag `v0.1.23`, commit `54420bc602e8520e7eb061480575d5787d7d4a54` |
| SRC-B | A marketplace plugin's deal record profile in its two versions: v0 (a closed set of twenty-four record types, per its schema's enum, its typed action records, its settlement notes, its reconcile of two closes and its countersign rung) and v1 (ten record types of its own and sixteen overlay types, per its schema's enum, its sent pairs and its sealed deal report) | commit `546cc0966548de1d32fe942b74151d5805c994bd` |
| SRC-C | The core the marketplace plugin builds on: the `countersign/v1` entry, the cadence tree and the verifier of its chain, the settlement-leg builders | commit `47afa723095141e916dc79591795d348278d0af2` |

The earlier revision of this mapping read SRC-A at release `v0.1.4`, and SRC-B v0 at another
location, where its enum had twenty types. §4.1 and §4.2 are re-read at the pins above. Four v0
types are new since then (B30 to B33).

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

Fit is one of three. **SR** means the record is defined by SR, so it is not a BA object (SR's
statement, quoted above). **IP** means it is an interop-profile acceptance record, which IP defines apart
from BA's objects (IP §11.1, §11.1.6). **plugin-local** means none of BA, SR or IP defines it. No record
either producer seals today is a BA object. The "Nearest BA object" column names what each record
comes closest to, and "Lacks" names what keeps it from being one.

### 4.1 SRC-A: the compute-exchange plugin's records

| # | Record (sealer) | What it carries at SRC-A | Fit | Nearest BA object | Lacks | Shared record |
|---|---|---|---|---|---|---|
| A1 | terms leg (payer) | One per invoice: a deposit invoice, a final invoice, both or neither. `amount` (the invoice amount, `BTC`, `assetScale` 11), `payment_ref` (`ln.payment_hash`). It is pushed to the provider over a record-push binding. A leg not known to have reached the provider under a checkpoint is pushed again, once, under a checkpoint that covers it. | SR: terms | none. In SR's model a BA-ACT may cite it. | — | required: agreed terms |
| A2 | payer-observed (payer) | `terms_ref`, `amount` (the wallet transaction's own amount), `payment_ref`, `status` `settled`, `observed_at` (coarsened to the minute), `routing_fee` when the host reports it | SR: payer_observed | none | BA has no object for either party's observation of the payment. | required: payer's observation |
| A3 | payee-observed (payee) | `terms_ref` (the first pushed terms leg for one of the provider's own invoices at that invoice's amount), `received`, `receive_fee`, `payment_ref`, `status` `settled`, `observed_at`. Sealed only when the host reports both the credited amount and the fee. When the exchange ran under a session agreement (A8) whose proposer's key signed the terms leg, and exactly one session names the model served, the leg carries a plugin-local extension block that cites the agreement's acceptance by digest. No `references[]`, so no `counterparty_half` citation of the payer's leg. | SR: payee_observed | none | As A2. | required: payee's observation |
| A4 | delivered, direction `received` (payer) | `terms_ref` (the final invoice's terms leg, or the deposit's when the deposit covered the bill), `observed_at`, `delivery.content_digest` (the exchange's response digest). Sealed once the host reports the bill accounted. An exchange with no invoice has no terms leg and gets no delivered leg. It carries the same agreement citation block as A3, when the exchange has an agreement. | SR: delivered | BA-ACK by the requester | It is an observation of delivered content. A BA-ACK acknowledges an attestation and has no content-digest member. | required: delivered |
| A5 | delivered, direction `sent` | not sealed at SRC-A: the provider's exchange events are not joined to its payment events | — | BA-ACT (`executed`) | — | required: delivered (the other direction serves) |
| A6 | intent | none emitted | — | — | — | optional; omitted |
| A7 | negotiation trail | none emitted beyond the session agreement (A8). The requester never accepts a provider's counter. | — | — | — | optional; omitted |
| A8 | session agreement: `proposed` (requester), `accepted` (provider; or `declined` or `countered`, which the requester never accepts), and the acceptance receipt the requester signs | One acceptance per bounded paid session with a provider. The proposal names the session's evidence contract, its model policy and its terms (spend cap, unit, payment reference type, optionally a count), each a digested document carried beside it. The records are checked with the profile's own verifier. The spend terms are the agent's assertion, and no record carries `authority`. | IP: acceptance record (§11.1) and acceptance receipt (§11.1.4) | none for the records; BA-ACK for the receipt | IP calls the receipt an acknowledgment (§11.1.4), but it acknowledges an acceptance record, not a BA attestation. IP §11.1.6: an acknowledgment, which the receipt is, "records receipt only", and "A BA action attestation records how a request was handled [BA §3]. It is not an acceptance either". The parties are identified by key identifiers, not by verifiable organizational identity. | optional: trail (as agreement) |
| A9 | payment lifecycle settlement records (payer and provider sides) | One record per host payment lifecycle event, sealed verbatim, each naming the side that observed it and who asserted each value (payer, the provider's invoice, or the wallet) | plugin-local | none | They are the host's events, not either party's statement about the exchange. No records means no lifecycle was observed, never unpaid. | — |

### 4.2 SRC-B v0: the marketplace plugin's v0 records

Every value of SRC-B v0's `record_type` enum and every typed record of its §9 appears at least once.

| # | Record | What it is | Fit | Nearest BA object | Lacks | Shared record |
|---|---|---|---|---|---|---|
| B1 | `baseline` (open) | First contact: the request, pre-agreement terms, `recourse`, `channel`, and counterparty identifiers as per-deal keyed fingerprints | plugin-local | BA-REQ | Not addressed or signed to the counterparty. It names the counterparty by keyed fingerprints, not by a verifiable organizational identity. It has no validity window, and its terms are first-contact terms, not agreed ones. | its intent: optional (B3) |
| B2 | shared `deal_id`, two-party open (open) | Both parties' steps carry one opaque `deal_id`, and a composition joins their copies on it, or derives `unjoined` | plugin-local | BA-ASYM correlation identifier | No shared action digest and no asymmetry disposition. `unjoined` is the nearest thing SRC-B has to BA's orphan. | — |
| B3 | `intent`, the baseline's `intent`, `task-authority/v0` (intent) | The user's request and limits, by commitment. The task authority is re-sealed when the user confirms new limits. | plugin-local | none (§5.3) | — | optional |
| B4 | `check`, typed `proposed-action/v0` (check) | The exact act about to be taken, before a point of no return | plugin-local | BA-ACT, the evaluated input | `proposed_action_digest` covers the proposed action only. The evaluator also reads the ruleset, task authority, history and platform approvals (the check request), so this is a subset of BA's input commitment. The evaluator is the acting party's own agent checking against its user's authority; the counterparty sends no request. | — |
| B5 | `verdict`, typed `action-evaluation/v0` (check) | Disposition `DO`, `ASK` or `DENY`, with findings | plugin-local | BA-ACT, constraint record and disposition | `ruleset_digest` pins the constraint set (meets BA's MUST). `findings` lists differences only, never a passing rule, and `rules_checks` gives one verdict per ruleset, so BA's result for every constraint (MUST) is not met. It has no request-attestation digest and no verifiable organizational identity. It carries no `verdict_class`; a proposed reading (not stated by any source) is `DENY` as `denied` or `blocked`, `ASK` as `hitl_dispatched` or `needs_decision`, and `DO` as no terminal class until the following action. | — |
| B6 | `approval`, typed `action-approval/v0` with `user_approval`, `card_answer`, `policy_change`, `platform_approval`, or `one_shot_override` (reserved, refused) (check) | The authority for the next step | plugin-local | none | Authority between a user and its own agent. BA mentions this layer only informatively: a request attestation "may reference the delegation receipt authorizing the requesting agent". | — |
| B7 | typed `check-request/v0`, `check-response/v0`; the external rules checker's `external-check-input/v0` and `external-check-result/v0`; the `commercial-bounds/v0` document a baseline or intent cites (check) | The shapes an evaluator takes and returns, sealed or not, and a bounds document cited by digest | plugin-local | none | — | — |
| B8 | countersign: a `countersign/v1` entry on a deal's Evidence Bundle (SRC-B rung, SRC-C entry) | A signature over one bundle's digest, with `statement.checks`, `recomputed_at`, `scope` | plugin-local | BA-ACK | §5.1 | — |
| B9 | `close` (close) | The deal's end, its outcome, `actor` and `reason` | plugin-local | none | — | — |
| B10 | DR half: a final close's `amount` and `currency` commitments (close) | Only a final close with status `received` commits non-empty terms: the delivered price and currency, or the agreed ones where the close names none. Every other close commits the empty text. DR reconciles the two parties' halves. | plugin-local | none | Two independent self-records reconciled by a verifier, like SR's derived state. Neither half is a BA object, and neither is an SR terms leg. | — |
| B11 | cadence: one cadence-log entry per tick, and the `x-cadence-witness/v0` bundle extension that carries a deal checkpoint's chain to it (written by SRC-B, verified by SRC-C) | A fixed-depth tree over each deal's checkpoint plus a filler leaf, published to a witness on the clock alone | plugin-local | BA-REG. Its chain's nearest kind is EB `parent-log-witness/v1`, which it matches link for link (§5.2) | As EB `parent-log-witness/v1`: the registered name; the parent-log members under `parent`, not `cadence`; `earlier` read by its presence, not by `extent`. It adds `state` (and the not-yet-witnessed states that ride in the same member), `extent`, `checkpoint_at`, the deal's `steps_witnessed`, `steps` and `rest`, and a path fixed at 16 hashes (§5.2) | its chain: EB `parent-log-witness/v1` (§5.2) |
| B12 | `sale` (sale) | The root of a seller's sale to one of several buyers | plugin-local | none | BA has one requester and one performer per exchange. Each buyer's thread is a deal of its own, mapped by the other rows. | — |
| B13 | `thread`, `thread_opened` (sale) | Registration and opening of one buyer's thread on the sale's log | plugin-local | none | — | — |
| B14 | `sale_cut`, `sale_close` (sale) | The cut a sale bundle is made at; the end of the sale | plugin-local | none | — | — |
| B15 | `check` with `action: offer`, its `supersedes` chain, the offer `action` (negotiation) | A seller's exact proposal; each later offer supersedes the latest earlier one | plugin-local | BA-REQ | §5.4 | optional: trail |
| B16 | counterparty acceptance observation, typed `action-approval/v0` (negotiation) | That the counterparty accepted the latest offer, its words by commitment | plugin-local | BA-ACT by the counterparty | Observed and sealed by one side; the counterparty signs nothing (§5.4). | optional: trail |
| B17 | `message` (negotiation) | One message in the thread, its text by commitment | plugin-local | none | — | optional: trail |
| B18 | `action`, typed `action-record/v0`, including an approved disclosure (`disclosed`) | A point-of-no-return act taken, with its authority basis | plugin-local | BA-ACT, unilateral, at reduced assurance | No request-attestation digest (the counterparty sent none). No BA-RAI marker, which BA requires on a unilateral record. Constraint completeness as B5. No verifiable organizational identity. | — |
| B19 | `outcome`, typed `action-outcome/v0` | What was observed afterwards | plugin-local | none | It overlaps SR's delivered leg in meaning but is not one. | — |
| B20 | `evidence` carrying a `settlement` member: payment received (seller) | SR payee-observed leg, `payment_ref` `x402.transaction` or `ln.payment_hash` (the record then may carry the payment's `preimage`), answering the buyer's terms leg by `terms_ref` | SR: payee_observed | none | As A2. | required: payee's observation |
| B21 | `evidence` carrying a `settlement` member: delivered (seller) | SR delivered leg, direction `sent`, a content digest or the carrier fields | SR: delivered | BA-ACT effect | An SR leg is an observation and carries no constraint results or disposition. | required: delivered |
| B22 | `evidence`, other uses | A claim's evidence, a merchant's signed email, a held object by digest (`wrapped`, in SR's shape) | plugin-local | none | — | — |
| B23 | `claim` | An assertion (the counterparty's, the listing's or the agent's), recorded as a claim, by commitment | plugin-local | none | — | — |
| B24 | `agent_move` | The agent's search, options, recommendation, choice or failure | plugin-local | none | — | — |
| B25 | `detail_change` | The counterparty changed an identifier, a term or the rail | plugin-local | none | — | — |
| B26 | `disclosure` (authority `none`, or any untyped disclosure) | What the agent told someone about the user, by class and commitment. An approved disclosure in a typed deal is B18. | plugin-local | none | — | — |
| B27 | `counterparty_profile` | The payee fingerprinted under a profile key; never shared | plugin-local | none | — | — |
| B28 | sealed report, standalone report; typed `action-report/v0` (reserved) | A copy's readable text, sealed; not a step | plugin-local | none | — | — |
| B29 | terms Result on the deal's results book | The DR Result a party computes and seals | plugin-local | none | — | — |
| B30 | `sale_unpost` (sale) | On a sale's own log, a listing taken down from one platform, citing the live post it ends. It needs no check, evaluation or approval. | plugin-local | none | — | — |
| B31 | `rules_verdict` (close) | The party's own overall rules word for the deal (`met`, `not_met`, `unknown` or `out_of_scope`) under the pack its `pack_digest` names. At most one per deal, sealed once, after the final close. | plugin-local | BA-ACT disposition | `pack_digest` pins the rules the word is under, but the word is one result for the whole deal, not a result for every constraint. It cites the party's own close, not a request attestation, and carries no `verdict_class`. | — |
| B32 | `claim_authority` (sale) | Where the user sells, the seller's own verdict on its agent's claim: what authorized it, or that nothing did, citing the claim right before it | plugin-local | none | Authority between a user and its own agent, as B6. | — |
| B33 | `outcome_note` (close) | Temporary, by the profile's own text: the book owner's own note that the deal did not hold against the owner, with a `reason`. It is never checked against a ruling or the other side. The producer's share path leaves it out of every shared copy (a producer rule, not a check of the profile). | plugin-local | BA-RAI | It is not a marker of missing attestations. It is the owner's statement of its own failure, and no counterparty sees it. | — |

SRC-B v0 seals no payer-observed leg and no delivered leg in direction `received`. A buyer
writes its terms leg as a signed Capsule file, apart from any deal book. The seller's payment
received and delivered notes name that file and never restate it. SRC-C's settlement package
exports builders for the payee-observed leg (x402) and the delivered leg (direction `sent`) only;
SRC-B builds its Lightning payee-observed leg itself.

### 4.3 SRC-B v1: the marketplace plugin's v1 records

Every value of SRC-B v1's `record_type` enum appears at least once. A v1 record is never a v0 record: a
book has the version of its first record, and a deal has one version on both sides. The v1
overlay types keep v0's bodies, so their rows point to the v0 row.

| # | Record (where sealed) | What it is | Fit | Nearest BA object | Lacks | Shared record |
|---|---|---|---|---|---|---|
| V1 | `propose` (offerer's journal; sent whole) | An offer or counter-offer: `role`, `to` (the key the offer is addressed to, or none for a counterparty with no layer), `counter_to`, `terms`, `terms_rows`, `agree_by`, `adjudicator`, `forums`, `witnesses`. Sent whole as a standalone signed Capsule whose payload is the record. | plugin-local | BA-REQ | It is addressed by key (or to no key, for a counterparty with no layer) and signed by the offerer, and `agree_by` bounds when it can be agreed. But it names both parties by key, not by verifiable organizational identity. It carries no nonce member (`deal_id` is random but names the deal, not one request, and a counter-offer cites the offer it counters). Its terms are offered, not requested as an action. | optional: trail |
| V2 | `settlement` member on an offer's sent Capsule | Present exactly when the offer's terms have one payment row: `{"version": "0", "leg": "terms", "sealer_role", "amount"}`, the row's owed amount. No other sent record carries a `settlement` member. | SR: terms | none. In SR's model a BA-ACT may cite it. | — | required: agreed terms |
| V3 | `agree`, kind `agreement` (each party's deal book, `seq` 1) | Each side seals its own agreement, citing the offer's record digest and the digest of its terms rows. The acceptor's comes first; with a counterparty that runs a layer, the offerer's names the acceptor's agreement it holds, in `seen`. | plugin-local | none (§5.7) | It is closest in purpose to an IP acceptance, but it is not one: IP's acceptance is the acceptor's alone, and here both sides seal one. Read as BA, the acceptor's is no BA-ACT: it carries no constraint result and no disposition. The offerer's naming of the acceptor's agreement is not a BA-ACK: a BA-ACK asserts receipt only, and the agreement asserts agreement. | required: agreed terms (by citing V2's offer) |
| V4 | `agree`, kind `decline` (journal; sent whole) | The answer refusing an offer, signed by the key the offer was sent `to`, with an optional `reason` (`not_selected` or `other`) and a committed free-text reason | plugin-local | BA-ACT with a decline disposition | BA reads a declined request as a completed exchange whose action attestation records the decline and its constraint basis, and keeps it apart from `countersign_refused`. A decline cites the offer by digest, as a BA-ACT cites its request, but carries no constraint results, no `verdict_class` and no organizational identity. A `not_selected` decline (one buyer chosen from several) is closer to BA's party that declines to engage, as with B12. | optional: trail |
| V5 | `agree`, kind `cancellation` (journal; sent whole) | The offerer withdrawing its offer, signed by the offer's signer | plugin-local | none | BA has no state for a request its own requester withdrew (§5.4). | optional: trail |
| V6 | `perform` (deal book) | A delivery or other act, or a remedy that is not a payment: `act`, `observed`, a detail commitment, the author's statements on the agreed rows, the journal `check` it rests on | plugin-local | BA-ACT (`executed`) | Its statements are the author's own `met`, `not_met` or `cannot_tell` on the rows it names, not a result for every constraint in a pinned set. It cites the author's own agreement (`agreement_ref`), not a request attestation, and its `check` is in the author's own journal. No `verdict_class`. SRC-B v1 names no `settlement` member for it, so it is no SR delivered leg (§5.6). | — |
| V7 | `settle`, leg `payer` (deal book) | A payment, carrying its SR payer-observed leg as the Capsule's `settlement` member, with `terms_ref` set to the offer's sent Capsule. The body adds statements, the `check` it rests on (required), `supersedes`, `reverses`, `remedy_for`. | SR: payer_observed (the member); plugin-local (the body) | none | As A2. A refund (`reverses`) or a remedy that is a payment has no SR terms leg of its own, so the payment check is not run over it. | required: payer's observation |
| V8 | `settle`, leg `payee` (deal book) | A payment received, carrying its SR payee-observed leg (`received`, `receive_fee`, required), with the same body members as V7, `check` optional | SR: payee_observed (the member); plugin-local (the body) | none | As A2. | required: payee's observation |
| V9 | `statement` (deal book) | Statements with no act, or a record naming one arrived cancellation or ruling | plugin-local | BA-ACK, when it names an arrived record | A BA-ACK acknowledges the counterparty's attestation. A statement names a counterparty's cancellation or a third party's ruling, and may state values on rows, which a BA-ACK does not. | — |
| V10 | `dispute`, kind `dispute`, `withdrawal` or `challenge` (deal book) | A dispute of one row before the agreement's adjudicator and one of its forums; its withdrawal; a challenge of a ruling | plugin-local | none | BA has no dispute and no adjudicator. | — |
| V11 | `ruling` (the adjudicator's case book) | The adjudicator's ruling on one row: `value`, `against`, an optional `remedy`, and per side the last record it read | plugin-local | none | BA defines no signer besides the two parties that rules on an exchange. | — |
| V12 | `ask`, `answer` (journal, or the deal book between the two parties) | An evidence request and its outcome (`evidence`, `refusal` or `absence`), each citing a request or answer document by digest | plugin-local | none | The documents they wrap belong to an evidence-request format this mapping does not cover. BA has no request for evidence about an exchange. | — |
| V13 | `admit` (journal) | The holder's admission decision on a counterparty (`GO`, `ASK` or `LIMIT`) at a tier of an admission pack, with the card it read by digest. Never sent; an agreement cites it. | plugin-local | none | It is one party's own decision about whom to deal with, before any request. | — |
| V14 | `intent` (journal overlay) | v0's body, with its required verbatim commitment | plugin-local | none (§5.3) | As B3. | optional |
| V15 | `check` (journal overlay) | v0's untyped check body (the `action` and the facts the check reads), plus `payment_ref` and `nonce` | plugin-local | BA-ACT, the evaluated input | It carries the proposed act itself, with no digest of it and no commitment over the other inputs the check consults. The checker is the acting party's own agent, as in B4. | — |
| V16 | `verdict` (journal overlay) | v0's untyped verdict body (`result` `pass`, `pause` or `deny`, the differences found, the rules the pinned checker reported), plus `nonce`, citing exactly one check | plugin-local | BA-ACT, constraint record and disposition | `rules`, when the pinned checker ran, names the ruleset by id and definition digest. `differences` lists differences only, so there is no result for every constraint. No request-attestation digest, no `verdict_class`. | — |
| V17 | `approval` (journal overlay) | v0's body, plus `nonce`, naming the verdict it answers, or on `confirm_limits` the intent. When the approval is the person's own (`user`, `agent_card`), and for each `confirm_limits` a `standing_intent` approval relies on, the person's signature over it travels beside the record. | plugin-local | none | As B6. | — |
| V18 | `rules_verdict` (deal-book overlay) | v0's body, sealed once the holder computes the deal settled, at most one per deal | plugin-local | BA-ACT disposition | As B31, except that it follows the computed settlement, not a close. | — |
| V19 | `message`, `claim`, `evidence`, `detail_change`, `agent_move` (journey overlay) | v0's bodies, in the journal only | plugin-local | as B17, B23, B22, B25, B24 | As those rows. SRC-B v1 names a `settlement` member only on V2, V7 and V8, and none for a journal `evidence`. | optional: trail (`message`) |
| V20 | `disclosure`, `sale`, `thread`, `thread_opened`, `sale_unpost`, `counterparty_profile` (journey overlay) | v0's bodies, in the journal only | plugin-local | as B26, B12, B13, B30, B27 | As those rows. | — |
| V21 | the sealed deal report and its bundle extension | A standalone signed snapshot of each row's status as the holder computed it, with the records it relied on carried beside it. Not a record type: appended to no book and cited by no record. | plugin-local | none | — | — |

v0's `baseline`, `action`, `close`, `outcome`, `outcome_note`, `sale_cut` and `sale_close` have no
v1 counterpart (SRC-B v1 §4). A v1 book opens with its agreement, an act is a `perform` or
`settle`, and a deal is settled by computation, with no close.

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
  `self_countersigned`, `unresolved_signer`, `unverified`, `unchecked` and `not_countersigned`; SRC-C's verify
  step reports its own results. BA has no counterpart.

The word also collides: BA's `countersign_refused` is a performing party refusing to issue its
half. That is not the absence of a `countersign/v1` entry, which SRC-B reports as
`not_countersigned`. **Classification: plugin-local.** Where the signer is the counterparty, it
can also issue a BA-ACK, but the BA-ACK does not replace the entry.

### 5.2 Cadence: not without loss onto BA; link for link onto EB parent-log-witness/v1

**Onto BA.** Cadence is not a statement about an exchange, so it maps to no BA object. It is how
one party publishes its own logs to a witness. Its nearest BA object is BA-REG. Forcing it into
BA-REG loses the property cadence exists for. Cadence publishes one entry per tick on the clock
alone, over a fixed-depth tree with a filler leaf and salted leaves at random positions, so a
witness learns neither how many exchanges there are nor when each happened. BA-REG registers each
attestation itself, which reveals that volume and timing. BA's Privacy Considerations name this
correlation risk and leave its mitigations TBD. **Classification: plugin-local.** It is
compatible with BA, because it registers checkpoints that cover the records, and it is a
candidate input to BA's open mitigation.

**Onto EB.** The chain a cadence bundle carries is EB's `parent-log-witness/v1`: the cadence log
is EB's parent log, a tick's tree is EB's tree, and a deal's checkpoint is the covered
checkpoint. Read at the pins, the cryptography is the same in every link:

- **Leaf.** SHA-256 of 0x00 and the JCS of `checkpoint_sha256`, `log_id`, `salt` and `size`, in
  both.
- **Node and fold.** SHA-256 of 0x01, left, right. The root is folded from the leaf by the bits
  of `index` in the same order.
- **Parent entry.** The root is the 32-octet value of the parent log's entry, proved by a CLL
  inclusion proof under the parent checkpoint. SRC-C passes the root as hex to CLL's hex form of
  the same check.
- **Earlier checkpoint.** It is signed by the same key and has the same log identifier and a
  smaller MMR size, with a CLL consistency proof to the Bundle's checkpoint.
- **Signer and receipts.** The parent checkpoint is signed by the key of the Bundle's checkpoint.
  Its receipts are CLL witness records (`ts_url`, `entry_hash`, `receipt_b64`, `leaf_index`,
  `tree_size`), the form EB's verifier reads.
- **Salt.** SRC-B draws a fresh 32-octet salt per leaf, which meets EB's SHOULD of at least 256
  bits.
- **Filler and empty leaves.** SRC-B's filler leaf (0x03) and empty leaf (0x02) appear to a
  verifier only as sibling hashes on a path. EB defines neither and never inspects them.

The two differ in these fields and rules.

| Point | `x-cadence-witness/v0` (SRC-B writes, SRC-C verifies) | EB `parent-log-witness/v1` | Gap |
|---|---|---|---|
| Name | a private `x-` kind; bundles before it used `cadence-witness/v0` and `x-deal-cadence-v0`, which SRC-C still reads | a registered kind (`spec/REGISTRY.md`) | cadence lacks the registered name |
| Parent-log members | under `cadence`: `log_id`, `checkpoint.cose`, `entry_index`, `inclusion_proof`, `witnesses` | the same five under `parent` | cadence lacks `parent`. The contents are the same, only the member name differs |
| Earlier checkpoint | checked only when `extent` is `"part"`; an `earlier` beside `"all"` is not checked | checked whenever `earlier` is present | cadence lacks presence as the trigger. A cadence block with `extent` `"part"` and no `earlier` fails in SRC-C. EB checks its leaf against the Bundle's own checkpoint, and it fails `parent_witness_leaf_does_not_name_this_checkpoint` |
| `state` | `"witnessed"`, and the same member carries a not-yet-witnessed chain as `"pending"` (with `tick`, `reason`, `text`, `cadence`), `"scheduled"`, `"unverified"` or `"not_configured"`. SRC-C checks the chain only when `state` is `"witnessed"` | not defined. EB has no not-yet-witnessed block: the block is absent, or its receipts are absent and the result is withheld | cadence adds `state`. Under EB, a member EB does not define is ignored, so a pending block would be checked as a chain and fail with `parent_witness_leaf_does_not_name_this_checkpoint` |
| `extent` | stated by the producer, `"all"` or `"part"`; SRC-B's own reports read it | MUST be computed by the verifier from the verified checkpoints, as two entry counts, and MUST NOT be read from the block | cadence adds a stated `extent`. EB ignores it |
| Step counts | `steps_witnessed`, `steps` and `rest` (the not-yet-witnessed remainder), added by SRC-B's deal session | none; the extent is entries, not steps | cadence adds them. EB ignores them |
| `checkpoint_at` | the tick's time | none | cadence adds it. EB ignores it |
| Path length | exactly 16 hashes; `index` below 2^16 | 0 to 32 hashes; `index` below 2 to the power of the path length. EB SHOULDs one length for every tree | cadence's 16 is within EB's range. An EB block with any other length fails `cadence_path_malformed` in SRC-C |
| Integers | read by SRC-C's `JSONUint`, which takes an integral `1.0` when the bundle is decoded to floating point | JSON integers only: `true` and `1.0` are not `1` | cadence can be laxer |
| Pre-rename log identifier | `deal_log_id` still read where `log_id` is absent | not defined | cadence adds a legacy reader |
| Findings | `cadence_` names, and `cadence_earlier_checkpoint_not_this_deal` | `parent_witness_` names, and `parent_witness_earlier_checkpoint_not_this_log` | the names differ but the steps are the same. SRC-C checks `index` and `salt` before the path, and EB the path first. EB also fails a non-object block (`parent_witness_malformed`), which SRC-C reads as no claim |
| Publication discipline | one entry per tick on the clock, a filler leaf, random positions, one fixed depth | not required. EB's Privacy Considerations SHOULD a fresh 256-bit salt and one path length, and say what a witness of the parent log sees | cadence adds the clock and the filler. EB does not need them to verify |

**What this means for the core.** Because every link matches, a cadence chain can be re-carried
as `parent-log-witness/v1` without new cryptography and without re-witnessing. The re-carried
block moves the five members from `cadence` to `parent`, carries `earlier` only when the
covered checkpoint is earlier, and leaves `state`, `extent`, the step counts and
`checkpoint_at` out or as members EB ignores. A core that verifies `parent-log-witness/v1` in
place of its own cadence check reads such a block unchanged. It does not read a bundle sealed
under `x-cadence-witness/v0` or an earlier name until that bundle is re-carried. Re-carrying
changes the Bundle, and so its bundle digest: a countersignature over the old digest does not
carry to the new one. It reports no
not-yet-witnessed state, and it reports extent as entries, not steps. SRC-B's own reports read
the stated `extent` and the step counts, so they stay plugin-side. **Classification of the
chain: EB `parent-log-witness/v1`**, once re-carried. The tick schedule and the filler stay
plugin-local.

### 5.3 Intent: no slot in BA; an optional reference is enough

BA has no member for intent. Its nearest text is informative: a request attestation "may
reference the delegation receipt authorizing the requesting agent". SRC-B's intent is the user's
request and limits, sealed by one side for its own agent, in v0 and in v1 alike. SRC-A emits
none.

§3 rule 4 is met without any new member. A producer that emits intent cites it from its own
records with an AAC `references[]` entry, by digest. That entry sits outside SR's `settlement`
member, so it leaves that member's closed list alone. A producer with no intent omits the entry,
and nothing else changes. Which registered `citation_purpose` that entry carries is open (O1).
A BA slot is needed only when BA fixes its wire encodings, and then only as an optional
reference on BA-REQ. SRC-B v1 keeps intent in the holder's journal, and an agreement names it
only by digest (`intent`), so v1 already follows this shape inside its own records.

### 5.4 Negotiation trail: plugin-local, in both versions

Read as BA, a trail would be a sequence of exchanges: each offer a BA-REQ from one party, and
each acceptance or counter the other party's BA-ACT.

As SRC-B v0 seals it, the trail is one party's record of both sides' moves. The offers are the
seller's own checks, which name the buyer only by keyed fingerprints and carry no validity
window. The acceptance is an observation of the buyer's words, and the buyer signs nothing.

SRC-B v1 closes most of that gap. Each offer and counter-offer is the offerer's own signed
record, sent whole and addressed by key (or to no key, for a counterparty with no layer). Each party seals its own agreement, and a decline is
signed by the party that declines. What still keeps a v1 trail from being a sequence of BA
exchanges is what V1, V3 and V4 lack: identity by key rather than by organization, no nonce, and
no constraint results on the answer (a decline gives a disposition-like answer; an agreement
gives none).

BA also has no state for a request that its own requester superseded or withdrew. Its asymmetry
dispositions cover requests that were not delivered, that lapsed after delivery, or that the
performer refused to answer. So an unanswered superseded offer (v0) and a cancellation (v1)
have no BA reading. **Classification: plugin-local, optional.**

### 5.5 The agreed terms verify without the trail, in SR's form only

The SR terms leg is self-contained: an amount, and optionally a deliverable, payment reference
and validity, in one Capsule. That the terms were agreed is shown by the other side's leg citing
them (`terms_ref`), not by any trail. SR: "A terms leg that no counterparty leg cites is one
party's statement of the terms, not an agreement on them." In that form, §3 rule 3 holds.

SRC-B v0's own record of agreement does not hold rule 3. A seller's commit is defined against
the trail: it cites the acceptance it rests on, and it is refused unless its terms equal the
accepted offer's. A DR half commits terms only on a `received` close. So those plugin-local
records cannot carry the agreed terms of the shared record. Only an SR terms leg, cited by the
other side's leg, can.

SRC-B v1 holds rule 3 for an offer with one payment row. The offer's sent Capsule carries the SR
terms leg (V2), and both parties' settle legs cite it by `terms_ref`. Its agreement records cite
the offer and its rows by digest, so they read the offer, but not any other step of the trail.
An offer with more than one payment row carries no terms leg. A refund or a remedy that is a
payment has no terms leg of its own. In those cases v1's agreed terms are plugin-local.

SRC-A meets rule 3, with one gap. When its host does not report the credited amount and fee, no
payee leg is sealed, and its terms leg stays one party's statement.

### 5.6 Required core: not yet sealed by both producers

| Core part | SRC-A | SRC-B v0, user sells | SRC-B v0, user buys | SRC-B v1 (either side) |
|---|---|---|---|---|
| agreed terms (SR terms) | sealed (by the payer), one per invoice | the buyer's, consumed and cited | sealed as a signed file, outside the deal book | sealed on the offer's sent Capsule, when the terms have one payment row |
| payer's observation | sealed | the buyer's; not sealed | not sealed | sealed (payer `settle`) |
| payee's observation | sealed (`ln.payment_hash`) when the host reports credited amount and fee | sealed (`x402.transaction` or `ln.payment_hash`) | the seller's | sealed (payee `settle`) |
| delivered | sealed, `received` | sealed, `sent` | not sealed (`outcome` only) | not sealed (`perform` only) |

Where SRC-B v0's user is the payee, it seals SR's legs for its side. Where its user buys, it
writes only the terms leg. SRC-B v1 seals three of the four legs on both sides, for an offer with
one payment row. It seals no delivered leg in either direction. A delivery is a `perform`, which
carries the author's statements on the rows, not an SR leg. So the shared core is complete only
at SRC-A, and SRC-A lacks the provider's `sent` direction. Both producers already use SR's legs
unchanged, so the core needs no second format, only the missing legs.

### 5.7 The v1 agreement pair is not a BA exchange

The two v1 agreements (V3) are the nearest either producer comes to a bilateral exchange. Each
side signs its own record, and each record cites the same offer by digest. With a
counterparty that runs a layer, the offerer's agreement names the acceptor's. A party's first
`perform` or payer `settle` is refused until it holds the
counterparty's stamp proof covering the counterparty's agreement, unless the counterparty runs no
layer (SRC-B v1 §8). BA-REG is the nearest BA notion to that gate.

It still maps to no BA object, for three reasons. BA's exchange is a request and an action, and
v1's pair agrees on terms before any action. BA's action attestation reports constraint results
and a disposition, and an agreement reports neither. IP already draws the line BA would need here:
an acceptance is neither an acknowledgment nor an action attestation (IP §11.1.6). The pair is
also not an IP acceptance, which is the acceptor's alone. **Classification: plugin-local.** Of
the three objects, an IP acceptance record is the nearest existing one.

## 6. Open points

- **O1.** The `citation_purpose` for an optional intent reference (§5.3). The nearest registered
  value is `ran_under` ("executed under the runtime environment and authority the cited record
  states"), but a leg's Capsule records an observation, not an executed action. Not decided
  here.
- **O2.** Whether SRC-B's evaluation records (B5, V16) should meet BA's completeness rule, and
  carry a BA-RAI marker (B18), if they are to be carried as a BA-ACT. Not decided here.
- **O3.** Whether an SR delivered leg should accompany a v1 `perform` that delivers, so that
  SRC-B v1 seals the whole core (§5.6). Not decided here.
- **O4.** For a core that verifies EB `parent-log-witness/v1` in place of its cadence check
  (§5.2): whether bundles already sealed under `x-cadence-witness/v0` and its earlier names are
  re-carried, read by a plugin-side verifier, or left unverified by the core; and where a
  not-yet-witnessed state is reported once the block holds only a witnessed chain. Not decided
  here.
