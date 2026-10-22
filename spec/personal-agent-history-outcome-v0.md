# Personal-Agent History Profile — Outcome level, v0

**Status.** Informational host profile level, pre-Internet-Draft, kept in this repository. It is
the level above the Basic level of the Personal-Agent History Profile
(`spec/personal-agent-history-profile-v0.md`, cited here as PH), which points here as PA-9. It
changes no Internet-Draft, no part of the Minimum Evidence Interoperability Profile
(`spec/interop-profile-v0.md`, cited as IP) and no part of the Basic level. Where it needs a rule
that neither states, it states the rule as its own and lists it under
[Open points](#14-open-points) (PO-1, PO-2, …).

The **Outcome level** is a History whose deals carry **outcome claims**: what a named source says
happened in a deal. Each claim names exactly one source of four (§5) and one predicate of five
(§6). A verifier checks each claim against its own source and shows the claims side by side. It
never combines them into one outcome, one count or one figure.

## Dependency boundary

**Owns:** the definition `personal_history_outcome/1` and its member names (§3), the two record
kinds and three record members this level adds (§4), the four source labels and what each is
checked against (§5), the predicate table `outcome_predicates/1` and its digest (§6), the deal
commitment rule (§7), the level's properties and requirement results (§8), and the two named
selection and requirement sets (§10).

**Uses unchanged:**

| Tag | Document | What this level takes from it |
|---|---|---|
| PH | `spec/personal-agent-history-profile-v0.md` | the subject and anchor rules (§2), the request and artifact form (§4.3), the holder's pre-release scan (§4.4), linkage (§4.5), units (§5), §6.1, lifecycle links (§7), carriage (§8) |
| IP | `spec/interop-profile-v0.md` (`evidence-interop/0`) | the request, envelope and derivation rules (§6.1, §6.2, §6.5), the coverage declaration (§6.7), issuer independence (§6.7.4), the per-property vocabulary (§7.1), the result mapping (§8), lifecycle statements (§11.2), the producer record (§11.5) |
| ER | `draft-mih-agent-evidence-request` | what a record carries for a `correlation` subject, and what makes it cite an `exchange` half [ER §3.1.1, -01 text] |
| AD | `spec/adapters/` (`x402-v0.md`, `ucp-v0.md`, `acp-v0.md`) | each adapter's five declarations: native object, issuer, native method, the exact predicate (d) and per-property results (e) |
| JR | `spec/judge-record-family-v1.md` | `evaluation-report/v1`, its `cases[].verdict` and `acts` |
| PC | `spec/presentation-contract-v0.md` | the commitment construction `sha256-jcs-nonce256` (§7.2) |
| RES | `spec/evidence-result-v0.md` | sufficiency and verdict |

ER §3.1.1 is in the -01 text of the Evidence Request source, which has not been posted yet. This
level cites it by section and needs nothing from it beyond what §5.2 states.

**Does not define:** any record format of another party, any adapter, any judge, any trust policy,
who may receive a History, or what a recipient should conclude. It defines no figure that combines
claims, sources, deals, holders or counterparties, and no ordering of any of them.

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

Terms from PH §1, IP §1 and ER §2 are used unchanged. This level adds:

- **Outcome claim:** the `outcome` member of one `outcome_recorded` record (§4): one predicate,
  one source and the evidence the source is checked against.
- **Source:** whose statement an outcome claim rests on, from the closed list of §5.
- **Predicate:** what an outcome claim says happened, from the table of §6.
- **Deal commitment:** a commitment to the text of a deal's terms (§7).
- **Opening:** the nonce and text a deal commitment is recomputed from.

## 2. What the level keeps from the Basic level

PH §2 (subject and anchor), §4.2 (the identifier), §4.3 (the request and the artifact), §4.4 (the
holder's checks before release), §4.5 (linkage), §5 (units), §7 (lifecycle links) and §8
(carriage) apply to this level unchanged, with `personal_history_outcome/1` in place of
`personal_history_basic/1` and with §3 and §4 below in place of PH §4.1 and PH §3.

Every claim is answered at the History's one anchor, in the artifact of the deal it is about. A
claim about one deal is never evidence about another.

## 3. The definition document

This level fixes the member names of its derivation's definition [IP §6.5; PO-1]:

| Member | Value |
|---|---|
| `name` | `"personal_history_outcome/1"` |
| `kind` | `"projection"` |
| `subject_form` | `"correlation"` |
| `selection` | as PH §4.1: the deal references the holder picked, a non-empty array of non-empty text strings, sorted by code point, without duplicates |
| `reads` | exactly `["commit_alg", "committed_at", "consent", "deal_commitment", "epistemic_type", "event_time_claim", "outcome", "record_type"]` |
| `coverage_declaration` | the History's coverage declaration [IP §6.7.1]. Any of the three kinds. A `stream_interval` declaration's `rule` MUST be `all_records` |
| `holder_role` | `"seller"` or `"buyer"`: the holder's statement of its side in every selected deal (§10) |
| `sources` | the sources the History's claims may name: a non-empty array of §5's labels, sorted by code point, without duplicates |
| `predicates` | the digest of the predicate table of §6.1: `b5c7fe64bd1b4978aeef89cbc3bd9ecc23c2a57a48202a3d8d29e713ef4abfdc` |
| `recipient` | as PH §4.1 |

No other member is allowed in `/1`. Any change to a member, to `reads`, to the record kinds of §4,
to the sources of §5 or to the predicate table is `/2`, with a new definition and a new digest.

**Coverage.** This level carries the IP §6.7 declaration in its own member, so the three kinds are
available to it. It is the definition IP §6.7.6's example stands in for: what IP's vectors fix as
the unregistered `coverage_declaration_example/0` is, here, `coverage_declaration` of
`personal_history_outcome/1`. A `holder_selected` History stays legal: a holder may show three
deals. IP §6.7.3 item 4 then applies: a requirement whose condition needs the History to be
complete is never `SATISFIED` from it.

**What the definition binds.** Every envelope signs `derivation` (PH §4.2), so every envelope is
the holder key's signed statement of the selection, the role, the sources and the predicate table
the recipient's History is read under.

## 4. Record kinds and members

The Basic level's closed list of record kinds (PH §3) gains two kinds, at this level only [PO-2]:

| `record_type` | Meaning | Carries |
|---|---|---|
| `step_completed` | as PH §3 | — |
| `step_failed` | as PH §3 | — |
| `outcome_recorded` | the holder's agent recorded one outcome claim about the deal | `outcome` (§5) |
| `judge_consent` | the holder consented to one judge answering one question about the deal | `consent` (§5.4) |

- `outcome` is carried by every `outcome_recorded` record and by no other record. `consent` is
  carried by every `judge_consent` record and by no other.
- A deal's records carry at most one deal commitment (§7): `deal_commitment` and `commit_alg`,
  always together, on one record of any kind.
- A record of any other kind MUST NOT be in a selected deal. A verifier reports it as
  `record_kinds` `FAIL` (§8.2).
- An `outcome_recorded` record is the holder's agent's record. Its `epistemic_type` is the
  holder's own label, as at the Basic level (PH §3).

## 5. Sources

An outcome claim is a JSON object with `predicate` (an `id` of §6.1), `source` (one label below)
and the members its source requires. A claim names one source. A deal can carry several claims,
for one predicate or for several.

| `source` | Members besides `predicate` and `source` | Rests on |
|---|---|---|
| `holder_record` | none | the holder's agent's own record |
| `counterparty_half` | `evidence` | the other party's half of the exchange |
| `native_object` | `evidence`, `adapter`, `adapter_predicate` | an object of a commerce or payment protocol, read through an adapter declaration |
| `judge_verdict` | `evidence` | a judge's verdict, given after the holder's consent |

`evidence` is a non-empty array of SHA-256 digests, each 64 lowercase hex characters, sorted, without duplicates: the digests
of the objects the claim is checked against. The objects travel beside the answers, never in an
envelope or an artifact (§11).

Each claim also has a **deal binding**: how the evidence is tied to the deal.

- `carried`: the evidence itself names the deal reference, the way ER §3.1.1 says a record carries
  a correlation identifier.
- `holder_only`: only the holder's `outcome_recorded` record ties the evidence to the deal. That
  record is in an artifact whose `anchor_inclusion` is `NOT_CHECKED` (PH §6.1).

### 5.1 The holder's record

A `holder_record` claim is the holder's agent's statement that the predicate holds. It has no
evidence besides the record. It establishes "the holder's agent recorded P", and nothing more: it
is never corroboration (PH §3), and its deal binding is `holder_only`.

### 5.2 The other party's half

A `counterparty_half` claim cites the other party's half of the exchange by digest. The holder's
host holds the half under ER §3.1.1's `cites` form: in the holder's stream it is a record citing
the half with `citation_purpose` `counterparty_half` (`spec/REGISTRY.md` §11). That record asserts
custody of the half, not an observation of it.

The half is checked by its own format's rules. A verifier checks that its signature verifies
under the key it names (`half_signature`), that the trust policy accepts that key as the other party's (`half_signer_trust`), that it names the deal (`half_subject`), and that it states the claim's
predicate (`half_states`). How a format states a predicate is that format's matter. The vectors fix
one form (§12).

It establishes "the key named in the half states P". It is not "the other party agrees" unless
IP §6.7.4's `issuer_independence` between the half and the holder key is `PASS`, which no verifier
built from IP's current revision reports. A half signed by the holder key is
`issuer_independence` `FAIL`: redundant, not corroborating [IP §6.7.4]. Its deal binding is
`carried` when `half_subject` is `PASS`, and `holder_only` otherwise.

A trust policy that accepts keys for this level says which role it accepts each key in: the other
party's, or a judge's. A key accepted in one role is not accepted in the other. The vectors fix
that as `pins.outcome_roles` (§12).

### 5.3 A native object through an adapter declaration

A `native_object` claim cites the octets of an object a commerce or payment protocol produced,
and names the adapter declaration (`adapter`, a file name under `spec/adapters/` without `.md`)
and the predicate of that declaration's (d) it rests on (`adapter_predicate`).

- The verifier runs that adapter's checks and reports `native_check`: `PASS` when every check the
  adapter predicate requires is `PASS` [AD (d), (e)], and so is every check by which the adapter
  binds the object's parties and assets to the relying party's policy (for x402, `payer_trust` and
  `asset_trust`, as `x402-v0.md` §8 requires for a requirement that names a party); `FAIL` when
  one is `FAIL`; otherwise
  `NOT_CHECKED`, including when the verifier does not implement the adapter or does not hold the
  objects.
- `adapter_predicate_maps`: the adapter predicate is one the predicate table (§6.1) lists for the
  claim's predicate. A claim never establishes more than its adapter predicate. An adapter
  predicate the table does not list for the claim's predicate is `FAIL`, even when the object
  verifies.
- What `PASS` shows is the adapter predicate and nothing else. For x402 X3, it is that the holder of
  a payer address's key, which the policy binds to a party, signed a transfer authorization that
  was executed on chain inside its window (`x402-v0.md` §8). An adapter's online checks run from
  the lookup the relying party recorded (`x402-v0.md` §6.4), whatever the IP verification policy
  says about IP's own material.
- Its deal binding is `holder_only` unless the object itself names the deal reference. None of
  the objects the current adapter declarations cover does.

**The verifier-statement form.** Some native objects cannot be disclosed whole, and a projection of
one cannot be verified. A mail message signed under a sending domain's key is one: the signature
covers the body and headers, and a header-only extract verifies nothing and can expose the holder's
address. Such an object MAY be disclosed instead as a **verifier statement**: a named verifier's
signed statement that it ran a named native method (for example RFC 6376 signature verification)
over an object of a stated digest, with a stated result, released only to the definition's
recipient. A mail signature shows which domain signed the message. It does not show that what the
message says is true. This revision registers no form for a verifier statement and no adapter for
mail. A claim in that form is therefore `native_check` `NOT_CHECKED` [PO-5].

**Not a source.** A countersignature or a grade that an outside service gives a History or one of
its bundles is an assessment of disclosed evidence, not evidence of the event. It is never a
source and is never shown as the other party's corroboration.

### 5.4 A judge's verdict, under consent

A `judge_verdict` claim cites one judge record: an `evaluation-report/v1` [JR §2] about the deal,
held with the judge's key and the deal reference and signed by the judge. The vectors fix one form
for that (§12) [PO-6].

- **Consent first.** The deal's records include a `judge_consent` record whose `consent` is
  `{"judge": <the judge's key>, "contract_ref": <the question>}`, with a lower leaf index than the
  `outcome_recorded` record that cites the verdict (`consent_precedes_judgment`). The question is
  the judge record's `contract_ref`. A verdict with no consent before it is never a source.
- **Grounds.** The judge record's case for the predicate (`case_id` equal to the predicate)
  cites, in `acts`, only records of the deal's artifact (`judge_grounds`). A verdict that grounds
  on any other record is `FAIL`. A judge concludes only what the records it cites support.
- The judge record's signature verifies (`judge_signature`), the trust policy accepts the judge's
  key as a judge's (`judge_signer_trust`), and the record names the deal (`judge_subject`).
  The deal binding is `carried` when `judge_subject` is `PASS`, and `holder_only` otherwise.

It establishes "a judge concluded P, from these records, for this question". The verdict is the
case's `verdict`: `met`, `not_met` or `not_evaluable` [JR §2]. This level's requirements carry no
`out_of_scope` switch, so a case verdict outside those three, such as `out_of_scope`, gives a claim
that does not count, with `judge_verdict_allowed` `FAIL`. A producer MUST NOT map such a verdict to
another one. `judge_verdict_allowed` is `NOT_CHECKED` when there is not exactly one case for the
predicate, where `judge_grounds` already fails.

## 6. Predicates

### 6.1 The table

The predicates are one table, `outcome_predicates/1`, shared by every History at this level and by
both sets of §10. Its digest is SHA-256 of UTF-8 of JCS of the object below:
`b5c7fe64bd1b4978aeef89cbc3bd9ecc23c2a57a48202a3d8d29e713ef4abfdc`. Every definition carries it in
`predicates` (§3), so a recipient knows which predicate meanings every envelope was signed under
(`predicate_binding`, §8.2).

```json
{
  "name": "outcome_predicates/1",
  "predicates": [
    {"id": "cancelled", "sources": ["counterparty_half", "holder_record", "judge_verdict"]},
    {"id": "completed", "sources": ["counterparty_half", "holder_record", "judge_verdict", "native_object"],
     "native": [{"adapter": "ucp-v0", "predicate": "checkout-completed"}]},
    {"id": "delivered", "sources": ["counterparty_half", "holder_record", "judge_verdict"]},
    {"id": "disputed", "sources": [], "lifecycle": "disputes"},
    {"id": "paid", "sources": ["counterparty_half", "holder_record", "judge_verdict", "native_object"],
     "native": [{"adapter": "x402-v0", "predicate": "X3"}, {"adapter": "x402-v0", "predicate": "X4"}]}
  ]
}
```

`sources` lists the sources a claim of that predicate may name. `native` lists the adapter
predicates a `native_object` claim of it may rest on. `checkout-completed` is this table's name for
`ucp-v0.md` §3 (d) with `status` `completed`. X3 and X4 are `x402-v0.md` §8's.

### 6.2 What establishes each

| Predicate | Established by | Stays `not_evaluable` |
|---|---|---|
| `completed` | the holder's record (as the holder's statement); a half stating it; a judge's verdict from the deal's records; a business-signed checkout in state `completed` (`ucp-v0` §3 (d)) | payment and delivery: a completed checkout is the business's signed statement of a checkout state, not of payment or fulfilment (`ucp-v0` §3 (d)) |
| `delivered` | the holder's record; a half of the receiving party stating it; a judge's verdict | delivery from any payment object. No adapter declaration in this repository supports a delivery predicate: an x402 X5 receipt is the payee's statement about a response digest, not the payer's receipt (`x402-v0` §8) |
| `paid` | the holder's record; a half of the paid party stating it; a judge's verdict; an executed transfer authorization (x402 X3) or a payee's signed receipt (X4) | payment from a checkout or an order; the facilitator's agreement, whose response is unsigned (`x402-v0` §8) |
| `cancelled` | the holder's record; a half stating it; a judge's verdict | cancellation from the absence of later records: absence is never an outcome. An order snapshot kept without its signed request is possession only (`ucp-v0` §4, §5) |
| `disputed` | an IP §11.2 `disputes` statement (§6.4) | everything from an outcome claim: no source may claim it |

### 6.3 Evidence answers only its own question

A claim establishes only its own predicate. Evidence of payment establishes payment, not delivery
or receipt. A verifier asked about delivery, holding payment evidence and no delivery evidence,
shows what it found for payment (each claim and its result under §8.4) and that delivery is not
established. It never offers the payment evidence as the answer. A `native_object` claim resting
on an adapter predicate the table does not list for the claim's predicate is
`adapter_predicate_maps` `FAIL`, and also `outcome_form` `FAIL` when the predicate allows no
native source at all (§8.3).

### 6.4 `disputed`

IP §11.2 defines the lifecycle statement and its `disputes` token in full: its members (§11.2.2),
who may issue it and the `resolves` statement that closes it (§11.2.4), its properties and
findings (§11.2.5), and its status `open`, `upheld`, `dismissed` or `conflicting` (§11.2.6). This
level uses that definition and no other. What is still planned is the registration of `disputes`
as an Evidence Layer link type in `draft-mih-agent-evidence-layer` -01 (IP §11.2.1). Until then an
EL store carries the statement as a record payload, not in a `links` header, exactly as IP says.

So:

- a deal is shown as disputed when the verifier holds an IP §11.2 `disputes` statement, with the
  finding `lifecycle_effective`, whose target is a record of the deal. It is shown with its issuer
  and its status, by IP §11.2.6;
- the statement is obtained by its own request, as PH §7 says. It is never part of an answer at
  this level, and an outcome claim never claims `disputed` (its table entry lists no source: a
  claim of it is `outcome_form` `FAIL`);
- "not disputed" is never established: a verifier that holds no statement has not seen every
  statement there is;
- IP §11.2.6 leaves what an open or resolved dispute does to a requirement to the Evidence
  Contract prose. This level adds nothing to that: a requirement over `disputed` maps by
  §8.4 only once a contract states its effect [PO-4].

## 7. Deal commitments

A deal's terms (the text both parties agreed to) are committed in the holder's stream, never
disclosed by an answer:

- At most one record of the deal carries `commit_alg` `"sha256-jcs-nonce256"` and
  `deal_commitment`, the lowercase-hex SHA-256 of UTF-8 of JCS of `{"nonce": N, "text": T}`
  [PC §7.2]. `N` is 32 bytes from a cryptographically secure random source, fresh for each deal,
  as 64 lowercase hex characters.
- The artifact reveals `deal_commitment`, never `T`. Without the opening, the commitment shows
  only that the record committed to some text.
- The opening `{N, T}` travels in the History (§11) or in an Evidence Bundle beside it. It never
  travels in an envelope. A holder releases an opening only to the definition's recipient, and the
  holder's pre-release scan (PH §4.4) treats it as part of the release.
- A verifier reports `deal_commitment_opening` for each deal that carries a commitment: `PASS`
  when the opening's two members recompute the commitment; `FAIL` when they do not; `NOT_PRESENT`
  when no opening is carried. On `NOT_PRESENT` it shows the terms as committed and not opened,
  never a placeholder as the text. On `FAIL` it shows no text.

A `deal_commitment_opening` `FAIL` is shown with the deal. It does not change whether the History
is accepted, and it changes no claim.

## 8. Acceptance

### 8.1 Interop properties

Each exchange is verified as PH §6.1 says, and the IP §8 mapping applies unchanged. A History at
this level is **accepted** when every envelope is accepted under PH §6.1 and every History
property of §8.2 is `PASS`. Claims are evaluated only in an accepted History.

The other coverage properties of IP §6.7.2 are reported for the declared kind beside §8.2's, and
act only as IP §6.7.3 says: a `FAIL` means the History is not accepted as its declared kind
(IP §6.7.3 item 2), and any status lowers a completeness requirement by item 4. They are not
History properties, so `coverage_declaration_commitment` `NOT_CHECKED` never stops a
`stream_interval` History being accepted.

### 8.2 History properties

Each is reported in the IP §7.1 vocabulary [PO-3]:

| Property | Check |
|---|---|
| `definition_form` | the definition carries exactly the members of §3, with the values §3 fixes. For `predicates` it checks only that the value is 64 lowercase hex characters. Its value is `predicate_binding`'s check |
| `definition_binding` | as PH §6.2 |
| `predicate_binding` | the definition's `predicates` equals the digest of §6.1's table |
| `coverage_declaration_form` | as IP §6.7.2, with §3's restriction on the rule |
| `selection_coverage`, `single_signer`, `single_anchor` | as PH §6.2 |
| `artifact_form` | as PH §6.2, with this level's `reads` |
| `record_kinds` | every record's kind is in §4's list, `outcome` and `consent` are on exactly the records §4 names, and a deal carries at most one deal commitment, with both of its members |

### 8.3 Claim properties

For each `outcome_recorded` record of an accepted History, the verifier reports:

| Property | Sources | Check |
|---|---|---|
| `outcome_form` | all | the claim carries exactly the members §5 lists for its source; its predicate is in §6.1; the predicate's `sources` include the claim's source; `evidence` is sorted, duplicate-free and of 64-hex digests |
| `outcome_source_allowed` | all | the claim's source is in the definition's `sources` |
| `outcome_evidence` | all but `holder_record` | an object whose SHA-256 is each `evidence` digest is held. `NOT_PRESENT` otherwise |
| `half_signature`, `half_signer_trust`, `half_subject`, `half_states` | `counterparty_half` | §5.2 |
| `issuer_independence` | `counterparty_half` | IP §6.7.4, between the half's key and the holder key |
| `adapter_predicate_maps`, `native_check` | `native_object` | §5.3 |
| `judge_signature`, `judge_signer_trust`, `judge_subject`, `judge_grounds`, `consent_precedes_judgment`, `judge_verdict_allowed` | `judge_verdict` | §5.4 |

A claim's properties that need its evidence are `NOT_CHECKED` when the evidence is not held.

A claim **counts** when every one of its properties is `PASS`, except `issuer_independence`, which
may be `NOT_CHECKED`. A claim that does not count is shown with the properties that are not
`PASS`. It is never shown as the predicate failing. A claim property never changes an envelope
property, a History property or whether the History is accepted.

### 8.4 Requirement results

A recipient requirement at this level names a predicate and the sources it accepts, and is
evaluated per selected deal. For one deal, consider the claims of that predicate whose source the
requirement accepts. The first row that applies decides:

| Status = sufficiency | Verdict | When |
|---|---|---|
| `GAP` | `not_evaluable` | there is no such claim |
| `SATISFIED` | the verdict of the counting `carried` claims, when they all give the same one: `met` (a half; a judge's `met`) or `not_met` (a judge's `not_met`) | at least one such claim counts and has deal binding `carried`, and they agree |
| `UNKNOWN` | `not_evaluable` | a claim counts, but none is `carried`, or the `carried` ones disagree or give `not_evaluable`; or no claim counts and some claim's properties are all `PASS`, `NOT_CHECKED` or `INCONCLUSIVE` |
| `INSUFFICIENT` | `not_evaluable` | otherwise: every claim has a property that is `FAIL` or `NOT_PRESENT` |

- A `holder_only` claim never gives `met` or `not_met`. That is PH §6.1's rule, applied to claims:
  what only the holder's record ties to the deal rests on an artifact whose inclusion is not
  checked.
- Claims from different sources are never merged. Two sources that agree are two rows of §9. Two
  counting `carried` claims that disagree give `UNKNOWN`, and both are shown.
- A requirement at this level asks whether an accepted source states the predicate for the deal.
  It is not a corroboration condition. A half's `met` is "the half's key states P", as §5.2 says,
  never "two parties agree". A requirement whose condition needs corroboration takes IP §6.7.4's
  rule: with `issuer_independence` `NOT_CHECKED` it is `UNKNOWN`, never `SATISFIED`.
- IP §6.7.3 item 4 and IP §6.7.4 apply after this table, unchanged: they only ever lower a
  `SATISFIED`.

## 9. What a verifier shows

A verifier showing an accepted History at this level shows, in this order:

1. the coverage kind and what completeness is relative to [IP §6.7.3], and that outcomes are shown
   per source and never combined, before any count;
2. the number of selected deals and the Basic level's deal states (PH §5), each in its own unit;
3. per deal, one row per outcome claim: its predicate, its source label, whether it counts, its
   deal binding, and its properties that are not `PASS`. For a half, `issuer_independence` and what
   it means (IP §6.7.4). For a judge, the judge, the question and the records cited;
4. per deal, the deal commitment's state (§7) and any disputes held (§6.4);
5. per requirement and deal, the result of §8.4. A predicate with no claim is "not established",
   never "failed";
6. which checks ran and which did not, including `anchor_inclusion` `NOT_CHECKED`, and the limits
   of PH §4.5, PH §9 and §13 here.

## 10. Selection and requirement sets

A seller's record of what it delivered and a buyer's record of what it paid for are two uses of
this one level, not two protocols. Each is a named, informative **selection and requirement set**:
a constraint on the definition and a list of requirements over §6's predicates. Both use the same
members, the same predicate table and the same properties.

| Set | Definition | Requirements, per selected deal |
|---|---|---|
| seller-performance | `holder_role` `"seller"`. A `stream_interval` or `source_authoritative` declaration is RECOMMENDED, so the selection is not only the holder's choice | `delivered` and `completed`, accepting `counterparty_half` and `judge_verdict`; `cancelled` and any dispute shown |
| buyer-transaction | `holder_role` `"buyer"`. Any coverage kind | `paid` and `completed`, accepting `native_object` and `counterparty_half`; `cancelled` and any dispute shown |

The set names describe a selection and its requirements. Neither set defines a rate, a share or
any figure across deals, and a verifier that follows this level shows none.

## 11. Carriage

As PH §8, with these changes to the one-file container (PH §8.2) [PO-7]:

| Member | Value |
|---|---|
| `history` | `"personal_history_outcome/1"` |
| `definition`, `exchanges` | as PH §8.2 |
| `evidence` | the objects the claims cite: an array of `{"media_type", "octets_text"}` or `{"media_type", "octets_hex"}`, the octets exactly as held. A verifier finds each by its SHA-256 |
| `openings` | an object whose members are deal references and whose values are `{"nonce", "text"}` (§7). A deal with no opening is left out |

When a History is asked for (PH §8.1), the evidence and the openings reach the recipient by any
channel beside the answers, or in an Evidence Bundle. They are never added to an envelope or an
artifact.

## 12. Vectors

The vectors are in `vectors/personal-history-outcome-v0/`.
`python/scripts/generate_personal_history_outcome_v0_vectors.py` generates them from the Basic
level run in `vectors/personal-history-basic-v0/`, and
`python/tests/test_personal_history_outcome_v0_vectors.py` checks them. Every case is derived: the
run's replies, asked again under this level's definition and re-signed by the holder key.

As in IP §6.7.6, some formats are fixed for the vectors only and are not registered:

- a half: IP §11.5's producer record (`claim`, `issued_at`, `producer`, `sig`) with `subject_ref`,
  the deal reference. Its `claim` is the predicate's `id`;
- a judge record: `{"judge", "record", "subject_ref", "sig"}`, where `record` is an
  `evaluation-report/v1` and `sig` is Ed25519 by `judge` over UTF-8 of JCS of the other members;
- a recipient's outcome requirement: `{"id", "predicate", "sources"}`.

The native object is the x402 adapter corpus's `positive` case (`vectors/adapters/x402/`): its
payment payload and settlement response octets, unchanged, and its recorded lookup with `final`
`true`. The x402 adapter's pending revision makes a lookup without `final` `INCONCLUSIVE` for
`settlement_onchain`. This case's lookup states finality, and its objects are the same under both
texts, so it holds under the released adapter text and under the pending revision.

The pins fix, for these vectors only: `pins.outcome_roles`, the keys the trust policy accepts as
the other party's (`counterparty`) and as a judge's (`judge`); and `pins.outcome_requirements`:
`r-completed` accepts all four sources, and `r-delivered` and `r-paid` accept `counterparty_half`,
`judge_verdict` and `native_object`. Neither is one of §10's sets.

Every level property that can be `FAIL` has a mutant, except `native_check`. The x402 corpus's
failing case has a lookup that the pending adapter revision changes, so a `native_check` `FAIL`
here would depend on bytes that revision changes.

| Cases | What they show |
|---|---|
| `holder-record` | the holder's record of `completed`: counts, `holder_only`, `r-completed` `UNKNOWN` |
| `counterparty-half` | a half stating `delivered`: counts, `issuer_independence` `NOT_CHECKED`, `r-delivered` `SATISFIED`/`met` |
| `native-object` | an x402 X3 payment: `native_check` `PASS`, `holder_only`, `r-paid` `UNKNOWN` |
| `judge-verdict` | a consented judge's `met` for `completed` from the deal's records: `r-completed` `SATISFIED`/`met` |
| `not-evaluable-delivered-from-payment-evidence` | payment shown by the x402 object and by a half: `r-paid` `met`, `r-delivered` `GAP`/`not_evaluable` |
| `deal-commitment-unopened`, `deal-commitment-wrong-opening` | `deal_commitment_opening` `NOT_PRESENT` and `FAIL` |
| `source-not-allowed`, `judgment-before-consent`, `judge-acts-outside-deal`, `judge-signature-forged` | `outcome_source_allowed`, `consent_precedes_judgment`, `judge_grounds`, `judge_signature` `FAIL` |
| `judge-not-a-judge`, `judge-for-another-deal` | `judge_signer_trust` (with `consent_precedes_judgment`, whose consent names the judge) and `judge_subject` `FAIL`; the second is `holder_only` |
| `judge-verdict-out-of-scope` | a judge's case answering `out_of_scope`: `judge_verdict_allowed` `FAIL`, the claim does not count, `r-completed` `INSUFFICIENT` |
| `half-states-other-predicate`, `half-for-another-deal`, `half-signature-forged` | `half_states`, `half_subject` (and `holder_only`), `half_signature` `FAIL` |
| `half-under-holder-key`, `half-under-holder-key-trusted` | a half signed by the holder key: `half_signer_trust` with `issuer_independence` `FAIL`; and, where the policy accepts the holder key as the other party's, `issuer_independence` `FAIL` alone |
| `payment-evidence-claimed-as-delivered` | an x402 payment cited for `delivered`: `outcome_form` and `adapter_predicate_maps` `FAIL` (§6.3) |
| `native-object-not-held` | `outcome_evidence` `NOT_PRESENT`, `native_check` `NOT_CHECKED`: `r-paid` `INSUFFICIENT` |
| `disputed-as-outcome-claim` | a claim of `disputed`: `outcome_form` `FAIL` (§6.4) |
| `predicates-digest-altered`, `outcome-on-a-step-record`, `coverage-rule-not-all-records` | `predicate_binding`, `record_kinds` and `coverage_declaration_form` `FAIL`: the History is not accepted and no claim is evaluated |

The Basic level's vectors are unchanged.

## 13. Security and privacy considerations

- **Minimum disclosure.** `reads` adds `outcome`, `consent` and the deal commitment to the Basic
  level's set. An outcome claim names a predicate and digests, never an item, an amount, a
  counterparty or message text. The evidence it cites is disclosed only to the recipient, and the
  holder's scan (PH §4.4) covers it.
- **Evidence discloses what it holds.** A half, a native object or a judge record can name the
  other party, an amount or an address. Choosing a source is choosing to disclose that object to
  the recipient. A verifier-statement (§5.3) is the form for an object that cannot be disclosed
  whole.
- **Two signatures never show two parties.** A half under a key the holder controls is redundant
  (IP §6.7.4). Distinct keys alone are not independence.
- **A judge concludes only from what it cites.** `judge_grounds` bounds the verdict to the deal's
  records. Consent before judging is the holder's record, and what the judge retains afterwards is
  the judge's commitment, not something this level shows.
- **Commitments.** A commitment without its opening reveals nothing a guess can test (PC §7.2).
  An opening, once released, is the text: release it only to the recipient.
- **Linkage.** Evidence digests are stable across Histories, as deal references and record digests
  are (PH §4.5). Two recipients holding the same half can tell they hold the same deal.
- **No ordering.** This level defines no figure that orders or grades deals, holders,
  counterparties, judges or sources.

## 14. Open points

| # | Point |
|---|---|
| PO-1 | The definition's member names (§3), which IP leaves open as P-14. |
| PO-2 | The two added record kinds and the three added members (§4). They may later move into an EL revision's `record_type` guidance with PH's two (PA-2). |
| PO-3 | The level's History and claim properties (§8.2, §8.3) as properties in IP's vocabulary that are not IP §7.2 envelope properties and never enter the IP §8 mapping. |
| PO-4 | `disputed` rests on IP §11.2 as defined. `disputes`, `amends` and `resolves` are not yet registered as EL link types; registration is proposed for `draft-mih-agent-evidence-layer` -01. What a dispute does to a requirement waits for the Evidence Contract prose (IP §11.2.6). This revision has no vector for a disputed deal. |
| PO-5 | The verifier-statement form of a native object (§5.3), and an adapter declaration for signed mail. Until both exist, a claim in that form is `NOT_CHECKED`. |
| PO-6 | A carriage for a judge record outside a Capsule. The vectors fix one (§12). |
| PO-7 | The one-file container's `evidence` and `openings` members (§11). |
| PO-8 | Native objects that name the deal reference. With one, a `native_object` claim's deal binding becomes `carried` and §8.4 can give it `met`. |
