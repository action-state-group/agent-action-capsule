# Coverage declaration v0: conformance vectors

These vectors exercise the coverage declaration of `spec/interop-profile-v0.md`
(`evidence-interop/0`, cited as IP) §6.7. They cover:

- the three coverage kinds;
- the rule that a valid signature never implies completeness;
- the coverage properties;
- the aggregate rule;
- issuer independence.

Every case cites the sections its expected values come from.

## Derivation

**Everything is built from one run.** That run is
`vectors/personal-history-basic-v0/responder-run.json`: a holder stream of four deals, answered by an
IP responder for one recipient (see that corpus's README). The run file is not copied here. `run` in
`vectors.json` and `manifest.json` names it with its SHA-256.

`python/scripts/generate_coverage_declaration_v0_vectors.py` writes every file except this README.
It reads the run, uses no repository implementation, and states every expected status by hand from
the profile text. Each case's `source` says where its octets come from:

- `responder`: the run's requests and replies, unchanged;
- `derived: …`: replies from the run, asked again under another definition and re-signed by the
  holder key, as the case says.

`python/tests/test_coverage_declaration_v0_vectors.py` checks the corpus from the case inputs
alone:

- It runs every exchange through the IP reference verifier (`agent_action_capsule.interop_profile`)
  and applies the History profile's §6.1.
- It derives the History profile's §6.2 properties with its own evaluator.
- It derives IP §6.7.2's coverage properties, §6.7.3's report, §6.7.5's aggregate rule and
  §6.7.4's issuer independence with its own evaluator.
- It compares all of them with the case's whole `expected` block.
- It runs defective evaluators, each of which must disagree with at least one case.
- It regenerates the directory twice and requires both runs to be byte-identical to the committed
  files.

**Formats fixed for these vectors only, not registered (IP §6.7.6):**

| Format | What it is |
|---|---|
| `coverage_declaration_example/0` | the History profile's `personal_history_basic/1` definition with `coverage_declaration` in place of `completeness`. Only `/1` is a History level; the level that adopts a declaration is a later revision of the History profile (its PA-9, PA-15) |
| population object | `issued_at`, `issuer` (the source key), `items` (deal references, sorted), `subject` (the holder key), `sig`: Ed25519 by `issuer` over UTF-8 of JCS of the other members. It is carried in `inputs.population` as the octets transmitted |
| half | the producer record of IP §11.5: `claim`, `issued_at`, `producer`, `sig` |

The tick and each stream's checkpoint in the live set are label digests, not real checkpoints.
`coverage_declaration_commitment` is `NOT_CHECKED` in this revision (IP P-13, History profile
PA-14), so nothing reads them.

## What each case pins

| Pin | Where |
|---|---|
| Trust roots | `pins.trust_policy`: the holder key as the accepted responder key, the holder stream's checkpoint log keys, and in `foreign_keys` the source key and the two producer keys |
| Verification policy | `pins.verification_policy`: offline, `evidence-interop/0`, the three CLL kinds |
| Contract version | `pins.contract_ref` and `pins.contract_digest`, over `contract.document`. It has three requirements: `r-deal-steps` (as in the History corpus), `r-complete`, whose condition needs the set to be complete (IP §6.7.3 item 4), and `r-corroborated`, whose condition needs corroboration (IP §6.7.4). Their `coverage` and `independence` texts are opaque (IP P-48) |
| Evaluation time | `pins.evaluation_time` |
| Inputs | for a set: `history` (the definition's name), `definition`, `exchanges` (each request and reply as JSON octets, given as text), and where the case needs them, `population` and `aggregate`. For halves: `halves`, the two records' octets |

**All keys are test keys.** Each private key is the Ed25519 seed SHA-256 of the label in
`test_keys`. Never use one for anything else.

## Expected values

For a set, `expected` holds:

- `exchanges`: each envelope's IP result and its History profile §6.1 acceptance;
- `history_properties`: the History profile's §6.2;
- `coverage`, IP §6.7.3:
  - `declared_kind`;
  - `declared_by`: `completeness` for the Basic level, else `coverage_declaration`;
  - `properties`: only those that apply to the kind;
  - `relative_to`;
  - `accepted_as_declared`;
  - `satisfied_becomes`: what a `SATISFIED` `r-complete` becomes under item 4, `null` for
    unchanged;
  - with an aggregate, `aggregate` (`declared`, `derived`, `coverage_declaration_aggregate`);
- `accepted`;
- `fails`: the property each negative is there to fail.

For halves, `expected.halves` holds `signatures`, `agree`, `issuer_independence`, `shown_as` and
`satisfied_becomes` for `r-corroborated`.

Every requirement row is `envelope-4` (`UNKNOWN`/`not_evaluable`), because a derivation's
`anchor_inclusion` is `NOT_CHECKED` (History profile §6.1). A verifier built from IP alone also
gives `r-complete` and `r-corroborated` `UNKNOWN`, because their conditions are opaque text (P-48).
So `satisfied_becomes` states only what §6.7.3 item 4 and §6.7.4 would turn a `SATISFIED` into, for
a verifier that can apply those conditions. No case reaches that `SATISFIED`.

## Cases

| Case | Kind | Source | Fails |
|---|---|---|---|
| `holder-selected` | `holder_selected`, read from `completeness` | responder | nothing; aggregate `holder_selected` `PASS` |
| `stream-interval` | `stream_interval`: four deals in four streams at one tick, every record of the live set | derived | nothing; commitment `NOT_CHECKED`, so `r-complete` would be `UNKNOWN`; aggregate `stream_interval` `PASS` |
| `cherry-picked` | `stream_interval` over the holder's three chosen deals, same live set of four | derived | `coverage_declaration_population`; every History property `PASS`; its aggregate declares `holder_selected`, the only kind §6.7.5 allows it (`PASS`) |
| `stream-interval-record-missing` | `stream_interval`, one record left out of one artifact | derived | `coverage_declaration_population` |
| `stream-interval-anchor-mismatch` | `stream_interval` whose `interval.to` is not the anchor the answers are given at | derived | `coverage_declaration_anchor` |
| `stream-interval-unknown-rule` | `stream_interval` with a rule this revision does not define | derived | `coverage_declaration_form`, and no other coverage property is reported |
| `aggregate-stronger-than-evidence` | `holder_selected`, under an aggregate declaring `stream_interval` | responder | `coverage_declaration_aggregate` |
| `source-authoritative` | `source_authoritative`: three deals, all listed | derived | nothing |
| `source-authoritative-deal-unlisted` | `source_authoritative`: three answered, two listed | derived | `coverage_declaration_population` |
| `source-authoritative-other-subject` | `source_authoritative`: the source lists the three deals for another holder key | derived | `coverage_declaration_population` |
| `source-authoritative-forged-population` | `source_authoritative`: the object names the source and is signed by another key | derived | `coverage_declaration_source` |
| `same-controller-halves-same-key` | two agreeing halves, one key | derived | `issuer_independence` `FAIL`: "redundant, not corroborating"; `r-corroborated` would be `INSUFFICIENT` |
| `same-controller-halves-unbound-keys` | two agreeing halves, two keys, no evidence about their controllers | derived | nothing fails: `issuer_independence` `NOT_CHECKED`, "not corroborating", never "redundant"; `r-corroborated` would be `UNKNOWN` |

`PASS` for issuer independence needs evidence that this revision does not register (IP P-60), so
no case shows it.

## Not covered

- A real tick or a real commitment from an anchor to a stream's checkpoint (IP P-13, P-59).
- A holder that opens a dishonest live set: one that leaves out a stream, or under-counts one. It
  passes every property checked in v0, and only `coverage_declaration_commitment` would catch it
  (IP §6.7.3 item 3). `cherry-picked` shows the case the vectors can show: an honest live set with
  answers left out.
- `coverage_declaration_source` with a pinned key validity window. No case pins one, so "as of the
  object's issue time" reduces to the source key being in `foreign_keys`. The same goes for a
  method the verifier does not implement (`NOT_CHECKED`).
- A population object or a pair of halves the verifier could not parse.
- A `stream_interval` set with `interval.from` set. Every case starts each stream at 0.
- A rule other than `all_records`, which is the only rule this revision defines (IP P-59).
- An aggregate over two sets of different kinds.
