# Personal-Agent History Profile v0, Outcome level: conformance vectors

These vectors exercise `spec/personal-agent-history-outcome-v0.md` (`personal_history_outcome/1`),
the level above the Basic level of `spec/personal-agent-history-profile-v0.md`. They are written
against `spec/interop-profile-v0.md` (`evidence-interop/0`, cited as IP). Every case cites the
sections its expected values come from. The level's §12 lists the cases.

## Derivation

**Every case is derived.** No responder implements this level. So
`python/scripts/generate_personal_history_outcome_v0_vectors.py` takes the Basic level run in
`../personal-history-basic-v0/responder-run.json` (pinned by its SHA-256 in `manifest.json`) and
asks its three selected deals again under the Outcome level definition. To each deal it adds the
deal commitment, and to the first deal the outcome and consent records the case needs. Then it
re-signs each reply with the holder test key. The responder never produced these octets, and
every case's `source` says so.

The added records' digests are label digests, not record identifiers. That changes nothing a
verifier checks: `anchor_inclusion` is `NOT_CHECKED` at this level as at the Basic level.

The script uses no repository implementation. It states each claim's and each History property
by hand from the level text, and derives from them, by the level's rules, whether a claim counts,
its deal binding, the requirement results and the failing properties. This README is the only hand-written file in the directory.

**The native object** is the x402 adapter corpus's `positive` case (`../adapters/x402/`): its
payment payload and settlement response octets, carried unchanged, and its recorded lookup with
`final` set to `true`, given as the relying party's observation in `pins.native_observations`. The
x402 adapter's pending revision makes a lookup without `final` `INCONCLUSIVE` for
`settlement_onchain` and adds a `detail.source` to its reports. The case depends on neither: the
lookup states finality, and the test reads only the adapter corpus's per-check statuses. When this
corpus was written, its case tests were also run against the pending revision's x402 corpus and
passed. The test here does not repeat that, because the revision is not on this branch.

`python/tests/test_personal_history_outcome_v0_vectors.py` checks the corpus from the case inputs
alone:

- it runs every exchange through the IP reference verifier (`agent_action_capsule.interop_profile`)
  and applies the level's §8.1;
- it derives the History properties (§8.2), claim properties (§8.3), requirement results (§8.4) and
  deal commitment openings (§7) with its own evaluator, written from the level text. It reads the
  predicate table from the level text;
- for a native object it finds the x402 corpus case the claim cites, checks the observed lookup
  against it, and takes the statuses that corpus states for the adapter predicate's checks and for
  `payer_trust` and `asset_trust`. It does not run the adapter: the x402 corpus's own test checks
  those statuses;
- it compares all of that with each case's whole `expected` block, and checks that each case's
  `fails` are exactly the properties that are `FAIL`;
- it runs sixteen defective evaluators, each of which must disagree with at least one case;
- it checks that every file of the Basic level corpus has the digest it had when this level was
  cut, and that no file was added;
- it regenerates the directory twice and requires both runs to be byte-identical to the committed
  files.

## What each case pins

| Pin | Where |
|---|---|
| trust policy | `pins.trust_policy`: the holder key as the only responder key; the other party's key and the judge's key as foreign keys |
| roles | `pins.outcome_roles`: which keys the policy accepts as the other party's and as a judge's (the level's §5.2) |
| verification policy | `pins.verification_policy`: offline, `evidence-interop/0`, the three CLL kinds |
| contract | `pins.contract_ref` and `pins.contract_digest`: the IP requirement every envelope maps |
| outcome requirements | `pins.outcome_requirements`: `r-completed`, `r-delivered`, `r-paid`, in the form the level's §12 fixes for these vectors |
| evaluation time | `pins.evaluation_time` |
| native observation | `pins.native_observations`, only in cases with a native object |

The predicate table and its digest are at the top of `vectors.json` (`predicates`).

## Formats fixed for these vectors only

As the level's §12 says, three formats are fixed here and not registered: the half (IP §11.5's
producer record with `subject_ref`), the judge record (an `evaluation-report/v1` with `judge`,
`subject_ref` and `sig`) and the outcome requirement (`id`, `predicate`, `sources`).

## Test keys

Every key is the Ed25519 key whose 32-byte seed is SHA-256 of the seed label in
`vectors.json` (`test_keys`). They are public test keys. Never use one for anything else.
