# Personal-Agent History Profile v0, Basic level: conformance vectors

These vectors exercise the Basic level of `spec/personal-agent-history-profile-v0.md`
(`personal_history_basic/1`), an informational host profile written against
`spec/interop-profile-v0.md` (`evidence-interop/0`, cited as IP). They publish the acceptance run
of its §6.4 (open point PA-11). Every case cites the sections its expected values come from.

## Derivation

**The positive run comes from an IP responder.** `responder-run.json` holds every request and
reply of the run as the octets carried. The responder is evidencebook's `Book.Respond`, unmodified,
from <https://github.com/action-state-group/evidencebook> at commit
`43f3cb1b955d647bc92cb4da0d823973d1981cad`. `producer/main.go` drives it. It seeds a holder stream
of four deals, registers the Basic level definition for one recipient, and asks for each deal as
that recipient. It uses a fixed clock and test keys, so every run gives the same bytes. To
reproduce the file, set up that repository as its `docs/THIRD-PARTY-VERIFIER.md` §2 describes,
then run:

```bash
git checkout 43f3cb1b955d647bc92cb4da0d823973d1981cad
mkdir -p test/interop/personal-history
cp <this directory>/producer/main.go test/interop/personal-history/main.go
go run ./test/interop/personal-history > responder-run.json
```

The output's SHA-256 is `run_sha256` in `manifest.json`.

That page's own test responder (`test/interop/answer`) seeds seven `observation` records and
registers no derivation, so it refuses a Basic level request. `producer/main.go` calls the same
`Respond` over a book seeded for this profile.

**Everything else is written by
`python/scripts/generate_personal_history_basic_v0_vectors.py`**, except this README and
`producer/`. The script reads `responder-run.json`, uses no repository implementation, and states
every expected status by hand from the profile text. Each case's `source` says where its octets
come from:

- `responder`: the run's requests and replies, unchanged;
- `derived: …`: replies taken from the run and then changed in a way no conforming responder
  would. Where the case says so, they are re-signed with the holder key or the second holder key.

`python/tests/test_personal_history_basic_v0_vectors.py` checks the corpus from the case inputs
alone:

- It runs every exchange through the IP reference verifier (`agent_action_capsule.interop_profile`)
  and applies §6.1 to the result.
- It derives the seven History properties of §6.2 and the deal states of §5 with its own
  evaluator, written from the profile.
- It compares both with the case's whole `expected` block.
- It checks that each row of the §6.4 mutant table has a case that fails the property the row
  names.
- It runs ten defective History evaluators, each of which must disagree with at least one case,
  and one evaluator that counts envelopes §6.1 rejected, which must also disagree.
- It regenerates the directory twice and requires both runs to be byte-identical to the committed
  files.

## What each case pins

| Pin | Where |
|---|---|
| Trust roots | `pins.trust_policy`: the holder key as the accepted responder key (and the second holder key in `mutant-second-trusted-key`), the holder stream's two checkpoint log keys (`iss`, `sub`, `kid`) |
| Verification policy | `pins.verification_policy`: offline, `evidence-interop/0`, the three CLL kinds |
| Contract version | `pins.contract_ref` and `pins.contract_digest`. The document is `contract.document`: one requirement, `r-deal-steps`, for which a Basic level answer is the only evidence (§6.1). Its shape is that of the IP corpus contract. The Evidence Contract v0 schema it names (`contract.schema`) is not in this repository, so the contract is not validated against it here |
| Evaluation time | `pins.evaluation_time` |
| Inputs | `inputs`: §8.2's one-file History (`history`, `definition`, `exchanges`), holding the requests the recipient itself made and the replies it received (`mode` `asked`, §8.1). Requests and replies are JSON octets, given as text |

**All keys are test keys.** Each private key is the Ed25519 seed SHA-256 of the label in
`test_keys`. Never use one for anything else.

The holder stream is in `holder_stream`. It lists the four deal references, the three selected,
every record with its deal and kind, and the two checkpoints. The History is answered at the
second checkpoint.

## Cases

| Case | §6.4 mutant | Source | Fails |
|---|---|---|---|
| `history-basic` | (the positive run) | responder | nothing: every History property `PASS`, every envelope accepted, each requirement row `envelope-4` |
| `mutant-step-kind-in-transit` | one step's kind changed in an artifact in transit | derived | IP `artifact_digest` |
| `mutant-deal-added-to-definition` | a deal added to the definition the recipient holds | derived | `definition_binding` |
| `mutant-envelope-for-deal-not-selected` | an envelope, signed by the holder key, for a deal not selected | responder | `selection_coverage` |
| `mutant-selected-deal-not-answered` | a selected deal not answered | derived | `selection_coverage` |
| `mutant-second-trusted-key` | one deal answered under a second key the relying party also trusts | derived | `single_signer` |
| `mutant-deal-at-another-anchor` | one deal answered at another anchor | responder | `single_anchor` |
| `mutant-deal-at-another-anchor-request-at-history-anchor` | the same, read as the table's parenthesis reads it | derived | IP `anchor_match` |
| `mutant-record-kind-outside-list` | a record kind outside §3, re-signed by the holder key | derived | `record_kinds` |
| `mutant-member-outside-reads` | a record carrying a member outside `reads`, re-signed by the holder key | derived | `artifact_form` |
| `mutant-definition-reads-widened` | a definition whose `reads` adds `statement` and `counterparty_ref` | responder | `definition_form` |
| `multi-stream-one-tick` | (§2: the positive deals, each in its own stream, at one witnessed checkpoint tick) | derived | nothing: every History property `PASS`, every envelope accepted, each requirement row `envelope-4` |
| `mutant-multi-stream-mixed-anchor` | (§2: the same, one deal at its own stream's checkpoint) | derived | `single_anchor` |
| `refused-other-requester` | a request under the definition from another requester | responder | refused `not_authorized`: refusal properties `PASS`, row `refusal-withheld` |

## Reading the expected values

- `exchanges[]` gives each reply's IP §7.1 statuses (`properties`), whether §6.1 accepts it
  (`accepted`), its IP §8.1 row for `r-deal-steps`, and its claim.
- `history_properties` gives the seven §6.2 statuses. `accepted` is true when every envelope is
  accepted and every History property is `PASS`. `deal_states` (accepted Histories only) gives the
  number of selected deals and each deal's §5 state.
- `fails` names the property the §6.4 table names. A case may fail other properties too. Each of
  those is a consequence that the case states and the test derives.
- Every accepted envelope has `anchor_inclusion` `NOT_CHECKED`, `verification_binding`
  `NOT_PRESENT` (not required), and row `envelope-4`: `UNKNOWN`, `UNKNOWN`, `not_evaluable`. No
  case yields `met` or `not_met` (§6.1).

The profile leaves some readings open. This corpus fixes them as follows:

- **History properties count only envelopes §6.1 accepted** (§6.2). An envelope that fails an IP
  property is not counted, so the deal it answers counts as unanswered. That is why
  `mutant-step-kind-in-transit` also fails `selection_coverage`.
- **The other-anchor mutant has two readings.** §4.3 has every request name the History's
  anchor, and §6.4 says the mutant fails "`single_anchor` (and IP `anchor_match`)". The two
  failures cannot happen together:
  - If the request names the History's anchor, IP `anchor_match` fails, §6.1 rejects the envelope,
    and §6.2 never sees it. So `single_anchor` passes, and `selection_coverage` fails.
  - If the request names the other anchor, which is what the responder answers when asked,
    `anchor_match` passes and `single_anchor` fails.

  The corpus holds one case for each reading.
- **`artifact_form` reads `reads` from the definition the recipient holds.** In
  `mutant-definition-reads-widened` the records carry neither added member, so `artifact_form`
  passes under either reading.
- **The multi-stream cases are derived.** The responder of the run serves one stream. In
  `multi-stream-one-tick` each selected deal's records move to a stream of their own,
  `deal/<deal reference>`, in their order, with `leaf_index` counted from 0 in that stream; each
  request names the tick in `expected_pin`; each reply is re-signed by the holder key over that
  request. The tick and the one stream's checkpoint in `mutant-multi-stream-mixed-anchor` are label
  digests, not real checkpoints: at the Basic level a verifier checks only that every envelope
  names the same anchor (§2, PA-14). The definition, and so the derivation, is the positive run's.
- **A definition with one more deal still has a valid form.** In `mutant-deal-added-to-definition`
  the selection stays sorted and free of duplicates, so `definition_form` passes. Only the binding
  and the coverage fail.
