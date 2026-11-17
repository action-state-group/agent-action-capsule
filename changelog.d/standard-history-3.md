- Spec: a new derivation token `standard_history/3` (`spec/standard-history-v0.md` §11, #620),
  beside `standard_history/1` and `/2`, which are unchanged in every member, rule, document and
  vector. A `/3` card counts the deals of a shelf log of book facts (`spec/shelf-forms-v0.md`) from
  each deal's term rows as of the anchor's time, in the three outcomes: only rows the holder owed
  make a deal `did_not_hold`, a ruling the holder did not honour comes first, a final unmet row
  comes before a dispute, and a row not reached or not yet final makes the deal `undecided` only
  after `did_not_hold`. It counts,
  among the deals that did not hold, those the holder remedied (`remedied`, a remedy made without a
  ruling included) and those where it did not honour a ruling (`not_honoured`), leaves out a deal
  whose agreement names witnesses with no time from them, tallies the deals not counted by reason,
  and carries the shelf log's `coverage_start`. Its counting table and wording pack are in `spec/history-frame/`
  (History frame §6.1), its row in `spec/REGISTRY.md` §16, and its 27 vectors in
  `vectors/standard-history-v0/vectors-3.json`.
- Python and Go: `agent_action_capsule.standard_history` and `go/standardhistory` derive and check
  `standard_history/3` cards (`DERIVATION_3` and `outcome`; `Derivation3`, `Outcome`, `Deal.Rows`,
  `Deal.LeftOut` and `AsOf.CoverageStartTime`).
