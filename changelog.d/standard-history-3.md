- Spec: a new derivation token `standard_history/3` (`spec/standard-history-v0.md` §11, #620),
  beside `standard_history/1` and `/2`, which are unchanged in every member, rule, document and
  vector. A `/3` card counts the deals of a shelf log of book facts (`spec/shelf-forms-v0.md`) from
  each deal's term rows as of the anchor's time, in five outcome lines (`ruling_not_honoured`,
  `undecided`, `did_not_hold`, `held_so_far`, `held`, the first that applies wins), splits
  `did_not_hold` four ways in a tally of its own, leaves out a deal whose agreement names witnesses
  with no time from them, and carries the shelf log's `coverage_start`. Its counting table and
  wording pack are in `spec/history-frame/` (History frame §6.1), its row in `spec/REGISTRY.md`
  §16, and its 16 vectors in `vectors/standard-history-v0/vectors-3.json`.
- Python and Go: `agent_action_capsule.standard_history` and `go/standardhistory` derive and check
  `standard_history/3` cards (`DERIVATION_3` and `line`; `Derivation3`, `Line`, `Deal.Rows`,
  `Deal.LeftOut` and `AsOf.CoverageStartTime`).
