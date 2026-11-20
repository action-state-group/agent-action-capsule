- Spec: a new derivation token `standard_history/4` (`spec/standard-history-v0.md` §12, #634),
  beside `standard_history/1` to `/3`, which are unchanged in every member, rule, document and
  vector. A `/4` card is a `/3` card that leaves no deal out for want of a witness time: a started
  deal whose records hold no time from a witness its agreement names, or whose agreement names
  none, is counted and disclosed in `local_times`, whatever its rows say. Its deal entry has
  `no_witness_time` in place of `left_out`, and its card no `not_counted` tally, since only shop
  purchases paid up front are not counted. SH-12 and
  SH-13 say how `/3` and `/4` differ. Its counting table and wording pack are in
  `spec/history-frame/` (History frame §6.1), its row in `spec/REGISTRY.md` §16, and its 8 vectors
  in `vectors/standard-history-v0/vectors-4.json`.
- Python and Go: `agent_action_capsule.standard_history` and `go/standardhistory` derive and check
  `standard_history/4` cards (`DERIVATION_4`; `Derivation4`).
