- Spec: a new derivation token `standard_history/5` (`spec/standard-history-v0.md` §14, #682),
  beside `standard_history/1` to `/4`, which are unchanged in every member, rule, document and
  vector. A `/5` card is a `/4` card that counts every deal in the window, whatever its
  `counterparty_class`: a shop purchase paid up front (`shop_preauth`) is counted like any other
  deal, in the outcomes, bands, roles, how it happened and its disputes, raised and received. The
  card's new `shop_preauth` tally says how many counted deals were such purchases, and
  `in_window.not_counted` is 0. Like `/3` and `/4`, a `/5` deal's row results and disputes are
  read as of the anchor's time (§11.1 "One card, one time"), a shop purchase's included. SH-20
  records an open point: a shop that never states on its rows leaves its purchases `undecided`.
  Its counting table and wording pack are in `spec/history-frame/` (History frame §6.1), its row
  in `spec/REGISTRY.md` §16, and its 11 vectors in `vectors/standard-history-v0/vectors-5.json`,
  among them a shop purchase with a dispute the holder raised.
- Python and Go: `agent_action_capsule.standard_history` and `go/standardhistory` derive and check
  `standard_history/5` cards (`DERIVATION_5`; `Derivation5`).
