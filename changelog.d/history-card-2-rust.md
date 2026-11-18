<!-- changelog: rust/evidence-request/CHANGELOG.md -->
- `history_card/2` (`draft-mih-agent-evidence-request-03` §8.1.2, AAC#629): the new module
  `history_card` adds `positions`, `MAX_WINDOW` and `FINDINGS`, `registry` adds
  `DERIVATION_HISTORY_CARD_2`, and
  `cll_material::check_history_card_2` (feature `cll`) checks a card in Checkpointed Local Log
  form. Breaking: `request::Subject` gains the variant `CheckpointRange(a, b)` for a ranged
  `checkpoints` subject (-03 §3.1). `resolve` refuses a history card over a ranged subject with
  `no_such_subject`, and a range that ends past the anchor's checkpoint position with
  `coverage_unsatisfiable`.
