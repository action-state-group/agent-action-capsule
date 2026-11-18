- Spec: Evidence Request -03 (`spec/draft-mih-agent-evidence-request-03`, #629) registers
  `history_card/2`, the default first question, beside `history_card/1`, which is unchanged. A
  `/2` card lists the stream's first checkpoint, checkpoints 1, 2, 4, 8 and so on positions back
  from the anchor, and the latest W checkpoints (W from 1 to 64, stated in the card), each with its
  position, receipts and the consistency proof from the entry before it, so its size grows with
  the logarithm of the number of checkpoints. The `checkpoints` subject takes an optional range of
  checkpoint positions, so a requester can fetch the checkpoints between two listed entries. The
  derivation's row is in `spec/REGISTRY.md` §16.
- Vectors: `vectors/evidence-request/history-card-2.json` (36 cases and 42 position rows: a valid
  card over 1,100 checkpoints, a broken proof, a missing sample position, and a case for each
  check) and `vectors/evidence-request/checkpoints-range.json` (9 request and 9 resolution
  cases), both written from -03.
- Python, Go and TypeScript check a `history_card/2` card in Checkpointed Local Log form and give
  its positions: `agent_action_capsule.history_card` (`positions`, `check_history_card_2`);
  `evidencerequest.HistoryPositions` and `CheckHistoryCard2`; and `historyPositions` and
  `checkHistoryCard2`. The Python and Go request readers accept a ranged `checkpoints` subject,
  and a reply envelope signs and reads back the range: Go's `Subject` gains `Ranged`. Go's
  `Decide` has `history_card/2` built in beside `history_card/1` (`DerivationHistoryCard2`).
  TypeScript adds `decodeWellFormedItem`, the CBOR reader for a checkpoint's own octets. A history card over a ranged subject is refused
  `no_such_subject`, and a range that ends past the anchor's checkpoint position is refused
  `coverage_unsatisfiable`.
