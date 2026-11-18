- Spec: Evidence Request -03 (`spec/draft-mih-agent-evidence-request-03`, #629) registers
  `history_card/2`, the default first question, beside `history_card/1`, which is unchanged. A
  `/2` card lists the stream's first checkpoint, checkpoints 1, 2, 4, 8 and so on positions back
  from the anchor, and the latest W checkpoints (W from 1 to 64, stated in the card), each with its
  position, receipts and the consistency proof from the entry before it, so its size grows with
  the logarithm of the number of checkpoints. The `checkpoints` subject takes an optional range of
  checkpoint positions, so a requester can fetch the checkpoints between two listed entries. The
  derivation's row is in `spec/REGISTRY.md` §16.
