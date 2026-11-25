- Spec: Evidence Bundle -03 states what a clean-room verifier had to infer (AAC#460). A new "Wire
  Forms" section gives the members of `checkpoint` mapped to the signed COSE claims and the fold of
  `root`, `range_root` and `prev_root`; a record's log entry (its `capsule_id`) and MMR leaf; the
  JSON forms of `inclusion_proof` and `range_proof`, with the order of a range proof's `witness`;
  and a record's local `signature` and `key_id`. "Citation Closure" now says a supplied record the
  closure does not reach neither passes nor fails graph closure.
