- Spec: Evidence Bundle -03 `composed/v1` History members (AAC#537). A History answer, one party's
  derivation such as `standard_history/1`, is an `artifact` member with `form` `history`. Its body is
  the responder's signed response as received, its digest is that object's JCS SHA-256, and its
  coverage anchor travels as `anchor_checkpoint`. The new `same_key` join basis ties a History to its
  party's half of a deal. It derives `agree` when the half's Producer Envelope verifies, its key is
  the History's responder and the anchor is not earlier than the half, and `unjoined` when the keys
  differ or the anchor predates the deal. A `same_key` agreement is always redundant. Two History
  members are related only when each agrees with its half and the halves agree on
  `pre_agreed_identifier`, reported with that join's pointer, never by being carried together. A
  block without History members keeps its composed digest. There is still one request per subject, and no multi-subject request. Thirty vectors in
  `vectors/bundle/composed-history/`. The same revision states what a clean-room verifier had to
  infer (AAC#460): the members of `checkpoint` and the fold of its `root`, a record's log entry, the
  JSON forms of `inclusion_proof` and `range_proof` with the order of a range proof's `witness`, a
  record's local `signature` and `key_id`, and that a supplied record outside the closure neither
  passes nor fails graph closure.
- Python: `composed.verify_composed` verifies History members and `same_key` joins and reports
  `related_histories`. `ComposedOptions.history_signature` takes the deployment's signature check;
  `composed.evidence_interop_signature` is the evidence-interop one.
- Go: `bundle.VerifyComposed` does the same, with `Options.HistorySignature`,
  `bundle.EvidenceInteropSignature` and `ComposedResult.RelatedHistories`.
