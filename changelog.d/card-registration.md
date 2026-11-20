- Spec: a holder MAY register a Standard History card on a SCITT transparency service
  (`spec/standard-history-v0.md` §13, #639). A card statement is a Transparent Statement under the
  holder key over the SHA-256 of the card octets, with RFC 9942 Receipts in its `receipts` header,
  carried beside the card; the new check `card_registered` reports `PASS` with a registration time
  when a Receipt by a service the relying party lists covers it. It shows that the card existed by
  that time and nothing else: `anchor_inclusion` stays `NOT_CHECKED` (IP P-13 stays open for
  cards), it does not show that the holder registered no other card (SH-18), and it does not
  check the counts. Opt-in; no card, token, counting table or wording pack changes. 36 vectors in
  `vectors/card-registration-v0/`.
- Python, Go and TypeScript: `check_card_registered` and `check_card_statement` (Go `CheckCardRegistered`, TypeScript `checkCardRegistered`) in the
  witness modules run those vectors.
