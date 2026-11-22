- Spec: Person Signature v0 (`spec/person-signature-v0.md`, informational). A person's signature,
  made with the person's own key, over the digest of a record that another party signed, carried
  beside the record in `person_signatures`, never inside it. The first key type is `webauthn`: an
  assertion whose challenge is `person-signature/0:<record_digest>`, checked offline against the
  person keys, relying party id and origins the using profile supplies. A record without one reads
  `NOT_PRESENT`, "not signed by the person". Conformance vectors: `vectors/person-signature-v0/`
  (51 cases) with a Python generator and an independent evaluator test (#627).
