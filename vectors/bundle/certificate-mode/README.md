# Evidence Bundle vectors: certificate modes

These vectors pin strict `verify_bundle` on the certificate mode a Bundle
names in `completeness.selection` (`draft-mih-zhang-agent-disclosure-bundle-02`,
"Certificate Modes"). Everything not described here is read exactly as in
`../strict/README.md`: the case format, the claims and their order, the
verdict, and how to consume a case.

The log is the 64-leaf padded log of `../non-record-leaves/`.

## The rules

- **`selection` absent** (the member is not there; a present `null` is a
  value): **a range certificate.** The -01 rules apply, and
  `../non-record-leaves/` for a range that covers padding.
- **`selection` is `producer-selected`.** The producer chose the records; the
  certificate has no range (`first_seq`, `last_seq`, `body_digests`,
  `range_proof`) and claims nothing about the records between them. Interval
  coverage is `withheld` (`selection_not_checkable`). Per-record membership is
  each record's inclusion proof against the checkpoint, as in `../strict/`
  ("Producer-selected Bundles"), and in addition the certificate's `log_id`
  must equal the checkpoint's (`completeness_certificate_invalid`). With no
  signed checkpoint, the proofs are checked against the Bundle's JSON
  `checkpoint` (`range_root` must equal its `root`; the proof `size` its
  `mmr_size`): a failure stays a failure, and a claim that did not fail is
  `withheld` with `checkpoint_unverified`, as for a range Bundle.
  `payloads_mode` `none` says the Bundle carries no payload material; it
  changes no check.
- **Any other `selection` value**, including one that is not a string, names a
  mode the verifier does not implement. Interval coverage and per-record
  membership are both `withheld` with the one finding
  `certificate_mode_unsupported`, so the verdict is at best `INCOMPLETE`. The
  certificate is not read under any other mode, even when it would verify as a
  range, and the verifier never fails the Bundle for the mode.

## Cases

| id | What it shows | verdict |
|---|---|---|
| `incomplete-producer-selected-padded-log` | the 8 records of the padded log, producer-selected, `payloads_mode` `none` | INCOMPLETE |
| `neg-producer-selected-padded-log-tampered` | the same with the root record's proof edited | INVALID |
| `incomplete-certificate-mode-unknown` | `selection` `x-sampled` | INCOMPLETE |
| `incomplete-certificate-mode-not-a-string` | `selection` `7` | INCOMPLETE |
| `incomplete-certificate-mode-unknown-on-range` | a valid range [33, 64] under `selection` `x-sampled` | INCOMPLETE |
| `incomplete-certificate-mode-null` | the valid range [33, 64] under `selection` `null` | INCOMPLETE |
| `neg-producer-selected-unsigned-checkpoint-tampered` | the tampered Bundle without `checkpoint.cose` | INVALID |
| `neg-producer-selected-certificate-log-id` | the certificate names another log | INVALID |
| `neg-producer-selected-certificate-log-id-non-record-leaves` | the same, with `non_record_leaves` carried: per-record membership fails | INVALID |

## Regenerating

`python3 python/scripts/generate_bundle_02_vectors.py` (see
`../non-record-leaves/README.md`).
