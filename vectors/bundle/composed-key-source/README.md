# Evidence Bundle `composed/v1`: member key vectors

These vectors cover how `draft-mih-zhang-agent-disclosure-bundle-03`
"Joins" ("Member keys") determines a member Bundle's key under
`controller_binding` and `same_key` (agent-action-capsule#663). The -03
revision is held for ratification; the text and these vectors are reviewed
together.

A member Bundle's key, its time T and the key's source are:

- `record_signature`: the root record carries `signature` or `key_id`. The key
  is the one its producer signature verifies under, T its `timestamp`. A
  record with only one of the two, or whose signature fails, has no key and
  never falls back to its log.
- `log_checkpoint`: the root record carries neither. The key is the one that
  signed the Bundle's checkpoint, T that checkpoint's `timestamp`, only when
  the checkpoint verifies with every stated copy matching it, the record's
  `capsule_id` recomputes from its content, and its own membership entry
  proves it under that checkpoint (its log, `leaf_index = seq - 1`, the
  checkpoint's MMR size, a proof against the signed root). A failure elsewhere
  in the Bundle does not remove the key.

A key is never read from a value a record states. Under `controller_binding`
`pointer` is optional; when present it must select the key so determined,
else the join is `not_derivable`. Every `controller_binding` and `same_key`
join reports each member's key source (`record_signature`, `log_checkpoint`,
`history`, or `none` for a member with no key).

The composition is responder-a's and responder-b's halves of one exchange,
each its responder's whole log with a signed checkpoint, joined by
`controller_binding` on one binding over the two keys. responder-a's root
record is unsigned unless the case says otherwise.

## Cases (`vectors.json`)

| id | what changes | derived | responder-a source |
|---|---|---|---|
| `key-source-unsigned-logged-linked` | unsigned root, logged, no pointer | `agree` (redundant) | `log_checkpoint` |
| `key-source-unsigned-with-pointer` | the same, with pointer `/key_id` | not derivable | `log_checkpoint` |
| `key-source-unsigned-not-logged` | unsigned root, no checkpoint | not derivable | `none` |
| `key-source-root-missing-other-proved` | root listed missing, another record proved | not derivable | `none` |
| `key-source-edited-content-proved-id` | unsigned root edited after logging | not derivable | `none` |
| `key-source-membership-other-log` | root membership names another log | not derivable | `none` |
| `key-source-membership-size-mismatch` | root proof states another MMR size | not derivable | `none` |
| `key-source-proof-leaf-index-mismatch` | root proof states another `leaf_index` than its coordinates | not derivable | `none` |
| `key-source-stated-root-differs` | checkpoint JSON root differs from its signed form | not derivable | `none` |
| `key-source-unrelated-membership-fails` | another record's proof broken | `agree` (redundant) | `log_checkpoint` |
| `key-source-key-id-without-signature` | `key_id` only | not derivable | `none` |
| `key-source-signature-without-key-id` | `signature` only | not derivable | `none` |
| `key-source-failing-signature` | signature does not verify | not derivable | `none` |
| `key-source-checkpoint-time-after-revocation` | binding revoked between the records and the checkpoint | `unjoined` | `log_checkpoint` |
| `key-source-pointer-selects-other-key` | signed records; pointer selects another bound key | not derivable | `record_signature` |
| `key-source-signed-without-pointer` | signed records, no pointer | `agree` (redundant) | `record_signature` |
| `key-source-same-key-unsigned-logged` | history-a `same_key` responder-a's unsigned, logged root | `agree` (redundant, `same_key`) | `log_checkpoint` |

The member Bundles' own completeness claims are reported per member, as the
Bundle rules give them; a broken membership or an edited record fails them
there, which never enters the block's status.

Every implementation runs every case: Go (`go/bundle`), Python
(`agent_action_capsule.composed`), TypeScript (`ts/src/composed.ts`) and Rust
(`agent-action-capsule::bundle::composed`), and
`scripts/cross-language-interlock.sh` has all four print the same result line.

## Regenerating

```bash
python3 python/scripts/generate_bundle_composed_key_source_vectors.py
```

The run is deterministic. The keys are the test-only seeds of
`vectors/bundle/composed/`, listed in `vectors.json`.
