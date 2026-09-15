# Evidence Bundle conformance vectors

These vectors cover `draft-mih-scitt-agent-action-capsule-evidence-bundle-00`.
Each case states the three independent completeness outcomes. `withheld` means
the producer explicitly declared a reachable citation missing; it is not a
successful complete graph and not an unexplained verification failure.

The reference test builds the small, deterministic three-leaf CLL fixture
named by each case. The manifest, rather than its construction code, is the
cross-language expected-result contract. The fixture uses the CLL portable
proof shape in `completeness_certificate`: endpoint `range_proof` plus a
detached `memberships` map. The latter prevents an MMR proof from changing the
Capsule ID that it proves.

## Independent derivation

For the valid case, the root Capsule canonical preimage is:

```json
{"action_id":"bundle-3","action_type":"decide","assurance":{"attestation_mode":"self_attested","effect_mode":"not_applicable","ledger_mode":"standalone"},"canonicalization_id":"jcs","developer":"agent@v1","disposition":{"approver":"policy","decision":"reject","human_disposed":false,"verdict_class":"blocked"},"format_version":"4","operator":"ACME-CO","spec_version":"draft-mih-scitt-agent-action-capsule-04","timestamp":"2026-09-14T00:00:03Z"}
```

Applying SHA-256 to those UTF-8 bytes gives
`65fd43081d60ee74dbc702d1f6eb73c45e3509c20557ee9d55cbb09e0722277c`.
The valid bundle's `countersignatures`-omitted JCS form hashes to
`279aea6e55e2f59bdf5f4640e2e66d7a5d84280f33b5469996ae191c1ff22480`.

For its third record, `seq=3`, so `leaf_index=2`. The CLL MMR has size `4`
after three leaves. The proof has an empty witness and one left peak
`a7cd0779a1f2ee8617767c38f9fd32a5858bff0b950c296925fbf7b879d6fa9b`.
Bagging that peak with the leaf hash gives range root
`01ce0ca12b0435132d1a3d73ceb636ac394055be1de51414a68a61e0d859ba2c`.
This is independently derived from the CLL hash rules, not accepted merely
because the reference verifier returns it.
