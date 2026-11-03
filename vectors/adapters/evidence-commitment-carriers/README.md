# Evidence commitment carrier vectors (EXPERIMENTAL)

Vectors for `spec/bindings/evidence-commitment-carriers-v0.md`, an experimental binding that puts
one signed evidence commitment on four carriers: an attestation entry in a directory record's
trust manifest, an extension entry in an A2A Agent Card, an addressable Nostr announce event, and a
service entry in an ERC-8004 agent registration file.
The binding is not part of `evidence-interop/1` and has no binding token. These vectors are not
conformance vectors for that profile.

- `vectors.json`: the cases (binding §10). Each carries the carrier entries, the octets each URI
  serves, the announce events a relay holds, for an ERC-8004 entry the agent (`agentRegistry`,
  `agentId`) the verifier resolved the file from and, where a case needs them, an answer for the key
  binding, with the expected result of every verify step and the cards handed on (V6).
- `manifest.json`: the set, its status and the SHA-256 of each generated file.
- `SHA256SUMS`: every file here.

The responder and impostor keys, the manifest, the V5 answer envelope and the contract pin are
those of `vectors/interop-profile-v1/`. Every other key is a test key derived from a public label
(`test_keys` in `vectors.json`). History cards use the test-only format of
`spec/inference-service-history-profile-v0.md` §9. Commitment members that the binding does not
read are fixed placeholders. Nothing was contacted: `node.example` and `wss://relay.example` are
example names, and no chain was read. The ERC-8004 registry named is the Base Sepolia Identity
Registry, `eip155:84532:0x8004A818BFB912233c491871b3d84c89A494BD9e`; `agentId` 7 is an example.

Regenerate with `python python/scripts/generate_evidence_commitment_carriers_vectors.py`; check
with `pytest python/tests/test_evidence_commitment_carriers_vectors.py`. The workflow
`.github/workflows/evidence-commitment-carriers.yml` fails when a regeneration differs from these
files.
