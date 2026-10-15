# Test vectors: where they come from

Copied verbatim from the source; not edited here.

| Directory | Source | Pin | License |
| --- | --- | --- | --- |
| `scitt-proof-array/` | [scitt-cose](https://github.com/action-state-group/scitt-cose) `test-vectors/v1/` proof-array derivatives | commit `e539fe4d72e6ad70fe443bf2079795322c69a711` | Apache-2.0; see `scitt-proof-array/SOURCES.md` |

`scitt-proof-array/SHA256SUMS` pins every copied file and is checked by
`receipt_vectors.rs` before any vector is read.

The draft-mih-agent-evidence-request-00 conformance vectors are not copied:
`vectors.rs` reads this repository's `vectors/evidence-request/` in place and
checks it against that directory's `SHA256SUMS` first.
