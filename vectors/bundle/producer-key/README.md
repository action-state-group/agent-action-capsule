# Evidence Bundle `producer-key/v1` vectors

These vectors cover the `producer-key/v1` extension kind in
`draft-mih-zhang-agent-disclosure-bundle-01`, "The producer-key/v1 Extension"
and "Self-Countersignature", and its entry in `spec/REGISTRY.md` §14.

The extension is

```json
{"producer-key/v1":{"public_key":"<64 lowercase hex Ed25519 public key>"}}
```

and, like every extension, it is covered by the bundle digest. A verifier
uses the key for one thing only: a `countersign/v1` entry signed by that key
is reported as `not independent`. The declaration never makes an entry
independent, resolved or valid, and it is not an identity or authority claim.
A malformed block is ignored and never fails the Bundle.

## Cases (`vectors.json`)

Each case is a complete Bundle with one `countersign/v1` entry whose signature
is valid over the case's `bundle_digest`. `expect.declared_producer_keys` is
the key a verifier reads from the extension (empty when absent or malformed),
and `expect.stamp` is the entry's state. No countersigner directory is
consulted, so a valid independent entry is an `unresolved signer`.

| id | extension | signer | stamp |
|---|---|---|---|
| `declared-self-countersignature` | producer key | producer key | `not independent` |
| `undeclared-self-countersignature` | absent | producer key | `unresolved signer` |
| `declared-other-signer` | producer key | other key | `unresolved signer` |
| `malformed-uppercase-hex` | producer key, uppercase | producer key | `unresolved signer` |
| `malformed-short-hex` | 63 hex characters | producer key | `unresolved signer` |
| `malformed-key-list` | `public_key` is a list | producer key | `unresolved signer` |
| `malformed-block-not-object` | bare key string | producer key | `unresolved signer` |
| `malformed-missing-public-key` | `{}` | producer key | `unresolved signer` |

`extension_block_jcs` is the JCS form of the well-formed extension for the
producer test key. It is byte-identical to the block capsulectl emits for a
declared producer key and to the AAC TypeScript derived fixture
`week-bundle-producer-countersigned.json`, which uses the same test seed.

The base Bundle is the positive case of `../report-single-record.json`, read
as committed. Keys are TEST-ONLY: the producer seed is 32 bytes of `0x0b`,
the other signer's 32 bytes of `0x21`.

## Regenerating

From the repository root:

```sh
python3 python/scripts/generate_bundle_producer_key_vectors.py
```

The output is a pure function of the generator and the base Bundle (Ed25519
signatures are deterministic). `SHA256SUMS` pins every file in this
directory, including this hand-written README.
