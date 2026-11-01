# CBOR request data model

A request received in the CBOR binding is read only in core deterministic
encoding (RFC 8949 §4.2.1) and only when every item in it is `null`, `false`,
`true`, a text string, an unsigned integer from 0 to 2^53 − 1, an array, or a
map whose keys are text strings (`spec/interop-profile-v1.md` §5.2, #529). The
rule holds at every depth, inside members a responder ignores too; anything
else is `request_malformed`. So every responder reads one request alike, and
the request has one encoding and one digest whoever encoded it.

Before this rule Go read a request whose ignored member held a tag, a float, a
byte string or any other value outside the data model, or that was not in
deterministic encoding, while Python and Rust refused it.

`cases.json` holds the cases. Each is the CBOR encoding (`cbor_hex`) of the
minimal valid Evidence Request of `vectors/cbor-nesting/` whose open-world
member `x` holds the item under test, and whether a request reader reads it
(`accept`). `python/scripts/generate_cbor_request_model_vectors.py` regenerates
`cases.json`, `manifest.json` and `SHA256SUMS`; this file is hand-written.

| Case | `x` | Read |
|---|---|---|
| `pos-null` | `null` | yes |
| `pos-max-integer` | 2^53 − 1 | yes |
| `pos-containers` | `[{"a": true}, "t", 0]` | yes |
| `neg-tag` | tag 1000 around `null` | no |
| `neg-tag-nested` | `[{"a": 1(0)}]` | no |
| `neg-float-half` | 1.0, half precision | no |
| `neg-float-single` | 1.5, single precision | no |
| `neg-float-double` | 1.5, double precision | no |
| `neg-negative-integer` | −1 | no |
| `neg-integer-above-limit` | 2^53 | no |
| `neg-byte-string` | `h'00'` | no |
| `neg-integer-map-key` | `{1: 0}` | no |
| `neg-undefined` | `undefined` | no |
| `neg-simple-value` | `simple(16)` | no |
| `neg-non-shortest-integer` | 0 with a one-byte argument | no |
| `neg-indefinite-array` | `[_ ]` | no |
| `neg-indefinite-text` | `(_ "a")` | no |
| `neg-unsorted-keys` | `{"b": null, "a": null}` | no |

Run by Go (`./evidencerequest`), Python (`test_cbor_request_model_vectors.py`)
and Rust (`evidence-request:cbor_request_model`). TypeScript has no CBOR
request reader.
