# CBOR nesting limit

Every reader of received deterministic CBOR that accepts nested content reads
items nested up to 128 levels deep and refuses anything deeper as malformed,
so one document never reads differently across Go, Python and Rust (#504). It
is the limit the JSON readers apply (`vectors/json-nesting/`, #498), so one
Evidence Request reads the same in its JSON and CBOR bindings. An array, a map
or a tag around an item is one level: `[]` is one level, `[[]]` two. TypeScript
has no reader of this kind; its COSE Receipt reader applies the receipt rule
below.

Not changed:

- The COSE Receipt and anchor encoding rule keeps its own, stricter bound of
  16 levels (`spec/interop-profile-v1.md` §6.2.2).
- The Producer Envelope readers (Go and TypeScript stop at 8) read a
  COSE_Sign1 that nests two levels and refuse any other header or element
  whatever its depth, in a message of at most 4096 octets, so no input is read
  by one implementation and refused by another for its depth alone.

Before this limit Go read Evidence Request CBOR to 32 levels and the interop
profile's decoder to 64, Python to 64, Rust to 512 (its CLL Material reader to
256), while the same request in JSON was read to 128.

`cases.json` holds the cases. Each is the CBOR encoding (`cbor_hex`) of a
minimal valid Evidence Request whose open-world member `x` holds a chain of
containers, with its `depth` (the whole item) and whether it is read
(`accept`). Past-limit cases wrap the at-limit case by one level; the last case
nests 10,000 arrays and must be refused without exhausting the stack. `tag`
marks the cases built of tags: a generic decoder reads the one at the limit,
and every request reader refuses both, because a request holds no tag at any
depth (`vectors/cbor-request-model/`, #529).
`python/scripts/generate_cbor_nesting_vectors.py` regenerates `cases.json` and
`SHA256SUMS`; this file is hand-written.

| Case | Depth | Read |
|---|---|---|
| `pos-array-at-limit` | 128 | yes |
| `neg-array-past-limit` | 129 | no |
| `pos-map-at-limit` | 128 | yes |
| `neg-map-past-limit` | 129 | no |
| `pos-mixed-at-limit` | 128 | yes |
| `neg-mixed-past-limit` | 129 | no |
| `pos-tag-at-limit` | 128 | by generic decoders only |
| `neg-tag-past-limit` | 129 | no |
| `neg-arrays-far-past-limit` | 10,001 | no |

Run by Go (`./evidencerequest`), Python (`test_cbor_nesting_vectors.py`) and
Rust (`evidence-request:cbor_nesting`, and unit tests in the `evidence-request`
crate for the reply, refusal and CLL Material readers).
