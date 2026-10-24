# Evidence Bundle fragment codec vectors

These vectors cover the Evidence Bundle permalink codec in
`draft-mih-zhang-agent-disclosure-bundle`, "Fragment Codec": a JSON value is
carried in a URL fragment as its RFC 8785 JCS text, UTF-8, base64url without
padding. The TypeScript codec is `encodeFragment` and `decodeFragment` in
`ts/src/bundle.ts`; the Go codec is `bundle.EncodeFragment` and
`bundle.DecodeFragment`.

## Cases (`vectors.json`)

Each case has a `payload` and `fragment_py`, the token an independent
encoder wrote for it (its provenance is in the file's `description`).

- When `ascii_json` is true the payload's JSON text has no character at or
  above U+007F, and the codec MUST write exactly `fragment_py`.
- When it is false the independent encoder wrote `\uXXXX` escapes where the
  codec writes UTF-8, so the tokens differ.
- In every case the codec MUST decode `fragment_py` to `payload`.

| name | `ascii_json` |
|---|---|
| `empty-object` | true |
| `one-byte-tail` | true |
| `two-byte-tail` | true |
| `ascii-presentation-fragment` | true |
| `key-order` | true |
| `delete-character` | false |
| `non-ascii` | false |

`ts/test/fragment-vectors.test.ts` and `go/bundle/fragment_vectors_test.go`
run every case. The file moved here unchanged from
`ts/test/testdata/presentation-fragment-vectors.json`. `SHA256SUMS` pins
every file in this directory, and `manifest.json` carries the SHA-256 and case
count of `vectors.json`.
