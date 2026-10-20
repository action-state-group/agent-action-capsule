# Evidence Bundle vectors: category_coverage

These vectors pin `verify_bundle` on the `category_coverage` member
(`draft-mih-zhang-agent-disclosure-bundle-02`, "Category Coverage"): a
producer's signed declaration of what it offers in each category of a named
category set. The declaration declares; it does not prove. A verifier reports
five properties, each on its own, and never combines them into a count or a
score.

Every Bundle is the three-record whole-log Bundle of `../strict/`
(`pos-signed-whole-log`, VALID), with a `category_coverage` member added. The
member is inside the bundle digest like every member other than
`countersignatures`.

## The member

```json
"category_coverage": {
  "set": "<category set id>",
  "categories": {
    "<name>": { "status": "<STATUS>", "policy_uri": "<absolute URI>" }
  },
  "request_digest": "<64 lowercase hex>",
  "signer": { "key_id": "<64 lowercase hex>" },
  "signature": "<128 lowercase hex>"
}
```

- `set` is a non-empty string; `categories` a non-empty object keyed by
  category name, each value an object whose `status` is one of `AVAILABLE`,
  `PARTIAL`, `WITHHELD`, `DELETED`, `ABSENT`, `UNDISCLOSED`, upper case.
  `policy_uri`, when present, is an absolute URI (RFC 3986 Section 4.3); it is
  required for `UNDISCLOSED`. The vectors check it at the character level: a
  scheme (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`), `:`, then only ASCII
  unreserved and sub-delims characters, `:`, `@`, `/`, `?`, and `%` followed by
  two hex digits. A fragment (`#`), whitespace, any non-ASCII character or a
  bad percent-encoding is malformed.
- `request_digest` (optional) is the SHA-256, lowercase hex, of the Evidence
  Request octets as received.
- `signer` and `signature` are both present or both absent. `signature` is
  the Ed25519 signature by the raw key `signer.key_id` over
  `UTF8(JCS({"category_coverage": <member without signature>, "root": <the Bundle's root>}))`.
- Members not listed are ignored (and, when signed, covered by the
  signature). They never fail the form, whatever they hold.

## Inputs a Bundle cannot carry (`options`)

| option | meaning | when `null` |
|---|---|---|
| `category_sets` | the category sets the verifier knows: set id to its names | no set is known |
| `category_request` | the Evidence Request, as UTF-8 JSON text; its octets are the UTF-8 encoding of this string | no request |
| `record_categories` | each carried record's category, by `capsule_id`, as the set's rule assigns it | no assignment |

## The properties, in report order

Each is `PASS`, `FAIL`, `NOT_PRESENT`, `NOT_CHECKED` or `INCONCLUSIVE`. With no
member, `category_coverage` is `null`.

1. `category_coverage_form`: `PASS` when the member is as above, else `FAIL`.
   When it fails, the four others are `NOT_CHECKED`.
2. `category_coverage_signature`: `NOT_PRESENT` with no signature; `PASS` when
   it verifies; `FAIL` otherwise (another key, another root, an edited
   declaration, a signing input with no canonical form because the member or
   `root` holds a fractional number or an integer beyond ±(2^53 − 1), or a
   small-order public key, which these verifiers refuse as an Ed25519 key). A
   verifier with no Ed25519 implementation reports `NOT_CHECKED`.
3. `category_coverage_set_registered`: `NOT_PRESENT` for a set starting `x-`,
   which is never looked up; `INCONCLUSIVE` for a set the verifier does not
   know; `FAIL` when the set is known and a declared name is not in it; `PASS`
   otherwise.
4. `category_coverage_request`, in this order: `NOT_CHECKED` with no request;
   `FAIL` when `request_digest` is present and is not the SHA-256 of the
   request octets (checked before parsing, so also for octets that are not
   JSON); `NOT_CHECKED` when the octets are not UTF-8 JSON read strictly (no
   repeated member name, no `NaN` or `Infinity`, and no unpaired surrogate
   escape such as `\ud800` anywhere, as I-JSON, RFC 7493 Section 2.1,
   requires: such a request is refused, never read with the surrogate kept or
   replaced by U+FFFD), are not an object, or have a
   `categories` that is not `{set: string, names: [non-empty, distinct
   strings]}`; `NOT_PRESENT` when the request has no `categories`; `FAIL` when
   the request's `set` differs or a requested name has no entry; `PASS`
   otherwise. Declaring more names than were asked for is not a failure.
   How many digits an integer in the request may have before a verifier
   stops reading it is implementation-defined; the vectors do not pin it.
   How deeply the request may nest before a verifier stops reading it is
   implementation-defined; the vectors do not pin it either.
5. `category_coverage_consistency`: `NOT_CHECKED` with no assignment, or when
   a carried record is not in it (a record the caller could not assign could
   be in any category; `null` assigns a record to no category); `FAIL`
   when a carried record is assigned to a category declared `ABSENT` or
   `WITHHELD`; `PASS` otherwise. A record in a `DELETED` or `UNDISCLOSED`
   category is not a contradiction.

**Verdict.** The strict verdict is the one `../strict/` defines, and in
addition `INVALID` when `category_coverage_form`,
`category_coverage_signature` or `category_coverage_consistency` is `FAIL`.
The other properties never change it.

## Cases

| id | What it shows | verdict |
|---|---|---|
| `pos-all-six-statuses` | each status once, signed, every input supplied: all `PASS` | VALID |
| `pos-no-inputs` | the same with no inputs | VALID |
| `no-member` | no member: `null` | VALID |
| `private-set` | an `x-` set: `NOT_PRESENT`; the request names another set | VALID |
| `unsigned-member` | no signer, no signature: `NOT_PRESENT` | VALID |
| `neg-signature-wrong-key` | signed by another key | INVALID |
| `neg-signature-other-root` | signed over another root | INVALID |
| `neg-signature-edited` | a status changed after signing | INVALID |
| `neg-undisclosed-without-policy-uri` | `UNDISCLOSED` without `policy_uri` | INVALID |
| `neg-policy-uri-relative` | a relative `policy_uri` | INVALID |
| `neg-policy-uri-fragment` | a `policy_uri` with a fragment | INVALID |
| `neg-policy-uri-non-ascii` | a `policy_uri` with `é` | INVALID |
| `neg-policy-uri-bad-percent` | a `policy_uri` with `%zz` | INVALID |
| `neg-status-lowercase` | `available` | INVALID |
| `neg-status-unknown` | `LEGAL_HOLD` | INVALID |
| `neg-categories-empty` | `categories` is `{}` | INVALID |
| `neg-set-missing` | no `set` | INVALID |
| `neg-request-digest-uppercase` | `request_digest` in uppercase | INVALID |
| `neg-signer-without-signature` | `signer` alone | INVALID |
| `neg-member-not-object` | the member is an array | INVALID |
| `unknown-category` | a name the known set lacks: set `FAIL` | VALID |
| `unknown-set` | a set the verifier does not know: `INCONCLUSIVE` | VALID |
| `request-not-covered` | a requested name has no entry: request `FAIL` | VALID |
| `request-digest-mismatch` | `request_digest` of another request asking for the same categories: request `FAIL` | VALID |
| `request-without-categories` | the request asked for none: `NOT_PRESENT` | VALID |
| `request-digest-mismatch-unparsable` | `request_digest` of another request, octets not JSON: request `FAIL` | VALID |
| `request-duplicate-member` | the request repeats `categories`: `NOT_CHECKED` | VALID |
| `request-lone-surrogate` | the request carries an unpaired `\ud800` escape in a member nothing reads: `NOT_CHECKED` | VALID |
| `consistency-partial-assignment` | two of three records assigned: `NOT_CHECKED` | VALID |
| `neg-consistency-absent-with-record` | a record in an `ABSENT` category | INVALID |
| `neg-consistency-withheld-with-record` | a record in a `WITHHELD` category | INVALID |
| `consistency-deleted-with-record` | a record in a `DELETED` category | VALID |
| `consistency-undisclosed-with-record` | a record in an `UNDISCLOSED` category | VALID |

The set `example-set` exists only in these vectors. No category set is
registered yet.

## Regenerating

`python3 python/scripts/generate_bundle_02_vectors.py` (see
`../non-record-leaves/README.md`).
