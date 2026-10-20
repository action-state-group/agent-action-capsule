# agent-action-capsule (Rust)

Reference verification for the Agent Action Capsule, the Rust sibling of the
Python reference and the Go and TypeScript implementations in
[action-state-group/agent-action-capsule](https://github.com/action-state-group/agent-action-capsule).
It is checked against the same conformance vectors, and CI verifies Python-,
Go-, TypeScript- and Rust-sealed capsules in every implementation.

| Module | What it does | Go package |
|---|---|---|
| `canonical` | RFC 8785 JCS, JSON-DIGEST and `capsule_id` | `go/canonical` |
| `registries` | the profile registries, from an embedded `spec/REGISTRY.md` | `go/registries` |
| `verify` | Class 1 verification (checks 1-9) and the store checks | `go/verify` |
| `envelope` | Producer Envelope (COSE_Sign1 over the Capsule ID), a record's producer signature | `go/envelope` |
| `bundle` (feature `bundle`) | Evidence Bundle v2 codec and verifier; `verify_bundle_strict` and the producer `build_evidence_bundle` with feature `strict` | `go/bundle` |
| `witness` (feature `strict`) | witness receipts (`cll`, `rekor`, `scrapi`) in `checkpoint.witnesses` | Python `witness` |
| `settlement` (feature `settlement`) | two-party settlement records (`draft-mih-agent-settlement-records-00`) | Python `settlement` |

```rust
use agent_action_capsule::verify::{decode_capsule_json, verify};

let capsule = decode_capsule_json(bytes)?;
let result = verify(&capsule, None);
if result.ok {
    println!("{}", result.capsule_id.unwrap_or_default());
}
```

Decode capsules with `decode_capsule_json`, a strict RFC 8259 decoder.
Numbers are kept as written (`serde_json`'s `arbitrary_precision` feature), so
a float or an out-of-range integer is reported by check 1 instead of being
rounded away. `serde_json::from_slice` is not a substitute: with that feature
it turns an object holding `serde_json`'s private number token into a number,
which changes the Capsule ID. Cargo unifies features, so
`arbitrary_precision` applies to every `serde_json` user in a build that
depends on this crate.

The `bundle` feature adds `checkpointed-local-log`, which also carries an HTTP
witness client; record verification does not need it.

The `strict` feature (which includes `bundle`) adds
`bundle::verify_bundle_strict`, the checks a verifier needs before it tells a
person that a Bundle is VALID: each record's producer signature, the
checkpoint read only from its signed COSE form, producer-selected Bundles, the
`disclosures` overlay as one claim, and the witness receipts in
`checkpoint.witnesses` under a witness directory the caller supplies (none is
trusted by default). Its result carries a `VALID`, `INCOMPLETE` or `INVALID`
verdict; the plain `verify_bundle` is unchanged. It adds
`scitt-cose-receipt`, `coset` and `p256`. `vectors/bundle/strict/README.md`
describes every rule.

```rust
use agent_action_capsule::bundle::{verify_bundle_strict, StrictOptions};

let result = verify_bundle_strict(&bundle, &StrictOptions {
    require_signature: true,
    witness_directory: Some(&directory),
});
println!("{}", result.verdict());
```

With `strict`, `bundle::build_evidence_bundle(&source, &options)` builds a
Bundle from a `ProofSource`: the log's signed COSE checkpoint, its leaves,
records by Capsule ID, and inclusion and range proofs, in the Bundle's own
wire shape. It holds no key, and it checks the result with
`verify_bundle_strict` before returning it, refusing anything that verifier
calls INVALID; the `BuildError` message names the refusal.
`proof_source_from_cll(&backend, records)` makes a `ProofSource` from a CLL
backend (`EntrySource` and `CheckpointStateStore`) and a `RecordSource`, whose
`get_record` returns `Ok(None)` only for a record it does not hold.

- `BuildOptions::new(root, Interval::From(n))` carries every record from seq
  `n` to the checkpoint tip, and none below it, with a range proof: the Bundle
  can read VALID. `Interval::From(1)` is the whole log.
- `BuildOptions::new(root, Interval::ProducerSelected)` carries only the
  chosen records, each with its own inclusion proof, and states
  `completeness.selection: "producer-selected"`: it reads INCOMPLETE.

The interval is an argument of `BuildOptions::new` and `BuildOptions` has no
`Default`, so a caller never hands over the whole log by omission. A range
over a leaf that is not a record, a carried record below `n` and a record past
the checkpoint are refused by name. A missing citation or an unsigned record
is stated, not refused, and reads INCOMPLETE. `build_unproven_bundle(&records,
&UnprovenOptions::new(root))` is the form with no log proof, for Capsules
that belong to no log.

```rust
use agent_action_capsule::bundle::{
    build_evidence_bundle, proof_source_from_cll, BuildOptions, Interval,
};

let source = proof_source_from_cll(&backend, records)?;
let bundle = build_evidence_bundle(&source, &BuildOptions::new(root, Interval::From(1)))?;
```

The `settlement` feature adds `settlement::verify_settlements`, which derives
payment and delivery states from both parties' leg records.

Not yet in Rust: Disclosure Envelopes, composed bundles, and the emitter and
presentation layers.

## Development

From `rust/`:

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
```

The tests read `../../vectors/`, `../../provenance-mode-vectors/` and
`../../spec/REGISTRY.md`. `data/REGISTRY.md` and `data/cpb_provisional.json`
are byte copies of `spec/REGISTRY.md` and
`python/agent_action_capsule/data/cpb_provisional.json`; the `drift` test
fails until a changed source is copied over.

Licensed under BSD-3-Clause.
