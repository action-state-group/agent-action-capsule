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
| `envelope` | Producer Envelope (COSE_Sign1 over the Capsule ID) | `go/envelope` |
| `bundle` (feature `bundle`) | Evidence Bundle v2 codec and verifier | `go/bundle` |

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
