# evidence-request

The evidence request protocol of **draft-mih-agent-evidence-request-00**, in
Rust: a requester asks a responder for evidence about a subject, under a
coverage constraint, and the interaction ends in an artifact, a signed
refusal, or the requester's own record that nothing arrived.

| Module | What |
| --- | --- |
| `request` | parse a request in its JSON or CBOR binding (CBOR in core deterministic encoding only, 0.0.4) and check it: the six subject forms, exactly one coverage member, the optional fields; the exact refusal reason when it is not well formed |
| `digest` | the request digest: SHA-256 over the bytes as received |
| `resolve` | exact-match resolution against a responder's holdings (the `Responder` trait): the anchor to serve under, or the most specific refusal reason |
| `refusal` | sign a refusal; check a received one (signature, registry and conformance, reported separately) |
| `outcome` | the one state an interaction is recorded as; a signed refusal is never an absence, and silence is never a refusal |
| `invariance` | caller invariance: the same subject under the same anchor gives the same bytes |
| `retention` | retention commitments and the breach table |
| `unavailable_window` (unreleased) | -02 §4.7 unavailable-window statements: which ones a reader recognizes (well formed, signed by the responder, registered by an accepted receipt), and how it shows an absence one covers |
| `receipt` (0.0.3) | check RFC 9162 Ed25519 receipt form and authenticate any matching inclusion proof under a pinned service key |
| `envelope` (0.2.0) | the interop profile's artifact envelope (`evidence-interop/0` §6.2): sign it, encode it in either binding, read a reply as carried, and accept it as a responder's answer to your request |
| `cll_material` (0.2.0, feature `cll`) | check the Checkpointed Local Log verification material an envelope carries (profile §6.2.1, `anchor_inclusion`) |
| `acceptance` (unreleased, feature `acceptance`) | the interop profile's acceptance records and receipts (§11.1): sign them, read them as both parties must, and evaluate the §11.1.7 properties and the §11.1.8 finding. The profile's, not the request protocol's; it lives beside the profile's envelope |
| `controller_binding` (unreleased, feature `controller-binding`) | Controller Binding v0 (`spec/controller-binding-v0.md`), which the profile's issuer independence uses (§6.7.4): a binding record's properties, with `ed25519` and `bip340` (Nostr) keys, revocation statements and a revocation list declared complete, whether the binding applies to a pair, and the `issuer_independence` it gives |

**Features.** None is on by default: with no features the crate is the
protocol core (every module above except `receipt`, `cll_material`,
`acceptance` and `controller_binding`) and does not depend on
checkpointed-local-log. `cll` enables `cll_material` and the
checkpointed-local-log dependency; `receipt` enables `receipt`; `acceptance`
enables `acceptance`, with no new dependency; `controller-binding` enables
`controller_binding` and the k256 dependency, for BIP-340.

```toml
evidence-request = "0.2"                                     # protocol core
evidence-request = { version = "0.2", features = ["cll"] }  # and CLL material checks
```

```rust
use evidence_request::{digest, request, resolve};

let digest = digest::request_digest(&bytes);         // over the bytes as received
match request::parse_json(&bytes) {
    Ok(req) => match resolve::resolve(&req, &my_holdings) {
        resolve::Resolution::Artifact(anchor) => { /* build and send the artifact */ }
        resolve::Resolution::Refuse(reason) => { /* refusal::sign(&digest, reason, now, key) */ }
    },
    Err(e) => { /* refuse with e.reason() */ }
}
```

Where -00 leaves a wire shape open (subject and coverage shapes, digest
representation, the refusal's member names and signature profile), this crate
follows the readings the draft's conformance vectors document; each module
says which. The API is pre-stable (0.x) until a later draft fixes those
shapes.

To accept a refusal as a responder's answer to your request, use
`refusal::verify_for` (it binds the responder's key and your request
digest); `refusal::check` reports shape and self-consistency only and is not
authentication. To accept an artifact, use `envelope::parse_reply` and then
`Envelope::verify_for`: it binds the profile, the responder's key and your
request digest, and checks the signature, the artifact digest and each
verification item's digest. Whether the material proves the artifact under
the anchor is `cll_material::check_anchor_inclusion` (feature `cll`), which
takes your policy for the log's key.

Building an artifact from a store or a log is the responder's business. A
Checkpointed Local Log responder is the `evidencebook` crate; 0.1.0's
`answer` feature built and verified the crate's own pre-profile envelope,
which no other implementation signs, and is removed in 0.2.0.

Not in this crate: transport, storage, and any store-and-forward or delivery
guarantee.

## Tests

`cargo test --all-features` runs the draft's conformance vectors (every corpus, every case)
from this repository's `vectors/evidence-request/`, checked against that
directory's `SHA256SUMS` first. The Apache-2.0 `scitt-proof-array/` copies also have their
checksums validated before any test reads them; they cover proof ordering and
malformed proof classification. See `tests/vectors/SOURCES.md`. The
envelope, the CLL material checks and `acceptance` run against the interop
profile's corpus, `vectors/interop-profile-v0/`; `acceptance` is also compared
with session-scoped cases frozen from the profile's Python verifier
(`tests/vectors/acceptance-session.json`). `controller_binding` runs every case
of `vectors/controller-binding-v0/`.

## License

Apache-2.0. The conformance vectors it reads from `vectors/evidence-request/`
are BSD-3-Clause, like the rest of the repository's vectors. The shared
scitt-cose receipt vectors under `tests/vectors/scitt-proof-array/` are
Apache-2.0.
