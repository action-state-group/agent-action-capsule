- Spec, clarifications of verifier output in -06 (AAC#89, AAC#105): a `references` target is
  identified by its whole typed digest `{type, digest_alg, digest}`, and only an
  `agent-action-capsule`/`SHA-256` entry can duplicate the chain parent (§xref). Class 1 now says
  that a fail-closed declaration still reports the other checks and the derived modes, except the
  format-4-only `references` checks; that a verifier with no store reports the store-level chain
  checks as not run (info); that a later concurrent supersedes is info; and that only overclaims
  are reported. §everyverdict states that the every-verdict requirement binds the producer and
  cannot be checked from the Capsules a verifier holds. The Python, Go, TypeScript and Rust
  verifiers already behave this way, and no vector expectation changes. The capsule vectors
  README now lists every member removed for the Capsule ID.
