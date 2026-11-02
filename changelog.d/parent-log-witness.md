- Spec: Evidence Bundle `-03` working revision (`spec/draft-mih-zhang-agent-disclosure-bundle-03.md`) defines and
  registers the `parent-log-witness/v1` extension kind (action-state-group/agent-action-capsule#347): a chain from the
  Bundle's checkpoint, or an earlier checkpoint of the same log with a consistency proof, through a salted leaf of a
  Merkle tree whose root is an entry of a parent log signed by the same key, to witness receipts over the parent
  log's checkpoint. The verifier checks every link, names one finding per broken link, and computes the extent
  (entries witnessed of entries in the log) itself. A receipt over the parent checkpoint is never one over the
  Bundle's checkpoint. Additive: a Bundle without the block verifies as before. 36 vectors in
  `vectors/bundle/parent-log-witness/`.
- Python, Go, TypeScript and Rust: strict Bundle verification checks a `parent-log-witness/v1` block under the
  caller's witness directory and reports it beside the claims (`parent_witness`, `ParentWitness`, `parentWitness`);
  only a failure changes the verdict, and the kind's extension result carries its status in strict mode.
- TypeScript: the verification page model lists a checkpoint witnessed through a parent log with its extent, and no
  longer calls a checkpoint self-witnessed when a strict witness check passed.
  `buildVerifiedBundleContext` takes a `witnessDirectory` option, passed to its strict check, so a page can show
  a witnessed checkpoint at all; without one every receipt stays `withheld`, as before.
- Bundles already issued with capsulectl's private `x-cadence-witness/v0` block are not read as
  `parent-log-witness/v1`: the core still shows their checkpoint as self-witnessed until capsulectl writes the
  registered kind (action-state-group/capsule-cli#356).
