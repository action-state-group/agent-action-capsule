# Section map — draft-mih-scitt-agent-action-capsule

A reader's guide to the Internet-Draft: what each section defines and which
registry ([`REGISTRY.md`](REGISTRY.md)) it governs. Section numbers track the
current revision (`-03`); Git history preserves prior revision numbering.

**Companion document:** `draft-mih-scitt-agent-action-capsule-sel-disc-00.md`
profiles the selective-disclosure extension point.
It defines the `_sd_alg`/`_sd` vocabulary, commitment encoding, disclosure
syntax, and verifier checks (SD-1 through SD-6).

**Companion document:** `draft-mih-scitt-agent-action-capsule-disclosure-envelope-00.md`
profiles the out-of-band disclosure of digest-only fields — currently
`model_attestation.compute_attestation.agent_input_digest` and
`.agent_output_digest` (-02 §5.3, Observation mode). It defines the
`capsule`/`disclosures` wrapper vocabulary, the disclosure-eligible field
table, and the verifier checks (DE-1 through DE-3). Unlike the
selective-disclosure companion, it never modifies the Capsule payload or
its `capsule_id`; the wrapper is a sibling structure entirely outside the
signed bytes.

| I-D section | Defines | Registry governed |
|---|---|---|
| §1 Introduction | The may/did distinction; the three design commitments (effect-state binding, a Capsule on every verdict, independent verifiability) | — |
| §2 Conventions | BCP 14 terminology; Capsule and Producer Envelope definitions | — |
| §3.1 Producer Envelope | Independent COSE_Sign1 over the raw 32-byte Capsule ID; exact Ed25519 headers; signer authorization outside the cryptographic verdict | — |
| §3.2 SCITT registration | Distinct RFC 9943 registration statement over the same raw Capsule ID; Receipt and VDS verification remain substrate concerns | — |
| §3.x Outcomes | Asynchronous consequences represented as new Capsules with independent identities and envelopes | — |
| §4 Registries (summary) | The six registry-governed vocabularies, stated once with the binding invariant | all six |
| §5.1 Identity | Format 4 declared `jcs`, chain-committed Capsule ID, and the absent-field format-2 vintage verification path | — |
| §5.2 Effect Record | `effect.status`, the confirmed-effect binding (request/response digests), `effect.type`, `irreversibility_class`, `effect_attestation` and the validity matrix | `effect.type`, `irreversibility_class`, `effect_attestation` |
| §5.3 Assurance | `attestation_mode` / `effect_mode` / `ledger_mode` as independently-rederivable claims | — |
| §5.4 Disposition | `decision`, `approver` (closed enum), the honest `human_disposed` flag, `reason_digest`, `expiry_policy` | `disposition.decision` |
| §5.4.1 verdict_class | The terminal-verdict reason-class vocabulary | `verdict_class` |
| §5.4.2 Orthogonality | The pairing rule between `verdict_class` and `effect_mode` | — |
| §5.4.3 A Capsule on every verdict | Why refusals and blocks are recorded as affirmative evidence | — |
| §5.4.4 Chained Capsules | The `chain` block, HITL-resolution-as-supersedes, the open-items predicate | `chain.relation` |
| §6 Verification | Independent Capsule Class-1, Producer Envelope, authorization, and Receipt verification responsibilities | — |
| §7 Conformance | The two verifier classes (Class 1 / Class 2) | — |
| §8 Manifest-dependent material | Constraint Records and the Class 2 (manifest-aware) checks | — |
| §9 Extensibility / namespacing | The not-registry-governed, producer-local vocabularies | — |
| §10 Related Work | Adjacent SCITT/agentic-governance drafts | — |
| §11 Future Work | Reserved extension direction | — |
| §12 IANA Considerations | The six payload-vocabulary registries plus Capsule JSON and raw Capsule-ID media types | all six |
| §13 Security Considerations | Tamper-evidence vs recorder honesty; observed-and-bound; upstream spoofing; digest leakage | — |

The normative registry definitions and seeded values are in §12 of the I-D;
[`REGISTRY.md`](REGISTRY.md) is the interim registry of record that mirrors them.
