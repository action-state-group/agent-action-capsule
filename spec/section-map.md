# Section map — draft-mih-scitt-agent-action-capsule

A reader's guide to the Internet-Draft: what each section defines and which
registry ([`REGISTRY.md`](REGISTRY.md)) it governs. Section numbers track the
current revision (`-01`); see the built text (`draft-mih-scitt-agent-action-capsule-00.txt`)
for the authoritative numbering of the prior revision.

**Companion document:** `draft-mih-scitt-agent-action-capsule-selective-disclosure-00.md`
profiles the selective-disclosure extension point reserved in §6.2 of -01.
It defines the `_sd_alg`/`_sd` vocabulary, commitment encoding, disclosure
syntax, and verifier checks (SD-1 through SD-6).

| I-D section | Defines | Registry governed |
|---|---|---|
| §1 Introduction | The may/did distinction; the three design commitments (effect-state binding, a Capsule on every verdict, independent verifiability) | — |
| §2 Conventions | BCP 14 terminology; the meaning of "statement profile" | — |
| §3.1 Envelope | The SCITT Signed Statement (COSE_Sign1) protected header, the `capsule_*` CWT claims, the two `+json` media types | — |
| §3.x Outcomes | The asynchronous `outcome` statement type correlated to a decision | — |
| §4 Registries (summary) | The six registry-governed vocabularies, stated once with the binding invariant | all six |
| §5.1 Identity | `spec_version` / `format_version` / `capsule_id` and the canonical capsule form | — |
| §5.2 Effect Record | `effect.status`, the confirmed-effect binding (request/response digests), `effect.type`, `irreversibility_class`, `effect_attestation` and the validity matrix | `effect.type`, `irreversibility_class`, `effect_attestation` |
| §5.3 Assurance | `attestation_mode` / `effect_mode` / `ledger_mode` as independently-rederivable claims | — |
| §5.4 Disposition | `decision`, `approver` (closed enum), the honest `human_disposed` flag, `reason_digest`, `expiry_policy` | `disposition.decision` |
| §5.4.1 verdict_class | The terminal-verdict reason-class vocabulary | `verdict_class` |
| §5.4.2 Orthogonality | The pairing rule between `verdict_class` and `effect_mode` | — |
| §5.4.3 A Capsule on every verdict | Why refusals and blocks are recorded as affirmative evidence | — |
| §5.4.4 Chained Capsules | The `chain` block, HITL-resolution-as-supersedes, the open-items predicate | `chain.relation` |
| §6 Class 1 verification | The deterministic agent-profile checks performable from the record's own bytes | — |
| §7 Conformance | The two verifier classes (Class 1 / Class 2) | — |
| §8 Manifest-dependent material | Constraint Records and the Class 2 (manifest-aware) checks | — |
| §9 Extensibility / namespacing | The not-registry-governed, producer-local vocabularies | — |
| §10 Related Work | Adjacent SCITT/agentic-governance drafts | — |
| §11 Future Work | Reserved extension direction | — |
| §12 IANA Considerations | The six new payload-vocabulary registries, the `capsule_*` CWT claims, and the two media-type registrations | all six |
| §13 Security Considerations | Tamper-evidence vs recorder honesty; observed-and-bound; upstream spoofing; digest leakage | — |

The normative registry definitions and seeded values are in §12 of the I-D;
[`REGISTRY.md`](REGISTRY.md) is the interim registry of record that mirrors them.
