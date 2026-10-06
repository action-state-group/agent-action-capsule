# Section map: draft-mih-scitt-agent-action-capsule

This reader's guide follows the editor's [-05 source](draft-mih-scitt-agent-action-capsule-05.md)
and [rendered section numbers](draft-mih-scitt-agent-action-capsule-05.txt).
The current posted revision is -05 on the
[Datatracker](https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/).
This map describes the editor's -05 source. Git history preserves earlier maps.

The seven base-profile vocabularies are `verdict_class`,
`disposition.decision`, `effect.type`, `irreversibility_class`,
`effect_attestation`, `chain.relation`, and `citation_purpose`.
Their normative definitions and initial contents are in §12.1;
[REGISTRY.md](REGISTRY.md) is the interim registry of record. Its additional
extension vocabularies and reserved members are separate from these seven.

| Editor -05 section | Defines | Base registry vocabulary |
|---|---|---|
| §1 Introduction | The may/did distinction, effect-state binding, a Capsule on every verdict, independent verifiability | — |
| §2 Conventions and Definitions | BCP 14 terminology, Capsule and Producer Envelope definitions | — |
| §3.1 Producer Envelope wire profile | COSE_Sign1 over the raw 32-byte Capsule ID and exact Ed25519 headers | — |
| §3.2 Issuer Binding | Authenticated signing-key identity and separate caller authorization | — |
| §3.3 Registration and Receipts | A distinct SCITT registration statement; Receipt and VDS checks remain substrate concerns | — |
| §3.4 Outcomes | Asynchronous consequences recorded as independently identified and enveloped Capsules | — |
| §4 Registries of this profile (summary) | Seven vocabularies and the never-reject invariant for unregistered values | All seven |
| §5.1 Identity and parties | Format 4, declared JCS, chain-committed Capsule ID, parties and producer-local domain/provenance | — |
| §5.2 Configuration epochs | `epoch_id`, epoch-boundary Capsules and epoch-scoped verification | `verdict_class`, `chain.relation` |
| §5.3 Effect Record and the confirmed-effect binding | Effect status, request/response digests and the effect-attestation validity matrix | `effect.type`, `irreversibility_class`, `effect_attestation` |
| §5.4 Assurance | Independently rederivable attestation, effect and ledger modes | — |
| §5.4.1 Cross-party assurance | Independent cross-party rung claims and structural evidence for rederivation | — |
| §5.4.2 Cross-algorithm re-anchoring | Re-anchor Statements, verification hops and preservation of the original identity | — |
| §5.4.3 Provenance mode and backfilled records | Contemporaneous/backfilled records, required provenance and deduplication | `chain.relation` |
| §5.5 Disposition and the verdict reason-class | Decision, approver, human disposition, reason digest and expiry policy | `disposition.decision` |
| §5.5.1 The verdict_class vocabulary | Terminal-verdict reason classes | `verdict_class` |
| §5.5.2 Orthogonality with effect_mode | Verdict/effect pairing rules | — |
| §5.5.3 A Capsule on every verdict | Refusals and blocks as affirmative evidence | — |
| §5.5.4 Chained Capsules and human-in-the-loop resolution | Chain relations, superseding resolution and the open-items predicate | `chain.relation` |
| §5.5.5 Cross-record references | Content-addressed citations, purposes and verification | `citation_purpose` |
| §5.5.6 Retention declarations | Declared retention policy, evidence and verification limits | — |
| §6 Class 1 verification | Record-local checks and separate envelope, authorization and Receipt responsibilities | — |
| §7 Conformance: two verifier classes | Class 1 and manifest-aware Class 2 | — |
| §8 Manifest-dependent material | Constraint Records (§8.1) and Class 2 checks (§8.2) | — |
| §9 Extensibility | Namespacing (§9.1) and selective disclosure (§9.2) | — |
| §10 Related Work | Adjacent SCITT and agent-governance work | — |
| §11 Future Work | Extension directions | — |
| §12 IANA Considerations | Seven payload registries (§12.1), no new COSE/CWT registry (§12.2), media types (§12.3) | All seven |
| §13 Security Considerations | Tamper evidence, recorder honesty, observation, spoofing and digest leakage | — |
| §14 Privacy Considerations | Data-admission tiers (§14.1) and adapter allow-list pattern (§14.2) | — |
| §15 References | Normative and informative citations | — |

[Selective Disclosure Profile](draft-mih-scitt-agent-action-capsule-sel-disc-00.md)
defines `_sd_alg`/`_sd`, commitments, disclosure syntax and SD-1 through SD-6.
These members participate in the content-addressed Capsule form.

[Disclosure Envelope](draft-mih-agent-disclosure-envelope-00.md) defines the
out-of-band `capsule`/`disclosures` wrapper, disclosure-eligible digest fields
and DE-1 through DE-3. Its wrapper is outside the signed Capsule bytes and
does not change `capsule_id`; its field table determines eligibility.
