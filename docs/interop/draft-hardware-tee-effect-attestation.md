# Draft: hardware/TEE-anchored `effect_attestation` Registration Proposal

**Status:** DRAFT — for face-to-face discussion at RATS WG, IETF 126 (Vienna, Wed 22 Jul 2026)  
**DO NOT seed in the Internet-Draft before the WG session.**  
**Date:** 2026-06-29  
**Author:** Action State Group (AAC side); AEP reference-filler contribution: Tyche Institute  
**Registry:** `agent-action-capsule/spec/REGISTRY.md` §5 (`effect_attestation`)

---

## Background

The `effect_attestation` registry (REGISTRY.md §5) is initialized with two grades:

| Value | Grade meaning |
|---|---|
| `gate_executed` | The commit transited the gate; the engine observed the effect boundary directly. |
| `runtime_claimed` | The executing runtime asserted completion; the capsule records that claim. |

The registry preamble explicitly anticipates new registrations:

> *"Plausible future registrations exist and are deliberately NOT seeded here — e.g.
> independent sensor confirmation of a claimed effect, or hardware/TEE-anchored execution.
> A registration MUST state where its grade sits relative to the seeded values."*

The AAC ↔ AEP interop work with Anton Sokolov (Tyche, `draft-sokolov-rats-aep-composition`)
has identified **hardware/TEE-anchored execution** as the concrete first registration
for this "above `gate_executed`" slot. This document drafts that registration.

---

## Proposed registration

### Value

```
hardware_tee_attested
```

### Grade position

STRONGER than `gate_executed`. The grade order, ascending:

1. `runtime_claimed` — software claim only
2. `gate_executed` — gate observed the effect boundary; software-only root
3. **`hardware_tee_attested`** — hardware/TPM root of trust attests the execution
   environment; independent of the software stack

**Rationale for placing above `gate_executed`:** A gate-executed observation is
still software: the gate process makes the observation. Hardware attestation —
a TPM quote, a TEE measurement, a Veraison-verified RATS Evidence claim — provides
a root of trust that an adversary with OS-level access cannot forge. The grade is
strictly stronger.

**Grade-floor rule applies (registry preamble):** A verifier that does not
recognize `hardware_tee_attested` MUST treat it as no stronger than
`runtime_claimed` (the floor). This prevents grade-confusion attacks where an
unknown value is silently promoted.

### Semantics

`hardware_tee_attested` asserts that the executing environment for this action
was attested by a hardware root of trust at the time of execution. The capsule's
`effect.response_digest` commits the output of that execution. Evidence of the
hardware attestation is referenced by the capsule but not embedded in it (to
preserve content-privacy).

**Three concrete evidence sources that satisfy this grade:**

1. **RATS/TPM quote (RFC 9334):** A TPM PCR-extension or quote nonce binds the
   action's `capsule_id` or `response_digest` bytes. The quote is verified by
   a RATS verifier (e.g. Veraison) and the Attestation Result is authoritative.
   Reference: `draft-sokolov-rats-aep-composition` (AEP as filler for the quote).

2. **TEE measurement (e.g. Intel SGX, AMD SEV-SNP):** The enclave measurement
   commits the code that produced `response_digest`. An RA-TLS or DCAP quote
   proves the measurement; the relying party verifies against a reference value.

3. **Secure enclave signing key:** The effect output was signed by a key provisioned
   inside a TEE that refuses to export the key. The signature over `response_digest`
   is verified against the TEE-bound key's certificate.

### Producer requirements

A capsule carrying `effect_attestation: "hardware_tee_attested"` MUST:

1. Have `effect.status = "confirmed"` (the planned carve applies; no grade on a
   planned effect).
2. Have `effect.response_digest` present and correctly computed over the attested
   output.
3. Reference the hardware evidence externally, either:
   a. Via a future `effect.attestation_ref` field (not yet in the spec; to be
      proposed in a subsequent revision), or
   b. Via an out-of-band channel agreed between producer and verifier (acceptable
      for the initial AEP compose demonstration at IETF 126).

Producers MUST NOT use this grade unless an independent verifier can confirm the
hardware attestation. Self-assertion without a verifiable evidence chain degrades
the grade to `runtime_claimed` per the grade-floor rule.

### Verifier requirements

A verifier that implements the `hardware_tee_attested` grade MUST:

1. Treat the grade as opaque (no rejection) if it cannot verify the evidence —
   the never-reject invariant (REGISTRY.md preamble) applies.
2. If it CAN verify, confirm that the RATS Evidence or TEE measurement binds the
   `capsule_id` or `response_digest` in this capsule.
3. Report the attestation level in any human-readable verification output so the
   relying party can distinguish software-only from hardware-rooted records.

---

## Reference implementation path (AEP compose)

The `draft-sokolov-rats-aep-composition` architecture provides the reference filler
for `hardware_tee_attested` in the AAC compose:

```
AAC Capsule {
  effect.status: "confirmed"
  effect.response_digest: sha256(JCS(agent_output))     ← commits the output
  effect.effect_attestation: "hardware_tee_attested"    ← this registration
  # future: effect.attestation_ref: {
  #   type: "eatf:aep",
  #   hash: sha256(aep_package_bytes),
  #   uri: "https://verifier.example/aep/<attestation_id>"
  # }
}

AEP bundle (via EATF / draft-sokolov-rats-aep-composition) {
  response.txt: "capsule_id: c52a66d0…\nresponse_digest: 0ef1de7b…"
  hash.sha256: sha256(response.txt ∥ 0x0A ∥ JCS(metadata.json))
  + TPM quote nonce: raw_bytes(capsule_id) or raw_bytes(response_digest)
  + Veraison Attestation Result confirming the platform
}
```

The AEP `hash.sha256` + the TPM quote together constitute the hardware-attested
evidence that satisfies `hardware_tee_attested`. The SCITT receipt (Direction B
in the digest-binding spec) allows the AEP verifier to confirm the capsule was
also committed to the neutral transparency log.

---

## Registration preamble (for REGISTRY.md when ready)

**Candidate text for REGISTRY.md §5 addition (draft; DO NOT land until WG sign-off):**

> | `hardware_tee_attested` | The executing environment was attested by a hardware
> root of trust (TPM quote, TEE measurement, or TEE-bound signing key) at the time
> of execution. The `effect.response_digest` commits the output of that attested
> execution. Evidence is referenced externally. MUST be absent when
> `effect.status = "planned"`. Grade position: strictly above `gate_executed`.
> Reference: [this spec] §5; see also `draft-sokolov-rats-aep-composition`
> for the reference filler architecture. |

---

## Next steps

1. **Face-to-face at RATS WG (Wed 22 Jul, IETF 126 Vienna):** Present this draft
   alongside the live cross-verify result from the hackathon (18–19 Jul).
   The working group discussion should validate: (a) the grade position above
   `gate_executed`, (b) the verifier requirements, (c) whether a new
   `effect.attestation_ref` field belongs in the AAC spec or is left to extension.

2. **After WG consensus:** Seed the value into REGISTRY.md §5 and reference
   it in a subsequent revision of the Internet-Draft.

3. **AAC spec revision:** Propose `effect.attestation_ref` as an optional field
   in the `effect` block for future versions, to formalize the evidence reference
   channel.

---

## IP statement

AAC content (grade vocabulary, registry preamble, this proposal) is copyright
Action State Group, Inc. under IETF trust200902.  
The description of `draft-sokolov-rats-aep-composition` and the AEP compose
architecture is attributed to Tyche Institute and its authors; no Tyche AEP IP
is asserted here. The AEP format is referenced only for the interoperability
architecture; this proposal does not define or modify the AEP format.
