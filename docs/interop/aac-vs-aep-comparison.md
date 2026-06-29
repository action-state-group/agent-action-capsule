# AAC vs AEP — What Each Proves

**Date:** 2026-06-29  
**Context:** AAC ↔ AEP interop with Anton Sokolov (Tyche, `draft-sokolov-rats-aep-composition`)  
**Audience:** IETF 126 Hackathon / RATS WG face-to-face, Vienna, July 2026  
**Boundary:** Public-safe, neutral. Tyche AEP IP not reproduced; AAC side trust200902.

---

## What each record proves

| Property | AAC (Agent Action Capsule) | AEP (Agent Evidence Package) |
|---|---|---|
| **Full name** | Agent Action Capsule, `draft-mih-scitt-agent-action-capsule` | Agent Evidence Package, `draft-sokolov-rats-aep-composition` |
| **What it records** | A consequential agent action: what was decided, what model ran it, what effect was dispatched, all committed by digest | An AI agent response: the text output, the policy applied, the agent identity, timestamped by a TSA |
| **Primary attestation mechanism** | Software self-attestation (the gate/runtime seals what it observed); neutral SCITT transparency log for independent verification | PKI signatures (RSA-4096 + ML-DSA-65 dual-sig); RFC 3161 TSA timestamp; optionally hardware/TPM evidence via RATS composition |
| **Content privacy** | Yes — only SHA-256 digests of agent input/output leave the operator's boundary; the capsule contains commitments, not payloads | AEP v1: `response.txt` is included in the bundle (content visible to verifier); privacy is a policy/access-control concern, not a structural property |
| **TPM / hardware root required?** | No — works with no TPM; hardware attestation is a designed future `effect_attestation` grade (see §5 and the registration proposal) | Core AEP does not require hardware; TPM/RATS is an additive composition layer (`draft-sokolov-rats-aep-composition`) |
| **Transparency log / public verifiability** | Yes — every capsule is anchored in a neutral SCITT log (RFC 9162 CT structure); any third party can verify the inclusion receipt without contacting the operator | Not in core AEP v1; ledger is per-tenant, hash-chained but operator-hosted; an external transparency service is not part of the base spec |
| **Agent identity binding** | Developer (`developer` field) and operator (`operator`) committed to `capsule_id`; model identity committed via `model_attestation` | Agent identity via `urn:eatf:tenant:…:agent:<slug>` in `metadata.json`; PKI certificate chains to the EATF issuer |
| **Action/effect record** | Rich — `effect.type`, `effect.status`, `response_digest`, `verdict_class`, `disposition`; the "did it actually run and what was the outcome" question | Action type via `action_type` and `policy_id`; policy coverage recorded; no effect confirmation digest in core v1 |
| **Chaining / provenance chain** | Native — `chain.relation` links a capsule to its parent (`confirms`, `supersedes`); sequences of capsules form a verifiable chain | `overt_receipt.json` has a `prev` field for hash-chaining; core v1 does not require multi-capsule chains |
| **Regulatory framing** | IETF standard track (SCITT WG); not EU AI Act-specific | Explicitly EU AI Act Art. 10/12/13/14 mapped; ETSI/eIDAS alignment; compliance reporting output |
| **Verification without network** | Yes — capsule JSON is self-contained for Class 1 (format + digest) verification; Class 2 requires manifest; SCITT receipt can be verified offline against the cached STH | Yes — AEP v1 design goal: "offline verifiable evidence bundle"; verifier needs only the bundle and the public key |
| **Post-quantum readiness** | Not yet in spec; roadmap item | ML-DSA-65 (NIST PQC) already in AEP v1 alongside RSA-4096 (dual-sig) |

---

## Where each is stronger

### AAC is stronger for:

1. **Content-private attestation.** The capsule commits agent I/O by digest; the raw bytes never leave the operator's boundary. An auditor gets proof that a specific input produced a specific output — without receiving the input or the output.

2. **Neutral transparency anchoring.** The SCITT log is neutral (not the operator's own hash chain), public, and independently verifiable by any party with the receipt and the anchor's public key. The anchor does not need to trust the capsule emitter.

3. **No hardware dependency.** The capsule is sealed by the gate/runtime and verified against the SCITT log — no TPM or secure enclave is required. This makes AAC deployable in any environment: cloud, on-prem, edge, or partner-hosted.

4. **Structured action semantics.** `verdict_class`, `disposition`, `effect.type`, `chain.relation`, and the `effect_attestation` grade vocabulary give auditors precise answers about *what the agent decided*, not just *what it output*.

5. **Composable with policy manifests.** Class 2 verification checks the capsule against a declared manifest of allowed action types, operators, and effect grades. This enables the in-toto / SLSA supply-chain pattern applied to agent actions.

### AEP is stronger for:

1. **Hardware/TEE root of trust.** The RATS composition (`draft-sokolov-rats-aep-composition`) binds the AEP bundle to a hardware attestation (swtpm → Veraison), giving a platform-attested evidence trail. This is irreducible — no software layer can forge a valid TPM quote.

2. **EU AI Act compliance framing.** AEP maps explicitly to Articles 10, 12, 13, 14 and the ETSI/eIDAS standards. For regulated workflows in EU jurisdictions, this framing is pre-aligned.

3. **PKI verifier interoperability.** The RSA-4096 + ML-DSA-65 + RFC 3161 substrate is verifiable by any standard PKI toolchain without SCITT-specific infrastructure.

4. **Post-quantum signature coverage.** ML-DSA-65 is already mandatory-planned for v2; the dual-sig scheme provides algorithm agility today.

5. **Offline-first design.** The AEP bundle contains everything needed to verify without any network call (keys, timestamps, signatures). The AAC Class 1 verifier is also offline, but SCITT inclusion proof verification needs the anchor's public key (cacheable).

---

## The compose seam

These are complementary, not competing. The designed compose point is:

> **An AAC capsule that records a hardware-attested effect** by referencing AEP/RATS
> evidence via digest in the `effect_attestation` field.

Concretely:
- The agent action runs inside a TEE / on a platform with a TPM.
- The AEP/RATS quote attests the execution environment.
- The AAC capsule seals the action semantics (what was decided, what ran, what effect).
- The capsule's `effect_attestation` field carries a value like `hardware_tee_attested`
  (proposed future registration, see `docs/interop/draft-hardware-tee-effect-attestation.md`).
- The capsule optionally references the AEP attestation by digest in a future extension field.

This is not currently registered; the hardware/TEE grade is a **deliberately unseeded
planned value** in the `effect_attestation` registry (§5, REGISTRY.md), admitted once
a specification pins its semantics. That registration is the artifact this interop
is producing.

---

## Cross-verify matrix (what we can verify NOW)

| Cross-verify | Status | Method |
|---|---|---|
| AAC capsule_id determinism | ✅ Done | SHA-256(JCS(capsule)) recomputed; matches |
| AAC capsule passes `agent-action-capsule verify` | ✅ Done | `findings: none` |
| AAC capsule anchored in SCITT | ✅ Done | Receipt obtained; leaf_index=2, tree_size=3 |
| AEP `hash.sha256` computation spec | ✅ Understood | SHA-256(response.txt ∥ 0x0A ∥ JCS(metadata.json)); per EATF aep-profile-v1 |
| AEP minimal-roundtrip test vector | ✅ Inspected | Confirms format; offline-verifiable; uses dev RSA key |
| AEP bundle containing our capsule_id | ⏳ Pending | Anton produces at hackathon |
| TPM quote binding our capsule_id bytes | ⏳ Pending | Live cross-verify at IETF 126 (swtpm → Veraison) |
| AAC receipt verified by Anton's toolchain | ⏳ Pending | Requires his verifier to speak RFC 9162 COSE Receipt |
| Full bidirectional in a single action | ⏳ Target | Hackathon day 1 deliverable |

---

## IP boundary

- AAC content (this document, the capsule format, the REGISTRY.md §5 registration proposal)
  is copyright Action State Group, Inc. under IETF trust200902.
- AEP format, EATF schema, Tyche Institute tooling, and any descriptions of
  `draft-sokolov-rats-aep-composition` are the intellectual property of Tyche Institute
  and their respective authors. This document describes the AEP format only to the extent
  necessary for interoperability; no Tyche AEP IP is asserted or reproduced beyond
  the publicly available Internet-Draft and `tyche-institute/eatf` repository (MIT License).
- Joint text (if produced) should preserve attribution on both sides with explicit IP
  carve-outs in the preamble.
