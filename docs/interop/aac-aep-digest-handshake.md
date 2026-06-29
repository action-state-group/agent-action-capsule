# AAC ↔ AEP Digest Handshake Specification

**Status:** Pinned protocol — agreed for the Anton Sokolov (Tyche) live cross-verify  
**Date:** 2026-06-29  
**Live cross-verify scheduled:** IETF 126 Hackathon, Vienna, 18–19 July 2026  
**Applicable to:** `draft-mih-scitt-agent-action-capsule-01` ↔ `draft-sokolov-rats-aep-composition`

---

## Purpose

This document pins the digest-handshake protocol so that the bidirectional cross-verify
passes on first attempt. It specifies which AAC fields Anton binds into an AEP/TPM
quote, which AEP fields the AAC side verifies, and the exact byte encoding on both sides.

---

## Digest field reference

### AAC side (purchase capsule — the artifact handed to Anton)

| Field path | Value (hex-lowercase, 64 chars) | Meaning |
|---|---|---|
| `capsule_id` | `29b9a5569bc99585628040e3f262a3087809ce0044c79dbab98b5c7e9cae181b` | SHA-256 of canonical capsule — the primary content address |
| `effect.response_digest` | `248cdd0827f66d2ac5dfa46cfb58d5d0a48c254a237ce4422a4345f33b53f56e` | SHA-256 of agent_output (the "did" — digest-of-id for the payment decision) |
| `model_attestation.compute_attestation.agent_input_digest` | `e4e17626f890da25d269e1a6e80c6c9b5e43403a38f5bdf76fc80e882eadcd08` | SHA-256 of agent_input (procurement prompt) |

**Example:** a procurement payment — pay approved invoice INV-2026-0418, $4,250.00 ACH to
Acme Office Supplies. Status: confirmed, dispatched. Preimages in `docs/interop/purchase-example/`.

All AAC digests are **SHA-256, hex-lowercase, 64 characters**. No salt was applied
(`salt_digests=False`) — digests are deterministic and reproducible from the preimage JSON files.
The JSON input was serialized with `sort_keys=True, separators=(",",":")` before hashing (JCS-compatible).

### AEP side (Anton's bundle)

| Field path | Encoding | Meaning |
|---|---|---|
| `metadata.json → attestation_id` | ULID string | Unique AEP attestation identifier |
| `hash.sha256` | hex-lowercase, 64 chars | SHA-256 of `canonical.bin` = `response.txt` ∥ `0x0A` ∥ JCS(`metadata.json`) |
| Receipt `receipt_b64` (our SCITT receipt) | Base64-standard | COSE Receipt proving capsule_id was registered |

---

## Encoding agreement (explicit)

**Both sides MUST agree on these encoding points:**

| Concern | Agreed encoding |
|---|---|
| Hash algorithm | SHA-256 |
| Digest representation **in JSON** | hex-lowercase string (64 chars) — e.g. `"c52a66d0…"` |
| Digest representation **in AEP quote / PCR extension / swtpm nonce** | **raw bytes** (32 bytes binary), NOT the hex string |
| JSON input for digest computation | JCS-canonical form: `sort_keys=True, separators=(",",":")`, no BOM, UTF-8 |
| Capsule body for `capsule_id` derivation | All fields except `capsule_id` itself, JCS-sorted |
| Receipt format | COSE Receipt per RFC 9162 (CT Merkle + Ed25519), Base64-standard |

**Critical:** The raw-bytes-in-quote / hex-in-JSON distinction is where cross-format
verifiers most commonly misalign. The nonce or PCR-extension in an swtpm quote is
binary; the `capsule_id` in the capsule JSON and the `hash.sha256` in AEP metadata
are both hex strings. Confirm at the wire level before first cross-verify.

---

## Direction A — Anton binds our capsule into his AEP/TPM quote

**What he does:**

1. Takes our `capsule_id` (hex string) and `response_digest` (hex string) from
   `docs/interop/aac-aep-interop-artifacts.md`.
2. Constructs an AEP `response.txt` that references our capsule, e.g.:

   ```
   AAC capsule_id: 29b9a5569bc99585628040e3f262a3087809ce0044c79dbab98b5c7e9cae181b
   AAC response_digest: 248cdd0827f66d2ac5dfa46cfb58d5d0a48c254a237ce4422a4345f33b53f56e
   AAC spec: draft-mih-scitt-agent-action-capsule-01
   AAC action: procurement payment (send_payment/INV-2026-0418)
   ```

3. (If using swtpm/RATS layer) Folds the raw bytes of `capsule_id` and/or `response_digest`
   as a nonce or PCR-extension in the TPM quote. The raw-bytes form is:

   ```python
   capsule_id_bytes = bytes.fromhex("29b9a5569bc99585628040e3f262a3087809ce0044c79dbab98b5c7e9cae181b")
   response_digest_bytes = bytes.fromhex("248cdd0827f66d2ac5dfa46cfb58d5d0a48c254a237ce4422a4345f33b53f56e")
   # Concatenate or use individually as nonce material in the TPM quote
   ```

4. The resulting AEP bundle + its TPM quote commits to our `capsule_id`. He sends us
   the AEP `hash.sha256` + the TPM quote evidence.

**What we verify:**

1. His AEP `hash.sha256` is SHA-256 of `canonical.bin` (= `response.txt` ∥ LF ∥ JCS(metadata)).
2. The `response.txt` in that canonical form contains our `capsule_id` + `response_digest`.
3. (If TPM layer) The quote nonce contains `capsule_id_bytes` or `response_digest_bytes`.
4. The AEP `hash.sha256` can be recomputed independently — verifier MUST refuse if mismatch.

---

## Direction B — We anchor in SCITT; Anton verifies the receipt resolves

**What we provide:**

The SCITT receipt from `docs/interop/aac-aep-interop-artifacts.md` (anchored 2026-06-29):

```json
{
  "receipt_b64": "0oRHogEnGQGLAaEZAYyhIIFYSIMEA4JYIM6ef1L3fWsfmekhxus/h/CvzFR+NmhRoIj5tNPqybstWCBWrtv+syZpMz1A0QgGO5XHNJwp7vkvenEv+7zJOyjwd/ZYQNiJOU57SscGqnCtnZ8daxKse/BXLZF9Ks3+5UcP4jy/7ydfQ80DV3BGaW9Uknfi5DdSypRtBuzDRGNc6/u+Egc=",
  "entry_hash": "8767e07982b43db647cb39451719c07364a13444cce0b0003854c270f27317e5",
  "leaf_index": 3,
  "tree_size": 4
}
```

Anchor public key (`key_id: 39bb654c9dc0afe1`):

```
GET https://anchor.agentactioncapsule.org/attest/pubkey
GET https://anchor.agentactioncapsule.org/.well-known/did.json
```

**What Anton verifies:**

1. Decode `receipt_b64` as a COSE Receipt (COSE_Sign1 with an inclusion proof in the
   unprotected header, per RFC 9162 §4).
2. Confirm the inclusion proof resolves `capsule_id` at `leaf_index=3` in a log of
   `tree_size=4` under the signed tree head.
3. Verify the Ed25519 signature over the STH using the anchor's published public key
   (`key_id: 39bb654c9dc0afe1`).
4. Confirm the root hash in the STH matches his independently-computed Merkle root.

**Anchor log query (live):**

```bash
# Verify the capsule is in the log
curl -s "https://anchor.agentactioncapsule.org/anchor/inclusion-proof?leaf_index=3"
# Get the current STH
curl -s "https://anchor.agentactioncapsule.org/anchor/sth"
```

---

## Composability: full four-layer digest thread

```
PermitReceipt.action_digest
        │
        ▼
AAC capsule_id ←────────── SHA-256(JCS(capsule JSON \ {capsule_id}))
        │
        ├─ effect.response_digest ←── SHA-256(JCS(agent_output))  ← folded into AEP response.txt
        │                                                              and optionally TPM nonce
        └─ SCITT receipt ←─────────── RFC 9162 inclusion proof over capsule_id
                                      → AEP verifier cross-checks receipt_b64

AEP hash.sha256 ←────────── SHA-256(response.txt ∥ 0x0A ∥ JCS(metadata.json))
        │                   where response.txt contains our capsule_id + response_digest
        └─ TPM/swtpm quote ←── nonce or PCR-ext = raw bytes of capsule_id or response_digest
                               → Veraison verifies the quote
```

The same SHA-256 digest threads all four layers. No separate hash-of-hashes is needed;
`capsule_id` is already the content address of the full capsule, and `response_digest`
is already the content address of the output that the AEP response text repeats.

---

## Summary checklist for first cross-verify (hackathon day 1)

- [x] Capsule minted (purchase payment, `capsule_id: 29b9a556…e181b`) — 2026-06-29
- [x] Anchored at `anchor.agentactioncapsule.org` (`leaf_index=3, tree_size=4`) — 2026-06-29
- [ ] Anton has received `capsule_id` + `response_digest` + `receipt_b64` (from artifacts doc) — Steven to send
- [ ] Anton confirms raw-bytes-in-quote / hex-in-JSON encoding
- [ ] Anton confirms which AEP canonicalization his live signer uses (v0.1 response-only vs v1 response+LF+JCS)
- [ ] Anton produces AEP bundle with our `capsule_id` + `response_digest` in `response.txt`
- [ ] We confirm his `hash.sha256` covers a document containing our fields
- [ ] We decode his TPM quote and confirm the nonce/PCR-ext matches our digest bytes
- [ ] Anton decodes our `receipt_b64` and verifies the Ed25519 STH signature
- [ ] Anton confirms inclusion proof resolves at `leaf_index=3, tree_size=4`
- [ ] Both sides confirm: one SHA-256 threads the full chain
