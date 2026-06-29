# AAC ↔ AEP Digest Threading — One-Page Figure

**Permit · Action · Record-Anchor · Platform-Attest**  
The SAME SHA-256 digest threads all four layers.

---

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     PERMIT (upstream gate / policy)                         │
│                                                                             │
│  PermitReceipt {                                                            │
│    action_digest: sha256(action_request_bytes)   ──────────────────┐        │
│    receipt: <SCITT inclusion proof>                                 │        │
│  }                                                                  │        │
└─────────────────────────────────────────────────────────────────────│───────┘
                                                                      │
                                          same digest flows down ─────▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     ACTION (agent runs; capsule sealed)                     │
│                                                                             │
│  AAC Capsule {                                                              │
│    capsule_id:       sha256(JCS(capsule \ {capsule_id}))   ◄─── content     │
│                      = c52a66d0…c7635                            address    │
│                                                                             │
│    request_digest:   sha256(JCS(agent_input))                               │
│                      = b5a448d0…34bd3   ◄── binds what the agent was told  │
│                                                                             │
│    response_digest:  sha256(JCS(agent_output))    ◄─── the "did"           │
│    (effect.response_digest)                             digest-of-output    │
│                      = 0ef1de7b…f2f41a                                      │
│  }                                                                          │
└───────────────────┬─────────────────────────┬───────────────────────────────┘
                    │                         │
         capsule_id anchored            response_digest
         to SCITT log                  handed to AEP layer
                    │                         │
                    ▼                         ▼
┌───────────────────────────────┐  ┌──────────────────────────────────────────┐
│  RECORD-ANCHOR (SCITT log)    │  │  PLATFORM-ATTEST (AEP / swtpm / RATS)   │
│                               │  │                                          │
│  /v1/digest POST              │  │  AEP bundle {                            │
│    { capsule_id: "c52a…" }    │  │    response.txt:                         │
│                               │  │      "capsule_id: c52a66d0…c7635        │
│  Receipt {                    │  │       response_digest: 0ef1de7b…f2f41a" │
│    receipt_b64: "0oRH…"  ◄──  │  │                                          │
│    leaf_index: 2              │  │    hash.sha256:                          │
│    tree_size: 3               │  │      sha256(response.txt ∥ 0x0A          │
│    entry_hash: "d012…"        │  │             ∥ JCS(metadata.json))        │
│  }                            │  │                                          │
│                               │  │    TPM quote (swtpm → Veraison) {        │
│  Anchor: Ed25519 key          │  │      nonce: raw_bytes(capsule_id) or     │
│  key_id: 39bb654c9dc0afe1     │  │             raw_bytes(response_digest)   │
│                               │  │    }                                     │
└───────────────────┬───────────┘  └──────────────────────────┬───────────────┘
                    │                                          │
                    └──────────────┬───────────────────────────┘
                                   │
                                   ▼
                ┌──────────────────────────────────────────┐
                │    CROSS-VERIFY (both sides; hackathon)  │
                │                                          │
                │  Anton verifies:                         │
                │  • receipt_b64 inclusion proof resolves  │
                │    capsule_id at leaf 2, tree_size 3     │
                │  • Ed25519 sig over STH is valid         │
                │                                          │
                │  We verify:                              │
                │  • his AEP hash.sha256 covers a doc      │
                │    containing our capsule_id             │
                │  • his TPM quote nonce = our digest bytes│
                │                                          │
                │  ENCODING AGREEMENT (explicit):          │
                │  • In JSON/AEP metadata: hex-lowercase   │
                │  • In TPM quote nonce:   raw 32 bytes    │
                │  • Hash algorithm:       SHA-256         │
                └──────────────────────────────────────────┘
```

---

## Reading the figure

**One invariant:** every arrow that crosses a layer boundary carries the SAME
SHA-256 digest, in one of two representations (hex string in JSON, raw bytes in
hardware structures). There is no hash-of-hashes, no translation function, no
format conversion — the digest is the same value.

**Why this matters:** a verifier at any layer can confirm the full chain without
any privileged access to the layers above or below it. The SCITT anchor does not
see the agent output; the TPM does not know the SCITT receipt; yet all four layers
are cryptographically bound by the digest thread.

---

## Layer-by-layer digest ownership

| Layer | Digest produced | Digest consumed |
|---|---|---|
| Permit | `action_digest = sha256(request_bytes)` | ← may flow into `request_digest` |
| Action (AAC) | `capsule_id = sha256(JCS(capsule))` | ← `action_digest` from Permit (optional) |
| Action (AAC) | `response_digest = sha256(JCS(output))` | |
| Record-Anchor (SCITT) | Merkle root over `capsule_id` entries | ← `capsule_id` |
| Record-Anchor (SCITT) | `receipt_b64` (COSE Receipt, Ed25519) | |
| Platform-Attest (AEP) | `hash.sha256 = sha256(response.txt ∥ JCS(metadata))` | ← `capsule_id`, `response_digest` (in response.txt) |
| Platform-Attest (TPM) | TPM quote signed by EK/AK | ← `capsule_id` raw bytes as nonce |

---

## For the co-authored one-pager (face-to-face at IETF 126)

This figure is intended as the visual anchor for the joint discussion with Anton.
The narrative:

> *"Permit, Action, Record-Anchor, Platform-Attest: each layer binds the same
> SHA-256 digest. The agent action capsule is the bridge: it is both the record
> that the SCITT log anchors and the document that the AEP bundle references.
> Verifying any one layer gives you a chain of custody to all the others."*

IP: AAC portion (left column, SCITT layer) is trust200902.
AEP / Tyche portion (right column, RATS layer) is carved out — Tyche IP,
not asserted here; described only for interoperability alignment.
