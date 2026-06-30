# AAC ↔ AEP Interop — Minted Capsule Artifacts

**Date:** 2026-06-29
**Purpose:** Live capsule minted for the Anton Sokolov (Tyche / `draft-sokolov-rats-aep-composition`) ↔
AAC bidirectional cross-verify binding. Steven committed "this week" to deliver these to Anton.

**Canonical example: a procurement payment.** A purchase is the textbook consequential action
(money moves) — the exact case the permit → action → record → platform chain exists for, and the
natural permit-before case for Lee's PermitReceipt layer. The capsule binds both the **prompt**
(what the agent was asked) and the **output** (what it did) by digest; only the hashes travel, so
the invoice amount, vendor, and payment ID stay private (`prompt.json` / `output.json` are the
preimages, kept locally / shared only as needed).

> **Status:** capsule minted, **verifies locally** (ok, findings: none; all digests reproduce from preimages),
> and **anchored** 2026-06-29 at `anchor.agentactioncapsule.org` (leaf_index=3, tree_size=4).
> `receipt_b64` is live below — Direction B is ready for Anton.

Files: `docs/interop/purchase-example/{prompt.json, output.json, capsule.json}`

---

## PRIMARY DELIVERABLE — Hand these to Anton

### capsule_id

```
29b9a5569bc99585628040e3f262a3087809ce0044c79dbab98b5c7e9cae181b
```

### response_digest (the "did" — the field Anton binds into his AEP/swtpm quote)

```
248cdd0827f66d2ac5dfa46cfb58d5d0a48c254a237ce4422a4345f33b53f56e
```

SHA-256 of the agent_output JSON (JCS-canonical, no salt), hex-lowercase. Preimage: `output.json`
— the payment decision ($4,250.00 ACH to Acme Office Supplies, invoice INV-2026-0418, status submitted).

### request_digest / prompt digest (`agent_input_digest` — optional, for direction-B binding)

```
e4e17626f890da25d269e1a6e80c6c9b5e43403a38f5bdf76fc80e882eadcd08
```

SHA-256 of the agent_input JSON (JCS-canonical). Preimage: `prompt.json` — the instruction
"pay approved invoice INV-2026-0418 … only if approved AND amount matches the linked PO."

### SCITT receipt (live anchor `anchor.agentactioncapsule.org`, leaf_index=3, tree_size=4)

Anchored 2026-06-29. Anchor: `https://anchor.agentactioncapsule.org/v1/digest`  
Storage: Postgres-backed. Key_id: `39bb654c9dc0afe1` (Ed25519).

```json
{
  "receipt_b64": "0oRHogEnGQGLAaEZAYyhIIFYSIMEA4JYIM6ef1L3fWsfmekhxus/h/CvzFR+NmhRoIj5tNPqybstWCBWrtv+syZpMz1A0QgGO5XHNJwp7vkvenEv+7zJOyjwd/ZYQNiJOU57SscGqnCtnZ8daxKse/BXLZF9Ks3+5UcP4jy/7ydfQ80DV3BGaW9Uknfi5DdSypRtBuzDRGNc6/u+Egc=",
  "entry_hash": "8767e07982b43db647cb39451719c07364a13444cce0b0003854c270f27317e5",
  "leaf_index": 3,
  "tree_size": 4
}
```

`receipt_b64` is a COSE Receipt (RFC 9162 CT log inclusion proof, Merkle + Ed25519 over the STH).
Anton verifies: decode → check inclusion proof resolves `capsule_id` at `leaf_index=3, tree_size=4`
→ verify Ed25519 STH sig against anchor's published pubkey.

### Anchor verifying key (hand to Anton for Direction B)

```
key_id        : 39bb654c9dc0afe1     (= first 8 bytes of the raw key)
Ed25519 JWK x : ObtlTJ3Ar-HA7e8N7_qmkJm4UYg2ybom4EkVNYQPlrU
raw hex       : 39bb654c9dc0afe1c0edef0deffaa69099b8518836c9ba26e0491535840f96b5
resolve at    : https://anchor.agentactioncapsule.org/.well-known/did.json
                https://anchor.agentactioncapsule.org/anchor/authority-pubkey
```

(NOTE: correct pubkey path is `/.well-known/did.json` + `/anchor/authority-pubkey`. An earlier draft
pointed at `/attest/pubkey`, which does not exist — fixed 2026-06-29.)

---

## Full capsule JSON (format_version "2", spec -01)

```json
{
  "spec_version": "draft-mih-scitt-agent-action-capsule-01",
  "format_version": "2",
  "capsule_id": "29b9a5569bc99585628040e3f262a3087809ce0044c79dbab98b5c7e9cae181b",
  "action_id": "send_payment/fa929685-6db1-4332-ae6b-3b11e6a14e21",
  "action_type": "decide",
  "domain": "action",
  "operator": "action-state-group",
  "developer": "procurement-agent@v1",
  "timestamp": "2026-06-29T20:05:26.527286Z",
  "model_attestation": {
    "model_id": "claude-sonnet-4-6",
    "provider": "anthropic",
    "compute_attestation": {
      "agent_input_digest": "e4e17626f890da25d269e1a6e80c6c9b5e43403a38f5bdf76fc80e882eadcd08",
      "agent_output_digest": "248cdd0827f66d2ac5dfa46cfb58d5d0a48c254a237ce4422a4345f33b53f56e"
    }
  },
  "effect": {
    "status": "confirmed",
    "type": "send_payment",
    "irreversibility_class": "one_way_consequential",
    "response_digest": "248cdd0827f66d2ac5dfa46cfb58d5d0a48c254a237ce4422a4345f33b53f56e",
    "effect_attestation": "runtime_claimed"
  },
  "assurance": {
    "attestation_mode": "self_attested",
    "effect_mode": "confirmed",
    "ledger_mode": "standalone"
  },
  "disposition": {
    "decision": "accept",
    "approver": "policy",
    "human_disposed": false,
    "verdict_class": "executed"
  }
}
```

Honest grading note: `effect_attestation: runtime_claimed` / `attestation_mode: self_attested` —
the capsule claims no hardware. That is the point: composing with Anton's AEP is what would grade
it up (the `hardware_tee_attested` candidate, RATS WG face-to-face). The capsule demonstrates the
5.2 grade-floor invariant rather than working around it.

---

## Capsule_id derivation (for Anton's cross-verify)

`capsule_id` is SHA-256 of the JCS-canonical (RFC 8785) form of the capsule JSON **excluding** the
`capsule_id` field itself, hex-lowercase. Both the Python reference (`agent_action_capsule.jcs` +
`compute_capsule_id`) and the Go implementation are byte-identical for this capsule form.

```python
import hashlib
from agent_action_capsule import jcs, compute_capsule_id
import json
cap = json.load(open("capsule.json"))
assert compute_capsule_id({k:v for k,v in cap.items() if k!="capsule_id"}) == cap["capsule_id"]
# preimage digests:
assert hashlib.sha256(jcs(json.load(open("prompt.json")))).hexdigest() == cap["model_attestation"]["compute_attestation"]["agent_input_digest"]
assert hashlib.sha256(jcs(json.load(open("output.json")))).hexdigest() == cap["effect"]["response_digest"]
```

---

## Verification

```
Store-level verification of 1 capsule(s):
  [0] ok: True
  capsule_id (recomputed): 29b9a5569bc99585628040e3f262a3087809ce0044c79dbab98b5c7e9cae181b
  derived: effect_mode=confirmed attestation_mode=self_attested ledger_mode=standalone
  findings: none
```

Prompt digest, response digest, and capsule_id all reproduce from the preimages (verified
2026-06-29).

---

## How Anton uses these

See `docs/interop/aac-aep-digest-binding.md` for the full bidirectional protocol. Short version:

1. He takes our `capsule_id` + `response_digest` and includes them in his AEP attestation
   (`response.txt` / `metadata.json` — agreed encoding in the binding doc).
2. His AEP `hash.sha256` then commits to a document referencing our capsule — binding AEP evidence
   to the AAC record.
3. He verifies our receipt (COSE Receipt, RFC 9162) once anchored — confirming `capsule_id` is in
   the SCITT log.
4. We verify his AEP bundle by confirming `hash.sha256` covers a document containing our
   `capsule_id` + `response_digest`.
