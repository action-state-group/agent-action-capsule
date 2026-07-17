# AAC PermitReceipt + MachineMandate Binding Profile

**Status:** OWNER-PROPOSED — REVIEW PENDING — NOT AGREED — NOT A RESULT  
**Date:** 2026-07-17  
**Live cross-verify target:** three-way run by 2026-07-21  
**Applicable to:** `draft-mih-scitt-agent-action-capsule-02`

---

## 1. Purpose

This profile pins the digest-binding semantics for a three-way composition:

1. **PermitReceipt** — a permit authority credential; represents the approved
   request (e.g., a payment authorization with currency and amount in EUR minor units).
2. **MachineMandate** — an AEP authority credential; represents the
   delegated scope for the action (e.g., a maximum spend limit in EUR minor units).
3. **AAC capsule** — the Agent Action Capsule that records the AI agent action that
   consumed both.

The goal is a single capsule that cryptographically binds all three artifacts so that
any verifier can confirm the agent acted within both the PermitReceipt it was given
and the MachineMandate under which it was delegated.

---

## 2. Binding location — `effect.authorization` payload extension

This profile binds PermitReceipt and MachineMandate via **two typed references** in a
namespaced payload extension under `effect.authorization`.  It does NOT overload
`effect.request_digest` or `effect.response_digest`, which retain their -02 semantics:

| Field | -02 semantics (unchanged) |
|---|---|
| `effect.request_digest` | JSON-DIGEST of the actual protected-action request, when present |
| `effect.response_digest` | JSON-DIGEST of the actual observed response (REQUIRED when `status: "confirmed"`) |

The authorization references live alongside these fields:

| Extension field | Bound artifact |
|---|---|
| `effect.authorization.permit_receipt_digest` | Typed reference to PermitReceipt |
| `effect.authorization.machine_mandate_digest` | Typed reference to MachineMandate |

### Why these references are signature-covered

`capsule_id` is defined as:

```
capsule_id = SHA-256(JCS(capsule_body \ {capsule_id, chain}))
```

The `effect` sub-object — including `effect.authorization` and both typed references
inside it — is inside the capsule body, and therefore inside the JCS hash.  Any
post-emission change to either reference produces a different `capsule_id`.

---

## 3. Typed reference schema

Each authorization reference is a JSON object with the following fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | REQUIRED | Artifact type identifier, e.g. `"PermitReceipt"` or `"MachineMandate"` |
| `digest_alg` | string | REQUIRED | Hash algorithm identifier, e.g. `"SHA-256"` |
| `digest` | string | REQUIRED | 64-char lowercase hex SHA-256 of the canonical companion document |

Additional fields (e.g., `profile`, `action_hash`) MAY be present; verifiers MUST
ignore unrecognized fields.

### Preimage definition

The digest is computed over the JCS-canonical form of the companion JSON document:

1. Apply absent-field normalization: remove `null` values and empty containers
   bottom-up.
2. Serialize with RFC 8785 JCS: sort keys by UTF-16 code-unit order, compact
   separators, UTF-8, no BOM.
3. Compute SHA-256 of the resulting bytes; encode as lowercase hex (64 chars).

### SD-JWT preimage

When the companion document is an SD-JWT, use the exact bytes of the
**issuer-signed JWT component** (the `~` separated JWT before the holder
presentation suffix).  NEVER hash the holder-presentation/KB bytes or an unsigned
companion descriptor — only the issuer-signed component is deterministic.

---

## 4. Resolution and comparison procedure

The companion documents are provided as parsed JSON objects alongside the capsule.
The verifier resolves and passes them in; they are not fetched from a network.

### Step-by-step for each reference

**PermitReceipt → `effect.authorization.permit_receipt_digest`**

1. Locate `capsule.effect.authorization`.  If absent or not an object, FAIL at gate
   `permit_receipt_bound`.
2. Locate `.permit_receipt_digest`.  If absent, FAIL at gate `permit_receipt_bound`.
3. Confirm `.permit_receipt_digest` is an object containing `type`, `digest_alg`,
   and `digest`.  If any field is missing, FAIL at gate `permit_receipt_bound`.
4. Confirm `.type == "PermitReceipt"`.  FAIL on mismatch.
5. Apply absent-field normalization to the PermitReceipt companion document.
6. Serialize with RFC 8785 JCS.
7. Compute SHA-256; encode as 64-char lowercase hex.
8. Compare to `.digest`.  FAIL on mismatch.

**MachineMandate → `effect.authorization.machine_mandate_digest`**

1. Locate `capsule.effect.authorization`.  If absent or not an object, FAIL at gate
   `machine_mandate_bound`.
2. Locate `.machine_mandate_digest`.  If absent, FAIL at gate `machine_mandate_bound`.
3. Confirm `.machine_mandate_digest` is an object with `type`, `digest_alg`, `digest`.
   FAIL on any missing field.
4. Confirm `.type == "MachineMandate"`.  FAIL on mismatch.
5. Apply absent-field normalization to the MachineMandate companion document.
6. Serialize with RFC 8785 JCS.
7. Compute SHA-256; encode as 64-char lowercase hex.
8. Compare to `.digest`.  FAIL on mismatch.

Both references are evaluated independently.

---

## 5. Fail-closed gates

| Gate name | Input field | Failure condition | Effect |
|---|---|---|---|
| `permit_receipt_bound` | `effect.authorization.permit_receipt_digest` | Authorization block absent; reference absent; required field missing; type mismatch; digest mismatch | `ok=False` |
| `machine_mandate_bound` | `effect.authorization.machine_mandate_digest` | Authorization block absent; reference absent; required field missing; type mismatch; digest mismatch | `ok=False` |

`ok=True` only when **both** gates pass.

**Gate failure semantics (per Scott Lee's correction):** "no effect-commit marker"
means zero external-effect commits may proceed on the basis of this capsule's
authorization binding.  A capsule whose gates fail MAY still be signed and
registered as audit evidence — gate failure does not invalidate the capsule record
itself.

---

## 6. Worked example (illustrative — paths subject to revision)

### Illustrative composition paths

| Document | Field path | Value | Meaning |
|---|---|---|---|
| PermitReceipt | `requested.amount` | `425000` | EUR minor units (€4,250.00) — approved amount |
| MachineMandate | `scope.max_spend` | `500000` | EUR minor units (€5,000.00) — delegated ceiling |

### Minimal PermitReceipt

```json
{
  "type": "PermitReceipt",
  "version": "1",
  "permit_id": "permit-2026-0716-001",
  "issued_at": "2026-07-16T00:00:00Z",
  "issuer": "example-permit-authority",
  "requested": {
    "currency": "EUR",
    "amount": 425000,
    "description": "Payment approved for INV-2026-0716 — server infrastructure renewal"
  }
}
```

### Minimal MachineMandate

```json
{
  "type": "MachineMandate",
  "version": "1",
  "mandate_id": "mandate-2026-0716-001",
  "issued_at": "2026-07-16T00:00:00Z",
  "issuer": "example-aep-authority",
  "scope": {
    "currency": "EUR",
    "max_spend": 500000,
    "description": "Delegated payment authority for server infrastructure renewal"
  }
}
```

### Capsule effect block (after emission)

```json
{
  "effect": {
    "status": "dispatched",
    "type": "payment",
    "effect_attestation": "runtime_claimed",
    "authorization": {
      "permit_receipt_digest": {
        "type": "PermitReceipt",
        "digest_alg": "SHA-256",
        "digest": "<SHA-256(JCS(PermitReceipt)) — 64-char hex>"
      },
      "machine_mandate_digest": {
        "type": "MachineMandate",
        "digest_alg": "SHA-256",
        "digest": "<SHA-256(JCS(MachineMandate)) — 64-char hex>"
      }
    }
  }
}
```

### Full digest thread

```
PermitReceipt ──JCS+SHA-256──► effect.authorization.permit_receipt_digest.digest
                                        │
                                        ▼
MachineMandate ─JCS+SHA-256──► effect.authorization.machine_mandate_digest.digest
                                        │
                                        ▼
                capsule body (effect.authorization inside)
                        │
                        ▼
              capsule_id = SHA-256(JCS(capsule \ {capsule_id, chain}))
```

---

## Reference implementation

```python
from agent_action_capsule.verify_composition import verify_permitreceipt_mandate

result = verify_permitreceipt_mandate(capsule, permit_receipt, machine_mandate)
# result = {"ok": True/False, "gates": [{"name": ..., "passed": ..., "reason": ...}, ...]}
```

Source: `python/agent_action_capsule/verify_composition.py`  
Tests: `python/tests/test_permitreceipt_mandate_profile.py`
