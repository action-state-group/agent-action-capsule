# AAC PermitReceipt + MachineMandate Binding Profile

**Status:** OWNER-PROPOSED — REVIEW PENDING — NOT AGREED — NOT A RESULT  
**Date:** 2026-07-16  
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
and the MachineMandate under which it was delegated, without any party needing to
exchange raw document content after the fact.

---

## 2. References — where each binding lives in the capsule JSON

The AAC capsule body contains an `effect` object.  Two fields in that object carry
the bindings:

| Field | Bound artifact | Meaning |
|---|---|---|
| `effect.request_digest` | PermitReceipt | SHA-256 of the canonical PermitReceipt — the input that authorized this action |
| `effect.response_digest` | MachineMandate | SHA-256 of the canonical MachineMandate — the output scope this action operated under |

### Why these fields are signature-covered

`capsule_id` is defined as:

```
capsule_id = SHA-256(JCS(capsule_body \ {capsule_id, chain}))
```

Both `effect.request_digest` and `effect.response_digest` are inside the capsule
body, and therefore inside the JCS hash.  Any post-emission change to either digest
produces a different `capsule_id`, making tampering detectable without a separate
signing step.

This is the same mechanism by which `model_attestation.compute_attestation` binds
agent I/O digests in the existing AAC profile: all fields in the capsule body are
committed at emission time.

---

## 3. Encoding

| Concern | Agreed encoding |
|---|---|
| Hash algorithm | SHA-256 |
| Digest representation in JSON | hex-lowercase string, 64 chars — e.g. `"c52a66d0…"` |
| No prefix | Plain 64-char hex; NOT `"sha256:…"` or any other prefix |
| Input for digest computation | JCS-canonical form: RFC 8785 sort order, absent-field normalization (null / empty array / empty object members removed bottom-up), UTF-8, no BOM |
| `capsule_id` derivation | SHA-256(JCS(capsule \ {capsule_id, chain})) per §5.1 |

Absent-field normalization removes `null` values and empty containers before
serialization.  Verifiers MUST apply the same normalization before computing a
digest, or the comparison will diverge on sparse documents.

---

## 4. Resolution and comparison procedure

The PermitReceipt and MachineMandate are provided as **companion JSON files**
alongside the capsule.  The verifier does not fetch them from a network; the caller
resolves and passes them in.

### Step-by-step for each reference

**PermitReceipt → `effect.request_digest`**

1. Locate `capsule.effect.request_digest`.  If absent or not a 64-char hex string,
   FAIL at gate `permit_receipt_bound`.
2. Take the PermitReceipt companion document (parsed JSON dict).
3. Apply absent-field normalization (remove null / empty-array / empty-object members
   bottom-up).
4. Serialize the normalized document with RFC 8785 JCS (sort keys by UTF-16 code
   unit order, compact separators, UTF-8).
5. Compute SHA-256 of those bytes; encode as lowercase hex (64 chars).
6. Compare to `capsule.effect.request_digest`.  If they differ, FAIL at gate
   `permit_receipt_bound`.

**MachineMandate → `effect.response_digest`**

1. Locate `capsule.effect.response_digest`.  If absent or not a 64-char hex string,
   FAIL at gate `machine_mandate_bound`.
2. Take the MachineMandate companion document (parsed JSON dict).
3. Apply absent-field normalization.
4. Serialize with RFC 8785 JCS.
5. Compute SHA-256; encode as lowercase hex (64 chars).
6. Compare to `capsule.effect.response_digest`.  If they differ, FAIL at gate
   `machine_mandate_bound`.

---

## 5. Fail-closed gates

| Gate name | Input field | Failure condition | Effect on result |
|---|---|---|---|
| `permit_receipt_bound` | `effect.request_digest` | Field absent, malformed, or digest mismatch | `ok=False`; no effect-commit marker |
| `machine_mandate_bound` | `effect.response_digest` | Field absent, malformed, or digest mismatch | `ok=False`; no effect-commit marker |

Both gates are evaluated independently.  The result is `ok=True` only when **both**
pass.  A verifier MUST NOT treat a partial pass as actionable — either the full
three-way binding holds or it does not.

No effect-commit marker (e.g., a SCITT anchor receipt) should be acted upon if
either gate fails.

---

## 6. Worked example (illustrative — paths subject to revision)

### Frozen composition paths

| Document | Field path | Value | Meaning |
|---|---|---|---|
| PermitReceipt | `requested.amount` | `425000` | EUR minor units (€4,250.00) — approved amount |
| MachineMandate | `scope.max_spend` | `500000` | EUR minor units (€5,000.00) — delegated ceiling |

The mandate ceiling (€5,000.00) is above the approved amount (€4,250.00), so the
action is within scope.

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
    "status": "confirmed",
    "type": "payment",
    "request_digest": "<SHA-256(JCS(PermitReceipt)) — 64-char hex>",
    "response_digest": "<SHA-256(JCS(MachineMandate)) — 64-char hex>"
  }
}
```

Both digest values are deterministic and reproducible from the companion JSON files
using any conforming JCS implementation.  The values are exact-decimal integers
(`amount`, `max_spend`) so they serialize identically in JCS and SHA-256 is stable.

### Full digest thread

```
PermitReceipt ──JCS+SHA-256──► effect.request_digest
                                        │
                                        ▼
MachineMandate ─JCS+SHA-256──► effect.response_digest
                                        │
                                        ▼
                capsule body (both digests inside)
                        │
                        ▼
              capsule_id = SHA-256(JCS(capsule \ {capsule_id, chain}))
```

`capsule_id` is the single content address that commits to both the PermitReceipt and
MachineMandate references, as well as the full capsule body.  No secondary hash of
hashes is needed.

---

## Reference implementation

```python
from agent_action_capsule.verify_composition import verify_permitreceipt_mandate

result = verify_permitreceipt_mandate(capsule, permit_receipt, machine_mandate)
# result = {"ok": True/False, "gates": [{"name": ..., "passed": ..., "reason": ...}, ...]}
```

Source: `python/agent_action_capsule/verify_composition.py`  
Tests: `python/tests/test_permitreceipt_mandate_profile.py`
