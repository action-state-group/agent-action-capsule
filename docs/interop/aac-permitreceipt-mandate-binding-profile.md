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

## 2. Binding location — `effect.authorization` profile-defined payload extension

This profile binds PermitReceipt and MachineMandate via **two typed references** in a
profile-defined payload extension under `effect.authorization`.  It does NOT overload
`effect.request_digest` or `effect.response_digest`, which retain their -02 semantics:

| Field | -02 semantics (unchanged) |
|---|---|
| `effect.request_digest` | JSON-DIGEST of the actual protected-action request, when present |
| `effect.response_digest` | JSON-DIGEST of the actual observed response (REQUIRED when `status: "confirmed"`; this is the outcome weld for downstream consumers such as TPM PCR16) |

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

Each authorization reference is a JSON object:

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | REQUIRED | Artifact type identifier: `"PermitReceipt"` or `"MachineMandate"` |
| `digest_alg` | string | REQUIRED | Hash algorithm: MUST be exactly the string `"SHA-256"` — case-sensitive, no aliases |
| `digest` | string | REQUIRED | 64-char lowercase hex SHA-256 — matches `^[0-9a-f]{64}$` |
| `preimage` | string | optional | Preimage convention (see §3.1); defaults inferred from companion type |

Additional fields (e.g., `profile`, `action_hash`) MAY be present; verifiers MUST
ignore unrecognized fields.

### 3.1 Preimage conventions (profile-defined — exactly ONE per companion type)

| `preimage` value | Companion type | What is hashed |
|---|---|---|
| `json/jcs` (default for dict) | JSON document | SHA-256(JCS(normalize(companion_dict))) |
| `jws/issuer-signed` (default for bytes) | SD-JWT credential | SHA-256(exact issuer-signed JWS component bytes) |

**SD-JWT rule:** NEVER hash the holder-presentation or key-binding bytes; NEVER hash
an unsigned companion descriptor.  The preimage MUST be the exact bytes of the
issuer-signed component (the portion before the `~` separator in compact form).

---

## 4. Resolution and comparison procedure

The companion documents are provided as parsed JSON objects (or raw JWS bytes for
SD-JWT) alongside the capsule.  The verifier resolves and passes them in; they are not
fetched from a network.

### Step-by-step for each reference

**PermitReceipt → `effect.authorization.permit_receipt_digest`**

1. Locate `capsule.effect.authorization`.  If absent or not an object, FAIL at gate
   `permit_receipt_bound`.
2. Locate `.permit_receipt_digest`.  If absent, FAIL at gate `permit_receipt_bound`.
3. Confirm the reference is an object containing `type`, `digest_alg`, and `digest`.
   If any field is missing, FAIL.
4. Confirm `.type == "PermitReceipt"`.  FAIL on mismatch.
5. Confirm `.digest` matches `^[0-9a-f]{64}$`.  FAIL on mismatch.
6. Compute the expected digest using the preimage convention declared in `.preimage`
   (or the default for the companion type if absent).
7. Compare to `.digest`.  FAIL on mismatch.

**MachineMandate → `effect.authorization.machine_mandate_digest`**

Same steps, with `.machine_mandate_digest` and `expected_type = "MachineMandate"`.

Both references are evaluated independently.

---

## 5. Binding-only verifier — four gates

This profile's verifier checks **cryptographic binding only**.  It does NOT perform
owner appraisal.  Callers MUST supply the owner-appraisal result for each artifact
as a mandatory input.  A digest match without a positive appraisal MUST NOT be
treated as authorization success.

| Gate name | Source | Failure condition |
|---|---|---|
| `permit_receipt_reference_bound` | Digest binding check | Authorization block absent; reference absent; required field missing; `digest_alg` ≠ `"SHA-256"` (exact string); type or digest mismatch |
| `permit_receipt_appraised` | **Caller-supplied** (owner verifier result) | `None` (not provided) or `False` (owner rejected) |
| `machine_mandate_bound` | Digest binding check | Authorization block absent; reference absent; required field missing; `digest_alg` ≠ `"SHA-256"` (exact string); type or digest mismatch |
| `machine_mandate_appraised` | **Caller-supplied** (owner verifier result) | `None` (not provided) or `False` (owner rejected) |

`bindings_ok` is True only when **all four** gates pass.

**Gate failure semantics (per Scott Lee):** "no effect-commit marker" means zero
external-effect commits may proceed on the basis of this capsule's authorization
binding.  A capsule whose gates fail MAY still be signed and registered as audit
evidence — gate failure does not invalidate the capsule record itself.

**Profile statement — `capsule_id` and `COSE_Sign1` semantics:**  
`capsule_id` is a content address (SHA-256 over the JCS preimage of the full
capsule body, §5.1), providing change detection: any mutation to
`effect.authorization` or any other capsule field produces a different
`capsule_id`, making post-seal tampering detectable without a separate
signature.  Successful `COSE_Sign1` verification — as exercised by
`test_cose_sign1_roundtrip_preserves_authorization` in the reference
implementation — means: (a) the signing key's signature over the COSE
payload is cryptographically valid, AND (b) the signed-payload integrity
holds under the trust inputs selected by the relying party (issuer DID, key,
algorithm).  These two properties are complementary: `capsule_id` binds
content; `COSE_Sign1` binds provenance.

---

## 6. Worked example (illustrative — paths subject to revision)

### Illustrative composition paths

| Document | Field path | Value | Meaning |
|---|---|---|---|
| PermitReceipt | `requested.amount` | `425000` | EUR minor units (€4,250.00) — approved amount |
| MachineMandate | `scope.max_spend` | `500000` | EUR minor units (€5,000.00) — delegated ceiling |

### Capsule effect block (confirmed status, all fields)

```json
{
  "effect": {
    "status": "confirmed",
    "type": "payment",
    "effect_attestation": "runtime_claimed",
    "request_digest": "<SHA-256(JCS(protected_action_request)) — actual I/O>",
    "response_digest": "<SHA-256(JCS(observed_response)) — actual I/O, outcome weld>",
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

Note that `response_digest` is the outcome weld — it commits to the actual observed
response, NOT the MachineMandate.  The two bindings are independent.

### Full digest thread

```
PermitReceipt ──JCS+SHA-256──► effect.authorization.permit_receipt_digest.digest
                                        │
MachineMandate ─JCS+SHA-256──► effect.authorization.machine_mandate_digest.digest
                                        │
protected_request ─JCS+SHA-256─► effect.request_digest (actual I/O)
                                        │
observed_response ─JCS+SHA-256─► effect.response_digest (outcome weld)
                                        │
                capsule body (all four inside)
                        │
              capsule_id = SHA-256(JCS(capsule \ {capsule_id, chain}))
```

---

## Reference implementation

```python
from agent_action_capsule.verify_composition import verify_permitreceipt_mandate

result = verify_permitreceipt_mandate(
    capsule,
    permit_receipt,        # dict or bytes (SD-JWT: issuer-signed JWS bytes)
    machine_mandate,       # dict or bytes
    permit_receipt_appraised=<bool from owner verifier>,
    machine_mandate_appraised=<bool from owner verifier>,
)
# {
#   "bindings_ok": True/False,
#   "gates": [
#     {"name": "permit_receipt_bound",      "passed": ..., "reason": "..."},
#     {"name": "permit_receipt_appraised",  "passed": ..., "reason": "..."},
#     {"name": "machine_mandate_bound",     "passed": ..., "reason": "..."},
#     {"name": "machine_mandate_appraised", "passed": ..., "reason": "..."},
#   ]
# }
```

Source: `python/agent_action_capsule/verify_composition.py`  
Tests: `python/tests/test_permitreceipt_mandate_profile.py`
