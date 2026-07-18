# Verification depths and semantic conventions

**Status:** Working document  
**Date:** 2026-07-16  
**Applies to:** `draft-mih-scitt-agent-action-capsule-02`

---

## Overview

Verifying an Agent Action Capsule record involves three distinct operations that
build on each other but can be performed independently.  They answer different
questions and require different inputs; confusing them is the most common source
of overclaimed or underclaimed verification results.

| Depth | Question answered | Requires |
|---|---|---|
| 1 — Record | Was this sealed, anchored, and untampered? | Shared record grammar only (JCS+SHA-256 convention, capsule envelope) |
| 2 — Disclosure | *What* exactly was cited in a referenced artifact? | Depth 1 + the revealed preimage whose hash matches the sealed reference |
| 3 — Semantics | What does the cited artifact *mean*? What may I conclude? | Depth 2 + the artifact's profile vocabulary, plus a mapping note if crossing vocabularies |

Rules that hold at every depth:

- **Depth 1 never requires resolving references.** No profile is a root of trust
  for another; record verification succeeds or fails on the capsule's own fields.
- **Disclosure never adds claims; it substantiates sealed ones.** A Depth-2 check
  proves *what* was cited but carries the same observation boundary as the capsule
  itself (dispatched vs confirmed, `runtime_claimed` vs `gate_executed` — those
  boundaries are explicit in-band).  Revealing the preimage cannot extend the
  claim beyond what the original record witnessed.
- **Meaning is never inferred from bytes.** Interpreting an artifact requires its
  own profile vocabulary.  When two artifact types meet in one record, a mapping
  note — not byte-level inspection — is what makes the claim testable.

---

## Depth 1 — Record verification

A Depth-1 check answers: "Is this a genuine, untampered, properly sealed
capsule?"

**What to verify:**

1. **`capsule_id` integrity.** Recompute `SHA-256(JCS(capsule_body \ {capsule_id,
   chain}))` per §5.1 and compare to the stored `capsule_id`.  Mismatch → reject.
2. **Absent-field normalization.** Before computing any digest, remove `null`
   values and empty containers bottom-up.  JCS sorts keys by UTF-16 code-unit
   order.  Both steps are required for reproducibility.
3. **Signature coverage.** `capsule_id` is the signed payload; `agent_input_digest`
   and `agent_output_digest`, the `effect` block (including any `request_digest`
   and `response_digest`), and every other envelope field are inside the JCS hash
   and therefore inside the signature.
4. **Inclusion proof (if anchored).** Follow the SCITT Receipt and Merkle-path
   verification per §9.  A ledger-mode of "anchored" requires this step.

Depth 1 does not require the referenced artifacts (the things pointed to by
`agent_input_digest`, `agent_output_digest`, `effect.request_digest`, etc.) — only
the capsule record itself.

---

## Depth 2 — Disclosure verification

A Depth-2 check answers: "Is this the exact document that was cited when the
capsule was sealed?"

The caller provides the companion artifact (e.g., the PermitReceipt or
MachineMandate document).  The verifier:

1. Normalizes the artifact (absent-field normalization).
2. Canonicalizes with RFC 8785 JCS (sort keys by UTF-16 code-unit order, compact
   separators, UTF-8, no BOM).
3. Computes SHA-256; encodes as 64-char lowercase hex.
4. Compares to the corresponding capsule field (`effect.request_digest`,
   `agent_input_digest`, etc.).

A match proves the artifact is exactly what the capsule author committed to at
emission time.  A mismatch proves tampering or a wrong companion document.

### The low-entropy caveat and the salt commitment scheme

Digest-binding hides the preimage only when the preimage is not guessable.  For
low-entropy fields — small integer amounts, short fixed-vocabulary strings — an
attacker may enumerate candidates and reconstruct the preimage from the hash
alone.

To prevent this, a producer can use a salted commitment instead of a plain
digest.  The `selective_disclosure` module
(`python/agent_action_capsule/selective_disclosure.py`) implements per-field
salted commitments:

```
commitment = SHA-256(salt_bytes + field_name.encode('utf-8') + b':' + json_value_bytes)
```

where `salt_bytes` is 16 bytes from a cryptographically secure random source
(`secrets.token_bytes(16)`).  The salt is stored with the producer and revealed
only to authorized parties; `verify_disclosure()` confirms a disclosed
field+salt pair recomputes to a stored commitment.

See the salting audit at the end of this document for what is and is not salted
by default in the current codebase.

---

## Depth 3 — Semantic verification

A Depth-3 check answers: "What does this cited artifact prove, and may I act on
that conclusion?"

Semantics load whenever a non-author must act on the record's content, not merely
verify its integrity.  Integrity has one customer class (anyone); semantics has
another (anyone who must draw a conclusion).

Interpreting an artifact requires its own profile vocabulary.  When the capsule
references an artifact from a different ecosystem (a VeritasChain VCP event, an
EMILIA Protocol receipt, an AEP MachineMandate), a **mapping note** is required.
The mapping note aligns vocabularies within a single claim type; it does not move
artifacts across claim types.

**Mikhail's observation-boundary bound:** A record supports no claim beyond what
its stated observation boundary witnessed.  The `dispatched`/`confirmed` effect
postures and the `runtime_claimed`/`gate_executed` attestation types make that
boundary explicit in-band.  A Depth-3 analysis must respect these; it cannot
infer that an action was completed when the capsule says only that it was
dispatched.

### Live Depth-3 examples

**EP composition pack** (`interop-vectors/composition/`, branch
`composition-vectors-ep-cosa`) — a Class-1 (WHAT) AAC capsule composed with an
EP-RECEIPT-v1 (WHO) artifact on a shared `subject_digest`.  Demonstrates that a
human-authorization receipt from the EMILIA Protocol maps to the WHO slot without
changing the capsule vocabulary.  Six test vectors (3 positive, 3 negative) with
a runnable `verify_composition.py` harness.

**VCP refusal mapping** (`interop/vcp-refusal-mapping/`, branch
`vcp-refusal-mapping`) — joint interop note (Action State × VeritasChain/VSO).
Maps VeritasChain Protocol refusal-events onto AAC `verdict_class`, preserving
the VCP completeness invariant (one ATTEMPT → exactly one Outcome).  Six paired
examples (VCP event + verifying AAC capsule) with four runnable pytest checks.
The mapping table:

| VCP Outcome | Discriminator | AAC `verdict_class` |
|---|---|---|
| `DENY` | operator refusal | `denied` |
| `DENY` | policy refusal | `denied` |
| `DENY` | automatic constraint | `blocked` |
| `GENERATE` | completed | `executed` |
| `ERROR` | pre-dispatch | `engine_failure` |
| `ERROR` | post-dispatch, uncertain | `errored` |

**AAC is compatible with VAP's Shared Assurance Core; it is not "VAP-aligned."**
AAC sits at the SCITT statement-profile layer; VCP is a domain profile above the
VeritasChain assurance framework.  The mapping note joins the two vocabularies; it
does not assert that one profile is a sub-profile of the other.

---

## Worked example — three-way composition (PermitReceipt + MachineMandate)

This example threads all three depths using the PermitReceipt + MachineMandate
three-way composition (see
`docs/interop/aac-permitreceipt-mandate-binding-profile.md`).

**Setup:** An AI agent makes a EUR payment.  Two external artifacts authorize the
action: a PermitReceipt (a permit authority credential) and a MachineMandate (an
AEP authority credential).  The bindings live in `effect.authorization`, a
namespaced payload extension — not in `effect.request_digest`/`response_digest`,
which retain their -02 semantics for the actual protected-action request and
observed response.

**Depth 1 — record integrity:**

```python
from agent_action_capsule.canonical import compute_capsule_id

# Recompute capsule_id — effect.authorization is inside the JCS preimage
assert compute_capsule_id(capsule) == capsule["capsule_id"]
```

This check requires only the capsule record.  It does not require the
PermitReceipt or MachineMandate documents.  Both authorization references are
inside the preimage, so tampering with either changes `capsule_id`.

**Depth 2 — disclosure of both referenced artifacts:**

```python
from agent_action_capsule.canonical import json_digest

auth = capsule["effect"]["authorization"]

permit_digest = json_digest(permit_receipt)
assert permit_digest == auth["permit_receipt_digest"]["digest"]

mandate_digest = json_digest(machine_mandate)
assert mandate_digest == auth["machine_mandate_digest"]["digest"]
```

Both typed references are inside `effect.authorization`, which is inside the
`capsule_id` commitment from Depth 1.  Passing Depth 2 proves that these exact
documents — `PermitReceipt.requested.amount = 425000` (EUR minor units,
€4,250.00) and `MachineMandate.scope.max_spend = 500000` (EUR minor units,
€5,000.00) — were the ones committed to at emission.

For a runnable implementation that also checks artifact structure:

```python
from agent_action_capsule.verify_composition import verify_permitreceipt_mandate

result = verify_permitreceipt_mandate(capsule, permit_receipt, machine_mandate)
# {"ok": True, "gates": [{"name": "permit_receipt_bound", "passed": True, ...},
#                        {"name": "machine_mandate_bound", "passed": True, ...}]}
```

**Depth 3 — semantic interpretation:**

To conclude "the agent acted within the approved amount and within the delegated
ceiling," the verifier must apply the PermitReceipt vocabulary (what does
`requested.amount` mean in the permit authority's domain?) and the MachineMandate
vocabulary (what does `scope.max_spend` mean in the AEP domain?), then check the
numeric relationship.

This step cannot be performed from hashes alone.  It requires the profile
specifications for PermitReceipt and MachineMandate, plus a mapping note that
establishes that `requested.amount ≤ scope.max_spend` is the correct semantic
gate for this claim type.

---

## The hub math — why one vocabulary at the center matters

Given n distinct artifact vocabularies, all-pairs translation requires n(n−1)/2
mapping notes.  For the current interop landscape (approximately 31 distinct
audit/attribution formats), that is 465 bilateral mappings.

Via a shared record vocabulary at the hub, n mappings suffice: each vocabulary
maps to and from the hub, and hub-transitivity gives A → hub → B for free.  That
collapses 465 translations to 31.

**Two honest caveats:**

1. Hub transitivity (A → hub → B) holds only if the hub vocabulary is a
   **lossless common core** — every meaningful distinction in A and B must be
   expressible at the hub without collapsing.  This is why `verdict_class`
   completeness and the ATTEMPT→outcome invariant are load-bearing design
   requirements, not decorative detail.

2. Nobody builds all 31 mappings upfront.  The practical approach is to build the
   five or six that matter for the current interop set (EP, VAP, GAR, AEP, …) and
   build the rest on demand, freezing each as a test-vector set as it stabilizes.

---

## Documented conventions

### Multi-leg actions

Some workflows span multiple agent actions — e.g., a five-leg curtailment or
settlement sequence.  Each leg produces its own capsule; the legs are chained
using `chain.relation: "supersedes"` (or `"epoch_opens"` at boundary events).
There is no "partial" verdict class on a single capsule.  Partial completion is a
**chain shape**, not a verdict value on one record.

This is not a new vocabulary term; it is a pattern built from existing fields.

### Blocked vs denied for Authority-evaluation results

An agent blocked by an automated constraint gate belongs in `verdict_class:
"blocked"`, not `"denied"`.  An authority's evaluation result — e.g., a
constraint set check that rejected the action — is already expressible as
`blocked` with completeness results against the pinned constraint set.  No new
field is needed; the pattern should be documented by the profile that governs the
constraint set, not added to the base capsule vocabulary.

---

## Salting audit

The following is an accurate accounting of what the current codebase salts by
default.  Where site documentation overstates the implementation, the site copy
should be corrected to match the code.

### What IS salted

The `selective_disclosure` module in `agent-action-capsule`
(`python/agent_action_capsule/selective_disclosure.py:9–32`) implements per-field
salted commitments.  Key properties:

- **Salt generation:** `secrets.token_bytes(16)` per field (line 23) — 16 bytes,
  cryptographically secure, independent per field per call.
- **Commitment scheme:** `SHA-256(salt_bytes + field_name.encode('utf-8') + b':' +
  json_value_bytes)` (lines 26–28).
- **Disclosure store:** `{field_name: {"salt": hex_salt, "value": value}}` (line
  30) — the salt is kept private by the producer and revealed only to authorized
  parties.
- **Verification:** `verify_disclosure(commitments, disclosed)` (lines 48–73)
  confirms each disclosed field+salt pair recomputes to one of the stored
  commitments.  Subset disclosure is valid; not all fields need to be revealed.
- **Test coverage:** `python/tests/` — there is a test for the selective
  disclosure API, exercised via the composition profile tests.

### What is NOT salted by default

The default `emit()` path in both `capsule-emit` and `agent-action-capsule` does
**not** apply salting to `agent_input_digest` or `agent_output_digest`.

- `capsule_emit/core.py:37–59` — `_digest(value)` calls `json_digest(value)` with
  no salt.  This is a plain SHA-256 over JCS-canonical bytes.
- `agent_action_capsule/emit.py` — the `emit()` function has no `salt_digests`
  parameter.  There is no call to `selective_disclosure.commit_fields()` in the
  default code path.

### Implication for site documentation

Any site copy claiming that capsule-emit "salts low-entropy fields before hashing"
by default overstates the current implementation.  The accurate statement is:

> The library provides a salted per-field commitment API (`selective_disclosure`)
> for producers who need to hide low-entropy field content.  The default `emit()`
> path uses plain JCS+SHA-256 digests without salting.

Producers handling low-entropy inputs (small integers, short fixed-vocabulary
strings) should use `selective_disclosure.commit_fields()` and store the resulting
`salted_disclosures` dict privately, placing only the commitments list in the
capsule.
