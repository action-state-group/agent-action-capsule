# QuadX Three-Way Kit — IETF 126 Hackathon B10

**For David / Srini (QuadX)**

This kit gives QuadX everything needed to (a) re-verify the B9 AAC capsule,
(b) ingest it into a WORM store or SCITT log, and (c) apply selective disclosure
over the compute attestation block. It also maps the `subject_digest` coordinate
shared with Karthik / PEDIGREE (B9).

All data is SYNTHETIC. Identities and organizations are fictional.
Board rows should be filed only for what actually cross-verifies in your environment.

---

## 1. The sealed AAC capsule (positive case)

```json
{
  "spec_version": "draft-mih-scitt-agent-action-capsule-02",
  "format_version": "2",
  "capsule_id": "cd895b1f82fd11c4816cee542568b5d43358579424cab4b9d195a4dc98f91ff5",
  "action_id": "aac-prov-binding-b9-0001",
  "action_type": "decide",
  "operator": "alpha-corp",
  "developer": "alpha-corp:agent-A@v2",
  "timestamp": "2026-07-18T10:05:00Z",
  "model_attestation": {
    "model_id": "claude-sonnet-4-6",
    "provider": "anthropic",
    "compute_attestation": {
      "subject_digest": "0b4da06b84263c0ee02746e52f6893a40586c0563e01961314b1bddf74d72cb6",
      "runtime": "alpha-corp-delegation-engine@v2"
    }
  },
  "effect": {
    "status": "dispatched",
    "type": "api_delegation",
    "request_digest": "0b4da06b84263c0ee02746e52f6893a40586c0563e01961314b1bddf74d72cb6",
    "effect_attestation": "runtime_claimed"
  },
  "assurance": {
    "attestation_mode": "self_attested",
    "effect_mode": "dispatched_unconfirmed",
    "ledger_mode": "standalone"
  },
  "disposition": {
    "decision": "accept",
    "approver": "policy",
    "human_disposed": false,
    "authority": "policy:alpha-corp:cross-org-delegation@v1",
    "verdict_class": "executed"
  },
  "provenance_binding": {
    "version": "1",
    "refs": [
      {
        "ref_id": "grant:alpha-corp:2026-Q3-0042",
        "ref_type": "delegation_grant",
        "digest_alg": "SHA-256/JCS",
        "digest": "ff1107b405a2a010046b14860618dcbc2e65979cc8af649dd931a10ef404d564"
      }
    ],
    "subject_digest": "0b4da06b84263c0ee02746e52f6893a40586c0563e01961314b1bddf74d72cb6"
  }
}
```

The full bundle (action + grant_doc + capsule) is in:
`interop-vectors/provenance-binding/pos-provenance-binding/input.json`
in the `agent-action-capsule` repo at
`https://github.com/action-state-group/agent-action-capsule`

---

## 2. The subject_digest

```
0b4da06b84263c0ee02746e52f6893a40586c0563e01961314b1bddf74d72cb6
```

This is `SHA-256(JCS(action))` — the RFC 8785 JCS canonicalization of the
action dict, then SHA-256 in lowercase hex. It is committed into `capsule_id`
via `provenance_binding.subject_digest`.

To recompute it locally:

```python
import sys; sys.path.insert(0, "python")
import json
from agent_action_capsule.canonical import json_digest

bundle = json.load(open("interop-vectors/provenance-binding/pos-provenance-binding/input.json"))
print(json_digest(bundle["action"]))
# expected: 0b4da06b84263c0ee02746e52f6893a40586c0563e01961314b1bddf74d72cb6
```

---

## 3. How to re-verify the capsule

### Install

```
pip install "agent-action-capsule>=0.1.0"
git clone https://github.com/action-state-group/agent-action-capsule
cd agent-action-capsule/interop-vectors/provenance-binding
```

### Run

```
python3 verify_provenance.py pos-provenance-binding/input.json
```

Expected output (exit 0):

```json
{
  "verified": true,
  "failed_stage": null,
  "stages": {
    "subject_digest_recompute": true,
    "provenance_ref_binds": true,
    "capsule_id_integrity": true,
    "capsule_class1": true
  }
}
```

`capsule_id_integrity: true` confirms the `provenance_binding` extension is
committed into the `capsule_id` preimage — it cannot be stripped or altered
without breaking verification.

---

## 4. How to ingest into a WORM store / SCITT log

Register the capsule as a **Signed Statement** with:

- **Subject**: `subject_digest` = `0b4da06b84263c0ee02746e52f6893a40586c0563e01961314b1bddf74d72cb6`
- **Payload**: the capsule JSON above (COSE_Sign1 envelope not yet applied — this is
  the payload layer; wrap in COSE_Sign1 per RFC 9052 before anchoring)
- **Content-Type**: `application/json` (or `application/aac+json` once the IANA
  registration lands)
- **Registration Policy**: append-only; duplicate `capsule_id` is a conflict

For SCITT (RFC 9592), the `subject` header maps directly to `subject_digest`.
The `capsule_id` (`cd895b1f...`) is the internal content-address; use
`subject_digest` as the SCITT subject to allow co-registration of WHO receipts
(EP-RECEIPT-v1 or PEDIGREE) over the same action.

---

## 5. How to apply SD-CWT selective disclosure

Apply selective disclosure over `capsule.compute_attestation` using
`subject_digest` as the SD-CWT subject (`sub` claim):

```
sub = "0b4da06b84263c0ee02746e52f6893a40586c0563e01961314b1bddf74d72cb6"
```

Selective-disclosure fields (suggested):
- **Disclose**: `subject_digest`, `runtime` (non-sensitive)
- **Selectively disclose**: `model_id`, `provider` (identity-sensitive)
- **Keep opaque**: any internal compute context not for counterparty

SD-CWT draft reference: draft-ietf-oauth-selective-disclosure-jwt (apply same
pattern over CBOR claims for CWT).

The `capsule_id` (`cd895b1f...`) MAY be included as a `cnf`-equivalent claim
so a recipient can verify the full capsule if they obtain it later.

---

## 6. Karthik / PEDIGREE coordination

The same `subject_digest`:

```
0b4da06b84263c0ee02746e52f6893a40586c0563e01961314b1bddf74d72cb6
```

is the **B9 bundle root** in `karthik-titech/cross-org-delegation-registry`.

- **PEDIGREE hardening** (Karthik's track) attaches OVER this `subject_digest`
  as a separate, independently verifiable statement
- **QuadX SD-CWT** (your track) also uses it as `sub`
- The three-way join: `subject_digest` is the single shared coordinate across
  AAC (WHAT), PEDIGREE provenance (WHO), and SD-CWT selective disclosure (HOW MUCH)

To coordinate: confirm your `subject_digest` recompute matches
`0b4da06b84263c0ee02746e52f6893a40586c0563e01961314b1bddf74d72cb6`
and file your board row pointing to your re-run output.

---

## 7. Board row guidance

Only file a board row for what actually cross-verifies in your environment.
Label everything synthetic.

Suggested row:

| Field | Value |
|---|---|
| track | B10-QuadX |
| subject_digest | `0b4da06b84263c0ee02746e52f6893a40586c0563e01961314b1bddf74d72cb6` |
| capsule_id | `cd895b1f82fd11c4816cee542568b5d43358579424cab4b9d195a4dc98f91ff5` |
| evidence_type | `local_harness` (upgrade to `independent_interop` after re-run) |
| data_label | SYNTHETIC |
| verifier | `verify_provenance.py pos-provenance-binding/input.json` → exit 0 |
| sd_cwt_subject | `0b4da06b84263c0ee02746e52f6893a40586c0563e01961314b1bddf74d72cb6` |
| pedigree_join | same subject_digest as B9 / Karthik's registry |

---

## 8. Quick reference

```
repo:           https://github.com/action-state-group/agent-action-capsule
branch:         feat/provenance-binding-vectors
bundle:         interop-vectors/provenance-binding/pos-provenance-binding/input.json
verifier:       interop-vectors/provenance-binding/verify_provenance.py
subject_digest: 0b4da06b84263c0ee02746e52f6893a40586c0563e01961314b1bddf74d72cb6
capsule_id:     cd895b1f82fd11c4816cee542568b5d43358579424cab4b9d195a4dc98f91ff5
grant_digest:   ff1107b405a2a010046b14860618dcbc2e65979cc8af649dd931a10ef404d564
```
