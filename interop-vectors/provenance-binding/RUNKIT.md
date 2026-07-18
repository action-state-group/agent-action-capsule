# Provenance-Binding Vector Run Kit — IETF 126 Hackathon B9

**For Karthik / cross-org-delegation-registry**

All data is SYNTHETIC. Identities and organizations are fictional.

## Prerequisites

- Python 3.9+
- pip

## Install

```
pip install "agent-action-capsule>=0.1.0"
```

## Clone

```
git clone https://github.com/action-state-group/agent-action-capsule
cd agent-action-capsule/interop-vectors/provenance-binding
```

## Run the positive case (exit 0)

```
python3 verify_provenance.py pos-provenance-binding/input.json
```

Expected output (verbatim):

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

Exit code: `0`

## Run the splice negative case (exit 2)

```
python3 verify_provenance.py neg-provenance-splice/input.json
```

Expected output (verbatim):

```json
{
  "verified": false,
  "failed_stage": "provenance_ref_binds",
  "stages": {
    "subject_digest_recompute": true,
    "provenance_ref_binds": false
  },
  "reason": "refs[0].digest='ff1107b405a2a010046b14860618dcbc2e65979cc8af649dd931a10ef404d564' != json_digest(grant_doc)='55d76dd9e678e5df66e67de87f1ef740d7be132b4b4131bcadada0739a602742'; the provenance ref does not bind to the carried grant document (possible splice: this grant was issued for a different action)"
}
```

Exit code: `2` — stage: `provenance_ref_binds`

## What the stages check

| Stage | What it checks |
|---|---|
| `subject_digest_recompute` | `json_digest(action) == capsule.provenance_binding.subject_digest` |
| `provenance_ref_binds` | `refs[0].digest == json_digest(grant_doc)` — proves the grant document in the bundle is the exact artifact the capsule committed to |
| `capsule_id_integrity` | `compute_capsule_id(capsule) == capsule["capsule_id"]` — proves `provenance_binding` entered the capsule_id preimage |
| `capsule_class1` | AAC Class-1 structural verification (§6) |

## The subject_digest

```
0b4da06b84263c0ee02746e52f6893a40586c0563e01961314b1bddf74d72cb6
```

This is `SHA-256(JCS(action))` over the canonical action in
`pos-provenance-binding/input.json`. It is committed into `capsule_id`
via `provenance_binding.subject_digest` (which enters the preimage).

## Splice attack explained

In `neg-provenance-splice/`, an attacker:
1. Built a capsule around a DIFFERENT action (scope inflated to `delete:records`, records to 50000)
2. Presented a TAMPERED `grant_doc` (same `grant_id`, but wider scope)
3. Left the capsule's `provenance_binding.refs[0].digest` pointing to the ORIGINAL narrow-scope grant

The verifier catches this at `provenance_ref_binds`:
`json_digest(tampered_grant_doc) != refs[0].digest`

The capsule itself is internally consistent (capsule_id is valid for the spliced body),
but the provenance link is broken — the grant digest doesn't match the grant document presented.

## evidence_type note

Results from running this harness locally are classified as:

```
evidence_type: "local_harness"
```

To upgrade to `evidence_type: "independent_interop"`:
1. Run `verify_provenance.py pos-provenance-binding/input.json` in your own environment
2. Confirm exit 0 and matching `subject_digest`
3. Share your output + codebase link via a GitHub issue on `action-state-group/agent-action-capsule`

## How to submit your result

Open a GitHub issue at `https://github.com/action-state-group/agent-action-capsule/issues` with:

```
Title: [B9 interop] <your implementation or codebase name>

Body:
## Observed subject_digest
<your computed SHA-256(JCS(action)) hex>

## Harness output — pos-provenance-binding
<full JSON output>

## Exit code
<0 or 2>

## Codebase / implementation link
<URL>
```
