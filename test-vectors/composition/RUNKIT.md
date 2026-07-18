# Composition Vector Run Kit — IETF 126 Hackathon B6

## Prerequisites

- Python 3.9+
- pip

## Install

```
pip install agent-action-capsule>=0.1.0
```

## Clone

```
git clone https://github.com/action-state-group/agent-action-capsule
cd agent-action-capsule/test-vectors/composition
```

## Run all four real cases

```
python3 verify_composition.py pos-composition-grid-curtailment/input.json
python3 verify_composition.py neg-composition-wrong-action-splice/input.json
python3 verify_composition.py neg-composition-capsule-id-mismatch/input.json
python3 verify_composition.py neg-composition-unsigned-who-ref/input.json
```

## Expected outputs (verbatim)

### `pos-composition-grid-curtailment` — exit 0

```json
{
  "verified": true,
  "failed_stage": null,
  "stages": {
    "subject_digest_recompute": true,
    "what_class1": true,
    "what_binds_subject": true,
    "digest_agreement": true,
    "who_authorization_present": true,
    "ref_binds": true
  }
}
```

### `neg-composition-wrong-action-splice` — exit 2

```json
{
  "verified": false,
  "failed_stage": "digest_agreement",
  "stages": {
    "subject_digest_recompute": true,
    "what_class1": true,
    "what_binds_subject": true,
    "digest_agreement": false
  }
}
```

### `neg-composition-capsule-id-mismatch` — exit 2

```json
{
  "verified": false,
  "failed_stage": "what_class1",
  "stages": {
    "subject_digest_recompute": true,
    "what_class1": false
  }
}
```

### `neg-composition-unsigned-who-ref` — exit 2

```json
{
  "verified": false,
  "failed_stage": "who_authorization_present",
  "stages": {
    "subject_digest_recompute": true,
    "what_class1": true,
    "what_binds_subject": true,
    "digest_agreement": true,
    "who_authorization_present": false
  }
}
```

## Integrity check

On Linux:
```
sha256sum -c SHA256SUMS
```

On macOS:
```
shasum -a 256 -c SHA256SUMS
```

All files should report `OK`.

## The shared subject_digest

The composition join is `subject_digest` = `SHA-256(JCS(action))`:

```
8cf0c36ee36a7b98f2ea7c39251ec4faa337393a8c2e14443c12783e3f51623d
```

This value was computed independently by both parties (capsule producer and
EP-RECEIPT-v1 receipt producer) over the same `action.json` using JCS
(RFC 8785) then SHA-256.

## How to submit your result

Open a GitHub issue at
`https://github.com/action-state-group/agent-action-capsule/issues` with
the following template:

---

**Title:** `[B6 interop] <your implementation name or codebase>`

**Body:**

```
## Observed subject_digest

<paste your computed SHA-256(JCS(action)) hex here>

## Harness output — pos-composition-grid-curtailment

<paste the full JSON output of verify_composition.py pos-composition-grid-curtailment/input.json>

## Exit code

<0 or 2>

## Codebase / implementation link

<URL to your repo, branch, or implementation>

## Notes (optional)

<any deviations, environment details, or observations>
```

---

**Freeze rule:** Two independent implementations that both arrive at
`8cf0c36ee36a7b98f2ea7c39251ec4faa337393a8c2e14443c12783e3f51623d`
as their `subject_digest` upgrades the evidence type from `local_harness`
to `independent_interop`. File a PR to the agent-accountability org with
your run's output to record it.

## Third-attestor slot

`pos-composition-third-attestor-STUB/` shows the reserved third-attestor
position in the composition model: a separate signed claim over the same
`subject_digest` by an independent party (e.g., a metering observer). The
slot is not verified by `verify_composition.py`; it documents the composition
pattern. See `DESIGN-NOTE.md` for context and `pos-composition-third-attestor-STUB/`
for the template.
