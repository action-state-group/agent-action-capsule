# Composition vectors — WHAT (Agent Action Capsule) × WHO (EP-RECEIPT-v1)

Our side of a cross-party composition vector set. One agent action is threaded
through two independently-produced records:

- **WHAT** — an Agent Action Capsule (Class-1) records *what the agent did* and
  its disposition.
- **WHO** — an EP-RECEIPT-v1 (supplied by EMILIA Protocol / Continuum) records
  *which accountable human authorized this exact action*.

They are joined only by a **shared `subject_digest` = SHA-256(JCS(action))** and a
`human_authorization_ref` from the capsule to the receipt. This is **composition,
not format merger**: the capsule never embeds EP semantics, and the receipt is
never treated as a capsule. Each profile verifies with its own tooling.

## The claim (implementation evidence, RFC 7942 style)

**Two independent implementations compose through a shared action digest.** The
capsule producer (Action State) and the receipt producer (EMILIA Protocol)
compute `SHA-256(JCS(action))` independently and arrive at the *same* value for
the flagship `grid.curtailment` action —
`8cf0c36ee36a7b98f2ea7c39251ec4faa337393a8c2e14443c12783e3f51623d`. This is
**not** two implementations of AAC, and it is **not** a claim that either profile
verifies the other's content; it is evidence that the digest-join composes.

## Vectors

| Vector | Result | Rejected at stage |
|---|---|---|
| `pos-composition-grid-curtailment` | accept | — (all stages pass) |
| `neg-composition-wrong-action-splice` | reject | `digest_agreement` — WHO authorizes a different action than the capsule recorded |
| `neg-composition-capsule-id-mismatch` | reject | `what_class1` — the WHAT capsule fails Class-1 before composition is considered |
| `neg-composition-unsigned-who-ref` | reject | `who_authorization_present` — the referenced WHO carries no signoff/signature |
| `pos-composition-third-attestor-STUB` | reserved | — (stub; see `DESIGN-NOTE.md`) |

The staged verifier (`verify_composition.py`) checks, in order:
`subject_digest_recompute` → `what_class1` → `what_binds_subject` →
`digest_agreement` → `who_authorization_present` → `ref_binds`. A negative fails
at exactly one documented stage.

## Run

```
python3 verify_composition.py pos-composition-grid-curtailment/input.json
# {"verified": true, ...}   exit 0
python3 verify_composition.py neg-composition-wrong-action-splice/input.json
# {"verified": false, "failed_stage": "digest_agreement", ...}   exit 2
```

`agent-action-capsule>=0.1.0` on the path (or run from the repo tree). The WHO
profile (EP-RECEIPT-v1 signatures / quorum) verifies independently with EMILIA's
own tooling; this harness verifies the WHAT capsule and the composition join —
our side of the interop.

## Frozen

`SHA256SUMS` fixes every file. The shared action and the WHO artifacts under
`who/` are the EMILIA-supplied samples, included verbatim so the digest join is
reproducible end to end. Terminology is neutral; EP-RECEIPT-v1 is named as the
external WHO artifact it is.
