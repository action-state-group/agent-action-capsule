# agent-action-capsule (reference library)

The reference implementation of the Agent Action Capsule profile: **parse** a
Capsule and **verify** the agent-domain checks defined in the Internet-Draft
(`../spec/`). Published to PyPI as **`agent-action-capsule`**.

> **Status: scaffold.** This directory reserves the package name and layout. The
> verifier is being extracted from the reference engine into a clean, dependency-
> minimal library here. Until that lands, the normative behavior is the
> Internet-Draft (`../spec/`) and the conformance vectors (`../test-vectors/`).

## Scope (what this library is and is not)

**Does** — given a Capsule (a SCITT Signed Statement payload) and the substrate
verification result:

- parse the Capsule payload and its `assurance` / `disposition` / `effect` /
  `chain` structure;
- perform the **Class 1** agent-profile checks of I-D §6 — deterministic,
  performable from the record's own bytes (capsule_id recompute, the
  confirmed-effect binding, verdict/effect orthogonality, the effect-attestation
  matrix, chain semantics, assurance reconciliation, unknown-value reporting);
- return a **structured result, never throw** — a single `ok` gates trust in
  every other reported field.

**Does NOT** — substrate verification (the COSE_Sign1 signature, registration,
the Receipt's inclusion proof) is **not** re-implemented here; it is performed by
reference to the SCITT/COSE substrate (see
[`scitt-cose`](https://github.com/action-state-group/scitt-cose)). This library
verifies the agent-domain payload on top of a verified envelope. It is **not** a
Transparency Service and holds no keys.

## Conformance

Correctness is defined by agreement with the frozen vectors in
`../test-vectors/`: a Class 1 verifier built from the I-D text alone and this
reference library MUST agree, byte-for-byte, on every valid and invalid Capsule.
Wire-facing changes ship with negative (MUST-reject) tests.

## Planned layout

```
python/
  pyproject.toml                 # name = "agent-action-capsule"
  agent_action_capsule/
    __init__.py
    parse.py                     # payload -> typed Capsule
    verify.py                    # Class 1 checks -> structured result
  tests/
    test_vectors.py              # runs ../test-vectors against verify()
```
