# agent-action-capsule (reference library)

The reference implementation of the Agent Action Capsule profile: **parse** and
**seal** a Capsule, and run the **Class 1 verifier** defined in the
Internet-Draft (`../spec/`). Published to PyPI as **`agent-action-capsule`**.

The spec (`../spec/`) is the source of truth. Where the draft says MUST / MUST
NOT, the code and tests enforce it, section by section.

## Quickstart (30 seconds)

Install the payload-only core (stdlib only — **zero required dependencies**):

```bash
pip install agent-action-capsule        # from a checkout: cd python && pip install .
```

**Verify a conformant capsule** — point at a shipped positive vector:

```bash
$ agent-action-capsule verify ../test-vectors/pos-executed-confirmed/input.json
Agent Action Capsule — Class-1 payload verification: ../test-vectors/pos-executed-confirmed/input.json
  ok: True
  capsule_id (recomputed): 5b7c4ff1bcf4364e0dd8c8b65eddddbb1d6102f27bed3ad1a3595cba51d3502a
  derived: effect_mode=confirmed attestation_mode=self_attested ledger_mode=standalone
  findings: none
# exit code 0
```

**Verify a failing capsule** — the finding is self-explaining, with its §6 check number:

```bash
$ agent-action-capsule verify ../test-vectors/neg-confirmed-without-response/input.json
  ok: False
  ...
  findings:
    - [error] (check 3) confirmed_without_response: effect.status 'confirmed' requires a 64-hex response_digest (§5.2)
# exit code 1  (0 = ok, 1 = not ok, 2 = could not run / malformed input)
```

Add `--json` for the raw `VerificationResult`, or `--store <dir-or-ledger-file>`
for store-level chain checks (supersedes / concurrent-supersedes / open-items).

### The two layers

Verification is two layers, and this package is honest about which it does:

| Layer | Who verifies it | This package |
|---|---|---|
| **payload** — the Agent Action Capsule (Class-1, §6): capsule_id, confirmed-effect binding, effect_attestation matrix, disposition, assurance | **this profile** | ✅ implemented |
| **substrate** — the SCITT/COSE envelope: the `COSE_Sign1` signature and the RFC 9162 Receipt / inclusion proof (§3.2) | **SCITT/COSE, by reference** | calls [`scitt-cose`](https://github.com/action-state-group/scitt-cose) — never reimplemented |

To verify both layers of a SCITT **Signed Statement**, install the optional extra
and pass `--transparent`:

```bash
pip install 'agent-action-capsule[transparent]'     # adds the public scitt-cose verifier

agent-action-capsule verify --transparent statement.cose --issuer-key issuer_pub.pem [--log-key log_pub.pem --leaf-entry-hex <hex>]
```

```
  substrate (SCITT/COSE, via scitt-cose):
    signature_verified : True
    receipt_verified   : True
    attestation_tier   : anchored        # 'anchored' ONLY when a receipt actually verified (§3.2)
  payload (Agent Action Capsule, Class-1):
  ok: True
```

Without a verified receipt the substrate tier is `self_attested`, never
`anchored`. The optional extra is **public** (`scitt-cose`, deps `cbor2` +
`cryptography`); the default install pulls nothing extra.

### Build → verify (producer side)

[`../examples/build_and_verify.py`](../examples/build_and_verify.py) is the
smallest honest round trip: construct a capsule with the typed builders, `seal()`
it (compute `capsule_id`), then `verify()` it — an executed action and a blocked
one, in ~40 lines.

### Conformance vectors

[`../test-vectors/`](../test-vectors/) is the frozen conformance suite a second
implementer runs against their **own** verifier: each `input.json` plus its
spec-anchored `expected.json` (`ok`, the §6 check numbers + severities, the
derived modes, the recomputed `capsule_id`). See
[`../spec/section-map.md`](../spec/section-map.md) for the spec section map.

## What it implements

| Module | Spec | Implements |
|---|---|---|
| `canonical.py` | §2, §5.1 | JSON-DIGEST = `HEX(SHA-256(JCS(normalize(v))))`; RFC 8785 JCS; absent-field normalization; `capsule_id` over the canonical capsule form (envelope minus `capsule_id` and the chain block). Floats in digest fields are rejected (§5.1). |
| `registries.py` | §12 | Loads the six registries from `../spec/REGISTRY.md` (single-sourced — the code hard-codes no seeded values, so it cannot drift from the spec). |
| `contracts.py` | §5.2–§5.4 | Typed **producer** carriers whose constructors enforce the invariants a producer MUST NOT violate: the disposition honesty invariant and the closed `approver` enum (§5.4), the confirmed-effect binding and the status/digest table (§5.2). A non-conforming Capsule cannot be built. Also the `effect_mode` derivation (§5.2) and the never-dispatch set (§5.4.2). |
| `verify.py` | §6 | The **Class 1 verifier**: the eight checks in fixed order, a structured result that never throws, a single `ok` boolean, store-level chain checks (`verify_store`), and the SHOULD-level defensive disposition-honesty assert over arbitrary bytes. Unknown registry values are informational, never a rejection. |
| `parse.py` | §5 | `Capsule` builder + `seal()` (computes `capsule_id`); strict `parse_capsule` (raises on a non-conforming Capsule). |

```python
from agent_action_capsule import verify, Capsule, EffectRecord, Disposition, AssuranceBlock

capsule = Capsule(
    spec_version="draft-mih-scitt-agent-action-capsule-00", format_version="2",
    action_id="po-12345", action_type="decide", operator="ACME-CO", developer="agent@v1",
    timestamp="2026-06-13T00:00:00Z",
    effect=EffectRecord(status="confirmed", type="write_order",
                        response_digest="a"*64, effect_attestation="gate_executed"),
    assurance=AssuranceBlock(attestation_mode="self_attested", effect_mode="confirmed",
                             ledger_mode="standalone"),
    disposition=Disposition(decision="accept", approver="human", human_disposed=True,
                            verdict_class="executed"),
).seal()

result = verify(capsule)        # never throws
assert result.ok               # a single `ok` gates trust in every other field
```

## Scope boundary (deliberate)

**Does** — the Class 1 agent-profile surface (§6), performable from the Capsule's
own bytes plus the registry contents (and, for chain checks, the producer's
store of Capsules).

**Does NOT** —
- **Substrate verification.** The COSE_Sign1 signature, registration, and the
  Receipt's inclusion proof are the SCITT/COSE substrate's, by reference
  ([`scitt-cose`](https://github.com/action-state-group/scitt-cose)). This
  package never derives `anchored`; a claimed `anchored` mode is reported as an
  unverifiable overclaim (§5.3).
- **Class 2 / manifest-aware verification** (§8.2). Constraint Records are
  *represented* as data (§8.1) but no manifest is fetched and no evidence-schema
  check is performed.

## Develop / test

```bash
cd python
pip install -e ".[dev]"
python -m pytest -q        # positive + negative (MUST-reject) suite
python -m ruff check .
```

The test suite is the conformance contract: every MUST / MUST NOT in the
implemented sections has a positive and a negative case, and the frozen
byte-level vectors under `../test-vectors/` are replayed through `verify()` /
`verify_store()`. The two-layer (`--transparent`) tests run only when the
optional `[transparent]` extra is installed, and skip cleanly otherwise.
