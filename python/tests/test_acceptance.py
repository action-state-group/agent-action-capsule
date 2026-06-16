# SPDX-License-Identifier: BSD-3-Clause
"""Acceptance test (1): clean-env build→record(dispatched→chained confirmed)→anchor.

This test reproduces the full acceptance scenario from the [core-extract] task:
1. Build a dispatched capsule (rung 1 emit + rung 2 EffectRecord).
2. Build a chained confirmed capsule referencing the first by capsule_id.
3. Anchor both (rung 6 — non-blocking, digest-only).
4. Verify both with agent_action_capsule.verify() (Class-1 payload verifier).
5. Confirm capsule_id commits model_id, provider, compute_attestation.

The transparent (SCITT/COSE substrate) layer is exercised separately when
agent-action-capsule[transparent] is installed (see transparent.py).
"""
from agent_action_capsule import (
    EffectRecord,
    emit,
    json_digest,
    verify,
)
from agent_action_capsule.anchor import anchor


MODEL_KWARGS = dict(
    operator="acme-co",
    developer="hermes-agent@0.1.0",
    model_id="claude-sonnet-4-6",
    provider="anthropic",
    compute_attestation={"endpoint": "https://api.anthropic.com", "chip": "TPU-v5p"},
)


def test_full_dispatched_to_chained_confirmed_flow():
    req_digest = json_digest({"tool": "stripe_charge", "amount": "40.00", "currency": "USD"})

    # --- Rung 1+2: dispatched ---
    dispatched = emit(
        action_id="charge-001-dispatch",
        action_type="decide",
        effect=EffectRecord(
            status="dispatched",
            type="stripe_charge",
            request_digest=req_digest,
        ),
        **MODEL_KWARGS,
    )
    d_result = verify(dispatched)
    assert d_result.ok, [f.detail for f in d_result.findings if f.severity == "error"]
    assert d_result.assurance["effect_mode"] == "dispatched_unconfirmed"
    assert d_result.assurance["attestation_mode"] == "self_attested"

    # --- Rung 6: anchor dispatched (fire-and-forget) ---
    anchor(dispatched["capsule_id"], endpoint="http://127.0.0.1:1", timeout=0.01,
           on_error=lambda _: None)  # unreachable server — errors suppressed

    # --- Rung 2: chained confirmed ---
    resp_digest = json_digest({"charge_id": "ch_test_abc", "status": "succeeded"})
    confirmed = emit(
        action_id="charge-001-confirm",
        action_type="decide",
        effect=EffectRecord(
            status="confirmed",
            type="stripe_charge",
            request_digest=req_digest,
            response_digest=resp_digest,
        ),
        prior_capsule_id=dispatched["capsule_id"],
        chain_relation="confirms",
        **MODEL_KWARGS,
    )
    c_result = verify(confirmed)
    assert c_result.ok, [f.detail for f in c_result.findings if f.severity == "error"]
    assert c_result.assurance["effect_mode"] == "confirmed"
    assert c_result.assurance["ledger_mode"] == "chained"
    assert confirmed["chain"]["parent_capsule_id"] == dispatched["capsule_id"]

    # --- Rung 6: anchor confirmed ---
    anchor(confirmed["capsule_id"], endpoint="http://127.0.0.1:1", timeout=0.01,
           on_error=lambda _: None)


def test_capsule_id_commits_all_three_model_fields():
    """Tamper model_id, provider, or compute_attestation → verify fails."""
    sealed = emit(action_id="tamper-test", action_type="decide", **MODEL_KWARGS)
    assert verify(sealed).ok

    for field, bad_value in [
        ("model_id", "tampered-model"),
        ("provider", "tampered-provider"),
        ("compute_attestation", {"endpoint": "FAKE", "chip": "FAKE"}),
    ]:
        tampered = dict(sealed)
        tampered["model_attestation"] = dict(tampered["model_attestation"])
        tampered["model_attestation"][field] = bad_value
        result = verify(tampered)
        assert not result.ok, f"tampering {field} should have failed verify"
        assert any("capsule_id" in f.code for f in result.findings if f.severity == "error"), \
            f"expected capsule_id mismatch finding for tampered {field}"
