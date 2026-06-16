# SPDX-License-Identifier: BSD-3-Clause
"""Tests for rung 1 emit() and the ModelAttestation tamper-evidence guarantee.

Acceptance check: capsule_id commits model_id, provider, compute_attestation —
tampering any of the three makes verify() report ok=False.
"""

import pytest

from agent_action_capsule import (
    EffectRecord,
    ModelAttestation,
    compute_capsule_id,
    emit,
    json_digest,
    verify,
)

EMIT_KWARGS = dict(
    action_id="act-001",
    action_type="decide",
    operator="test-org",
    developer="test-agent@1.0",
    model_id="claude-sonnet-4-6",
    provider="anthropic",
    compute_attestation={"endpoint": "https://api.anthropic.com", "chip": "TPU-v5"},
)


def test_emit_returns_sealed_capsule():
    sealed = emit(**EMIT_KWARGS)
    assert isinstance(sealed, dict)
    assert len(sealed["capsule_id"]) == 64
    assert sealed["capsule_id"].islower()


def test_emit_verify_ok():
    sealed = emit(**EMIT_KWARGS)
    result = verify(sealed)
    assert result.ok, [f.detail for f in result.findings if f.severity == "error"]


def test_emit_model_attestation_in_body():
    sealed = emit(**EMIT_KWARGS)
    ma = sealed["model_attestation"]
    assert ma["model_id"] == "claude-sonnet-4-6"
    assert ma["provider"] == "anthropic"
    assert ma["compute_attestation"] == {"endpoint": "https://api.anthropic.com", "chip": "TPU-v5"}


def test_model_attestation_committed_to_capsule_id():
    """capsule_id is a digest over the body including model_attestation."""
    sealed = emit(**EMIT_KWARGS)
    # Recomputing capsule_id over the body (minus capsule_id + chain) must match.
    assert sealed["capsule_id"] == compute_capsule_id({k: v for k, v in sealed.items() if k != "chain"})


def test_tamper_model_id_fails_verify():
    sealed = emit(**EMIT_KWARGS)
    tampered = dict(sealed)
    tampered["model_attestation"] = dict(tampered["model_attestation"])
    tampered["model_attestation"]["model_id"] = "TAMPERED"
    result = verify(tampered)
    assert not result.ok


def test_tamper_provider_fails_verify():
    sealed = emit(**EMIT_KWARGS)
    tampered = dict(sealed)
    tampered["model_attestation"] = dict(tampered["model_attestation"])
    tampered["model_attestation"]["provider"] = "TAMPERED"
    result = verify(tampered)
    assert not result.ok


def test_tamper_compute_attestation_fails_verify():
    sealed = emit(**EMIT_KWARGS)
    tampered = dict(sealed)
    tampered["model_attestation"] = dict(tampered["model_attestation"])
    tampered["model_attestation"]["compute_attestation"] = {"endpoint": "TAMPERED", "chip": "FAKE"}
    result = verify(tampered)
    assert not result.ok


def test_emit_without_compute_attestation():
    kw = {**EMIT_KWARGS, "compute_attestation": None}
    del kw["compute_attestation"]
    sealed = emit(**kw)
    result = verify(sealed)
    assert result.ok
    assert "compute_attestation" not in sealed.get("model_attestation", {})


def test_emit_dispatched_effect():
    req_digest = json_digest({"request": "do-something"})
    sealed = emit(
        **EMIT_KWARGS,
        effect=EffectRecord(
            status="dispatched",
            type="api_call",
            request_digest=req_digest,
        ),
    )
    result = verify(sealed)
    assert result.ok
    assert result.assurance["effect_mode"] == "dispatched_unconfirmed"


def test_emit_confirmed_effect():
    req_digest = json_digest({"request": "do-something"})
    resp_digest = json_digest({"result": "ok"})
    sealed = emit(
        **EMIT_KWARGS,
        effect=EffectRecord(
            status="confirmed",
            type="api_call",
            request_digest=req_digest,
            response_digest=resp_digest,
        ),
    )
    result = verify(sealed)
    assert result.ok
    assert result.assurance["effect_mode"] == "confirmed"


def test_emit_chained_capsule():
    """Rung 2 chaining: second emit references the first by capsule_id."""
    kw = {k: v for k, v in EMIT_KWARGS.items() if k != "action_id"}
    first = emit(action_id="act-001", **kw)
    second = emit(
        action_id="act-002",
        prior_capsule_id=first["capsule_id"],
        **kw,
    )
    assert second.get("chain", {}).get("parent_capsule_id") == first["capsule_id"]
    result = verify(second)
    assert result.ok
    assert result.assurance["ledger_mode"] == "chained"


def test_emit_dispatched_then_chained_confirmed():
    """Full rung-2 round-trip: dispatched → chained confirmed capsule."""
    req_digest = json_digest({"call": "stripe_charge", "amount": "40.00"})
    kw = {k: v for k, v in EMIT_KWARGS.items() if k != "action_id"}

    dispatched = emit(
        action_id="charge-dispatch",
        effect=EffectRecord(
            status="dispatched",
            type="stripe_charge",
            request_digest=req_digest,
        ),
        **kw,
    )
    assert verify(dispatched).ok
    assert dispatched["assurance"]["effect_mode"] == "dispatched_unconfirmed"

    resp_digest = json_digest({"charge_id": "ch_test_123", "status": "succeeded"})
    confirmed = emit(
        action_id="charge-confirm",
        effect=EffectRecord(
            status="confirmed",
            type="stripe_charge",
            request_digest=req_digest,
            response_digest=resp_digest,
        ),
        prior_capsule_id=dispatched["capsule_id"],
        chain_relation="confirms",
        **kw,
    )
    assert verify(confirmed).ok
    assert confirmed["assurance"]["effect_mode"] == "confirmed"
    assert confirmed["assurance"]["ledger_mode"] == "chained"
    assert confirmed["chain"]["parent_capsule_id"] == dispatched["capsule_id"]
    assert confirmed["chain"]["relation"] == "confirms"


def test_model_attestation_dataclass_validation():
    from agent_action_capsule.contracts import InvariantError

    with pytest.raises(InvariantError):
        ModelAttestation(model_id="", provider="anthropic")
    with pytest.raises(InvariantError):
        ModelAttestation(model_id="gpt-4", provider="")
    with pytest.raises((InvariantError, TypeError)):
        ModelAttestation(model_id="gpt-4", provider="openai", compute_attestation="not-a-dict")
