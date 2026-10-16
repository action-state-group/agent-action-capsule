# SPDX-License-Identifier: BSD-3-Clause
"""Verifier checks over Capsules sealed with ``Capsule.seal()``.

The model attestation, effect and chain blocks are committed to
``capsule_id``; ``verify()`` reports the assurance they imply and fails on a
post-seal tamper of any of them.
"""
import pytest
from _capsules import sealed

from agent_action_capsule import (
    Chain,
    EffectRecord,
    ModelAttestation,
    compute_capsule_id,
    json_digest,
    verify,
)
from agent_action_capsule.contracts import InvariantError

MODEL = ModelAttestation(
    model_id="claude-sonnet-4-6",
    provider="anthropic",
    compute_attestation={"endpoint": "https://api.anthropic.com", "chip": "TPU-v5"},
)


def _errors(result):
    return [f.detail for f in result.findings if f.severity == "error"]


def test_model_attested_capsule_verifies():
    result = verify(sealed(model_attestation=MODEL))
    assert result.ok, _errors(result)


def test_model_attestation_committed_to_capsule_id():
    capsule = sealed(model_attestation=MODEL)
    assert capsule["capsule_id"] == compute_capsule_id(capsule)


@pytest.mark.parametrize("field,value", [
    ("model_id", "TAMPERED"),
    ("provider", "TAMPERED"),
    ("compute_attestation", {"endpoint": "FAKE", "chip": "FAKE"}),
])
def test_tampered_model_attestation_fails_verify(field, value):
    tampered = dict(sealed(model_attestation=MODEL))
    tampered["model_attestation"] = {**tampered["model_attestation"], field: value}
    assert not verify(tampered).ok


def test_model_attestation_without_compute_attestation_verifies():
    capsule = sealed(model_attestation=ModelAttestation(model_id="claude-sonnet-4-6", provider="anthropic"))
    assert verify(capsule).ok


def test_dispatched_effect_reports_dispatched_unconfirmed():
    effect = EffectRecord(
        status="dispatched",
        type="api_call",
        request_digest=json_digest({"request": "do-something"}),
        effect_attestation="runtime_claimed",
    )
    result = verify(sealed(model_attestation=MODEL, effect=effect))
    assert result.ok, _errors(result)
    assert result.assurance["effect_mode"] == "dispatched_unconfirmed"


def test_confirmed_effect_reports_confirmed():
    effect = EffectRecord(
        status="confirmed",
        type="api_call",
        request_digest=json_digest({"request": "do-something"}),
        response_digest=json_digest({"result": "ok"}),
        effect_attestation="runtime_claimed",
    )
    result = verify(sealed(model_attestation=MODEL, effect=effect))
    assert result.ok, _errors(result)
    assert result.assurance["effect_mode"] == "confirmed"


def test_chained_capsule_reports_chained():
    first = sealed(action_id="act-001", model_attestation=MODEL)
    second = sealed(
        action_id="act-002",
        model_attestation=MODEL,
        chain=Chain(parent_capsule_id=first["capsule_id"], relation="follows"),
    )
    result = verify(second)
    assert result.ok, _errors(result)
    assert result.assurance["ledger_mode"] == "chained"


def test_dispatched_then_chained_confirmed():
    req_digest = json_digest({"call": "stripe_charge", "amount": "40.00"})
    dispatched = sealed(
        action_id="charge-dispatch",
        effect=EffectRecord(
            status="dispatched",
            type="stripe_charge",
            request_digest=req_digest,
            effect_attestation="runtime_claimed",
        ),
    )
    assert verify(dispatched).ok
    confirmed = sealed(
        action_id="charge-confirm",
        effect=EffectRecord(
            status="confirmed",
            type="stripe_charge",
            request_digest=req_digest,
            response_digest=json_digest({"charge_id": "ch_test_123", "status": "succeeded"}),
            effect_attestation="runtime_claimed",
        ),
        chain=Chain(parent_capsule_id=dispatched["capsule_id"], relation="confirms"),
    )
    result = verify(confirmed)
    assert result.ok, _errors(result)
    assert result.assurance["effect_mode"] == "confirmed"
    assert result.assurance["ledger_mode"] == "chained"


def test_tamper_changes_capsule_id():
    capsule = sealed()
    mutated = {**capsule, "operator": "EVIL-CO"}
    assert compute_capsule_id(mutated) != capsule["capsule_id"]
    assert not verify(mutated).ok


def test_model_attestation_dataclass_validation():
    with pytest.raises(InvariantError):
        ModelAttestation(model_id="", provider="anthropic")
    with pytest.raises(InvariantError):
        ModelAttestation(model_id="gpt-4", provider="")
    with pytest.raises((InvariantError, TypeError)):
        ModelAttestation(model_id="gpt-4", provider="openai", compute_attestation="not-a-dict")
