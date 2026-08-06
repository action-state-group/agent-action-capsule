# SPDX-License-Identifier: BSD-3-Clause
"""Disclosure Envelope reference verifier (draft-mih-...-disclosure-envelope-00)."""
from conftest import reseal

from agent_action_capsule import ModelAttestation, json_digest, verify_disclosure_envelope
from agent_action_capsule.disclosure_envelope import MATCH, MISMATCH


def with_compute_attestation(executed, **compute_attestation):
    d = dict(executed)
    d["model_attestation"] = {"compute_attestation": compute_attestation}
    return reseal(d)


def test_matching_disclosure(executed):
    agent_input = {"amount": "500.00"}
    capsule = with_compute_attestation(executed, agent_input_digest=json_digest(agent_input))
    envelope = {"capsule": capsule, "disclosures": {"agent_input": agent_input}}

    res = verify_disclosure_envelope(envelope)

    assert res.capsule_result.ok
    assert res.ok
    assert res.disclosures_checked == 1
    assert res.disclosures_matched == 1
    assert res.disclosure_findings[0].code == MATCH


def test_mismatching_disclosure_does_not_affect_capsule_verification(executed):
    agent_input = {"amount": "500.00"}
    capsule = with_compute_attestation(executed, agent_input_digest=json_digest(agent_input))
    envelope = {"capsule": capsule, "disclosures": {"agent_input": {"amount": "999.00"}}}

    res = verify_disclosure_envelope(envelope)

    assert res.capsule_result.ok  # capsule_id / Class 1 unaffected by a bad disclosure
    assert not res.ok
    assert res.disclosures_matched == 0
    assert res.disclosure_findings[0].code == MISMATCH


def test_capsule_id_unchanged_by_disclosure(executed):
    agent_input = {"amount": "500.00"}
    capsule = with_compute_attestation(executed, agent_input_digest=json_digest(agent_input))
    id_with_match = capsule["capsule_id"]

    matching = {"capsule": capsule, "disclosures": {"agent_input": agent_input}}
    mismatching = {"capsule": capsule, "disclosures": {"agent_input": {"amount": "999.00"}}}

    assert verify_disclosure_envelope(matching).capsule_result.capsule_id == id_with_match
    assert verify_disclosure_envelope(mismatching).capsule_result.capsule_id == id_with_match


def test_withheld_by_default(executed):
    agent_input = {"amount": "500.00"}
    capsule = with_compute_attestation(executed, agent_input_digest=json_digest(agent_input))
    envelope = {"capsule": capsule}  # no disclosures object at all

    res = verify_disclosure_envelope(envelope)

    assert res.ok
    assert res.disclosures_checked == 0


def test_ineligible_field_reported():
    envelope = {"capsule": {}, "disclosures": {"secret_notes": "nope"}}
    res = verify_disclosure_envelope(envelope)
    assert res.disclosure_findings[0].code == "disclosure_ineligible_field"
    assert not res.ok


def test_no_committed_digest_is_not_a_match(executed):
    capsule = reseal(dict(executed))  # no model_attestation at all
    envelope = {"capsule": capsule, "disclosures": {"agent_output": {"result": "ok"}}}
    res = verify_disclosure_envelope(envelope)
    assert res.disclosure_findings[0].code == "disclosure_no_committed_digest"
    assert not res.ok


def test_both_fields_independently_disclosable(executed):
    agent_input = {"amount": "500.00"}
    agent_output = {"status": "settled"}
    capsule = with_compute_attestation(
        executed,
        agent_input_digest=json_digest(agent_input),
        agent_output_digest=json_digest(agent_output),
    )
    envelope = {"capsule": capsule, "disclosures": {"agent_output": agent_output}}

    res = verify_disclosure_envelope(envelope)

    assert res.ok
    assert res.disclosures_checked == 1  # agent_input stays WITHHELD (not in disclosures)


def test_float_disclosure_is_mismatch_not_error(executed):
    capsule = with_compute_attestation(executed, agent_input_digest="a" * 64)
    envelope = {"capsule": capsule, "disclosures": {"agent_input": {"amount": 12.5}}}
    res = verify_disclosure_envelope(envelope)
    assert res.disclosure_findings[0].code == MISMATCH
    assert not res.ok


def test_model_attestation_dataclass_round_trips(executed):
    """ModelAttestation (§5.3) serializes to the same shape this module reads."""
    agent_input = {"amount": "500.00"}
    ma = ModelAttestation(
        model_id="gpt-x",
        provider="acme",
        compute_attestation={"agent_input_digest": json_digest(agent_input)},
    )
    d = dict(executed)
    d["model_attestation"] = {
        "model_id": ma.model_id,
        "provider": ma.provider,
        "compute_attestation": ma.compute_attestation,
    }
    capsule = reseal(d)
    envelope = {"capsule": capsule, "disclosures": {"agent_input": agent_input}}
    assert verify_disclosure_envelope(envelope).ok
