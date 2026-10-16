# SPDX-License-Identifier: BSD-3-Clause
"""``agent_action_capsule.settlement.verify_settlements`` against ``vectors/settlement``.

``test_settlement_vectors.py`` checks the vectors with an independent reading
of the draft; this runs the library verifier on the same cases.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

pytest.importorskip("scitt_cose")

from agent_action_capsule.settlement import (  # noqa: E402
    DELIVERY_DIRECTIONS,
    LEGS,
    MEMBERS,
    PAYMENT_REF_TYPES,
    ROLES,
    SETTLEMENT_VERSION,
    STATUSES,
    WRAPPED_TYPES,
    structure_failures,
    verify_settlements,
)

DIR = Path(__file__).resolve().parents[2] / "vectors" / "settlement"
CASES = json.loads((DIR / "cases.json").read_text())
REGISTRY = json.loads((DIR / "registry.json").read_text())


def _b64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def test_tables_match_the_draft_registry():
    assert SETTLEMENT_VERSION == REGISTRY["settlement_version"]
    assert list(LEGS) == REGISTRY["legs"]
    assert list(ROLES) == REGISTRY["sealer_roles"]
    assert list(STATUSES) == REGISTRY["statuses"]
    assert DELIVERY_DIRECTIONS == REGISTRY["delivery_directions"]
    assert WRAPPED_TYPES == REGISTRY["wrapped_types"]
    assert {t: (list(v["qualifiers"]), v["receive_fee"]) for t, v in PAYMENT_REF_TYPES.items()} == {
        t: (v["qualifiers"], v["receive_fee"]) for t, v in REGISTRY["payment_ref_types"].items()}
    assert {leg: {k: list(v) for k, v in m.items()} for leg, m in MEMBERS.items()} == REGISTRY["settlement_members"]


def run(case: dict) -> dict:
    """Run one case: each leg gets its envelope as ``signature``/``key_id``,
    and capsule IDs in the report are mapped back to the case's labels."""
    capsules, labels = [], {}
    for r in case["records"]:
        capsule = dict(r["capsule"])
        if r.get("envelope_hex"):
            capsule["signature"] = r["envelope_hex"]
            capsule["key_id"] = r["envelope_kid"]
        capsules.append(capsule)
        labels[r["capsule_id"]] = r["label"]
    objects = {w["digest"]: _b64u(w["octets_b64u"]) for w in case["wrapped_objects"]}
    report = verify_settlements(capsules, key_policy=case["key_policy"], wrapped_objects=objects)

    def relabel(entries):
        return [{"records": [labels.get(c, c) for c in e["records"]], "code": e["code"]} for e in entries]

    settlements = []
    for s in report.settlements:
        s = {k: v for k, v in s.items() if k != "iso20022"}  # not carried by the vectors
        s["terms"] = labels[s["terms"]]
        settlements.append(s)
    return {"conforming": report.conforming, "failures": relabel(report.failures),
            "findings": relabel(report.findings), "settlements": settlements}


@pytest.mark.parametrize("case", CASES["cases"], ids=lambda c: c["id"])
def test_derivation_matches_the_vector(case):
    assert run(case) == case["expect"]


def test_every_case_ran():
    assert len(CASES["cases"]) == CASES["count"] == 19


def test_non_dict_inputs_are_reported_not_raised():
    report = verify_settlements([None, "x", {"capsule_id": 1}])
    assert not report.conforming
    assert [f["code"] for f in report.failures][:2] == ["capsule_invalid", "capsule_invalid"]


def test_structure_failures_names_the_draft_codes():
    assert structure_failures(None) == ["settlement_malformed"]
    leg = {"version": "0", "leg": "payer_observed", "sealer_role": "payee", "terms_ref": "0" * 64,
           "amount": {"value": "1.5", "assetCode": "USD", "assetScale": 2},
           "payment_ref": {"type": "acp.order_id", "value": "o-1"}, "status": "settled",
           "observed_at": "2026-10-15T00:00:00Z"}
    assert structure_failures(leg) == ["leg_role_mismatch", "amount_not_exact"]


def _observed(**overrides):
    leg = {"version": "0", "leg": "payer_observed", "sealer_role": "payer", "terms_ref": "0" * 64,
           "amount": {"value": "15", "assetCode": "USD", "assetScale": 2},
           "payment_ref": {"type": "acp.order_id", "value": "o-1"}, "status": "settled",
           "observed_at": "2026-10-15T00:00:00Z"}
    leg.update(overrides)
    return leg


@pytest.mark.parametrize("overrides", [
    {"amount": {"value": "15\n", "assetCode": "USD", "assetScale": 2}},
    {"terms_ref": "0" * 64 + "\n"},
    {"observed_at": "2026-10-15T00:00:00Z\n"},
    {"observed_at": "２０２6-10-15T00:00:00Z"},
])
def test_patterns_match_the_whole_string_in_ascii(overrides):
    assert structure_failures(_observed(**overrides))


def test_a_null_payment_ref_is_malformed_not_a_crash():
    assert structure_failures(_observed(payment_ref=None)) == ["settlement_malformed"]


def test_unhashable_members_are_malformed_not_a_crash():
    leg = {"version": "0", "leg": "delivered", "sealer_role": "payer", "terms_ref": "0" * 64,
           "observed_at": "2026-10-15T00:00:00Z", "delivery": {"direction": ["received"]}}
    assert structure_failures(leg) == ["settlement_malformed"]
    assert structure_failures(_observed(wrapped=[{"type": ["x402.offer"], "digest_alg": "SHA-256",
                                                  "digest": "0" * 64}])) == ["settlement_malformed"]
    assert structure_failures(_observed(wrapped=[{"type": "x402.offer", "digest_alg": "SHA-256",
                                                  "digest": "0" * 64, "content": 7}])) == ["settlement_malformed"]


def test_two_heads_stating_one_amount_at_two_scales_agree():
    case = next(c for c in CASES["cases"] if c["id"] == "pos-x402-two-sided-agreed")
    payer = next(r for r in case["records"] if r["capsule"]["settlement"]["leg"] == "payer_observed")
    from agent_action_capsule.settlement import SettlementReport, _pair  # noqa: PLC0415

    leg = payer["capsule"]["settlement"]
    rescaled = {**leg, "amount": {**leg["amount"], "value": leg["amount"]["value"] + "00",
                                  "assetScale": leg["amount"]["assetScale"] + 2}}
    payee = next(r for r in case["records"] if r["capsule"]["settlement"]["leg"] == "payee_observed")
    terms = next(r for r in case["records"] if r["capsule"]["settlement"]["leg"] == "terms")
    report = SettlementReport(conforming=True, keys={"a:k1": "k1", "b:k1": "k1", "c:k2": "k2"})
    out = _pair(terms["capsule_id"], terms["capsule"]["settlement"], [("a:k1", leg), ("b:k1", rescaled)],
                [("c:k2", payee["capsule"]["settlement"])], report, {})
    assert out["payment_state"] == "agreed", out


@pytest.mark.parametrize("network", [True, 1, None, ["eip155:8453"], {"id": 1}])
def test_payment_ref_qualifiers_are_strings(network):
    ref = {"type": "x402.transaction", "value": "0xabc", "network": network}
    assert structure_failures(_observed(payment_ref=ref)) == ["settlement_malformed"]


def test_wrapped_content_that_does_not_decode_is_a_digest_mismatch():
    import hashlib

    from agent_action_capsule.settlement import _wrapped_failures

    leg = _observed(wrapped=[{"type": "x402.offer", "digest_alg": "SHA-256",
                              "digest": hashlib.sha256(b"").hexdigest(), "content": "!"}])
    assert _wrapped_failures(leg, None, {}) == ["wrapped_digest_mismatch"]


def test_an_envelope_with_whitespace_in_its_hex_is_not_authenticated():
    from agent_action_capsule.settlement import _envelope_key

    case = CASES["cases"][0]
    record = next(r for r in case["records"] if r.get("envelope_hex"))
    capsule = {**record["capsule"], "signature": record["envelope_hex"]}
    assert _envelope_key(capsule) is not None
    assert _envelope_key({**capsule, "signature": " " + record["envelope_hex"]}) is None


def _delivered(**delivery):
    return {"version": "0", "leg": "delivered", "sealer_role": "payee", "terms_ref": "0" * 64,
            "observed_at": "2026-10-15T00:00:00Z", "delivery": {"direction": "sent", **delivery}}


@pytest.mark.parametrize("delivery", [
    {"carrier": None}, {"carrier": "UPS", "tracking_digest": "AB"}, {"carrier": "UPS", "address_digest": 1},
    {"carrier": "UPS", "status": "lost"}, {"carrier": "UPS", "shipped_at": "yesterday"},
    {"carrier": "UPS", "delivered_at": None},
])
def test_optional_delivery_members_keep_their_types(delivery):
    assert structure_failures(_delivered(**delivery)) == ["settlement_malformed"]


def test_a_well_formed_physical_delivery_passes():
    assert structure_failures(_delivered(carrier="UPS", tracking_digest="ab" * 32, status="in_transit",
                                         shipped_at="2026-10-15T00:00:00Z")) == []


def test_valid_until_is_an_rfc3339_utc_time():
    terms = {"version": "0", "leg": "terms", "sealer_role": "payee",
             "amount": {"value": "1", "assetCode": "USD", "assetScale": 2}, "valid_until": 7}
    assert structure_failures(terms) == ["settlement_malformed"]
    assert structure_failures({**terms, "valid_until": "2026-10-16T00:00:00Z"}) == []


def test_amounts_longer_than_the_int_conversion_limit_compare_exactly():
    from agent_action_capsule.settlement import _amount_rule_holds, _amounts_equal

    big = "9" * 5000
    assert _amounts_equal({"value": big, "assetCode": "X", "assetScale": 0},
                          {"value": big + "00", "assetCode": "X", "assetScale": 2})
    payer = {"amount": {"value": "1" + "0" * 5000, "assetCode": "X", "assetScale": 0}}
    payee = {"received": {"value": big, "assetCode": "X", "assetScale": 0}}
    assert _amount_rule_holds(payer, payee, {"value": "1", "assetCode": "X", "assetScale": 0})
    assert not _amount_rule_holds(payer, payee, {"value": "2", "assetCode": "X", "assetScale": 0})


def test_deeply_nested_wrapped_octets_never_raise():
    import hashlib

    from agent_action_capsule.settlement import _x402_scheme

    octets = b"[" * 100000 + b"]" * 100000
    leg = {"wrapped": [{"type": "x402.payment-payload", "digest": hashlib.sha256(octets).hexdigest()}]}
    assert _x402_scheme([leg], {hashlib.sha256(octets).hexdigest(): octets}) is None
