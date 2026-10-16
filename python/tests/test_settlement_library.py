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
