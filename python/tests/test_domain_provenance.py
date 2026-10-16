# SPDX-License-Identifier: BSD-3-Clause
"""Tests for §-02 domain / provenance / self_reported_reasoning fields.

Acceptance criteria:
- Round-trip: a Capsule sealed with domain/provenance/self_reported_reasoning
  → verify → ok.
- Backward-compat: a -01 capsule (no domain/provenance) still verifies ok.
- Unknown value is info, not error.
- Type violation (non-string domain/provenance) is an error.
- self_reported_reasoning.digest malformed → InvariantError at construction.
- capsule_id commits domain/provenance/self_reported_reasoning (tamper = mismatch).
"""
import hashlib

import pytest
from _capsules import sealed

from agent_action_capsule import ModelAttestation, verify
from agent_action_capsule.contracts import (
    DOMAIN_VALUES,
    PROVENANCE_RANK,
    PROVENANCE_VALUES,
    InvariantError,
    SelfReportedReasoning,
)
from agent_action_capsule.parse import parse_capsule

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE = dict(
    action_id="act-domain-01",
    action_type="decide",
    operator="test-org",
    developer="test-agent@1.0",
    model_attestation=ModelAttestation(model_id="claude-sonnet-4-6", provider="anthropic"),
)

_COT = b"I decided to call the tool because the user asked for it."
_COT_DIGEST = hashlib.sha256(_COT).hexdigest()
_SRR = SelfReportedReasoning(digest=_COT_DIGEST)


# ---------------------------------------------------------------------------
# Contract constants
# ---------------------------------------------------------------------------


def test_domain_values_frozen():
    assert DOMAIN_VALUES == frozenset({"action", "memory", "reasoning"})


def test_provenance_values_frozen():
    assert PROVENANCE_VALUES == frozenset({"gate", "runtime", "collector"})


def test_provenance_rank_order():
    assert PROVENANCE_RANK["gate"] > PROVENANCE_RANK["runtime"] > PROVENANCE_RANK["collector"]


# ---------------------------------------------------------------------------
# Sealed round-trips
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fields", [
    {"domain": "action"},
    {"domain": "memory"},
    {"domain": "reasoning", "action_type": "fyi"},
    {"provenance": "gate"},
    {"provenance": "runtime"},
    {"provenance": "collector"},
    {"domain": "action", "provenance": "gate"},
    {"self_reported_reasoning": _SRR},
    {"domain": "action", "provenance": "runtime", "self_reported_reasoning": _SRR},
])
def test_sealed_domain_provenance_reasoning_verifies(fields):
    r = verify(sealed(**{**_BASE, **fields}))
    assert r.ok, [f.code for f in r.findings]


# ---------------------------------------------------------------------------
# capsule_id tamper-evidence
# ---------------------------------------------------------------------------


def test_domain_committed_to_capsule_id():
    c = sealed(**_BASE, domain="action")
    tampered = dict(c)
    tampered["domain"] = "memory"
    r = verify(tampered)
    assert not r.ok
    codes = [f.code for f in r.findings]
    assert "capsule_id_mismatch" in codes


def test_provenance_committed_to_capsule_id():
    c = sealed(**_BASE, provenance="gate")
    tampered = dict(c)
    tampered["provenance"] = "collector"
    r = verify(tampered)
    assert not r.ok
    assert any(f.code == "capsule_id_mismatch" for f in r.findings)


def test_self_reported_reasoning_committed_to_capsule_id():
    c = sealed(**_BASE, self_reported_reasoning=_SRR)
    tampered = dict(c)
    tampered["self_reported_reasoning"] = {"digest": "a" * 64}
    r = verify(tampered)
    assert not r.ok
    assert any(f.code == "capsule_id_mismatch" for f in r.findings)


# ---------------------------------------------------------------------------
# Backward-compat: -01 capsules still verify ok
# ---------------------------------------------------------------------------


def test_minus_01_capsule_verifies():
    c = sealed(**_BASE, spec_version="draft-mih-scitt-agent-action-capsule-01")
    assert "domain" not in c
    assert "provenance" not in c
    r = verify(c)
    assert r.ok


# ---------------------------------------------------------------------------
# Unknown value → info, not error
# ---------------------------------------------------------------------------


def test_unknown_domain_value_is_info():
    c = sealed(**_BASE, domain="workflow")
    r = verify(c)
    assert r.ok
    info_codes = [f.code for f in r.findings if f.severity == "info"]
    assert "domain_unknown_value" in info_codes


def test_unknown_provenance_value_is_info():
    c = sealed(**_BASE, provenance="hardware_tee")
    r = verify(c)
    assert r.ok
    info_codes = [f.code for f in r.findings if f.severity == "info"]
    assert "provenance_unknown_value" in info_codes


def test_x_prefixed_domain_no_info():
    c = sealed(**_BASE, domain="x-custom-domain")
    r = verify(c)
    assert r.ok
    assert not any(f.code == "domain_unknown_value" for f in r.findings)


def test_x_prefixed_provenance_no_info():
    c = sealed(**_BASE, provenance="x-hardware-tee")
    r = verify(c)
    assert r.ok
    assert not any(f.code == "provenance_unknown_value" for f in r.findings)


# ---------------------------------------------------------------------------
# Type violations → error
# ---------------------------------------------------------------------------


def test_non_string_domain_is_error():
    c = sealed(**_BASE)
    tampered = dict(c)
    tampered["domain"] = 42
    r = verify(tampered)
    assert not r.ok
    assert any(f.code == "domain_not_string" for f in r.findings)


def test_non_string_provenance_is_error():
    c = sealed(**_BASE)
    tampered = dict(c)
    tampered["provenance"] = ["gate"]
    r = verify(tampered)
    assert not r.ok
    assert any(f.code == "provenance_not_string" for f in r.findings)


# ---------------------------------------------------------------------------
# SelfReportedReasoning dataclass invariants
# ---------------------------------------------------------------------------


def test_self_reported_reasoning_bad_digest():
    with pytest.raises(InvariantError, match="64-hex"):
        SelfReportedReasoning(digest="not-hex")


def test_self_reported_reasoning_ok():
    srr = SelfReportedReasoning(digest=_COT_DIGEST)
    assert srr.digest == _COT_DIGEST


# ---------------------------------------------------------------------------
# parse_capsule round-trip
# ---------------------------------------------------------------------------


def test_parse_capsule_domain_provenance():
    c = sealed(**_BASE, domain="memory", provenance="collector")
    parsed = parse_capsule(c)
    assert parsed.domain == "memory"
    assert parsed.provenance == "collector"


def test_parse_capsule_self_reported_reasoning():
    c = sealed(**_BASE, self_reported_reasoning=_SRR)
    parsed = parse_capsule(c)
    assert parsed.self_reported_reasoning is not None
    assert parsed.self_reported_reasoning.digest == _COT_DIGEST


def test_parse_capsule_none_when_absent():
    c = sealed(**_BASE)
    parsed = parse_capsule(c)
    assert parsed.domain is None
    assert parsed.provenance is None
    assert parsed.self_reported_reasoning is None
