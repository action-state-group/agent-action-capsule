# SPDX-License-Identifier: BSD-3-Clause
"""W9 format_version validation tests.

Guards the 'no silent v1/v2 mis-parse' invariant. The verifier MUST explicitly
reject any format_version other than "2" (the only currently defined value per
§5.1 of draft-mih-scitt-agent-action-capsule-01).
"""
import re

import pytest

from agent_action_capsule import verify
from agent_action_capsule.emit import emit, DEFAULT_FORMAT_VERSION, DEFAULT_SPEC_VERSION
from conftest import reseal, base_executed


# ---------------------------------------------------------------------------
# 1. v2 is the canonical declared version
# ---------------------------------------------------------------------------

def test_default_format_version_is_v2():
    """The library constant must declare version '2'."""
    assert DEFAULT_FORMAT_VERSION == "2"


def test_emit_produces_v2():
    """emit() must always stamp format_version='2' on the sealed capsule."""
    capsule = emit("test/fv", "fyi", "OP", "DEV")
    assert capsule["format_version"] == "2"


# ---------------------------------------------------------------------------
# 2. v2 capsule verifies cleanly (no format_version finding)
# ---------------------------------------------------------------------------

def test_v2_capsule_accepted():
    """A well-formed v2 capsule verifies without any format_version finding."""
    capsule = emit("test/v2", "fyi", "OP", "DEV")
    res = verify(capsule)
    assert res.ok
    codes = {f.code for f in res.findings}
    assert "unsupported_format_version" not in codes


# ---------------------------------------------------------------------------
# 3. Unknown format_version is explicitly rejected (not silent)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fv", ["1", "3", "v2", "2.0", "", "unknown", "draft-01", "2a"])
def test_unknown_format_version_rejected(fv):
    """Any format_version other than '2' MUST be explicitly rejected."""
    cap = base_executed()
    cap["format_version"] = fv
    cap = reseal(cap)
    res = verify(cap)
    # Must NOT silently accept an unknown format version
    assert not res.ok, f"format_version {fv!r} should be rejected, not silently accepted"
    codes = {f.code for f in res.findings}
    assert "unsupported_format_version" in codes, (
        f"Expected unsupported_format_version finding for {fv!r}"
    )


# ---------------------------------------------------------------------------
# 4. Missing format_version is a structural error (existing behavior)
# ---------------------------------------------------------------------------

def test_missing_format_version_is_structural_error():
    """A capsule missing format_version is rejected with missing_required_field,
    NOT unsupported_format_version (it's absent, not wrong)."""
    cap = base_executed()
    del cap["format_version"]
    res = verify(cap)
    assert not res.ok
    codes = {f.code for f in res.findings}
    assert "missing_required_field" in codes
    # Must NOT also emit unsupported_format_version (field is absent, not wrong)
    assert "unsupported_format_version" not in codes


# ---------------------------------------------------------------------------
# 5. format_version check is check 1 (structural, gates ok)
# ---------------------------------------------------------------------------

def test_format_version_check_is_check_1():
    """The unsupported_format_version finding MUST be check=1 and severity='error'."""
    cap = base_executed()
    cap["format_version"] = "1"
    cap = reseal(cap)
    res = verify(cap)
    fv_findings = [f for f in res.findings if f.code == "unsupported_format_version"]
    assert len(fv_findings) == 1
    assert fv_findings[0].check == 1
    assert fv_findings[0].severity == "error"


# ---------------------------------------------------------------------------
# 6. VAAP v1 format is explicitly rejected (boundary guard)
# ---------------------------------------------------------------------------

def test_vaap_v1_format_explicitly_rejected():
    """gopher-ai/vaap uses format_version '1'. Verifiers MUST reject v1 explicitly
    (no silent mis-parse across v1/v2 boundary). VAAP→v2 reconciliation is flagged
    for the gopher-ai track only — NOT executed here per boundary constraints.
    This test guards the 'no silent v1/v2 mis-parse' requirement."""
    cap = base_executed()
    cap["format_version"] = "1"
    cap = reseal(cap)
    res = verify(cap)
    assert not res.ok
    assert any(f.code == "unsupported_format_version" for f in res.findings)


# ---------------------------------------------------------------------------
# 7. Independent clean-room conformance harness (differential)
# ---------------------------------------------------------------------------

def _cleanroom_check(capsule: dict) -> bool:
    """Minimal clean-room structural check (independent-reader differential).

    Checks only the invariants the VAAP harness would assert on the statement
    layer: format_version=2, required fields present, capsule_id is 64 hex.
    """
    HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
    required = (
        "spec_version", "format_version", "capsule_id", "action_id",
        "action_type", "operator", "developer", "timestamp",
    )
    if not isinstance(capsule, dict):
        return False
    if capsule.get("format_version") != "2":
        return False
    for fld in required:
        if not isinstance(capsule.get(fld), str):
            return False
    if not HEX64.match(capsule.get("capsule_id", "")):
        return False
    return True


def test_cleanroom_accepts_what_library_accepts():
    """Clean-room and library verifier must agree on a well-formed capsule."""
    capsule = emit("test/cleanroom", "fyi", "OP", "DEV")
    lib_ok = verify(capsule).ok
    cr_ok = _cleanroom_check(capsule)
    assert lib_ok is True
    assert cr_ok is True  # cleanroom and library agree


def test_cleanroom_rejects_v1():
    """Clean-room verifier independently rejects format_version='1'."""
    cap = base_executed()
    cap["format_version"] = "1"
    cap = reseal(cap)
    assert _cleanroom_check(cap) is False


def test_cleanroom_rejects_missing_field():
    """Clean-room verifier independently rejects a capsule with a missing required field."""
    cap = base_executed()
    del cap["operator"]
    assert _cleanroom_check(cap) is False
