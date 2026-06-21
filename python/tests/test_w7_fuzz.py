# SPDX-License-Identifier: BSD-3-Clause
"""W7 DoS / fuzz hardening tests.

Verifies that malformed inputs never crash the verifier or CLI, and that the
CLI exits nonzero on error and zero on success.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from agent_action_capsule import verify, verify_store


# ---------------------------------------------------------------------------
# 1. Malformed JSON types never crash verify()
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("garbage", [
    None,
    42,
    "string",
    True,
    False,
    [],
    b"bytes",
    {},
    {"effect": "not-an-object"},
    {"disposition": []},
    {"constraints": "not-an-array"},
    {"action_type": 99, "capsule_id": "x"},
    {"effect": {"status": 1.5}},  # float in effect
])
def test_verify_never_raises_on_garbage(garbage):
    """verify() must return a result (ok=False) for any garbage input, never raise."""
    res = verify(garbage)
    assert res.ok is False


# ---------------------------------------------------------------------------
# 2. Deep nesting never causes recursion error
# ---------------------------------------------------------------------------

def _deeply_nested(depth: int) -> dict:
    v: object = "leaf"
    for _ in range(depth):
        v = {"a": v}
    return v  # type: ignore[return-value]


@pytest.mark.parametrize("depth", [50, 200, 500])
def test_deep_nesting_no_crash(depth):
    """Deeply nested structures must not trigger RecursionError."""
    capsule = {
        "effect": _deeply_nested(depth),
        "spec_version": "x",
        "format_version": "2",
        "action_id": "a",
        "action_type": "fyi",
        "operator": "o",
        "developer": "d",
        "timestamp": "t",
        "capsule_id": "a" * 64,
    }
    res = verify(capsule)
    # May or may not be ok, but must not raise
    assert isinstance(res.ok, bool)


# ---------------------------------------------------------------------------
# 3. Huge arrays in constraints
# ---------------------------------------------------------------------------

def test_huge_constraints_array_no_crash():
    """10 000-element constraints array must not crash or time out."""
    capsule = {
        "spec_version": "x",
        "format_version": "2",
        "action_id": "a",
        "action_type": "fyi",
        "operator": "o",
        "developer": "d",
        "timestamp": "t",
        "capsule_id": "a" * 64,
        "constraints": [{"id": f"c{i}", "result": "pass"} for i in range(10000)],
    }
    res = verify(capsule)
    assert isinstance(res.ok, bool)


# ---------------------------------------------------------------------------
# 4. Pathological unicode strings
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ustr", [
    " " * 100,               # whitespace only
    "\xff\xfe" * 50,         # high-byte sequences
    "\U0001F600" * 100,      # emoji (non-BMP)
    "‮" + "x" * 100,   # RTL override
    "﻿" + "action",     # BOM
    "a" * (10 ** 6),         # 1 MB string
])
def test_pathological_unicode_no_crash(ustr):
    """Pathological strings in action_id must not crash the verifier."""
    capsule = {
        "spec_version": "s",
        "format_version": "2",
        "action_id": ustr,
        "action_type": "fyi",
        "operator": "o",
        "developer": "d",
        "timestamp": "t",
        "capsule_id": "a" * 64,
    }
    res = verify(capsule)
    assert isinstance(res.ok, bool)  # must not raise


# ---------------------------------------------------------------------------
# 5. verify_store with mixed garbage
# ---------------------------------------------------------------------------

def test_verify_store_mixed_garbage_no_crash():
    """verify_store must handle a store containing non-capsule objects."""
    store = [None, {}, "string", 42, {"capsule_id": "a" * 64}]
    results = verify_store(store)
    assert len(results) == 5
    for r in results:
        assert isinstance(r.ok, bool)


# ---------------------------------------------------------------------------
# 6. CLI: nonzero exit on bad input, zero exit on valid capsule
# ---------------------------------------------------------------------------

def _cli(*args: str) -> subprocess.CompletedProcess:
    # Use the installed console-script entry point.  There is no __main__.py so
    # "-m agent_action_capsule" does not work; we call cli.main via -c instead
    # so we never depend on the install prefix of the entry-point script.
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "from agent_action_capsule.cli import main; import sys; sys.exit(main())",
            *args,
        ],
        capture_output=True,
        text=True,
    )


def test_cli_nonexistent_file_exits_nonzero():
    result = _cli("verify", "/tmp/nonexistent-capsule-hardening-test.json")
    assert result.returncode != 0


def test_cli_malformed_json_exits_nonzero(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json {{{")
    result = _cli("verify", str(bad))
    assert result.returncode != 0


def test_cli_invalid_capsule_exits_nonzero(tmp_path):
    cap = tmp_path / "invalid.json"
    cap.write_text(json.dumps({"spec_version": "x"}))  # missing required fields
    result = _cli("verify", str(cap))
    assert result.returncode != 0


def test_cli_valid_capsule_exits_zero(tmp_path):
    from agent_action_capsule.emit import emit
    capsule = emit("test/cli", "fyi", "OP", "DEV")
    cap = tmp_path / "cap.json"
    cap.write_text(json.dumps(capsule))
    result = _cli("verify", str(cap))
    assert result.returncode == 0


def test_cli_tampered_capsule_exits_one(tmp_path):
    from agent_action_capsule.emit import emit
    capsule = emit("test/cli-tamper", "fyi", "OP", "DEV")
    capsule["operator"] = "HACKER"  # tamper without resealing
    cap = tmp_path / "tampered.json"
    cap.write_text(json.dumps(capsule))
    result = _cli("verify", str(cap))
    assert result.returncode == 1  # EXIT_NOT_OK


def test_cli_store_nonexistent_exits_nonzero():
    result = _cli("verify", "--store", "/tmp/no-such-store-hardening")
    assert result.returncode != 0


# ---------------------------------------------------------------------------
# 7. Malformed capsule with very large number of keys
# ---------------------------------------------------------------------------

def test_many_keys_no_crash():
    """A capsule with 10 000 extra keys must not crash the verifier."""
    capsule = {f"key_{i}": f"val_{i}" for i in range(10000)}
    capsule.update({
        "spec_version": "x",
        "format_version": "2",
        "action_id": "a",
        "action_type": "fyi",
        "operator": "o",
        "developer": "d",
        "timestamp": "t",
        "capsule_id": "a" * 64,
    })
    res = verify(capsule)
    assert isinstance(res.ok, bool)


# ---------------------------------------------------------------------------
# 8. Floats at various positions are rejected
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path,value", [
    ("top_float", 1.5),
    ("effect_amount", {"status": "dispatched", "amount": 12.50, "effect_attestation": "runtime_claimed"}),
])
def test_float_at_various_positions_rejected(path, value, tmp_path):
    from conftest import base_executed
    cap = base_executed()
    if path == "top_float":
        cap["amount"] = value
    else:
        cap["effect"] = value
    # Do NOT reseal: compute_capsule_id raises FloatInDigestError on floats.
    # verify() must detect the float and report it without raising.
    res = verify(cap)
    assert not res.ok
    assert "float_in_digest_field" in {f.code for f in res.findings}
