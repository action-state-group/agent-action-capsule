# SPDX-License-Identifier: BSD-3-Clause
"""The shared JSON nesting limit against ``vectors/json-nesting`` (#498, #427).

The strict readers read objects and arrays nested up to 128 levels deep and
refuse deeper text as other malformed input, JCS refuses a deeper value, and
the verifiers refuse a deeper Capsule or Bundle before any check. No path
raises RecursionError, however deep the input. Go, TypeScript and Rust run
the same file.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from agent_action_capsule import evidence_request as er
from agent_action_capsule.bundle import verify_bundle
from agent_action_capsule.canonical import (
    MAX_NESTING_DEPTH,
    NestingTooDeepError,
    jcs,
    json_digest,
    json_text_too_deep,
    normalize,
    too_deep,
)
from agent_action_capsule.interop_profile._common import parse_json
from agent_action_capsule.verify import verify

ROOT = Path(__file__).resolve().parents[2]
DIR = ROOT / "vectors" / "json-nesting"
DATA = json.loads((DIR / "cases.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
BY_ID = {c["id"]: c for c in CASES}


def test_generator_reproduces_every_file_byte_for_byte(tmp_path):
    (tmp_path / "README.md").write_bytes((DIR / "README.md").read_bytes())
    script = ROOT / "python" / "scripts" / "generate_json_nesting_vectors.py"
    subprocess.run([sys.executable, str(script), "--out", str(tmp_path)], check=True)
    for path in DIR.iterdir():
        assert (tmp_path / path.name).read_bytes() == path.read_bytes(), path.name


def test_the_readme_lists_every_case():
    readme = (DIR / "README.md").read_text(encoding="utf-8")
    assert DATA["max_nesting_depth"] == MAX_NESTING_DEPTH == 128
    for case in CASES:
        assert f"`{case['id']}`" in readme, case["id"]


def _deeper(case: dict):
    """A refused case's value, built from the accepted case it wraps."""
    inner = json.loads(BY_ID[case["wraps"]]["json"])
    return [inner] if case["json"].startswith("[") else {"a": inner}


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_readers_and_jcs(case):
    data = case["json"].encode("utf-8")
    assert json_text_too_deep(case["json"]) is not case["accept"]
    parsed = parse_json(data)
    if case["accept"]:
        value = er._decode_json(data)
        assert parsed is not None and parsed.well_formed and parsed.value == value
        assert not too_deep(value)
        assert hashlib.sha256(jcs(value)).hexdigest() == case["jcs_sha256"]
        assert json.loads(case["json"]) == value
    else:
        with pytest.raises(er.RequestError) as refused:
            er._decode_json(data)
        assert refused.value.reason == er.REASON_REQUEST_MALFORMED
        assert parsed is None
        value = _deeper(case)
        assert value == json.loads(case["json"])
        assert too_deep(value)
        with pytest.raises(NestingTooDeepError):
            jcs(value)
        with pytest.raises(NestingTooDeepError):
            normalize(value)


def _arrays(depth: int):
    value: object = 0
    for _ in range(depth):
        value = [value]
    return value


@pytest.mark.parametrize("depth", [999, 100_000])
def test_far_deeper_input_is_refused_without_recursion_error(depth):
    # #427: jcs recursed once per level and raised RecursionError near 500.
    text = "[" * depth + "]" * depth
    assert parse_json(text.encode()) is None
    with pytest.raises(er.RequestError):
        er._decode_json(text.encode())
    with pytest.raises(NestingTooDeepError):
        json_digest(_arrays(depth))


def test_a_value_that_contains_itself_is_too_deep():
    cycle: dict = {}
    cycle["self"] = cycle
    assert too_deep(cycle)
    with pytest.raises(NestingTooDeepError):
        jcs(cycle)


def test_brackets_in_strings_do_not_nest():
    assert not json_text_too_deep('["' + "[" * 500 + '\\"' + '"]')
    assert json_text_too_deep("[" * 129 + '"]]"' + "]" * 129)
    # An escaped backslash ends the escape: the quote after it closes the string.
    assert json_text_too_deep('["\\\\"' + "[" * 129)
    assert not json_text_too_deep('["\\\\\\"' + "[" * 129)


@pytest.mark.parametrize(
    "text",
    [
        '["' + '\\"' * 500_000,  # 1 MB unterminated string of escaped quotes
        '"' * 1_000_000,
        "[" * 128 + '"' + "\\" * 1_000_000,
    ],
    ids=["escaped-quotes", "quotes", "backslashes"],
)
def test_the_text_check_is_linear(text):
    # The regex scan it replaced took about 12 s on 80 KB of escaped quotes
    # (quadratic). One pass over 1 MB takes well under a second; the bound is
    # loose so a slow runner does not flake.
    started = time.perf_counter()
    json_text_too_deep(text)
    parse_json(text.encode())
    with pytest.raises(er.RequestError):
        er._decode_json(text.encode())
    assert time.perf_counter() - started < 5


def test_verify_refuses_a_capsule_past_the_limit():
    at_limit = {"deep": _arrays(MAX_NESTING_DEPTH - 1)}
    assert all(f.code != "verifier_internal_error" for f in verify(at_limit).findings)
    past = verify({"deep": _arrays(MAX_NESTING_DEPTH)})
    assert not past.ok
    assert [f.code for f in past.findings] == ["verifier_internal_error"]


def test_verify_bundle_refuses_a_bundle_past_the_limit():
    malformed = ("fail", ("bundle_malformed",))
    at_limit = verify_bundle({"records": [], "x": _arrays(MAX_NESTING_DEPTH - 1)})
    assert (at_limit.graph_closure.status, at_limit.graph_closure.findings) != malformed
    past = verify_bundle({"records": [], "x": _arrays(MAX_NESTING_DEPTH)})
    for claim in (past.graph_closure, past.interval_coverage, past.per_record_membership):
        assert (claim.status, claim.findings) == malformed


def test_a_record_past_the_limit_has_an_invalid_signature_not_unclaimed():
    # Go and Rust grade it before anything else; the unsigned shortcut must not hide it.
    from agent_action_capsule.producer_envelope import verify_record_signature

    assert verify_record_signature({"capsule_id": "c", "x": _arrays(MAX_NESTING_DEPTH - 1)})[0] == "unclaimed"
    assert verify_record_signature({"capsule_id": "c", "x": _arrays(MAX_NESTING_DEPTH)})[0] == "invalid"


def test_a_settlement_leg_past_the_limit_reports_only_capsule_invalid():
    from agent_action_capsule.settlement import verify_settlements

    report = verify_settlements([{"capsule_id": "c1", "x": _arrays(MAX_NESTING_DEPTH)}])
    assert report.failures == [{"records": ["c1"], "code": "capsule_invalid"}]


def test_a_standard_history_card_past_the_limit_is_read_without_recursion_error():
    from agent_action_capsule.standard_history import check_card

    # Go's Check fails card_form and counts_integral for a card it cannot parse.
    for depth in (MAX_NESTING_DEPTH + 1, 100_000):
        result = check_card(_arrays(depth))
        assert result["card_form"] == "FAIL" and result["counts_integral"] == "FAIL"
        assert result == check_card(_arrays(MAX_NESTING_DEPTH + 1))


def test_loads_bounded_keeps_the_encodings_json_loads_accepts():
    from agent_action_capsule.canonical import loads_bounded

    assert loads_bounded("[1]".encode("utf-16")) == [1]
    assert loads_bounded('["é"]'.encode()) == ["é"]


def test_the_cli_reads_a_file_past_the_limit_without_recursion_error(tmp_path):
    from agent_action_capsule import cli

    path = tmp_path / "deep.json"
    path.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    with pytest.raises(ValueError):
        cli._load_json(str(path))
    assert cli.main(["verify", str(path)]) == cli.EXIT_CANNOT_RUN
