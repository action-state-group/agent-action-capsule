# SPDX-License-Identifier: BSD-3-Clause
"""The shared CBOR nesting limit against ``vectors/cbor-nesting`` (#504).

The interop profile's strict CBOR decoder and the Evidence Request reader read
items nested up to 128 levels deep (an array, a map or a tag around an item is
one level) and refuse deeper input as malformed, however deep. Go and Rust run
the same file.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_action_capsule import evidence_request as er
from agent_action_capsule.canonical import MAX_NESTING_DEPTH
from agent_action_capsule.interop_profile import _cbor

DIR = Path(__file__).resolve().parents[2] / "vectors" / "cbor-nesting"
DATA = json.loads((DIR / "cases.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]


def test_the_vector_states_the_json_limit() -> None:
    assert DATA["max_nesting_depth"] == MAX_NESTING_DEPTH == 128
    assert len(CASES) == 9


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_generic_decoder(case: dict) -> None:
    data = bytes.fromhex(case["cbor_hex"])
    if case["accept"]:
        decoded = _cbor.decode(data)
        assert decoded.well_formed and decoded.deterministic
    else:
        with pytest.raises(_cbor.CborError, match="nesting too deep"):
            _cbor.decode(data)


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_request_reader(case: dict) -> None:
    data = bytes.fromhex(case["cbor_hex"])
    if case["tag"]:
        # A request holds no tag at any depth (vectors/cbor-request-model/).
        with pytest.raises(er.RequestError):
            er.parse_request(data, binding="cbor")
    elif case["accept"]:
        assert er.parse_request(data, binding="cbor").nonce == "n-1"
    else:
        with pytest.raises(er.RequestError, match="not well-formed CBOR"):
            er.parse_request(data, binding="cbor")
