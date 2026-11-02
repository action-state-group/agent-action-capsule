# SPDX-License-Identifier: BSD-3-Clause
"""The CBOR request data model against ``vectors/cbor-request-model`` (#529).

A request in the CBOR binding is read only in core deterministic encoding with
every item, inside ignored members too, in the request data model; anything
else is ``request_malformed``. Go and Rust run the same file.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_action_capsule import evidence_request as er

DIR = Path(__file__).resolve().parents[2] / "vectors" / "cbor-request-model"
CASES = json.loads((DIR / "cases.json").read_text(encoding="utf-8"))["cases"]


def test_the_set_has_every_case() -> None:
    assert len(CASES) == 18


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_request_reader(case: dict) -> None:
    data = bytes.fromhex(case["cbor_hex"])
    if case["accept"]:
        assert er.parse_request(data, binding="cbor").nonce == "n-1"
    else:
        with pytest.raises(er.RequestError) as refused:
            er.parse_request(data, binding="cbor")
        assert refused.value.reason == er.REASON_REQUEST_MALFORMED
