# SPDX-License-Identifier: BSD-3-Clause
"""Machine-check the AAC/AEP/SCITT digest-binding interop vector."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

import pytest

from agent_action_capsule import compute_capsule_id, jcs

ROOT = Path(__file__).resolve().parents[2]
INTEROP = ROOT / "docs" / "interop"
VECTOR = json.loads((INTEROP / "aac-aep-scitt-digest-binding-vector.json").read_text())
PROFILE_LABEL = VECTOR["profile_label"]


class BindingError(ValueError):
    """Raised by the test-local verifier when the vector contract is violated."""


def _load_json(relative_path: str) -> dict:
    return json.loads((ROOT / relative_path).read_text())


def _assert_lower_hex_32(value: str) -> None:
    assert re.fullmatch(r"[0-9a-f]{64}", value), value


def _raw_b64(digest_hex: str) -> str:
    return base64.b64encode(bytes.fromhex(digest_hex)).decode("ascii")


def _decode_b64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _verify_quote_binding(bound_digest_raw_b64: str, digest_hex: str, profile_label: str) -> bool:
    if profile_label != PROFILE_LABEL:
        raise BindingError("profile_label_mismatch")

    bound = _decode_b64(bound_digest_raw_b64)
    expected = bytes.fromhex(digest_hex)
    if bound == expected:
        return True
    if bound == digest_hex.encode("ascii"):
        raise BindingError("digest_binding_encoding_mismatch")
    raise BindingError("digest_binding_mismatch")


def test_positive_vector_recomputes_capsule_and_preimage_digests():
    capsule = _load_json(VECTOR["inputs"]["capsule"])
    agent_input = _load_json(VECTOR["inputs"]["agent_input"])
    agent_output = _load_json(VECTOR["inputs"]["agent_output"])
    receipt = _load_json(VECTOR["inputs"]["receipt"])
    positive = VECTOR["positive"]

    assert compute_capsule_id(capsule) == positive["capsule_id"]["hex"]
    assert capsule["capsule_id"] == positive["capsule_id"]["hex"]

    response_digest = hashlib.sha256(jcs(agent_output)).hexdigest()
    agent_input_digest = hashlib.sha256(jcs(agent_input)).hexdigest()
    assert response_digest == positive["response_digest"]["hex"]
    assert agent_input_digest == positive["agent_input_digest"]["hex"]
    assert capsule["effect"]["response_digest"] == positive["response_digest"]["hex"]
    assert (
        capsule["model_attestation"]["compute_attestation"]["agent_input_digest"]
        == positive["agent_input_digest"]["hex"]
    )

    assert receipt["capsule_id"] == positive["capsule_id"]["hex"]
    for key in ("receipt_b64", "entry_hash", "leaf_index", "tree_size", "key_id", "alg"):
        assert receipt[key] == positive["scitt_receipt"][key]


def test_raw_byte_encodings_are_pinned():
    for name in ("capsule_id", "response_digest", "agent_input_digest"):
        digest_hex = VECTOR["positive"][name]["hex"]
        _assert_lower_hex_32(digest_hex)
        assert VECTOR["positive"][name]["raw_b64"] == _raw_b64(digest_hex)
        assert len(_decode_b64(VECTOR["positive"][name]["raw_b64"])) == 32


def test_positive_aep_quote_binding_accepts_raw_digest_bytes():
    positive = VECTOR["positive"]
    quote = positive["aep_quote_commitment"]
    digest_hex = positive[quote["bound_digest"]]["hex"]

    assert _verify_quote_binding(
        quote["bound_digest_raw_b64"],
        digest_hex,
        quote["profile_label"],
    )


@pytest.mark.parametrize("case", VECTOR["negative_cases"], ids=lambda case: case["id"])
def test_negative_cases_are_rejected(case):
    positive = VECTOR["positive"]

    if case["id"] in {
        "ascii_hex_string_in_quote",
        "different_digest_bytes_in_quote",
        "profile_label_mismatch",
    }:
        mutation = case["mutated"]
        digest_hex = positive[mutation["bound_digest"]]["hex"]
        with pytest.raises(BindingError, match=case["expected_error"]):
            _verify_quote_binding(
                mutation["bound_digest_raw_b64"],
                digest_hex,
                mutation["profile_label"],
            )
        return

    if case["id"] == "noncanonical_json_input":
        agent_output = _load_json(VECTOR["inputs"]["agent_output"])
        noncanonical = json.dumps(agent_output, indent=2).encode("utf-8")
        assert hashlib.sha256(noncanonical).hexdigest() == case["mutated"]["response_digest_hex"]
        assert case["mutated"]["response_digest_hex"] != positive["response_digest"]["hex"]
        assert case["expected_error"] == "canonicalization_mismatch"
        return

    if case["id"] == "receipt_binds_different_capsule_id":
        receipt = _load_json(VECTOR["inputs"]["receipt"])
        assert case["mutated"]["capsule_id"] != positive["capsule_id"]["hex"]
        assert receipt["capsule_id"] == positive["capsule_id"]["hex"]
        assert case["expected_error"] == "receipt_statement_mismatch"
        return

    raise AssertionError(f"unhandled negative case: {case['id']}")
