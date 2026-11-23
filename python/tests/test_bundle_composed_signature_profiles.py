# SPDX-License-Identifier: BSD-3-Clause
"""The ``composed/v1`` carried signature profile vectors (#676) against the
reference verifiers in :mod:`agent_action_capsule.carried_signatures`.

Bundle -03, "Carried Signature Profiles". Each object case pins the profile a
carried refusal or response is read in and its signature state; each composed
case pins the member's state and the block's status with both verifiers set.
The four strict-Ed25519 cases of ``vectors/interop-profile-v1/`` are run
against the same verifiers.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from agent_action_capsule import carried_signatures as cs  # noqa: E402
from agent_action_capsule.composed import (  # noqa: E402
    REFUSAL_SIGNATURE_UNVERIFIED,
    ComposedOptions,
    verify_composed,
)

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "bundle" / "composed-signature-profiles"
GENERATOR = ROOT / "python" / "scripts" / "generate_bundle_composed_signature_profile_vectors.py"
INTEROP_V1 = ROOT / "vectors" / "interop-profile-v1" / "vectors.json"
HAND_WRITTEN = ("README.md",)

DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
OPTIONS = ComposedOptions(refusal_signature=cs.verify_carried_refusal, response_signature=cs.verify_carried_response)


@pytest.mark.parametrize("case", DATA["cases"], ids=lambda c: c["id"])
def test_object_case(case):
    obj = case["object"]
    if case["kind"] == "refusal":
        profile, state = cs.refusal_profile(obj), cs.verify_carried_refusal(obj)
    else:
        profile, state = cs.response_profile(obj), cs.verify_carried_response(obj)
    assert profile == case["expect"]["profile"]
    assert state == case["expect"]["state"]


@pytest.mark.parametrize("case", [c for c in DATA["cases"] if "signing_input_hex" in c], ids=lambda c: c["id"])
def test_signing_input(case):
    obj = case["object"]
    if case["expect"]["profile"] == cs.THREE_MEMBER_REFUSAL:
        got = cs.three_member_refusal_signing_input(obj)
    elif case["expect"]["profile"] == cs.WHOLE_REFUSAL:
        got = json.dumps({k: v for k, v in obj.items() if k != "signature"}, separators=(",", ":"),
                         sort_keys=True, ensure_ascii=False).encode()
    else:
        got = cs.artifact_response_signing_input(*(obj[k] for k in (
            "request_digest", "anchor", "artifact_kind", "artifact_digest", "issued_at")))
    assert got is not None and got.hex() == case["signing_input_hex"]


@pytest.mark.parametrize("case", DATA["composed_cases"], ids=lambda c: c["id"])
def test_composed_case(case):
    result = verify_composed(case["container"]["extensions"]["composed/v1"], OPTIONS)
    assert result.status == case["expect"]["status"]
    assert result.findings == case["expect"]["findings"]
    members = {m.id: m for m in result.members}
    for member_id, states in case["expect"]["members"].items():
        for name, state in states.items():
            assert getattr(members[member_id], name) == state, (member_id, name)


@pytest.mark.parametrize("case", DATA["composed_cases"], ids=lambda c: c["id"])
def test_composed_default_is_unverified(case):
    """Without the verifiers every carried signature stays signature-unverified."""
    result = verify_composed(case["container"]["extensions"]["composed/v1"])
    for member_id, states in case["expect"]["members"].items():
        member = next(m for m in result.members if m.id == member_id)
        for name in states:
            assert getattr(member, name) == REFUSAL_SIGNATURE_UNVERIFIED


def _interop_reply(case_id: str) -> dict:
    case = next(c for c in json.loads(INTEROP_V1.read_text(encoding="utf-8"))["cases"] if c["id"] == case_id)
    return json.loads(case["inputs"]["replies"][0]["octets_text"])


@pytest.mark.parametrize("case_id", ["forged-refusal-small-order-key", "forged-refusal-identity-r"])
def test_interop_v1_forged_refusal_is_invalid(case_id):
    refusal = _interop_reply(case_id)
    assert cs.refusal_profile(refusal) == cs.THREE_MEMBER_REFUSAL
    assert cs.verify_carried_refusal(refusal) == "invalid"


@pytest.mark.parametrize("case_id", ["envelope-small-order-key", "envelope-identity-r"])
def test_interop_v1_forged_envelope(case_id):
    """An interop envelope carries responder, so it is in none of these
    profiles; its key and signature carried as key_id and sig of a
    digest-bound response do not verify."""
    envelope = _interop_reply(case_id)
    assert cs.verify_carried_response(envelope) == REFUSAL_SIGNATURE_UNVERIFIED
    rehomed = {"request_digest": envelope["request_digest"], "anchor": envelope["anchor"]["digest"],
               "artifact_kind": "evidence-bundle/v2", "artifact_digest": envelope["artifact_digest"],
               "issued_at": envelope["issued_at"], "key_id": envelope["responder"], "sig": envelope["sig"]}
    assert cs.verify_carried_response(rehomed) == "invalid"


def test_generator_reproduces_every_file_byte_for_byte(tmp_path):
    for name in HAND_WRITTEN:
        shutil.copyfile(VECTORS / name, tmp_path / name)
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(tmp_path)], check=True)
    committed = sorted(p.name for p in VECTORS.iterdir() if p.is_file())
    assert committed == sorted(p.name for p in tmp_path.iterdir() if p.is_file())
    for name in committed:
        assert (tmp_path / name).read_bytes() == (VECTORS / name).read_bytes(), name


def test_sha256sums_pin_every_file():
    listed = dict(reversed(line.split("  ", 1)) for line in (VECTORS / "SHA256SUMS").read_text().splitlines())
    on_disk = {p.name for p in VECTORS.iterdir() if p.is_file() and p.name != "SHA256SUMS"}
    assert set(listed) == on_disk
    for name, digest in listed.items():
        assert hashlib.sha256((VECTORS / name).read_bytes()).hexdigest() == digest, name
