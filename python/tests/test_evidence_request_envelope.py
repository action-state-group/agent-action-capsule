# SPDX-License-Identifier: BSD-3-Clause
"""The artifact envelope (interop profile §6.2) built by
:func:`agent_action_capsule.evidence_request.sign_envelope`.

The reference is the generator of ``vectors/interop-profile-v0/``: for the
same inputs the builder must produce byte-identical replies in both bindings.
Those vectors are what the profile's reference verifier is tested against.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

import agent_action_capsule.evidence_request as er
from agent_action_capsule.interop_profile import _cbor

GENERATOR = Path(__file__).resolve().parents[1] / "scripts" / "generate_interop_profile_v0_vectors.py"


@pytest.fixture(scope="module")
def gen():
    spec = importlib.util.spec_from_file_location("_interop_vector_generator", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Signer:
    def __init__(self, gen, name: str):
        self._gen, self._name = gen, name
        self.key_id = gen.PUB[name]

    def sign(self, body: bytes):
        return self._gen.sign(self._name, body), self.key_id


REQUEST = b'{"coverage":{"expected_pin":"' + b"ab" * 32 + b'"},"nonce":"n-1","subject":{"record":"' + b"cd" * 32 + b'"}}'
RECORD = "cd" * 32
ANCHOR = "ab" * 32
ARTIFACT = b'{"record":"bytes of the artifact"}'
MATERIAL = [("cll-checkpoint", b"checkpoint statement"), ("cll-inclusion-proof", b"\x82\x01\x80")]
ISSUED_AT = "2026-10-15T00:00:00Z"


@pytest.mark.parametrize("binding,media_type", [("json", "application/json"), ("cbor", "application/cbor")])
@pytest.mark.parametrize("material", [MATERIAL, []])
def test_matches_the_vector_generator_byte_for_byte(gen, binding, media_type, material):
    env = er.sign_envelope(REQUEST, er.Subject("record", RECORD), ANCHOR, ARTIFACT,
                           signer=_Signer(gen, "responder"), issued_at=ISSUED_AT, verification=material)
    want = gen.envelope(REQUEST, RECORD, ANCHOR, ARTIFACT, material, ISSUED_AT, media_type)
    assert env.encode(binding) == want


def test_signature_covers_the_jcs_of_the_signed_members(gen):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    env = er.sign_envelope(REQUEST, er.Subject("record", RECORD), ANCHOR, ARTIFACT,
                           signer=_Signer(gen, "responder"), issued_at=ISSUED_AT, verification=MATERIAL)
    signed = env.signed_members()
    assert set(signed) == {"profile", "request_digest", "subject", "anchor", "artifact_digest",
                           "responder", "issued_at", "verification"}
    assert signed["request_digest"] == hashlib.sha256(REQUEST).hexdigest()
    assert signed["artifact_digest"] == hashlib.sha256(ARTIFACT).hexdigest()
    assert signed["profile"] == er.PROFILE == "evidence-interop/0"
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(env.responder)).verify(bytes.fromhex(env.sig), env.signing_body())
    # The JSON frame carries the artifact and material as unpadded base64url.
    frame = json.loads(env.encode("json"))
    assert frame["sig"] == env.sig and "=" not in frame["artifact"]
    assert len(frame["verification_content"]) == len(MATERIAL)


def test_optional_members_appear_only_when_present(gen):
    signer = _Signer(gen, "responder")
    bare = er.sign_envelope(REQUEST, er.Subject("checkpoints"), ANCHOR, ARTIFACT, signer=signer, issued_at=ISSUED_AT)
    assert "derivation" not in bare.signed_members() and "verification" not in bare.signed_members()
    assert "verification_content" not in bare.to_value()
    assert bare.signed_members()["anchor"] == {"digest": ANCHOR}

    fresh = er.sign_envelope(REQUEST, er.Subject("full_history"), ANCHOR, ARTIFACT, signer=signer,
                             issued_at=ISSUED_AT, derivation="history_card/1", freshness=42)
    assert fresh.signed_members()["derivation"] == "history_card/1"
    assert fresh.signed_members()["anchor"] == {"digest": ANCHOR, "freshness": 42}
    assert fresh.signed_members()["subject"] == {"full_history": None}

    ranged = er.sign_envelope(REQUEST, er.Subject("range", (0, 3)), ANCHOR, ARTIFACT, signer=signer,
                              issued_at=ISSUED_AT, freshness="2026-10-14T00:00:00Z")
    assert ranged.signed_members()["subject"] == {"range": [0, 3]}
    assert ranged.signed_members()["anchor"]["freshness"] == "2026-10-14T00:00:00Z"


def test_rejects_what_it_must_not_sign(gen):
    signer = _Signer(gen, "responder")
    with pytest.raises(ValueError, match="anchor_digest"):
        er.sign_envelope(REQUEST, er.Subject("record", RECORD), "AB" * 32, ARTIFACT, signer=signer, issued_at=ISSUED_AT)
    with pytest.raises(ValueError, match="issued_at"):
        er.sign_envelope(REQUEST, er.Subject("record", RECORD), ANCHOR, ARTIFACT, signer=signer, issued_at="yesterday")

    class Liar(_Signer):
        def sign(self, body):
            sig, _ = super().sign(body)
            return sig, "00" * 32

    with pytest.raises(ValueError, match="key other than"):
        er.sign_envelope(REQUEST, er.Subject("record", RECORD), ANCHOR, ARTIFACT, signer=Liar(gen, "responder"),
                         issued_at=ISSUED_AT)
    env = er.sign_envelope(REQUEST, er.Subject("record", RECORD), ANCHOR, ARTIFACT, signer=signer, issued_at=ISSUED_AT)
    with pytest.raises(ValueError, match="binding"):
        env.encode("xml")


def test_cbor_encoder_is_core_deterministic():
    # Map keys sort by their encodings: a shorter key first, then bytewise.
    assert _cbor.encode({"b": 1, "a": 2, "aa": 3}) == bytes.fromhex("a3616102616201626161" + "03")
    assert _cbor.encode([None, True, False, b"\x00", "x", 23, 24, 2**53 - 1]) == bytes.fromhex(
        "88f6f5f441006178171818" + "1b001fffffffffffff")
    decoded = _cbor.decode(_cbor.encode({"k": [1, {"z": b"", "y": "t"}]}))
    assert decoded.value == {"k": [1, {"z": b"", "y": "t"}]} and decoded.deterministic and decoded.well_formed
    for bad in (-1, 2**53, 1.5, {1: "x"}, object()):
        with pytest.raises(ValueError):
            _cbor.encode(bad)
