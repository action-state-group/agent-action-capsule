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
    for when in ("yesterday", "2026-10-15T00:00:00.5Z", "2026-10-15T00:00:00+00:00", "2026-02-30T00:00:00Z",
                 "2026-10-15T00:00:61Z", "2026-10-15T00:00:99Z"):
        with pytest.raises(ValueError, match="issued_at"):
            er.sign_envelope(REQUEST, er.Subject("record", RECORD), ANCHOR, ARTIFACT, signer=signer, issued_at=when)
    for fresh in (True, -1, 2**53, 1.5, "yesterday", "2026-10-14T00:00:00.5Z", "2026-10-14T00:00:99Z"):
        with pytest.raises(ValueError, match="freshness"):
            er.sign_envelope(REQUEST, er.Subject("checkpoints"), ANCHOR, ARTIFACT, signer=signer,
                             issued_at=ISSUED_AT, freshness=fresh)
    for subject in (er.Subject("bogus"), er.Subject("record", "XY"), er.Subject("record", "AB" * 32),
                    er.Subject("range", (3, 0)), er.Subject("checkpoints", RECORD), er.Subject("correlation", "")):
        with pytest.raises(ValueError, match="request could ask for"):
            er.sign_envelope(REQUEST, subject, ANCHOR, ARTIFACT, signer=signer, issued_at=ISSUED_AT)
    for derivation in ("", "history_card", "AB" * 32):
        with pytest.raises(ValueError, match="request could ask for"):
            er.sign_envelope(REQUEST, er.Subject("full_history"), ANCHOR, ARTIFACT, signer=signer,
                             issued_at=ISSUED_AT, derivation=derivation)
    with pytest.raises(ValueError, match="empty"):
        er.sign_envelope(REQUEST, er.Subject("record", RECORD), ANCHOR, b"", signer=signer, issued_at=ISSUED_AT)

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
    # Map keys sort bytewise by their encoded form (RFC 8949 §4.2.1); for text
    # keys the length in the head byte puts a shorter key first.
    assert _cbor.encode({"b": 1, "a": 2, "aa": 3}) == bytes.fromhex("a3616102616201626161" + "03")
    assert _cbor.encode([None, True, False, b"\x00", "x", 23, 24, 2**53 - 1]) == bytes.fromhex(
        "88f6f5f441006178171818" + "1b001fffffffffffff")
    decoded = _cbor.decode(_cbor.encode({"k": [1, {"z": b"", "y": "t"}]}))
    assert decoded.value == {"k": [1, {"z": b"", "y": "t"}]} and decoded.deterministic and decoded.well_formed
    for bad in (-1, 2**53, 1.5, {1: "x"}, object()):
        with pytest.raises(ValueError):
            _cbor.encode(bad)


# --- the reading side: parse_reply, ReceivedEnvelope, check_anchor_inclusion --------------------

CORPUS = Path(__file__).resolve().parents[2] / "vectors" / "interop-profile-v0" / "vectors.json"


@pytest.mark.parametrize("binding", ["json", "cbor"])
def test_parse_reply_reads_what_sign_envelope_writes(gen, binding):
    signer = _Signer(gen, "responder")
    env = er.sign_envelope(REQUEST, er.Subject("record", RECORD), ANCHOR, ARTIFACT, signer=signer,
                           issued_at=ISSUED_AT, verification=MATERIAL, freshness=7)
    got = er.parse_reply(env.encode(binding), binding)
    assert isinstance(got, er.ReceivedEnvelope)
    assert dict(got.signed) == env.signed_members() and got.sig == env.sig
    assert got.artifact == ARTIFACT and got.verification_content == tuple(o for _, o in MATERIAL)
    assert got.signing_body() == env.signing_body()
    got.verify_for(signer.key_id, REQUEST)


def test_verify_names_what_is_wrong(gen):
    from dataclasses import replace as dc_replace

    signer = _Signer(gen, "responder")
    env = er.sign_envelope(REQUEST, er.Subject("record", RECORD), ANCHOR, ARTIFACT, signer=signer,
                           issued_at=ISSUED_AT, verification=MATERIAL)
    got = er.parse_reply(env.encode("json"))
    cases = [
        (dc_replace(got, artifact=got.artifact + b" "), "artifact does not hash"),
        (dc_replace(got, verification_content=(MATERIAL[0][1], b"x")), "verification item 1 does not hash"),
        (dc_replace(got, verification_content=(MATERIAL[0][1],)), "2 verification entries but 1 items"),
        (dc_replace(got, sig=got.sig.upper()), "128 lowercase hex"),
        (dc_replace(got, signed={**got.signed, "issued_at": "2026-10-15T00:00:01Z"}), "does not verify"),
    ]
    for bad, why in cases:
        with pytest.raises(er.EnvelopeError, match=why):
            bad.verify()
    with pytest.raises(er.EnvelopeError, match="another key"):
        got.verify_for("00" * 32, REQUEST)
    with pytest.raises(er.EnvelopeError, match="another request"):
        got.verify_for(signer.key_id, b"{}")
    with pytest.raises(er.EnvelopeError, match="not the profile"):
        dc_replace(got, signed={**got.signed, "profile": "evidence-interop/1"}).verify_for(signer.key_id, REQUEST)


def test_parse_reply_reads_only_what_it_can_authenticate(gen):
    env = er.sign_envelope(REQUEST, er.Subject("record", RECORD), ANCHOR, ARTIFACT,
                           signer=_Signer(gen, "responder"), issued_at=ISSUED_AT, verification=MATERIAL)
    for octets, why in [
        (b"[]", "not a map"),
        (b'{"x":1}', "neither"),
        (b'{"artifact_digest":"a","reason":"b"}', "both"),
        (b'{"reason":"a","reason":"b"}', "well-formed JSON"),
        (b'{"reason":"a","n":1.5}', "well-formed JSON"),
    ]:
        with pytest.raises(er.EnvelopeError, match=why):
            er.parse_reply(octets)
    assert er.parse_reply(b'{"reason":"declined","sig":"00"}') == {"reason": "declined", "sig": "00"}
    frame = json.loads(env.encode("json"))
    for member, value, why in [
        ("artifact", frame["artifact"] + "==", "artifact"),
        ("subject", {"record": "XY"}, "subject"),
        ("anchor", {"digest": ANCHOR, "x": 1}, "anchor"),
        ("verification", [{"kind": "k"}], "verification"),
        ("sig", 7, "sig"),
        ("verification", [], "present and empty"),
    ]:
        with pytest.raises(er.EnvelopeError, match=why):
            er.parse_reply(json.dumps({**frame, member: value}).encode())
    with pytest.raises(er.EnvelopeError, match="CBOR"):
        er.parse_reply(env.encode("cbor") + b"\x00", "cbor")
    with pytest.raises(er.EnvelopeError, match="deterministic"):
        er.parse_reply(bytes.fromhex("a2616201616102"), "cbor")  # {"b": 1, "a": 2}
    with pytest.raises(er.EnvelopeError):
        er.parse_reply(env.encode("json"), "cbor")


def test_anchor_inclusion_matches_the_corpus():
    from agent_action_capsule.interop_profile._common import TrustPolicy

    corpus = json.loads(CORPUS.read_text())
    checked = passed = 0
    for case in corpus["cases"]:
        trust = TrustPolicy.from_dict(case["pins"]["trust_policy"])
        replies = case["inputs"].get("replies", [])
        for i, (reply, want) in enumerate(zip(replies, case["expected"].get("replies", []))):
            if want["message_type"] != "envelope":
                continue
            octets = reply["octets_text"].encode() if "octets_text" in reply else bytes.fromhex(reply["octets_hex"])
            binding = "cbor" if reply["media_type"] == "application/cbor" else "json"
            props = want["properties"]
            try:
                env = er.parse_reply(octets, binding)
            except er.EnvelopeError:
                assert props["anchor_inclusion"] == "NOT_CHECKED", case["id"]
                checked += 1
                continue
            if props["profile_version"] == "PASS":
                bound = all(props[p] == "PASS" for p in ("envelope_signature", "artifact_digest",
                                                         "verification_binding"))
                try:
                    env.verify()
                    verified = True
                except er.EnvelopeError:
                    verified = False
                assert verified == bound, f"{case['id']} reply {i}"
            got = er.check_anchor_inclusion(env, trust)
            assert got.status == props["anchor_inclusion"], f"{case['id']} reply {i}: {got.detail}"
            checked += 1
            passed += got.status == "PASS"
    assert checked >= 17 and passed >= 10
