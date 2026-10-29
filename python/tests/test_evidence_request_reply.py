# SPDX-License-Identifier: BSD-3-Clause
"""Reading and verifying a reply (interop profile §6.2, §6.2.1):
:func:`~agent_action_capsule.evidence_request.parse_reply`,
:meth:`Envelope.verify`, :meth:`Envelope.verify_for` and the Checkpointed Local
Log material checks.

The envelope corpus is ``vectors/interop-profile-v0/``, the one Go and Rust
check against: every envelope reply in it verifies exactly when the corpus
says its signature and digests PASS, and gets the ``anchor_inclusion`` status
the corpus states. The MMR proof checks are also run against the
Checkpointed Local Log's own tree when the ``bundle`` extra is installed.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
from pathlib import Path

import pytest

import agent_action_capsule.evidence_request as er
from agent_action_capsule.canonical import jcs
from agent_action_capsule.interop_profile import TrustPolicy, _cbor, _mmr

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

CORPUS = Path(__file__).resolve().parents[2] / "vectors" / "interop-profile-v0" / "vectors.json"


class _SeedSigner:
    def __init__(self, seed: bytes):
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        self.key_id = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def sign(self, body: bytes):
        return self._key.sign(body).hex(), self.key_id


# RFC 8032 §7.1 tests 1 and 2.
SIGNER = _SeedSigner(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
OTHER = _SeedSigner(bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))
RECORD = "cd" * 32
ANCHOR = "ab" * 32
REQUEST = b'{"coverage":{"expected_pin":"' + ANCHOR.encode() + b'"},"subject":{"record":"' + RECORD.encode() + b'"}}'
ARTIFACT = b'{"record":"bytes of the artifact"}'
MATERIAL = (("cll-checkpoint", b"checkpoint statement"), ("cll-inclusion-proof", b"\x82\x01\x80"))
ISSUED_AT = "2026-10-15T00:00:00Z"


def _envelope(**overrides) -> er.Envelope:
    args = dict(signer=SIGNER, issued_at=ISSUED_AT, verification=MATERIAL)
    args.update(overrides)
    return er.sign_envelope(REQUEST, er.Subject("record", RECORD), ANCHOR, ARTIFACT, **args)


def _b64(octets: bytes) -> str:
    return base64.urlsafe_b64encode(octets).rstrip(b"=").decode()


def _frame(binding: str, value: dict) -> bytes:
    return jcs(value) if binding == "json" else _cbor.encode(value)


def _wire(env: er.Envelope, binding: str) -> dict:
    """The envelope as the binding carries it, to alter and re-encode."""
    return json.loads(env.encode("json")) if binding == "json" else _cbor.decode(env.encode("cbor")).value


# --- round trips ---------------------------------------------------------------------


@pytest.mark.parametrize("binding", ["json", "cbor"])
@pytest.mark.parametrize("kwargs", [
    {},
    {"verification": ()},
    {"derivation": "history_card/1", "freshness": 42},
    {"freshness": "2026-10-14T00:00:00Z"},
])
def test_parse_reply_is_the_inverse_of_encode(binding, kwargs):
    env = _envelope(**kwargs)
    parsed = er.parse_reply(env.encode(binding), binding)
    assert isinstance(parsed, er.Envelope)
    assert parsed.encode(binding) == env.encode(binding)
    assert parsed.encode("cbor" if binding == "json" else "json") == env.encode("cbor" if binding == "json" else "json")
    assert dataclasses.replace(parsed, artifact_digest=None, verification_digests=None) == env
    parsed.verify()
    parsed.verify_for(REQUEST, SIGNER.key_id)


@pytest.mark.parametrize("subject", [
    er.Subject("full_history"), er.Subject("checkpoints"), er.Subject("range", (0, 3)),
    er.Subject("correlation", "deal-7"), er.Subject("exchange", "ef" * 32),
])
def test_every_subject_form_round_trips(subject):
    env = er.sign_envelope(REQUEST, subject, ANCHOR, ARTIFACT, signer=SIGNER, issued_at=ISSUED_AT)
    for binding in ("json", "cbor"):
        parsed = er.parse_reply(env.encode(binding), binding)
        assert parsed.subject == subject
        parsed.verify()


def test_parse_reply_reads_a_refusal_in_both_bindings():
    refusal = er.sign_refusal(er.request_digest(REQUEST), "no_such_subject", signer=SIGNER, issued_at=ISSUED_AT)
    for octets, binding in ((jcs(refusal.to_dict()), "json"), (refusal.to_cbor(), "cbor")):
        parsed = er.parse_reply(octets, binding)
        assert parsed == refusal
        assert er.verify_refusal_offline(parsed)
    # detail is outside the signature: it is read, and verification ignores it.
    with_detail = dict(refusal.to_dict(), detail="no record by that digest")
    parsed = er.parse_reply(jcs(with_detail))
    assert parsed == dataclasses.replace(refusal, detail="no record by that digest")
    assert er.verify_refusal_offline(parsed)


def test_unsigned_members_are_ignored():
    wire = dict(_wire(_envelope(), "json"), retention="ab" * 32, extension={"x": [1, 2]})
    er.parse_reply(jcs(wire)).verify()


# --- verify ----------------------------------------------------------------------------


@pytest.mark.parametrize("binding", ["json", "cbor"])
def test_verify_names_what_was_altered(binding):
    env = _envelope()

    def altered(change) -> er.Envelope:
        wire = _wire(env, binding)
        change(wire)
        reply = er.parse_reply(_frame(binding, wire), binding)
        assert isinstance(reply, er.Envelope)
        return reply

    def item(i):
        def change(wire):
            octets = wire["verification_content"][i]
            wire["verification_content"][i] = (
                _b64(base64.urlsafe_b64decode(octets + "==") + b"\x00") if binding == "json" else octets + b"\x00")
        return change

    def artifact(wire):
        wire["artifact"] = _b64(b"another artifact") if binding == "json" else b"another artifact"

    cases = {
        "artifact does not hash to its signed digest": artifact,
        "verification item 0 does not hash to its signed digest": item(0),
        "verification item 1 does not hash to its signed digest": item(1),
        "signature does not verify": lambda w: w.update(issued_at="2026-10-15T00:00:01Z"),
        "envelope signature is not 128 lowercase hex characters": lambda w: w.update(sig=w["sig"].upper()),
        "responder is not an Ed25519 public key": lambda w: w.update(responder="ab"),
    }
    for message, change in cases.items():
        with pytest.raises(er.VerificationError, match=message):
            altered(change).verify()

    def swap_responder(wire):
        wire["responder"] = OTHER.key_id
    with pytest.raises(er.VerificationError, match="signature does not verify"):
        altered(swap_responder).verify()


def test_verify_refuses_digests_that_do_not_pair_with_items():
    env = er.parse_reply(_envelope().encode())
    with pytest.raises(er.VerificationError, match="3 verification entries but 2 items"):
        dataclasses.replace(env, verification_digests=env.verification_digests + (ANCHOR,)).verify()


def test_verify_refuses_a_small_order_responder_key():
    # The identity point "verifies" every signature under a lax verifier.
    identity = "01" + "00" * 31
    forged = dataclasses.replace(_envelope(), responder=identity, sig="01" + "00" * 31 + "00" * 32)
    with pytest.raises(er.VerificationError, match="signature does not verify"):
        forged.verify()


def test_verify_for_binds_profile_responder_and_request():
    env = _envelope()
    env.verify_for(REQUEST, SIGNER.key_id)
    with pytest.raises(er.VerificationError, match="another key"):
        env.verify_for(REQUEST, OTHER.key_id)
    with pytest.raises(er.VerificationError, match="request_digest"):
        env.verify_for(REQUEST + b" ", SIGNER.key_id)
    other_profile = er.Envelope(**{**{f.name: getattr(env, f.name) for f in dataclasses.fields(env)},
                                   "profile": "evidence-interop/1", "sig": ""})
    signed = dataclasses.replace(other_profile, sig=SIGNER.sign(other_profile.signing_body())[0])
    signed.verify()
    with pytest.raises(er.VerificationError, match="profile"):
        signed.verify_for(REQUEST, SIGNER.key_id)


# --- parse_reply refusals ---------------------------------------------------------------


def _json_envelope(**changes) -> bytes:
    wire = _wire(_envelope(), "json")
    for key, value in changes.items():
        if value is _DROP:
            del wire[key]
        else:
            wire[key] = value
    return jcs(wire)


_DROP = object()


@pytest.mark.parametrize("octets,message", [
    (b"[]", "not a map"),
    (b"{", "not well-formed JSON"),
    (b'{"reason":"a","reason":"b"}', "duplicate"),
    (b'{"x":1}', "neither an envelope nor a refusal"),
    (_json_envelope(reason="no_such_subject"), "both"),
    (_json_envelope(sig=_DROP), "sig is missing"),
    (_json_envelope(issued_at=7), "issued_at is not a text string"),
    (_json_envelope(derivation=""), "derivation is present and empty"),
    (_json_envelope(subject={"record": "AB" * 32}), "subject"),
    (_json_envelope(subject={"record": RECORD, "checkpoints": None}), "subject"),
    (_json_envelope(anchor=ANCHOR), "anchor is not a map"),
    (_json_envelope(anchor={"digest": ANCHOR, "size": 3}), "anchor member 'size'"),
    (_json_envelope(anchor={"digest": ANCHOR, "freshness": -1}), "freshness"),
    (_json_envelope(anchor={"digest": ANCHOR, "freshness": 7}).replace(b'"freshness":7', b'"freshness":1.5'),
     "freshness"),
    (_json_envelope(verification={"kind": "x"}), "verification is not an array"),
    (_json_envelope(verification=[]), "verification is present and empty"),
    (_json_envelope(verification=[{"kind": "x", "digest": ANCHOR, "more": 1}, {"kind": "y", "digest": ANCHOR}]),
     "not {kind, digest}"),
    (_json_envelope(verification_content=_DROP), "2 verification entries but 0 items"),
    (_json_envelope(artifact=_b64(ARTIFACT) + "=="), "artifact is not opaque bytes"),
    (_json_envelope(artifact=base64.b64encode(b"\xfb\xff").decode()), "artifact is not opaque bytes"),
    # "QR" decodes to b"A" only by ignoring nonzero trailing bits: not the canonical spelling "QQ".
    (_json_envelope(artifact="QR"), "artifact is not opaque bytes"),
    (_json_envelope(verification_content=["AA", 3]), "verification_content item"),
    (_json_envelope(responder="x").replace(b'"responder":"x"', b'"responder":"\\ud800"'), "unpaired surrogate"),
])
def test_parse_reply_refuses_json(octets, message):
    with pytest.raises(er.VerificationError, match=message):
        er.parse_reply(octets, "json")


def test_parse_reply_refuses_cbor():
    wire = _wire(_envelope(), "cbor")
    for value, message in [
        (dict(wire, artifact=_b64(ARTIFACT)), "artifact is not opaque bytes"),
    ]:
        with pytest.raises(er.VerificationError, match=message):
            er.parse_reply(_cbor.encode(value), "cbor")
    too_large = _cbor.encode(dict(wire, anchor={"digest": ANCHOR, "freshness": 7})).replace(
        b"\x69freshness\x07", b"\x69freshness\x1b\x00\x20\x00\x00\x00\x00\x00\x00")  # 2^53
    with pytest.raises(er.VerificationError, match="freshness"):
        er.parse_reply(too_large, "cbor")
    tagged = _cbor.encode(wire).replace(b"\x67subject\xa1", b"\x67subject\xd8\x18\xa1")  # tag 24
    with pytest.raises(er.VerificationError, match="subject"):
        er.parse_reply(tagged, "cbor")
    with pytest.raises(er.VerificationError, match="duplicate"):
        er.parse_reply(bytes.fromhex("a2") + b"\x61a\x01" + b"\x61a\x02", "cbor")
    with pytest.raises(er.VerificationError, match="not a map"):
        er.parse_reply(bytes.fromhex("a1") + b"\x01" + b"\x61a", "cbor")
    with pytest.raises(ValueError, match="binding"):
        er.parse_reply(b"{}", "xml")


def test_a_deeply_nested_unknown_member_is_ignored_not_a_crash():
    deep = b"[" * 900 + b"]" * 900
    wire = _json_envelope()
    refusal = jcs(er.sign_refusal(er.request_digest(REQUEST), "no_such_subject", signer=SIGNER,
                                  issued_at=ISSUED_AT).to_dict())
    for octets in (wire, refusal):
        nested = octets[:-1] + b',"zz":' + deep + b"}"
        try:
            er.parse_reply(nested)
        except er.VerificationError:
            pass  # too deep for the JSON reader: refused, never an uncaught error


def test_a_cbor_frame_need_not_be_deterministic():
    # Signed over RFC 8785 of the members (§5.1), not over the frame.
    wire = _wire(_envelope(), "cbor")
    entries = sorted(((_cbor.encode(k), _cbor.encode(v)) for k, v in wire.items()), reverse=True)
    frame = _cbor.encode_head(5, len(entries)) + b"".join(k + v for k, v in entries)
    assert not _cbor.decode(frame).deterministic
    er.parse_reply(frame, "cbor").verify()


# --- the interop profile corpus ----------------------------------------------------------


def _corpus_replies():
    corpus = json.loads(CORPUS.read_text())
    for case in corpus["cases"]:
        expected = case["expected"].get("replies") or []
        for i, (reply, want) in enumerate(zip(case["inputs"].get("replies") or [], expected)):
            if want.get("message_type") == "envelope":
                yield case, i, reply, want["properties"]


def test_corpus_envelopes_verify_and_check_anchor_inclusion():
    checked = passed = 0
    for case, i, reply, props in _corpus_replies():
        where = f"{case['id']} reply {i}"
        octets = reply["octets_text"].encode() if "octets_text" in reply else bytes.fromhex(reply["octets_hex"])
        binding = "cbor" if reply["media_type"] == "application/cbor" else "json"
        try:
            envelope = er.parse_reply(octets, binding)
        except er.VerificationError as exc:
            # A reply this module cannot read is never checked.
            assert props["anchor_inclusion"] == "NOT_CHECKED", f"{where}: {exc}"
            checked += 1
            continue
        assert isinstance(envelope, er.Envelope), where
        bound = all(props[p] == "PASS" for p in ("envelope_signature", "artifact_digest", "verification_binding"))
        if props["profile_version"] == "PASS":
            try:
                envelope.verify()
                verified = True
            except er.VerificationError:
                verified = False
            assert verified == bound, where
        report = er.check_cll_material(envelope, TrustPolicy.from_dict(case["pins"]["trust_policy"]))
        assert report.status == props["anchor_inclusion"], f"{where}: {report.detail}"
        checked += 1
        if report.status == "PASS":
            passed += 1
            assert report.method.startswith("CLL-01 checkpoint (Ed25519) + MMR-02 inclusion")
    assert checked >= 17, checked
    assert passed >= 10, passed


def test_corpus_material_checks_one_by_one():
    """The primitives on the worked example's real bytes (§10.1), and the
    forged-and-signed inclusion proof, which only the proof check catches."""
    from agent_action_capsule.interop_profile.cll import _decode_checkpoint

    replies = {case["id"]: reply for case, _, reply, _ in _corpus_replies()}
    good = er.parse_reply(replies["valid-exchange"]["octets_text"].encode())
    items = dict(good.verification)
    cp = _decode_checkpoint(items["cll-checkpoint"])
    entry = bytes.fromhex(good.signed_members()["artifact_digest"])
    er.verify_cll_inclusion(cp.commitment, entry, items["cll-inclusion-proof"])
    er.verify_cll_consistency(cp.prev_commitment, cp.commitment, items["cll-consistency-proof"])
    with pytest.raises(er.VerificationError, match="reaches no peak"):
        er.verify_cll_inclusion(cp.commitment, hashlib.sha256(b"another entry").digest(), items["cll-inclusion-proof"])
    with pytest.raises(er.VerificationError, match="not the peak list"):
        er.verify_cll_consistency(cp.prev_commitment, list(reversed(cp.commitment)) + [b"\x00" * 32],
                                  items["cll-consistency-proof"])

    forged = replies["inclusion-proof-forged-and-signed"]
    forged_env = er.parse_reply(
        forged["octets_text"].encode() if "octets_text" in forged else bytes.fromhex(forged["octets_hex"]),
        "cbor" if forged["media_type"] == "application/cbor" else "json")
    forged_env.verify()  # signed and bound: only the proof is wrong
    forged_items = dict(forged_env.verification)
    with pytest.raises(er.VerificationError, match="reaches no peak"):
        er.verify_cll_inclusion(_decode_checkpoint(forged_items["cll-checkpoint"]).commitment,
                                bytes.fromhex(forged_env.signed_members()["artifact_digest"]),
                                forged_items["cll-inclusion-proof"])


def test_check_cll_material_never_checks_material_of_an_envelope_that_does_not_verify():
    replies = {case["id"]: reply for case, _, reply, _ in _corpus_replies()}
    good = er.parse_reply(replies["valid-exchange"]["octets_text"].encode())
    trust = TrustPolicy.from_dict(json.loads(CORPUS.read_text())["cases"][0]["pins"]["trust_policy"])
    assert er.check_cll_material(good, trust).status == "PASS"
    assert er.check_cll_material(dataclasses.replace(good, issued_at="2026-10-12T00:00:12Z"), trust).status \
        == "NOT_CHECKED"
    assert er.check_cll_material(good, TrustPolicy()).status == "FAIL"  # no log key accepted


# --- the MMR proof checks against the log's own tree ----------------------------------------


def test_cll_material_against_the_log_tree():
    core = pytest.importorskip("cll.checkpoint.core")
    from cll.checkpoint import MemoryNodeStore

    store = MemoryNodeStore()
    entries, sizes = [], []
    for i in range(13):
        entry = hashlib.sha256(bytes([i])).digest()
        core.add_leaf(store, core.leaf_hash(entry))
        entries.append(entry)
        sizes.append(store.size())

    def peaks_at(size):
        return [store.node(p) for p in core.peaks(size)]

    for size in sizes:
        peaks = peaks_at(size)
        assert len(_mmr.peaks(size - 1)) == len(peaks)
        for leaf in range(core.leaf_count(size)):
            proof = core.inclusion_proof(store, leaf, size)
            index = core.leaf_index_to_pos(leaf)
            octets = _cbor.encode([index, [bytes.fromhex(h) for h in proof.witness]])
            er.verify_cll_inclusion(peaks, entries[leaf], octets)
            with pytest.raises(er.VerificationError):
                er.verify_cll_inclusion(peaks, hashlib.sha256(entries[leaf]).digest(), octets)
            if proof.witness:
                tampered = octets[:-1] + bytes([octets[-1] ^ 1])
                with pytest.raises(er.VerificationError):
                    er.verify_cll_inclusion(peaks, entries[leaf], tampered)
    for i, old in enumerate(sizes):
        for new in sizes[i:]:
            proof = core.consistency_proof(store, old, new)
            old_peaks = [bytes.fromhex(h) for h in proof.old_peaks]
            new_peaks = [bytes.fromhex(h) for h in proof.new_peaks]
            paths = [[bytes.fromhex(h) for h in path] for path in proof.witness]
            roots = _mmr.consistent_roots(old - 1, old_peaks, paths)
            octets = _cbor.encode([old, new, paths, new_peaks[len(roots):]])
            er.verify_cll_consistency(old_peaks, new_peaks, octets)
            with pytest.raises(er.VerificationError):
                er.verify_cll_consistency([b"\x00" * 32] + old_peaks[1:], new_peaks, octets)


@pytest.mark.parametrize("octets", [
    b"\xff",                                   # not CBOR
    _cbor.encode([]),                          # not a pair
    _cbor.encode([2, []]),                     # not a leaf
    _cbor.encode([0, [b"\x01"]]),              # short node
    bytes.fromhex("82f93c0080"),               # index a float
    bytes.fromhex("82180080"),                 # not deterministic: 0 in two octets
    _cbor.encode([0, [b"\x00" * 32] * 53]),    # longer than any MMR path
    _cbor.encode([0, [b"\x00" * 32] * 64]),
    _cbor.encode([0, [b"\x00" * 32] * 65]),
])
def test_verify_cll_inclusion_refuses_malformed_proofs(octets):
    with pytest.raises(er.VerificationError):
        er.verify_cll_inclusion([b"\x00" * 32], hashlib.sha256(b"e").digest(), octets)


@pytest.mark.parametrize("octets", [
    _cbor.encode([0, 1, [], []]),              # size 0
    _cbor.encode([3, 1, [[]], []]),            # tree-size-1 beyond tree-size-2
    _cbor.encode([1, 1, [[b"\x00" * 32] * 53], []]),
    _cbor.encode([1, 1, [[b"\x00" * 32] * 64], []]),
    _cbor.encode([1, 1, [[b"\x00" * 32] * 65], []]),
    _cbor.encode([1, 1, [], []]),              # path count is not the old peak count
])
def test_verify_cll_consistency_refuses_malformed_proofs(octets):
    with pytest.raises(er.VerificationError):
        er.verify_cll_consistency([b"\x00" * 32], [b"\x00" * 32], octets)
