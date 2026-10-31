# SPDX-License-Identifier: Apache-2.0
"""``agent_action_capsule.evidence_request`` against draft-mih-agent-evidence-request-00.

The first part runs the module against every case of every file in
``vectors/evidence-request/``; :func:`test_every_vector_case_is_asserted`
checks that each file's cases are all run. The second part pins the responder's own behavior
(:func:`answer` over an in-memory :class:`EvidenceStore`) where the vectors
leave it to the implementation: the store interface, forced checkpoints,
declines and caller invariance by construction.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import agent_action_capsule.evidence_request as er
from agent_action_capsule.evidence_request import (
    REASON_COVERAGE_UNSATISFIABLE,
    REASON_NO_SUCH_SUBJECT,
    REASON_POLICY_DECLINED,
    REASON_REQUEST_MALFORMED,
    Anchor,
    Artifact,
    Decline,
    Refusal,
    RequestError,
    Resolution,
    Subject,
    answer,
    check_refusal,
    check_refusal_cbor,
    parse_request,
    request_digest,
    sign_refusal,
    verify_refusal_offline,
)

VECTORS = Path(__file__).resolve().parents[2] / "vectors" / "evidence-request"
NOW = "2026-09-28T00:00:00Z"


def _load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


MANIFEST = _load("manifest.json")
REGISTRY = _load("registry.json")
REFUSAL_CORPUS = _load("refusal.json")
RESPONDER = _load("resolution.json")["responder"]


def _cases(name: str) -> list[dict]:
    return _load(f"{name}.json")["cases"]


def _params(name: str):
    cases = _cases(name)
    return pytest.mark.parametrize("case", cases, ids=[c["id"] for c in cases])


class _Signer:
    def __init__(self, seed: bytes = b"\x07" * 32) -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        self.key_id = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def sign(self, body: bytes) -> tuple[str, str]:
        return self._key.sign(body).hex(), self.key_id


PRIMARY = _Signer(bytes.fromhex(REFUSAL_CORPUS["keys"]["primary"]["seed_hex"]))


@dataclass
class _Store:
    """An :class:`EvidenceStore` over the declared responder state of
    ``resolution.json``. ``artifact`` returns its own arguments, so a test can
    see exactly what the responder asked the store for."""

    state: dict
    after_push: list = field(default_factory=list)
    pushes: int = 0
    decline: str | None = None

    def holds_record(self, digest: str) -> bool:
        return digest in self.state["records"]

    def holds_correlation(self, correlation_id: str) -> bool:
        return correlation_id in self.state["correlations"]

    def cites_exchange(self, half_digest: str) -> bool:
        return half_digest in self.state["exchange_citations"]

    def positional_ordering(self) -> bool:
        return self.state["positional_ordering"]

    def anchors(self) -> list[Anchor]:
        return [Anchor(**a) for a in self.state["anchors"]]

    def derivation_forms(self, derivation: str):
        return self.state["supported_derivations"].get(derivation)

    def artifact(self, subject: Subject, derivation: str | None, resolution: Resolution):
        if self.decline:
            raise Decline(self.decline, "test")
        return {"subject": subject, "derivation": derivation, "anchor": resolution.anchor_digest}

    def force_checkpoint(self, signer) -> None:
        self.pushes += 1
        self.state["anchors"] = self.state["anchors"] + self.after_push


def _store(**overrides) -> _Store:
    return _Store(json.loads(json.dumps({**RESPONDER, **overrides})))


def _request_bytes(case: dict) -> list[tuple[str, bytes, str]]:
    """Each binding a case gives the request in, with the digest it pins."""
    out = []
    if "request_json" in case:
        out.append(("json", case["request_json"].encode("utf-8"), case.get("request_json_digest")))
    if "request_cbor_hex" in case:
        out.append(("cbor", bytes.fromhex(case["request_cbor_hex"]), case.get("request_cbor_digest")))
    return out


# --- registry.json -----------------------------------------------------------------


def test_registry_strings_are_the_modules():
    assert er.DRAFT == REGISTRY["draft"]
    assert er.SUBJECT_FORMS == tuple(REGISTRY["subject_forms"])
    assert er.COVERAGE_MEMBERS == tuple(REGISTRY["coverage_members"])
    # registry.json is the -00 registry; -02 adds two (refusal-02.json).
    reasons_02 = json.loads((VECTORS / "refusal-02.json").read_text(encoding="utf-8"))["refusal_reasons"]
    assert reasons_02[:8] == REGISTRY["refusal_reasons"] and len(REGISTRY["refusal_reasons"]) == 8
    assert er.REFUSAL_REASONS == frozenset(reasons_02)
    assert er.OUTCOMES == tuple(REGISTRY["outcomes"])
    assert er.REQUEST_STATES == tuple(REGISTRY["request_states"])
    assert er.SUBPROTOCOL == REGISTRY["subprotocol"]
    assert set(REGISTRY["derivations"]) == {er.DERIVATION_HISTORY_CARD}
    assert {k for k, v in REGISTRY["request_fields"].items() if v == "REQUIRED"} == {"subject", "coverage"}
    for token in REGISTRY["not_registered_examples"]:
        assert token not in er.REFUSAL_REASONS and token not in er.SUBJECT_FORMS


# --- request.json ----------------------------------------------------------------------


@_params("request")
def test_request_vector(case):
    bindings = _request_bytes(case)
    assert {b for b, _, _ in bindings} == {"json", "cbor"}
    for binding, data, pinned in bindings:
        assert request_digest(data) == pinned
        if case["expect"]["well_formed"]:
            parse_request(data, binding=binding)
        else:
            with pytest.raises(RequestError) as exc:
                parse_request(data, binding=binding)
            assert exc.value.reason == case["expect"]["reason"], binding
        result = answer(data, store=_store(), signer=PRIMARY, binding=binding, now=NOW)
        if not case["expect"]["well_formed"]:
            assert isinstance(result, Refusal)
            assert result.reason == case["expect"]["reason"]
            assert result.request_digest == pinned


def test_both_bindings_parse_to_the_same_request():
    for case in _cases("request"):
        if case["expect"]["well_formed"]:
            json_request = parse_request(case["request_json"].encode(), binding="json")
            cbor_request = parse_request(bytes.fromhex(case["request_cbor_hex"]), binding="cbor")
            assert json_request == cbor_request, case["id"]


# --- resolution.json ------------------------------------------------------------------------


@_params("resolution")
def test_resolution_vector(case):
    for binding, data, pinned in _request_bytes(case):
        overrides = dict(case.get("responder_overrides", {}))
        uniform = overrides.pop("uniform_policy_declined", False)
        result = answer(
            data, store=_store(**overrides), signer=PRIMARY, binding=binding, now=NOW,
            uniform_policy_declined=uniform,
        )
        if case["expect"]["answer"] == "artifact":
            assert isinstance(result, Artifact), (binding, result)
            request = parse_request(data, binding=binding)
            assert result.body["subject"] == request.subject
            assert result.anchor == result.body["anchor"]
            if request.coverage.expected_pin is not None:
                assert result.anchor == request.coverage.expected_pin
        else:
            assert isinstance(result, Refusal), (binding, result)
            assert result.reason == case["expect"]["reason"], binding
            assert result.request_digest == pinned
            assert check_refusal(result.to_dict()).conformant


# --- digest.json -----------------------------------------------------------------------------


@_params("digest")
def test_digest_vector(case):
    if "refusal_request_digest" in case:
        sent = case["request_json"].encode("utf-8")
        identifies = case["refusal_request_digest"] == request_digest(sent)
        assert identifies is case["expect"]["identifies_request"]
        if identifies:
            assert answer(sent, store=_store(), signer=PRIMARY, now=NOW).anchor
    else:
        binding = case["encoding"]
        data = case["request_json"].encode("utf-8") if binding == "json" else bytes.fromhex(case["request_cbor_hex"])
        assert request_digest(data) == case["expect"]["request_digest"]
        # Refused or not, a responder's refusal names the bytes as received.
        result = answer(data, store=_store(), signer=PRIMARY, binding=binding, now=NOW)
        if binding == "cbor" and not case["deterministic_encoding"]:
            assert isinstance(result, Refusal) and result.reason == REASON_REQUEST_MALFORMED
            assert result.request_digest == case["expect"]["request_digest"]
        else:
            assert isinstance(result, Artifact)


# --- refusal.json and refusal-imported.json ------------------------------------------------------


def _refusal_object(case: dict) -> dict:
    if "file" in case:
        raw = (VECTORS / case["file"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == case["file_sha256"]
        return json.loads(raw)
    return case["refusal"]


@_params("refusal")
def test_refusal_vector(case):
    obj = _refusal_object(case)
    expect = case["expect"]
    checked = check_refusal(obj)
    assert checked.signature_valid is (expect["signature"] == "valid")
    assert checked.reason_registered is expect["reason_registered"]
    assert checked.conformant is expect["conformant"]
    if "signing_body" in case:
        assert er._signing_body(obj) == case["signing_body"].encode("utf-8")
    if "refusal_cbor_hex" in case:
        frame = bytes.fromhex(case["refusal_cbor_hex"])
        assert hashlib.sha256(frame).hexdigest() == case["refusal_cbor_digest"]
        assert check_refusal_cbor(frame) == checked
        assert Refusal(**obj).to_cbor() == frame
    members = set(Refusal.__dataclass_fields__) - {"detail"}
    if members <= set(obj) <= members | {"detail"} and all(isinstance(v, str) for v in obj.values()):
        assert verify_refusal_offline(Refusal(**obj)) is checked.signature_valid
    # The responder reproduces every conforming primary-key refusal byte for
    # byte (Ed25519 is deterministic), and refuses to sign anything else.
    if obj.get("key_id") == PRIMARY.key_id and checked.signature_valid:
        args = (obj.get("request_digest"), obj.get("reason"))
        if checked.conformant:
            signed = sign_refusal(*args, signer=PRIMARY, issued_at=obj["issued_at"], detail=obj.get("detail"))
            assert signed.to_dict() == obj
            if "refusal_cbor_hex" in case:
                assert signed.to_cbor() == bytes.fromhex(case["refusal_cbor_hex"])
        else:
            with pytest.raises((ValueError, TypeError)):
                sign_refusal(*args, signer=PRIMARY, issued_at=obj.get("issued_at"))


def test_a_detail_is_outside_the_signature():
    digest = "a" * 64
    plain = sign_refusal(digest, "request_malformed", signer=PRIMARY, issued_at="2026-09-28T00:00:00Z")
    with_detail = sign_refusal(
        digest, "request_malformed", signer=PRIMARY, issued_at="2026-09-28T00:00:00Z", detail="profiles supported: x"
    )
    assert with_detail.sig == plain.sig and with_detail.signing_body() == plain.signing_body()
    assert "detail" not in plain.to_dict() and with_detail.to_dict()["detail"] == "profiles supported: x"
    # An empty detail is absent, as in the Go signer.
    assert sign_refusal(digest, "request_malformed", signer=PRIMARY, issued_at="2026-09-28T00:00:00Z", detail="") == plain
    assert verify_refusal_offline(with_detail) and check_refusal(with_detail.to_dict()).conformant
    assert check_refusal_cbor(with_detail.to_cbor()).conformant
    for binding, octets in (("json", json.dumps(with_detail.to_dict()).encode()), ("cbor", with_detail.to_cbor())):
        assert er.parse_reply(octets, binding) == with_detail
    # Editing the detail does not touch the signature.
    assert verify_refusal_offline(Refusal(**{**with_detail.to_dict(), "detail": "other prose"}))


# --- outcomes.json ----------------------------------------------------------------------------


@_params("outcomes")
def test_outcome_vector(case):
    facts = case["facts"]
    refusal = None
    if facts["received"] == "refusal":
        signed = facts["refusal_signature"] == "valid"
        registered = facts["refusal_reason"] in er.REFUSAL_REASONS
        refusal = er.RefusalCheck(signed, registered, signed and registered)
    state = er.record_outcome(
        facts["received"],
        window_open=facts["window"] == "open",
        artifact_verified=facts.get("artifact_verification") == "verified",
        refusal=refusal,
    )
    assert state == case["expect"]["state"]
    assert state not in case["expect"]["must_not_record_as"]


# --- invariance.json ---------------------------------------------------------------------------


@_params("invariance")
def test_invariance_vector(case):
    observations = [(o["resolved_anchor"], bytes.fromhex(o["artifact_hex"])) for o in case["observations"]]
    for o in case["observations"]:
        assert hashlib.sha256(bytes.fromhex(o["artifact_hex"])).hexdigest() == o["artifact_digest"]
    assert er.compare_observations(observations) == case["expect"]["invariance"]


# --- refusal-02.json ---------------------------------------------------------------------------


@_params("refusal-02")
def test_refusal_02_vector(case):
    """The -02 reasons as this module checks and classifies them; the load-shedding and mapping
    cases state requirements no function here decides."""
    expect, facts = case["expect"], case.get("facts", {})
    if "refusal" in case:
        check = er.check_refusal(case["refusal"])
        assert (check.signature_valid, check.reason_registered, check.conformant) == (
            expect["signature"] == "valid", expect["reason_registered"], expect["conformant"])
    elif "commitment" in facts:
        assert er.classify_refusal(facts["commitment"], facts["refusal_reason"]) == expect["classification"]


# --- retention.json -----------------------------------------------------------------------------


@_params("retention")
def test_retention_vector(case):
    expect = case["expect"]
    if "commitment" in case:
        assert er.commitment_well_formed(case["commitment"]) is expect["well_formed"]
    elif "refusal_reason" in case["facts"]:
        facts = case["facts"]
        assert er.classify_refusal(facts["commitment"], facts["refusal_reason"]) == expect["classification"]
    else:
        facts = case["facts"]
        assert er.classify_absence(facts["commitment"]) == expect["classification"]
        state = er.record_outcome(facts["received"], window_open=facts["window"] == "open")
        assert state == expect["state"]


def test_every_vector_case_is_parametrized():
    """Each test above runs every case of its file, unfiltered, and asserts
    on each with no skip path; the manifest's counts pin the total."""
    counts = {f["path"]: f["count"] for f in MANIFEST["files"]}
    for name in ("request", "resolution", "digest", "refusal", "outcomes", "invariance", "retention"):
        assert len(_cases(name)) == counts[f"{name}.json"]
    files = [c["file"] for c in _cases("refusal") if "file" in c]
    assert files == ["refusal-imported.json"] and counts["refusal-imported.json"] == 1
    assert set(counts) == {p.name for p in VECTORS.glob("*.json")} - {"manifest.json"}
    assert sum(counts[f"{n}.json"] for n in ("request", "resolution", "digest", "refusal", "outcomes",
                                               "invariance", "retention")) == 125


# --- the responder beyond the vectors -------------------------------------------------------------

PIN = RESPONDER["anchors"][1]["digest"]
RECORD = RESPONDER["records"][0]


def _req(**members) -> bytes:
    return json.dumps(members).encode()


def test_any_bytes_get_a_signed_refusal_over_the_bytes_received():
    for data in (b"", b"\xff", b"[]", b"{}", b"null", b'{"subject": NaN}', b'{"a":1,"a":1}'):
        result = answer(data, store=_store(), signer=_Signer(), now=NOW)
        assert isinstance(result, Refusal) and result.reason == REASON_REQUEST_MALFORMED
        assert result.request_digest == hashlib.sha256(data).hexdigest()
        assert verify_refusal_offline(result) and check_refusal(result.to_dict()).conformant


def test_a_duplicate_json_member_is_malformed():
    data = b'{"subject":{"record":"%s"},"subject":{"checkpoints":null},"coverage":{"expected_pin":"%s"}}' % (
        RECORD.encode(), PIN.encode())
    with pytest.raises(RequestError) as exc:
        parse_request(data)
    assert exc.value.reason == REASON_REQUEST_MALFORMED


@pytest.mark.parametrize("bad", [
    {"deadline": "tomorrow"}, {"deadline": "2026-09-28T00:00:00+00:00"}, {"nonce": 7}, {"route": ["a"]},
    {"derivation": "history_card"}, {"derivation": "/1"}, {"subject": {"range": [0, 2 ** 53]}},
    {"subject": {"range": [-1, 2]}}, {"subject": {"range": [0.0, 2]}}, {"subject": {"range": [True, 2]}},
    {"subject": {"correlation": ""}}, {"subject": {"exchange": PIN.upper()}},
    {"coverage": {"min_freshness": "2026-02-30T00:00:00Z"}}, {"coverage": {"min_freshness": 1.5}},
])
def test_a_defined_member_that_does_not_conform_is_malformed(bad):
    members = {"subject": {"checkpoints": None}, "coverage": {"min_freshness": 1}, **bad}
    with pytest.raises(RequestError) as exc:
        parse_request(_req(**members))
    assert exc.value.reason == REASON_REQUEST_MALFORMED


def test_unknown_members_may_hold_anything():
    data = b'{"x":[-1,1.5,1e300,%s,{"y":null}],"subject":{"checkpoints":null},"coverage":{"min_freshness":1}}'
    assert parse_request(data % (b"9" * 300)).subject == Subject("checkpoints")
    for out_of_range in (b"1e999", b"-1e999", b"9" * 400):
        with pytest.raises(RequestError) as exc:
            parse_request(data % out_of_range)
        assert exc.value.reason == REASON_REQUEST_MALFORMED


@pytest.mark.parametrize("binding", ["json", "cbor"])
def test_a_null_coverage_is_malformed_not_absent(binding):
    data = b'{"coverage":null,"subject":{"checkpoints":null}}'
    if binding == "cbor":
        data = bytes.fromhex("a2677375626a656374a16b636865636b706f696e7473f668636f766572616765f6")
    with pytest.raises(RequestError) as exc:
        parse_request(data, binding=binding)
    assert exc.value.reason == REASON_REQUEST_MALFORMED


def test_a_cbor_frame_must_be_core_deterministic():
    case = next(c for c in _cases("request") if c["id"] == "pos-subject-record")
    frame = bytes.fromhex(case["request_cbor_hex"])
    parse_request(frame, binding="cbor")
    for bad in (
        frame + b"\x00",  # trailing bytes
        b"\xb9\x00\x03" + frame[1:],  # a map length not in its shortest form
        b"\xbf" + frame[1:] + b"\xff",  # an indefinite-length map
        b"\xc0" + frame,  # a tag
    ):
        with pytest.raises(RequestError) as exc:
            parse_request(bad, binding="cbor")
        assert exc.value.reason == REASON_REQUEST_MALFORMED
    with pytest.raises(ValueError):
        parse_request(frame, binding="xml")


def test_the_store_never_sees_the_requester_nonce_route_or_deadline():
    """Caller invariance by construction (§5): two requests differing only in
    nonce, route and deadline produce the same artifact."""
    base = {"subject": {"record": RECORD}, "coverage": {"expected_pin": PIN}}
    a = answer(_req(**base, nonce="one"), store=_store(), signer=_Signer(), now=NOW)
    b = answer(_req(**base, nonce="two", route="https://r.example", deadline="2027-01-01T00:00:00Z"),
               store=_store(), signer=_Signer(b"\x01" * 32), now="2027-01-01T00:00:00Z")
    assert a == b


def test_min_freshness_picks_the_largest_qualifying_anchor():
    anchors = [Anchor("a" * 64, 40, "2026-09-26T00:00:00Z"), Anchor("b" * 64, 42, "2026-09-27T00:00:00Z")]
    assert er._freshest(anchors, 40).digest == "b" * 64
    assert er._freshest(anchors, "2026-09-26T00:00:00Z").digest == "b" * 64
    assert er._freshest(anchors, 43) is None


def test_a_range_past_the_anchor_is_not_served_under_it():
    for end, expected in ((41, Artifact), (42, Refusal)):
        result = answer(_req(subject={"range": [0, end]}, coverage={"expected_pin": PIN}),
                        store=_store(), signer=_Signer(), now=NOW)
        assert isinstance(result, expected)
        if expected is Refusal:
            assert result.reason == REASON_COVERAGE_UNSATISFIABLE


def test_an_exchange_pin_that_is_not_the_half_must_be_a_held_anchor():
    half = next(iter(RESPONDER["exchange_citations"]))
    result = answer(_req(subject={"exchange": half}, coverage={"expected_pin": PIN}),
                    store=_store(), signer=_Signer(), now=NOW)
    assert isinstance(result, Artifact) and result.anchor == PIN
    result = answer(_req(subject={"exchange": half}, coverage={"expected_pin": "c" * 64}),
                    store=_store(), signer=_Signer(), now=NOW)
    assert result.reason == REASON_COVERAGE_UNSATISFIABLE


def test_a_store_decline_is_a_signed_refusal():
    store = _store()
    store.decline = REASON_POLICY_DECLINED
    result = answer(_req(subject={"full_history": None}, coverage={"expected_pin": PIN}),
                    store=store, signer=_Signer(), now=NOW)
    assert result.reason == REASON_POLICY_DECLINED and verify_refusal_offline(result)
    with pytest.raises(ValueError):
        Decline("no_such_record")


FRESH = {"digest": "d" * 64, "size": 50, "issued_at": "2026-09-28T00:00:00Z"}
STALE_ASK = {"subject": {"record": RECORD}, "coverage": {"min_freshness": 50}}


@pytest.mark.parametrize("deadline, opt_in", [(None, False), (None, True), ("2026-09-29T00:00:00Z", False)])
def test_unmet_freshness_is_refused_without_both_deadline_and_opt_in(deadline, opt_in):
    store = _store()
    store.after_push = [FRESH]
    ask = {**STALE_ASK, **({"deadline": deadline} if deadline else {})}
    result = answer(_req(**ask), store=store, signer=_Signer(), now=NOW, allow_forced_checkpoint=opt_in)
    assert result.reason == REASON_COVERAGE_UNSATISFIABLE
    assert store.pushes == 0


def test_unmet_freshness_forces_one_checkpoint_with_deadline_and_opt_in():
    store = _store()
    store.after_push = [FRESH]
    ask = {**STALE_ASK, "deadline": "2026-09-29T00:00:00Z"}
    result = answer(_req(**ask), store=store, signer=_Signer(), now=NOW, allow_forced_checkpoint=True)
    assert isinstance(result, Artifact) and result.anchor == FRESH["digest"]
    assert store.pushes == 1


def test_still_unmet_after_the_forced_checkpoint_is_refused():
    store = _store()
    ask = {**STALE_ASK, "deadline": "2026-09-29T00:00:00Z"}
    result = answer(_req(**ask), store=store, signer=_Signer(), now=NOW, allow_forced_checkpoint=True)
    assert result.reason == REASON_COVERAGE_UNSATISFIABLE
    assert store.pushes == 1


def test_an_expected_pin_never_forces_a_checkpoint():
    store = _store()
    ask = {"subject": {"record": RECORD}, "coverage": {"expected_pin": "e" * 64}, "deadline": "2026-09-29T00:00:00Z"}
    result = answer(_req(**ask), store=store, signer=_Signer(), now=NOW, allow_forced_checkpoint=True)
    assert result.reason == REASON_COVERAGE_UNSATISFIABLE and store.pushes == 0


def test_not_held_is_no_such_subject_never_a_prefix_match():
    result = answer(_req(subject={"correlation": "c-7d1e9a4"}, coverage={"expected_pin": PIN}),
                    store=_store(), signer=_Signer(), now=NOW)
    assert result.reason == REASON_NO_SUCH_SUBJECT


def test_sign_refusal_refuses_non_conforming_members():
    digest = "a" * 64
    for args, issued_at in (((digest, "no_such_record"), NOW), (("abc", REASON_NO_SUCH_SUBJECT), NOW),
                            ((digest, REASON_NO_SUCH_SUBJECT), "2026-09-28")):
        with pytest.raises(ValueError):
            sign_refusal(*args, signer=_Signer(), issued_at=issued_at)


def test_tampered_or_garbage_refusals_do_not_verify():
    good = sign_refusal("a" * 64, REASON_NO_SUCH_SUBJECT, signer=_Signer(), issued_at=NOW)
    forged = Refusal(good.request_digest, REASON_POLICY_DECLINED, good.issued_at, good.key_id, good.sig)
    assert not verify_refusal_offline(forged)
    assert not verify_refusal_offline(Refusal("", "", "", "zz", "zz"))
    assert check_refusal([]) == er.RefusalCheck(False, False, False)
    assert check_refusal_cbor(b"\xa1") == er.RefusalCheck(False, False, False)


def test_parse_utc_orders_instants_and_refuses_other_forms():
    assert er.parse_utc("1970-01-01T00:00:00Z") == (0, 0)
    assert er.parse_utc("2000-03-01T00:00:00Z") == (951_868_800, 0)
    assert er.parse_utc("2024-02-29T23:59:59Z") == (1_709_251_199, 0)
    assert er.parse_utc("0000-01-01T00:00:00Z") < er.parse_utc("1969-12-31T23:59:59.999999999Z") < (0, 0)
    assert er.parse_utc("2026-09-27T12:00:00Z") < er.parse_utc("2026-09-27T12:00:00.5Z")
    for bad in ("2026-09-27", "2026-09-27T00:00:00", "2026-09-27t00:00:00z", "2026-02-30T00:00:00Z",
                "2026-09-27T24:00:00Z", "2026-09-27T00:00:00.Z", "2026-09-27T00:00:00.1234567890Z",
                "2025-02-29T00:00:00Z", "\u0662026-09-27T00:00:00Z", None, 7):
        assert er.parse_utc(bad) is None, bad


def test_record_outcome_rejects_unknown_observations():
    with pytest.raises(ValueError):
        er.record_outcome("silence", window_open=True)
    assert er.record_outcome("refusal", window_open=False) == "refusal_signature_invalid"


def test_a_signed_refusal_missing_a_member_is_nonconformant_never_absence():
    case = next(c for c in REFUSAL_CORPUS["cases"] if c["id"] == "neg-missing-issued_at")
    checked = check_refusal(case["refusal"])
    assert checked.signature_valid and checked.reason_registered and not checked.conformant
    assert er.record_outcome("refusal", window_open=False, refusal=checked) == "refusal_nonconformant"


def test_a_small_order_key_never_verifies():
    # The identity point "verifies" any message under plain RFC 8032 checks.
    for key in ("01" + "00" * 31, "00" * 32, "ec" + "ff" * 30 + "7f", "ee" + "ff" * 30 + "7f",
                "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
                "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"):
        obj = {"request_digest": "ab" * 32, "reason": REASON_NO_SUCH_SUBJECT, "issued_at": NOW,
               "key_id": key, "sig": "01" + "00" * 63}
        assert check_refusal(obj) == er.RefusalCheck(False, True, False), key
        assert not verify_refusal_offline(Refusal(**obj))
    assert not er._small_order(bytes.fromhex(PRIMARY.key_id))


def test_a_refusal_member_with_no_canonical_form_is_unsigned_not_a_crash():
    deep = []
    for _ in range(100_000):
        deep = [deep]
    obj = {"request_digest": "ab" * 32, "reason": deep, "issued_at": NOW, "key_id": PRIMARY.key_id, "sig": "00" * 64}
    assert check_refusal(obj) == er.RefusalCheck(False, False, False)


def test_a_refusal_frame_may_carry_any_integer_in_an_unknown_member():
    refusal = sign_refusal("a" * 64, REASON_NO_SUCH_SUBJECT, signer=PRIMARY, issued_at=NOW)
    frame = refusal.to_cbor()
    extra = bytes([0xA6]) + frame[1:] + b"\x61x\x20"  # one more member: "x": -1
    assert check_refusal_cbor(extra).conformant


def test_issued_at_is_whole_second_utc():
    now = er._now_iso()
    assert er.parse_utc(now) is not None and "." not in now
