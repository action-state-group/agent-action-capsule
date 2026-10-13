# SPDX-License-Identifier: BSD-3-Clause
"""The evidence-request responder (``agent_action_capsule.evidence_request``).

``answer()`` runs here against an in-memory :class:`EvidenceStore`, so these
tests pin the decision logic without any log implementation. The refusal
signing and verification are also checked against the signed refusals in
``vectors/evidence-request/refusal.json``: Ed25519 is deterministic, so the
responder must reproduce each vector signature byte for byte.
"""
from __future__ import annotations

import hashlib
import json
import warnings
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import agent_action_capsule.evidence_request as er
from agent_action_capsule.evidence_request import (
    REASON_COVERAGE_UNSATISFIABLE,
    REASON_DERIVATION_UNSUPPORTED,
    REASON_NO_SUCH_RECORD,
    REASON_NO_SUCH_SUBJECT,
    REASON_REQUEST_MALFORMED,
    REFUSAL_REASONS,
    Artifact,
    NotYetCovered,
    Refusal,
    answer,
    normalize_refusal_reason,
    parse_request,
    sign_refusal,
    verify_refusal_offline,
)

VECTORS = Path(__file__).resolve().parents[2] / "vectors" / "evidence-request"
NOW = "2026-10-01T12:00:00Z"


class _Signer:
    def __init__(self, seed: bytes = b"\x07" * 32) -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        self.key_id = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def sign(self, body: bytes) -> tuple[str, str]:
        return self._key.sign(body).hex(), self.key_id


@dataclass(frozen=True)
class _Checkpoint:
    mmr_size: int
    root: str
    timestamp: str


@dataclass(frozen=True)
class _Bundle:
    capsule_id: str
    checkpoint: _Checkpoint

    def to_dict(self) -> dict:
        return {"capsule_id": self.capsule_id, "mmr_size": self.checkpoint.mmr_size}


@dataclass
class _Store:
    """Records in append order; ``covered_by`` is the checkpoint covering
    every record, or ``None`` before the first checkpoint."""

    records_: list[dict] = field(default_factory=list)
    covered_by: _Checkpoint | None = None
    after_push: _Checkpoint | None = None
    pushes: int = 0
    pushed_by: str | None = None
    segment_owner: str | None = None

    def holds(self, capsule_id: str) -> bool:
        return any(r["capsule_id"] == capsule_id for r in self.records_)

    def bundle(self, capsule_id: str) -> _Bundle:
        if self.covered_by is None:
            raise NotYetCovered(capsule_id)
        return _Bundle(capsule_id, self.covered_by)

    def select_range(self, selector: str) -> list[str] | None:
        wanted = selector.split(",")
        found = [r["capsule_id"] for r in self.records_ if r["capsule_id"] in wanted]
        return found or None

    def records(self) -> list[dict]:
        return list(self.records_)

    def chain_segment(self, subject: dict, *, self_owner_id: str) -> _Bundle | None:
        if not self.records_:
            return None
        if self.covered_by is None:
            raise NotYetCovered("no checkpoints")
        self.segment_owner = self_owner_id
        return _Bundle("segment", self.covered_by)

    def force_checkpoint(self, signer) -> None:
        self.pushes += 1
        self.pushed_by = signer.key_id
        self.covered_by = self.after_push


CP_OLD = _Checkpoint(mmr_size=3, root="r" * 64, timestamp="2026-10-01T11:00:00Z")
CP_NEW = _Checkpoint(mmr_size=5, root="s" * 64, timestamp="2026-10-01T11:59:50Z")


def _ids(n: int) -> list[str]:
    return [f"{i:064x}" for i in range(1, n + 1)]


def _store(n: int = 3, covered_by: _Checkpoint | None = CP_OLD, **kw) -> _Store:
    return _Store(records_=[{"capsule_id": cid} for cid in _ids(n)], covered_by=covered_by, **kw)


def _req(**members) -> bytes:
    return json.dumps(members).encode()


def _ask(store: _Store, request: bytes, **kw):
    return answer(request, store=store, signer=_Signer(), now=NOW, **kw)


def _refused(result, reason: str) -> None:
    assert isinstance(result, Refusal), result
    assert result.reason == reason
    assert verify_refusal_offline(result)


# --- refusals ---------------------------------------------------------------


@pytest.mark.parametrize(
    "request_bytes",
    [b"not json", b"[]", _req(subject={"kind": "nope"}), _req(subject={"kind": "record"}),
     _req(subject={"kind": "chain_segment", "last": 2, "to_size": 3}),
     _req(subject={"kind": "range", "selector": "a"}, page={"token": "x"})],
)
def test_malformed_request_is_a_signed_refusal_over_the_bytes_received(request_bytes):
    result = _ask(_store(), request_bytes)
    _refused(result, REASON_REQUEST_MALFORMED)
    assert result.request_digest == hashlib.sha256(request_bytes).hexdigest()
    assert result.issued_at == NOW


def test_any_derivation_is_refused_unsupported():
    _refused(_ask(_store(), _req(subject={"kind": "record", "capsule_id": _ids(1)[0]}, derivation="x/1")),
             REASON_DERIVATION_UNSUPPORTED)


def test_record_not_held_is_no_such_subject():
    _refused(_ask(_store(), _req(subject={"kind": "record", "capsule_id": "f" * 64})), REASON_NO_SUCH_SUBJECT)


def test_record_held_but_uncovered_is_coverage_unsatisfiable():
    _refused(_ask(_store(covered_by=None), _req(subject={"kind": "record", "capsule_id": _ids(1)[0]})),
             REASON_COVERAGE_UNSATISFIABLE)


def test_tampered_refusal_does_not_verify():
    result = _ask(_store(), b"not json")
    forged = Refusal(result.request_digest, REASON_NO_SUCH_SUBJECT, result.issued_at, result.key_id, result.sig)
    assert not verify_refusal_offline(forged)
    assert not verify_refusal_offline(Refusal("", "", "", "zz", "zz"))


# --- artifacts and paging ---------------------------------------------------


def test_record_held_and_covered_is_an_artifact():
    cid = _ids(2)[1]
    result = _ask(_store(), _req(subject={"kind": "record", "capsule_id": cid}))
    assert isinstance(result, Artifact)
    assert result.to_dict() == {"v": 1, "subject_kind": "record", "bundles": [{"capsule_id": cid, "mmr_size": 3}]}


def test_answer_does_not_depend_on_the_nonce():
    cid = _ids(1)[0]
    a = _ask(_store(), _req(subject={"kind": "record", "capsule_id": cid}, nonce="one"))
    b = _ask(_store(), _req(subject={"kind": "record", "capsule_id": cid}, nonce="two"))
    assert a.to_dict() == b.to_dict()


def test_range_pages_through_the_selection(monkeypatch):
    monkeypatch.setattr(er, "DEFAULT_PAGE_SIZE", 2)
    ids = _ids(5)
    seen, token = [], None
    for _ in range(3):
        page = {"token": token} if token else {}
        result = _ask(_store(5), _req(subject={"kind": "range", "selector": ",".join(ids)}, page=page))
        seen += [b.capsule_id for b in result.bundles]
        token = result.next_page_token
    assert seen == ids
    assert token is None


def test_page_size_is_capped(monkeypatch):
    monkeypatch.setattr(er, "MAX_PAGE_SIZE", 3)
    ids = _ids(5)
    result = _ask(_store(5), _req(subject={"kind": "range", "selector": ",".join(ids)}, page={"size": 100}))
    assert [b.capsule_id for b in result.bundles] == ids[:3]
    assert result.next_page_token == "3"


def test_a_token_past_the_end_is_an_empty_artifact():
    ids = _ids(2)
    result = _ask(_store(2), _req(subject={"kind": "range", "selector": ",".join(ids)}, page={"token": "9"}))
    assert isinstance(result, Artifact)
    assert result.bundles == ()
    assert result.next_page_token is None


def test_range_selecting_nothing_is_no_such_subject():
    _refused(_ask(_store(), _req(subject={"kind": "range", "selector": "f" * 64})), REASON_NO_SUCH_SUBJECT)


# --- correlation ------------------------------------------------------------


def test_correlation_matches_a_correlator_at_any_depth_and_under_any_alias():
    s = _store(0)
    s.records_ = [
        {"capsule_id": "a" * 64, "x": {"y": [{"client_nonce": "n1"}]}},
        {"capsule_id": "b" * 64, "nonce": "n2"},
        {"capsule_id": "c" * 64, "deep": {"nonce": "n1"}},
    ]
    result = _ask(s, _req(subject={"kind": "correlation", "by": "nonce", "value": "n1"}))
    assert [b.capsule_id for b in result.bundles] == ["a" * 64, "c" * 64]


def test_counterparty_matches_an_adjudication_naming_it():
    s = _store(0)
    s.records_ = [
        {"capsule_id": "a" * 64, "m": {"adjudication": {"verdict": "contradicted:peer"}}},
        {"capsule_id": "b" * 64, "m": {"adjudication": {"verdict": "corroborated"}}},
        {"capsule_id": "c" * 64, "counterparty_ref": "peer"},
    ]
    result = _ask(s, _req(subject={"kind": "correlation", "by": "counterparty", "value": "peer"}))
    assert [b.capsule_id for b in result.bundles] == ["a" * 64, "c" * 64]


def test_correlation_matching_nothing_is_no_such_subject():
    _refused(_ask(_store(), _req(subject={"kind": "correlation", "by": "deal_id", "value": "d"})),
             REASON_NO_SUCH_SUBJECT)


# --- chain_segment ----------------------------------------------------------


def test_chain_segment_passes_the_signer_as_self_owner():
    s = _store()
    result = _ask(s, _req(subject={"kind": "chain_segment", "last": 2}))
    assert isinstance(result, Artifact)
    assert s.segment_owner == _Signer().key_id


def test_chain_segment_on_an_empty_store_is_no_such_subject():
    _refused(_ask(_store(0), _req(subject={"kind": "chain_segment", "last": 1})), REASON_NO_SUCH_SUBJECT)


def test_chain_segment_not_available_is_coverage_unsatisfiable():
    _refused(_ask(_store(covered_by=None), _req(subject={"kind": "chain_segment", "last": 1})),
             REASON_COVERAGE_UNSATISFIABLE)


# --- coverage ---------------------------------------------------------------


def _record_req(**coverage_and_more) -> bytes:
    return _req(subject={"kind": "record", "capsule_id": _ids(1)[0]}, **coverage_and_more)


def test_expected_pin_must_match_the_covering_checkpoint():
    pin = {"root": CP_OLD.root, "mmr_size": CP_OLD.mmr_size}
    assert isinstance(_ask(_store(), _record_req(coverage={"expected_pin": pin})), Artifact)
    pin["mmr_size"] = 4
    _refused(_ask(_store(), _record_req(coverage={"expected_pin": pin})), REASON_COVERAGE_UNSATISFIABLE)


@pytest.mark.parametrize(
    "deadline, opt_in",
    [(None, False), (None, True), ("2026-10-02T00:00:00Z", False)],
)
def test_stale_evidence_is_refused_without_both_deadline_and_opt_in(deadline, opt_in):
    s = _store(after_push=CP_NEW)
    request = _record_req(coverage={"min_freshness": {"max_age_seconds": 60}}, deadline=deadline)
    _refused(_ask(s, request, allow_forced_checkpoint=opt_in), REASON_COVERAGE_UNSATISFIABLE)
    assert s.pushes == 0


def test_stale_evidence_forces_one_checkpoint_with_deadline_and_opt_in():
    s = _store(after_push=CP_NEW)
    request = _record_req(coverage={"min_freshness": {"max_age_seconds": 60}}, deadline="2026-10-02T00:00:00Z")
    result = _ask(s, request, allow_forced_checkpoint=True)
    assert isinstance(result, Artifact)
    assert result.bundles[0].checkpoint == CP_NEW
    assert s.pushes == 1
    assert s.pushed_by == _Signer().key_id


def test_uncovered_evidence_forces_one_checkpoint_with_deadline_and_opt_in():
    s = _store(covered_by=None, after_push=CP_NEW)
    request = _record_req(coverage={"min_freshness": {"max_age_seconds": 60}}, deadline="2026-10-02T00:00:00Z")
    assert isinstance(_ask(s, request, allow_forced_checkpoint=True), Artifact)
    assert s.pushes == 1


def test_still_stale_after_the_forced_checkpoint_is_refused():
    s = _store(after_push=CP_OLD)
    request = _record_req(coverage={"min_freshness": {"max_age_seconds": 60}}, deadline="2026-10-02T00:00:00Z")
    _refused(_ask(s, request, allow_forced_checkpoint=True), REASON_COVERAGE_UNSATISFIABLE)
    assert s.pushes == 1


def test_no_min_freshness_never_forces_a_checkpoint():
    s = _store(covered_by=None, after_push=CP_NEW)
    request = _record_req(coverage={}, deadline="2026-10-02T00:00:00Z")
    _refused(_ask(s, request, allow_forced_checkpoint=True), REASON_COVERAGE_UNSATISFIABLE)
    assert s.pushes == 0


def test_expected_pin_takes_precedence_over_min_freshness():
    """With both members present only the pin is checked: a matching pin
    serves stale evidence and never forces a checkpoint."""
    s = _store(after_push=CP_NEW)
    pin = {"root": CP_OLD.root, "mmr_size": CP_OLD.mmr_size}
    request = _record_req(
        coverage={"expected_pin": pin, "min_freshness": {"max_age_seconds": 60}}, deadline="2026-10-02T00:00:00Z"
    )
    result = _ask(s, request, allow_forced_checkpoint=True)
    assert isinstance(result, Artifact)
    assert result.bundles[0].checkpoint == CP_OLD
    assert s.pushes == 0


def test_stale_evidence_that_vanishes_after_the_forced_checkpoint_is_refused():
    s = _store(after_push=None)
    request = _record_req(coverage={"min_freshness": {"max_age_seconds": 60}}, deadline="2026-10-02T00:00:00Z")
    _refused(_ask(s, request, allow_forced_checkpoint=True), REASON_COVERAGE_UNSATISFIABLE)
    assert s.pushes == 1


# --- parsing, reasons, time -------------------------------------------------


def test_parse_request_ignores_unknown_members():
    req = parse_request(_req(subject={"kind": "record", "capsule_id": "a"}, extra=1, deadline=0))
    assert req.has_deadline and req.coverage == {} and req.page == {}


def test_normalize_refusal_reason_translates_only_the_legacy_spelling():
    with pytest.warns(DeprecationWarning):
        assert normalize_refusal_reason(REASON_NO_SUCH_RECORD) == REASON_NO_SUCH_SUBJECT
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        for reason in REFUSAL_REASONS:
            assert normalize_refusal_reason(reason) == reason


def test_issued_at_is_whole_second_utc():
    now = er._now_iso()
    assert now.endswith("Z") and "." not in now and len(now) == len("2026-10-01T12:00:00Z")


# --- the -00 refusal vectors ------------------------------------------------


def _refusal_cases() -> list[dict]:
    corpus = json.loads((VECTORS / "refusal.json").read_text(encoding="utf-8"))
    cases = []
    for case in corpus["cases"]:
        if "file" in case:
            case = {**case, "refusal": json.loads((VECTORS / case["file"]).read_text(encoding="utf-8"))}
        refusal = case["refusal"]
        if set(refusal) == {"request_digest", "reason", "issued_at", "key_id", "sig"} and all(
            isinstance(v, str) for v in refusal.values()
        ):
            cases.append(case)
    return cases


REFUSAL_CASES = _refusal_cases()
PRIMARY_SEED = bytes.fromhex(
    json.loads((VECTORS / "refusal.json").read_text(encoding="utf-8"))["keys"]["primary"]["seed_hex"]
)


def test_the_vector_corpus_is_covered():
    """Every case is checked except the two that cannot be built as a
    Refusal: a list-valued reason, and a refusal with no issued_at."""
    corpus = json.loads((VECTORS / "refusal.json").read_text(encoding="utf-8"))
    skipped = {c["id"] for c in corpus["cases"]} - {c["id"] for c in REFUSAL_CASES}
    assert skipped == {"neg-two-reasons", "neg-missing-issued_at"}
    assert {c["id"] for c in PRIMARY_VALID} == {
        c["id"] for c in REFUSAL_CASES
        if c["expect"]["signature"] == "valid" and "file" not in c
    }


@pytest.mark.parametrize("case", REFUSAL_CASES, ids=[c["id"] for c in REFUSAL_CASES])
def test_verify_refusal_offline_agrees_with_every_signed_vector(case):
    assert verify_refusal_offline(Refusal(**case["refusal"])) is (case["expect"]["signature"] == "valid")


PRIMARY_VALID = [
    c for c in REFUSAL_CASES
    if c["expect"]["signature"] == "valid" and c["refusal"]["key_id"] == _Signer(PRIMARY_SEED).key_id
]


@pytest.mark.parametrize("case", PRIMARY_VALID, ids=[c["id"] for c in PRIMARY_VALID])
def test_sign_refusal_reproduces_every_valid_primary_key_vector(case):
    refusal = case["refusal"]
    signer = _Signer(PRIMARY_SEED)
    signed = sign_refusal(refusal["request_digest"], refusal["reason"], signer=signer, issued_at=refusal["issued_at"])
    assert signed.to_dict() == refusal
