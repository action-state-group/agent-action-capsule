"""The Evidence Bundle producer: ``build_evidence_bundle`` over a ``ProofSource``
and ``build_unproven_bundle``.

Every produced Bundle is read back with ``verify_bundle(strict=True)``: a
range-proven Bundle of signed records is VALID, a producer-selected one
INCOMPLETE, and a one-byte change INVALID. Each refusal is checked by name."""

from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

pytest.importorskip("cll.log")
pytest.importorskip("scitt_cose")

from cll.checkpoint import (  # noqa: E402
    CheckpointRecord,
    MemoryNodeStore,
    add_leaf,
    checkpoint_to_cose,
    leaf_hash,
    peaks,
    root_from_peaks,
)
from cll.log import AppendInput, CheckpointState, CllState  # noqa: E402
from cll.log.memory import MemoryStore  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from scitt_cose.cose_sign1 import sign_sign1  # noqa: E402
from scitt_cose.statement import build_signed_statement  # noqa: E402

from agent_action_capsule.bundle import (  # noqa: E402
    BundleBuildError,
    StoredRecord,
    build_evidence_bundle,
    build_unproven_bundle,
    proof_source_from_cll,
    verify_bundle,
)
from agent_action_capsule.canonical import compute_capsule_id, jcs  # noqa: E402

PRODUCER = Ed25519PrivateKey.from_private_bytes(bytes([0x0B]) * 32)
LOG_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x2C]) * 32)
LOG_ID = "log:producer-tests"
TIMESTAMP = "2026-10-19T00:00:00Z"
APPENDED_AT = datetime(2026, 10, 19, tzinfo=timezone.utc)
ABSENT = "ab" * 32


def _raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def capsule(action_id: str, *, parent: str | None = None, cites: tuple[str, ...] = (), agent_input: object = None) -> dict:
    record: dict = {
        "spec_version": "draft-mih-scitt-agent-action-capsule-04",
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_id": action_id,
        "action_type": "fyi",
        "operator": "ACME-CO",
        "developer": "agent@v1",
        "timestamp": TIMESTAMP,
        "assurance": {"effect_mode": "not_applicable", "attestation_mode": "self_attested", "ledger_mode": "standalone"},
        "disposition": {"verdict_class": "not_applicable", "decision": "report", "approver": "policy", "human_disposed": False},
    }
    if parent:
        record["chain"] = {"parent_capsule_id": parent, "relation": "follows"}
    if cites:
        record["references"] = [{"type": "agent-action-capsule", "digest_alg": "SHA-256", "digest": c} for c in cites]
    if agent_input is not None:
        from agent_action_capsule.canonical import json_digest

        record["model_attestation"] = {"compute_attestation": {"agent_input_digest": json_digest(agent_input)}}
    record["capsule_id"] = compute_capsule_id(record)
    return record


def envelope(capsule_id: str) -> bytes:
    return bytes.fromhex(
        sign_sign1(
            bytes.fromhex(capsule_id),
            alg="EdDSA",
            private_key_pem=_pem(PRODUCER),
            protected={3: "application/agent-action-capsule-id", 4: _raw(PRODUCER)},
            unprotected={},
        ).hex()
    )


class _Signer:
    key_id = _raw(LOG_KEY).hex()

    def sign_cose_statement(self, payload, *, content_type, issuer, subject, extra_cwt_claims=None):
        return build_signed_statement(
            payload, alg="EdDSA", private_key_pem=_pem(LOG_KEY), issuer=issuer, subject=subject,
            content_type=content_type, extra_cwt_claims=extra_cwt_claims, kid=_raw(LOG_KEY),
        )


class _NotFound(Exception):
    code = "not_found"


class Records:
    """A record store in the artifact-store shape: ``get`` returns capsule and
    envelope bytes, and raises an error with ``code == "not_found"``."""

    def __init__(self) -> None:
        self.held: dict[str, StoredRecord] = {}

    def put(self, record: dict, *, signed: bool = True) -> None:
        cid = record["capsule_id"]
        self.held[cid] = StoredRecord(jcs(record), envelope(cid) if signed else b"")

    def get(self, capsule_id: str) -> StoredRecord:
        if capsule_id not in self.held:
            raise _NotFound(capsule_id)
        return self.held[capsule_id]


def make_log(leaves: list[str], records: Records, *, checkpoint_after: int | None = None):
    """A CLL memory backend holding ``leaves`` (hex values), checkpointed after
    the first ``checkpoint_after`` leaves (all by default)."""
    backend = MemoryStore()
    nodes = MemoryNodeStore()
    covered = len(leaves) if checkpoint_after is None else checkpoint_after
    for index, value in enumerate(leaves):
        backend.append(AppendInput(value=bytes.fromhex(value), appended_at=APPENDED_AT))
        if index < covered:
            add_leaf(nodes, leaf_hash(bytes.fromhex(value)))
    size = nodes.size()
    peak_hashes = [nodes.node(p) for p in peaks(size)]
    root = root_from_peaks(peak_hashes).hex()
    cp = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id=LOG_ID, mmr_size=size, root=root, prev_size=0, prev_root="",
        key_id=_Signer.key_id, timestamp=TIMESTAMP, signature="",
    )
    cose = checkpoint_to_cose(cp, _Signer(), peak_hashes)
    state = CllState(
        size=size,
        nodes=tuple(nodes.node(i) for i in range(size)),
        indexed_seq=covered,
        checkpoint=CheckpointState(bytes=cose, size=size, indexed_seq=covered, peaks=tuple(peak_hashes)),
    )
    backend.commit_cll(0, None, state)
    return proof_source_from_cll(backend, records)


def verdict(bundle: dict) -> str:
    return verify_bundle(bundle, strict=True).verdict


def claims(bundle: dict) -> dict:
    return {name: claim.status for name, claim in verify_bundle(bundle, strict=True).claims}


@pytest.fixture
def chain():
    """Three signed records, each citing the one before; every leaf a record."""
    records = Records()
    a = capsule("a", agent_input={"step": 0})
    b = capsule("b", parent=a["capsule_id"])
    c = capsule("c", parent=b["capsule_id"])
    for r in (a, b, c):
        records.put(r)
    return make_log([r["capsule_id"] for r in (a, b, c)], records), [a, b, c], records


# -- success ---------------------------------------------------------------------


def test_whole_log_range_is_valid(chain):
    source, caps, _ = chain
    bundle = build_evidence_bundle(source, root=caps[2]["capsule_id"], interval_from=1)
    assert [r["capsule_id"] for r in bundle["records"]] == [c["capsule_id"] for c in caps]
    cert = bundle["completeness_certificate"]
    assert (cert["first_seq"], cert["last_seq"]) == (1, 3)
    assert cert["body_digests"] == [c["capsule_id"] for c in caps]
    assert "selection" not in bundle["completeness"]
    assert all(r["key_id"] == _raw(PRODUCER).hex() for r in bundle["records"])
    assert verdict(bundle) == "VALID"


def test_suffix_range_is_valid(chain):
    source, caps, _ = chain
    bundle = build_evidence_bundle(source, root=caps[2]["capsule_id"], interval_from=2, closure_depth=1)
    assert [r["capsule_id"] for r in bundle["records"]] == [c["capsule_id"] for c in caps[1:]]
    assert verdict(bundle) == "VALID"


def test_no_range_is_producer_selected_and_incomplete(chain):
    source, caps, _ = chain
    bundle = build_evidence_bundle(source, root=caps[1]["capsule_id"], interval_from=None, closure_depth=0)
    assert [r["capsule_id"] for r in bundle["records"]] == [caps[1]["capsule_id"]]
    assert bundle["completeness"]["selection"] == "producer-selected"
    assert "range_proof" not in bundle["completeness_certificate"]
    assert claims(bundle)["per_record_membership"] == "pass"
    assert verdict(bundle) == "INCOMPLETE"


def test_checkpoint_fields_come_from_the_signed_statement(chain):
    from cll.checkpoint import verify_checkpoint_cose_offline

    source, caps, _ = chain
    cp = build_evidence_bundle(source, root=caps[0]["capsule_id"], interval_from=1)["checkpoint"]
    decoded = verify_checkpoint_cose_offline(base64.urlsafe_b64decode(cp["cose"] + "=" * (-len(cp["cose"]) % 4))).decoded
    for name in ("log_id", "mmr_size", "root", "prev_size", "prev_root", "key_id", "timestamp"):
        assert cp[name] == getattr(decoded, name)


def test_include_carries_further_records(chain):
    source, caps, _ = chain
    bundle = build_evidence_bundle(
        source, root=caps[2]["capsule_id"], interval_from=None, closure_depth=0, include=[caps[0]["capsule_id"]]
    )
    assert [r["capsule_id"] for r in bundle["records"]] == [caps[0]["capsule_id"], caps[2]["capsule_id"]]


def test_an_unsigned_record_is_carried_unsigned_and_incomplete():
    records = Records()
    a = capsule("unsigned")
    records.put(a, signed=False)
    source = make_log([a["capsule_id"]], records)
    bundle = build_evidence_bundle(source, root=a["capsule_id"], interval_from=1)
    assert "signature" not in bundle["records"][0] and "key_id" not in bundle["records"][0]
    assert claims(bundle)["signatures"] == "withheld"
    assert verdict(bundle) == "INCOMPLETE"


def test_a_missing_citation_is_declared_and_incomplete():
    records = Records()
    a = capsule("cites-absent", cites=(ABSENT,))
    records.put(a)
    bundle = build_evidence_bundle(make_log([a["capsule_id"]], records), root=a["capsule_id"], interval_from=1)
    assert bundle["completeness"]["missing"] == [ABSENT]
    assert bundle["completeness"]["records_mode"] == "declared_incomplete"
    assert verdict(bundle) == "INCOMPLETE"


def test_disclosures_and_payloads_mode(chain):
    source, caps, _ = chain
    root = caps[0]["capsule_id"]
    revealed = build_evidence_bundle(source, root=root, interval_from=None, closure_depth=0, disclosures={root: {"agent_input": {"step": 0}}})
    assert revealed["completeness"]["payloads_mode"] == "all"
    assert claims(revealed)["disclosures"] == "pass"
    plain = build_evidence_bundle(source, root=root, interval_from=None, closure_depth=0)
    assert plain["completeness"]["payloads_mode"] == "selected"
    declared = build_evidence_bundle(source, root=root, interval_from=None, closure_depth=0, payloads_mode="all")
    assert declared["completeness"]["payloads_mode"] == "all", "material carried elsewhere is the caller's claim"
    with pytest.raises(BundleBuildError, match="does not reveal"):
        build_evidence_bundle(
            source, root=caps[2]["capsule_id"], interval_from=1, payloads_mode="all",
            disclosures={caps[1]["capsule_id"]: {}, root: {}},
        )


def test_extensions_verification_and_producer_key(chain):
    source, caps, _ = chain
    key = bytes(range(32))
    bundle = build_evidence_bundle(
        source, root=caps[0]["capsule_id"], interval_from=1, producer_key=key,
        extensions={"example/notes": {"n": 1}}, verification={"producer": "tests", "checks": []},
    )
    assert bundle["extensions"] == {"example/notes": {"n": 1}, "producer-key/v1": {"public_key": key.hex()}}
    assert bundle["verification"] == {"producer": "tests", "checks": []}
    assert verdict(bundle) == "VALID"
    for owned in ("producer-key/v1", "composed/v1"):
        with pytest.raises(BundleBuildError, match="owns"):
            build_evidence_bundle(source, root=caps[0]["capsule_id"], interval_from=1, extensions={owned: {}})
    with pytest.raises(BundleBuildError, match="32-byte"):
        build_evidence_bundle(source, root=caps[0]["capsule_id"], interval_from=1, producer_key=b"short")


# -- tamper ----------------------------------------------------------------------


def _flip(text: str) -> str:
    return ("0" if text[0] != "0" else "1") + text[1:]


@pytest.mark.parametrize("where", ["record", "body_digest", "inclusion_proof", "range_witness", "cose", "checkpoint_root"])
def test_a_one_byte_change_is_invalid(chain, where):
    source, caps, _ = chain
    bundle = build_evidence_bundle(source, root=caps[2]["capsule_id"], interval_from=2, closure_depth=1)
    bad = copy.deepcopy(bundle)
    cert = bad["completeness_certificate"]
    if where == "record":
        bad["records"][0]["action_id"] = _flip(bad["records"][0]["action_id"])
    elif where == "body_digest":
        cert["body_digests"][0] = _flip(cert["body_digests"][0])
    elif where == "inclusion_proof":
        proof = cert["memberships"][caps[1]["capsule_id"]]["inclusion_proof"]
        key = next(k for k in ("witness", "peaks_left", "peaks_right") if proof[k])
        proof[key][0] = _flip(proof[key][0])
    elif where == "range_witness":
        cert["range_proof"]["witness"][0] = _flip(cert["range_proof"]["witness"][0])
    elif where == "cose":
        raw = bytearray(base64.urlsafe_b64decode(bad["checkpoint"]["cose"] + "=" * (-len(bad["checkpoint"]["cose"]) % 4)))
        raw[-1] ^= 1
        bad["checkpoint"]["cose"] = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
    else:
        bad["checkpoint"]["root"] = _flip(bad["checkpoint"]["root"])
    assert verdict(bad) == "INVALID"


# -- refusals --------------------------------------------------------------------


def test_interval_from_is_required(chain):
    source, caps, _ = chain
    with pytest.raises(TypeError):
        build_evidence_bundle(source, root=caps[0]["capsule_id"])  # type: ignore[call-arg]
    for bad in (0, -1, True, "1"):
        with pytest.raises(BundleBuildError, match="interval_from"):
            build_evidence_bundle(source, root=caps[0]["capsule_id"], interval_from=bad)  # type: ignore[arg-type]
    with pytest.raises(BundleBuildError, match="past the checkpoint tip"):
        build_evidence_bundle(source, root=caps[0]["capsule_id"], interval_from=9)


def test_a_record_below_interval_from_is_refused_by_name(chain):
    source, caps, _ = chain
    with pytest.raises(BundleBuildError, match=rf"below interval_from 2: {caps[0]['capsule_id']} \(seq 1\)"):
        build_evidence_bundle(source, root=caps[2]["capsule_id"], interval_from=2, closure_depth=2)
    with pytest.raises(BundleBuildError, match="below interval_from"):
        build_evidence_bundle(source, root=caps[2]["capsule_id"], interval_from=3, closure_depth=0, include=[caps[0]["capsule_id"]])


def test_a_range_over_a_non_record_leaf_is_refused():
    records = Records()
    a, b = capsule("a"), capsule("b")
    records.put(a)
    records.put(b)
    stamp = "cd" * 32  # a leaf the store does not hold as a record
    source = make_log([a["capsule_id"], stamp, b["capsule_id"]], records)
    with pytest.raises(BundleBuildError, match="seq 2 in the interval is not a record"):
        build_evidence_bundle(source, root=b["capsule_id"], interval_from=1)
    assert verdict(build_evidence_bundle(source, root=b["capsule_id"], interval_from=3)) == "VALID"


def test_an_uncovered_record_is_refused():
    records = Records()
    a, late = capsule("a"), capsule("late")
    records.put(a)
    records.put(late)
    source = make_log([a["capsule_id"], late["capsule_id"]], records, checkpoint_after=1)
    with pytest.raises(BundleBuildError, match="not covered by the checkpoint"):
        build_evidence_bundle(source, root=late["capsule_id"], interval_from=None)


def test_unknown_root_and_include_are_refused(chain):
    source, caps, _ = chain
    with pytest.raises(BundleBuildError, match="no such record"):
        build_evidence_bundle(source, root=ABSENT, interval_from=None)
    with pytest.raises(BundleBuildError, match="include: no such record"):
        build_evidence_bundle(source, root=caps[0]["capsule_id"], interval_from=None, include=[ABSENT])


@pytest.mark.parametrize(
    ("disclosures", "suppressed", "payloads", "message"),
    [
        ({ABSENT: {"agent_input": {}}}, (), None, "does not carry"),
        ("root", ("tool_args",), None, "not disclosure-eligible"),
        ("root-input", ("agent_input",), None, "declared suppressed"),
        (None, ("tool_args",), None, "suppressed_fields names"),
        (None, (), "none", "payloads_mode must be"),
    ],
)
def test_bad_options_are_refused(chain, disclosures, suppressed, payloads, message):
    source, caps, _ = chain
    root = caps[0]["capsule_id"]
    if disclosures == "root":
        disclosures, suppressed = {root: {m: {} for m in suppressed}}, ()
    elif disclosures == "root-input":
        disclosures = {root: {"agent_input": {"step": 0}}}
    with pytest.raises(BundleBuildError, match=message):
        build_evidence_bundle(
            source, root=root, interval_from=None, closure_depth=0, disclosures=disclosures,
            suppressed_fields=suppressed, payloads_mode=payloads,
        )


def test_a_mismatched_disclosure_is_refused_by_the_self_check(chain):
    source, caps, _ = chain
    root = caps[0]["capsule_id"]
    with pytest.raises(BundleBuildError, match="does not verify"):
        build_evidence_bundle(source, root=root, interval_from=None, closure_depth=0, disclosures={root: {"agent_input": {"step": 9}}})


def test_negative_closure_depth_is_refused(chain):
    source, caps, _ = chain
    with pytest.raises(BundleBuildError, match="closure_depth"):
        build_evidence_bundle(source, root=caps[0]["capsule_id"], interval_from=None, closure_depth=-1)


@dataclass
class _Lying:
    """A ProofSource that wraps a good one and overrides one member."""

    base: object
    override: dict

    def __getattr__(self, name):
        return self.override.get(name) or getattr(self.base, name)


def test_a_source_that_lies_is_refused(chain):
    source, caps, records = chain
    root = caps[2]["capsule_id"]
    good_inclusion = source.inclusion_proof

    def wrong_inclusion(seq):
        proof = dict(good_inclusion(seq))
        proof["leaf_index"] = (proof["leaf_index"] + 1) % 3
        return proof

    other = capsule("other")
    cases = [
        ({"checkpoint": lambda: b""}, "does not verify"),
        ({"leaves": lambda: source.leaves()[:-1]}, "the source gave 2 leaves"),
        ({"leaves": lambda: [b"short"] + source.leaves()[1:]}, "32-byte"),
        ({"record": lambda cid: StoredRecord(jcs(other), b"")}, "different capsule"),
        ({"record": lambda cid: StoredRecord(records.held[cid].capsule, envelope(ABSENT))}, "envelope does not verify"),
        ({"record": lambda cid: StoredRecord(b"not json", b"")}, "not a JSON object"),
        ({"inclusion_proof": wrong_inclusion}, "does not verify"),
    ]
    for override, message in cases:
        with pytest.raises(BundleBuildError, match=message):
            build_evidence_bundle(_Lying(source, override), root=root, interval_from=None)


def test_a_store_error_other_than_not_found_propagates(chain):
    source, caps, _ = chain

    class Broken:
        def get(self, capsule_id):
            raise OSError("disk")

    from agent_action_capsule.bundle import _CllProofSource

    broken = copy.copy(source)
    assert isinstance(broken, _CllProofSource)
    broken._records = Broken()
    with pytest.raises(OSError, match="disk"):
        build_evidence_bundle(broken, root=caps[0]["capsule_id"], interval_from=None)


def test_a_log_without_a_checkpoint_is_refused():
    backend = MemoryStore()
    source = proof_source_from_cll(backend, Records())
    with pytest.raises(BundleBuildError, match="no checkpoint"):
        build_evidence_bundle(source, root=ABSENT, interval_from=None)


# -- the unproven form -----------------------------------------------------------


def test_unproven_bundle_carries_no_log_proof(chain):
    _, caps, _ = chain
    bundle = build_unproven_bundle(caps, root=caps[2]["capsule_id"])
    assert "checkpoint" not in bundle and "completeness_certificate" not in bundle
    assert bundle["completeness"]["records_mode"] == "complete"
    assert verdict(bundle) == "INCOMPLETE"
    partial = build_unproven_bundle(caps[1:], root=caps[2]["capsule_id"])
    assert partial["completeness"]["missing"] == [caps[0]["capsule_id"]]


def test_unproven_bundle_refusals(chain):
    _, caps, _ = chain
    with pytest.raises(BundleBuildError, match="not among the records"):
        build_unproven_bundle(caps, root=ABSENT)
    with pytest.raises(BundleBuildError, match="duplicate"):
        build_unproven_bundle(caps + caps[:1], root=caps[0]["capsule_id"])
    with pytest.raises(BundleBuildError, match="capsule_id"):
        build_unproven_bundle([{}], root="x")
    with pytest.raises(BundleBuildError, match="does not carry"):
        build_unproven_bundle(caps, root=caps[0]["capsule_id"], disclosures={ABSENT: {}})


# -- round-1 review fixes --------------------------------------------------------


@pytest.mark.parametrize("option", [{"extensions": {"example/notes": {"n": 1.5}}}, {"verification": {"n": 2**60}}])
def test_a_bundle_with_no_canonical_digest_is_refused(chain, option):
    source, caps, _ = chain
    with pytest.raises(BundleBuildError, match="no canonical digest"):
        build_evidence_bundle(source, root=caps[0]["capsule_id"], interval_from=1, **option)


@pytest.mark.parametrize(
    "inline",
    [
        {"signature": "VALID", "key_id": "VALID"},
        {"signature": "00", "key_id": "11"},
        {"signature": "VALID"},
        {"key_id": "VALID"},
    ],
)
def test_an_empty_envelope_means_unsigned_whatever_the_stored_json_says(inline):
    from agent_action_capsule.canonical import jcs as canonical

    a = capsule("inline")
    real = {"signature": envelope(a["capsule_id"]).hex(), "key_id": _raw(PRODUCER).hex()}
    stored = dict(a, **{k: real[k] if v == "VALID" else v for k, v in inline.items()})
    records = Records()
    records.held[a["capsule_id"]] = StoredRecord(canonical(stored), b"")
    bundle = build_evidence_bundle(make_log([a["capsule_id"]], records), root=a["capsule_id"], interval_from=1)
    assert "signature" not in bundle["records"][0] and "key_id" not in bundle["records"][0]
    assert verdict(bundle) == "INCOMPLETE"


def test_closure_stops_when_the_graph_is_exhausted(chain):
    import time

    source, caps, _ = chain
    started = time.monotonic()
    bundle = build_evidence_bundle(source, root=caps[0]["capsule_id"], interval_from=None, closure_depth=2**53 - 1)
    assert time.monotonic() - started < 5
    assert bundle["completeness"]["closure_depth"] == 2**53 - 1
    with pytest.raises(BundleBuildError, match="closure_depth"):
        build_evidence_bundle(source, root=caps[0]["capsule_id"], interval_from=None, closure_depth=2**53)


def test_payloads_mode_is_all_when_nothing_committed_is_unrevealed(chain):
    source, caps, _ = chain
    # caps[1] commits no payload digest: nothing to reveal, so "all".
    nothing = build_evidence_bundle(source, root=caps[1]["capsule_id"], interval_from=None, closure_depth=0)
    assert nothing["completeness"]["payloads_mode"] == "all"
    # caps[0] commits agent_input; suppressing it leaves nothing unrevealed.
    suppressed = build_evidence_bundle(
        source, root=caps[0]["capsule_id"], interval_from=None, closure_depth=0, suppressed_fields=["agent_input"]
    )
    assert suppressed["completeness"]["payloads_mode"] == "all"
    assert verdict(suppressed) == "INCOMPLETE"  # no range: producer-selected


def test_source_proofs_are_normalised_to_their_wire_fields(chain):
    source, caps, _ = chain
    inclusion, ranged = source.inclusion_proof, source.range_proof
    padded = _Lying(
        source,
        {
            "inclusion_proof": lambda seq: {**inclusion(seq), "smuggled": "x"},
            "range_proof": lambda first: {**ranged(first), "note": "hi"},
        },
    )
    bundle = build_evidence_bundle(padded, root=caps[2]["capsule_id"], interval_from=1)
    cert = bundle["completeness_certificate"]
    assert "note" not in cert["range_proof"]
    assert all("smuggled" not in m["inclusion_proof"] for m in cert["memberships"].values())
    for override, message in (
        ({"inclusion_proof": lambda seq: None}, "inclusion proof for seq 1 is malformed"),
        ({"range_proof": lambda first: [1]}, "range proof is malformed"),
    ):
        with pytest.raises(BundleBuildError, match=message):
            build_evidence_bundle(_Lying(source, override), root=caps[2]["capsule_id"], interval_from=1)


def test_a_source_that_lies_under_a_range_is_refused(chain):
    source, caps, records = chain
    root = caps[2]["capsule_id"]
    inclusion, ranged, leaves = source.inclusion_proof, source.range_proof, source.leaves

    def flip(proof, field):
        proof = {k: list(v) if isinstance(v, (list, tuple)) else v for k, v in dict(proof).items()}
        proof[field][0] = _flip(proof[field][0])
        return proof

    def swapped():
        values = list(leaves())
        values[0], values[1] = values[1], values[0]
        return values

    def edited(cid):
        body = dict(capsule("a", agent_input={"step": 0}), action_id="edited", capsule_id=cid)
        return StoredRecord(jcs(body), b"")

    def wrong_inclusion(seq):
        proof = dict(inclusion(seq))
        field = next(k for k in ("witness", "peaks_left", "peaks_right") if proof[k])
        return flip(proof, field)

    cases = [
        ({"range_proof": lambda first: flip(ranged(first), "witness")}, 2, "does not verify"),
        ({"leaves": swapped}, 1, "does not verify"),
        ({"inclusion_proof": wrong_inclusion}, 1, "does not verify"),
        ({"record": edited}, 1, "record_identity_invalid"),
    ]
    for override, first, message in cases:
        with pytest.raises(BundleBuildError, match=message):
            build_evidence_bundle(_Lying(source, override), root=root, interval_from=first, closure_depth=1 if first > 1 else 2)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"producer_key": "a" * 32}, "producer_key"),
        ({"include": "abc"}, "include must be"),
        ({"extensions": [1]}, "extensions must be"),
        ({"verification": [1]}, "verification must be"),
    ],
)
def test_wrongly_typed_options_are_refused(chain, kwargs, message):
    source, caps, _ = chain
    with pytest.raises(BundleBuildError, match=message):
        build_evidence_bundle(source, root=caps[0]["capsule_id"], interval_from=None, **kwargs)
