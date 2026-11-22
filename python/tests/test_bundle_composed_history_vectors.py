# SPDX-License-Identifier: BSD-3-Clause
"""The Evidence Bundle -03 History member vectors, rederived.

An independent reading of the draft text ("History Members", "Joins",
"Observers and Redundancy"): the standard library, ``cryptography`` for
Ed25519, ``cbor2`` for a root record's producer envelope, CLL's offline
checkpoint verifier for anchor checkpoints and empty-history checkpoints, and
the bytes in ``vectors/bundle/composed-history/``. Nothing is imported from the
generator or from this repository's verifiers. Controller binding records are
read only as far as the one case that delivers one needs.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

cbor2 = pytest.importorskip("cbor2")
pytest.importorskip("cll")

from cll.checkpoint import verify_checkpoint_cose_offline  # noqa: E402
from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DATA = json.loads((ROOT / "vectors" / "bundle" / "composed-history" / "vectors.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
PROFILES = {"evidence-interop/0", "evidence-interop/1", "evidence-interop/2"}
SIGNED = ("profile", "request_digest", "subject", "derivation", "anchor", "artifact_digest", "verification",
          "responder", "issued_at")


def _jcs(value: Any) -> bytes:
    # RFC 8785 for these vectors' value space (ASCII keys, integers only).
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _ed25519(key_hex: str, message: bytes, sig_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(bytes.fromhex(sig_hex), message)
        return True
    except (InvalidSignature, ValueError):
        return False


def _time(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def _checkpoint(cose: bytes, *, one_form: bool = False):
    """A CLL COSE checkpoint that verifies; with ``one_form``, only in the
    interop profile's one form: tag 18 and an empty unprotected header."""
    if one_form:
        tagged = cbor2.loads(cose)
        if not (isinstance(tagged, cbor2.CBORTag) and tagged.tag == 18 and len(tagged.value[1]) == 0):
            return None
    verified = verify_checkpoint_cose_offline(cose)
    return verified.decoded if verified.ok else None


def _history_view(member: dict) -> tuple[dict, tuple[str, str] | None]:
    """The five checks of "History Members" and the join view."""
    env = member["history"]["envelope"]
    artifact = _b64u(env["artifact"])
    try:
        card = json.loads(artifact)
        anchor_ok = isinstance(card, dict) and _jcs(card) == artifact and card.get("anchor") == env["anchor"]["digest"]
    except ValueError:
        anchor_ok = False
    cp = _b64u(member["history"]["anchor_checkpoint"])
    decoded = _checkpoint(cp, one_form=True) if _sha(cp) == env["anchor"]["digest"] else None
    signature = "signature_unverified"
    if isinstance(env.get("profile"), str) and env["profile"] in PROFILES:
        body = _jcs({k: env[k] for k in SIGNED if k in env})
        signature = "verified" if _ed25519(env["responder"], body, env["sig"]) else "invalid"
    checks = {
        "envelope_signature": signature,
        "artifact_digest": "matches" if _sha(artifact) == env["artifact_digest"] else "mismatch",
        "request_digest": "matches" if env["request_digest"] == member["request_digest"] else "mismatch",
        "artifact_anchor": "matches" if anchor_ok else "mismatch",
        "anchor_checkpoint": ("mismatch" if _sha(cp) != env["anchor"]["digest"]
                              else "verified" if decoded is not None else "invalid"),
    }
    passed = (signature == "verified" and all(v in ("matches", "verified") for v in checks.values())
              and _sha(_jcs(env)) == member["digest"])
    return checks, ((env["responder"], decoded.timestamp) if passed else None)


def _root(member: dict) -> dict | None:
    bundle = member.get("bundle")
    if not bundle:
        return None
    return next((r for r in bundle.get("records", []) if r.get("capsule_id") == bundle.get("root")), None)


def _signer(record: dict) -> str | None:
    """The key a root record's producer envelope verifies under, when that is
    its key_id: a tagged COSE_Sign1 over the raw Capsule ID."""
    try:
        tag = cbor2.loads(bytes.fromhex(record["signature"]))
        protected, _, payload, signature = tag.value
        key = cbor2.loads(protected)[4]
        structure = cbor2.dumps(["Signature1", protected, b"", payload])
        Ed25519PublicKey.from_public_bytes(key).verify(signature, structure)
    except (KeyError, ValueError, TypeError, AttributeError, InvalidSignature, binascii.Error):
        return None
    if payload != bytes.fromhex(record["capsule_id"]) or key.hex() != record.get("key_id"):
        return None
    return record["key_id"]


def _empty(member: dict) -> bool:
    bundle = member.get("bundle")
    return bundle is not None and not bundle.get("records") and "root" not in bundle


def _binding_applies(record: dict, a: tuple[str, datetime], b: tuple[str, datetime]) -> bool:
    keys = record["keys"]
    body = _jcs({k: v for k, v in record.items() if k != "sigs"})
    signed = all(_ed25519(s["key_id"], body, s["sig"]) for s in record["sigs"]) and \
        [s["key_id"] for s in record["sigs"]] == keys
    window = all(_time(record["not_before"]) <= t < _time(record["not_after"]) for _, t in (a, b))
    return signed and window and sorted([a[0], b[0]]) == keys


def _derive(case: dict, join: dict, views: dict) -> tuple[str | None, list]:
    block = case["container"]["extensions"]["composed/v1"]
    members = {m["id"]: m for m in block["members"]}
    missing = set(block.get("missing", []))
    a, b = (members[i] for i in join["members"])
    if any(m["id"] in missing and "history" not in m and "bundle" not in m for m in (a, b)):
        return None, []
    histories = [m for m in (a, b) if "history" in m]
    if histories and (join["basis"] not in ("same_key", "controller_binding") or any(m["id"] not in views
                                                                                       for m in histories)):
        return None, []
    with_records = [m for m in (a, b) if m["outcome"] == "artifact" and not _empty(m)]
    empty = [m for m in (a, b) if m["outcome"] == "artifact" and _empty(m)]

    def side(m: dict) -> tuple[str, datetime] | None:
        if "history" in m:
            key, at = views[m["id"]]
            return key, _time(at)
        if _empty(m):
            decoded = _checkpoint(_b64u(m["bundle"]["checkpoint"]["cose"]))
            return (decoded.key_id, _time(decoded.timestamp)) if decoded else None
        record = _root(m)
        if join["basis"] == "same_key":
            key = _signer(record)
            return (key, _time(record["timestamp"])) if key else None
        return record[join["pointer"][1:]], _time(record["timestamp"])

    def linked(sa, sb) -> bool:
        if join["basis"] == "same_key":
            return sa[0] == sb[0]
        record = next(r for r in case["controller_bindings"]
                      if _sha(_jcs({k: v for k, v in r.items() if k != "sigs"})) == join["identifier_digest"])
        return _binding_applies(record, sa, sb)

    if not with_records:
        return "unjoined", []
    if len(with_records) == 1:
        if not empty:
            return "one_sided", []
        sa, sb = side(with_records[0]), side(empty[0])
        if sa is None or sb is None:
            return None, []
        if linked(sa, sb):
            return "one_sided", []
        by = {with_records[0]["id"]: sa[0], empty[0]["id"]: sb[0]}
        keys = [{"member": i, "key": by[i]} for i in join["members"]] if join["basis"] == "same_key" else []
        return "unjoined", keys
    if join["basis"] == "pre_agreed_identifier":
        ra, rb = _root(a), _root(b)
        token = join["pointer"].split("/")[1:]

        def at(record):
            for t in token:
                record = record[t]
            return record
        ok = _sha(at(ra).encode()) == join["identifier_digest"] == _sha(at(rb).encode())
        return ("agree" if ok else "unjoined"), []
    sa, sb = side(a), side(b)
    if sa is None or sb is None:
        return None, []
    if not linked(sa, sb):
        keys = [{"member": a["id"], "key": sa[0]}, {"member": b["id"], "key": sb[0]}] \
            if join["basis"] == "same_key" else []
        return "unjoined", keys
    # A History has no root record: a compare pointer never resolves in it.
    if join.get("compare") and histories:
        return "mismatch", []
    return "agree", []


@pytest.mark.parametrize("case", [c for c in CASES if not c["expect"].get("malformed")],
                         ids=[c["id"] for c in CASES if not c["expect"].get("malformed")])
def test_history_case_rederived(case):
    block = case["container"]["extensions"]["composed/v1"]
    views = {}
    for member in block["members"]:
        want = case["expect"]["members"][member["id"]]
        if "history" not in member:
            continue
        checks, view = _history_view(member)
        got = dict(checks, derivation=member["history"]["envelope"]["derivation"],
                   key=view[0] if view else None, time=view[1] if view else None)
        assert got == want["history_member"], member["id"]
        assert want["digest"] == ("reproduced" if _sha(_jcs(member["history"]["envelope"])) == member["digest"]
                                  else "mismatch")
        if view:
            views[member["id"]] = view
    members = {m["id"]: m for m in block["members"]}
    for join, want in zip(block["joins"], case["expect"]["joins"]):
        derived, keys = _derive(case, join, views)
        assert derived == want["derived"], (join["members"], join["basis"])
        assert keys == want.get("keys", [])
        times = None
        for h, o in ((join["members"][0], join["members"][1]), (join["members"][1], join["members"][0])):
            record = _root(members[o])
            if h in views and record is not None:
                ht, rt = _time(views[h][1]), _time(record["timestamp"])
                times = {"history": h, "history_time": views[h][1], "record": o, "record_time": record["timestamp"],
                         "relation": "before" if ht < rt else "after" if ht > rt else "equal"}
        assert times == want.get("history_times")


def test_same_key_agreements_are_redundant_and_never_corroborate():
    for case in CASES:
        joins = case["container"]["extensions"]["composed/v1"].get("joins", [])
        for join, value in zip(joins, case["expect"].get("corroboration", [])):
            if join["basis"] == "same_key" and value["result"] != "not_applicable":
                assert value == {"members": join["members"], "result": "redundant", "reason": "same_key",
                                 "report": "redundant, not corroborating"}


MALFORMED_RULE = {
    "history-malformed-subject": lambda b: b["members"][2]["history"]["envelope"]["subject"] != {"full_history": None},
    "history-malformed-with-response": lambda b: "response" in b["members"][2],
    "history-malformed-with-bundle": lambda b: "bundle" in b["members"][2],
    "history-malformed-noncanonical-base64url": lambda b: any(
        base64.urlsafe_b64encode(_b64u(v)).rstrip(b"=").decode() != v
        for v in (b["members"][2]["history"]["anchor_checkpoint"], b["members"][2]["history"]["envelope"]["artifact"])),
    "history-malformed-same-key-pointer": lambda b: any(j["basis"] == "same_key" and "pointer" in j
                                                         for j in b["joins"]),
}


@pytest.mark.parametrize("case_id", sorted(MALFORMED_RULE))
def test_malformed_cases_break_the_rule_they_name(case_id):
    case = next(c for c in CASES if c["id"] == case_id)
    assert case["expect"] == {"status": "fail", "malformed": True}
    assert MALFORMED_RULE[case_id](case["container"]["extensions"]["composed/v1"])


def test_every_case_is_covered():
    malformed = {c["id"] for c in CASES if c["expect"].get("malformed")}
    assert malformed == set(MALFORMED_RULE)
    assert DATA["count"] == len(CASES) == 30
