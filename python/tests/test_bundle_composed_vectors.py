# SPDX-License-Identifier: BSD-3-Clause
"""The Evidence Bundle ``composed/v1`` vectors recompute from the files alone.

The composed-digest, join, closure and redundancy checks below are an
independent reading of the draft text: they use only the standard library
and the bytes in ``vectors/bundle/composed/``. Nothing is imported from the
generator. The base-profile checks (Capsule ID, Producer Envelope, per-member
completeness claims) use this repository's reference library.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from agent_action_capsule import compute_capsule_id
from agent_action_capsule.bundle import verify_bundle
from agent_action_capsule.verify import verify

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "bundle" / "composed"
GENERATOR = ROOT / "python" / "scripts" / "generate_bundle_composed_vectors.py"
KIND = "composed/v1"
HAND_WRITTEN = ("README.md",)

DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
CASES = {c["id"]: c for c in DATA["cases"]}


# ---------------------------------------------------------------------------
# An independent reading of the draft text
# ---------------------------------------------------------------------------


def _jcs(value: Any) -> bytes:
    # RFC 8785 for these vectors' value space (ASCII keys, no floats).
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pointer(doc: Any, pointer: str) -> Any:
    if not pointer.startswith("/"):
        return None
    cur = doc
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(cur, dict) or token not in cur:
            return None
        cur = cur[token]
    return cur


def _composed_input(block: dict) -> dict:
    """Composed Digest: the five members, arrays sorted, bodies and `missing` excluded."""
    member_fields = ("id", "observer", "request_digest", "outcome", "digest")
    join_fields = ("members", "basis", "pointer", "identifier_digest", "compare", "state")
    return {
        "kind": KIND,
        "members": sorted(({k: m[k] for k in member_fields if k in m} for m in block["members"]),
                          key=lambda m: m["id"]),
        "observers": sorted(({k: o[k] for k in ("id", "role", "custody_domain")} for o in block.get("observers", [])),
                            key=lambda o: o["id"]),
        "joins": sorted(({k: j[k] for k in join_fields if k in j} for j in block.get("joins", [])),
                        key=lambda j: (j["members"][0], j["members"][1], j["basis"], j.get("pointer", ""))),
        "not_requested": sorted(block.get("not_requested", [])),
    }


def _member_body(member: dict) -> Any:
    return member.get({"artifact": "bundle", "refusal": "refusal", "absence": "absence"}[member["outcome"]])


def _member_digest(member: dict) -> str:
    body = _member_body(member)
    if member["outcome"] == "artifact":
        body = {k: v for k, v in body.items() if k != "countersignatures"}
    return _sha(_jcs(body))


def _root(member: dict) -> dict | None:
    bundle = member.get("bundle")
    if not isinstance(bundle, dict):
        return None
    return next((r for r in bundle["records"] if r.get("capsule_id") == bundle["root"]), None)


def _derive(join: dict, by_id: dict[str, dict]) -> str | None:
    """Joins: derive the state, or None when a needed member body is not carried."""
    a, b = (by_id[i] for i in join["members"])
    granted = [m["outcome"] == "artifact" for m in (a, b)]
    if not any(granted):
        return "unjoined"
    if not all(granted):
        return "one_sided"
    ra, rb = _root(a), _root(b)
    if ra is None or rb is None:
        return None
    va, vb = _pointer(ra, join["pointer"]), _pointer(rb, join["pointer"])
    if join["basis"] == "pre_agreed_identifier":
        linked = all(isinstance(v, str) and _sha(v.encode("utf-8")) == join["identifier_digest"] for v in (va, vb))
    elif join["basis"] == "shared_artifact_digest":
        linked = isinstance(va, str) and va == vb
    else:
        return None
    if not linked:
        return "unjoined"
    same = all(_jcs(_pointer(ra, p)) == _jcs(_pointer(rb, p)) and _pointer(ra, p) is not None
               for p in join.get("compare", []))
    return "agree" if same else "mismatch"


def _block(case: dict) -> dict:
    return case["container"]["extensions"][KIND]


# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------


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
        assert _sha((VECTORS / name).read_bytes()) == digest, name
    top = dict(reversed(line.split("  ", 1)) for line in (ROOT / "vectors" / "SHA256SUMS").read_text().splitlines())
    for name in on_disk:
        assert top.get(f"bundle/composed/{name}") == _sha((VECTORS / name).read_bytes()), name


def test_three_cases():
    assert DATA["count"] == len(DATA["cases"]) == 3
    assert set(CASES) == {"agree", "one-member-missing", "same-custody-redundant"}


# ---------------------------------------------------------------------------
# The composed digest, from the vector file alone
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_composed_digest_recomputes_from_the_container_alone(case_id):
    case = CASES[case_id]
    block = _block(case)
    preimage = _jcs(_composed_input(block))
    assert preimage.decode("utf-8") == case["expect"]["canonical_preimage"]
    assert _sha(preimage) == block["composed_digest"] == case["expect"]["composed_digest"]


def test_withholding_a_member_body_does_not_change_the_composed_digest():
    assert CASES["one-member-missing"]["expect"]["composed_digest_equals_case"] == "agree"
    assert _block(CASES["one-member-missing"])["composed_digest"] == _block(CASES["agree"])["composed_digest"]


def test_any_declaration_change_changes_the_composed_digest():
    block = _block(CASES["agree"])
    base = _sha(_jcs(_composed_input(block)))
    for mutate in (
        lambda b: b["members"][0].__setitem__("outcome", "refusal"),
        lambda b: b["members"][0].__setitem__("digest", "0" * 64),
        lambda b: b["observers"][0].__setitem__("custody_domain", b["observers"][1]["custody_domain"]),
        lambda b: b["joins"][0].__setitem__("state", "mismatch"),
        lambda b: b.__setitem__("not_requested", ["responder-c"]),
    ):
        changed = json.loads(json.dumps(block))
        mutate(changed)
        assert _sha(_jcs(_composed_input(changed))) != base


# ---------------------------------------------------------------------------
# Members, closure, joins, redundancy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_members_and_composition_closure(case_id):
    case = CASES[case_id]
    block = _block(case)
    missing = set(block.get("missing", []))
    ids = [m["id"] for m in block["members"]]
    assert len(ids) == len(set(ids))
    assert missing <= set(ids)
    observer_ids = {o["id"] for o in block["observers"]}
    for member in block["members"]:
        want = case["expect"]["members"][member["id"]]
        assert member["outcome"] == want["outcome"]
        assert member["observer"] in observer_ids
        body = _member_body(member)
        if member["id"] in missing:
            assert body is None and want["body"] == "declared_missing" and want["digest"] == "not_shown"
            continue
        assert want["body"] == "carried"
        assert _member_digest(member) == member["digest"], member["id"]
        assert want["digest"] == "reproduced"
    status = "withheld" if missing else "pass"
    assert case["expect"]["composition_closure"]["status"] == status
    assert sorted(missing) == case["expect"]["composition_closure"]["missing"]


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_joins_are_rederived_not_trusted(case_id):
    case = CASES[case_id]
    block = _block(case)
    by_id = {m["id"]: m for m in block["members"]}
    assert len(block["joins"]) == len(case["expect"]["joins"])
    for join, want in zip(block["joins"], case["expect"]["joins"]):
        assert join["members"] == want["members"] == sorted(join["members"])
        derived = _derive(join, by_id)
        assert derived == want["derived"]
        assert join["state"] == want["declared"]
        assert want["result"] == ("not_derivable" if derived is None else
                                  "derived_matches" if derived == join["state"] else "join_state_mismatch")


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_same_custody_agreement_is_redundant_not_corroborating(case_id):
    case = CASES[case_id]
    block = _block(case)
    by_id = {m["id"]: m for m in block["members"]}
    custody = {o["id"]: o["custody_domain"] for o in block["observers"]}
    assert len(block["joins"]) == len(case["expect"]["corroboration"])
    for join, want in zip(block["joins"], case["expect"]["corroboration"]):
        if _derive(join, by_id) != "agree":
            assert want["result"] == "not_applicable"
            continue
        a, b = (by_id[i] for i in join["members"])
        same_custody = custody[a["observer"]] == custody[b["observer"]]
        same_key = _root(a)["key_id"] == _root(b)["key_id"]
        if same_custody or same_key:
            assert want["result"] == "redundant"
            assert want["report"] == "redundant, not corroborating"
        else:
            assert want == {"members": join["members"], "result": "corroborating", "qualifier": "custody_declared"}


# ---------------------------------------------------------------------------
# Base profile: every carried record verifies; member claims stay per member
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_carried_records_verify_and_member_claims_are_reported_per_member(case_id):
    case = CASES[case_id]
    container = case["container"]
    for record in container["records"]:
        assert compute_capsule_id(record) == record["capsule_id"]
        assert verify(record).ok
    outer = verify_bundle(container)
    assert [x.kind for x in outer.extensions] == [KIND]
    for member in _block(case)["members"]:
        want = case["expect"]["members"][member["id"]]["claims"]
        if "bundle" not in member:
            assert want is None
            continue
        record = _root(member)
        assert compute_capsule_id(record) == record["capsule_id"]
        assert verify(record).ok
        result = verify_bundle(member["bundle"])
        assert result.bundle_digest == member["digest"]
        assert {
            "graph_closure": result.graph_closure.status,
            "interval_coverage": result.interval_coverage.status,
            "per_record_membership": result.per_record_membership.status,
        } == want
