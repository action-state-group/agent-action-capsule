# SPDX-License-Identifier: BSD-3-Clause
"""``vectors/bundle/composed-history/``: History members in ``composed/v1``.

The composed digest is recomputed from the vector file alone (standard
library only). Every case is then verified with the reference library,
:func:`agent_action_capsule.composed.verify_composed`, and each expected
result in the file is compared with what it reports.
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

from agent_action_capsule.composed import (
    ComposedOptions,
    composed_digest_preimage,
    evidence_interop_signature,
    verify_composed,
)

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "bundle" / "composed-history"
GENERATOR = ROOT / "python" / "scripts" / "generate_bundle_composed_history_vectors.py"
KIND = "composed/v1"
HAND_WRITTEN = ("README.md",)

DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
CASES = {c["id"]: c for c in DATA["cases"]}


def _jcs(value: Any) -> bytes:
    # RFC 8785 for these vectors' value space (ASCII keys, no floats).
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _block(case: dict) -> dict:
    return case["container"]["extensions"][KIND]


def _composed_input(block: dict) -> dict:
    """Composed Digest (-03): each member's five declarations plus `form` when carried."""
    member_fields = ("id", "observer", "request_digest", "outcome", "digest", "form")
    join_fields = ("members", "basis", "pointer", "identifier_digest", "compare", "state")
    return {
        "kind": KIND,
        "members": sorted(({k: m[k] for k in member_fields if k in m} for m in block["members"]),
                          key=lambda m: m["id"]),
        "observers": sorted(({k: o[k] for k in ("id", "role", "custody_domain")} for o in block["observers"]),
                            key=lambda o: o["id"]),
        "joins": sorted(({k: j[k] for k in join_fields if k in j} for j in block.get("joins", [])),
                        key=lambda j: (j["members"][0], j["members"][1], j["basis"], "pointer" in j,
                                       j.get("pointer", ""))),
        "not_requested": sorted(block.get("not_requested", [])),
    }


def _options(case: dict) -> ComposedOptions:
    named = case["options"].get("history_signature")
    assert named in (None, "evidence-interop/0")
    return ComposedOptions(history_signature=evidence_interop_signature if named else None)


# ---------------------------------------------------------------------------
# The files
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
        assert top.get(f"bundle/composed-history/{name}") == _sha((VECTORS / name).read_bytes()), name


def test_thirty_cases():
    assert DATA["count"] == len(DATA["cases"]) == 30


@pytest.mark.parametrize("case_id", sorted(c for c in CASES if not CASES[c]["expect"].get("malformed")))
def test_composed_digest_recomputes_from_the_container_alone(case_id):
    case = CASES[case_id]
    preimage = _jcs(_composed_input(_block(case)))
    assert preimage.decode("utf-8") == case["expect"]["canonical_preimage"]
    assert _sha(preimage) == _block(case)["composed_digest"] == case["expect"]["composed_digest"]


def test_withholding_a_history_does_not_change_the_composed_digest():
    assert CASES["history-member-missing"]["expect"]["composed_digest_equals_case"] == "history-staple"
    assert _block(CASES["history-member-missing"])["composed_digest"] == _block(CASES["history-staple"])["composed_digest"]


def test_form_is_in_the_library_composed_digest():
    block = json.loads(json.dumps(_block(CASES["history-staple"])))
    assert composed_digest_preimage(block) == CASES["history-staple"]["expect"]["canonical_preimage"].encode()
    assert b'"form":"history"' in composed_digest_preimage(block)


def test_history_member_digest_is_the_answer_as_carried():
    for member in _block(CASES["history-staple"])["members"]:
        if member.get("form") == "history":
            assert member["digest"] == _sha(_jcs(member["history"]))
            # The anchor checkpoint is bound by the signed anchor digest, not by `digest`.
            assert "anchor_checkpoint" not in member["history"]


# ---------------------------------------------------------------------------
# The reference library against every expected result
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_library_matches_the_vector(case_id):
    case = CASES[case_id]
    expect = case["expect"]
    got = verify_composed(_block(case), _options(case))
    assert got.status == expect["status"]
    assert got.findings == expect["findings"]
    if expect.get("malformed"):
        assert got.malformed
        return
    assert got.composed_digest.recomputed == expect["composed_digest"]
    assert got.composed_digest.matches
    members = {m.id: m for m in got.members}
    assert set(members) == set(expect["members"])
    for member_id, want in expect["members"].items():
        m = members[member_id]
        assert (m.outcome, m.body, m.digest) == (want["outcome"], want["body"], want["digest"]), member_id
        if "form" in want:
            assert m.form == want["form"], member_id
        if want.get("form") == "history" and want["body"] == "carried":
            assert m.history_signature == want["history_signature"], member_id
            assert m.anchor_checkpoint == want["anchor_checkpoint"], member_id
            assert m.anchor_time == want["anchor_time"], member_id
            assert m.findings == want["findings"], member_id
        if "claims" in want:
            claims = {
                "graph_closure": m.bundle.graph_closure.status,
                "interval_coverage": m.bundle.interval_coverage.status,
                "per_record_membership": m.bundle.per_record_membership.status,
            }
            assert claims == want["claims"], member_id
    closure = expect["composition_closure"]
    assert (got.composition_closure.status, got.composition_closure.missing) == (closure["status"], closure["missing"])
    assert [
        {"members": list(j.members), "declared": j.declared, "derived": j.derived, "result": j.result,
         "findings": j.findings}
        for j in got.joins
    ] == expect["joins"]
    for c, want in zip(got.corroboration, expect["corroboration"]):
        assert list(c.members) == want["members"]
        assert c.result == want["result"]
        if "reasons" in want:
            assert c.reasons == want["reasons"]
            assert c.report == "redundant, not corroborating"
        if "qualifier" in want:
            assert c.qualifier == want["qualifier"]
    assert len(got.corroboration) == len(expect["corroboration"])
    assert got.related_histories == expect["related_histories"]


def test_a_history_never_corroborates_its_own_half():
    got = verify_composed(_block(CASES["history-staple"]), _options(CASES["history-staple"]))
    for c in got.corroboration:
        if "history-a" in c.members or "history-b" in c.members:
            assert c.result == "redundant" and "same_key" in c.reasons


def test_only_a_pre_agreed_identifier_link_relates_two_histories():
    other = verify_composed(_block(CASES["history-halves-linked-other-basis"]),
                            _options(CASES["history-halves-linked-other-basis"]))
    assert other.related_histories == []
    shared = verify_composed(_block(CASES["history-related-through-a-shared-field"]),
                             _options(CASES["history-related-through-a-shared-field"]))
    assert [r["pointer"] for r in shared.related_histories] == ["/spec_version"]


def test_carrying_two_histories_relates_nothing():
    # The deal join is unjoined: each History agrees with its own half, yet the
    # two Histories are not related (HF §4.7: never by being shown together).
    got = verify_composed(_block(CASES["history-deal-unjoined"]), _options(CASES["history-deal-unjoined"]))
    assert [j.derived for j in got.joins] == ["unjoined", "agree", "agree"]
    assert got.related_histories == []
