# SPDX-License-Identifier: BSD-3-Clause
"""The controller binding vectors for revocation against an attested time
(``vectors/controller-binding-v0-anchoring/``, CB §5.2 and §10.1).

Every case is run from its inputs alone, by the evaluator of ``test_controller_binding_v0_vectors``
(CB §3 to §7) with CB §5.2 added:

- each half's T is its ``issued_at``; its attested time is the ``attested_at`` of its earliest
  stamp that counts, or none;
- a stamp or anchor counts when it verifies, its attester is one the using profile accepts, the
  attester is neither bound key, and it is not dated after the evaluation time;
- a revocation statement that applies counts at a half with no attested time when its
  ``revoked_at`` <= T (CB §5), and at an attested half when, in addition, its earliest anchor is
  not later than the half's attested time.

All of it is compared with the case's whole ``expected`` block, which the generator states by hand.
The same evaluator is also run over ``vectors/controller-binding-v0/``, where no T is attested, and
must give every expected result there unchanged (CB §12: the change is additive). Nothing here
imports the generator. Defective evaluators, each breaking one rule of §5.2, must each disagree
with at least one case.
"""
from __future__ import annotations

import ast
import copy
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("cryptography")

import test_controller_binding_v0_vectors as cb  # noqa: E402
from test_controller_binding_v0_vectors import (  # noqa: E402
    SHOWN,
    ed25519_ok,
    is_time,
    jcs,
    parse,
    sha,
    without,
)

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "controller-binding-v0-anchoring"
GENERATOR = ROOT / "python" / "scripts" / "generate_controller_binding_v0_anchoring_vectors.py"
HAND_WRITTEN = ("README.md",)
DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
SPEC_TEXT = (ROOT / DATA["spec"]).read_text(encoding="utf-8")

# CB §10.1: the vectors' time attestation.
ATTESTATION_MEMBERS = {"attested_at", "attester", "subject", "sig"}


@dataclass(frozen=True)
class Anchoring:
    """Each field is one rule of CB §5.2; a defective evaluator replaces one."""

    stamps_read: bool = True               # a member is attested by a stamp that counts
    anchors_read: bool = True              # at an attested member, the anchor must be by the stamp
    revoked_at_still_checked: bool = True  # at an attested member, revoked_at <= its own T still holds
    earliest_anchor: bool = True           # the earliest anchor counts
    earliest_stamp: bool = True            # the earliest stamp gives the attested time
    at_or_before: bool = True              # anchor <= attested time counts, equality included
    attester_accepted: bool = True         # the attester is one the using profile accepts
    attester_not_bound: bool = True        # an attestation by a bound key is neither stamp nor anchor
    attestation_verifies: bool = True      # the attestation's signature verifies
    subject_matches: bool = True           # an anchor is over this statement
    not_after_e: bool = True               # an attestation dated after E does not count
    per_member: bool = True                # each member is attested or not on its own


SPEC = Anchoring()


def attestations(case: dict, name: str, r: dict, rules: Anchoring) -> list[dict]:
    """CB §5.2 and §10.1: the attestations of ``inputs[name]`` that count."""
    out = []
    for o in case["inputs"].get(name, []):
        a = parse(o["octets_text"])
        if not (isinstance(a, dict) and set(a) == ATTESTATION_MEMBERS and is_time(a["attested_at"])):
            continue
        if rules.not_after_e and a["attested_at"] > case["pins"]["evaluation_time"]:
            continue
        if rules.attester_accepted and a["attester"] not in case["pins"]["trust_policy"]["time_attesters"]:
            continue
        if rules.attester_not_bound and a["attester"] in r.get("keys", []):
            continue
        if rules.attestation_verifies and not ed25519_ok(a["attester"], a["sig"], jcs(without(a, "sig"))):
            continue
        out.append(a)
    return out


def members(case: dict, r: dict, rules: Anchoring) -> list[tuple[str, str | None, str | None]]:
    """Each half's T (its issued_at, CB §6.1), its attested time and the attester, or None
    (CB §5.2)."""
    stamps = attestations(case, "stamps", r, rules) if rules.stamps_read else []
    out = []
    for h in case["inputs"]["halves"]:
        mine = sorted((s["attested_at"], s["attester"]) for s in stamps if s["subject"] == sha(h["octets_text"].encode()))
        at, by = (mine[0] if rules.earliest_stamp else mine[-1]) if mine else (None, None)
        out.append((parse(h["octets_text"])["issued_at"], at, by))
    if not rules.per_member and any(at for _, at, _ in out):  # the defect: one stamp attests the pair
        stamped = next((at, by) for _, at, by in out if at)
        out = [(t, at or stamped[0], by or stamped[1]) for t, at, by in out]
    return out


def received(case: dict) -> list[Any]:
    """Every received statement: delivered, and the declared list's entries (CB §5.1)."""
    out = [parse(o["octets_text"]) for o in case["inputs"].get("revocations", [])]
    return out + [e for e in cb.list_entries(case) or [] if isinstance(e, dict)]


def first_anchor(s: dict, case: dict, r: dict, rules: Anchoring) -> str | None:
    """CB §5.2: the earliest anchor over SHA-256 of JCS of the statement, or None."""
    at = sorted(a["attested_at"] for a in attestations(case, "anchors", r, rules)
                if a["subject"] == sha(jcs(s)) or not rules.subject_matches)
    if not at:
        return None
    return at[0] if rules.earliest_anchor else at[-1]


def revocation(r: dict, case: dict, ms: list[tuple[str, str | None, str | None]],
               rules: Anchoring) -> tuple[str, str | None]:
    """CB §5.2 and §6.1: the status of ``controller_binding_revocation`` and the time the statement
    that counts is counted from."""
    for s in received(case):
        if not cb.revocation_applies(s, r, cb.SPEC):
            continue
        anchor = first_anchor(s, case, r, rules)
        for t, at, _ in ms:
            if at is None or not rules.anchors_read:  # §5 unchanged
                if s["revoked_at"] <= t:
                    return "FAIL", s["revoked_at"]
                continue
            dated = s["revoked_at"] <= t or not rules.revoked_at_still_checked
            anchored = anchor is not None and (anchor <= at if rules.at_or_before else anchor < at)
            if dated and anchored:
                return "FAIL", max(anchor, s["revoked_at"])
    if cb.declaration_counts(r, case, [t for t, _, _ in ms], cb.SPEC):
        return "PASS", None
    return "NOT_CHECKED", None


def evaluate(case: dict, rules: Anchoring = SPEC) -> dict:
    """``cb.evaluate`` with the revocation status taken from CB §5.2. Every other property is
    judged at each half's issued_at, as before."""
    r = parse(case["inputs"]["binding"]["octets_text"])
    ms = members(case, r, rules)
    ts = [t for t, _, _ in ms]
    out = cb.evaluate(case)
    b = out["binding"]
    props = b["properties"]
    counted_from = None
    if props["controller_binding_form"] == "PASS":
        props["controller_binding_revocation"], counted_from = revocation(r, case, ms, rules)
    b["applies"] = (b["binds_pair"] and all(props.get(p) == "PASS" for p in (
        "controller_binding_form", "controller_binding_signatures", "controller_binding_window"))
        and props.get("controller_binding_revocation") != "FAIL")
    if "revocation_list" in b:
        b["revocation_list"] = cb.list_report(r, case, ts, cb.SPEC)
    b["times"] = [{"t": t, "attested_at": at, "attested_by": by} for t, at, by in ms]
    b["revocation_counted_from"] = counted_from
    if out["issuer_independence"]["reason"] != "same key":  # CB §7 item 4: one key is FAIL whatever the binding
        status = "FAIL" if b["applies"] else "NOT_CHECKED"
        out["issuer_independence"] = {
            "status": status, "shown_as": SHOWN[status][0],
            "reason": f"controller binding {r['claim']} {cb.digest_of(r)}" if b["applies"] else None,
            "satisfied_becomes": {"r-corroborated": SHOWN[status][1]}}
    return out


def comparable(expected: dict) -> dict:
    e = copy.deepcopy(expected)
    e.pop("fails")
    return e


# ---------------------------------------------------------------------------
# The vectors
# ---------------------------------------------------------------------------


def test_corpus_shape_and_pins():
    assert DATA["count"] == len(CASES) == 18
    assert sha(DATA["contract"]["document_jcs"].encode()) == DATA["contract"]["contract_digest"]
    for case in CASES:
        assert case["pins"]["contract_digest"] == DATA["contract"]["contract_digest"]
        assert case["pins"]["verification_policy"]["online"] is False
        assert case["source"].startswith("derived: ")
        inputs = case["inputs"]
        for o in [*inputs["halves"], inputs["binding"], *inputs.get("revocations", []),
                  *inputs.get("stamps", []), *inputs.get("anchors", [])]:
            assert o["octets_text"].encode() == jcs(parse(o["octets_text"])), case["id"]


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_case(case):
    assert evaluate(case) == comparable(case["expected"])


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_named_property_fails(case):
    props = evaluate(case)["binding"]["properties"]
    assert {p for p, s in props.items() if s == "FAIL"} == set(case["expected"]["fails"])


@pytest.mark.parametrize("case", cb.CASES, ids=[c["id"] for c in cb.CASES])
def test_no_attested_t_leaves_every_controller_binding_v0_result_unchanged(case):
    """CB §5.2, §12: with no stamp, every T is a half's issued_at, and the result is the one
    vectors/controller-binding-v0/ pins."""
    got = evaluate(case)
    assert all(t["attested_by"] is None for t in got["binding"].pop("times"))
    got["binding"].pop("revocation_counted_from")  # vectors/controller-binding-v0 does not pin it
    assert got == cb.comparable(case["expected"])


def test_the_acceptance_pair():
    """The two cases the brief names: revoked_at before the stamp, attested after it, leaves the
    binding applying; attested before it, removes it."""
    by_id = {c["id"]: c for c in CASES}
    after, before = by_id["anchored-after-the-stamp"], by_id["anchored-before-the-stamp"]
    for c in (after, before):
        s = parse(c["inputs"]["revocations"][0]["octets_text"])
        stamp = parse(c["inputs"]["stamps"][0]["octets_text"])["attested_at"]
        assert s["revoked_at"] < stamp
    assert parse(after["inputs"]["anchors"][0]["octets_text"])["attested_at"] > stamp
    assert parse(before["inputs"]["anchors"][0]["octets_text"])["attested_at"] < stamp
    assert evaluate(after)["binding"]["applies"] is True
    assert evaluate(before)["binding"]["applies"] is False


def test_the_negatives_carry_a_valid_attestation_but_for_their_one_defect():
    """Each attestation negative fails for its named reason, not a broken signature elsewhere."""
    by_id = {c["id"]: c for c in CASES}
    attester = DATA["test_keys"]["keys"]["time-attester"]["public"]
    for cid in ("anchor-by-bound-key", "anchor-attester-not-accepted", "anchor-other-statement"):
        a = parse(by_id[cid]["inputs"]["anchors"][0]["octets_text"])
        assert ed25519_ok(a["attester"], a["sig"], jcs(without(a, "sig"))), cid
    forged = parse(by_id["anchor-forged"]["inputs"]["anchors"][0]["octets_text"])
    assert forged["attester"] == attester and not ed25519_ok(attester, forged["sig"], jcs(without(forged, "sig")))
    other = parse(by_id["anchor-other-statement"]["inputs"]["anchors"][0]["octets_text"])
    assert other["attester"] == attester and other["attested_at"] < "2026-10-15T00:05:00Z"


def test_spec_lists_every_case():
    section = SPEC_TEXT.split("### 10.1 ", 1)[1].split("\n## ", 1)[0]
    assert set(re.findall(r"^\| `([a-z0-9-]+)` \|", section, re.M)) == {c["id"] for c in CASES}


def test_spec_states_which_time_is_used():
    section = " ".join(SPEC_TEXT.split("### 5.2 ", 1)[1].split("\n## ", 1)[0].split())
    assert "no attested time: `revoked_at` ≤ T, as in §5, unchanged" in section
    assert "`revoked_at` ≤ T, as in §5, **and** its earliest anchor is not later than the member's attested time" in section
    assert "its attested time is the earliest `attested_at` among them" in section


# ---------------------------------------------------------------------------
# Negative checks: each defective evaluator must disagree with some case
# ---------------------------------------------------------------------------

DEFECTS = {
    "revoked_at alone counts at an attested member (CB §5 alone)": replace(SPEC, anchors_read=False),
    "stamps ignored": replace(SPEC, stamps_read=False),
    "at an attested member the anchor alone counts, whatever revoked_at": replace(SPEC, revoked_at_still_checked=False),
    "the latest anchor, not the earliest": replace(SPEC, earliest_anchor=False),
    "the latest stamp, not the earliest": replace(SPEC, earliest_stamp=False),
    "the anchor must be strictly before the stamp": replace(SPEC, at_or_before=False),
    "any attester": replace(SPEC, attester_accepted=False),
    "a bound key may attest": replace(SPEC, attester_not_bound=False),
    "attestation signature not checked": replace(SPEC, attestation_verifies=False),
    "an anchor over any statement": replace(SPEC, subject_matches=False),
    "an attestation dated after E counts": replace(SPEC, not_after_e=False),
    "one stamped member attests the pair": replace(SPEC, per_member=False),
}

# The one case each defect is caught by, at least.
CAUGHT_BY = {
    "revoked_at alone counts at an attested member (CB §5 alone)": "anchored-after-the-stamp",
    "stamps ignored": "not-anchored-stamped",
    "at an attested member the anchor alone counts, whatever revoked_at": "revoked-between-signing-and-stamp",
    "the latest anchor, not the earliest": "earliest-anchor-counts",
    "the latest stamp, not the earliest": "earliest-stamp-counts",
    "the anchor must be strictly before the stamp": "anchored-at-the-stamp",
    "any attester": "anchor-attester-not-accepted",
    "a bound key may attest": "anchor-by-bound-key",
    "attestation signature not checked": "anchor-forged",
    "an anchor over any statement": "anchor-other-statement",
    "an attestation dated after E counts": "stamp-after-evaluation-time",
    "one stamped member attests the pair": "one-half-stamped",
}


@pytest.mark.parametrize("name", list(DEFECTS))
def test_every_defective_evaluator_is_caught(name):
    rules = DEFECTS[name]
    caught = [c["id"] for c in CASES if evaluate(c, rules) != comparable(c["expected"])]
    assert CAUGHT_BY[name] in caught, (name, caught)


def test_bound_key_stamp_is_caught_by_its_own_case():
    """stamp-by-bound-key is what catches a bound key's stamp being taken as an attested T."""
    rules = DEFECTS["a bound key may attest"]
    case = next(c for c in CASES if c["id"] == "stamp-by-bound-key")
    assert evaluate(case, rules) != comparable(case["expected"])


def test_the_current_rule_fails_exactly_the_anchoring_cases():
    """An evaluator that counts every statement from revoked_at (CB §5 before §5.2, which every
    implementation in this repository follows) disagrees with exactly these cases."""
    rules = replace(SPEC, anchors_read=False)
    caught = sorted(c["id"] for c in CASES if evaluate(c, rules) != comparable(c["expected"]))
    assert caught == sorted(["anchored-after-the-stamp", "anchor-by-bound-key", "anchor-attester-not-accepted",
                             "anchor-forged", "anchor-other-statement", "complete-list-entry-not-anchored",
                             "not-anchored-stamped", "anchored-before-the-stamp", "anchored-at-the-stamp",
                             "earliest-anchor-counts", "earliest-stamp-counts", "complete-list-entry-anchored"])


# ---------------------------------------------------------------------------
# Reproducibility and registration
# ---------------------------------------------------------------------------


def _generate(out: Path) -> None:
    for name in HAND_WRITTEN:
        shutil.copyfile(VECTORS / name, out / name)
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(out)], check=True)


def _files(d: Path) -> list[str]:
    return sorted(p.relative_to(d).as_posix() for p in d.rglob("*") if p.is_file() and "__pycache__" not in p.parts)


def test_generator_is_deterministic_and_reproduces_every_file(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    _generate(a)
    _generate(b)
    committed = _files(VECTORS)
    assert committed == _files(a) == _files(b)
    for name in committed:
        assert (a / name).read_bytes() == (b / name).read_bytes() == (VECTORS / name).read_bytes(), name


def test_sha256sums_and_registration():
    listed = dict(reversed(line.split("  ", 1)) for line in (VECTORS / "SHA256SUMS").read_text().splitlines())
    assert set(listed) == set(_files(VECTORS)) - {"SHA256SUMS"}
    for name, digest in listed.items():
        assert sha((VECTORS / name).read_bytes()) == digest, name
    top = dict(reversed(line.split("  ", 1)) for line in (ROOT / "vectors" / "SHA256SUMS").read_text().splitlines())
    for name in set(_files(VECTORS)) - {"SHA256SUMS"}:
        assert top[f"controller-binding-v0-anchoring/{name}"] == sha((VECTORS / name).read_bytes()), name
    corpora = json.loads((ROOT / "vectors" / "manifest.json").read_text())["corpora"]
    assert corpora["controller_binding_v0_anchoring"] == "controller-binding-v0-anchoring/manifest.json"
    assert "generate_controller_binding_v0_anchoring_vectors.py" in (
        ROOT / "python" / "scripts" / "generate_all_vectors.py").read_text()


def test_does_not_import_the_generator():
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    modules = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    modules += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not [m for m in modules if m.startswith("generate_")]
