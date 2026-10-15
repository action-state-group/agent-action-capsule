# SPDX-License-Identifier: BSD-3-Clause
"""Registry conformance: the checker and vectors/registry-conformance/."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from agent_action_capsule import compute_capsule_id, verify
from agent_action_capsule.registries import REGISTRY_NAMES, load_registries
from agent_action_capsule.registry_conformance import (
    CAPSULE_FIELDS,
    check_capsule,
    is_conformant,
    legacy_aliases,
    load_axes,
    main,
)

VECTORS = Path(__file__).resolve().parents[2] / "vectors" / "registry-conformance"
MANIFEST = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
CASES = [case["name"] for case in MANIFEST["cases"]]


def _load(name: str, file: str) -> dict:
    return json.loads((VECTORS / name / file).read_text(encoding="utf-8"))


def test_axes_agree_with_the_verifier_registries():
    """One value set, two readers: the conformance axes and the registries the
    verifier loads must be the same sets, so the two cannot disagree on what is
    registered."""
    axes, registries = load_axes(), load_registries()
    for name in REGISTRY_NAMES:
        assert axes[name] == registries[name], name
    assert {axis for _, axis in CAPSULE_FIELDS} <= set(axes)


def test_legacy_aliases_stay_unregistered():
    """§6 aliases are read-only spellings: none is registered, each maps to a
    registered value."""
    relations = load_axes()["chain.relation"]
    aliases = legacy_aliases()
    assert set(aliases) == {"sequence", "resolves", "escalates", "adjudicates", "assesses"}
    for alias, target in aliases.items():
        assert alias not in relations, alias
        assert target in relations, target


def test_an_unregistered_value_fails():
    findings = check_capsule({"disposition": {"decision": "approve"}})
    assert [f.status for f in findings] == ["unregistered"]
    assert not is_conformant(findings)


def test_a_non_string_value_is_unregistered():
    findings = check_capsule({"domain": 1, "chain": {"relation": {"follows": True}}})
    assert [f.status for f in findings] == ["unregistered", "unregistered"]


def test_an_absent_field_produces_no_finding():
    assert check_capsule({}) == []


def test_supersedes_is_matched_by_field_not_by_string():
    """`supersedes` is registered on chain.relation and on the §18 link type;
    carried as a citation_purpose it is registered on neither that axis."""
    ok = check_capsule({"chain": {"relation": "supersedes"}})
    wrong = check_capsule({"references": [{"citation_purpose": "supersedes"}]})
    assert [f.status for f in ok] == ["registered"]
    assert [f.status for f in wrong] == ["cross_axis"]
    assert wrong[0].registered_on == ("Evidence Layer link type", "chain.relation")


def test_manifest_lists_every_case_directory():
    on_disk = sorted(p.name for p in VECTORS.iterdir() if p.is_dir())
    assert sorted(CASES) == on_disk
    assert MANIFEST["count"] == len(CASES)


def test_sha256sums_cover_every_file():
    listed = dict(reversed(line.split("  ", 1)) for line in (VECTORS / "SHA256SUMS").read_text().splitlines())
    on_disk = {p.relative_to(VECTORS).as_posix() for p in VECTORS.rglob("*") if p.is_file()} - {"SHA256SUMS"}
    assert set(listed) == on_disk
    for name, digest in listed.items():
        assert hashlib.sha256((VECTORS / name).read_bytes()).hexdigest() == digest, name


@pytest.mark.parametrize("name", CASES)
def test_vector(name):
    capsule, expected = _load(name, "input.json"), _load(name, "expected.json")
    assert compute_capsule_id({k: v for k, v in capsule.items() if k != "capsule_id"}) == capsule["capsule_id"]
    findings = check_capsule(capsule)
    assert [f.as_dict() for f in findings] == expected["findings"]
    assert is_conformant(findings) is expected["conformant"]
    assert expected["conformant"] is name.startswith("pos-")
    assert verify(copy.deepcopy(capsule)).ok is expected["verify_ok"]


@pytest.mark.parametrize("name", [n for n in CASES if n.startswith("neg-")])
def test_negative_changes_one_value_from_its_twin(name):
    """Each negative differs from its positive twin in exactly one
    registry-governed value, so that value alone decides the result."""
    axis = name.removeprefix("neg-").removesuffix("-unregistered")
    twin = f"pos-{axis}-registered"
    if twin not in CASES:
        twin = "pos-all-fields-registered"
    neg = {f["path"]: f["value"] for f in _load(name, "expected.json")["findings"]}
    pos = {f["path"]: f["value"] for f in _load(twin, "expected.json")["findings"]}
    assert neg.keys() == pos.keys()
    changed = [path for path in neg if neg[path] != pos[path]]
    assert len(changed) == 1, (name, twin, changed)
    neg_input, pos_input = _load(name, "input.json"), _load(twin, "input.json")
    neg_input.pop("capsule_id"), pos_input.pop("capsule_id")
    assert neg_input != pos_input


def test_verify_accepts_what_conformance_rejects():
    """The gap the set exists to show: a wrong token is silent at verify by
    design, except where a closed enum or a type error catches it first."""
    silent = [n for n in CASES if n.startswith("neg-") and _load(n, "expected.json")["verify_ok"]]
    assert sorted(set(n for n in CASES if n.startswith("neg-")) - set(silent)) == [
        "neg-provenance-mode-unregistered",
        "neg-verdict-class-not-a-string",
    ]


def test_cli_exit_codes(capsys):
    assert main([str(VECTORS / "pos-all-fields-registered" / "input.json")]) == 0
    assert main([str(VECTORS / "neg-disposition-decision-cross-axis-verdict-class" / "input.json")]) == 1
    assert "cross_axis" in capsys.readouterr().out
    assert main([]) == 2
