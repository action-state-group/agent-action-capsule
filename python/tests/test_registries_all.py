# SPDX-License-Identifier: BSD-3-Clause
"""Every registry in REGISTRY.md is parsed and importable.

Pins the full set of registries (by name and by section), their exact values,
the exclusion of ``### Provisional`` subsections, the shipped
``data/registries.json`` against a fresh parse, and the older-snapshot
behaviour: a registry a snapshot predates is ABSENT from the result, never an
empty set (the ``citation_purpose`` regression).
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from agent_action_capsule import registries as r
from agent_action_capsule.registries import (
    ALL_REGISTRY_NAMES,
    CHAIN_RELATIONS,
    CITATION_PURPOSES,
    DISCLOSURE_ELIGIBLE_FIELDS,
    EPISTEMIC_TYPES,
    LINK_TYPES,
    load_registries,
    parse_registry_tables,
    registries_document,
    values,
)

_ROOT = Path(__file__).resolve().parents[2]
_SPEC = _ROOT / "spec" / "REGISTRY.md"
_JSON = _ROOT / "python" / "agent_action_capsule" / "data" / "registries.json"
_GO_JSON = _ROOT / "go" / "registries" / "data" / "registries.json"

# Every numbered section of REGISTRY.md, by section number -> registry names.
EXPECTED_SECTIONS = {
    "1": ["verdict_class"],
    "2": ["disposition.decision"],
    "3": ["effect.type"],
    "4": ["irreversibility_class"],
    "5": ["effect_attestation"],
    "6": ["chain.relation"],
    "7": ["sel_disc.reserved_member"],
    "8": ["domain"],
    "9": ["provenance"],
    "10": ["disclosure_envelope.reserved_member", "disclosure_envelope.disclosable_field"],
    "11": ["citation_purpose"],
    "12": ["provenance_mode"],
    "13": ["evidence_bundle.kind"],
    "14": ["evidence_bundle.extension_kind"],
    "15": ["evidence_bundle.countersignature_type"],
    "16": ["evidence_request.derivation"],
    "17": ["epistemic_type"],
    "18": ["link_type"],
}

EXPECTED_NEW = {
    "sel_disc.reserved_member": ("_sd_alg", "_sd"),
    "domain": ("action", "memory", "reasoning"),
    "provenance": ("gate", "runtime", "collector"),
    "disclosure_envelope.reserved_member": ("capsule", "disclosures"),
    "disclosure_envelope.disclosable_field": ("agent_input", "agent_output"),
    "provenance_mode": ("contemporaneous", "backfilled"),
    "evidence_bundle.kind": ("evidence-bundle/v2",),
    "evidence_bundle.extension_kind": ("producer-key/v1", "composed/v1"),
    "evidence_bundle.countersignature_type": ("cose-sign1", "countersign/v1"),
    "evidence_request.derivation": ("history_card/1",),
    "epistemic_type": (
        "observed_event", "system_of_record_fact", "producer_claim", "human_report",
        "semantic_judgment", "derived_metric", "adjudication", "obligation_reference",
    ),
    "link_type": ("cites", "adjudicates", "supersedes", "acknowledges", "rebuts", "closes"),
}

# Values held for ratification under "### Provisional" subsections.
PROVISIONAL = {
    "disclosure_envelope.disclosable_field": {'agent_input_version: "1"'},
    "evidence_bundle.extension_kind": {"disclosure-policy-decisions/v1", "sd-jwt-issuers/v1"},
    "evidence_request.derivation": {"minimum_necessary_report/1"},
}


def _spec_md() -> str:
    if _SPEC.exists():
        return _SPEC.read_text(encoding="utf-8")
    return r._bundled_registry_md().read_text(encoding="utf-8")


def test_every_section_is_parsed():
    tables = parse_registry_tables(_spec_md())
    by_section: dict[str, list[str]] = {}
    for name, t in tables.items():
        by_section.setdefault(t.section, []).append(name)
    assert by_section == EXPECTED_SECTIONS
    assert list(tables) == list(ALL_REGISTRY_NAMES)
    assert len(ALL_REGISTRY_NAMES) == 19  # 18 sections; §10 holds two tables


def test_every_numbered_heading_is_mapped():
    """A new "## N. ..." section in REGISTRY.md must be mapped to a registry
    name, or this fails rather than leaving it unparsed."""
    headings = [ln for ln in _spec_md().splitlines() if r._HEADER_RE.match(ln)]
    assert len(headings) == len(EXPECTED_SECTIONS)
    for ln in headings:
        assert r._section_key_title(r._HEADER_RE.match(ln).group(1)) is not None, ln


def test_values_of_previously_unparsed_registries():
    for name, expected in EXPECTED_NEW.items():
        assert r.ordered_values(name) == expected, name
        assert values(name) == frozenset(expected)


def test_named_constants():
    assert EPISTEMIC_TYPES == frozenset(EXPECTED_NEW["epistemic_type"])
    assert LINK_TYPES == frozenset(EXPECTED_NEW["link_type"])
    assert CHAIN_RELATIONS == {"follows", "confirms", "supersedes", "epoch_opens", "duplicates"}
    assert CITATION_PURPOSES == {
        "acted_on", "responds_to", "ran_under", "corroborates_source_time",
        "counterparty_half", "counterparty_inclusion",
    }


def test_provisional_subsections_not_seeded():
    tables = parse_registry_tables(_spec_md())
    for name, held in PROVISIONAL.items():
        assert not (set(tables[name].values) & held), name


def test_provisional_subsection_ends_at_next_heading():
    md = """## 13. Evidence Bundle kind

| Value | Semantics |
|---|---|
| `a/v1` | x |

### Provisional: held

| Value | Semantics |
|---|---|
| `held/v1` | y |

## 14. Evidence Bundle extension kind

| Value | Semantics |
|---|---|
| `b/v1` | z |
"""
    tables = parse_registry_tables(md)
    assert tables["evidence_bundle.kind"].values == ("a/v1",)
    assert tables["evidence_bundle.extension_kind"].values == ("b/v1",)


def test_disclosure_eligible_fields_match_registry():
    assert set(DISCLOSURE_ELIGIBLE_FIELDS) == values("disclosure_envelope.disclosable_field")


def test_defined_in_provenance():
    tables = parse_registry_tables(_spec_md())
    assert tables["epistemic_type"].defined_in == "draft-mih-agent-evidence-layer"
    assert tables["link_type"].defined_in == "draft-mih-agent-evidence-layer"
    assert tables["chain.relation"].defined_in == "draft-mih-scitt-agent-action-capsule"


def test_unknown_registry_name_raises():
    with pytest.raises(KeyError):
        values("no_such_registry")


def test_heading_present_but_empty_is_empty_not_absent():
    tables = parse_registry_tables("## 14. Evidence Bundle extension kind\n\nNo initial extension kind is defined.\n")
    assert tables["evidence_bundle.extension_kind"].values == ()


def test_core_registry_parsing_empty_raises(tmp_path: Path):
    p = tmp_path / "REGISTRY.md"
    p.write_text(PRE_CITATION_PURPOSE.replace("1. `two_way`", "Prose only."), encoding="utf-8")
    with pytest.raises(ValueError, match="irreversibility_class"):
        load_registries(path=p)


# ---- registries.json -------------------------------------------------------
def test_shipped_json_matches_parse():
    shipped = json.loads(_JSON.read_text(encoding="utf-8"))
    assert shipped == registries_document()
    assert list(shipped["registries"]) == list(ALL_REGISTRY_NAMES)


@pytest.mark.skipif(not _SPEC.exists(), reason="source tree only")
def test_json_generator_check_is_clean():
    script = _ROOT / "python" / "scripts" / "generate_registries_json.py"
    proc = subprocess.run(["python3", str(script), "--check"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


@pytest.mark.skipif(not _GO_JSON.exists(), reason="Go module not present")
def test_go_embedded_json_is_the_same_file():
    assert _GO_JSON.read_bytes() == _JSON.read_bytes()


# ---- Older snapshots: absent, never emptied --------------------------------
def _git_snapshot(sha: str) -> str | None:
    proc = subprocess.run(
        ["git", "-C", str(_ROOT), "show", f"{sha}:spec/REGISTRY.md"],
        capture_output=True, text=True,
    )
    return proc.stdout if proc.returncode == 0 else None


# A pre-references snapshot: the six core registries and §7-§10, no §11.
PRE_CITATION_PURPOSE = """## 1. `verdict_class`

| Value | Semantics |
|---|---|
| `executed` | ran |

## 2. `disposition.decision`
Initial contents: `accept`, `reject`.

## 3. `effect.type`
Initial contents: `write_order`.

## 4. `irreversibility_class`

1. `two_way`

## 5. `effect_attestation`

| Value | Semantics |
|---|---|
| `gate_executed` | observed |

## 6. `chain.relation`

| Value | Semantics |
|---|---|
| `confirms` | non-terminal |

## No registry
"""


def test_older_snapshot_omits_citation_purpose_instead_of_emptying(tmp_path: Path):
    """Regression: an older REGISTRY.md that predates citation_purpose used to
    load as ``citation_purpose: frozenset()`` -- a registry that exists with no
    values. It is now absent from the result, so a caller can tell the snapshot
    predates the registry; the verifier still treats such values as unknown."""
    p = tmp_path / "REGISTRY.md"
    p.write_text(PRE_CITATION_PURPOSE, encoding="utf-8")
    regs = load_registries(path=p)
    assert "citation_purpose" not in regs
    assert "epistemic_type" not in regs
    assert regs["chain.relation"] == {"confirms"}


def test_older_snapshot_still_requires_core_registries(tmp_path: Path):
    p = tmp_path / "REGISTRY.md"
    p.write_text(PRE_CITATION_PURPOSE.replace("## 6. `chain.relation`", "## 6. `chain.relations`"), encoding="utf-8")
    with pytest.raises(ValueError, match="chain.relation"):
        load_registries(path=p)


@pytest.mark.parametrize("sha,has_cp", [("51e8994", False), ("676cd51", True), ("3153e94", True), ("7204edc", True)])
def test_real_historical_snapshots(tmp_path: Path, sha: str, has_cp: bool):
    md = _git_snapshot(sha)
    if md is None:
        pytest.skip("git history unavailable")
    p = tmp_path / "REGISTRY.md"
    p.write_text(md, encoding="utf-8")
    regs = load_registries(path=p)
    assert ("citation_purpose" in regs) is has_cp
    if has_cp:
        assert regs["citation_purpose"], "present registry must not be empty"
    assert "epistemic_type" not in regs


