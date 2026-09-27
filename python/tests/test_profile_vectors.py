# SPDX-License-Identifier: BSD-3-Clause
"""Buzz profile vectors (vectors/profiles/): freshness, digest re-derivation, and rule checks.

Go (go/canonical/profile_vectors_test.go) and TypeScript (ts/test/profile-vectors.test.ts)
assert the same committed files against the same labels and rule codes.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from agent_action_capsule.canonical import json_digest

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "profiles"
_SPEC = importlib.util.spec_from_file_location(
    "generate_profile_vectors", ROOT / "python" / "scripts" / "generate_profile_vectors.py"
)
assert _SPEC is not None and _SPEC.loader is not None
gen = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gen)

MANIFEST = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))
CASES = [c["file"] for c in MANIFEST["cases"]]
WITHDRAWN = ("outcome" + "_digest", "content" + "_digest", "gate" + "_digest")


def _load(rel: str) -> dict:
    return json.loads((VECTORS / rel).read_text(encoding="utf-8"))


def _at(record: dict, path: str):
    value = record
    for part in path.split("."):
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def test_committed_files_match_generator() -> None:
    rendered = gen.render()
    committed = {
        p.relative_to(VECTORS).as_posix(): p.read_text(encoding="utf-8")
        for p in VECTORS.rglob("*.json")
    }
    assert committed == rendered


@pytest.mark.parametrize("rel", CASES)
def test_digests_rederive_from_labels(rel: str) -> None:
    doc = _load(rel)
    for entry in doc["digest_labels"]:
        expected = entry.get("prefix", "") + json_digest({"label": entry["label"]})
        assert _at(doc["record"], entry["path"]) == expected, entry["path"]


@pytest.mark.parametrize("rel", CASES)
def test_rules_match_expectation(rel: str) -> None:
    doc = _load(rel)
    assert gen.check_record(doc["record"]) == doc["expect"]["violations"]
    assert doc["expect"]["valid"] is (not doc["expect"]["violations"])


@pytest.mark.parametrize("rel", [c["file"] for c in MANIFEST["cases"] if not c["valid"]])
def test_negative_rule_is_load_bearing(rel: str) -> None:
    """Disabling the documented rule makes the negative pass: it fails for that reason only."""
    doc = _load(rel)
    documented = frozenset(doc["expect"]["violations"])
    assert gen.check_record(doc["record"], disabled=documented) == []


def test_every_record_uses_the_uniform_subject() -> None:
    for rel in CASES:
        record = _load(rel)["record"]
        assert set(record["subject"]) == {"event_id", "semantic_digest"}
        roles = [c["role"] for c in record.get("payload_commitments", [])]
        assert "semantic_digest" not in roles


def test_no_withdrawn_per_profile_digest_names() -> None:
    for path in VECTORS.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            for name in WITHDRAWN:
                assert name not in text, (path, name)


def test_moderation_worked_vector_names_content_and_decision_body_digests() -> None:
    record = _load("buzz.moderation/v1/positive-semantic-judgment.json")["record"]
    roles = [c["role"] for c in record["payload_commitments"]]
    assert roles == ["moderated-content", "moderation-decision"]
    digests = {c["digest"] for c in record["payload_commitments"]}
    assert record["subject"]["semantic_digest"] not in digests
    assert record["subject"]["event_id"] not in digests
