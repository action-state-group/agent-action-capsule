# SPDX-License-Identifier: BSD-3-Clause
"""The salted JSON-DIGEST commitment vectors (informative) check under this library.

The opening check is the reference library's ``json_digest``, the same
function a Disclosure Envelope verifier uses for DE-3: recompute JSON-DIGEST of
the disclosed ``{"nonce", "text"}`` object and compare. Each committed
``opening_jcs`` is also checked against the library's ``jcs``, and every
commitment is recomputed once more with ``hashlib`` alone from that string.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable

import pytest

from agent_action_capsule.canonical import jcs, json_digest

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "salted-digest-commitment"
GENERATOR = ROOT / "python" / "scripts" / "generate_salted_digest_commitment_vectors.py"
HAND_WRITTEN = ("README.md",)
NONCE = re.compile(r"^[0-9a-f]{64}$")

DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
POSITIVE = {c["id"]: c for c in DATA["positive"]}

Opens = Callable[[dict, str], bool]


def opens(opening: dict, commitment: str) -> bool:
    """DE-3 applied to an opening: recompute JSON-DIGEST and compare."""
    return json_digest(opening) == commitment


def failures(check: Opens) -> list[str]:
    """Every way the corpus disagrees with ``check``; empty when the check is right."""
    found = []
    for case in DATA["positive"]:
        if not check(case["opening"], case["commitment"]):
            found.append(f"{case['id']} did not open")
    for case in DATA["negative"]:
        if case["commitment"] != POSITIVE[case["against"]]["commitment"]:
            found.append(f"{case['id']} does not carry the commitment of {case['against']}")
        if check(case["opening"], case["commitment"]):
            found.append(f"{case['id']} opened {case['against']}")
    eq = DATA["equality"]
    opening = {"nonce": eq["nonce"], "text": eq["text"]}
    if not (eq["equal"] and eq["first"] == eq["second"] and check(opening, eq["first"])):
        found.append("equality case does not hold")
    return found


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
        assert hashlib.sha256((VECTORS / name).read_bytes()).hexdigest() == digest, name
    top = dict(reversed(line.split("  ", 1)) for line in (ROOT / "vectors" / "SHA256SUMS").read_text().splitlines())
    for name in on_disk:
        assert top.get(f"salted-digest-commitment/{name}") == listed[name], name


def test_corpus_shape_and_registration():
    assert DATA["identifier"] == "sha256-jcs-nonce256"
    assert DATA["status"].startswith("INFORMATIVE")
    assert DATA["count"] == len(DATA["positive"]) + len(DATA["negative"]) + 1 == 9
    assert (ROOT / DATA["note"]).is_file()
    corpora = json.loads((ROOT / "vectors" / "manifest.json").read_text(encoding="utf-8"))["corpora"]
    assert corpora["salted_digest_commitment"] == "salted-digest-commitment/manifest.json"


# ---------------------------------------------------------------------------
# The opening check
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", DATA["positive"] + DATA["negative"], ids=lambda c: c["id"])
def test_opening_jcs_and_commitment_recompute(case):
    assert jcs(case["opening"]).decode("utf-8") == case["opening_jcs"]
    recomputed = hashlib.sha256(case["opening_jcs"].encode("utf-8")).hexdigest()
    assert json_digest(case["opening"]) == recomputed
    assert recomputed == case.get("recomputed", case["commitment"])


@pytest.mark.parametrize("case", DATA["positive"], ids=lambda c: c["id"])
def test_positive_nonce_is_256_bit_lowercase_hex(case):
    assert NONCE.match(case["opening"]["nonce"])
    assert NONCE.match(case["commitment"])


def test_corpus_holds_under_the_reference_check():
    assert failures(opens) == []


# Each mutant is a plausible wrong opening check; the corpus must catch every one.
_KNOWN_NONCES = {c["opening"]["nonce"] for c in DATA["positive"]}
MUTANTS: dict[str, Opens] = {
    "always-true": lambda o, cm: True,
    "text-only": lambda o, cm: json_digest(o["text"]) == cm,
    "any-known-nonce": lambda o, cm: any(json_digest({"nonce": n, "text": o["text"]}) == cm for n in _KNOWN_NONCES),
    "case-folds-nonce": lambda o, cm: json_digest({"nonce": o["nonce"].lower(), "text": o["text"]}) == cm,
    "strips-text": lambda o, cm: json_digest({"nonce": o["nonce"], "text": o["text"].strip()}) == cm,
    "ascii-escaped-jcs": lambda o, cm: hashlib.sha256(
        json.dumps(o, sort_keys=True, separators=(",", ":")).encode()).hexdigest() == cm,
    "array-not-object": lambda o, cm: json_digest([o["nonce"], o["text"]]) == cm,
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_corpus_rejects_mutant_check(name):
    assert failures(MUTANTS[name]), f"mutant {name} survived the corpus"
