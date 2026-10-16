# SPDX-License-Identifier: BSD-3-Clause
"""The CLL material encoders against ``vectors/cll-material``, and their refusals.

Each case's octets come from the generator's own MMR code, not from this
library; Go's and Rust's encoders are checked against the same file.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agent_action_capsule import evidence_request as er

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "cll-material"
GENERATOR = ROOT / "python" / "scripts" / "generate_cll_material_vectors.py"

DATA = json.loads((VECTORS / "cases.json").read_text(encoding="utf-8"))
INCLUSION = [c for c in DATA["cases"] if c["kind"] == "cll-inclusion-proof"]
CONSISTENCY = [c for c in DATA["cases"] if c["kind"] == "cll-consistency-proof"]


def _nodes(hexes):
    return [bytes.fromhex(h) for h in hexes]


def test_corpus_shape():
    assert DATA["count"] == len(DATA["cases"]) == 184
    assert len(INCLUSION) == 92 and len(CONSISTENCY) == 92
    for case in DATA["cases"]:
        octets = bytes.fromhex(case["expected"]["octets_hex"])
        assert hashlib.sha256(octets).hexdigest() == case["expected"]["sha256"]


def test_corpus_regenerates_byte_for_byte(tmp_path):
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(tmp_path)], check=True)
    for name in ("cases.json", "manifest.json"):
        assert (tmp_path / name).read_bytes() == (VECTORS / name).read_bytes(), name


@pytest.mark.parametrize("case", INCLUSION, ids=lambda c: c["id"])
def test_inclusion_encoding(case):
    inputs, ctx = case["inputs"], case["context"]
    octets = er.encode_cll_inclusion_proof(inputs["leaf"], _nodes(inputs["path"]))
    assert octets.hex() == case["expected"]["octets_hex"]
    er.verify_cll_inclusion(_nodes(ctx["peaks"]), bytes.fromhex(ctx["entry"]), octets)


@pytest.mark.parametrize("case", CONSISTENCY, ids=lambda c: c["id"])
def test_consistency_encoding(case):
    i = case["inputs"]
    old_peaks, new_peaks = _nodes(i["old_peaks"]), _nodes(i["new_peaks"])
    octets = er.encode_cll_consistency_proof(i["old_size"], i["new_size"], old_peaks,
                                             [_nodes(p) for p in i["paths"]], new_peaks)
    assert octets.hex() == case["expected"]["octets_hex"]
    er.verify_cll_consistency(old_peaks, new_peaks, octets)


def test_worked_example_digests_are_the_profiles():
    by_id = {c["id"]: c for c in DATA["cases"]}
    assert by_id["worked-example-inclusion"]["expected"]["sha256"] == \
        "013ac5a3bdff9cf62a3ea2816b3cd197151930f6dd49d67d9286f12c3c47527a"
    assert by_id["worked-example-consistency"]["expected"]["sha256"] == \
        "06550cca75319242ea40e7f3fd9ff0b8e5e3bfa8a06122f678578a57cb4bdc71"


NODE = b"\x11" * 32


@pytest.mark.parametrize("leaf, path", [
    (-1, []),                      # not an unsigned integer
    (True, []),                    # a boolean is not a leaf number
    (1 << 53, []),                 # node index beyond 2^53 - 1
    (0, [NODE] * 53),              # longer than any MMR path
    (0, [NODE] * 65),
    (0, [b"\x11" * 31]),           # short node
])
def test_inclusion_encoder_refuses(leaf, path):
    with pytest.raises(ValueError):
        er.encode_cll_inclusion_proof(leaf, path)


def _consistency_inputs(case_id):
    i = next(c for c in CONSISTENCY if c["id"] == case_id)["inputs"]
    return (i["old_size"], i["new_size"], _nodes(i["old_peaks"]), [_nodes(p) for p in i["paths"]],
            _nodes(i["new_peaks"]))


def test_consistency_encoder_refuses_paths_that_do_not_reach():
    old, new, old_peaks, paths, new_peaks = _consistency_inputs("consistency-n3-n7")
    assert er.encode_cll_consistency_proof(old, new, old_peaks, paths, new_peaks)
    with pytest.raises(ValueError):
        er.encode_cll_consistency_proof(old, new, old_peaks, paths, [NODE] + new_peaks[1:])
    with pytest.raises(ValueError):
        er.encode_cll_consistency_proof(old, new, [NODE] + old_peaks[1:], paths, new_peaks)
    with pytest.raises(ValueError):  # the right peaks do not complete the new peak list
        er.encode_cll_consistency_proof(old, new, old_peaks, paths, new_peaks + [NODE])


@pytest.mark.parametrize("old_size, new_size", [(0, 4), (7, 4), (4, 1 << 53)])
def test_consistency_encoder_refuses_bad_sizes(old_size, new_size):
    with pytest.raises(ValueError):
        er.encode_cll_consistency_proof(old_size, new_size, [NODE], [[]], [NODE])


def test_consistency_encoder_refuses_a_peak_count_that_is_not_tree_size_1s():
    old, new, old_peaks, paths, new_peaks = _consistency_inputs("consistency-n3-n7")
    with pytest.raises(ValueError):
        er.encode_cll_consistency_proof(old, new, old_peaks[:1], paths[:1], new_peaks)
