# SPDX-License-Identifier: BSD-3-Clause
"""Run every ran_under interop vector through verify_ran_under.py and assert its
expected.json. This is what makes the vectors CI-checked, not just static.

Also asserts the R4 shape directly: each negative fails at EXACTLY one
documented stage (every stage before it is True, the named stage is the only
False, and no stage after it was even evaluated)."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

VECTORS_DIR = Path(__file__).resolve().parents[2] / "vectors/interop" / "ran_under"
VERIFIER_PATH = VECTORS_DIR / "verify_ran_under.py"

CASES = [
    "pos-ran-under-attested",
    "neg-ran-under-signer-untrusted",
    "neg-ran-under-measurement-mismatch",
    "neg-ran-under-grade-absent",
    "neg-ran-under-inner-claim",
    "neg-ran-under-digest-mismatch",
]


def _load_verifier():
    spec = importlib.util.spec_from_file_location("verify_ran_under", VERIFIER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


VERIFIER = _load_verifier()


@pytest.mark.parametrize("case", CASES)
def test_vector_matches_expected(case):
    bundle = json.loads((VECTORS_DIR / case / "input.json").read_text())
    expected = json.loads((VECTORS_DIR / case / "expected.json").read_text())

    failed_stage, stages, verdict = VERIFIER.check(bundle)
    lifted = failed_stage is None

    assert lifted == expected["lift"], case
    assert lifted == expected["verified"], case
    assert verdict == expected["verdict"], case
    assert failed_stage == expected["failed_stage"], case

    # R4: exactly one documented stage fails, and it is the last stage evaluated.
    if failed_stage is None:
        assert all(stages.values()), (case, stages)
    else:
        assert list(stages)[-1] == failed_stage, (case, stages)
        assert stages[failed_stage] is False, (case, stages)
        assert all(v for k, v in stages.items() if k != failed_stage), (case, stages)


@pytest.mark.parametrize("case", CASES)
def test_vector_cli_exit_code(case):
    """The CLI entry point (as an external consumer would invoke it) agrees with
    the library-level check() result — same process boundary CI actually runs."""
    expected = json.loads((VECTORS_DIR / case / "expected.json").read_text())
    proc = subprocess.run(
        [sys.executable, str(VERIFIER_PATH), str(VECTORS_DIR / case / "input.json")],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == (0 if expected["lift"] else 2), (case, proc.stdout, proc.stderr)
    payload = json.loads(proc.stdout)
    assert payload["verdict"] == expected["verdict"], case
    assert payload["failed_stage"] == expected["failed_stage"], case


def test_every_negative_has_a_distinct_failed_stage():
    """Two-sided-set sanity: the five negatives name five distinct stages (no
    negative is a duplicate of another's failure mode)."""
    failed_stages = set()
    for case in CASES:
        if case == "pos-ran-under-attested":
            continue
        expected = json.loads((VECTORS_DIR / case / "expected.json").read_text())
        assert expected["failed_stage"] not in failed_stages, case
        failed_stages.add(expected["failed_stage"])


def test_harness_does_not_import_attestation_parsing_libraries():
    """The 🔴 constraint made mechanically checkable: the verifier module's own
    source never references quote/measurement/attestation-parsing primitives —
    it only ever reads cited_verifier_result as a given input."""
    source = VERIFIER_PATH.read_text()
    for banned in ("parse_quote", "evaluate_measurement", "verify_attestation", "decode_quote"):
        assert banned not in source
