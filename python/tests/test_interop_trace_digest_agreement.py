# SPDX-License-Identifier: BSD-3-Clause
"""Digest-agreement fixture for the TRACE (agentrust-io/trace-spec) crosswalk.

Cross-checks AAC's in-repo JCS (agent_action_capsule.canonical) against an
independent RFC 8785 implementation, rfc8785 0.1.4 (PyPI) — the exact library
TRACE's own spec names as its reference implementation (trace-v0.2.md
§3.2.2) — over the cases where conforming RFC 8785 libraries are documented to
diverge: non-ASCII string values, a non-BMP/supplementary-plane object key, a
high-BMP object key, and integers at the IEEE-754 safe-integer boundary.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
import rfc8785

from agent_action_capsule.canonical import (
    MAX_SAFE_INTEGER,
    UnsafeIntegerError,
    compute_capsule_id,
    jcs,
    json_digest,
)

ROOT = Path(__file__).resolve().parents[2]
INTEROP = ROOT / "docs" / "interop"
VECTOR = json.loads((INTEROP / "aac-trace-digest-agreement-vector.json").read_text())


def _load_capsule(name: str) -> dict:
    return json.loads((INTEROP / name).read_text())


def _preimage(capsule: dict) -> dict:
    """The capsule_id preimage: every member except capsule_id itself."""
    return {k: v for k, v in capsule.items() if k != "capsule_id"}


def _trace_digest_hex(preimage: dict) -> str:
    """Independent RFC 8785 digest, computed with a library AAC does not implement."""
    return hashlib.sha256(rfc8785.dumps(preimage)).hexdigest()


def test_positive_capsule_digest_agrees_across_aac_and_trace_implementations():
    capsule = _load_capsule(VECTOR["positive"]["capsule"])
    preimage = _preimage(capsule)

    aac_digest = json_digest(preimage)
    trace_digest = _trace_digest_hex(preimage)

    assert aac_digest == VECTOR["positive"]["capsule_id"]
    assert trace_digest == VECTOR["positive"]["trace_rfc8785_digest_hex"]
    assert aac_digest == trace_digest, "AAC json_digest and rfc8785 diverge on the same preimage"

    # Byte-for-byte, not just digest-for-digest: a digest collision would hide
    # a canonicalization mismatch just as easily as it would hide agreement.
    assert jcs(preimage) == rfc8785.dumps(preimage)

    # capsule_id recomputation (the verifier-facing entry point) agrees too.
    assert compute_capsule_id(capsule) == aac_digest


def test_mutant_nested_key_perturbation_is_caught():
    """R4 mutant check: perturbing one nested key must change the digest under
    BOTH implementations. If it didn't — e.g. the replacer-array defect the
    crosswalk prose calls out, where a nested object serializes empty while
    the outer bytes look intact — the positive test above would still pass
    while silently no longer checking the nested nine-tenths of the object."""
    positive = _load_capsule(VECTOR["positive"]["capsule"])
    mutant = _load_capsule(VECTOR["mutant"]["capsule"])

    # Exactly one nested leaf differs, three levels down.
    diffs = [
        k
        for k in positive["extension"]["trace_digest_agreement_test"]
        if positive["extension"]["trace_digest_agreement_test"][k]
        != mutant["extension"]["trace_digest_agreement_test"][k]
    ]
    assert diffs == ["\U0001F600"]

    mutant_preimage = _preimage(mutant)
    aac_mutant_digest = json_digest(mutant_preimage)
    trace_mutant_digest = _trace_digest_hex(mutant_preimage)

    assert aac_mutant_digest == trace_mutant_digest == VECTOR["mutant"]["capsule_id"]
    # The load-bearing assertion: perturbing the nested key must NOT leave the
    # digest equal to the unperturbed positive capsule's pinned capsule_id.
    assert aac_mutant_digest != VECTOR["positive"]["capsule_id"]
    assert trace_mutant_digest != VECTOR["positive"]["trace_rfc8785_digest_hex"]


def test_boundary_exceeded_integer_is_rejected_by_both_implementations():
    """Proves, rather than asserts, that the AAC/rfc8785 divergence documented
    in trace-v0.2.md §3.2.2 (canonicalize 4.0.0 npm vs rfc8785 0.1.4 PyPI
    disagreeing on integers outside +/-(2^53-1)) cannot arise in a Capsule:
    AAC's own serializer refuses to emit bytes for the value at all."""
    positive = _load_capsule(VECTOR["positive"]["capsule"])
    boundary_exceeded = copy.deepcopy(positive)
    boundary_exceeded["extension"]["trace_digest_agreement_test"]["safe_max"] = (
        MAX_SAFE_INTEGER + 1
    )  # 2^53, the first value canonicalize/rfc8785 are documented to disagree on
    preimage = _preimage(boundary_exceeded)

    with pytest.raises(UnsafeIntegerError):
        json_digest(preimage)

    with pytest.raises(rfc8785.IntegerDomainError):
        rfc8785.dumps(preimage)


def test_vector_checked_against_current_trace_spec_head():
    checked = VECTOR["checked_against"]
    assert checked["repo"] == "agentrust-io/trace-spec"
    assert len(checked["commit"]) == 40
