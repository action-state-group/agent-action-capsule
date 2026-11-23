#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the outcome-claim-limit vectors (``vectors/outcome-claim-limits``).

Four cases: two negatives a reader must refuse, each with a positive twin it
must accept. They carry two proposed negative vectors,
``physical_completion_absent_presented_as_proof`` and
``outcome_signer_not_independent``, in this repository's spelling. The
README.md records the name mapping.

Every expected result below is written by hand from the draft text:
``draft-mih-scitt-agent-action-capsule-05`` §5.3 (the Effect Record's
``effect_attestation`` grade) and ``spec/REGISTRY.md`` §5 for the Capsule pair,
and ``draft-mih-zhang-agent-disclosure-bundle-01``, "Self-Countersignature",
for the countersignature pair. Nothing here imports or runs an
implementation. The script builds two Capsules and hashes them (RFC 8785 JCS,
SHA-256), and copies two signed Bundles verbatim from
``vectors/bundle/producer-key/vectors.json`` (a released vector, never
rewritten here). It signs nothing, so it needs no key.

Output: ``vectors/outcome-claim-limits/`` (or ``--out DIR``). The run is a
pure function of this file and the producer-key vectors: no clock, no
randomness. ``README.md`` is hand-written; when present in the output
directory it is included in ``SHA256SUMS`` but never rewritten.

Dependencies: the standard library only.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "outcome-claim-limits"
PRODUCER_KEY = ROOT / "vectors" / "bundle" / "producer-key" / "vectors.json"
PRODUCER_KEY_PATH = "vectors/bundle/producer-key/vectors.json"

CAPSULE_DRAFT = "draft-mih-scitt-agent-action-capsule-05"
BUNDLE_DRAFT = "draft-mih-zhang-agent-disclosure-bundle-01"

# A countersigner source as the caller passes it (Bundle -01, "Countersigner
# directory"): names come from here, never from the Bundle.
COUNTERSIGNER_NAME = "countersign.example"
PRODUCER_LISTED_NAME = "producer.example"

# The one Class-1 result both Capsule twins produce (-05 §6). It is the same
# for both because the verifier's derived assurance carries effect_mode, not
# the effect_attestation grade.
CLASS1 = {
    "ok": True,
    "derived": {"attestation_mode": "self_attested", "effect_mode": "confirmed", "ledger_mode": "standalone"},
    "finding_codes": [],
}


def _check_json_value(value: Any) -> None:
    """The stdlib JCS below is exact only for strings, booleans and containers."""
    if isinstance(value, dict):
        for key, item in value.items():
            if not key.isascii():
                raise ValueError("the vectors use ASCII member names only")
            _check_json_value(item)
    elif isinstance(value, list):
        for item in value:
            _check_json_value(item)
    elif not isinstance(value, (str, bool)) and value is not None:
        raise TypeError(f"the vectors use no numbers: {value!r}")


def _jcs(value: Any) -> bytes:
    _check_json_value(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _capsule(grade: str) -> dict:
    body = {
        "action_id": "ocl-effect-001",
        "action_type": "decide",
        "assurance": {"attestation_mode": "self_attested", "effect_mode": "confirmed", "ledger_mode": "standalone"},
        "canonicalization_id": "jcs",
        "developer": "agent@v1",
        "disposition": {"approver": "policy", "decision": "accept", "human_disposed": False, "verdict_class": "executed"},
        "effect": {
            "effect_attestation": grade,
            "response_digest": "1" * 64,
            "status": "confirmed",
            "type": "write_order",
        },
        "format_version": "4",
        "operator": "operator.example",
        "spec_version": CAPSULE_DRAFT,
        "timestamp": "2026-07-06T00:00:00Z",
    }
    return {"capsule_id": hashlib.sha256(_jcs(body)).hexdigest(), **body}


def _producer_key_cases() -> tuple[dict, dict]:
    corpus = json.loads(PRODUCER_KEY.read_text(encoding="utf-8"))
    cases = {c["id"]: c for c in corpus["cases"]}
    return corpus, cases


def build_corpus() -> dict:
    pk, cases = _producer_key_cases()
    producer = pk["keys"]["producer_public_key_hex"]
    other = pk["keys"]["other_public_key_hex"]
    self_signed = cases["declared-self-countersignature"]
    undeclared = cases["undeclared-self-countersignature"]
    other_signed = cases["declared-other-signer"]

    claimed = _capsule("runtime_claimed")
    observed = _capsule("gate_executed")

    return {
        "format_version": "1",
        "provenance": "spec-derived",
        "spec": [CAPSULE_DRAFT, "spec/REGISTRY.md §5", BUNDLE_DRAFT],
        "description": (
            "Two negatives a reader must refuse, each with a positive twin it must accept: a "
            "controller's report of success is not proof that the effect occurred, and an outcome "
            "signed by the producer's own key is not independent proof. Each case names a "
            "condition-removed mutant that must flip its result. A reader decides from the Class-1 "
            "result, the effect_attestation grade in the payload, and the countersignature stamp; "
            "the Class-1 derived assurance alone is identical across the Capsule twins."
        ),
        "intents": {
            "physical_proof": (
                "Accept only if the Class-1 result is ok, the derived effect_mode is confirmed, and "
                "effect.effect_attestation is gate_executed. Any other grade, an unregistered one "
                "included, is no stronger than runtime_claimed (REGISTRY §5) and is refused with "
                "reason physical_completion_absent. An accepted case names its observer: the gate."
            ),
            "independent_outcome_proof": (
                "Accept only if the countersign/v1 entry's stamp is resolved: valid, not signed by a "
                "declared producer key, and named by the caller's countersigner source. not "
                "independent is refused with reason outcome_signer_not_independent; unresolved "
                "signer is refused with reason outcome_signer_unresolved. An accepted case names "
                "its countersigner, taken from the caller's source."
            ),
        },
        "count": 4,
        "cases": [
            {
                "id": "physical-completion-absent-presented-as-proof",
                "proposed_name": "physical_completion_absent_presented_as_proof",
                "kind": "negative",
                "twin": "physical-completion-observed",
                "consumer_intent": "physical_proof",
                "description": (
                    "The runtime asserted completion and the Capsule records that claim, not an "
                    "observation (effect_attestation runtime_claimed). Class 1 accepts the record "
                    "and derives effect_mode confirmed; presented as proof that the effect "
                    "occurred, it is refused."
                ),
                "capsule": claimed,
                "expect": {
                    "class1": CLASS1,
                    "grade": "runtime_claimed",
                    "accept": False,
                    "reason": "physical_completion_absent",
                },
                "mutants": [
                    {
                        "removes": "the grade below gate_executed",
                        "set": {"effect.effect_attestation": "gate_executed"},
                        "expect": {"accept": True},
                    }
                ],
            },
            {
                "id": "physical-completion-observed",
                "proposed_name": "physical_completion: observed (positive twin)",
                "kind": "positive",
                "twin": "physical-completion-absent-presented-as-proof",
                "consumer_intent": "physical_proof",
                "description": (
                    "The commit transited the gate and the engine observed the effect boundary "
                    "directly (effect_attestation gate_executed). The Capsule differs from its twin "
                    "only in that grade and its capsule_id. Accepted, observer named: the gate."
                ),
                "capsule": observed,
                "expect": {
                    "class1": CLASS1,
                    "grade": "gate_executed",
                    "accept": True,
                    "observed_by": "gate",
                },
                "mutants": [
                    {
                        "removes": "the gate_executed grade",
                        "set": {"effect.effect_attestation": "runtime_claimed"},
                        "expect": {"accept": False, "reason": "physical_completion_absent"},
                    },
                    {
                        "removes": "a registered grade: the proposed spelling 'observed', unregistered, grades no higher than runtime_claimed",
                        "set": {"effect.effect_attestation": "observed"},
                        "expect": {"accept": False, "reason": "physical_completion_absent"},
                    },
                ],
            },
            {
                "id": "outcome-signer-not-independent",
                "proposed_name": "outcome_signer_not_independent",
                "kind": "negative",
                "twin": "outcome-signer-independent",
                "consumer_intent": "independent_outcome_proof",
                "description": (
                    "The countersign/v1 entry is valid and signed by the key the Bundle declares "
                    "in producer-key/v1. The caller's countersigner source also lists that key, so "
                    "a listing alone would name it; the declaration still makes it not independent. "
                    "Refused."
                ),
                "source": {"file": PRODUCER_KEY_PATH, "case": self_signed["id"]},
                "bundle": copy.deepcopy(self_signed["bundle"]),
                "bundle_digest": self_signed["bundle_digest"],
                "countersigners": [{"name": PRODUCER_LISTED_NAME, "key_ids": [producer]}],
                "expect": {
                    "stamp": "not independent",
                    "accept": False,
                    "reason": "outcome_signer_not_independent",
                },
                "mutants": [
                    {
                        "removes": "the producer-key/v1 declaration (the same key, undeclared, re-signed over the new digest)",
                        "source": {"file": PRODUCER_KEY_PATH, "case": undeclared["id"]},
                        "bundle": copy.deepcopy(undeclared["bundle"]),
                        "bundle_digest": undeclared["bundle_digest"],
                        "expect": {"stamp": "resolved", "accept": True, "countersigner": PRODUCER_LISTED_NAME},
                    }
                ],
            },
            {
                "id": "outcome-signer-independent",
                "proposed_name": "outcome_signer.relationship: independent (positive twin)",
                "kind": "positive",
                "twin": "outcome-signer-not-independent",
                "consumer_intent": "independent_outcome_proof",
                "description": (
                    "The countersign/v1 entry is valid and signed by a key other than the declared "
                    "producer key, and the caller's countersigner source names that key. Accepted, "
                    "countersigner named from the caller's source."
                ),
                "source": {"file": PRODUCER_KEY_PATH, "case": other_signed["id"]},
                "bundle": copy.deepcopy(other_signed["bundle"]),
                "bundle_digest": other_signed["bundle_digest"],
                "countersigners": [{"name": COUNTERSIGNER_NAME, "key_ids": [other]}],
                "expect": {"stamp": "resolved", "accept": True, "countersigner": COUNTERSIGNER_NAME},
                "mutants": [
                    {
                        "removes": "the caller's listing of the signer key",
                        "countersigners": [],
                        "expect": {"stamp": "unresolved signer", "accept": False, "reason": "outcome_signer_unresolved"},
                    },
                    {
                        "removes": "the signer's independence (the caller also holds the signer key as a producer key)",
                        "extra_producer_keys": [other],
                        "expect": {"stamp": "not independent", "accept": False, "reason": "outcome_signer_not_independent"},
                    },
                ],
            },
        ],
    }


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build(out: Path = DEFAULT_OUT) -> dict[str, bytes]:
    """Return {file name: bytes} for every generated file, SHA256SUMS included."""
    files = {"vectors.json": _dump(build_corpus())}
    readme = out / "README.md"
    pinned = dict(files)
    if readme.exists():
        pinned["README.md"] = readme.read_bytes()
    files["SHA256SUMS"] = "".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(pinned.items())
    ).encode("utf-8")
    return files


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in build(args.out).items():
        (args.out / name).write_bytes(data)
        print(f"wrote {args.out / name}")


if __name__ == "__main__":
    main()
