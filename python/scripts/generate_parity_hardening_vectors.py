#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Add the cross-language parity-hardening cases to the shared corpora.

Each case pins a behaviour on which the Go, Python, Rust and TypeScript
verifiers once disagreed, so their conformance runners now exercise it:

- capsule/: a nested member named ``__proto__`` stays inside ``capsule_id``;
  the -02 addendum's ``domain`` and ``provenance`` are strings and its
  ``self_reported_reasoning`` and ``provenance_mode`` blocks are objects.
- producer-envelope/: protected-header labels are integers, each label
  appears once, ``alg`` is an integer, and ``alg`` is checked before the
  label count.
- disclosure-envelope/: a missing ``capsule`` member fails rather than the
  envelope being read as its own Capsule, and a committed digest is lowercase
  hexadecimal.

Only these cases are written; existing, released cases are left untouched.
Manifests gain the new entries and each corpus's SHA256SUMS is refreshed.
The run is deterministic.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_action_capsule import compute_capsule_id, json_digest, verify, verify_disclosure_envelope

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from generate_disclosure_vectors import expected as disclosure_expected  # noqa: E402

SPEC_V05 = "draft-mih-scitt-agent-action-capsule-05"


def _dump(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _base_capsule(action_id: str) -> dict:
    return {
        "action_id": action_id,
        "action_type": "decide",
        "assurance": {"attestation_mode": "self_attested", "effect_mode": "not_applicable", "ledger_mode": "standalone"},
        "canonicalization_id": "jcs",
        "developer": "conformance-vector@v1",
        "disposition": {"approver": "policy", "decision": "accept", "human_disposed": False, "verdict_class": "executed"},
        "format_version": "4",
        "operator": "AAC-CONFORMANCE",
        "spec_version": SPEC_V05,
        "timestamp": "2026-10-10T00:00:00Z",
    }


def _append(manifest_path: Path, entries: list[dict]) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    listed = {case["name"] for case in manifest["cases"]}
    manifest["cases"].extend(entry for entry in entries if entry["name"] not in listed)
    manifest["count"] = len(manifest["cases"])
    _dump(manifest_path, manifest)


def capsule_cases() -> list[dict]:
    out = VECTORS / "capsule"
    cases = [
        (
            "canonical-nested-member-named-proto",
            "positive",
            "A nested member named __proto__ is an ordinary member: it stays in the canonical form and the capsule_id.",
            {"extension": {"canonical_test_value": {"__proto__": {"inner": "kept"}, "b": "x"}}},
        ),
        (
            "neg-field-not-string-domain-number",
            "negative",
            "The -02 addendum's domain member is a string; a number is a check-1 type error.",
            {"domain": 1},
        ),
        (
            "neg-field-not-string-provenance-list",
            "negative",
            "The -02 addendum's provenance member is a string; a list is a check-1 type error.",
            {"provenance": ["gate"]},
        ),
        (
            "neg-block-not-object-self-reported-reasoning",
            "negative",
            "self_reported_reasoning is a block; a string where the object belongs is a check-1 type error.",
            {"self_reported_reasoning": "digest"},
        ),
        (
            "neg-block-not-object-provenance-mode",
            "negative",
            "provenance_mode is a block; a string where the object belongs is a check-1 type error.",
            {"provenance_mode": "backfilled"},
        ),
    ]
    entries = []
    for name, kind, description, extra in cases:
        capsule = _base_capsule(name)
        capsule.update(extra)
        capsule["capsule_id"] = compute_capsule_id(capsule)
        result = verify(capsule)
        directory = out / name
        directory.mkdir(exist_ok=True)
        _dump(directory / "input.json", capsule)
        _dump(
            directory / "expected.json",
            {
                "capsule_id_recomputed": result.capsule_id,
                "derived": result.assurance,
                "description": description,
                "findings": [
                    {"check": item.check, "code": item.code, "detail": item.detail, "severity": item.severity}
                    for item in result.findings
                ],
                "kind": kind,
                "ok": result.ok,
                "provenance": "reference-derived",
            },
        )
        entries.append({"name": name, "kind": kind, "description": description, "provenance": "reference-derived"})
    _append(out / "vectors.json", entries)
    return entries


CONTENT_TYPE = "application/agent-action-capsule-id"
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC_KEY = PRIVATE_KEY.public_key().public_bytes_raw()
PAYLOAD = bytes(range(32, 64))


def _text(value: str) -> bytes:
    return cbor2.dumps(value)


def _envelope(protected: bytes) -> bytes:
    """A COSE_Sign1 over PAYLOAD whose protected header is these exact bytes.

    The bytes are written by hand so a header the CBOR encoder would refuse to
    produce (a boolean or repeated label, a float alg) can be signed honestly:
    only the header check under test can fail.
    """
    sig_structure = cbor2.dumps(["Signature1", protected, b"", PAYLOAD])
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, PAYLOAD, PRIVATE_KEY.sign(sig_structure)]))


def producer_envelope_cases() -> list[dict]:
    out = VECTORS / "producer-envelope"
    ct = bytes([0x03]) + _text(CONTENT_TYPE)
    kid = bytes([0x04]) + cbor2.dumps(PUBLIC_KEY)
    cases = [
        (
            "protected-label-boolean",
            "protected alg is keyed by CBOR true, not the integer label 1",
            bytes([0xA3, 0xF5, 0x27]) + ct + kid,
            "envelope_malformed",
        ),
        (
            "protected-label-duplicate",
            "protected header repeats label 1",
            bytes([0xA4, 0x01, 0x27, 0x01, 0x27]) + ct + kid,
            "envelope_malformed",
        ),
        (
            "protected-alg-float",
            "protected alg is the half-precision float -8.0, not the integer -8",
            bytes([0xA3, 0x01, 0xF9, 0xC8, 0x00]) + ct + kid,
            "envelope_algorithm_mismatch",
        ),
        (
            "wrong-algorithm-extra-header",
            "wrong alg and an extra label together: alg is checked first",
            bytes([0xA4, 0x01, 0x26]) + ct + kid + bytes([0x18, 0x63]) + _text("extra"),
            "envelope_algorithm_mismatch",
        ),
    ]
    entries = []
    for name, description, protected, code in cases:
        directory = out / name
        directory.mkdir(exist_ok=True)
        (directory / "capsule_id.txt").write_text(PAYLOAD.hex() + "\n", encoding="ascii")
        (directory / "envelope.cose").write_bytes(_envelope(protected))
        _dump(directory / "expected.json", {"ok": False, "finding_codes": [code], "public_key_hex": None})
        entries.append({"name": name, "description": description})
    _append(out / "vectors.json", entries)
    return entries


def disclosure_envelope_cases() -> list[dict]:
    out = VECTORS / "disclosure-envelope"
    base = json.loads((out / "pos-disclosure-envelope-both-fields" / "input.json").read_text(encoding="utf-8"))
    envelope = base["envelope"]
    capsule = envelope["capsule"]
    agent_input = envelope["disclosures"]["agent_input"]

    upper = copy.deepcopy(capsule)
    compute = upper["model_attestation"]["compute_attestation"]
    compute["agent_input_digest"] = json_digest(agent_input).upper()
    upper["capsule_id"] = compute_capsule_id(upper)

    cases = [
        (
            "neg-disclosure-envelope-capsule-missing",
            "a valid bare Capsule passed as an envelope has no capsule member and fails Class 1; "
            "it is never read as its own Capsule",
            capsule,
        ),
        (
            "neg-disclosure-envelope-uppercase-commitment",
            "DE-2 requires a lowercase-hex committed digest; an uppercase one is no commitment",
            {"capsule": upper, "disclosures": {"agent_input": agent_input}},
        ),
    ]
    entries = []
    for name, description, value in cases:
        directory = out / name
        directory.mkdir(exist_ok=True)
        _dump(directory / "input.json", {"envelope": value})
        record = disclosure_expected(verify_disclosure_envelope(value), description, "negative")
        record["provenance"] = "reference-derived"
        _dump(directory / "expected.json", record)
        entries.append({"name": name, "kind": "negative", "description": description, "provenance": "reference-derived"})
    _append(out / "vectors.json", entries)
    return entries


def update_checksums(directory: Path, paths: list[Path]) -> None:
    """Record ``paths`` in ``directory``'s SHA256SUMS, leaving every other line as is.

    Unlike a full regeneration this keeps the released file's line order and
    coverage, so the diff shows only the files this script wrote.
    """
    sums = directory / "SHA256SUMS"
    lines = sums.read_text(encoding="utf-8").splitlines()
    index = {line.split("  ", 1)[1]: i for i, line in enumerate(lines)}
    for path in sorted(paths):
        relative = path.relative_to(directory).as_posix()
        line = f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}"
        if relative in index:
            lines[index[relative]] = line
            continue
        position = next((i for i, existing in enumerate(lines) if existing.split("  ", 1)[1] > relative), len(lines))
        lines.insert(position, line)
        index = {existing.split("  ", 1)[1]: i for i, existing in enumerate(lines)}
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    written: dict[str, list[str]] = {
        "capsule": [entry["name"] for entry in capsule_cases()],
        "producer-envelope": [entry["name"] for entry in producer_envelope_cases()],
        "disclosure-envelope": [entry["name"] for entry in disclosure_envelope_cases()],
    }
    every: list[Path] = []
    for corpus, names in written.items():
        directory = VECTORS / corpus
        files = [directory / "vectors.json"] + [
            path for name in names for path in sorted((directory / name).iterdir()) if path.is_file()
        ]
        update_checksums(directory, files)
        every.extend(files)
    update_checksums(VECTORS, every)


if __name__ == "__main__":
    main()
