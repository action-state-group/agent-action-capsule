# SPDX-License-Identifier: BSD-3-Clause
"""Generate the RFC 8785 negative-zero vectors in ../../vectors/capsule/.

No shared vector carried ``-0``, so Go writing it as ``-0`` (fixed in #188)
went unnoticed while Python and TypeScript wrote ``0``. Two spec-derived
positive cases pin the RFC 8785 rule (S:3.2.2.3, ECMAScript
Number::toString):

- ``canonical-integer-negative-zero``: ``-0`` as a direct member, nested in an
  object and inside an array, beside ``0``.
- ``canonical-integer-negative-zero-as-zero``: the same Capsule with every
  ``-0`` written ``0``. Its ``action_id`` stays that of the first case so the
  preimages match, and ``same_capsule_id_as`` names the case whose
  ``capsule_id`` it must equal.

A Python ``int`` has no negative zero, so the Capsule is built and digested
with ``0`` and ``input.json`` is written as raw JSON text with the ``-0``
tokens put back. Each consumer parses that text with its integer-preserving
decoder, so the ``-0`` token reaches its serializer.

The cases first appeared in #190, which merged into the already-merged #188
branch and never reached main; the bytes here are those #190 reviewed.

Run: cd python && python scripts/generate_negative_zero_vectors.py
"""
from __future__ import annotations

import sys
from pathlib import Path

from agent_action_capsule import compute_capsule_id, verify

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vector_layout import append_cases, dumps, preimage, sort_members  # noqa: E402

OUT = Path(__file__).resolve().parents[2] / "vectors/capsule"
SPEC = "draft-mih-scitt-agent-action-capsule-05"
PROVENANCE = "spec-derived"
NAME = "canonical-integer-negative-zero"
TWIN = "canonical-integer-negative-zero-as-zero"

# Stands in for a -0 token while the text is rendered; json.dumps cannot emit one.
_NEG_ZERO = "\u0000negative-zero\u0000"
# The test value with each -0 token marked; digesting uses it with every mark as 0.
VALUE = {"a": _NEG_ZERO, "b": 0, "c": {"d": _NEG_ZERO, "e": 0}, "f": [_NEG_ZERO, 0, _NEG_ZERO]}

DESCRIPTION = (
    "Negative zero serialized as '0' (RFC 8785 S:3.2.2.3, ECMAScript Number::toString) as a "
    "direct member, nested in an object and inside an array, beside integer 0, under explicit "
    "format-4 plain JCS. input.json is raw JSON text: each consumer parses it with its "
    "integer-preserving decoder, so the -0 token reaches the serializer."
)
TWIN_DESCRIPTION = (
    f"Twin of {NAME} with every -0 token written 0 (action_id kept identical so the preimages "
    "match): the JCS bytes and capsule_id MUST equal that case's, so -0 and 0 give the same "
    "JSON-DIGEST."
)


def as_zero(value):
    """``value`` with every -0 mark replaced by integer 0."""
    if isinstance(value, dict):
        return {key: as_zero(item) for key, item in value.items()}
    if isinstance(value, list):
        return [as_zero(item) for item in value]
    return 0 if value == _NEG_ZERO else value


def capsule(value) -> dict:
    """The fixed format-4 Capsule carrying ``value``, its capsule_id over the 0 form."""
    cap = sort_members({
        "action_id": NAME,
        "action_type": "decide",
        "assurance": {"attestation_mode": "self_attested", "effect_mode": "not_applicable", "ledger_mode": "standalone"},
        "canonicalization_id": "jcs",
        "capsule_id": None,
        "developer": "conformance-vector@v1",
        "disposition": {"approver": "policy", "decision": "accept", "human_disposed": False, "verdict_class": "executed"},
        "extension": {"canonical_test_value": value},
        "format_version": "4",
        "operator": "AAC-CONFORMANCE",
        "spec_version": SPEC,
        "timestamp": "2026-10-06T00:00:00Z",
    })
    cap["capsule_id"] = compute_capsule_id(as_zero(cap))
    return cap


def expected(cap: dict, description: str, same_as: str | None = None) -> dict:
    digested = as_zero(cap)
    result = verify(digested)
    if not result.ok:
        raise SystemExit(f"{cap['action_id']}: the reference verify() rejected a positive case")
    record = {
        "canonical_preimages": {"capsule_id": preimage(digested)},
        "capsule_id_recomputed": result.capsule_id,
        "derived": result.assurance,
        "description": description,
        "findings": [
            {"check": f.check, "code": f.code, "detail": f.detail, "severity": f.severity}
            for f in result.findings
        ],
        "kind": "positive",
        "ok": result.ok,
        "provenance": PROVENANCE,
    }
    if same_as is not None:
        record["same_capsule_id_as"] = same_as
    return sort_members(record)


def write(name: str, cap: dict, record: dict) -> None:
    directory = OUT / name
    directory.mkdir(exist_ok=True)
    text = dumps(cap).replace(dumps(_NEG_ZERO).strip(), "-0")
    (directory / "input.json").write_text(text, encoding="utf-8")
    (directory / "expected.json").write_text(dumps(record), encoding="utf-8")


def main() -> None:
    negative = capsule(VALUE)
    twin = capsule(as_zero(VALUE))
    write(NAME, negative, expected(negative, DESCRIPTION))
    write(TWIN, twin, expected(twin, TWIN_DESCRIPTION, same_as=NAME))
    append_cases(OUT / "vectors.json", [
        {"name": NAME, "kind": "positive", "description": DESCRIPTION, "provenance": PROVENANCE},
        {"name": TWIN, "kind": "positive", "description": TWIN_DESCRIPTION, "provenance": PROVENANCE},
    ])
    print(f"wrote 2 negative-zero vectors to {OUT}")


if __name__ == "__main__":
    main()
