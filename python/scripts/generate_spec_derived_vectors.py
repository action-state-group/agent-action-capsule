# SPDX-License-Identifier: BSD-3-Clause
"""Generate the spec-derived format-4 cases in ../../vectors/capsule/.

#99 added these with the format-4-only reference: payload digests over flat,
nested and Unicode values, the chain block and present null and empty
members inside capsule_id, and the null and empty canonicalization_id
negatives. Their expected results are derived from the draft and RFC 8785;
expected.json records every canonical preimage, so this script only
reproduces them, and the reference verify() must agree.

They are part of the -04 compatibility set and keep the hand-written layout
they were released in. generate_disclosure_vectors.py reuses the nested
payload and its Capsule.

Run after generate_reference_vectors.py: the manifest entries are appended.
"""
from __future__ import annotations

import sys
from pathlib import Path

from agent_action_capsule import compute_capsule_id, json_digest, verify
from agent_action_capsule.canonical import jcs

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vector_layout import append_cases, dumps, hand_dumps, preimage, sort_members  # noqa: E402

OUT = Path(__file__).resolve().parents[2] / "vectors/capsule"
SPEC = "draft-mih-scitt-agent-action-capsule-04"
PROVENANCE = "spec-derived"

FLAT = {"kind": "flat", "value": "alpha"}
NESTED = {
    "request": {"items": [{"meta": {"sku": "A1"}}, {"meta": {"sku": "B2"}}], "region": "us"},
    "trace": {"flags": {"dry_run": False}},
}
UNICODE = {"control": chr(0x01), "emoji": chr(0x1F600), "solidus": "a/b"}


def capsule(action_id: str, timestamp: str, ledger_mode: str = "standalone", **members) -> dict:
    """A sealed format-4 Capsule with sorted members."""
    cap = sort_members({
        "action_id": action_id,
        "action_type": "decide",
        "assurance": {"attestation_mode": "self_attested", "effect_mode": "not_applicable", "ledger_mode": ledger_mode},
        "canonicalization_id": "jcs",
        "capsule_id": None,
        "developer": "agent@v1",
        "disposition": {"approver": "policy", "decision": "accept", "human_disposed": False, "verdict_class": "executed"},
        "format_version": "4",
        "operator": "ACME-CO",
        "spec_version": SPEC,
        "timestamp": timestamp,
        **members,
    })
    cap["capsule_id"] = compute_capsule_id(cap)
    return cap


def payload_capsule(action_id: str, timestamp: str, field: str, value: dict) -> dict:
    """A Capsule committing ``value`` at model_attestation.compute_attestation.``field``."""
    return capsule(action_id, timestamp, model_attestation={"compute_attestation": {field: json_digest(value)}})


def nested_output_capsule() -> dict:
    return payload_capsule("spec-nested-digest", "2026-09-13T00:00:02Z", "agent_output_digest", NESTED)


def payload_preimages(field: str, value: dict, cap: dict) -> dict:
    return {field: jcs(value).decode("utf-8"), "capsule_id": preimage(cap)}


def expected(cap: dict, description: str, kind: str, preimages: dict | None) -> dict:
    result = verify(cap)
    if result.ok != (kind == "positive"):
        raise SystemExit(f"{description}: the reference verify() disagrees with the expected verdict")
    out = {
        "capsule_id_recomputed": result.capsule_id,
        "derived": result.assurance,
        "description": description,
        "findings": [
            {"check": f.check, "code": f.code, "detail": f.detail, "severity": f.severity}
            for f in result.findings
        ],
        "kind": kind,
        "ok": result.ok,
        "provenance": PROVENANCE,
    }
    out = sort_members(out)
    if preimages:
        out = {"canonical_preimages": preimages, **out}
    return out


def cases() -> list[tuple[str, str, str, dict, dict | None, str]]:
    """(name, kind, description, input, preimages, layout) in manifest order.

    ``layout`` "hand" keeps each member of the root on one line; "pretty" is
    the indented layout.
    """
    flat = payload_capsule("spec-flat-digest", "2026-09-13T00:00:01Z", "agent_input_digest", FLAT)
    nested = nested_output_capsule()
    unicode = payload_capsule("spec-unicode-digest", "2026-09-13T00:00:03Z", "agent_input_digest", UNICODE)
    chain = capsule("spec-v4-chain", "2026-09-13T00:00:00Z", ledger_mode="chained",
                    chain={"parent_capsule_id": "a" * 64, "relation": "confirms"})
    null_empty = capsule("spec-v4-null-empty", "2026-09-13T00:00:00Z",
                         extension={"empty_array": [], "empty_object": {}, "null_value": None})

    def declaration(value) -> dict:
        # The null-and-empty Capsule without its extension, carrying that Capsule's id.
        out = {key: val for key, val in null_empty.items() if key != "extension"}
        out["canonicalization_id"] = value
        return out

    return [
        ("spec-derived-flat-payload-digest", "positive",
         "Format 4 commits a flat agent_input value with SHA-256(JCS(value)).",
         flat, payload_preimages("agent_input_digest", FLAT, flat), "hand"),
        ("spec-derived-nested-payload-digest", "positive",
         "Format 4 commits a nested agent_output value, including objects inside an array.",
         nested, payload_preimages("agent_output_digest", NESTED, nested), "hand"),
        ("spec-derived-unicode-payload-digest", "positive",
         "RFC 8785 string serialization preserves non-BMP and solidus characters while escaping U+0001.",
         unicode, payload_preimages("agent_input_digest", UNICODE, unicode), "hand"),
        ("spec-derived-v4-chain", "positive",
         "Format 4 plain JCS commits the chain block to capsule_id.",
         chain, {"capsule_id": preimage(chain)}, "pretty"),
        ("spec-derived-v4-null-empty-members", "positive",
         "Format 4 plain JCS commits present null, empty-array, and empty-object members.",
         null_empty, {"capsule_id": preimage(null_empty)}, "pretty"),
        ("neg-v4-canonicalization-null", "negative",
         "Format 4 with canonicalization_id null fails closed.",
         declaration(None), None, "hand"),
        ("neg-v4-canonicalization-empty", "negative",
         "Format 4 with an empty canonicalization_id fails closed.",
         declaration(""), None, "hand"),
    ]


def main() -> None:
    entries = []
    for name, kind, description, cap, preimages, layout in cases():
        result = expected(cap, description, kind, preimages)
        directory = OUT / name
        directory.mkdir(exist_ok=True)
        if layout == "hand":
            text_in = hand_dumps(cap)
            # The released negatives indent their expected result in full.
            text_out = hand_dumps(result, expand=[("canonical_preimages",)]) if preimages else dumps(result)
        else:
            text_in, text_out = dumps(cap), dumps(result)
        (directory / "input.json").write_text(text_in, encoding="utf-8")
        (directory / "expected.json").write_text(text_out, encoding="utf-8")
        entries.append({"name": name, "kind": kind, "description": description, "provenance": PROVENANCE})
    append_cases(OUT / "vectors.json", entries)
    print(f"wrote {len(entries)} spec-derived vectors to {OUT}")


if __name__ == "__main__":
    main()
