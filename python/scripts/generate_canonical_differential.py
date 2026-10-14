# SPDX-License-Identifier: BSD-3-Clause
"""Generate the canonical differential vectors in ../../vectors/capsule/.

These exercise canonicalization paths that the base capsule vectors do not
reach. Source: Joel Hillier (Certisyn), DISCRIMINATING list from
conformance/runners/run_aac_vectors.py (feat/revision-02-canonicalization).

Attribution: the discriminating input set is Joel Hillier's work.
This script computes our independently-derived expected values and writes them
in AAC vector-dir format.

Each value sits at ``extension.canonical_test_value`` of an otherwise fixed
format-4 Capsule (spec_version -04, part of the released compatibility set),
so the RFC 8785 path under test is inside the capsule_id preimage, which
expected.json records. #99 dropped the original inputs that tested the
withdrawn format-2 normalization or float and unsafe-integer refusal, and
those whose string paths spec-derived-unicode-payload-digest now covers
(generate_spec_derived_vectors.py).

Run: cd python && python scripts/generate_canonical_differential.py
"""
from __future__ import annotations

import sys
from pathlib import Path

from agent_action_capsule import compute_capsule_id, verify

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vector_layout import append_cases, dumps, preimage, sort_members  # noqa: E402

OUT = Path(__file__).resolve().parents[2] / "vectors/capsule"
SPEC = "draft-mih-scitt-agent-action-capsule-04"
PROVENANCE = "spec-derived"

# Build tricky inputs with chr() to avoid encoding ambiguity in this source.
# Notation used in comments: U+XXXX.
_EMOJI   = chr(0x1F600)   # U+1F600 GRINNING FACE (two UTF-16 surrogates: D83D DE00)
_FWZED   = chr(0xFF3A)    # U+FF3A FULLWIDTH LATIN CAPITAL LETTER Z
_NDC_A   = "A" + chr(0x030A)  # NFD Å: A (U+0041) + COMBINING RING ABOVE (U+030A)
_DQUOTE  = chr(0x22)      # "
_BSLASH  = chr(0x5C)      # \
_BS      = chr(0x08)      # backspace  (\b)
_TAB     = chr(0x09)      # tab        (\t)
_LF      = chr(0x0A)      # newline    (\n)
_FF      = chr(0x0C)      # form feed  (\f)
_CR      = chr(0x0D)      # carriage return (\r)

# Manifest order. Each value keeps its member order: canonicalization, not
# the input file, decides the order inside the preimage.
DISCRIMINATING = [
    ("canonical-array-preserved-not-sorted",
     {"a": ["b", "a", "c"]},
     "Array elements preserved in insertion order, not sorted (RFC 8785 S:3.2.2)"),
    ("canonical-bool-and-deep-nesting",
     {"a": True, "b": {"c": {"d": {"e": "f"}}}},
     "Boolean true and deep object nesting: exercises bool branch and recursive dict serialization"),
    ("canonical-integer-at-safe-max",
     {"a": 9007199254740991},
     "Integer at exactly Number.MAX_SAFE_INTEGER = 9007199254740991 accepted (S:5.1 boundary)"),
    ("canonical-integer-at-safe-min",
     {"a": -9007199254740991},
     "Integer at exactly -Number.MAX_SAFE_INTEGER = -9007199254740991 accepted (S:5.1 boundary)"),
    ("canonical-integer-negative",
     {"a": -1},
     "Negative integer -1 serialized as '-1'"),
    ("canonical-integer-zero",
     {"a": 0},
     "Integer 0 serialized as '0' (int branch in _jcs_value, S:5.1)"),
    # JCS does not unicode-normalize. NFD key (A + combining ring) has first
    # UTF-16 code unit U+0041, so it sorts before B (U+0042). The precomposed
    # NFC form (U+00C5) would sort after B because 00C5 > 0042.
    ("canonical-key-nfc-vs-nfd",
     {_NDC_A: "combining", "B": "plain"},
     "JCS does not normalize Unicode; NFD key A+U+030A (first unit 0x0041) sorts before B (0x0042)"),
    # UTF-16 key ordering: D83D (first surrogate of emoji) > FF3A (fullwidth Z)
    # so emoji key sorts AFTER fullwidth Z.
    ("canonical-key-sort-utf16-vs-codepoint",
     {_EMOJI: "hi", _FWZED: "wide"},
     "UTF-16 key ordering: U+1F600 emoji (first surrogate 0xD83D) sorts after U+FF3A (single unit)"),
    ("canonical-nested-member-named-capsule-id",
     {"a": {"capsule_id": "inner"}},
     "Top-level capsule_id/chain exclusion does not apply to nested members with those names"),
    ("canonical-nested-member-named-chain",
     {"a": {"chain": "inner"}},
     "Top-level capsule_id/chain exclusion does not apply to nested members with those names"),
    # All six mandatory JCS escape sequences in one string value.
    ("canonical-string-escapes",
     {"a": "q" + _DQUOTE + "b" + _BSLASH + "s" + _BS + _TAB + _LF + _FF + _CR},
     'JCS mandatory escapes: \\" \\\\ \\b \\t \\n \\f \\r in a single string value (RFC 8785 S:3.2.2.2)'),
]


def capsule(name: str, value: dict) -> dict:
    """The fixed format-4 Capsule carrying ``value``, members sorted around it."""
    cap = sort_members({
        "action_id": name,
        "action_type": "decide",
        "assurance": {"attestation_mode": "self_attested", "effect_mode": "not_applicable", "ledger_mode": "standalone"},
        "canonicalization_id": "jcs",
        "capsule_id": None,
        "developer": "conformance-vector@v1",
        "disposition": {"approver": "policy", "decision": "accept", "human_disposed": False, "verdict_class": "executed"},
        "extension": None,
        "format_version": "4",
        "operator": "AAC-CONFORMANCE",
        "spec_version": SPEC,
        "timestamp": "2026-09-13T00:00:00Z",
    })
    cap["extension"] = {"canonical_test_value": value}
    cap["capsule_id"] = compute_capsule_id(cap)
    return cap


def expected(cap: dict, description: str) -> dict:
    result = verify(cap)
    if not result.ok:
        raise SystemExit(f"{cap['action_id']}: the reference verify() rejected a positive case")
    return sort_members({
        "canonical_preimages": {"capsule_id": preimage(cap)},
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
    })


def main() -> None:
    entries = []
    for name, value, description in DISCRIMINATING:
        description = f"{description} under explicit format-4 plain JCS."
        cap = capsule(name, value)
        directory = OUT / name
        directory.mkdir(exist_ok=True)
        (directory / "input.json").write_text(dumps(cap), encoding="utf-8")
        (directory / "expected.json").write_text(dumps(expected(cap, description)), encoding="utf-8")
        entries.append({"name": name, "kind": "positive", "description": description, "provenance": PROVENANCE})
    append_cases(OUT / "vectors.json", entries)
    print(f"wrote {len(entries)} canonical vectors to {OUT}")


if __name__ == "__main__":
    main()
