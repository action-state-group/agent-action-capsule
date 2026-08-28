# SPDX-License-Identifier: BSD-3-Clause
"""Generate the 24 canonical differential vectors in ../../test-vectors/.

These exercise canonicalization paths that the 32 frozen capsule vectors do not
reach. Source: Joel Hillier (Certisyn), DISCRIMINATING list from
conformance/runners/run_aac_vectors.py (feat/revision-02-canonicalization).

Attribution: the discriminating input set is Joel Hillier's work.
This script computes our independently-derived expected values and writes them
in AAC vector-dir format.

Run: cd python && python -m scripts.generate_canonical_differential
"""
from __future__ import annotations

import json
from pathlib import Path

from agent_action_capsule import canonical

OUT = Path(__file__).resolve().parents[2] / "test-vectors"

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
_SOH     = chr(0x01)      # U+0001 SOH (control char, not in named-shortcut set)

DISCRIMINATING = [
    ("canonical-null-member-removed",
     {"a": "1", "b": None}),
    ("canonical-empty-object-removed",
     {"a": "1", "b": {}}),
    ("canonical-empty-array-removed",
     {"a": "1", "b": []}),
    ("canonical-object-emptied-by-normalization",
     {"a": "1", "b": {"c": None}}),
    ("canonical-nested-two-deep-emptied",
     {"a": "1", "b": {"c": {"d": None}}}),
    ("canonical-array-of-objects-normalized",
     {"a": [{"x": None, "y": "1"}, {"z": "2"}]}),
    ("canonical-array-preserved-not-sorted",
     {"a": ["b", "a", "c"]}),
    ("canonical-nested-member-named-capsule-id",
     {"a": {"capsule_id": "inner"}}),
    ("canonical-nested-member-named-chain",
     {"a": {"chain": "inner"}}),
    # UTF-16 key ordering: D83D (first surrogate of emoji) > FF3A (fullwidth Z)
    # so emoji key sorts AFTER fullwidth Z.
    ("canonical-key-sort-utf16-vs-codepoint",
     {_EMOJI: "hi", _FWZED: "wide"}),
    # JCS does not unicode-normalize. NFD key (A + combining ring) has first
    # UTF-16 code unit U+0041, so it sorts before B (U+0042). The precomposed
    # NFC form (U+00C5) would sort after B because 00C5 > 0042.
    ("canonical-key-nfc-vs-nfd",
     {_NDC_A: "combining", "B": "plain"}),
    # All six mandatory JCS escape sequences in one string value.
    ("canonical-string-escapes",
     {"a": "q" + _DQUOTE + "b" + _BSLASH + "s" + _BS + _TAB + _LF + _FF + _CR}),
    # Control char U+0001 (not in named-shortcut set): serialized as .
    ("canonical-control-char-below-0x20",
     {"a": "x" + _SOH + "y"}),
    ("canonical-non-bmp-value",
     {"a": _EMOJI}),
    ("canonical-solidus-not-escaped",
     {"a": "a/b"}),
    ("canonical-integer-zero",
     {"a": 0}),
    ("canonical-integer-negative",
     {"a": -1}),
    ("canonical-integer-at-safe-max",
     {"a": 9007199254740991}),
    ("canonical-integer-above-safe-max",
     {"a": 9007199254740992}),
    ("canonical-integer-at-safe-min",
     {"a": -9007199254740991}),
    ("canonical-float-in-value",
     {"a": 1.5}),
    ("canonical-float-integral-valued",
     {"a": 2.0}),
    ("canonical-bool-and-deep-nesting",
     {"a": True, "b": {"c": {"d": {"e": "f"}}}}),
    ("canonical-all-members-removed",
     {"a": None, "b": [], "c": {}}),
]

DESCRIPTIONS = {
    "canonical-null-member-removed":
        "normalize() removes a null-valued member (S:2 absent-field normalization)",
    "canonical-empty-object-removed":
        "normalize() removes an empty-object member (S:2 absent-field normalization)",
    "canonical-empty-array-removed":
        "normalize() removes an empty-array member (S:2 absent-field normalization)",
    "canonical-object-emptied-by-normalization":
        "normalize() bottom-up: object becomes empty after null member removed; parent removes it",
    "canonical-nested-two-deep-emptied":
        "normalize() bottom-up two levels: d->c->b all emptied and removed",
    "canonical-array-of-objects-normalized":
        "normalize() recurses into array elements; null member in nested object removed",
    "canonical-array-preserved-not-sorted":
        "Array elements preserved in insertion order, not sorted (RFC 8785 S:3.2.2)",
    "canonical-nested-member-named-capsule-id":
        "Top-level capsule_id/chain exclusion does not apply to nested members with those names",
    "canonical-nested-member-named-chain":
        "Top-level capsule_id/chain exclusion does not apply to nested members with those names",
    "canonical-key-sort-utf16-vs-codepoint":
        "UTF-16 key ordering: U+1F600 emoji (first surrogate 0xD83D) sorts after U+FF3A (single unit)",
    "canonical-key-nfc-vs-nfd":
        "JCS does not normalize Unicode; NFD key A+U+030A (first unit 0x0041) sorts before B (0x0042)",
    "canonical-string-escapes":
        "JCS mandatory escapes: \\\" \\\\ \\b \\t \\n \\f \\r in a single string value (RFC 8785 S:3.2.2.2)",
    "canonical-control-char-below-0x20":
        "Control char U+0001 not in named-shortcut set: serialized as \\u0001 (RFC 8785 S:3.2.2.2)",
    "canonical-non-bmp-value":
        "Non-BMP char U+1F600 in a string value passes through as UTF-8 (no \\uXXXX escaping needed)",
    "canonical-solidus-not-escaped":
        "Solidus / is NOT escaped in JCS (RFC 8785 S:3.2.2.2 forbids the \\/ escape)",
    "canonical-integer-zero":
        "Integer 0 serialized as '0' (int branch in _jcs_value, S:5.1)",
    "canonical-integer-negative":
        "Negative integer -1 serialized as '-1'",
    "canonical-integer-at-safe-max":
        "Integer at exactly Number.MAX_SAFE_INTEGER = 9007199254740991 accepted (S:5.1 boundary)",
    "canonical-integer-above-safe-max":
        "Integer one above Number.MAX_SAFE_INTEGER raises UnsafeIntegerError (S:5.1 guard)",
    "canonical-integer-at-safe-min":
        "Integer at exactly -Number.MAX_SAFE_INTEGER = -9007199254740991 accepted (S:5.1 boundary)",
    "canonical-float-in-value":
        "Float value raises FloatInDigestError (S:5.1 forbids floats in digest-bearing fields)",
    "canonical-float-integral-valued":
        "Integral-valued float 2.0 raises FloatInDigestError: the guard is a type check, not a value check",
    "canonical-bool-and-deep-nesting":
        "Boolean true and deep object nesting: exercises bool branch and recursive dict serialization",
    "canonical-all-members-removed":
        "After normalization all members removed; capsule_id = SHA-256(JCS({})) = SHA-256('{}')",
}


def generate_expected(name: str, inp: dict) -> dict:
    exc = None
    cap_id = None
    try:
        cap_id = canonical.compute_capsule_id(inp)
    except Exception as e:
        exc = type(e).__name__
    return {
        "kind": "canonical",
        "capsule_id_recomputed": cap_id,
        "exception": exc,
        "description": DESCRIPTIONS[name],
    }


def write_vector(name: str, inp: dict, exp: dict) -> None:
    d = OUT / name
    d.mkdir(exist_ok=True)
    (d / "input.json").write_text(
        json.dumps(inp, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (d / "expected.json").write_text(
        json.dumps(exp, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def main() -> list[dict]:
    cases = []
    for name, inp in DISCRIMINATING:
        exp = generate_expected(name, inp)
        write_vector(name, inp, exp)
        cases.append({"name": name, "kind": "canonical",
                       "description": DESCRIPTIONS[name]})
        status = ("REFUSED:" + exp["exception"]) if exp["exception"] else exp["capsule_id_recomputed"][:20] + "..."
        print(f"  {name:<50} {status}")

    print(f"\n  {len(cases)} canonical vectors written to {OUT}")
    return cases


if __name__ == "__main__":
    main()
