#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the JSON nesting-limit vectors in ../../vectors/json-nesting/.

Every reader and canonicalizer in this repository accepts objects and arrays
nested up to 128 levels deep (``[]`` is one level, ``[[]]`` two) and refuses
anything deeper as it refuses other malformed input (#498). Before, Go read
Evidence Request objects 33 deep, Rust 128, TypeScript 1001 and Python up to
its recursion limit, so one document could be read by one verifier and not by
another.

Each case is JSON text with its nesting ``depth`` and whether a reader
``accept``s it. An accepted case's text is already its RFC 8785 form, and
``jcs_sha256`` is the SHA-256 of that form. A refused case names in ``wraps``
the accepted case whose text it wraps in one more array or object, so an
implementation whose own decoder cannot build the deeper value can build it
from the accepted one, to check that canonicalization refuses it too.

Output: ``cases.json``, ``manifest.json`` and ``SHA256SUMS`` in ``vectors/json-nesting/`` (or
``--out DIR``). ``README.md`` is hand-written; when present it is included in
``SHA256SUMS`` but never rewritten. Deterministic: no clock, randomness or
keys.

Run: cd python && python scripts/generate_json_nesting_vectors.py
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from agent_action_capsule.canonical import MAX_NESTING_DEPTH, jcs

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vector_layout import dumps  # noqa: E402

OUT = Path(__file__).resolve().parents[2] / "vectors" / "json-nesting"

# Brackets, braces and an escaped quote inside strings, which do not nest.
LEAF = '"]}[{\\"["'
# A member name ending in an escaped backslash: the quote after it closes the string.
AFTER_ESCAPED_BACKSLASH = '{"k[\\\\":' + "[" * 127 + "]" * 127 + "}"
BRACKETS_IN_STRING = '{"s":"' + "[{" * 100 + '\\"' + "]}" * 3 + '"}'


def arrays(depth: int) -> str:
    return "[" * depth + "]" * depth


def objects(depth: int) -> str:
    return '{"a":' * (depth - 1) + "{}" + "}" * (depth - 1)


def mixed(depth: int) -> str:
    """Objects and arrays alternating, an object outermost, around LEAF."""
    text = LEAF
    for level in range(depth, 0, -1):
        text = '{"a":' + text + "}" if level % 2 == 1 else "[" + text + "]"
    return text


def accepted(case_id: str, description: str, text: str, depth: int) -> dict:
    value = json.loads(text)
    canonical = jcs(value)
    if canonical != text.encode("utf-8"):
        raise SystemExit(f"{case_id}: the text is not its own RFC 8785 form")
    return {
        "id": case_id,
        "description": description,
        "depth": depth,
        "accept": True,
        "json": text,
        "jcs_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def refused(case_id: str, description: str, text: str, depth: int, wraps: str) -> dict:
    return {
        "id": case_id,
        "description": description,
        "depth": depth,
        "accept": False,
        "wraps": wraps,
        "json": text,
    }


def cases() -> list[dict]:
    limit = MAX_NESTING_DEPTH
    past = limit + 1
    out = [
        accepted("pos-arrays-at-limit", f"{limit} nested arrays: accepted.", arrays(limit), limit),
        refused("neg-arrays-past-limit", f"{past} nested arrays: refused as malformed.",
                arrays(past), past, "pos-arrays-at-limit"),
        accepted("pos-objects-at-limit", f"{limit} nested objects, each with one member \"a\": accepted.",
                 objects(limit), limit),
        refused("neg-objects-past-limit",
                f"{past} nested objects: refused as malformed.",
                '{"a":' + objects(limit) + "}", past, "pos-objects-at-limit"),
        accepted("pos-mixed-at-limit",
                 f"{limit} levels, objects and arrays alternating (an object outermost) around a string "
                 "holding brackets, braces and an escaped quote: accepted.",
                 mixed(limit), limit),
        refused("neg-mixed-past-limit",
                f"The {limit}-level mixed case inside one more array, {past} levels: refused as malformed.",
                "[" + mixed(limit) + "]", past, "pos-mixed-at-limit"),
        accepted("pos-brackets-in-string",
                 "One object whose string member holds 200 opening and 6 closing brackets and braces and "
                 "an escaped quote: one level deep, accepted. A reader that counts brackets without "
                 "skipping strings refuses it.",
                 BRACKETS_IN_STRING, 1),
        accepted("pos-after-escaped-backslash",
                 f"One object whose member name ends in an escaped backslash, then {limit - 1} nested "
                 "arrays: the quote after the backslash closes the name, so the arrays count and the "
                 f"value is {limit} levels deep, accepted.",
                 AFTER_ESCAPED_BACKSLASH, limit),
        refused("neg-after-escaped-backslash",
                f"The previous case inside one more array, {past} levels: refused as malformed. A reader "
                "that takes a backslash-quote pair as an escaped quote never leaves the name, misses "
                "the arrays and accepts it.",
                "[" + AFTER_ESCAPED_BACKSLASH + "]", past, "pos-after-escaped-backslash"),
    ]
    for case in out:
        if case["depth"] != _depth(json.loads(case["json"])):
            raise SystemExit(f"{case['id']}: depth {case['depth']} is wrong")
    return out


def _depth(value) -> int:
    if isinstance(value, dict):
        return 1 + max((_depth(v) for v in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_depth(v) for v in value), default=0)
    return 0


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    doc = {
        "description": (
            "JSON nesting limit shared by every implementation (#498): objects and arrays nested "
            f"up to {MAX_NESTING_DEPTH} levels deep are read and canonicalized; deeper text is "
            "refused as malformed, and a deeper value has no RFC 8785 form. Generated by "
            "python/scripts/generate_json_nesting_vectors.py."
        ),
        "max_nesting_depth": MAX_NESTING_DEPTH,
        "cases": cases(),
    }
    text = dumps(doc)
    (out / "cases.json").write_text(text, encoding="utf-8")
    manifest = {
        "spec": "spec/draft-mih-scitt-agent-action-capsule-06.md",
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_json_nesting_vectors.py",
        "files": [{
            "path": "cases.json",
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "count": len(doc["cases"]),
        }],
    }
    (out / "manifest.json").write_text(dumps(manifest), encoding="utf-8")
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}"
             for p in sorted(out.iterdir()) if p.is_file() and p.name != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=OUT)
    write(parser.parse_args().out)


if __name__ == "__main__":
    main()
