#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate ``vectors/cross-language/verify-number-findings.json``.

The fixture pins the ``float_in_digest_field`` and
``unsafe_integer_in_digest_field`` findings every verifier reports for one
record: at most 64 of each kind, in a depth-first walk with object members in
code point order of their keys, each path cut to 256 code points followed by
``...``. The Rust, Python, Go and TypeScript tests each verify ``record`` and
compare those findings, in order, with ``expected``.

``record`` lists its keys out of order (Python keeps insertion order), holds
two keys whose code point and UTF-16 orders differ (U+FF61 and U+1F600), a
key of 301 code points, mostly two-byte, and more than 64 failing numbers of
each kind. ``expected`` is built here from that layout, not by running a
verifier.
"""
from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "vectors" / "cross-language" / "verify-number-findings.json"

MAX_FINDINGS = 64
MAX_CHARS = 256
UNSAFE = 9007199254740993

LONG_KEY = "k" + "é" * 300


def main() -> None:
    record = {
        "z": [1.5] * 70,
        "w": [UNSAFE if i % 2 == 0 else -UNSAFE for i in range(66)],
        LONG_KEY: [0.25],
        "a": {"\U0001f600": 1.5, "n": 1, "t": True, "｡": 0.5, "big": 9007199254740991},
    }
    floats = ["a.｡", "a.\U0001f600", (LONG_KEY + "[0]")[:MAX_CHARS] + "..."]
    floats += [f"z[{i}]" for i in range(MAX_FINDINGS - len(floats))]
    unsafe = [f"w[{i}]" for i in range(MAX_FINDINGS)]
    fixture = {
        "description": (
            "Number findings every verifier reports for record: at most 64 per code, "
            "object members in code point order, paths cut to 256 code points then '...'."
        ),
        "record": record,
        "expected": [{"code": "float_in_digest_field", "path": p} for p in floats]
        + [{"code": "unsafe_integer_in_digest_field", "path": p} for p in unsafe],
    }
    OUT.write_text(json.dumps(fixture, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
