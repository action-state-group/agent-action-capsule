#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the salted JSON-DIGEST commitment vectors (informative).

The construction, identifier ``sha256-jcs-nonce256``, is described in
``docs/salted-digest-commitment.md``. A producer commits to a text ``T`` with
a 256-bit nonce ``N`` (64 lowercase hex characters):

    commitment = JSON-DIGEST({"nonce": N, "text": T})

JSON-DIGEST is the base profile's rule: lowercase-hex SHA-256 of
``UTF8(JCS(value))`` (RFC 8785). The commitment is opened by disclosing the
object ``{"nonce": N, "text": T}``, and the opening is checked exactly as
Disclosure Envelope DE-3 checks a disclosed value: recompute JSON-DIGEST of
it and compare.

Every case carries its opening and the literal JCS string of the opening, so a
reader recomputes every commitment without running this script. Nothing here
imports a repository implementation.

Cases:

* ``pos-*``: three openings and their commitments. The texts are illustrative;
  two carry non-ASCII characters and one a newline, so RFC 8785 string
  escaping is exercised.
* ``neg-*``: five openings, each paired with the commitment of the positive it
  names (``against``). None of them opens it: an edited text, another nonce,
  the nonce in upper case, an empty nonce, and one trailing space added.
* ``equality``: the same nonce and text committed twice give the same
  commitment, so a producer that reuses a nonce makes equal texts visibly
  equal (and different texts visibly different).

Output: ``vectors/salted-digest-commitment/`` (or ``--out DIR``).
Deterministic: no clock, no randomness, no keys. The nonces are fixed test
values, not secrets. ``README.md`` is hand-written; when present in the output
directory it is included in ``SHA256SUMS`` but never rewritten.
Dependencies: the standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "salted-digest-commitment"
SET = "aac-salted-digest-commitment-v1"
IDENTIFIER = "sha256-jcs-nonce256"
NOTE = "docs/salted-digest-commitment.md"
STATUS = ("INFORMATIVE: describes a construction a profile may use; it registers nothing "
          "and places no requirement on producers.")
NONCE = re.compile(r"^[0-9a-f]{64}$")

N_A = "ab" * 32
N_B = "22" * 32
N_C = "33" * 32
TEXT_A = "412.00 USD"
TEXT_B = "Proceed with the €412.00 order?\nReason: within your limit."
TEXT_C = "Yes, go ahead — that's fine."

POSITIVES = [
    ("pos-ascii", N_A, TEXT_A,
     "ASCII text."),
    ("pos-non-ascii-newline", N_B, TEXT_B,
     "Text with a non-ASCII character (U+20AC) and a newline, which JCS escapes as \\n."),
    ("pos-non-ascii-punctuation", N_C, TEXT_C,
     "Text with U+2014 and an apostrophe, which JCS leaves unescaped."),
]

NEGATIVES = [
    ("neg-text-edited", "pos-non-ascii-punctuation", N_C, "Yes, go ahead — that's fine!",
     "The disclosed text differs in its last character."),
    ("neg-nonce-other", "pos-non-ascii-punctuation", N_B, TEXT_C,
     "The right text with a different (well-formed) nonce."),
    ("neg-nonce-uppercase", "pos-ascii", N_A.upper(), TEXT_A,
     "The right nonce written in upper case; JCS does not case-fold strings."),
    ("neg-nonce-empty", "pos-non-ascii-punctuation", "", TEXT_C,
     "The right text with the nonce left empty."),
    ("neg-trailing-space", "pos-non-ascii-newline", N_B, TEXT_B + " ",
     "The disclosed text has one trailing space added."),
]


def jcs(value: Any) -> str:
    """RFC 8785 for the value space these vectors use (objects of string members, ASCII keys).

    With ASCII keys, UTF-16 code-unit order equals code-point order, so
    ``sort_keys`` is the RFC 8785 member order, and ``json.dumps`` escapes
    strings as RFC 8785 does when ``ensure_ascii`` is off.
    """
    if not isinstance(value, dict) or not all(isinstance(k, str) and k.isascii() and isinstance(v, str)
                                              for k, v in value.items()):
        raise TypeError("an opening is an object of string members with ASCII keys")
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_digest(value: Any) -> str:
    return sha256_hex(jcs(value).encode("utf-8"))


def opening(nonce: str, text: str) -> dict:
    return {"nonce": nonce, "text": text}


def cases() -> dict:
    positive = []
    by_id = {}
    for case_id, nonce, text, description in POSITIVES:
        if not NONCE.match(nonce):
            raise ValueError(f"{case_id}: positive nonce is not 64 lowercase hex characters")
        o = opening(nonce, text)
        commitment = json_digest(o)
        positive.append({"id": case_id, "description": description, "opening": o,
                         "opening_jcs": jcs(o), "commitment": commitment, "expected": "match"})
        by_id[case_id] = commitment
    negative = []
    for case_id, against, nonce, text, description in NEGATIVES:
        o = opening(nonce, text)
        recomputed = json_digest(o)
        if recomputed == by_id[against]:
            raise ValueError(f"{case_id} opens {against}: the negative is not negative")
        negative.append({"id": case_id, "description": description, "against": against,
                         "commitment": by_id[against], "opening": o, "opening_jcs": jcs(o),
                         "recomputed": recomputed, "expected": "mismatch"})
    first = json_digest(opening(N_B, TEXT_B))
    second = json_digest(opening(N_B, TEXT_B))
    equality = {"id": "equality-same-nonce-same-text", "nonce": N_B, "text": TEXT_B,
                "first": first, "second": second, "equal": first == second}
    return {"positive": positive, "negative": negative, "equality": equality}


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build() -> dict[str, bytes]:
    c = cases()
    count = len(c["positive"]) + len(c["negative"]) + 1
    files = {
        "vectors.json": _dump({
            "set": SET,
            "status": STATUS,
            "provenance": "spec-derived",
            "identifier": IDENTIFIER,
            "note": NOTE,
            "rules": {
                "json_digest": "lowercase hex SHA-256 of UTF8(JCS(value)) (RFC 8785), no member filtering",
                "nonce": "256 bits as 64 lowercase hex characters",
                "commitment": 'json_digest({"nonce": N, "text": T})',
                "opening": '{"nonce": N, "text": T}, checked as Disclosure Envelope DE-3 checks a disclosed value',
            },
            "count": count,
            **c,
        }),
    }
    files["manifest.json"] = _dump({
        "set": SET,
        "status": STATUS,
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_salted_digest_commitment_vectors.py",
        "note": NOTE,
        "files": [{"path": name, "sha256": sha256_hex(data), "count": json.loads(data).get("count")}
                  for name, data in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
    lines = [f"{sha256_hex(p.read_bytes())}  {p.name}"
             for p in sorted(out.iterdir()) if p.is_file() and p.name != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    write(parser.parse_args().out)


if __name__ == "__main__":
    main()
