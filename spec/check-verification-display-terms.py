#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
check-verification-display-terms.py

spec/verification-display-v0.md must not cite capsule-viewer, whose
presentation contract defines most of the words a page uses, so it defines
every term it uses in its own section 1 ("Terms"). This script checks that:

  1. UNDEFINED: every term in TERMS that the document uses outside section 1
     is defined there, as a bold label (`**term**`) in that section.

  2. CITATION: the document names no capsule-viewer document or path.

TERMS is the declared list: each term with the patterns that count as a use.
A new term a revision starts using is added here, and the check then requires
its definition.

Usage:
    python spec/check-verification-display-terms.py        # run from repo root
    python check-verification-display-terms.py             # run from spec/ dir
    python spec/check-verification-display-terms.py --self-test

Exit 0: clean. Exit 1: findings with diagnostics.

--self-test runs the check on mutants of the document (a definition removed, a
capsule-viewer citation added) and fails unless each mutant is reported, so the
check is shown to be able to fail.
"""
import re
import sys
from pathlib import Path

DOC = Path(__file__).resolve().parent / "verification-display-v0.md"

# term (as its bold label reads, lowercase) -> patterns that count as a use.
TERMS = {
    "bundle": [r"\bbundles?\b"],
    "record": [r"\brecords?\b"],
    "payload": [r"\bpayloads?\b"],
    "extension": [r"\bextensions?\b"],
    "disclosure": [r"\bdisclosures?\b", r"\bdisclosed\b"],
    "match": [r"\bmatch\b"],
    "checkpoint": [r"\bcheckpoints?\b"],
    "witness receipt": [r"\bwitness receipts?\b"],
    "countersignature": [r"\bcountersignatures?\b"],
    "graph closure": [r"\bgraph closure\b"],
    "interval coverage": [r"\binterval\s+coverage\b"],
    "per-record membership": [r"\bper-record membership\b"],
    "producer": [r"\bproducers?\b"],
    "verifier": [r"\bverifiers?\b"],
    "verification result": [r"\bverification result\b"],
    "strict verdict": [r"\bstrict verdict\b"],
    "viewer": [r"\bviewers?\b"],
    "runtime": [r"\bruntimes?\b"],
    "core": [r"\bcore\b"],
    "page": [r"\bpages?\b"],
    "header chrome": [r"\bheader chrome\b"],
    "banner": [r"\bbanners?\b"],
    "verification state": [r"\bverification state\b"],
    "details line": [r"\bdetails line\b"],
    "verification page": [r"\bverification page\b"],
    "check": [r"\bchecks?\b"],
    "check list": [r"\bcheck[- ]lists?\b"],
    "full verifier": [r"\bfull\s+verifier\b"],
    "module": [r"\bmodules?\b"],
    "module region": [r"\bmodule regions?\b"],
    "row": [r"\brows?\b"],
    "row model": [r"\brow model\b"],
    "host": [r"\bhosts?\b"],
    "refusal": [r"\brefusals?\b", r"\brefuse[sd]?\b"],
    "verified": [r"\bverified\b"],
    "wording pack": [r"\bwording packs?\b"],
    "presentation words": [r"\bpresentation words\b"],
    "evidentiary words": [r"\bevidentiary words\b"],
    "relying party": [r"\brelying party\b"],
    "commitment": [r"\bcommitments?\b"],
    "opening": [r"\bopenings?\b"],
    "jcs": [r"\bJCS\b"],
    "digest-committed": [r"\bdigest-committed\b"],
    "theme": [r"\btheme\b"],
    "locale": [r"\blocale\b"],
    "depth": [r"\bdepth\b"],
}

CITATION = re.compile(r"capsule-viewer", re.IGNORECASE)


def split(text: str):
    """Return (terms section, rest), with fenced code removed from the rest."""
    m = re.search(r"^## 1\. Terms\n(.*?)(?=^## )", text, re.S | re.M)
    if m is None:
        return None, text
    rest = text[: m.start()] + text[m.end():]
    rest = re.sub(r"^```.*?^```", "", rest, flags=re.S | re.M)
    return m.group(1), rest


def defined(terms_section: str) -> set:
    labels = re.findall(r"\*\*(.+?)\*\*", terms_section, re.S)
    return {re.sub(r"\s+", " ", label).strip().lower() for label in labels}


def findings(text: str) -> list:
    out = []
    section, rest = split(text)
    if section is None:
        return ["MISSING-TERMS: no '## 1. Terms' section"]
    have = defined(section)
    for term, patterns in TERMS.items():
        used = [p for p in patterns if re.search(p, rest, re.IGNORECASE)]
        if used and term not in have:
            out.append(f"UNDEFINED {term!r}: used ({used[0]}) but not defined in section 1")
    for number, line in enumerate(text.splitlines(), start=1):
        if CITATION.search(line):
            out.append(f"CITATION line {number}: names capsule-viewer: {line.strip()!r}")
    return out


def self_test(text: str) -> list:
    problems = []
    mutant = re.sub(r"^- \*\*Banner\*\*:.*\n", "", text, count=1, flags=re.M)
    if mutant == text or not any("UNDEFINED 'banner'" in f for f in findings(mutant)):
        problems.append("a document with the 'Banner' definition removed was not reported")
    mutant = text + "\nSee capsule-viewer's `spec/presentation-contract-v0.md`.\n"
    if not any(f.startswith("CITATION") for f in findings(mutant)):
        problems.append("a document citing capsule-viewer was not reported")
    return problems


def main() -> int:
    text = DOC.read_text(encoding="utf-8")
    if "--self-test" in sys.argv[1:]:
        problems = self_test(text)
        for p in problems:
            print(f"SELF-TEST FAIL: {p}")
        if not problems:
            print("self-test OK: both mutants reported")
        return 1 if problems else 0
    found = findings(text)
    for f in found:
        print(f)
    if found:
        print(f"{len(found)} finding(s) in {DOC.name}")
        return 1
    print(f"OK: every declared term {DOC.name} uses is defined in its section 1")
    return 0


if __name__ == "__main__":
    sys.exit(main())
