#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
check_evidence_dataset_examples.py

Runs every case of vectors/evidence-dataset/ (written by
generate_dataset_examples.py) through the Python reference, evidence_dataset.py:

  1. POSITIVE: check_dataset accepts the case's dataset.
  2. NEGATIVE: check_dataset refuses it with the reason cases.json names, the
     reason go/evidenceplan must give too.
  3. LOAD-BEARING: each negative's base positive is accepted, so the one
     change the generator made is what the gate refuses.
  4. REPRODUCIBLE: every committed file is what the generator writes now.

Exit 0: every check passed. Exit 1: a finding was printed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evidence_dataset import REASONS, DatasetError, check_dataset  # noqa: E402
from generate_dataset_examples import OUT_DIR, cases  # noqa: E402


def _load(name: str, part: str) -> object:
    return json.loads((OUT_DIR / f"{name}.{part}.json").read_text(encoding="utf-8"))


def _verdict(name: str) -> str:
    try:
        check_dataset(_load(name, "plan"), _load(name, "dataset"), _load(name, "records"))
    except DatasetError as exc:
        return exc.reason
    return "valid"


def main() -> int:
    findings = []
    manifest = json.loads((OUT_DIR / "cases.json").read_text(encoding="utf-8"))
    names = {entry["name"] for entry in manifest}
    for entry in manifest:
        name, expect = entry["name"], entry["expect"]
        if expect != "valid" and expect not in REASONS:
            findings.append(f"UNKNOWN-REASON {name}: {expect}")
            continue
        got = _verdict(name)
        if got != expect:
            findings.append(f"WRONG-VERDICT {name}: expected {expect}, got {got}")
        else:
            print(f"OK  {expect:<17} {name}")
        base = entry.get("base")
        if expect != "valid":
            if base not in names or _verdict(base) != "valid":
                findings.append(f"NOT-LOAD-BEARING {name}: its base {base!r} is not an accepted positive")
        elif base is not None:
            findings.append(f"POSITIVE-WITH-BASE {name}")

    for reason in REASONS:
        if not any(entry["expect"] == reason for entry in manifest):
            findings.append(f"REASON-WITHOUT-VECTOR {reason}")

    generated = cases()
    if [n for n, *_ in generated] != [entry["name"] for entry in manifest]:
        findings.append("STALE cases.json: rerun generate_dataset_examples.py")
    for name, _base, _expect, case in generated:
        for part in ("plan", "records", "dataset"):
            path = OUT_DIR / f"{name}.{part}.json"
            want = json.dumps(case[part], indent=2, sort_keys=True) + "\n"
            if not path.exists() or path.read_text(encoding="utf-8") != want:
                findings.append(f"STALE {path.name}: rerun generate_dataset_examples.py")

    if findings:
        for finding in findings:
            print(f"FINDING  {finding}")
        return 1
    positives = sum(1 for entry in manifest if entry["expect"] == "valid")
    print(f"\nOK — {positives} positive and {len(manifest) - positives} negative dataset case(s), "
          f"every reason covered, each negative's base accepted, and the files reproduce.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
