#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
check_verdict_class_refs.py

Enforces two properties across all spec drafts that are not the authoritative
source of the verdict_class vocabulary (I-D.mih-scitt-agent-action-capsule):

  1. VERBATIM-CLAIM: no draft claims 'verbatim' correspondence with the
     verdict_class vocabulary or with a "disposition vocabulary".

  2. INCOMPLETE-ENUMERATION: no draft lists 4 or more seeded verdict_class
     values in a short span without covering the complete seeded set.

Usage:
    python spec/check_verdict_class_refs.py        # run from repo root
    python check_verdict_class_refs.py             # run from spec/ dir

Exit 0: clean. Exit 1: findings with diagnostics.

Mutant-failure guarantee (QUEUE_PROTOCOL §7): before the
bilateral-disposition-vocabulary-drift fix this script reports the four
missing values (hitl_dispatched, engine_failure, needs_decision, resolved)
and exits 1. After the fix it exits 0. Run against both states to confirm
the check can actually fail.
"""
import re
import sys
from pathlib import Path

SPEC_DIR = (Path(__file__).parent / "spec"
            if not Path(__file__).parent.name == "spec"
            else Path(__file__).parent)

# Authoritative source: the latest AAC main draft (not sel-disc, not bilateral).
# The verdict_class table is the same across revisions; we read the highest one.
_AAC_PATTERN = re.compile(
    r"^draft-mih-scitt-agent-action-capsule-\d{2}\.md$"
)
_NON_AUTHORITATIVE_PATTERN = re.compile(
    r"^draft-mih-(?!scitt-agent-action-capsule-\d{2}\.md).*\.md$"
)


def _find_aac_draft(spec_dir: Path) -> Path:
    candidates = sorted(
        p for p in spec_dir.glob("draft-mih-scitt-agent-action-capsule-??.md")
    )
    if not candidates:
        raise FileNotFoundError(
            f"No draft-mih-scitt-agent-action-capsule-NN.md found in {spec_dir}"
        )
    return candidates[-1]  # highest revision


def _parse_seeded_values(text: str) -> list[str]:
    """
    Extract seeded verdict_class values from the table that follows the header
    line containing 'verdict_class | Meaning'.
    """
    values: list[str] = []
    in_table = False
    for line in text.splitlines():
        stripped = line.strip()
        if re.search(r"\|\s*verdict_class\s*\|\s*Meaning", stripped):
            in_table = True
            continue
        if in_table:
            if not stripped.startswith("|"):
                break
            m = re.match(r"\|\s*([a-z_]+)\s*\|", stripped)
            if m:
                values.append(m.group(1))
    return values


def _check_draft(
    path: Path, seeded: list[str], check_enumeration: bool = True
) -> list[str]:
    text = path.read_text(encoding="utf-8")
    name = path.name
    findings: list[str] = []

    # --- Check 1: "verbatim" claim near verdict/disposition/vocabulary ---
    for i, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        if "verbatim" in low and any(
            w in low for w in ("verdict", "disposition", "vocabulary")
        ):
            findings.append(
                f"  VERBATIM-CLAIM  {name}:{i}: {line.strip()}"
            )

    if not check_enumeration:
        return findings

    # --- Check 2: incomplete enumeration (draft files only) ---
    # Scan overlapping 6-line windows; suppress duplicate reports for the
    # same offending span.  Windows that explicitly label their contents as
    # examples ("e.g.", "for example", "such as") are skipped — an
    # illustrative list is not an attempt to be exhaustive.
    lines = text.splitlines()
    reported_start: int = -1
    for start in range(len(lines)):
        if start <= reported_start:
            continue
        window = " ".join(lines[start : start + 6])
        window_low = window.lower()
        if any(phrase in window_low
               for phrase in ("e.g.", "for example", "such as", "illustrative")):
            continue
        hits = [v for v in seeded if re.search(r"\b" + v + r"\b", window)]
        if len(hits) >= 4:
            missing = sorted(set(seeded) - set(hits))
            if missing:
                reported_start = start + 5
                findings.append(
                    f"  INCOMPLETE-ENUMERATION  {name}:{start + 1}: "
                    f"found {len(hits)}/{len(seeded)} seeded values; "
                    f"missing: {', '.join(missing)}\n"
                    f"    context: {lines[start].strip()[:120]}"
                )

    return findings


def main(argv: list[str] | None = None) -> int:
    spec_dir = Path(argv[0]) if (argv or sys.argv[1:]) else SPEC_DIR

    try:
        aac_path = _find_aac_draft(spec_dir)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}")
        return 2

    seeded = _parse_seeded_values(aac_path.read_text(encoding="utf-8"))
    if len(seeded) < 8:
        print(
            f"ERROR: too few verdict_class values parsed from {aac_path.name}; "
            f"got {seeded!r} — check the table format"
        )
        return 2

    print(
        f"verdict_class seeded values ({len(seeded)}) from {aac_path.name}:\n"
        f"  {', '.join(seeded)}"
    )

    all_findings: list[str] = []
    checked = 0
    for draft_path in sorted(spec_dir.glob("*.md")):
        if _AAC_PATTERN.match(draft_path.name):
            continue  # authoritative source; not checked here
        if draft_path.name.startswith("_"):
            continue  # internal drafts
        # REGISTRY.md and similar companion files are authoritative registry
        # definitions, not drafts that could claim "verbatim" correspondence.
        # Restrict the INCOMPLETE-ENUMERATION check to draft-*.md files.
        is_draft = draft_path.name.startswith("draft-")
        checked += 1
        found = _check_draft(draft_path, seeded, check_enumeration=is_draft)
        if found:
            all_findings.append(f"\n{draft_path.name}:")
            all_findings.extend(found)

    if all_findings:
        print("\nFAIL — findings:")
        print("\n".join(all_findings))
        return 1

    print(f"\nOK — {checked} draft(s) checked, no findings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
