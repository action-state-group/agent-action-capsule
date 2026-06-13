# SPDX-License-Identifier: BSD-3-Clause
"""The six profile registries (§12), sourced from ``spec/REGISTRY.md``.

The seeded values are NOT hard-coded here: they are parsed at load time from the
interim registry of record (``spec/REGISTRY.md``) so the code and the spec cannot
drift. The binding invariant (§4, §12) — unregistered values are informational
and never a rejection — is applied by the verifier, not here; this module only
reports which values are seeded.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

__all__ = ["REGISTRY_NAMES", "load_registries", "find_registry_md"]

# The six registry-governed vocabularies (§4). approver is deliberately NOT here:
# it is a closed enum fixed by the spec (§5.4), not registry-governed.
REGISTRY_NAMES = (
    "verdict_class",
    "disposition.decision",
    "effect.type",
    "irreversibility_class",
    "effect_attestation",
    "chain.relation",
)

_HEADER_RE = re.compile(r"^##\s+\d+\.\s+`([^`]+)`\s*$")
_TICK_RE = re.compile(r"`([^`]+)`")
_OL_ITEM_RE = re.compile(r"^\s*\d+\.\s+`([^`]+)`\s*$")


def find_registry_md(start: Path | None = None) -> Path:
    """Locate ``spec/REGISTRY.md``. Honors AAC_REGISTRY_PATH; otherwise walks up
    from this module looking for a ``spec/REGISTRY.md`` sibling."""
    override = os.environ.get("AAC_REGISTRY_PATH")
    if override:
        return Path(override)
    here = (start or Path(__file__)).resolve()
    for parent in [here, *here.parents]:
        candidate = parent / "spec" / "REGISTRY.md"
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "spec/REGISTRY.md not found by walking up from "
        f"{here}; set AAC_REGISTRY_PATH to point at it"
    )


def _seeded_values_in_section(lines: list[str]) -> list[str]:
    """Extract seeded vocabulary tokens from one registry section.

    Tokens come ONLY from structured loci — table data rows (first column),
    ordered-list items, and an 'Initial contents' line — never from prose
    backticks (which carry guidance, not seeded values).
    """
    values: list[str] = []
    seen: set[str] = set()

    def add(tok: str) -> None:
        if tok not in seen:
            seen.add(tok)
            values.append(tok)

    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        stripped = line.strip()
        # Markdown table data row: first cell is a backticked token, and the row
        # is neither the header (first cell "Value") nor the |---| separator.
        if stripped.startswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            first = cells[0] if cells else ""
            if first and first != "Value" and not (set(first) <= set("-: ")):
                m = _TICK_RE.fullmatch(first)
                if m:
                    add(m.group(1))
            i += 1
            continue
        # Ordered-list item: "N. `token`"
        m = _OL_ITEM_RE.match(line)
        if m:
            add(m.group(1))
            i += 1
            continue
        # Inline "Initial contents ...: `a`, `b`, ..." — the value list may wrap
        # across lines; collect backticks from the marker line through the rest
        # of the paragraph (until a blank line).
        if "Initial contents" in stripped:
            while i < n and lines[i].strip() != "":
                for tok in _TICK_RE.findall(lines[i]):
                    add(tok)
                i += 1
            continue
        i += 1
    return values


def load_registries(path: Path | None = None) -> dict[str, frozenset[str]]:
    """Parse ``spec/REGISTRY.md`` and return ``{registry_name: frozenset(values)}``
    for the six registries. Raises if a named registry is missing or empty."""
    md = (path or find_registry_md()).read_text(encoding="utf-8")
    lines = md.splitlines()

    # Partition into sections keyed by the backticked name in each "## N. `name`".
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in lines:
        h = _HEADER_RE.match(line)
        if h:
            current = h.group(1)
            sections[current] = []
        elif current is not None:
            if line.startswith("## "):  # next non-registry section ends the block
                current = None
            else:
                sections[current].append(line)

    out: dict[str, frozenset[str]] = {}
    for name in REGISTRY_NAMES:
        if name not in sections:
            raise ValueError(f"registry {name!r} not found in REGISTRY.md")
        vals = _seeded_values_in_section(sections[name])
        if not vals:
            raise ValueError(f"registry {name!r} parsed with no seeded values")
        out[name] = frozenset(vals)
    return out
