# SPDX-License-Identifier: BSD-3-Clause
"""The six profile registries (§12), sourced from ``spec/REGISTRY.md``.

The seeded values are NOT hard-coded here: they are parsed at load time from the
interim registry of record (``spec/REGISTRY.md``) so the code and the spec cannot
drift. The binding invariant (§4, §12) — unregistered values are informational
and never a rejection — is applied by the verifier, not here; this module only
reports which values are seeded.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

__all__ = [
    "REGISTRY_NAMES",
    "load_registries",
    "find_registry_md",
    "load_cpb_provisional_values",
    "find_cpb_provisional",
]

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
    """Locate ``spec/REGISTRY.md``. Search order:
    1. ``AAC_REGISTRY_PATH`` env var (explicit override).
    2. Bundled ``data/REGISTRY.md`` next to this module (wheel install path).
    3. Walk up from this module looking for ``spec/REGISTRY.md`` (dev/source tree).
    """
    override = os.environ.get("AAC_REGISTRY_PATH")
    if override:
        return Path(override)
    # Bundled copy included in the wheel (agent_action_capsule/data/REGISTRY.md).
    bundled = Path(__file__).resolve().parent / "data" / "REGISTRY.md"
    if bundled.is_file():
        return bundled
    # Source-tree fallback: walk up looking for spec/REGISTRY.md.
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
        # across lines; collect backticks from AFTER the marker on the marker
        # line, then through the rest of the paragraph (until a blank line). Only
        # text after the marker is the value list — prose backticks before it
        # (e.g. guidance naming a value) are not seeded values.
        if "Initial contents" in stripped:
            first = True
            while i < n and lines[i].strip() != "":
                text = lines[i]
                if first:
                    text = text[text.find("Initial contents"):]
                    first = False
                for tok in _TICK_RE.findall(text):
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


# --------------------------------------------------------------------------- #
# Vendored CPB provisional registry (§12 known-provisional resolution).
#
# The machine-readable CPB registry of record lives in
# ``action-state-group/scitt-payload-binding``; its *provisional* (Rung 3)
# artifact-type entries are vendored here as a local, no-network snapshot
# (``data/cpb_provisional.json``, refreshed by ``scripts/vendor_cpb_registry.py``,
# pinned to an upstream commit). The verifier consults it so that a value a
# provisional payload class is known to set — e.g. the mesh-inference-exchange
# class's ``effect.type='inference_completion'`` — resolves as *known with
# status provisional* rather than unknown. The never-reject invariant (§4, §12)
# is unchanged: a provisional value is still informational, never a rejection,
# and a genuinely unknown value still surfaces as ``unknown_registry_value``.
# --------------------------------------------------------------------------- #
def find_cpb_provisional(start: Path | None = None) -> Path | None:
    """Locate the vendored ``data/cpb_provisional.json``. Returns ``None`` if it
    is not present (the snapshot is optional; absence means no provisional
    resolution, never an error). Honors ``AAC_CPB_PROVISIONAL_PATH`` override."""
    override = os.environ.get("AAC_CPB_PROVISIONAL_PATH")
    if override:
        p = Path(override)
        return p if p.is_file() else None
    bundled = Path(__file__).resolve().parent / "data" / "cpb_provisional.json"
    return bundled if bundled.is_file() else None


def load_cpb_provisional_values(
    path: Path | None = None,
) -> dict[str, dict[str, str]]:
    """Return ``{aac_registry_name: {value: payload_class_name}}`` for the values
    that vendored *provisional* CPB payload classes are known to set on the
    surrounding capsule's six AAC registry fields.

    Returns an empty dict if the vendored snapshot is absent or malformed —
    provisional resolution is a best-effort enrichment, never a hard dependency
    (the verifier must still run, and never reject, without it)."""
    p = path or find_cpb_provisional()
    if p is None:
        return {}
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    out: dict[str, dict[str, str]] = {}
    types = doc.get("provisional_artifact_types", {})
    if not isinstance(types, dict):
        return {}
    for type_name, entry in types.items():
        if not isinstance(entry, dict):
            continue
        cfv = entry.get("capsule_field_values", {})
        if not isinstance(cfv, dict):
            continue
        for reg_name, values in cfv.items():
            if reg_name not in REGISTRY_NAMES or not isinstance(values, list):
                continue
            bucket = out.setdefault(reg_name, {})
            for v in values:
                if isinstance(v, str):
                    bucket.setdefault(v, type_name)
    return out
